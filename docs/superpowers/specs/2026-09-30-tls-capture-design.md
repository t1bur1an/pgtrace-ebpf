# Opt-in TLS capture — design

Date: 2026-09-30. Approved in conversation: approach A (uprobes on pgbouncer's
libssl), mixed TLS/plain connections on both hops, a temporary fallback for
sessions that exist before the agent starts, and TLS version and cipher as
span attributes. Evidence: the spike on branch `spike/tls-uprobes`
(`docs/perf-results/tls-spike/` there).

## Goal

Trace queries on pgbouncer connections that use TLS as completely as plain
ones. Encryption only changes where the bytes come from. The parser,
correlator, sampling, metrics and export stay as they are.

- Opt-in: `-tls-capture` (env `PGTRACE_TLS_CAPTURE`), default `false`. When
  off, no new BPF program is loaded or attached, and the cost is unchanged.
- Either hop can be TLS or plain, per connection, in the same run.
- Success: TLS connections produce the same traces and metrics as plain
  connections. Loss is visible in metrics, and the cost is measured and
  documented.

## Why uprobes, and what it costs

TLS 1.3 and TLS 1.2 with ECDHE have forward secrecy: certificates and private
keys can't decrypt captured traffic. The plaintext has to come from inside
pgbouncer, before encryption and after decryption. The spike measured, on the
worst-case workload (select-only, ~0.1 ms queries):

| clients | TLS | TLS + capture | pgbouncer CPU per query |
|---:|---:|---:|---|
| 8 | 68 998 TPS | 47 409 TPS (−31 %) | 10.7 → 17.2 µs |
| 64 | 60 954 TPS | 39 105 TPS (−36 %) | 12.6 → 21.5 µs |

Most of it is the uprobe traps: 6 per query, about 1 µs each. Copying the
plaintext adds about 1.8 µs per query. The cost applies only to TLS
connections of traced processes. Rejected alternatives:
- extracting session keys and decrypting in the agent: needs probes on
  unexported OpenSSL internals, and a lost record breaks decryption;
- kTLS: pgbouncer doesn't support it.

## 1. Capture and attach

### Finding libssl

For each traced pgbouncer process (found by the existing 5 s rescan), the
agent:
1. Reads `/proc/<pid>/maps` and finds the mapped `libssl.so*`. It opens the
   file through `/proc/<pid>/root/<path>`, so containers work.
2. Checks that the pgbouncer executable imports `SSL_read` and `SSL_write`
   (dynamic symbol table). If it doesn't (e.g. a build using `SSL_read_ex`),
   it logs `unsupported TLS API` and attaches nothing.
3. Attaches the probes below with a PID filter, one link per probe per
   process. Other processes using the same library file, including other
   containers from the same image, never hit them.
4. Detaches the links when the process exits.

A process with no libssl mapped, or missing symbols, gets a warning. Its
plain connections are traced as today.

### Probes

All of these are functions pgbouncer 1.25 imports:

| probe | purpose | fires |
|---|---|---|
| `SSL_write` entry + return | plaintext sent: buffer at entry, bytes actually written at return | every send |
| `SSL_read` entry | remember (session, buffer) for this thread | every receive |
| `SSL_read` return | plaintext received (return value = length) | every receive |
| `SSL_set_rfd` entry | session → socket fd | once per new session |
| `SSL_free` entry | forget the session | once per session |
| `SSL_get_version` entry + return | TLS version string for the session | when pgbouncer builds a connection log line |
| `SSL_CIPHER_get_name` return | cipher name, for the session last passed to `SSL_get_version` on this thread | same |

pgbouncer is single-threaded and calls `SSL_get_version` and
`SSL_CIPHER_get_name` back-to-back for its `login attempt … tls=%s` and
`SSL established: %s` log lines. So "the session last passed to
`SSL_get_version` on this thread" identifies the cipher's session. Version
and cipher are best-effort: if pgbouncer stops asking for them (e.g. with
connection logging off), they're missing.

### Kernel side

- Map `tls_sessions`: key (tgid, session pointer) → fd. Filled by
  `SSL_set_rfd`, deleted by `SSL_free`, limited to 65,536 entries.
- Map `tls_current`: key thread id → (session pointer, buffer). Filled at
  `SSL_read`/`SSL_write` entry, then read and deleted at their return.

> **Amended during implementation (2026-09-30):** `SSL_write` was first
> captured at entry. The 30-minute TLS soak then found that with a slow
> reader, `SSL_write` returns without writing (socket full) and pgbouncer
> calls it again with the same bytes. Entry capture duplicated them and
> misaligned the parser (44k orphans in 30 min). `SSL_write` is now
> captured at return, and only the bytes it reports as written. That is one
> more uprobe trap per `SSL_write`: 8 per query instead of 6.
- Plaintext events use the existing event format: `kind` = data, `dir` =
  send/recv, `fd` from `tls_sessions`, and a new flag bit `flagTLS`.
  - They carry no TCP stream offset (`flagSeq` clear). For a session with no
    known fd, `fd` = −1 and the session pointer goes into the `addr` field.
  - Payload copy uses the same `-capture-bytes` limit, per-CPU scratch buffer
    and ring buffer as the socket probes.
- New event kinds:
  - `K_TLS_FD {session, fd}`: emitted when the fallback learns a session's fd;
  - `K_TLS_INFO {session, fd, version | cipher}`: up to 32 bytes of text.
- No double capture: OpenSSL writes and reads ciphertext with
  `write`/`read`, which the existing `sendto`/`recvfrom` probes don't see.
  The `accept4`/`connect`/`close` probes still fire for TLS connections, so
  connection tracking is unchanged.

### Fallback for sessions opened before the agent

`SSL_set_rfd` only fires for new sessions. For older ones:
- The agent attaches fentry programs on `ksys_read` and `ksys_write`,
  filtered in the kernel to traced processes. It attaches them at startup,
  when TLS capture is on, and again whenever an event arrives with
  `fd` = −1.
- When a traced thread is inside `SSL_read`/`SSL_write` (per `tls_current`)
  and its session has no fd, the fentry program stores the syscall's fd in
  `tls_sessions` and emits `K_TLS_FD`.
- The agent detaches them after 30 s with neither an `fd` = −1 event nor a
  `K_TLS_FD`: each session the fallback finds suggests more are waiting.
  While attached, they add a trampoline to every `read`/`write` on the
  host.
- If `ksys_read`/`ksys_write` can't be attached (e.g. inlined in a kernel
  build), the fallback is unavailable. The agent logs it and retries at
  most every 10 minutes. Meanwhile pre-existing sessions stay untraced, and
  their events are counted as unresolved drops.

## 2. Inside the agent

- Plaintext events go through the normal data path: connmap by fd, both
  parsers, correlator, sampler, metrics, export. The TCP-offset gap check is
  skipped for events without `flagSeq`. The per-message length bounds still
  guard the parser.
- **Protocol handoff:** the TLS request (`SSLRequest`) and the one-byte `S`
  answer travel via `send`/`recv` before encryption and are parsed as today.
  After `S` the frontend parser expects a startup message. With capture on,
  that startup message is the next plaintext event on the fd, so the parser
  continues without changes.
- **Unresolved events** (`fd` = −1) occur for sessions opened before the
  agent while the fallback isn't attached yet. With `SSL_write` captured at
  return, its ciphertext `write` has already mapped the fd whenever the
  fallback is attached. The hold below is kept as a safety net.
  - The agent holds at most one such event per process.
  - If the next event from that process is the matching `K_TLS_FD`, the
    held event is fed right then, i.e. in its original position. pgbouncer
    is single-threaded, and the mapping comes from the same `SSL_write`
    call, so nothing of that process can come in between.
  - If anything else from that process arrives first, the held event is
    dropped and counted. Feeding it later would reorder events and could
    mislink queries.
  - `SSL_read` events with `fd` = −1 are dropped and counted too. Their
    ciphertext `read` happened before the return probe fired, so if the fd
    is still unknown, the fallback wasn't attached yet. The next call on
    that session will be mapped.
- **Connection TLS state:** a connection is TLS when the parser consumed an
  `S` answer on it, or when its first TLS event arrives. Version and cipher
  are stored when `K_TLS_INFO` arrives. The state is cleared on close.
- **Span attributes** follow OpenTelemetry semantic conventions and are set
  only on TLS connections:
  - `tls.protocol.name` = `tls`, `tls.protocol.version` (e.g. `1.3`, from
    `TLSv1.3`), `tls.cipher` (e.g. `TLS_AES_256_GCM_SHA384`);
  - the root span uses the client connection's values; each server child
    span uses its own server connection's values;
  - connection-error spans get the values too.
- **Metrics:** `pgtrace_connections{side}` becomes
  `pgtrace_connections{side,tls}`. The `tls` label works even with capture
  off, since the `S` answer is always seen. So untraced encrypted traffic is
  visible.
- Correlation is unchanged. It relies on event order within pgbouncer, and
  TLS events arrive in the same order as plain ones.

## 3. Failures and metrics

| situation | behaviour | visible as |
|---|---|---|
| no libssl mapped yet (just after exec), or /proc unreadable | retried at each rescan for 30 s, then as below | – |
| no libssl, missing symbols | warn, trace plain connections | `pgtrace_tls_processes{state="unsupported"}` |
| pgbouncer doesn't import `SSL_read`/`SSL_write` | warn, attach nothing | same |
| probe run skipped by the kernel | parser length checks | `pgtrace_bpf_recursion_misses_total{program}` |
| ring buffer full | event dropped | `pgtrace_kernel_drops_total` |
| unresolved event not followed by its mapping | dropped | `pgtrace_tls_unresolved_total{result="dropped"}` |
| fallback can't attach (`ksys_read`/`ksys_write` missing) | pre-existing sessions untraced | log line; unresolved drops |
| capture off, TLS in use | connection traced up to `S` only | `pgtrace_connections{tls="true"}` |

New series. Only the `tls` label exists with capture off; the rest are
registered when it's on:

| metric | labels | series |
|---|---|---:|
| `pgtrace_connections` | `side` × `tls` | 4 (was 2) |
| `pgtrace_tls_processes` | `state` = attached, unsupported | 2 |
| `pgtrace_tls_fallback_attached` | – | 1 |
| `pgtrace_tls_unresolved_total` | `result` = resolved, dropped | 2 |
| `pgtrace_bpf_recursion_misses_total` | 11 new `program` values | +11 |

`metrics.MaxSeries` takes TLS capture into account. The base ceiling becomes
2,541 with capture off (+2) and 2,557 with it on (+16 more).

## 4. Testing

- **Unit tests:**
  - pgwire: after an `S` answer, a plaintext startup message and queries
    parse on the same connection.
  - agent:
    - a held `fd` = −1 event is fed on its directly following
      `K_TLS_FD`, and dropped and counted when another event of that
      process comes first;
    - TLS state is set from `S` or from the first TLS event, and cleared on
      close;
    - TLS events skip the gap check;
    - version/cipher from `K_TLS_INFO`.
  - export: `tls.*` attributes on spans of TLS connections, absent on plain
    ones, and per hop.
  - metrics: the `tls` label; `MaxSeries` with capture on and off.
  - capture: the libssl path from a sample `/proc/<pid>/maps`; the import
    check against a small ELF fixture.
  - CI compiles the BPF program (as today).
- **End-to-end** (`scripts/e2e_tls.sh`). PKI: root → intermediate → leaf
  server and client certificates, generated by `deploy/tls/gencerts.sh`
  (moved from the spike). Two runs:
  1. **Mixed:** `client_tls_sslmode=prefer`; pgbench clients with
     `sslmode=disable` and `sslmode=verify-full` in the same run; plain
     server hop.
  2. **Strict:** `verify-full` with client certificates on both hops.

  Both apply the existing completeness checks: exact correlation, child SQL
  matching the root, times nested, stored = kept. Plus:
  - `tls.*` attributes exactly on the TLS hops;
  - `pgtrace_connections{tls}` matching the mix;
  - 0 unresolved drops;
  - 0 kernel drops.
- **Sessions opened before the agent:** start TLS pgbench for 90 s and start
  the agent 10 s in. Check that:
  - queries from those sessions are traced after the agent starts;
  - `pgtrace_tls_fallback_attached` goes 1 → 0 within 30 s after the load
    ends;
  - resolved and dropped are reported. With `SSL_write` captured at return,
    a session is mapped before its data is emitted whenever the fallback is
    attached, so both are expected to be about 0.
- **Connection logging off** (`log_connections=0`, `log_disconnections=0`):
  record whether version/cipher still appear. Either result is acceptable
  and gets documented.
- **Performance** (`scripts/perf_tls.sh`, from the spike's script): 8 and 64
  clients, 3 × 20 s, alternated. Configurations:
  - no TLS;
  - no TLS + agent;
  - TLS;
  - TLS + agent with capture off;
  - TLS + agent with capture on.

  Documented, no pass/fail threshold, but with capture on the agent must see
  every client query with 0 kernel drops.
- **Soak:** 30 minutes, strict TLS, big-JSON workload (`soak.sh` with the TLS
  override). The same checks as the existing soak.

## 5. Docs

- README: the `-tls-capture` flag; requirements (pgbouncer with
  dynamically linked OpenSSL 3, `SSL_read`/`SSL_write`); the cost; the
  limitations below.
- `performance.md`: a TLS section from `perf_tls.sh`.
- `metrics.md`: the new series and ceilings.

## Out of scope

- client certificate subject or identity;
- kTLS;
- GSSAPI encryption;
- statically linked or symbol-stripped pgbouncer;
- `SSL_read_ex`/`SSL_write_ex`/`SSL_peek`;
- libssl other than OpenSSL 3 (BoringSSL, LibreSSL, GnuTLS).
