# pgbouncer → postgres eBPF query tracing — design

Date: 2026-09-28

## Goal

A Go agent that uses eBPF to observe the traffic pgbouncer sends to and receives
from postgres, turns each query into an OpenTelemetry span, samples the spans,
and exports them to VictoriaTraces over OTLP. The whole stack is runnable and
testable locally with docker compose and synthetic traffic.

Success criteria:

- Queries flowing through pgbouncer appear as spans in VictoriaTraces with SQL
  text, operation, duration, row count and error status.
- Sampling is configurable; errors and slow queries are always kept.
- `make test` (unit) and `make e2e` (full stack) pass.

## Scope

In scope: server-side connections only (pgbouncer → postgres), plaintext TCP,
simple and extended query protocols, one pgbouncer process (or several with the
same comm name) on the host.

Out of scope: TLS between pgbouncer and postgres, client → pgbouncer tracing,
correlating server queries to originating clients, COPY data content,
production hardening (multi-host deployment, Kubernetes manifests).

## Architecture

docker compose services:

| service         | image / build            | notes                                              |
|-----------------|--------------------------|----------------------------------------------------|
| `postgres`      | `postgres:17`            | TCP 5432, md5/scram auth                           |
| `pgbouncer`     | `edoburu/pgbouncer` (or equivalent) | `pool_mode=transaction`, connects to postgres over TCP |
| `victoriatraces`| `victoriametrics/victoria-traces` | OTLP/HTTP ingest, Jaeger-compatible query API |
| `agent`         | built from this repo     | `privileged: true`, `pid: host`, mounts `/sys/kernel/debug`, `/sys/fs/bpf` |
| `loadgen`       | `postgres:17` (pgbench)  | run on demand by the e2e script                    |

## Components

### BPF program — `bpf/pgtrace.bpf.c`

CO-RE, compiled via `cilium/ebpf` `bpf2go` against `vmlinux.h` generated from
`/sys/kernel/btf/vmlinux`.

- Maps:
  - `target_pids` (hash, u32 tgid → u8): pids to trace, filled by the agent.
  - `active` (hash, u64 pid_tgid → args): stash of syscall args between enter/exit.
  - `events` (ringbuf, 16 MiB).
  - `scratch` (per-CPU array) for building events larger than the BPF stack.
- Tracepoints:
  - `sys_enter/exit_sendto`, `sys_enter/exit_recvfrom`: at exit, if return > 0,
    emit `data` event `{ts_ns, tgid, tid, fd, dir(send|recv), total_len,
    captured_len, payload[≤4096]}`.
  - `sys_enter/exit_write`, `sys_enter/exit_read` as fallback for builds that
    use read/write on sockets (only when tgid is targeted; userspace ignores
    non-socket fds).
  - `sys_enter/exit_connect`: emit `connect` event with fd and destination
    sockaddr (AF_INET/AF_INET6) — the return value may be `-EINPROGRESS`, which
    is treated as success.
  - `sys_enter_close`: emit `close` event with fd.
- `ts_ns` is `bpf_ktime_get_ns()` (CLOCK_MONOTONIC).

### Go packages

- `cmd/pgtrace-agent` — main: flags/env config, wiring, graceful shutdown.
- `internal/capture` — loads BPF objects, attaches tracepoints, discovers
  pgbouncer pids by scanning `/proc/*/comm` (rescans every 5 s), decodes ringbuf
  records into typed Go events and delivers them on a channel.
- `internal/connmap` — decides whether `(tgid, fd)` is a server connection.
  Source 1: `connect` events whose destination port matches `--pg-port`
  (default 5432; optional `--pg-addr` filter). Source 2 (fds opened before the
  agent started): lazily resolve `/proc/<tgid>/fd/<fd>` → `socket:[inode]`, then
  find that inode in `/proc/<tgid>/net/tcp{,6}` and check remote port. Results
  cached; entry dropped on `close`.
- `internal/pgwire` — per-connection streaming parser.
  - Frontend stream (send direction) and backend stream (recv direction) each
    have a reassembly buffer: messages are `type(1) + len(4) + body`; handles
    messages split across syscalls and many messages in one syscall. When the
    kernel truncated capture (`captured_len < total_len`) the parser knows the
    true length and skips the missing bytes instead of desyncing; affected
    fields are marked truncated.
  - Startup/SSLRequest/Cancel packets (no type byte) are recognised on a new
    connection and skipped.
  - Query lifecycle:
    - Simple: `Q` starts a query; backend `C` (command tag), `D` (row count),
      `E` (error), and finally `Z` end it. A `Q` with multiple statements yields
      one span with the full text.
    - Extended: `P` records statement name → SQL; `B`/`E` (Execute) start a
      query using the SQL of the bound statement (or unnamed); `S` (Sync) +
      `Z` ends it. Unknown statement names (prepared before the agent started)
      produce text `<unknown prepared statement "name">`.
  - Output: `Query{Conn, Start, End, SQL, Operation, CommandTag, Rows,
    ErrorCode, ErrorMessage, Protocol(simple|extended), Truncated}`.
  - Operation = first keyword of SQL (upper-cased), falling back to command tag.
- `internal/sampler` — `Keep(q) bool`: true if error, or duration ≥ `--slow-ms`
  (default 100), else deterministic-random with probability `--sample-ratio`
  (default 0.1). Counters for seen/kept per reason.
- `internal/export` — OTel SDK tracer provider with OTLP/HTTP exporter
  (`--otlp-endpoint`, default `http://victoriatraces:10428/insert/opentelemetry/v1/traces`),
  resource `service.name=pgbouncer` (configurable), batch span processor.
  Each kept query → one root span, kind CLIENT, name = operation, explicit start/end
  timestamps converted from monotonic to wall clock using an offset measured at
  startup. Attributes: `db.system=postgresql`, `db.query.text` (≤2048 chars),
  `db.operation.name`, `db.response.status_code`, `db.response.returned_rows`,
  `server.address`, `server.port`, `pgbouncer.pid`, `pgbouncer.server_fd`,
  `pgtrace.protocol`, `pgtrace.truncated`, `pgtrace.sample_reason`. Errors set
  span status Error with the message.

## Error handling

- BPF load/attach failure: fatal with clear message (needs CAP_BPF/privileged).
- Ringbuf full: BPF drops events; a per-CPU `drops` counter map is read by the
  agent and logged periodically. Parser for an affected connection resets on
  the next recognisable message boundary (next `Q`/`P`/`Z` after a gap is
  detected via length mismatch).
- Exporter failures are logged; spans are dropped rather than blocking capture.
- Agent logs periodic stats: events, queries, kept by reason, drops.

## Testing

- Unit: `pgwire` table tests with hand-built wire bytes — simple query, multi-row
  results, error response, extended protocol with named/unnamed statements,
  fragmented buffers (byte-by-byte feed), coalesced buffers, truncated capture.
  `sampler` tests for ratio accuracy and always-keep rules. `connmap` test for
  `/proc/net/tcp` parsing with fixture files.
- E2E (`scripts/e2e.sh`, `make e2e`):
  1. `docker compose up -d --build`, wait for health.
  2. Run pgbench init, then pgbench with `-M simple` and `-M extended`
     (fixed transaction count), plus deliberate failures
     (`SELECT 1/0`, missing table) and slow queries (`SELECT pg_sleep(0.2)`).
  3. Wait for batch flush, query VictoriaTraces Jaeger API
     (`/select/jaeger/api/traces?service=pgbouncer`).
  4. Assert: spans exist; every deliberate error and slow query is present with
     correct status; SELECT/UPDATE/INSERT operations appear; kept count for
     normal queries is within a tolerance of `ratio × total`.
