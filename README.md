# pgtrace

eBPF agent that traces queries **through pgbouncer**: every client query
becomes a trace whose root span is the query as the client experienced it and
whose child span is the query pgbouncer ran on its postgres connection. Traces
are sampled and exported over OpenTelemetry (OTLP/HTTP) to
[VictoriaTraces](https://docs.victoriametrics.com/victoriatraces/). The agent
also serves Prometheus metrics computed from **every** query, and the stack
includes Prometheus and Grafana with a ready-made dashboard.

```
client ══▶ pgbouncer ══▶ postgres
             │  fexit: __sys_sendto / __sys_recvfrom / __sys_connect / __sys_accept4
             │  fentry: __x64_sys_close
             │  in-kernel filter: traced pid, fds not marked "neither client nor server"
             │  per event: payload + TCP stream offset (detects events the kernel skipped)
             ▼
     BPF ringbuf ─▶ pgtrace-agent (event loop)
                      connmap (client / server socket) → pgwire parsers (both sides)
                      → correlator (link server queries to client queries)
                      ├─▶ metrics (all queries) ─▶ /metrics ─▶ Prometheus ─▶ Grafana
                      └─▶ sampler ─▶ export queue ─▶ N workers: OTLP protobuf ─▶ VictoriaTraces
                                                                 ─▶ Grafana (Jaeger datasource)
```

A trace for one client query:

| span | kind | what it measures |
|---|---|---|
| `SELECT` (root) | SERVER | pgbouncer reading the client's query → pgbouncer sending the last reply to the client. Attributes include `client.address`, `db.namespace`, `db.user`, `application_name`, `pgbouncer.pool_wait_ms`, `pgtrace.correlation` |
| `SELECT` (child) | CLIENT | pgbouncer sending the query to postgres → postgres's `ReadyForQuery`. Attributes include `server.address`, SQLSTATE and row count |
| `SET` (child, optional) | CLIENT | queries pgbouncer issues itself for this client (`pgbouncer.internal=true`), e.g. parameter sync |

Errors that pgbouncer generates itself (admin console, pool errors) appear as
root spans with no child. Server queries with no client (e.g.
`server_check_query`) are exported as standalone spans with
`pgtrace.correlation=none`.

**Sampling:** a trace is kept if any span failed or the root took at least
`slow-ms`; otherwise it is kept with probability `sample-ratio`.

**Correlation:** pgbouncer's binary is normally stripped, so the link is
inferred from the traffic. pgbouncer is single-threaded, which means the agent
sees its reads and writes in order. A server connection is linked to one
client until the server reports an idle transaction status. A query starting
on an unlinked server is matched to the waiting client whose oldest
unforwarded query has the same signature (SQL plus bind values). When several
clients wait with identical queries, the link is marked `inferred`. Details:
`docs/superpowers/specs/2026-09-28-client-correlation-and-observability-design.md`.

**Joining application traces (SQLCommenter):** if the application appends a
[SQLCommenter](https://google.github.io/sqlcommenter/) comment with a W3C
`traceparent` to its SQL (`… /*traceparent='00-<trace>-<span>-01'*/`), the
pgbouncer root span becomes a child of the application's span. One trace then
shows application → pgbouncer (pool wait) → postgres. Other comment keys
(`application`, `route`, …) become `sqlcommenter.*` attributes. A sampled
parent means the trace is always kept (`pgtrace.sample_reason=parent`). A
traceparent inside a *reused* prepared statement is ignored, since it belongs
to whichever request prepared it (counted as `not_per_execution`).

**Contention:** deadlocks, lock and statement timeouts, serialization
failures, pool exhaustion, pgbouncer queue timeouts, idle-in-transaction
holders and rejected logins all show up in traces and metrics, and the
dashboard has a *Contention* row. `scripts/contention.sh` provokes each case
and checks the evidence; `docs/contention.md` explains what to look for and
what can't be seen (e.g. which session held a lock).

Performance: `docs/performance.md` (limits found and removed:
`docs/bottlenecks.md`). Metrics and cardinality: `docs/metrics.md`.
Contention: `docs/contention.md`.

## Quick start

```bash
make e2e                  # builds, starts the stack, generates traffic, verifies traces, metrics and Grafana
./scripts/e2e_tls.sh      # the same over TLS (-tls-capture): strict, mixed TLS/plain, pre-existing sessions, restart
./scripts/contention.sh   # deadlocks, lock waits, timeouts, pool exhaustion, idle-in-transaction, rejected logins
./scripts/soak.sh         # 90-minute soak with big JSON statements (DURATION=seconds)
```

or manually:

```bash
cd deploy && docker compose up -d --build
docker compose run --rm loadgen pgbench -i -s 1
docker compose run --rm loadgen pgbench -c 8 -T 60
```

| what | where |
|---|---|
| Grafana (no login) | http://localhost:3000, dashboard **pgtrace**; *Explore → VictoriaTraces* for traces |
| Prometheus | http://localhost:9090 |
| Agent metrics | http://localhost:9464/metrics |
| VictoriaTraces | http://localhost:10428 (`/select/jaeger/api/...`, `/select/logsql/query`) |
| pgbouncer | `localhost:16432`, user/password `postgres`/`postgres`; database `tiny` has a 2-connection pool for seeing pool waits |

The Jaeger search index in VictoriaTraces lags ingestion by up to ~60 s, so
Grafana's trace tables fill in about a minute after the traffic. LogsQL queries
see spans immediately.

## Agent configuration

Flags (or `PGTRACE_<FLAG>` env, e.g. `PGTRACE_SAMPLE_RATIO`):

| flag | default | |
|---|---|---|
| `-comm` | `pgbouncer` | process name to trace |
| `-proc` | `/proc` | procfs of the host pid namespace |
| `-pg-port` | `5432` | postgres port; sockets to it are server connections |
| `-listen-port` | `6432` | pgbouncer's listen port; identifies client sockets opened before the agent started |
| `-client-tracing` | `true` | trace client connections and link them to server queries; `false` = server spans only |
| `-sample-ratio` | `0.1` | fraction of normal traces kept |
| `-slow-ms` | `100` | traces at least this slow are always kept |
| `-otlp-endpoint` | `http://victoriatraces:10428/insert/opentelemetry/v1/traces` | OTLP/HTTP traces URL |
| `-service-name` | `pgbouncer` | `service.name` resource attribute |
| `-export-workers` | `4` | concurrent export workers; each encodes and sends its own batches |
| `-export-batch` | `8192` | most spans per OTLP request |
| `-export-queue` | `65536` | traces waiting for a worker; when full, new traces are dropped and counted |
| `-export-interval` | `1s` | a partial batch is sent after this long |
| `-metrics-addr` | `:9464` | Prometheus `/metrics` address; empty disables it |
| `-stats-interval` | `10s` | stats log interval |
| `-bpf-stats` | `false` | enable kernel BPF run-time accounting (~1% extra overhead) |
| `-capture-bytes` | `4096` | payload bytes the kernel copies per send/recv (64 … 16384) |
| `-max-message-bytes` | `65536` | most bytes of one protocol message the parser keeps; memory is allocated per message up to this |
| `-max-query-text` | `2048` | most bytes of SQL in `db.query.text` |
| `-metrics-labels` | *(off)* | opt-in per-client metrics: any of `database,user,client_addr` |
| `-metrics-label-limit` | `200` | most label combinations tracked; extra ones are recorded as `other` |
| `-metrics-label-ttl` | `30m` | idle label combinations are removed after this |
| `-sqlcommenter` | `true` | read SQLCommenter comments; a `traceparent` parents the pgbouncer span |
| `-sqlcommenter-parent-sampling` | `true` | always keep traces whose SQLCommenter parent is sampled |
| `-attach-param-sync` | `true` | attach pgbouncer's parameter-sync `SET`/`RESET` statements (e.g. `SET application_name`) to the client query they precede, as internal children |
| `-tls-capture` | `false` | trace TLS connections: capture plaintext with uprobes on pgbouncer's libssl (OpenSSL 3, dynamically linked). Costs pgbouncer CPU on every TLS query; see `docs/performance.md` |

The image sets `GOMEMLIMIT=768MiB`, a soft memory cap for the Go runtime;
override it with `-e` to match the agent's memory budget. It is built on
`gcr.io/distroless/static-debian12` (≈ 14 MB; CA certificates included, no
shell), so debug through `/metrics`, `-pprof` and `-debug-dump-dir` rather
than `docker exec`.

The agent needs `privileged` (or CAP_BPF + CAP_PERFMON + CAP_SYS_PTRACE) and the
host pid namespace.

## Metrics

| metric | labels | |
|---|---|---|
| `pgtrace_queries_total` | `side`, `operation`, `protocol` | queries seen; `side` is `client` (client↔pgbouncer) or `server` (pgbouncer↔postgres) |
| `pgtrace_query_duration_seconds` | `side`, `operation` | latency histogram |
| `pgtrace_query_errors_total` | `side`, `sqlstate` | failed queries |
| `pgtrace_pool_wait_seconds` | | client query read → sent to a server |
| `pgtrace_correlation_total` | `result` | exact / inferred / internal / none / orphan |
| `pgtrace_spans_total` | `decision` | kept_error / kept_slow / kept_ratio / dropped |
| `pgtrace_events_total` | `kind` | kernel events |
| `pgtrace_kernel_drops_total` | | ringbuf overflows (should be 0) |
| `pgtrace_capture_gaps_total` | `side` | capture events the kernel skipped, detected by TCP stream offset; the parser skips the gap |
| `pgtrace_bpf_recursion_misses_total` | `program` | BPF runs the kernel skipped (recursion protection) |
| `pgtrace_export_spans_total` | `stage` | created / exported / dropped (export queue full) / failed_batches |
| `pgtrace_export_queue_length` | | traces waiting for an export worker |
| `pgtrace_connections` | `side`, `tls` | tracked sockets; `tls="true"` also without `-tls-capture` (queries on those aren't seen then) |
| `pgtrace_tls_processes` | `state` | with `-tls-capture`: processes with TLS probes `attached` / `unsupported` |
| `pgtrace_tls_unresolved_total` | `result` | with `-tls-capture`: TLS events whose socket wasn't known yet, `resolved` / `dropped` |
| `pgtrace_traced_processes` | | pgbouncer processes |
| `pgtrace_bpf_run_seconds_total`, `pgtrace_bpf_runs_total` | | with `-bpf-stats` |
| `pgtrace_truncations_total` | `layer` | kernel / parser / export: which size cap fired |
| `pgtrace_trace_context_total` | `result` | SQLCommenter: linked / not_per_execution / invalid |
| `pgtrace_client_*` | enabled client labels | opt-in (`-metrics-labels`): queries, errors, duration, pool wait per database/user/client IP |

Plus the standard Go and process collectors. Every label is bounded; the
series ceiling is 2,541 without client labels and 8,975 with the default
label limit (2,557 / 8,991 with `-tls-capture`). See `docs/metrics.md` for every series and how to size the limit.

## Releases

Pushing a tag like `v1.2.3` runs `.github/workflows/release.yml`, which:
- runs the tests;
- builds a static linux/amd64 `pgtrace-agent` with the version embedded
  (`pgtrace-agent -version`);
- publishes `pgtrace-agent_<tag>_linux_amd64.tar.gz` and `checksums.txt` as a
  GitHub Release with generated notes (tags containing `-`, e.g.
  `v1.0.0-rc1`, become pre-releases);
- pushes the image `ghcr.io/t1bur1an/pgtrace-agent:<version>` (plus
  `:<major>.<minor>` and `:latest` for non-pre-releases) and lists it in the
  release notes. Images are published from `v0.1.1` on; `v0.1.0` has release
  archives only.

```bash
docker pull ghcr.io/t1bur1an/pgtrace-agent:0.3.1
docker run --rm --privileged --pid host -v /sys/kernel/tracing:/sys/kernel/tracing \
  ghcr.io/t1bur1an/pgtrace-agent:0.3.1 -otlp-endpoint http://victoriatraces:10428/insert/opentelemetry/v1/traces
```

The body of the annotated tag's message (everything after its first line)
becomes the release's **Changes** section, above the image instructions and
GitHub's generated notes. Lines starting with `#` are stripped from tag
messages by git, so use plain section names:

```bash
git tag -a v0.3.0 -F - <<'EOF'
v0.3.0

Export
- what changed
EOF
git push origin v0.3.0
```

`.github/workflows/ci.yml` runs vet, race-enabled tests, a check that the BPF
program compiles, and a binary and image build on every push to `main` and on
pull requests.

## Development

```bash
make test        # unit tests (no privileges needed)
make generate    # re-generate BPF objects after editing bpf/pgtrace.bpf.c (clang + libbpf headers)
```

## Limitations

- Correlation is inferred. When several clients wait with byte-identical
  queries (same SQL and parameters), which of them got which server can be
  swapped (`pgtrace.correlation=inferred`). Durations stay correct.
- Client connections opened before the agent started have no startup
  attributes (user, database, application_name).
- TLS is traced only with `-tls-capture`, for pgbouncer builds that call
  OpenSSL 3's `SSL_read`/`SSL_write` from a dynamically linked `libssl`.
  Without it, TLS connections are counted (`pgtrace_connections{tls="true"}`)
  but their queries aren't seen. Version and cipher attributes are
  best-effort (present when pgbouncer asks OpenSSL for them; pgbouncer 1.25
  does so even with connection logging off). Sessions opened before the
  agent started are picked up by a temporary fallback on `read`/`write`; the
  first calls of such a session can be lost (counted in
  `pgtrace_tls_unresolved_total`). The cost: 8 uprobe traps in pgbouncer per
  TLS query, ≈ 9–11 µs of its CPU on the benchmark box; see
  `docs/performance.md`.
- Payload capture is capped per syscall (`-capture-bytes`) and per message
  (`-max-message-bytes`); longer SQL is truncated (`pgtrace.truncated=true`)
  but the parser stays in sync. `pgtrace_truncations_total` shows which cap fires.
- The kernel occasionally skips a capture event (fentry/fexit recursion
  protection). The agent detects the lost bytes by TCP stream offset and
  skips them (`pgtrace_capture_gaps_total`). When a gap covers more than one
  message, that query can lose its link: 1 in 1.26 M in a 90-minute soak.
- Prepared statements parsed before the agent started show as
  `<unknown prepared statement "name">`. They still correlate through their
  bind values.
- x86-64 only (generated BPF bindings); kernel needs BTF and BPF trampolines
  (fentry/fexit, 5.5+). Tested on 7.2.
- Only `send`/`recv`-family syscalls are captured (what pgbouncer uses);
  `read`/`write` on sockets is not.

## License

MIT, see `LICENSE`. The eBPF program `bpf/pgtrace.bpf.c` is dual-licensed
`MIT OR GPL-2.0-only` and declares `"Dual MIT/GPL"` to the kernel. The kernel
only lets GPL-compatible programs use `bpf_probe_read_user` and fentry/fexit,
so this declaration is required; you may use the file under MIT.
