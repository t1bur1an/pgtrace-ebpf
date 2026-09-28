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
             ▼
     BPF ringbuf ─▶ pgtrace-agent
                      connmap (client / server socket) → pgwire parsers (both sides)
                      → correlator (link server queries to client queries)
                      ├─▶ metrics (all queries) ─▶ /metrics ─▶ Prometheus ─▶ Grafana
                      └─▶ sampler ─▶ OTLP ─▶ VictoriaTraces ─▶ Grafana (Jaeger datasource)
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

Performance: `docs/performance.md`.

## Quick start

```bash
make e2e      # builds, starts the stack, generates traffic, verifies traces, metrics and Grafana
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
| `-metrics-addr` | `:9464` | Prometheus `/metrics` address; empty disables it |
| `-stats-interval` | `10s` | stats log interval |
| `-bpf-stats` | `false` | enable kernel BPF run-time accounting (~1% extra overhead) |
| `-capture-bytes` | `4096` | payload bytes the kernel copies per send/recv (64 … 16384) |
| `-max-message-bytes` | `65536` | most bytes of one protocol message the parser keeps; memory is allocated per message up to this |
| `-max-query-text` | `2048` | most bytes of SQL in `db.query.text` |
| `-metrics-labels` | *(off)* | opt-in per-client metrics: any of `database,user,client_addr` |
| `-metrics-label-limit` | `200` | most label combinations tracked; extra ones are recorded as `other` |
| `-metrics-label-ttl` | `30m` | idle label combinations are removed after this |

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
| `pgtrace_connections` | `side` | tracked sockets |
| `pgtrace_traced_processes` | | pgbouncer processes |
| `pgtrace_bpf_run_seconds_total`, `pgtrace_bpf_runs_total` | | with `-bpf-stats` |
| `pgtrace_truncations_total` | `layer` | kernel / parser / export: which size cap fired |
| `pgtrace_client_*` | enabled client labels | opt-in (`-metrics-labels`): queries, errors, duration, pool wait per database/user/client IP |

Plus the standard Go and process collectors. Every label is bounded; the
series ceiling is 1,897 without client labels and 8,331 with the default
label limit. See `docs/metrics.md` for every series and how to size the limit.

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
- No TLS on either side (payloads would be encrypted).
- Payload capture is capped per syscall (`-capture-bytes`) and per message
  (`-max-message-bytes`); longer SQL is truncated (`pgtrace.truncated=true`)
  but the parser stays in sync. `pgtrace_truncations_total` shows which cap fires.
- Prepared statements parsed before the agent started show as
  `<unknown prepared statement "name">`. They still correlate through their
  bind values.
- x86-64 only (generated BPF bindings); kernel needs BTF and BPF trampolines
  (fentry/fexit, 5.5+). Tested on 7.2.
- Only `send`/`recv`-family syscalls are captured (what pgbouncer uses);
  `read`/`write` on sockets is not.
