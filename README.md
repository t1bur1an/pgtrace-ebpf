# pgtrace

eBPF agent that traces the queries **pgbouncer sends to postgres**, samples
them, and exports them as OpenTelemetry spans (OTLP/HTTP) — tested against
[VictoriaTraces](https://docs.victoriametrics.com/victoriatraces/).

```
pgbench ─▶ pgbouncer ══(send/recv syscalls)══▶ postgres
                │  fexit: __sys_sendto / __sys_recvfrom / __sys_connect, fentry: __x64_sys_close
                │  in-kernel filter: traced pid + fds not yet marked "not postgres"
                ▼
        BPF ringbuf ─▶ pgtrace-agent: connmap → pgwire parser → sampler → OTLP ─▶ VictoriaTraces
```

One span per statement execution (simple `Q` or extended `Parse/Bind/Execute…Sync`)
with SQL text, operation, command tag, row count, SQLSTATE and duration.
Sampling: every error and every query ≥ `slow-ms` is kept, other queries are
kept with probability `sample-ratio`.

Design: `docs/superpowers/specs/2026-09-28-pgbouncer-ebpf-tracing-design.md`.
Performance: `docs/performance.md`.

## Quick start

```bash
make e2e      # builds, starts the stack, runs pgbench, verifies spans in VictoriaTraces
```

or manually:

```bash
cd deploy && docker compose up -d --build
docker compose run --rm loadgen pgbench -i -s 1
docker compose run --rm loadgen pgbench -c 4 -T 30
curl 'http://localhost:10428/select/jaeger/api/traces?service=pgbouncer&limit=20'
curl http://localhost:10428/select/logsql/query --data-urlencode 'query=name:* | stats by (name) count()'
```

pgbouncer listens on `localhost:16432` (user/password `postgres`/`postgres`).
The Jaeger search index in VictoriaTraces lags ingestion by up to ~60 s; LogsQL
queries see spans immediately.

## Agent configuration

Flags (or `PGTRACE_<FLAG>` env, e.g. `PGTRACE_SAMPLE_RATIO`):

| flag | default | |
|---|---|---|
| `-comm` | `pgbouncer` | process name to trace |
| `-proc` | `/proc` | procfs of the host pid namespace |
| `-pg-port` | `5432` | postgres port; sockets to it are server connections |
| `-sample-ratio` | `0.1` | fraction of normal queries kept |
| `-slow-ms` | `100` | queries at least this slow are always kept |
| `-otlp-endpoint` | `http://victoriatraces:10428/insert/opentelemetry/v1/traces` | OTLP/HTTP traces URL |
| `-service-name` | `pgbouncer` | `service.name` resource attribute |
| `-stats-interval` | `10s` | stats log interval |
| `-bpf-stats` | `false` | enable kernel BPF run-time accounting and log it (~1% extra overhead) |

The agent needs `privileged` (or CAP_BPF + CAP_PERFMON + CAP_SYS_PTRACE) and the
host pid namespace.

## Development

```bash
make test        # unit tests (no privileges needed)
make generate    # re-generate BPF objects after editing bpf/pgtrace.bpf.c (clang + libbpf headers)
```

## Limitations

- Server side only: no attribution to the originating client connection.
- No TLS between pgbouncer and postgres (payload would be encrypted).
- Payload capture is capped at 4 KiB per syscall; longer SQL is truncated
  (`pgtrace.truncated=true`) but the parser stays in sync.
- Prepared statements parsed before the agent started show as
  `<unknown prepared statement "name">`.
- x86-64 only (generated BPF bindings); kernel needs BTF and BPF trampolines
  (fentry/fexit, 5.5+). Tested on 7.2.
- Only `send`/`recv`-family syscalls are captured (what pgbouncer uses);
  `read`/`write` on sockets is not.
