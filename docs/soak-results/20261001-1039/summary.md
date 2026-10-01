# Soak test 20261001-1039

duration_s: 5400  
started: 2026-10-01T10:39:47+03:00  
sample_ratio: 0.1  
agent_container: ca2dd6f05c90361655f00fbba0f5f4ab471263f104c32abd54560aa3ac32eb4c 2026-10-01T07:39:44.88389489Z  
cpu: AMD Ryzen 7 7700X 8-Core Processor (16 threads)  
memory: 61 GiB  
kernel: 7.2.7-arch1-1  
pgbouncer: PgBouncer 1.25.2  
postgres: postgres (PostgreSQL) 17.11 (Debian 17.11-1.pgdg13+2)  
finished: 2026-10-01T12:10:11+03:00

## Checks

| result | check | detail |
|---|---|---|
| PASS | agent ran the whole time without crashing or restarting | 91 samples, 1 start time(s), 0 crash lines |
| PASS | agent memory stable (median RSS last third ≤ 1.3 × first third, after warm-up) | 62 → 63 MiB (×1.02), max 65 MiB |
| PASS | agent heap stable (≤ 1.3×) | 7 → 7 MiB |
| PASS | goroutines bounded | 23–26 |
| PASS | no kernel ringbuf drops | 0 |
| PASS | ≥ 99.9 % of forwarded server queries linked to their client query | 1265488 exact, 45 inferred, 1 orphan, 1103 internal, 28 none |
| PASS | every kept trace reached VictoriaTraces (±0.1 %) | 158327 stored / 158327 kept |
| PASS | no exporter errors in agent log | 0 lines |
| PASS | big (truncated) statements traced and linked | 9484/9484 truncated client roots linked exactly |
| PASS | every error trace kept (invalid JSON + pgbouncer admin errors) | 538 invalid-JSON, 538 admin-console roots; 538 of each sent |
| PASS | load streams ran to completion | big: 0 aborted, ext: 0 aborted, churn: 0 aborted |

## Load

| stream | tps | transactions | failed (retried out) | avg latency ms |
|---|---:|---:|---:|---:|
| big | 20.023897 | 108129 | 0 | 43.437 |
| ext | 149.867729 | 809292 | 0 | 19.062 |
| churn | 20.138856 | 108749 | 0 | 9.896 |

## Resources (averages over the run)

- duration: 1.51 h, 91 samples
- client queries: 1266072 (233/s), server queries: 1266664
- kernel events: 51327066 (9463/s)
- agent CPU: 0.05 cores; pgbouncer: 0.04; postgres: 2.29
- agent RSS: min 55 MiB, max 65 MiB
- traces: kept 158327 (error 1587, slow 33481, ratio 123259), dropped by sampling 1107978
- truncated client roots stored: 9484

Per-minute samples: `samples.csv`. pgbench progress: `stream-*.log`. Agent log: `agent.log`.
