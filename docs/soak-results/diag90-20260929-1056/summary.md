# Soak test diag90-20260929-1056

duration_s: 5400  
started: 2026-09-29T10:56:56+03:00  
sample_ratio: 0.1  
agent_container: d3a3b2b7612b2cb6bc6ac4891d8f8ecb6594911b5784a6bd280b667d4727e721 2026-09-29T07:56:55.268732074Z  
cpu: AMD Ryzen 7 7700X 8-Core Processor (16 threads)  
memory: 61 GiB  
kernel: 7.2.7-arch1-1  
pgbouncer: PgBouncer 1.25.2  
postgres: postgres (PostgreSQL) 17.11 (Debian 17.11-1.pgdg13+2)  
finished: 2026-09-29T12:27:21+03:00

## Checks

| result | check | detail |
|---|---|---|
| PASS | agent ran the whole time without crashing or restarting | 91 samples, 1 start time(s), 0 crash lines |
| PASS | agent memory stable (median RSS last third ≤ 1.3 × first third, after warm-up) | 72 → 72 MiB (×1.00), max 77 MiB |
| PASS | agent heap stable (≤ 1.3×) | 12 → 14 MiB |
| PASS | goroutines bounded | 14–17 |
| PASS | no kernel ringbuf drops | 0 |
| **FAIL** | ≥ 99.9 % of forwarded server queries linked to their client query | 1255817 exact, 9 inferred, 7364 orphan, 1102 internal, 176 none |
| PASS | every kept trace reached VictoriaTraces (±0.1 %) | 148497 stored / 148497 kept |
| PASS | no exporter errors in agent log | 0 lines |
| PASS | big (truncated) statements traced and linked | 8835/8835 truncated client roots linked exactly |
| PASS | every error trace kept (invalid JSON + pgbouncer admin errors) | 538 invalid-JSON, 538 admin-console roots; 538 of each sent |
| PASS | load streams ran to completion | big: 0 aborted, ext: 0 aborted, churn: 0 aborted |

## Load

| stream | tps | transactions | failed (retried out) | avg latency ms |
|---|---:|---:|---:|---:|
| big | 20.001661 | 108010 | 0 | 38.397 |
| ext | 149.898666 | 809574 | 0 | 16.695 |
| churn | 19.950791 | 107733 | 0 | 7.548 |

## Resources (averages over the run)

- duration: 1.51 h, 91 samples
- client queries: 1256364 (232/s), server queries: 1264463
- kernel events: 51570106 (9508/s)
- agent CPU: 0.05 cores; pgbouncer: 0.03; postgres: 2.18
- agent RSS: min 57 MiB, max 77 MiB
- traces: kept 148497 (error 1506, slow 23202, ratio 123789), dropped by sampling 1115606
- truncated client roots stored: 8835

Per-minute samples: `samples.csv`. pgbench progress: `stream-*.log`. Agent log: `agent.log`.
