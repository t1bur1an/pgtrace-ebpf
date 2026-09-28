# Soak test 20260928-2137

duration_s: 5400  
started: 2026-09-28T21:37:53+03:00  
sample_ratio: 0.1  
agent_container: 29e1119e77d672e2fc1b5c6a916ad8fa51e218028185720962ef7be46c934e67 2026-09-28T18:37:51.070743443Z  
cpu: AMD Ryzen 7 7700X 8-Core Processor (16 threads)  
memory: 61 GiB  
kernel: 7.2.7-arch1-1  
pgbouncer: PgBouncer 1.25.2  
postgres: postgres (PostgreSQL) 17.11 (Debian 17.11-1.pgdg13+2)  
finished: 2026-09-28T23:08:17+03:00

## Checks

| result | check | detail |
|---|---|---|
| PASS | agent ran the whole time without crashing or restarting | 91 samples, 1 start time(s), 0 crash lines |
| PASS | agent memory stable (median RSS last third ≤ 1.3 × first third, after warm-up) | 63 → 65 MiB (×1.03), max 67 MiB |
| PASS | agent heap stable (≤ 1.3×) | 7 → 7 MiB |
| PASS | goroutines bounded | 14–16 |
| PASS | no kernel ringbuf drops | 0 |
| PASS | ≥ 99.9 % of forwarded server queries linked to their client query | 1265951 exact, 3 inferred, 0 orphan, 0 internal, 1355 none |
| PASS | every kept trace reached VictoriaTraces (±0.1 %) | 148828 stored / 148828 kept |
| PASS | no exporter errors in agent log | 0 lines |
| PASS | big (truncated) statements traced and linked | 8892/8892 truncated client roots linked exactly |
| PASS | every error trace kept (invalid JSON + pgbouncer admin errors) | 538 invalid-JSON, 538 admin-console roots; 538 of each sent |
| PASS | load streams ran to completion | big: 0 aborted, ext: 0 aborted, churn: 0 aborted |

## Load

| stream | tps | transactions | failed (retried out) | avg latency ms |
|---|---:|---:|---:|---:|
| big | 20.009653 | 108049 | 0 | 55.619 |
| ext | 149.975928 | 809869 | 0 | 16.078 |
| churn | 20.137475 | 108742 | 0 | 6.970 |

## Resources (averages over the run)

- duration: 1.51 h, 91 samples
- client queries: 1266494 (233/s), server queries: 1267309
- kernel events: 51691890 (9530/s)
- agent CPU: 0.05 cores; pgbouncer: 0.03; postgres: 2.23
- agent RSS: min 57 MiB, max 67 MiB
- traces: kept 148828 (error 1590, slow 23131, ratio 124107), dropped by sampling 1119230
- truncated client roots stored: 8892

Per-minute samples: `samples.csv`. pgbench progress: `stream-*.log`. Agent log: `agent.log`.
