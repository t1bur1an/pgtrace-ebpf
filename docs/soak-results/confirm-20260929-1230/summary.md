# Soak test confirm-20260929-1230

duration_s: 5400  
started: 2026-09-29T12:30:51+03:00  
sample_ratio: 0.1  
agent_container: db54689a629c972a3d9c2c95ba47c5bf1e1885cf233d9bdb640a6755da1f8c5b 2026-09-29T09:30:49.004912989Z  
cpu: AMD Ryzen 7 7700X 8-Core Processor (16 threads)  
memory: 61 GiB  
kernel: 7.2.7-arch1-1  
pgbouncer: PgBouncer 1.25.2  
postgres: postgres (PostgreSQL) 17.11 (Debian 17.11-1.pgdg13+2)  
finished: 2026-09-29T14:01:15+03:00

## Checks

| result | check | detail |
|---|---|---|
| PASS | agent ran the whole time without crashing or restarting | 91 samples, 1 start time(s), 0 crash lines |
| PASS | agent memory stable (median RSS last third ≤ 1.3 × first third, after warm-up) | 71 → 71 MiB (×1.00), max 74 MiB |
| PASS | agent heap stable (≤ 1.3×) | 13 → 12 MiB |
| PASS | goroutines bounded | 14–17 |
| PASS | no kernel ringbuf drops | 0 |
| PASS | ≥ 99.9 % of forwarded server queries linked to their client query | 1008930 exact, 6937 inferred, 6 orphan, 1082 internal, 126 none |
| PASS | every kept trace reached VictoriaTraces (±0.1 %) | 156387 stored / 156387 kept |
| PASS | no exporter errors in agent log | 0 lines |
| PASS | big (truncated) statements traced and linked | 7740/7740 truncated client roots linked exactly |
| PASS | every error trace kept (invalid JSON + pgbouncer admin errors) | 528 invalid-JSON, 528 admin-console roots; 528 of each sent |
| PASS | load streams ran to completion | big: 0 aborted, ext: 0 aborted, churn: 0 aborted |

## Load

| stream | tps | transactions | failed (retried out) | avg latency ms |
|---|---:|---:|---:|---:|
| big | 17.248970 | 93223 | 56 | 169978.747 |
| ext | 110.314404 | 596202 | 53 | 155616.837 |
| churn | 19.534718 | 105488 | 0 | 95673.155 |

## Resources (averages over the run)

- duration: 1.51 h, 91 samples
- client queries: 1016397 (187/s), server queries: 1017077
- kernel events: 39728781 (7325/s)
- agent CPU: 0.04 cores; pgbouncer: 0.03; postgres: 2.09
- agent RSS: min 60 MiB, max 74 MiB
- traces: kept 156387 (error 4631, slow 56108, ratio 95648), dropped by sampling 860346
- truncated client roots stored: 7740

Per-minute samples: `samples.csv`. pgbench progress: `stream-*.log`. Agent log: `agent.log`.
