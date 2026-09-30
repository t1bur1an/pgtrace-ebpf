# Soak test tls-20260930-0316

duration_s: 1800  
started: 2026-09-30T03:16:19+03:00  
sample_ratio: 0.1  
agent_container: d903f3958c1dcb4bdc73d39e32a9cbd6cc7705285ae6c06c6f8cc7c24af5e7ea 2026-09-30T00:16:16.317607352Z  
cpu: AMD Ryzen 7 7700X 8-Core Processor (16 threads)  
memory: 61 GiB  
kernel: 7.2.7-arch1-1  
pgbouncer: PgBouncer 1.25.2  
postgres: postgres (PostgreSQL) 17.11 (Debian 17.11-1.pgdg13+2)  
finished: 2026-09-30T03:47:37+03:00

## Checks

| result | check | detail |
|---|---|---|
| PASS | agent ran the whole time without crashing or restarting | 32 samples, 1 start time(s), 0 crash lines |
| PASS | agent memory stable (median RSS last third ≤ 1.3 × first third, after warm-up) | 66 → 64 MiB (×0.98), max 68 MiB |
| PASS | agent heap stable (≤ 1.3×) | 9 → 9 MiB |
| PASS | goroutines bounded | 18–25 |
| PASS | no kernel ringbuf drops | 0 |
| **FAIL** | ≥ 99.9 % of forwarded server queries linked to their client query | 377704 exact, 12 inferred, 44457 orphan, 376 internal, 42 none |
| PASS | every kept trace reached VictoriaTraces (±0.1 %) | 52021 stored / 52016 kept |
| PASS | no exporter errors in agent log | 0 lines |
| PASS | big (truncated) statements traced and linked | 3061/3067 truncated client roots linked exactly |
| PASS | every error trace kept (invalid JSON + pgbouncer admin errors) | 180 invalid-JSON, 180 admin-console roots; 180 of each sent |
| PASS | load streams ran to completion | big: 0 aborted, ext: 0 aborted, churn: 0 aborted |

## Load

| stream | tps | transactions | failed (retried out) | avg latency ms |
|---|---:|---:|---:|---:|
| big | 20.152075 | 36275 | 0 | 133.123 |
| ext | 149.685798 | 269610 | 0 | 19.346 |
| churn | 20.136130 | 36245 | 0 | 11.399 |

## Resources (averages over the run)

- duration: 0.52 h, 32 samples
- client queries: 377930 (201/s), server queries: 422574
- kernel events: 17691960 (9421/s)
- agent CPU: 0.05 cores; pgbouncer: 0.08; postgres: 2.22
- agent RSS: min 60 MiB, max 68 MiB
- traces: kept 52016 (error 630, slow 10189, ratio 41197), dropped by sampling 370600
- truncated client roots stored: 3067

Per-minute samples: `samples.csv`. pgbench progress: `stream-*.log`. Agent log: `agent.log`.
