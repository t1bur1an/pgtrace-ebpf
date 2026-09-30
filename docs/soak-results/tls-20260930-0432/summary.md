# Soak test tls-20260930-0432

duration_s: 1800  
started: 2026-09-30T04:32:38+03:00  
sample_ratio: 0.1  
agent_container: a84103a91b6e90e784906436a6fa941ac96607d978f337765e7fcbe65465b182 2026-09-30T01:32:36.230872318Z  
cpu: AMD Ryzen 7 7700X 8-Core Processor (16 threads)  
memory: 61 GiB  
kernel: 7.2.7-arch1-1  
pgbouncer: PgBouncer 1.25.2  
postgres: postgres (PostgreSQL) 17.11 (Debian 17.11-1.pgdg13+2)  
finished: 2026-09-30T05:03:57+03:00

## Checks

| result | check | detail |
|---|---|---|
| PASS | agent ran the whole time without crashing or restarting | 32 samples, 1 start time(s), 0 crash lines |
| PASS | agent memory stable (median RSS last third ≤ 1.3 × first third, after warm-up) | 66 → 66 MiB (×1.00), max 68 MiB |
| PASS | agent heap stable (≤ 1.3×) | 7 → 7 MiB |
| PASS | goroutines bounded | 17–26 |
| PASS | no kernel ringbuf drops | 0 |
| PASS | ≥ 99.9 % of forwarded server queries linked to their client query | 419671 exact, 8 inferred, 0 orphan, 376 internal, 31 none |
| PASS | every kept trace reached VictoriaTraces (±0.1 %) | 50592 stored / 50592 kept |
| PASS | no exporter errors in agent log | 0 lines |
| PASS | big (truncated) statements traced and linked | 3016/3016 truncated client roots linked exactly |
| PASS | every error trace kept (invalid JSON + pgbouncer admin errors) | 180 invalid-JSON, 180 admin-console roots; 180 of each sent |
| PASS | load streams ran to completion | big: 0 aborted, ext: 0 aborted, churn: 0 aborted |

## Load

| stream | tps | transactions | failed (retried out) | avg latency ms |
|---|---:|---:|---:|---:|
| big | 19.951160 | 35912 | 0 | 41.614 |
| ext | 149.483583 | 269248 | 0 | 17.370 |
| churn | 19.884761 | 35792 | 0 | 11.279 |

## Resources (averages over the run)

- duration: 0.52 h, 32 samples
- client queries: 419859 (224/s), server queries: 420086
- kernel events: 17706185 (9428/s)
- agent CPU: 0.04 cores; pgbouncer: 0.09; postgres: 2.05
- agent RSS: min 57 MiB, max 68 MiB
- traces: kept 50592 (error 513, slow 8996, ratio 41083), dropped by sampling 369502
- truncated client roots stored: 3016

Per-minute samples: `samples.csv`. pgbench progress: `stream-*.log`. Agent log: `agent.log`.
