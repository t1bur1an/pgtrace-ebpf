# Soak test tls-20261001-1906

duration_s: 1800  
started: 2026-10-01T19:06:54+03:00  
sample_ratio: 0.1  
agent_container: da7d8710af30f927bc3fdb47cfe3f0eafbc3b67e95a1e7e24422ad1ac86b4b3d 2026-10-01T16:06:52.700014336Z  
cpu: AMD Ryzen 7 7700X 8-Core Processor (16 threads)  
memory: 61 GiB  
kernel: 7.2.7-arch1-1  
pgbouncer: PgBouncer 1.25.2  
postgres: postgres (PostgreSQL) 17.11 (Debian 17.11-1.pgdg13+2)  
finished: 2026-10-01T19:38:13+03:00

## Checks

| result | check | detail |
|---|---|---|
| PASS | agent ran the whole time without crashing or restarting | 32 samples, 1 start time(s), 0 crash lines |
| PASS | agent memory stable (median RSS last third ≤ 1.3 × first third, after warm-up) | 67 → 67 MiB (×1.00), max 69 MiB |
| PASS | agent heap stable (≤ 1.3×) | 8 → 7 MiB |
| PASS | goroutines bounded | 18–26 |
| PASS | no kernel ringbuf drops | 0 |
| PASS | ≥ 99.9 % of forwarded server queries linked to their client query | 421536 exact, 9 inferred, 0 orphan, 376 internal, 23 none |
| PASS | every kept trace reached VictoriaTraces (±0.1 %) | 51550 stored / 51550 kept |
| PASS | no exporter errors in agent log | 0 lines |
| PASS | big (truncated) statements traced and linked | 3247/3247 truncated client roots linked exactly |
| PASS | every error trace kept (invalid JSON + pgbouncer admin errors) | 180 invalid-JSON, 180 admin-console roots; 180 of each sent |
| PASS | load streams ran to completion | big: 0 aborted, ext: 0 aborted, churn: 0 aborted |

## Load

| stream | tps | transactions | failed (retried out) | avg latency ms |
|---|---:|---:|---:|---:|
| big | 19.940156 | 35891 | 0 | 39.077 |
| ext | 149.914750 | 269841 | 0 | 18.054 |
| churn | 20.138836 | 36250 | 0 | 11.391 |

## Resources (averages over the run)

- duration: 0.52 h, 32 samples
- client queries: 421725 (225/s), server queries: 421944
- kernel events: 17722027 (9437/s)
- agent CPU: 0.05 cores; pgbouncer: 0.09; postgres: 2.13
- agent RSS: min 61 MiB, max 69 MiB
- traces: kept 51550 (error 497, slow 10016, ratio 41037), dropped by sampling 370402
- truncated client roots stored: 3247

Per-minute samples: `samples.csv`. pgbench progress: `stream-*.log`. Agent log: `agent.log`.
