# Soak test diag-20260929-1023

duration_s: 1800  
started: 2026-09-29T10:23:55+03:00  
sample_ratio: 1  
agent_container: de2593711144ba990069ca39cec86837a8ef75f53bfbd27f6479e88185777338 2026-09-29T07:23:53.068954032Z  
cpu: AMD Ryzen 7 7700X 8-Core Processor (16 threads)  
memory: 61 GiB  
kernel: 7.2.7-arch1-1  
pgbouncer: PgBouncer 1.25.2  
postgres: postgres (PostgreSQL) 17.11 (Debian 17.11-1.pgdg13+2)  
finished: 2026-09-29T10:55:13+03:00

## Checks

| result | check | detail |
|---|---|---|
| PASS | agent ran the whole time without crashing or restarting | 32 samples, 1 start time(s), 0 crash lines |
| PASS | agent memory stable (median RSS last third ≤ 1.3 × first third, after warm-up) | 70 → 70 MiB (×1.00), max 81 MiB |
| PASS | agent heap stable (≤ 1.3×) | 13 → 10 MiB |
| PASS | goroutines bounded | 14–17 |
| PASS | no kernel ringbuf drops | 0 |
| PASS | ≥ 99.9 % of forwarded server queries linked to their client query | 421879 exact, 1 inferred, 0 orphan, 376 internal, 85 none |
| PASS | every kept trace reached VictoriaTraces (±0.1 %) | 422349 stored / 422349 kept |
| PASS | no exporter errors in agent log | 0 lines |
| PASS | big (truncated) statements traced and linked | 25480/25480 truncated client roots linked exactly |
| PASS | every error trace kept (invalid JSON + pgbouncer admin errors) | 180 invalid-JSON, 180 admin-console roots; 180 of each sent |
| PASS | load streams ran to completion | big: 0 aborted, ext: 0 aborted, churn: 0 aborted |

## Load

| stream | tps | transactions | failed (retried out) | avg latency ms |
|---|---:|---:|---:|---:|
| big | 20.047775 | 36090 | 0 | 81.706 |
| ext | 149.847742 | 269724 | 0 | 16.686 |
| churn | 20.095211 | 36171 | 0 | 7.406 |

## Resources (averages over the run)

- duration: 0.52 h, 32 samples
- client queries: 422060 (225/s), server queries: 422341
- kernel events: 17242037 (9181/s)
- agent CPU: 0.05 cores; pgbouncer: 0.03; postgres: 2.17
- agent RSS: min 62 MiB, max 81 MiB
- traces: kept 422349 (error 544, slow 8244, ratio 413561), dropped by sampling 0
- truncated client roots stored: 25480

Per-minute samples: `samples.csv`. pgbench progress: `stream-*.log`. Agent log: `agent.log`.
