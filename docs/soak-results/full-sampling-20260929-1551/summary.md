# Soak test full-sampling-20260929-1551

duration_s: 1800  
started: 2026-09-29T15:51:20+03:00  
sample_ratio: 1  
agent_container: fa259bf54e59906f09ddb07bd5bc8d182030f3a0064124d1961eec48bf01b1b2 2026-09-29T12:51:19.064848909Z  
cpu: AMD Ryzen 7 7700X 8-Core Processor (16 threads)  
memory: 61 GiB  
kernel: 7.2.7-arch1-1  
pgbouncer: PgBouncer 1.25.2  
postgres: postgres (PostgreSQL) 17.11 (Debian 17.11-1.pgdg13+2)  
finished: 2026-09-29T16:22:39+03:00

## Checks

| result | check | detail |
|---|---|---|
| PASS | agent ran the whole time without crashing or restarting | 32 samples, 1 start time(s), 0 crash lines |
| PASS | agent memory stable (median RSS last third ≤ 1.3 × first third, after warm-up) | 69 → 75 MiB (×1.08), max 78 MiB |
| PASS | agent heap stable (≤ 1.3×) | 11 → 13 MiB |
| PASS | goroutines bounded | 13–17 |
| PASS | no kernel ringbuf drops | 0 |
| PASS | ≥ 99.9 % of forwarded server queries linked to their client query | 422097 exact, 4 inferred, 0 orphan, 376 internal, 78 none |
| PASS | every kept trace reached VictoriaTraces (±0.1 %) | 422563 stored / 422563 kept |
| PASS | no exporter errors in agent log | 0 lines |
| PASS | big (truncated) statements traced and linked | 25494/25494 truncated client roots linked exactly |
| PASS | every error trace kept (invalid JSON + pgbouncer admin errors) | 180 invalid-JSON, 180 admin-console roots; 180 of each sent |
| PASS | load streams ran to completion | big: 0 aborted, ext: 0 aborted, churn: 0 aborted |

## Load

| stream | tps | transactions | failed (retried out) | avg latency ms |
|---|---:|---:|---:|---:|
| big | 20.236565 | 36427 | 0 | 110.476 |
| ext | 149.471359 | 269058 | 0 | 20.142 |
| churn | 20.101083 | 36181 | 0 | 7.910 |

## Resources (averages over the run)

- duration: 0.52 h, 32 samples
- client queries: 422281 (225/s), server queries: 422555
- kernel events: 17142270 (9123/s)
- agent CPU: 0.05 cores; pgbouncer: 0.03; postgres: 2.15
- agent RSS: min 60 MiB, max 78 MiB
- traces: kept 422563 (error 607, slow 8714, ratio 413242), dropped by sampling 0
- truncated client roots stored: 25494

Per-minute samples: `samples.csv`. pgbench progress: `stream-*.log`. Agent log: `agent.log`.
