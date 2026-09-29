# Soak test export-20260929-1704

duration_s: 5400  
started: 2026-09-29T17:05:00+03:00  
sample_ratio: 0.1  
agent_container: 1b4312df8fd4098996eb815b6a12c9d11d21a97dcd30632eb39e954f48cd8c2a 2026-09-29T14:04:58.166152633Z  
cpu: AMD Ryzen 7 7700X 8-Core Processor (16 threads)  
memory: 61 GiB  
kernel: 7.2.7-arch1-1  
pgbouncer: PgBouncer 1.25.2  
postgres: postgres (PostgreSQL) 17.11 (Debian 17.11-1.pgdg13+2)  
finished: 2026-09-29T18:35:24+03:00

## Checks

| result | check | detail |
|---|---|---|
| PASS | agent ran the whole time without crashing or restarting | 91 samples, 1 start time(s), 0 crash lines |
| PASS | agent memory stable (median RSS last third ≤ 1.3 × first third, after warm-up) | 141 → 142 MiB (×1.00), max 143 MiB |
| PASS | agent heap stable (≤ 1.3×) | 76 → 75 MiB |
| PASS | goroutines bounded | 23–28 |
| PASS | no kernel ringbuf drops | 0 |
| PASS | ≥ 99.9 % of forwarded server queries linked to their client query | 1263786 exact, 22 inferred, 1 orphan, 1102 internal, 117 none |
| PASS | every kept trace reached VictoriaTraces (±0.1 %) | 151986 stored / 151986 kept |
| PASS | no exporter errors in agent log | 0 lines |
| PASS | big (truncated) statements traced and linked | 9279/9279 truncated client roots linked exactly |
| PASS | every error trace kept (invalid JSON + pgbouncer admin errors) | 538 invalid-JSON, 538 admin-console roots; 538 of each sent |
| PASS | load streams ran to completion | big: 0 aborted, ext: 0 aborted, churn: 0 aborted |

## Load

| stream | tps | transactions | failed (retried out) | avg latency ms |
|---|---:|---:|---:|---:|
| big | 19.921423 | 107577 | 0 | 43.909 |
| ext | 149.869506 | 809318 | 0 | 17.354 |
| churn | 20.017181 | 108090 | 0 | 8.507 |

## Resources (averages over the run)

- duration: 1.51 h, 91 samples
- client queries: 1264348 (233/s), server queries: 1265028
- kernel events: 51276943 (9454/s)
- agent CPU: 0.03 cores; pgbouncer: 0.04; postgres: 2.21
- agent RSS: min 77 MiB, max 143 MiB
- traces: kept 151986 (error 1617, slow 26871, ratio 123498), dropped by sampling 1112684
- truncated client roots stored: 9279

Per-minute samples: `samples.csv`. pgbench progress: `stream-*.log`. Agent log: `agent.log`.
