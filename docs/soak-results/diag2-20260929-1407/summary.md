# Soak test diag2-20260929-1407

duration_s: 5400  
started: 2026-09-29T14:07:14+03:00  
sample_ratio: 0.1  
agent_container: 8bd3397e6adca399ae755bdf3a651aea9704e031a12135bb0bc0ebde63115ede 2026-09-29T11:07:12.15363721Z  
cpu: AMD Ryzen 7 7700X 8-Core Processor (16 threads)  
memory: 61 GiB  
kernel: 7.2.7-arch1-1  
pgbouncer: PgBouncer 1.25.2  
postgres: postgres (PostgreSQL) 17.11 (Debian 17.11-1.pgdg13+2)  
finished: 2026-09-29T15:37:38+03:00

## Checks

| result | check | detail |
|---|---|---|
| PASS | agent ran the whole time without crashing or restarting | 91 samples, 1 start time(s), 0 crash lines |
| PASS | agent memory stable (median RSS last third ≤ 1.3 × first third, after warm-up) | 72 → 72 MiB (×1.00), max 75 MiB |
| PASS | agent heap stable (≤ 1.3×) | 13 → 13 MiB |
| PASS | goroutines bounded | 14–17 |
| PASS | no kernel ringbuf drops | 0 |
| **FAIL** | ≥ 99.9 % of forwarded server queries linked to their client query | 1229455 exact, 14 inferred, 36441 orphan, 1108 internal, 146 none |
| PASS | every kept trace reached VictoriaTraces (±0.1 %) | 159332 stored / 159332 kept |
| PASS | no exporter errors in agent log | 0 lines |
| **FAIL** | big (truncated) statements traced and linked | 8830/9113 truncated client roots linked exactly |
| PASS | every error trace kept (invalid JSON + pgbouncer admin errors) | 538 invalid-JSON, 538 admin-console roots; 538 of each sent |
| PASS | load streams ran to completion | big: 0 aborted, ext: 0 aborted, churn: 0 aborted |

## Load

| stream | tps | transactions | failed (retried out) | avg latency ms |
|---|---:|---:|---:|---:|
| big | 20.029167 | 108160 | 0 | 44.102 |
| ext | 150.057512 | 810320 | 0 | 16.884 |
| churn | 20.081155 | 108437 | 0 | 7.869 |

## Resources (averages over the run)

- duration: 1.51 h, 91 samples
- client queries: 1266451 (233/s), server queries: 1267164
- kernel events: 51517627 (9498/s)
- agent CPU: 0.04 cores; pgbouncer: 0.03; postgres: 2.25
- agent RSS: min 62 MiB, max 75 MiB
- traces: kept 159332 (error 1578, slow 30374, ratio 127380), dropped by sampling 1143910
- truncated client roots stored: 9113

Per-minute samples: `samples.csv`. pgbench progress: `stream-*.log`. Agent log: `agent.log`.
