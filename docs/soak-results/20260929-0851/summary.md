# Soak test 20260929-0851

duration_s: 5400  
started: 2026-09-29T08:51:31+03:00  
sample_ratio: 0.1  
agent_container: f5bd74e4558bb5b8a644a7b6409d2900dc6a2b41cb9cad0a96e8f4b157f29eee 2026-09-29T05:51:29.270829523Z  
cpu: AMD Ryzen 7 7700X 8-Core Processor (16 threads)  
memory: 61 GiB  
kernel: 7.2.7-arch1-1  
pgbouncer: PgBouncer 1.25.2  
postgres: postgres (PostgreSQL) 17.11 (Debian 17.11-1.pgdg13+2)  
finished: 2026-09-29T10:21:56+03:00

## Checks

| result | check | detail |
|---|---|---|
| PASS | agent ran the whole time without crashing or restarting | 91 samples, 1 start time(s), 0 crash lines |
| **FAIL** | agent memory stable (median RSS last third ≤ 1.3 × first third, after warm-up) | 65 → 191 MiB (×2.92), max 279 MiB |
| **FAIL** | agent heap stable (≤ 1.3×) | 11 → 95 MiB |
| PASS | goroutines bounded | 14–17 |
| PASS | no kernel ringbuf drops | 0 |
| **FAIL** | ≥ 99.9 % of forwarded server queries linked to their client query | 1199741 exact, 7 inferred, 25007 orphan, 1080 internal, 184 none |
| PASS | every kept trace reached VictoriaTraces (±0.1 %) | 158571 stored / 158571 kept |
| PASS | no exporter errors in agent log | 0 lines |
| **FAIL** | big (truncated) statements traced and linked | 8540/8972 truncated client roots linked exactly |
| PASS | every error trace kept (invalid JSON + pgbouncer admin errors) | 538 invalid-JSON, 538 admin-console roots; 538 of each sent |
| PASS | load streams ran to completion | big: 0 aborted, ext: 0 aborted, churn: 0 aborted |

## Load

| stream | tps | transactions | failed (retried out) | avg latency ms |
|---|---:|---:|---:|---:|
| big | 19.957522 | 107770 | 0 | 65.536 |
| ext | 150.098953 | 810533 | 0 | 17.550 |
| churn | 19.977993 | 107881 | 0 | 7.517 |

## Resources (averages over the run)

- duration: 1.51 h, 91 samples
- client queries: 1265367 (233/s), server queries: 1226019
- kernel events: 51557581 (9504/s)
- agent CPU: 0.04 cores; pgbouncer: 0.04; postgres: 2.33
- agent RSS: min 59 MiB, max 279 MiB
- traces: kept 158571 (error 1632, slow 31479, ratio 125460), dropped by sampling 1132191
- truncated client roots stored: 8972

Per-minute samples: `samples.csv`. pgbench progress: `stream-*.log`. Agent log: `agent.log`.
