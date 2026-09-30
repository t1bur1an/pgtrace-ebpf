# Soak test tls-20260930-0910

duration_s: 1800  
started: 2026-09-30T09:10:56+03:00  
sample_ratio: 0.1  
agent_container: 218637bf936a52405b1dad8e203d24e81f820c457e7fa78bd863e9246837409d 2026-09-30T06:10:53.563608999Z  
cpu: AMD Ryzen 7 7700X 8-Core Processor (16 threads)  
memory: 61 GiB  
kernel: 7.2.7-arch1-1  
pgbouncer: PgBouncer 1.25.2  
postgres: postgres (PostgreSQL) 17.11 (Debian 17.11-1.pgdg13+2)  
finished: 2026-09-30T09:42:15+03:00

## Checks

| result | check | detail |
|---|---|---|
| PASS | agent ran the whole time without crashing or restarting | 32 samples, 1 start time(s), 0 crash lines |
| PASS | agent memory stable (median RSS last third ≤ 1.3 × first third, after warm-up) | 58 → 65 MiB (×1.12), max 69 MiB |
| PASS | agent heap stable (≤ 1.3×) | 6 → 8 MiB |
| PASS | goroutines bounded | 17–26 |
| PASS | no kernel ringbuf drops | 0 |
| PASS | ≥ 99.9 % of forwarded server queries linked to their client query | 420270 exact, 8 inferred, 0 orphan, 376 internal, 21 none |
| PASS | every kept trace reached VictoriaTraces (±0.1 %) | 52078 stored / 52078 kept |
| PASS | no exporter errors in agent log | 0 lines |
| PASS | big (truncated) statements traced and linked | 3117/3117 truncated client roots linked exactly |
| PASS | every error trace kept (invalid JSON + pgbouncer admin errors) | 180 invalid-JSON, 180 admin-console roots; 180 of each sent |
| PASS | load streams ran to completion | big: 0 aborted, ext: 0 aborted, churn: 0 aborted |

## Load

| stream | tps | transactions | failed (retried out) | avg latency ms |
|---|---:|---:|---:|---:|
| big | 20.062263 | 36111 | 0 | 86.794 |
| ext | 149.407252 | 268929 | 0 | 21.052 |
| churn | 19.899001 | 35817 | 0 | 11.922 |

## Resources (averages over the run)

- duration: 0.52 h, 32 samples
- client queries: 420458 (224/s), server queries: 420675
- kernel events: 17689085 (9419/s)
- agent CPU: 0.05 cores; pgbouncer: 0.09; postgres: 2.26
- agent RSS: min 54 MiB, max 69 MiB
- traces: kept 52078 (error 570, slow 10915, ratio 40593), dropped by sampling 368605
- truncated client roots stored: 3117

Per-minute samples: `samples.csv`. pgbench progress: `stream-*.log`. Agent log: `agent.log`.
