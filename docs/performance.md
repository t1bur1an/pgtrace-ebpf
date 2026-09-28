# pgtrace performance

What it costs to trace pgbouncer traffic with pgtrace, and how much it can
handle. Raw data is in `docs/perf-results/`; everything here can be reproduced
with `scripts/perf.sh` and `go test -bench`.

The agent has two modes. **Client + server** (`-client-tracing=true`, the
default) traces the client side too and links each client query to its server
query. **Server-only** (`-client-tracing=false`) traces only pgbouncer →
postgres. [Client tracing](#client-tracing-and-correlation) compares both. The
sections after it were measured with the server-only version and still
describe that mode.

## TL;DR

| question | answer |
|---|---|
| Throughput cost, CPU-bound, trivially cheap queries (worst case), **client + server tracing** | **−17 % TPS** at 8–64 clients (≈ 88 k client queries/s); −3 % at 1 client |
| Same, **server-only** tracing | **−10 % … −13 % TPS** at 8–64 clients (≈ 90 k queries/s); −1 % … −3.5 % at 1 client |
| Latency added per query (same workload) | **+10 µs** at 8 clients (75 → 85 µs), +2 µs at 1 client |
| Where it goes | −3.7 %: fexit trampolines on every `sendto`/`recvfrom` on the host (paid even by pgbench and postgres); −7.7 %: capturing pgbouncer's server traffic + agent; −1 %: optional BPF run-time stats |
| In-kernel cost | ≈ 10 BPF program runs per query host-wide, **≈ 95 ns per run** (with stats accounting on) |
| Agent CPU / memory at ≈ 90 k queries/s | client + server: **0.7 core**, **70 MiB** at sample ratio 0.1; **2.1 cores**, 310 MiB exporting every trace (2 spans each). Server-only: 0.3–0.4 core, 60–70 MiB |
| Highest rate tested | 93 k queries/s through a single pgbouncer (pgbouncer + postgres + pgbench on one 8-core box were the limit, not the agent) |
| Loss | **0 kernel ringbuf drops** in every run; **4 119 410 / 4 119 410** spans the agent kept arrived in VictoriaTraces |
| Agent userspace capacity (projected from benchmarks) | ≈ 650 k client queries/s/core through parse + correlate; ≈ 400 k exported spans/s/core |

For real workloads where queries take milliseconds rather than tens of
microseconds, the relative cost is proportionally smaller: the absolute cost is
roughly **1 µs of kernel CPU and 3 µs of agent CPU per query** (see
[Cost model](#cost-model)).

## Client tracing and correlation

`pgbench -S -M simple`, 20 s per run, 3 repetitions, configurations alternated
(`client-tracing.csv`). "Server-only" is `-client-tracing=false`. Both on runs
use sample ratio 0.1, `-bpf-stats`, and the Prometheus metrics endpoint.

| clients | off TPS | server-only | client + server | agent CPU (server-only → client+server) | agent mem | BPF ns/run |
|---:|---:|---:|---:|---|---:|---|
| 1 | 21 976 ± 195 | 21 473 (−2.3 %) | 21 325 (**−3.0 %**) | 10 % → 20 % | 67 MiB | 104 → 127 |
| 8 | 106 934 ± 448 | 93 267 (−12.8 %) | 88 207 (**−17.5 %**) | 38 % → 73 % | 70 MiB | 94 → 121 |
| 64 | 89 675 ± 214 | 78 473 (−12.5 %) | 74 412 (**−17.0 %**) | 33 % → 68 % | 72 MiB | 88 → 113 |

Spread between repetitions was under 0.5 %. There were 0 kernel drops.

- **Client tracing adds about 4.5 TPS points** on this worst-case workload. The
  kernel now copies payloads for pgbouncer's client-side syscalls too (4 copied
  payloads per query instead of 2; BPF ns/run rises about 25 %). The agent parses
  both sides and runs the correlator, which roughly doubles its CPU. The agent
  competes for the same 8 cores as pgbench, pgbouncer and postgres here.
- **Server-only mode uses more agent CPU than the first version** (38 % vs
  28 % at 8 clients). The difference is the Prometheus metrics, which observe
  every query (≈ 0.24 µs per trace, `BenchmarkObserveTrace`), plus signature
  hashing in the parser.
- **Exporting everything** (ratio 1.0, 64 clients, 2 spans per trace): 70 155
  TPS (−22 % vs off), agent 2.1 cores and 311 MiB, 1.4 M traces exported in
  20 s with 0 drops.
- **Correlation quality** from `make e2e` (pgbench simple/extended/prepared,
  4 clients): 4 288 exact + 1 inferred of 4 290 sampled client queries; every
  server child's time range lay inside its root and had identical SQL. The
  agent's counters for the whole run: 42 115 exact, 3 inferred, 8 none (pgbouncer
  `server_check_query`), 0 internal, 0 orphan.

Agent userspace cost per client query, from the Go benchmarks on the same CPU
(`bench.txt`):

| benchmark | ns/op |
|---|---:|
| `Pipeline`: client recv + server send + server recv + client send through connmap, both parsers and the correlator | 1 535 |
| `ObserveTrace`: Prometheus metrics for one trace | 241 |
| `Export`: one span into the batch processor | 2 486 |
| `ConnSimpleQuery` / `ConnExtendedQuery`: one parser round trip | 438 / 779 |

At ratio 0.1 that is ≈ 1.5 + 0.24 + 0.1 × 2 × 2.5 ≈ **2.3 µs of agent CPU per
client query** before ringbuf/decode overhead. Measured end-to-end, it was
0.73 core at 88 k/s ≈ 8.3 µs, including decode, channel hand-off, the Go
runtime and GC.

**Cost model with client tracing:** about 1.2 µs of kernel CPU (≈ 10 runs ×
120 ns) and 8 µs of agent CPU per client query. For example, 10 k client
queries/s costs about 0.012 core in the kernel and 0.08 core in the agent.

## Setup

| | |
|---|---|
| CPU | AMD Ryzen 7 7700X, 8 cores / 16 threads |
| RAM | 61 GiB |
| Kernel | 7.2.7-arch1-1 |
| Stack | docker 29.8.1; PgBouncer 1.25.2 (transaction pooling, `default_pool_size=20`); PostgreSQL 17.11; VictoriaTraces latest |
| Load | `pgbench` (scale 10) in a container on the same host, through pgbouncer |
| Agent | commit of this document; `sample-ratio=0.1`, `slow-ms=100`, `bpf-stats=true` unless noted |
| Duration | 20 s per run (30 s for the attribution runs) |

Everything — load generator, pgbouncer, postgres, VictoriaTraces and the agent
— shares one machine, so the agent competes with the workload for CPU. That
makes these numbers pessimistic.

How each column is measured:

- **TPS / latency**: pgbench's own report.
- **pgbouncer / agent CPU**: `usage_usec` delta of the container's cgroup
  `cpu.stat` over the run (100 % = one core). BPF programs run in the context of
  the task making the syscall, so kernel-side probe cost of pgbouncer's own
  syscalls shows up in pgbouncer's CPU.
- **agent memory**: peak cgroup `memory.current`, sampled every second.
- **queries/s, kept, drops, BPF ns/run, runs/query**: the agent's stats log
  (kernel run-time accounting via `BPF_STATS_RUN_TIME`).

## Results

### Read-only, CPU-bound (worst case)

`pgbench -S` — one indexed primary-key `SELECT` per transaction. Queries are as
cheap as possible, so per-query overhead is as visible as possible.

| protocol | clients | TPS off | TPS on | Δ | latency off → on (ms) | pgbouncer CPU off → on | agent CPU | agent mem |
|---|---:|---:|---:|---:|---|---|---:|---:|
| simple | 1 | 21 763 | 21 022 | −3.4 % | 0.046 → 0.048 | 25 → 26 % | 8 % | 62 MiB |
| simple | 8 | 106 583 | 92 442 | −13.3 % | 0.075 → 0.087 | 62 → 65 % | 29 % | 65 MiB |
| simple | 32 | 102 779 | 91 915 | −10.6 % | 0.311 → 0.348 | 60 → 64 % | 30 % | 69 MiB |
| simple | 64 | 90 467 | 79 069 | −12.6 % | 0.707 → 0.809 | 66 → 69 % | 26 % | 63 MiB |
| extended | 1 | 19 586 | 19 096 | −2.5 % | 0.051 → 0.052 | 23 → 24 % | 9 % | 61 MiB |
| extended | 8 | 103 989 | 89 747 | −13.7 % | 0.077 → 0.089 | 62 → 65 % | 36 % | 63 MiB |
| extended | 32 | 97 957 | 87 956 | −10.2 % | 0.327 → 0.364 | 61 → 64 % | 37 % | 66 MiB |
| extended | 64 | 87 822 | 76 177 | −13.3 % | 0.729 → 0.840 | 67 → 69 % | 33 % | 59 MiB |

Kernel drops were 0 in every run, BPF cost was 88–106 ns per program run, and
there were 10–11 program runs per query.

**Repeatability** (8 clients, simple, off/on alternated, 3 repetitions): off
107 795 / 106 837 / 107 265, on 93 870 / 93 857 / 93 575 → **−12.6 %**, spread
under 1 %.

### Write-heavy, CPU-bound

`pgbench` TPC-B-like (7 statements per transaction: BEGIN, 3 UPDATE, SELECT,
INSERT, END), with `synchronous_commit=off` and checkpoints pushed out so that
the disk is not the bottleneck. 3 repetitions, off/on alternated.

| clients | TPS off | TPS on | Δ | queries/s on | agent CPU |
|---:|---|---|---:|---:|---:|
| 8 | 15 151 / 14 855 / 14 949 | 13 267 / 13 271 / 13 262 | **−11.5 %** | ≈ 92 800 | 27 % |
| 32 | 14 192 / 14 254 / 14 183 | 12 806 / 12 787 / 12 748 | **−10.1 %** | ≈ 89 400 | 27 % |

Same cost as the read-only test at the same query rate. The overhead is per
query; it doesn't depend on the kind of statement.

### Write-heavy with durable commits (disk-bound)

The same TPC-B-like load with default `synchronous_commit=on` is limited by
fsync latency on this desktop NVMe, and the results swing by 5–7× between
identical runs. With the agent off, 8-client runs gave 8 178, 8 082, 7 527,
5 637, 6 040 and 1 586 TPS, and 32-client runs gave 2 227, 2 206, 10 894 and
9 521. Once the drive's write cache is exhausted, TPS
settles at about 1 590 whether or not the agent is running:

| run (8 clients, 30 s) | agent off | agent on, ratio 0 | agent on, ratio 0.1 |
|---|---:|---:|---:|
| 1 | 6 040 | 6 253 | 1 586 |
| 2 | 1 586 | 1 584 | 1 588 |
| 3 | 1 590 | 1 588 | 2 997 |

These runs can't resolve a percentage-level overhead, and the variance comes
from storage, not tracing. At the ~11 k queries/s this load reaches, the
CPU-bound results above put the agent's cost around 0.03 cores. Raw data:
`results.csv`, `repeats.csv`, `tpcb-fsync-attribution.txt`.

### Overhead breakdown

`pgbench -S -M simple -c 8`, 20 s × 3 repetitions per configuration:

| configuration | TPS (mean ± sd) | Δ vs off |
|---|---:|---:|
| agent off | 106 587 ± 184 | — |
| probes attached, no process traced | 102 669 ± 254 | −3.7 % |
| tracing pgbouncer | 94 409 ± 306 | −11.4 % |
| tracing pgbouncer + BPF run-time stats | 93 325 ± 122 | −12.4 % |

- **Attached, idle (−3.7 %)**: fexit programs run on every `sendto`/`recvfrom`
  on the host and exit after one hash lookup (is this pid pgbouncer?). In this
  test pgbench, the postgres backends and pgbouncer all pay it. On a dedicated
  pgbouncer host only pgbouncer's own syscalls would.
- **Tracing (−7.7 % more)**: copying payloads (≤ 4 KiB) of pgbouncer's
  server-side syscalls into the ringbuf, plus the agent's ≈ 0.28 core of
  userspace work competing for the same CPUs.
- **BPF stats (−1 %)**: two clock reads per program run. Off by default
  (`-bpf-stats`).

### Export every query (stress)

64 clients, `sample-ratio=1.0`, so every query becomes a span:

| protocol | TPS | queries/s | spans exported in 20 s | agent CPU | agent mem | drops |
|---|---:|---:|---:|---:|---:|---:|
| simple | 74 046 | 73 851 | 1 477 013 | 102 % | 124 MiB | 0 |
| extended | 71 180 | 71 011 | 1 420 216 | 109 % | 89 MiB | 0 |

Compared with ratio 0.1 at the same client count (79 069 / 76 177 TPS),
exporting everything costs a further 6–7 % TPS and about 0.75 core, almost all
of it in the OpenTelemetry SDK and the OTLP/HTTP protobuf encoding. Over the
whole matrix, VictoriaTraces stored **exactly** the 4 119 410 spans the agent
reported keeping.

### Userspace micro-benchmarks

`go test -bench . -count 3` on the same CPU (`bench.txt`); median of 3:

| benchmark | what | ns/op | allocs/op |
|---|---|---:|---:|
| `ConnSimpleQuery` | parse one simple-protocol round trip (Q → T, D, C, Z) | 348 | 15 |
| `ConnExtendedQuery` | parse Parse/Bind/Describe/Execute/Sync + responses | 666 | 21 |
| `Pipeline` | connmap lookup + parse + sample (ratio 0.1) per query | 477 | 15 |
| `Export` | build one span and hand it to the batch processor | 2 525 | 17 |

These exclude ringbuf reading, decoding and network export. Measured
end-to-end, the agent used 0.28 core at 93 k queries/s, about **3 µs of agent
CPU per query** at ratio 0.1, so one core of agent handles roughly
**300 k queries/s** at ratio 0.1. That is projected, not tested: a single
pgbouncer on this box tops out near 107 k queries/s.

## Cost model

Per query through pgbouncer, at ratio 0.1:

| where | cost | notes |
|---|---:|---|
| kernel, BPF | ≈ 10 runs × 95 ns ≈ **1 µs** CPU | 2 runs copy payload (pgbouncer's server-side send and recv); the rest exit early: pgbouncer's client-side sockets (filtered), pgbench and postgres syscalls |
| pgbouncer | +1.1 µs CPU per query | 5.75 → 6.89 µs of pgbouncer CPU per query (61.6 % / 106.6 k/s → 64.6 % / 92.4 k/s), i.e. its share of the probe cost above |
| agent | ≈ **3 µs** CPU | ringbuf read + decode + parse + sample; export of the 10 % kept adds ~0.25 µs |
| export, per kept span | ≈ 2.5 µs CPU + OTLP bytes | only spans that are kept |

Example: 10 k queries/s costs about 0.01 core of kernel time and 0.03 core of
agent time. At 50 k queries/s it is about 0.05 + 0.15 cores.

## Limits and caveats

- **pgbouncer is single-threaded.** The probe cost of its own syscalls
  (≈ 1.1 µs per query) comes straight out of its CPU budget. A pgbouncer that
  is already near 100 % of one core loses throughput in proportion, about
  16 % at 6.9 µs per query here. The fix is the usual one for a saturated
  pgbouncer: run several processes (`so_reuseport`); the agent traces all
  processes with the same name.
- **Payload cap.** At most 4 KiB is captured per syscall. Longer SQL is
  exported truncated (`pgtrace.truncated=true`). The parser also buffers at
  most 64 KiB of any message and skips result rows by length, so large results
  don't grow agent memory.
- **Ringbuf.** 16 MiB. The reader is woken once 1 MiB is pending and otherwise
  drains every 20 ms, so a stalled agent has roughly 16 MiB / (≈ 200 bytes per
  event × 2 events per query) ≈ 40 k queries of headroom before the kernel
  starts dropping (counted as `kernel_drops`). No drops happened in any test,
  including the stress runs.
- **Host-wide probe cost.** fexit programs run for every `sendto`/`recvfrom` on
  the machine, not only pgbouncer's. For untraced processes the program exits
  after one hash lookup, but the trampoline still costs something: that is the
  −3.7 % "attached, idle" row, where pgbench and postgres share the host. On a
  dedicated pgbouncer host only pgbouncer pays it.
- **Worst-case workload.** These queries are 20–70 µs round trips. With 1 ms
  queries, the same 4 µs per query is well under 1 %.

## How the numbers got here

The first implementation used `syscalls:sys_{enter,exit}_*` tracepoints
(sendto, recvfrom, read, write, connect, close), a fixed 4 KiB ringbuf
reservation per event and a wakeup per event. Same workload (8 clients,
select-only, 5 s smoke runs):

| version | TPS Δ | agent CPU | BPF ns/run | runs/query |
|---|---:|---:|---:|---:|
| syscall tracepoints, wakeup per event | −35 % | 116 % | 214 | 20 |
| + in-kernel fd filter, batched wakeups | −19 % | 28 % | 86 | 20 |
| fexit/fentry instead of tracepoints (final) | −12.5 % | 30 % | 94 | 10 |

- **Syscall tracepoints** set `TIF_SYSCALL_TRACEPOINT` on every task, which sends
  *every* syscall on the host through the slow path. fexit on
  `__sys_sendto`/`__sys_recvfrom`/`__sys_connect` only costs those functions,
  and one program now sees arguments and return value together (no enter/exit
  map). `read`/`write` capture was dropped because pgbouncer uses send/recv.
- **In-kernel fd filter.** Once the agent learns an fd isn't a postgres
  connection (for example a client socket), it marks it in a BPF map and the
  kernel stops copying that fd's payload. This halved ringbuf traffic.
- **Batched wakeups.** `BPF_RB_NO_WAKEUP` until 1 MiB is pending, and the
  reader polls every 20 ms. This removed one context switch per event.

## Reproduce

```bash
go test -run '^$' -bench . -count 3 ./internal/pgwire ./internal/agent ./internal/export
DURATION=20 ./scripts/perf.sh                     # full matrix + repeats + tpcb nosync + breakdown (~35 min)
SKIP_MATRIX=1 SKIP_REPEATS=1 SKIP_NOSYNC=1 SKIP_BREAKDOWN=1 ./scripts/perf.sh   # only the client-tracing comparison
```

Files written to `docs/perf-results/`: `results.csv` (matrix and stress),
`repeats.csv`, `tpcb-nosync.csv`, `client-tracing.csv`, `breakdown.csv`, `completeness.txt`,
`host.txt`, plus `bench.txt` and `tpcb-fsync-attribution.txt` from the commands
above.
