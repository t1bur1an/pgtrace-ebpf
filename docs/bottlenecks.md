# Bottlenecks at 100 % sampling

> **Status (2026-09-29):** fixes 1–3 and the capture-gap detection are done:
> own exporter, direct OTLP encoding, GC settings and TCP-offset gap
> detection. See [After the fixes](#after-the-fixes) at the end. The
> measurements below are the "before" state.

Measured on 2026-09-29 with `scripts/perf_sampling.sh`: 1,000 pgbench clients,
select-only, through one pgbouncer (pool 20), 30 s per run, 3 repetitions.
Everything runs on one 8-core / 16-thread box. The agent has client tracing,
per-client labels and parameter-sync attach enabled. Raw data:
`docs/perf-results/sampling/`; CPU profile: `profiles/cpu-ratio-1.pb.gz`.

## Measurements

| | agent off | 10 % sampling | 100 % sampling |
|---|---:|---:|---:|
| TPS | 84 534 ± 490 | 67 790 ± 138 (−19.8 %) | 61 004 ± 274 (−27.8 %) |
| avg latency | 11.83 ms | 14.75 ms | 16.39 ms |
| agent CPU / RSS | — | 0.74 core / 82 MB | **2.03 cores / 328 MB** |
| spans created per second | — | 13 264 | **119 549** |
| spans delivered per second | — | 13 264 (all) | **91 620** |
| spans lost per 30 s run | — | 0 | **≈ 838 k (23 %)** |
| kernel ringbuf drops | — | 0 | 0 |
| VictoriaTraces CPU / RSS | 6 % / 1.2 GB | 15 % / 1.4 GB | 81 % / 1.9 GB |

"Lost" is `pgtrace_export_spans_total{stage="created"} − {stage="exported"}`
after the run drained. No export batch failed. The spans were dropped by the
OpenTelemetry batch span processor when its queue (65,536) was full, and it
drops silently. Before this measurement the agent had no metric that could
show it.

## Sustained 100 % sampling at moderate rates is fine

A 30-minute soak at 100 % sampling with the big-JSON workload (~225 client
queries/s, ~470 spans/s; `docs/soak-results/full-sampling-*`) passed every
check:
- all 845,249 created spans were delivered, and 422,563 of 422,563 kept
  traces were stored;
- agent RSS 69–78 MiB, heap 11–13 MiB;
- 0 orphans, 0 kernel drops, 25,494 of 25,494 truncated statements linked.

So the limits below only apply at high rates. Loss starts above ~91 k
spans/s, i.e. ~45 k client queries/s at 100 % sampling (a client and a server
span per query), or ~450 k queries/s at 10 %.

## 1. Export throughput caps at ~91 k spans/s and drops the rest silently

Delivered spans per second were **91,433 / 91,433 / 91,993** in the three
runs, a hard ceiling. The batch span processor has one export goroutine that
sends one batch of 2,048 spans and waits for the HTTP response before
building the next, so each batch takes ~22 ms. That goroutine used ~0.4 core
(protobuf marshalling 12 % of agent CPU, OTLP conversion 6 %). The rest is
waiting on the round trip and on VictoriaTraces ingesting (81 % of a core).
Above the ceiling the queue fills and spans are dropped.

**Proposed fix:** a small exporter of our own instead of the SDK's batch
processor. N concurrent export workers (default 4), larger batches (8,192),
and a bounded queue whose drops are counted in `pgtrace_export_spans_total{stage="dropped"}`.
Expected: throughput scales with workers until VictoriaTraces becomes the
limit, and any loss is visible.

## 2. Garbage collection is a third of the agent's CPU

`runtime.gcBgMarkWorker` accounts for ~35 % of samples. Allocation comes mostly
from building spans through the OpenTelemetry SDK (a `recordingSpan`,
attribute slices and a snapshot per span) and from the OTLP protobuf
conversion when exporting.

**Proposed fix, in order of effort:**
- (a) Set `GOGC`/`GOMEMLIMIT` in the image (e.g. `GOGC=400`, `GOMEMLIMIT=512MiB`).
  This trades memory for CPU with no code change.
- (b) Build OTLP protobuf messages directly from our query structs in the
  exporter from 1, skipping the SDK's span objects, and reuse buffers.
  That removes most per-span allocations.

## 3. Span building runs on the event loop

The agent's single event goroutine consumes kernel events, parses,
correlates, and also builds spans (~19 % of agent CPU at 100 %). At 60 k
client queries/s it used ~0.8 core. It's the one part that can't use more
cores, and if it saturates, the kernel ringbuf overflows and data is lost
before sampling even applies.

**Proposed fix:** hand kept traces to export workers over a bounded channel,
so the event loop only parses and correlates, and span building happens on
other cores. That fits naturally with 1.

## 4. Throughput cost grows with sampling (−20 % → −28 % TPS)

Parsing and correlation cost the same at any sampling ratio. The extra
~8 points at 100 % are the agent's extra 1.3 cores and VictoriaTraces' extra
0.7 core, competing with pgbench, pgbouncer and postgres on the same 16
threads. On a dedicated pgbouncer host with the trace backend elsewhere, most
of that contention goes away. Fixes 1–3 reduce the agent's share.

## 5. VictoriaTraces sizing

Ingesting ~92 k spans/s took ~0.8 core, and its RSS grew with stored data
(1.2 → 2.1 GB over the benchmark). 100 % sampling of a busy pgbouncer needs
a trace backend sized for ~120 k spans/s per 60 k queries/s (a client and a
server span per query).

## Also found: capture events skipped by the kernel

Found in the soak investigation, not the sampling benchmark, but it's an
architectural limit of the capture. fentry/fexit programs on
`sendto`/`recvfrom` run for every process on the host, and the kernel's
recursion protection skips a run when another instance is active on the CPU.
The diagnostic soak counted 210 skipped `recvfrom` runs and 2 skipped `sendto`
runs in 1.5 h. When a skipped run was pgbouncer's, its bytes were lost and a
parser misaligned. The length checks now detect this within a message.
**Proposed fix:** record the TCP stream position per event, so gaps are
known exactly and skipped cleanly, plus a `pgtrace_bpf_recursion_misses_total`
metric.

## After the fixes

Same benchmark and machine (`scripts/perf_sampling.sh`, 1,000 clients, 3 × 30 s).
Raw data: `docs/perf-results/sampling-own-exporter/`.

The agent now has its own exporter. The event loop hands kept traces to a
bounded queue. 4 workers encode OTLP protobuf directly and each POSTs its own
8,192-span batches. The image sets `GOGC=200` and `GOMEMLIMIT=768MiB`.

| | before, 10 % | after, 10 % | before, 100 % | after, 100 % |
|---|---:|---:|---:|---:|
| TPS (agent off ≈ 84 900) | 67 790 | 68 021 | 61 004 | 61 385 |
| agent CPU | 0.74 core | **0.49 core** | 2.03 cores | **0.67 core** |
| agent RSS (peak) | 82 MB | 182 MB | 328 MB | 272 MB |
| spans created per second | 13 264 | 13 308 | 119 549 | 120 309 |
| spans delivered per second | 13 264 | 13 308 | 91 620 | **120 309 (all)** |
| spans lost per 30 s run | 0 | 0 | ≈ 838 k | **0** (queue drops 0, failed batches 0) |
| GC share of agent CPU | | | 35 % | **1.3 %** |
| event loop (`Agent.Run`) | | | 0.82 core | 0.43 core |
| VictoriaTraces CPU | 15 % | 15 % | 81 % | 115 % |

- **1. Export ceiling:** gone. Every span was delivered at 120 k spans/s, and
  the queue never filled. If it does fill, the loss shows up in
  `pgtrace_export_spans_total{stage="dropped"}`.
- **2. GC:** direct encoding into reused buffers removed nearly all per-span
  allocation. Encoding a two-span trace takes about 1 µs and 2 small
  allocations (`BenchmarkEncodeTrace`).
- **3. Event loop:** span building runs on the workers (17 % of agent CPU).
  The event loop is now parsing and correlation only, at 0.43 core for
  60 k client queries/s. That leaves about 2× headroom on this machine
  before it saturates one core.
- **4. TPS cost:** unchanged, −20 % at 10 % and −28 % at 100 %. The agent now
  uses about 1.4 cores less, but VictoriaTraces ingests 30 % more spans and
  uses about 0.35 core more. The remaining cost is the kernel capture and the
  competition for the shared 16 threads (see 4 above), not the export.
- **RSS** is higher at 10 % (82 → 182 MB) and lower at 100 % (328 → 272 MB).
  The workers keep their batch buffers, and `GOGC=200` lets the heap grow
  larger between collections. With GC at 1.3 %, `GOGC=200` buys little. The
  default (100) would likely return most of that memory.
