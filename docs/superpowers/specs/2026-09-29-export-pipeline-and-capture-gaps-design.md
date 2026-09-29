# Export pipeline and capture gaps — design

Date: 2026-09-29. Approved by the user: A (own exporter), B (direct OTLP
encoding), C (GC tuning), D (TCP-sequence gap detection). Context and
measurements: `docs/bottlenecks.md`.

## D. Detect skipped capture bytes exactly

The kernel's fentry/fexit recursion protection sometimes skips a run of our
`sendto`/`recvfrom` programs, and those bytes never reach the agent.

- **Kernel.** For events of traced processes only, the program reads the TCP
  stream position of the socket: task → files → fdtable → file →
  `private_data` (struct socket) → `sk`. This is only done for AF_INET/AF_INET6
  sockets with protocol TCP, using CO-RE reads through minimal
  `preserve_access_index` struct definitions (no vmlinux.h).
  - send: `tcp_sock.write_seq − ret`, the stream offset of the first byte sent;
  - recv: `tcp_sock.copied_seq − ret`, the offset of the first byte received.

  The event header gains `seq u32` and `flags u32` (bit 0 = seq valid), so the
  header grows from 48 to 56 bytes. `fd` is bounds-checked against
  `fdtable.max_fds`.
- **Agent.** Per connection and direction it remembers the next expected
  offset. For a valid event whose `seq` is ahead of it by `gap` bytes (u32
  wrap-around; a jump of 2³¹ or more is treated as out of order and ignored),
  the parser first skips `gap` bytes:
  - bytes inside the current message's remainder are skipped losslessly
    (discard) or truncate that message;
  - otherwise the stream resynchronises (counted), exactly like the existing
    kernel-truncation path, which is refactored into the same `skip(n)`.
- **Metrics.**
  - `pgtrace_capture_gaps_total{side}` counts gaps and
    `pgtrace_capture_gap_bytes_total{side}` their size (4 series);
  - `pgtrace_bpf_recursion_misses_total{program}` (5 series) comes from the
    kernel's per-program stats, which don't need `-bpf-stats`.
- Unix-socket connections have no sequence; for them the length checks stay
  the only guard.

## A + B. Own OTLP exporter

The OpenTelemetry SDK's batch span processor exports one batch at a time and
silently drops spans when its 65,536-span queue is full; that capped us at
~91 k spans/s with 23 % loss. Its span objects and the protobuf conversion
also cause most of the GC load.

- **Pipeline.** The sink (on the event loop) samples and then enqueues a
  `job{trace, client info, reason, server addresses}` into a bounded channel
  (`-export-queue`, default 65,536 traces). If the channel is full, the job is
  dropped and counted, and the event loop never blocks.
- **Workers.** `-export-workers` (default 4) goroutines turn jobs into OTLP
  spans, encoding them straight into the worker's reusable request buffer with
  `protowire` (no SDK span objects, no generated protobuf structs). A batch is
  sent when it reaches `-export-batch` spans (default 8,192) or
  `-export-interval` (default 1 s) passes. Each worker POSTs its own batches,
  so up to N requests are in flight.
- **Encoding.** One `ExportTraceServiceRequest` per batch, with one
  `ResourceSpans` (resource attribute `service.name`) and one `ScopeSpans`
  (scope `github.com/t1bur1an/pgtrace-ebpf`). Spans carry the same attributes,
  kinds, status and parent/child structure as before; SQLCommenter parents
  set the trace ID and parent span ID. IDs come from a per-worker PCG
  generator.
- **HTTP.** `POST` with `Content-Type: application/x-protobuf` to the same
  endpoint, on a shared `http.Client` with keep-alive and a 10 s timeout.
  2xx means delivered. A failure is counted and the batch dropped: no retry,
  so a stalled backend can't back up the agent.
- **Counters** (`pgtrace_export_spans_total{stage}`): `created` (encoded),
  `exported` (delivered), `failed_batches`, `dropped` (queue full, counted in
  spans the trace would have produced). Plus `pgtrace_export_queue_length`
  (gauge). That adds 2 series.
- **Shutdown.** Close the queue, workers flush their last batch (bounded by
  a 5 s context).
- **Tests** decode the produced requests with the official
  `go.opentelemetry.io/proto/otlp` types and check every field: IDs,
  parentage, kinds, times, attributes, status, resource and scope. An
  `httptest` server checks batching, concurrency, failure counting and queue
  overflow.

## C. GC tuning

The image sets `GOGC=200` and `GOMEMLIMIT=768MiB`; both are overridable
through the environment. The values are to be re-checked against the
benchmark after A+B, since B removes most of the allocation.

## Verification

- unit tests (race);
- `scripts/perf_sampling.sh` at 1,000 clients: expect export ≈ created at
  100 % sampling and lower agent CPU;
- e2e, contention, and a 90-minute soak at 10 % sampling with the flight
  recorder: expect capture gaps counted and skipped, orphans ≈ 0.
