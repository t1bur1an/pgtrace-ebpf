# Configurable capture caps, truncation metrics, bounded metric cardinality and opt-in labelled metrics — design

Date: 2026-09-28
Builds on: `2026-09-28-client-correlation-and-observability-design.md`

## Goals

1. Let the operator choose how much of each message is kept at each layer,
   with memory allocated per message according to its real size (up to the cap).
2. Show whether and where truncation happens.
3. Guarantee and document a bounded number of Prometheus series for long and
   production runs.
4. Offer opt-in per-database, per-user and per-client-IP metrics with a hard cap.

## 1. Caps

| flag | default | bounds | layer |
|---|---|---|---|
| `-capture-bytes` | 4096 | 64 … 16384 | kernel: bytes copied per send/recv syscall |
| `-max-message-bytes` | 65536 | ≥ 64, no upper bound | parser: bytes of one message body kept |
| `-max-query-text` | 2048 | ≥ 16 | export: `db.query.text` length (UTF-8 safe cut) |

- **Kernel.** The BPF program gets a `const volatile __u32 capture_bytes` global,
  set through the `.rodata` spec before load (cilium/ebpf `Variables`).
  `MAX_PAYLOAD` becomes a compile-time ceiling of 16384 (the per-CPU scratch
  value must stay under the 32 KiB per-CPU allocation limit; header + 16 KiB
  fits). The copy length is `min(ret, capture_bytes, MAX_PAYLOAD)`. Values
  outside the bounds are rejected at startup.
- **Parser.** `pgwire.NewConn`/`NewClientConn` take `Options{MaxMessage int}`
  (0 = default). When a message header shows the body will be kept and the
  message is incomplete, the reassembly buffer is allocated once with capacity
  `min(1+len, MaxMessage)` (plus the bytes already in hand) instead of growing
  by `append` doubling. It is released (`nil`) when the message completes.
  Messages whose bodies aren't read are never buffered (unchanged).
- **Export.** `export.New(..., Options{MaxQueryText int})`.

## 2. Truncation metric

`pgtrace_truncations_total{layer}` with `layer` ∈ `kernel`, `parser`, `export`:

- kernel: a Data event with `TotalLen > len(Payload)` (counted in the agent),
- parser: a message cut at `MaxMessage` (the parser reports a count in `Result.Truncated`),
- export: `db.query.text` shortened to `MaxQueryText` (the exporter calls a hook).

## 3. Cardinality

- `sqlstate` label: at most 300 distinct values per process; later new values
  are counted as `OTHER`. `operation` stays a fixed list of 37 + `OTHER`.
- `docs/metrics.md` lists every metric, its labels, all possible values, and
  its maximum number of series, the total ceiling, and a real scrape from the
  soak run with the measured series count.
- A unit test floods the metrics with random label inputs and asserts the
  gathered series count is ≤ the documented ceiling.

## 4. Opt-in labelled client metrics

| flag | default | meaning |
|---|---|---|
| `-metrics-labels` | "" (off) | comma list of `database`, `user`, `client_addr` |
| `-metrics-label-limit` | 200 | max distinct label combinations tracked at once |
| `-metrics-label-ttl` | 30m | a combination idle this long is deleted (frees its slot) |

Families (only the enabled labels are present, in the order database, user,
client_addr):

- `pgtrace_client_queries_total`
- `pgtrace_client_errors_total`
- `pgtrace_client_query_duration_seconds` (histogram, same buckets)
- `pgtrace_client_pool_wait_seconds` (histogram)
- `pgtrace_metrics_label_sets` (gauge, combinations currently tracked)
- `pgtrace_metrics_label_overflow_total` (counter, observations folded into `other`)

Values: `database`/`user` come from the client's startup parameters (`unknown`
if not seen); `client_addr` is the client IP (`unix` for unix sockets,
`unknown` if not known). When the limit is reached, a new combination is
recorded with every enabled label set to `other`. Eviction runs from the
agent's one-second tick using the monotonic clock. Ceiling:
`limit × 32` series (2 counters + 2 histograms × (12 buckets + +Inf + sum + count)), plus the
`other` combination.

## Testing

- pgwire: allocation for a 1 MiB statement with MaxMessage 64 KiB ≤ 64 KiB + one
  chunk; a 300-byte query allocates ≤ 300 + chunk; MaxMessage 1 MiB keeps the
  whole 450 KB statement; truncation count reported.
- export: MaxQueryText respected; hook called when shortening.
- metrics: truncation counter per layer; sqlstate cap; cardinality flood test;
  labelled metrics: disabled labels absent, limit → `other` + overflow, TTL
  eviction frees a slot, series ≤ ceiling.
- agent: kernel truncation counted from a short payload.
- e2e: agent runs with `-metrics-labels=database,user,client_addr` and
  `-capture-bytes=8192`; checks `pgtrace_client_pool_wait_seconds_count{database="tiny"}` > 0,
  `pgtrace_truncations_total{layer="parser"}` > 0 after a > 64 KiB statement,
  and that the agent log reports `capture_bytes=8192`.
