# pgtrace metrics

The agent serves Prometheus metrics on `-metrics-addr` (default `:9464`,
path `/metrics`). The metrics are computed from **every** query, not only the
sampled traces.

**Cardinality is bounded by design.** Every label has a fixed or capped set of
values, and no label carries SQL text, a client port, an fd or any other
per-connection value. On a long or production run the number of series
reaches a ceiling and stays there; only the counter *values* grow. The
ceiling is computed in code (`metrics.MaxSeries`) and enforced by a test that
floods the metrics with random operations, SQLSTATEs, databases, users and
addresses (`internal/metrics/cardinality_test.go`).

## Base metrics (always on)

| metric | type | labels and their possible values | max series |
|---|---|---|---:|
| `pgtrace_queries_total` | counter | `side` = client, server · `operation` = 36 SQL keywords + `OTHER` · `protocol` = simple, extended | 148 |
| `pgtrace_query_duration_seconds` | histogram (12 buckets, 50 µs … 3 s) | `side` · `operation` | 1 110 |
| `pgtrace_query_errors_total` | counter | `side` · `sqlstate` = up to 300 distinct 5-char codes + `OTHER` | 602 |
| `pgtrace_connection_errors_total` | counter | `side` · `sqlstate` (same cap): errors with no query in flight, e.g. rejected logins | 602 |
| `pgtrace_pool_wait_seconds` | histogram | – | 15 |
| `pgtrace_idle_in_transaction_seconds` | histogram | – : gaps where a client sat idle inside a transaction | 15 |
| `pgtrace_correlation_total` | counter | `result` = exact, inferred, internal, none, orphan | 5 |
| `pgtrace_spans_total` | counter | `decision` = kept_error, kept_slow, kept_parent, kept_ratio, dropped | 5 |
| `pgtrace_events_total` | counter | `kind` = data, connect, accept, close | 4 |
| `pgtrace_truncations_total` | counter | `layer` = kernel, parser, export | 3 |
| `pgtrace_trace_context_total` | counter | `result` = linked, not_per_execution, invalid (SQLCommenter) | 3 |
| `pgtrace_connections` | gauge | `side` = client, server · `tls` = true, false | 4 |
| `pgtrace_correlator_entries` | gauge | `kind` = queued, held, inflight, unattributed, paramsync | 5 |
| `pgtrace_parser_resyncs_total` | counter | `side` = client, server: a parser lost its place and resynchronised | 2 |
| `pgtrace_export_spans_total` | counter | `stage` = created (encoded), exported (delivered), dropped (export queue full; spans the trace would have had), failed_batches (counts batches, not spans). created − exported = spans in unsent or failed batches | 4 |
| `pgtrace_export_queue_length` | gauge | – : traces waiting for an export worker | 1 |
| `pgtrace_capture_gaps_total`, `pgtrace_capture_gap_bytes_total` | counter | `side` = client, server: jumps in a connection's TCP stream offset, i.e. capture events the kernel skipped | 4 |
| `pgtrace_traced_processes` | gauge | – | 1 |
| `pgtrace_kernel_drops_total` | counter | – | 1 |
| `pgtrace_bpf_run_seconds_total`, `pgtrace_bpf_runs_total` | counter | – (only with `-bpf-stats`) | 2 |
| `pgtrace_bpf_recursion_misses_total` | counter | `program`: runs the kernel skipped because another run was active on the CPU | 5 |
| **base ceiling** | | | **2 541** |

The `operation` keywords are SELECT, INSERT, UPDATE, DELETE, BEGIN, COMMIT,
END, ROLLBACK, SET, SHOW, WITH, COPY, CREATE, ALTER, DROP, TRUNCATE, VACUUM,
ANALYZE, EXPLAIN, CALL, DO, FETCH, DECLARE, CLOSE, DISCARD, LISTEN, NOTIFY,
PREPARE, EXECUTE, DEALLOCATE, RESET, LOCK, GRANT, REVOKE, COMMENT and MERGE.
Anything else is `OTHER`.

`sqlstate`: PostgreSQL defines about 260 codes. The first 300 distinct valid
codes seen by the process get their own label value, and later new ones are
counted as `OTHER`, so garbage or an unusual server can't create unbounded
series.

A histogram series count is its 12 buckets + `+Inf` + `_sum` + `_count` = 15.

The Go and process collectors (`go_*`, `process_*`) add about 45 series
(44 in the scrape below).

## With -tls-capture

| metric | type | labels | series |
|---|---|---|---:|
| `pgtrace_tls_processes` | gauge | `state` = attached, unsupported | 2 |
| `pgtrace_tls_fallback_attached` | gauge | – : 1 while the socket-finding fallback for pre-existing sessions is attached | 1 |
| `pgtrace_tls_unresolved_total` | counter | `result` = resolved, dropped: TLS events captured before their socket was known | 2 |
| `pgtrace_bpf_recursion_misses_total` | counter | 11 more `program` values (the TLS probes and the fallback) | 11 |

That adds 16 series: the ceiling is 2 557 without client labels and 8 991
with the default label limit.

## Opt-in per-client metrics

Enabled with `-metrics-labels` (any of `database`, `user`, `client_addr`).
Only the enabled labels are present, always in that order.

| metric | type | series per label combination |
|---|---|---:|
| `pgtrace_client_queries_total` | counter | 1 |
| `pgtrace_client_errors_total` | counter | 1 |
| `pgtrace_client_query_duration_seconds` | histogram | 15 |
| `pgtrace_client_pool_wait_seconds` | histogram | 15 |
| `pgtrace_metrics_label_sets` | gauge: combinations tracked now | (1 total) |
| `pgtrace_metrics_label_overflow_total` | counter: observations recorded as `other` | (1 total) |

Label values:
- `database` and `user` come from the client's startup packet. They're
  `unknown` for connections opened before the agent started.
- `client_addr` is the client IP (not the port, which changes on every
  reconnect), or `unix` for unix-socket clients.

**Cap.** At most `-metrics-label-limit` combinations (default 200) are tracked
at once. When the limit is reached, a new combination is recorded with every
label set to `other`, so totals stay correct, and
`pgtrace_metrics_label_overflow_total` counts those observations. A combination
not seen for `-metrics-label-ttl` (default 30 min) is deleted, which frees its
slot. That keeps short-lived clients from occupying the cap forever. A deleted
combination that comes back starts its counters from zero, which Prometheus
`rate()` handles as a reset.

**Ceiling** = base + (limit + 1) × 32 + 2:

| `-metrics-label-limit` | max pgtrace series |
|---:|---:|
| labels off | 2 541 |
| 50 | 4 175 |
| 200 (default) | 8 975 |
| 1 000 | 34 575 |

Choose the limit from your Prometheus budget. If
`pgtrace_metrics_label_overflow_total` keeps rising, there are more active
combinations than the limit. Either raise the limit, drop `client_addr`
(usually the largest dimension), or shorten the TTL.

## Measured

A real scrape from an e2e run (pgbench in three modes, error cases, a 100 KB
statement, pool pressure on `tiny`, all three client labels enabled) had **545
pgtrace series** (589 with Go/process). The breakdown below is from that run.
The latest e2e run (2026-09-29, with the capture-gap, recursion-miss and
export-queue series) had 577. The series actually present depend on
which operations, SQLSTATEs and clients occurred, never on how long the agent
has been running:

```
  390 pgtrace_query_duration_seconds      45 pgtrace_client_query_duration_seconds
   36 pgtrace_queries_total               30 pgtrace_client_pool_wait_seconds
   15 pgtrace_pool_wait_seconds            5 pgtrace_query_errors_total
    4 pgtrace_events_total                 4 pgtrace_spans_total
    3 pgtrace_correlation_total            3 pgtrace_client_queries_total
    2 pgtrace_truncations_total            2 pgtrace_client_errors_total
    2 pgtrace_connections                  1 each: traced_processes, kernel_drops_total,
                                             metrics_label_sets, metrics_label_overflow_total
```

Excerpt:

```
pgtrace_client_queries_total{client_addr="10.10.1.8",database="postgres",user="postgres"} 42040
pgtrace_client_queries_total{client_addr="10.10.1.8",database="tiny",user="postgres"} 80
pgtrace_client_queries_total{client_addr="10.10.1.8",database="pgbouncer",user="postgres"} 5
pgtrace_correlation_total{result="exact"} 42114
pgtrace_correlation_total{result="inferred"} 6
pgtrace_correlation_total{result="none"} 7
pgtrace_query_errors_total{side="client",sqlstate="08P01"} 5
pgtrace_query_errors_total{side="client",sqlstate="22012"} 5
pgtrace_query_errors_total{side="server",sqlstate="22012"} 5
pgtrace_truncations_total{layer="parser"} 2
pgtrace_truncations_total{layer="export"} 2
pgtrace_metrics_label_sets 3
pgtrace_metrics_label_overflow_total 0
```

In the 90-minute soak run (1.27 M client queries, before the labelled metrics
existed), the base series count stayed flat after the first minutes. The run
used a fixed set of operations and SQLSTATEs.

## Truncation layers

| layer | flag (default) | fires when |
|---|---|---|
| `kernel` | `-capture-bytes` (4096; 64 … 16384) | one send/recv moved more bytes than are copied. pgbouncer reads and writes in chunks of at most its `pkt_buf` (4096 by default), so this normally stays at 0. In the e2e run with a 100 KB statement it was 0. |
| `parser` | `-max-message-bytes` (65536) | a protocol message the parser reads (query, Parse/Bind, error…) is longer than the cap. Counted once per side, so one statement through pgbouncer counts twice. Result rows are never buffered and never count. |
| `export` | `-max-query-text` (2048) | SQL text longer than the cap was shortened for `db.query.text`. |

Memory: the parser allocates `min(message length, -max-message-bytes)` for
each message it reads, once, when the header arrives, and releases it when the
message completes. A 300-byte query costs 300 bytes, and a 450 KB statement
costs 450 KB if the cap allows it. The worst case is (connections with a
message in flight) × cap.
