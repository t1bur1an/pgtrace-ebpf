# SQLCommenter trace context — design

Date: 2026-09-28. Pre-approved by the user ("i would accept your design").

## Goal

When an application appends a [SQLCommenter](https://google.github.io/sqlcommenter/)
comment carrying W3C trace context to its SQL, e.g.

```sql
SELECT * FROM orders WHERE id = $1 /*application='shop',traceparent='00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01'*/
```

the pgbouncer root span becomes a child of the application's span. One trace
then shows application → pgbouncer (with pool wait) → postgres. pgbouncer
forwards SQL text unchanged, so no pgbouncer or postgres changes are needed.

## Parsing (`internal/sqlcomment`)

- Only a comment at the end of the statement counts, after trimming trailing
  whitespace and `;`. It has to end with `*/`, and the matching `/*` is the
  last one before it. This follows the SQLCommenter spec and keeps a `/*`
  inside a string literal earlier in the SQL from being picked up.
- The body is `key='value'` pairs separated by commas. Keys and values are
  URL-decoded, and `\'` inside a value is unescaped.
- `traceparent` must be a valid W3C version-00 header: 2-32-16-2 lowercase
  hex, trace ID and parent ID not all zeros, version not `ff`. `tracestate`
  is kept if present.
- Other keys (e.g. `application`, `controller`, `route`, `framework`,
  `db_driver`, `action`) become span attributes `sqlcommenter.<key>`. At most
  10 keys are kept, values go through the same UTF-8-safe 256-byte clean, and
  keys must match `[a-z0-9_.-]{1,64}`.
- `Parse(sql string) (Comment, bool)`, where `Comment{TraceParent, TraceState string; Attrs map[string]string; Valid bool}`.
  `ok` means a trailing comment was found; `Valid` means its traceparent
  parsed.

## Which executions may use it (`pgwire`)

A prepared statement's text is parsed once and executed many times, so a
`traceparent` inside a named statement's text would attach every later
execution to the first request's trace. `pgwire.Query` gets `PerExecution bool`:

- **simple protocol**: true, since the text is sent on every execution;
- **extended protocol**: true only if the statement's `Parse` arrived in the
  same Sync group as the `Execute`. This covers unnamed statements and
  parse-per-execute drivers.

The trace context is used only when `PerExecution` is true. Otherwise the
comment's other attributes are still recorded, but the span isn't parented.

## Export and sampling

- Root span: when the client query has a valid trace context, the span is
  started under `trace.ContextWithRemoteSpanContext` with the traceparent's
  trace ID, parent span ID, flags and tracestate. It keeps kind SERVER. It
  gets `pgtrace.trace_context=sqlcommenter`, plus `sqlcommenter.*` for the
  other keys.
- Server children stay under the root, so they join the application's trace
  as well.
- Sampling: if the parent is sampled (flag `01`) and `-sqlcommenter-parent-sampling`
  is true (default), the trace is kept with reason `parent`, so the
  application's sampled traces aren't missing their database part. Otherwise
  the usual rules apply: errors, slow queries, ratio.
- `-sqlcommenter` (default true) turns parsing off entirely.

## Metrics

`pgtrace_trace_context_total{result}`, where `result` is `linked` (valid, used),
`not_per_execution` (valid but in a reused prepared statement) or `invalid`
(comment with a malformed traceparent). That is 3 series; `MaxSeries` and
`docs/metrics.md` are updated.

## Limits

- The comment has to survive truncation. If the statement is longer than
  `-max-message-bytes`, the trailing comment is cut off and ignored. The same
  applies to `-capture-bytes` in the rare case that the kernel cap fires.
- The pg_tracing `SET pg_tracing.trace_context` method isn't supported.

## Tests

- sqlcomment: valid; URL-encoded values; escaped quote; missing; comment not at
  the end; `/*` in a string literal earlier; malformed traceparents (bad
  length, uppercase, version ff, zero IDs); more than 10 keys; invalid key names.
- pgwire: PerExecution for simple, unnamed extended, named with Parse in
  group, and named reused without Parse.
- export: root span's parent equals the remote span (trace ID, span ID,
  `remote=true`); children share the trace ID; attributes set.
- sampler: sampled parent → kept with reason `parent`; unsampled parent → ratio rules.
- metrics: trace_context_total results.
- e2e: a psql query with a SQLCommenter comment and a fixed traceparent → the
  stored root span has that trace_id and parent_span_id, and its server child
  has the same trace_id. A sampled parent is kept even though the query is
  fast.
