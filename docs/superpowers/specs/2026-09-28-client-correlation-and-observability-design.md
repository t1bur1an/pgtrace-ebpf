# Client-side tracing, correlation, metrics and Grafana — design

Date: 2026-09-28
Builds on: `2026-09-28-pgbouncer-ebpf-tracing-design.md`

## Goal

1. Trace each query as the **client** sees it through pgbouncer, and link it to
   the query pgbouncer runs on the **server** connection, as one trace: a root
   span (client ↔ pgbouncer) with a child span (pgbouncer ↔ postgres).
2. Expose Prometheus metrics from the agent, computed from **every** query
   (not just sampled spans).
3. Ship Prometheus and Grafana in the compose stack, with a provisioned
   dashboard and a VictoriaTraces (Jaeger) datasource, so a person can look at
   metrics and traces.

Success criteria:

- In e2e, ≥ 99 % of sampled pgbench client traces have exactly one server child
  whose SQL equals the root's, and every child's time range lies within its
  root's.
- Pool waits are visible (`pgbouncer.pool_wait_ms` > 0) when the pool is
  undersized.
- Errors pgbouncer generates itself (no server involved) appear as root spans
  with error status.
- `curl agent:9464/metrics` serves the metrics below; Grafana at
  `localhost:3000` shows the dashboard with data and can search traces.

## Decisions

- **Correlation is inferred from captured traffic.** The stock pgbouncer image
  is stripped (no symbols), so uprobes on its internals aren't an option.
- **One trace per client query.**
- **Sampling is decided per root.** An error or slow query on either side keeps
  both spans.

## Kernel capture changes

- New probe: `fexit/__sys_accept4(int fd, struct sockaddr *upeer, int *upeer_len, int flags) → ret`.
  When ret ≥ 0 and the pid is traced, it emits `K_ACCEPT` with `fd = ret` and
  the peer address (AF_INET / AF_INET6; AF_UNIX → family only).
- Event kind 3 = accept. The decode layout is unchanged; the address fields are
  reused.
- `fd_class` keeps its meaning: `CLASS_IGNORE (2)` suppresses capture. Client
  sockets are no longer marked ignored, so they are captured.

## fd classification (`connmap`)

`Info` gains `Side` (`SideNone`, `SideServer`, `SideClient`) and `Local`
(the local address). `Server bool` is replaced by `Side == SideServer`.

- connect to `-pg-port` → server.
- accept → client (peer address known). An accept of a Unix socket gives a
  client with an empty address.
- Lazy `/proc` resolution:
  - TCP socket with remote port = `-pg-port` → server;
  - TCP socket with local port = `-listen-port` (default 6432) → client;
  - socket inode listed in `/proc/<pid>/net/unix` → client;
  - anything else → none.
- `parseProcNetTCP` returns both local and remote addresses per inode.
- With `-client-tracing=false` (default true), client sockets are classified
  as none, so they are ignored in the kernel and the behaviour matches the
  previous version.

## Parser (`pgwire`)

- `NewConn()` stays the server-side constructor. `NewClientConn()` builds a
  parser for a client socket, where `DirRecv` carries frontend messages and
  `DirSend` carries backend messages. The rest of the logic is shared.
- The startup packet (protocol 3.0) is parsed. `Conn.Params()` returns
  `map[string]string` holding `user`, `database` and `application_name` when
  present.
- Every query gets a **signature** `Sig uint64` (FNV-1a 64):
  - simple: the `Q` text;
  - extended: the Parse SQL of the bound statement, a 0 byte, then the Bind
    body *after* the statement name (parameter formats, values, result
    formats).

  The statement and portal names are excluded, because pgbouncer renames
  prepared statements (`PGBOUNCER_n`).
- Extended queries also carry `BindSig`, a hash of the Bind body after the
  statement name alone. It is the fallback when one side doesn't know the
  statement's SQL (Parse sent before the agent started). Simple queries have
  `BindSig = 0`.
- **Query starts are reported.** `Feed` returns `Result{Started []Start; Done []Query}`,
  where `Start{ID uint64, Sig, BindSig uint64, SQLKnown bool, TS uint64, SQL string}`. `ID` is
  per-`Conn` and increases monotonically; the same ID is set on the completed
  `Query.ID`. A query starts when its `Q` or `Execute` is parsed.
- `Query` gains `ID`, `Sig`, and `TxStatus byte` (the status byte of the `Z`
  that ended its group, `I`/`T`/`E`).

## Correlator (`internal/correlate`)

It runs inside the agent's single event goroutine and has no locking. Its
state is kept per pgbouncer pid.

```
type Correlator struct { ... }
func New(sink func(Trace), holdTimeout time.Duration) *Correlator
func (c *Correlator) ClientStarted(pid uint32, client event.ConnKey, st pgwire.Start)
func (c *Correlator) ClientRecv(pid uint32, client event.ConnKey, ts uint64) // any data recv on a client fd
func (c *Correlator) ServerStarted(pid uint32, server event.ConnKey, st pgwire.Start) // returns nothing; records attribution
func (c *Correlator) ServerDone(server event.ConnKey, q pgwire.Query)
func (c *Correlator) ClientDone(client event.ConnKey, q pgwire.Query)
func (c *Correlator) ClientClosed(client event.ConnKey)
func (c *Correlator) ServerClosed(server event.ConnKey)
func (c *Correlator) Tick(now uint64) // flush held server queries older than holdTimeout

type Trace struct {
	Client *ClientQuery   // nil for uncorrelated server queries
	Server []ServerQuery  // children, in start order; may be empty
}
type ClientQuery struct { Key event.ConnKey; Q pgwire.Query }
type ServerQuery struct {
	Key         event.ConnKey
	Q           pgwire.Query
	Correlation string // "exact" | "inferred" | "none"
	Internal    bool   // issued by pgbouncer itself (not a client query)
}
```

Rules:

1. `ClientStarted` appends `{client, ID, Sig, TS}` to that client's
   **pending-forward queue**. `ClientRecv` records `(client, ts)` as the pid's
   last client read.
2. `ServerStarted(S, st)`:
   - Two starts **match** if their `Sig` values are equal, or, when either
     side has `SQLKnown=false`, if their non-zero `BindSig` values are equal.
   - **S is linked to client C and C's queue has a matching entry**:
     attribute to the first such entry, `exact`, and pop it and any entries
     before it.
   - **S is linked but no entry matches**: an internal query while in a
     transaction; attribute to the link with `Internal=true`.
   - **S is unlinked**: candidates are clients whose queue *head* matches.
     - Exactly 1 candidate → `exact`.
     - More than 1 → pick the pid's last-read client if it is a candidate,
       otherwise the candidate with the oldest head TS; `inferred`.
     - Link S → C and pop the head.
   - **S is unlinked and there are no candidates**: record it as *unattributed
     pending* on S. If S gets linked by a later `ServerStarted` in the same
     `Z` group (before S's next `Z`), it becomes an `Internal` child of that
     client query (for example parameter-sync `SET`s). Otherwise it becomes an
     uncorrelated trace when it completes.
3. `ServerDone(S, q)`: the completed server query is **held** under its client
   query (client key + client query ID). If `q.TxStatus == 'I'`, S is unlinked
   *after* this query (transaction pooling: the server returns to the pool).
   Uncorrelated completed queries are emitted immediately as
   `Trace{Client: nil, Server: [q with "none"]}`.
4. `ClientDone(C, q)`: emits `Trace{Client: q, Server: held children for (C, q.ID)}`.
   Children are sorted by start. If `q.ID` is still in C's queue, it is
   removed: pgbouncer answered it itself (admin console, pgbouncer error), and
   leaving it would block the queue head.
5. `ClientClosed(C)`: its held children are emitted as orphans (`Client=nil`,
   correlation kept). Its queue is dropped and any server linked to C is
   unlinked. `ServerClosed(S)`: S is unlinked and its unattributed pending
   entry is dropped.
6. `Tick`: children held longer than `holdTimeout` (default 30 s, for
   long-running client queries whose client side we never saw) are emitted as
   orphans.

Session pooling: the link persists while `TxStatus` isn't `I`, and each client
query still finds S by signature (`exact`, because S is linked once only one
client matches).

## Agent wiring

- Data on a client fd goes to the client `Conn`. `Started` →
  `ClientStarted`, and every recv → `ClientRecv`. `Done` → `ClientDone`.
- Data on a server fd: `Started` → `ServerStarted`, `Done` → `ServerDone`.
- Close → `ClientClosed` / `ServerClosed` for the side that was known.
- `Tick` runs every second from a ticker in `Run`'s select loop.
- **Sampling** moves to Traces. `Decide` gets a `TraceView` holding the root
  query (or the lone server query) plus the children:
  - error on the root or any child → error;
  - root duration (or the lone server query's) ≥ slow → slow;
  - otherwise ratio.
- **Export**: kept Traces are exported as one trace.
  - The root span is kind SERVER, named after the operation, and spans the
    client query's start to end. Attributes:
    - `db.system`, `db.system.name`, `db.query.text`, `db.operation.name`
    - `db.namespace` (database), `db.user`, `application_name`
    - `client.address`, `client.port`
    - `pgbouncer.pid`, `pgbouncer.client_fd`
    - `pgbouncer.pool_wait_ms`: first child's start minus root start; omitted
      without children
    - `db.response.status_code` and error status
    - `pgtrace.correlation`: the first child's value, or `none`
    - `pgtrace.sample_reason`, `pgtrace.protocol`, `pgtrace.truncated`
  - Child spans use the existing server span attributes, plus
    `pgtrace.correlation` and `pgbouncer.internal`.
  - Uncorrelated or orphan server queries are exported as today (a single
    CLIENT span) with `pgtrace.correlation`.

## Metrics (Prometheus)

The agent serves `/metrics` on `-metrics-addr` (default `:9464`; empty
disables it) using `prometheus/client_golang`, including the Go and process
collectors. Metrics count **all** queries, not only sampled ones.

| metric | type | labels |
|---|---|---|
| `pgtrace_queries_total` | counter | `side` (client/server), `operation`, `protocol` |
| `pgtrace_query_duration_seconds` | histogram | `side`, `operation` |
| `pgtrace_query_errors_total` | counter | `side`, `sqlstate` |
| `pgtrace_pool_wait_seconds` | histogram | — |
| `pgtrace_correlation_total` | counter | `result` (exact/inferred/none/orphan/internal) |
| `pgtrace_spans_total` | counter | `decision` (kept_error/kept_slow/kept_ratio/dropped) |
| `pgtrace_events_total` | counter | `kind` (data/connect/accept/close) |
| `pgtrace_connections` | gauge | `side` |
| `pgtrace_traced_processes` | gauge | — |
| `pgtrace_kernel_drops_total` | counter (func) | — |
| `pgtrace_bpf_run_seconds_total`, `pgtrace_bpf_runs_total` | counter (func) | — (only when `-bpf-stats`) |

- **Label cardinality**: `operation` is limited to a fixed set (SELECT,
  INSERT, UPDATE, DELETE, BEGIN, COMMIT, END, ROLLBACK, SET, SHOW, WITH, COPY,
  CREATE, ALTER, DROP, TRUNCATE, VACUUM, ANALYZE, EXPLAIN, CALL, DO, FETCH,
  DECLARE, CLOSE, DISCARD, LISTEN, NOTIFY, PREPARE, EXECUTE, DEALLOCATE,
  RESET, LOCK, GRANT, REVOKE, COMMENT, MERGE); anything else is `OTHER`.
  `sqlstate` is limited to 5-character codes, otherwise `OTHER`.
- Histogram buckets: 50 µs … 10 s, exponential (factor 2.5, 12 buckets).

## Compose additions

- `prometheus` (`prom/prometheus`) scrapes `agent:9464` every 5 s. Port 9090.
- `grafana` (`grafana/grafana`, anonymous Admin, no login). Port 3000.
  Provisioned with:
  - datasource **Prometheus** (uid `prometheus`) → `http://prometheus:9090`;
  - datasource **VictoriaTraces** (Jaeger type, uid `victoriatraces`) →
    `http://victoriatraces:10428/select/jaeger`;
  - dashboard **pgtrace** (`deploy/grafana/dashboards/pgtrace.json`):
    - query rate by side / operation;
    - client vs server latency p50 / p95 / p99;
    - pool wait p50 / p95 / p99;
    - errors by sqlstate and side;
    - correlation result share;
    - span sampling decisions;
    - events/s, kernel drops, BPF ns per run;
    - agent CPU and RSS (process collector), traced processes, connections
      by side;
    - a **traces table** (VictoriaTraces search, service `pgbouncer`, last
      100) whose trace IDs open the trace view.

## Testing

- **pgwire**: startup parameters; signatures (equal across a `PGBOUNCER_1`
  rename; different for different bind values; equal for identical simple
  text); `Result.Started` IDs match `Done` IDs; client-direction parsing.
- **correlate**: table tests with synthetic call sequences:
  1. immediate forward;
  2. pool wait (C2 queued while C1 holds S; C2 served after C1's `Z I`);
  2b. server-side statement with unknown SQL, matched by `BindSig`;
  3. two clients with the same SQL and different binds;
  4. two clients with identical signatures (inferred, last-read wins);
  5. multi-statement transaction on one link;
  6. `PGBOUNCER_n` prepared statement;
  7. internal `SET` before the forwarded query;
  8. admin-console query (client only);
  9. `server_check_query` (server only, correlation none);
  10. client closes mid-query (orphan);
  11. hold timeout.
- **connmap**: accept classification; local-port classification;
  `/proc/net/unix` classification; `-client-tracing=false`.
- **metrics**: a registry test checking that counters and histograms move for
  a synthetic trace; `operation` / `sqlstate` bucketing.
- **E2E** (`scripts/e2e.sh`) extended:
  - pgbouncer `default_pool_size` stays 20; a separate pool-pressure phase runs
    16 concurrent psql clients against a database alias `tiny` with
    `pool_size=2`, each running `SELECT pg_sleep(0.05), '<client>-<n>'`;
  - assertions: correlation rate ≥ 99 % among client roots with a server child
    during pgbench; child within root; root SQL == child SQL for non-internal
    children; pool wait > 10 ms observed in the `tiny` phase; error traces
    (`1/0`) have root + child both with error status; a pgbouncer-generated
    error (query to a non-existent database) produces a client root with
    error and no child (an invalid `SHOW` on the pgbouncer admin console:
    `psql -d pgbouncer -c 'SHOW nonsense'`);
  - metrics: `/metrics` has `pgtrace_queries_total{side="client"}` > 0 and
    `pgtrace_pool_wait_seconds_count` > 0; Prometheus has the agent target
    `up`; the Grafana API lists the dashboard and both datasources are healthy.
- **Performance**: `perf.sh` gains a client-tracing on/off comparison
  (select-simple, 8 clients, 3 reps); `docs/performance.md` is updated.

## Limitations

- Client connections opened before the agent started have no startup
  attributes. Their queries still correlate by signature.
- Truly identical concurrent queries (same text and parameters) from different
  clients can be swapped between clients (`inferred`). The durations stay
  right; only the client attribution may be wrong.
- Unix-socket clients have no address.

## Revisions

- During implementation: rule 2's "S is linked but no entry matches → internal"
  now first looks for another waiting client whose queue head matches. If one
  exists, the link was stale (its idle `Z` was missed, e.g. the agent attached
  mid-transaction) and S is relinked to that client. Seen live as 24 real
  queries marked internal + 3 orphans before the change.
- Completing query N on a connection clears older tracked entries on that
  connection (queries complete in order; older ones were lost to a parser
  resync), which bounds correlator memory.
- Extended-protocol queries are reported at their group's `ReadyForQuery`, so
  every query carries the transaction status used to unlink servers.
