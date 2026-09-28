# Contention detection, tests and dashboard — design

Date: 2026-09-29. Scope approved by the user: contention test suite
(scenarios 1–8), `docs/contention.md`, and additions A (dashboard row),
B (connection-level errors), C (idle-in-transaction holder).

## B. Connection-level errors

An `ErrorResponse` that arrives on a connection when no query is in flight is
a connection-level error. On the client side, pgbouncer rejects the client:
unknown database, authentication failure, `max_client_conn` reached, or a
FATAL shutdown. On the server side, postgres rejects pgbouncer or terminates
the session. Today these are ignored.

- `pgwire.Result` gains `ConnErrors []ConnError{TS uint64; Code, Message string}`.
- The agent records each connection's start: the accept/connect event, or its
  first data. For each ConnError it calls `OnConnError(ConnErrorEvent{Side, Key,
  Start, End, Code, Message, Addr, Params})`.
- Export: one span named `connect`, kind SERVER for client connections and
  CLIENT for server connections, from the connection start to the error. It
  carries error status, `db.response.status_code`, `client.address`/`port`,
  `db.namespace`, `db.user` and `application_name` when the startup packet was
  seen, and `pgtrace.connection_error=true`. It is always kept (reason `error`).
- Metric: `pgtrace_connection_errors_total{side, sqlstate}`, with sqlstate
  bounded by the same 300-value cap. That adds up to 602 series, and
  `MaxSeries` is updated.

## C. Idle in transaction

- Per client connection, the agent remembers `inTxSince`: the end of the last
  client query whose `TxStatus` was `T` or `E` (in a transaction), or 0.
- When the client's next query starts and `inTxSince > 0`, the gap is idle
  time during which the client held a server connection without using it.
  The gap is stored against that query's ID.
- The next query's root span gets `pgbouncer.idle_in_tx_ms`. The gap is also
  observed in `pgtrace_idle_in_transaction_seconds` (histogram, same buckets).
- If a client closes while in a transaction, the gap from `inTxSince` to the
  close is observed in the histogram as well; there's no span for it.
- `export.ClientInfo` gains `IdleInTx time.Duration` (per trace).

## A. Dashboard row "Contention"

- Lock and transaction conflicts per second: server errors with sqlstate
  40P01 (deadlock), 40001 (serialization), 55P03 (lock timeout), 57014
  (statement timeout / cancel), 25P03 (idle-in-transaction timeout), 53300
  (too many connections).
- Pool wait p95 against server time p95.
- Idle in transaction: p95/p99 and rate.
- Connection errors per second, by side and sqlstate.
- Trace table: deadlock traces (Jaeger tag `db.response.status_code=40P01`).

## Contention suite (`scripts/contention.sh` + `scripts/contention_check.py`)

It runs against the compose stack, which it brings up if needed, through
pgbouncer. Each scenario uses its own table rows or database alias. Statements
are sent one by one (psql reading a heredoc) so every statement is its own
span. Timeouts use `SET LOCAL` inside a transaction, so they can't leak onto
a pooled server connection.

| # | scenario | assertion |
|---|---|---|
| 1 | deadlock (A→B vs B→A with `pg_sleep(1)`) | a 40P01 root with a 40P01 server child; the other session's UPDATE is a slow trace ≥ 0.9 s |
| 2 | row-lock wait (holder keeps the lock 3 s) | waiter's server span ≥ 2 s, its pool wait < 100 ms |
| 3 | `SET LOCAL lock_timeout='500ms'` on a locked row | a 55P03 root ≈ 0.5 s |
| 4 | `SET LOCAL statement_timeout='300ms'` + `pg_sleep(2)` | a 57014 root ≈ 0.3 s |
| 5 | SERIALIZABLE write skew (up to 3 attempts) | a 40001 root |
| 6 | 16 clients × `pg_sleep(1)` on `tiny` (pool 2) | pool wait p95 ≥ 1 s; for waiting clients root ≈ pool wait + server time |
| 7 | `SET query_wait_timeout=2` via the admin console during 6, then restored | client roots with a pgbouncer error, no server child |
| 8 | `BEGIN; SELECT 1; \! sleep 5; SELECT 2; COMMIT;` on `tiny` while others wait | root of `SELECT 2` has `pgbouncer.idle_in_tx_ms` ≈ 5000; idle histogram count > 0 |
| B | unknown database; wrong password | `connection_errors_total{side="client"}` for 08P01 and 28P01; `connect` spans with error |

## Tests

- pgwire: ErrorResponse during startup, and after a completed query with
  nothing in flight, becomes a ConnError. An error in a query doesn't.
- agent: OnConnError fires with the start time and startup parameters; the
  idle-in-transaction gap lands on the next query; closing while in a
  transaction reports the gap.
- export: `connect` span attributes and status; `pgbouncer.idle_in_tx_ms`.
- metrics: connection error counter with the sqlstate cap; idle histogram;
  `MaxSeries` updated.
