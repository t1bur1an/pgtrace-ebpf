# Contention: what pgtrace shows and what it can't

pgtrace sees the PostgreSQL wire protocol between clients, pgbouncer and
postgres. Contention shows up there in three ways:

1. **Errors**: postgres and pgbouncer report deadlocks, serialization
   failures, timeouts and rejected logins with SQLSTATE codes.
2. **Time**: where a query spent its time, split into pool wait (in pgbouncer's
   queue), server time (inside postgres) and idle-in-transaction gaps (the
   client holding a server while doing nothing).
3. **Who**: every trace carries the client address, user, database and
   application, and optionally the application's own trace (SQLCommenter).

What it **can't** see is *why* a server span was slow. On the wire, a 3-second
lock wait looks the same as 3 seconds of CPU or I/O. It also can't see which
session held the lock. For that, combine the time window from pgtrace with
`pg_locks` / `pg_stat_activity` or `log_lock_waits`.

`scripts/contention.sh` provokes each case below through pgbouncer and checks
the evidence. All checks pass. Scenarios run with the default 10 % sampling;
the kept traces are kept because of errors, slowness or long idle gaps, not
by chance.

## Where to look

| symptom | traces | metrics / Grafana (dashboard **pgtrace**, row *Contention*) |
|---|---|---|
| Deadlock | root + server child with `db.response.status_code=40P01`; the other session's statement is a slow trace ≈ `deadlock_timeout` | `pgtrace_query_errors_total{side="server",sqlstate="40P01"}`; panel *Lock and transaction conflicts/s*; table *Deadlock traces* |
| Row-lock wait | long **server** span, pool wait ≈ 0 | server p95 rises while pool-wait p95 stays low (*Pool wait vs server time*) |
| `lock_timeout` | error `55P03` after the timeout | conflicts panel, `55P03` |
| `statement_timeout` / cancel | error `57014` after the timeout | conflicts panel, `57014` |
| Serialization failure | error `40001` (at the statement or at COMMIT) | conflicts panel, `40001` |
| Pool exhaustion | `pgbouncer.pool_wait_ms` large; root duration = pool wait + server time | *Pool wait vs server time*: pool wait p95 ≫ server p95; `pgtrace_pool_wait_seconds`; per database/user with `-metrics-labels` |
| pgbouncer queue timeout (`query_wait_timeout`) | client root with error (pgbouncer's message), **no server child** | `pgtrace_query_errors_total{side="client"}` without a matching server error |
| Idle in transaction | `pgbouncer.idle_in_tx_ms` on the query after the gap; other clients' pool wait rises meanwhile | *Idle in transaction* panel, `pgtrace_idle_in_transaction_seconds` |
| Rejected login / too many connections | `connect` span with error: `28P01`/`08P01` auth, `3D000` unknown database, `53300` too many connections | `pgtrace_connection_errors_total{side,sqlstate}`; *Connection errors/s* |

Rules of thumb:

- **Pool wait high, server time normal:** the pgbouncer pool is too small,
  or it's being held. Look at idle-in-transaction first; a client idling in a
  transaction holds a server connection in transaction pooling too.
- **Server time high, pool wait low:** the waiting happens inside postgres:
  locks, I/O or CPU. Error codes 40P01/55P03/57014 confirm lock trouble.
- **Client-side error with no server child:** pgbouncer itself refused or
  timed the query out; postgres never saw it.

## Measured by `scripts/contention.sh`

| # | scenario | observed |
|---|---|---|
| 1 | Deadlock (two sessions, rows A→B vs B→A) | one `40P01` root with a `40P01` server child; the survivor's UPDATE took 995 ms (≈ `deadlock_timeout` 1 s), kept as slow |
| 2 | Row-lock wait (lock held 3 s, waiter starts 0.5 s later) | waiter's server span 2 502 ms, pool wait 0.01 ms |
| 3 | `SET LOCAL lock_timeout='500ms'` on a locked row | `55P03` after 500 ms |
| 4 | `SET LOCAL statement_timeout='300ms'` + `pg_sleep(2)` | `57014` after 300 ms |
| 5 | SERIALIZABLE write skew | `40001` |
| 6 | 16 clients × `pg_sleep(1)` on a 2-connection pool | 16 traces; pool wait p95 7 008 ms; client time = pool wait + server time (±50 ms) for 16/16 |
| 7 | `query_wait_timeout=2` during the same load | 10 of 16 queries timed out: client roots with pgbouncer's `query_wait_timeout` error, no server child |
| 8 | `BEGIN; SELECT 1;` idle 5 s `SELECT 2; COMMIT` on the small pool | next query has `idle_in_tx_ms` = 5 001; other clients on the pool waited up to 2.5 s |
| B | unknown database; wrong password | `connect` error spans: `3D000` on both sides (pgbouncer's `*` entry passed the unknown database to postgres, which rejected it) and `08P01 SASL authentication failed` from pgbouncer |

The suite also found and fixed a correlation bug. When several clients
waited with *identical* queries, a freed server was attributed to the client
pgbouncer had read from most recently, but pgbouncer serves its queue oldest
first. Now the most-recent-read tie-break applies only when that read was
pgbouncer's immediately preceding action (an immediate forward). Otherwise the
oldest waiter is chosen. Scenario 6 went from 1/16 to 16/16 correctly linked.

## Limits

- **Lock holder unknown.** Traces show who waited, not who held the lock. In
  a deadlock you do see both sessions: the victim's error trace and the
  survivor's slow trace, with their client addresses and applications.
- **Waits inside one statement aren't split.** A server span includes lock
  waits, I/O and CPU together.
- **`idle_in_tx_ms` is measured at pgbouncer.** It includes network time
  between pgbouncer and the client, and it only appears once the client sends
  its next query. A client that disconnects while idle in a transaction is
  counted in the histogram but gets no span.
- **Connection errors before any bytes** (TCP refused, pgbouncer at
  `max_client_conn` closing immediately without an error message) aren't
  visible, since there is no protocol message to see.
