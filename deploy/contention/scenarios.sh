#!/bin/sh
# Contention scenarios, run inside the loadgen container (PG* env points at
# pgbouncer). Every statement is sent on its own (psql reads a heredoc), and
# tagged with a SQLCommenter comment so its span can be found by
# sqlcommenter.scenario. Timeouts use SET LOCAL so they can't leak onto a
# pooled server connection.
set -u
q() { psql -X -q -v ON_ERROR_STOP=0 "$@" >/dev/null 2>&1; }
say() { echo "$(date +%T) $*"; }

say setup
q <<'SQL'
DROP TABLE IF EXISTS ct; CREATE TABLE ct (id int PRIMARY KEY, v int NOT NULL DEFAULT 0);
INSERT INTO ct SELECT g, 0 FROM generate_series(1, 20) g;
DROP TABLE IF EXISTS cs; CREATE TABLE cs (id int PRIMARY KEY, v int NOT NULL DEFAULT 0);
INSERT INTO cs VALUES (1, 0), (2, 0);
SQL

say "1 deadlock"
q <<'SQL' &
BEGIN;
UPDATE ct SET v = v + 1 WHERE id = 1;
SELECT pg_sleep(1);
UPDATE ct SET v = v + 1 WHERE id = 2 /*scenario='deadlock-a'*/;
COMMIT;
SQL
q <<'SQL' &
BEGIN;
UPDATE ct SET v = v + 1 WHERE id = 2;
SELECT pg_sleep(1);
UPDATE ct SET v = v + 1 WHERE id = 1 /*scenario='deadlock-b'*/;
COMMIT;
SQL
wait

say "2 row-lock wait"
q <<'SQL' &
BEGIN;
UPDATE ct SET v = v + 1 WHERE id = 3;
SELECT pg_sleep(3);
COMMIT;
SQL
sleep 0.5
q -c "UPDATE ct SET v = v + 1 WHERE id = 3 /*scenario='lockwait'*/"
wait

say "3 lock_timeout"
q <<'SQL' &
BEGIN;
UPDATE ct SET v = v + 1 WHERE id = 4;
SELECT pg_sleep(2);
COMMIT;
SQL
sleep 0.5
q <<'SQL'
BEGIN;
SET LOCAL lock_timeout = '500ms';
UPDATE ct SET v = v + 1 WHERE id = 4 /*scenario='locktimeout'*/;
ROLLBACK;
SQL
wait

say "4 statement_timeout"
q <<'SQL'
BEGIN;
SET LOCAL statement_timeout = '300ms';
SELECT pg_sleep(2) /*scenario='stmttimeout'*/;
ROLLBACK;
SQL

say "5 serialization failure"
for attempt in 1 2 3; do
	for id in 1 2; do
		q <<SQL &
BEGIN ISOLATION LEVEL SERIALIZABLE;
SELECT sum(v) FROM cs;
SELECT pg_sleep(0.5);
UPDATE cs SET v = v + 1 WHERE id = $id /*scenario='serial'*/;
COMMIT /*scenario='serial-commit'*/;
SQL
	done
	wait
done

say "6 pool exhaustion: 16 x 1 s on a 2-connection pool"
for i in $(seq 1 16); do q -d tiny -c "SELECT pg_sleep(1) /*scenario='poolwait'*/" & done
wait

say "7 query_wait_timeout = 2 s"
q -d pgbouncer -c "SET query_wait_timeout = 2"
for i in $(seq 1 16); do q -d tiny -c "SELECT pg_sleep(1) /*scenario='qwt'*/" & done
wait
q -d pgbouncer -c "SET query_wait_timeout = 120"

say "8 idle in transaction for 5 s on the tiny pool"
q -d tiny <<'SQL' &
BEGIN;
SELECT 1 /*scenario='idle-begin'*/;
\! sleep 5
SELECT 2 /*scenario='idle-after'*/;
COMMIT;
SQL
sleep 0.5
for i in $(seq 1 6); do q -d tiny -c "SELECT pg_sleep(0.5) /*scenario='idle-victim'*/" & done
wait

say "B connection errors"
q -d nosuchdb -c "select 1"
PGPASSWORD=wrong q -c "select 1"
say done
