#!/usr/bin/env bash
# End-to-end tests for -tls-capture (TLS test PKI, deploy/tls):
#   1. strict: the full e2e suite with TLS on both hops, plus TLS checks
#   2. mixed: TLS and plain clients in one run, plain server hop
#   3. sessions opened before the agent started (socket-finding fallback)
#   4. pgbouncer connection logging off (version/cipher are best-effort)
#   5. pgbouncer restart: probes follow the new process
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root/deploy"
export BUILDX_BUILDER=${BUILDX_BUILDER:-default}
export COMPOSE_FILE=docker-compose.yml:tls/compose.tls.yml PGTRACE_TLS_CAPTURE=true PGTRACE_STATS_INTERVAL=2s
./tls/gencerts.sh >/dev/null
lg() { docker compose run --rm -T loadgen "$@"; }
stats() { docker compose logs agent | grep "INFO stats" | tail -1; }
check() { python3 "$root/scripts/e2e_tls_check.py" "$@" --stats "$(stats)"; }
fresh() { # fresh <pgbouncer ini>: stack without the agent, pgbench initialised
	docker compose down --remove-orphans >/dev/null 2>&1 || true
	PGBOUNCER_TLS_INI=$1 docker compose up -d --build --wait postgres pgbouncer victoriatraces prometheus >/dev/null
	lg pgbench -i -s 1 -q >/dev/null 2>&1
}
# hold [env…]: keep one session open for 15 s. The connection gauge is
# sampled every few seconds, longer than the short pgbench runs here.
hold() { lg env "$@" psql -qAtc "select pg_sleep(15)" >/dev/null & }
agent_up() {
	docker compose up -d --build agent >/dev/null
	for _ in $(seq 1 30); do docker compose logs agent 2>/dev/null | grep -q "tls probes attached" && return; sleep 1; done
	echo "TLS probes never attached"; docker compose logs agent; exit 1
}

echo "== 1. strict TLS: the full e2e suite"
PGBOUNCER_TLS_INI=pgbouncer.strict.ini SERIES_CEILING=8991 "$root/scripts/e2e.sh"
check strict

echo "== 2. mixed TLS and plain clients, plain server hop"
export PGTRACE_SAMPLE_RATIO=1.0
fresh pgbouncer.mixed.ini
agent_up
lg env PGSSLMODE=disable PGAPPNAME=plain-client pgbench -c 4 -t 300 -n | grep -E "^tps"
lg env PGAPPNAME=tls-client pgbench -c 4 -t 300 -n | grep -E "^tps"
hold PGSSLMODE=disable
hold PGSSLMODE=verify-full
sleep 12
check mixed
wait

echo "== 3. sessions opened before the agent"
fresh pgbouncer.strict.ini
lg env PGAPPNAME=pre pgbench -c 4 -T 90 -n | grep -E "^tps" &
load=$!
sleep 10
agent_up
wait $load
echo "   waiting for the fallback to detach"
sleep 45
check preexisting

echo "== 4. pgbouncer connection logging off"
mkdir -p tls/generated
sed 's/^\[pgbouncer\]$/[pgbouncer]\nlog_connections = 0\nlog_disconnections = 0/' tls/pgbouncer.strict.ini > tls/generated/pgbouncer.nolog.ini
unset PGTRACE_SAMPLE_RATIO
fresh generated/pgbouncer.nolog.ini
agent_up
lg pgbench -c 4 -t 300 -n | grep -E "^tps"
hold PGSSLMODE=verify-full
sleep 12
check nolog
wait

echo "== 5. pgbouncer restart: probes follow the new process"
docker compose restart pgbouncer >/dev/null
sleep 12 # two rescans
lg env PGAPPNAME=after-restart pgbench -c 2 -t 200 -n | grep -E "^tps"
hold PGSSLMODE=verify-full
sleep 12
check nolog --app after-restart
wait

echo "E2E TLS PASSED"
