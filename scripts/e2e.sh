#!/usr/bin/env bash
# End-to-end test: start the stack, generate traffic through pgbouncer and
# check traces in VictoriaTraces, agent metrics, Prometheus and Grafana.
set -euo pipefail
cd "$(dirname "$0")/../deploy"

RATIO=${PGTRACE_SAMPLE_RATIO:-0.1}
TX=${TX:-500}
CLIENTS=${CLIENTS:-4}
export PGTRACE_SAMPLE_RATIO=$RATIO PGTRACE_STATS_INTERVAL=2s
# Build on the local daemon, not whatever remote buildx builder is active.
export BUILDX_BUILDER=${BUILDX_BUILDER:-default}
lg() { docker compose run --rm -T loadgen "$@"; }

echo "== starting stack (fresh)"
docker compose down --remove-orphans >/dev/null 2>&1 || true
docker compose up -d --build --wait postgres pgbouncer victoriatraces prometheus grafana >/dev/null
docker compose up -d --build agent >/dev/null
for _ in $(seq 1 30); do
	docker compose logs agent 2>/dev/null | grep -q "tracing process" && break
	sleep 1
done
docker compose logs agent | grep -q "tracing process" || { echo "agent never attached"; docker compose logs agent; exit 1; }

echo "== generating traffic"
lg pgbench -i -s 1 -q >/dev/null 2>&1
for mode in simple extended prepared; do
	lg pgbench -M "$mode" -c "$CLIENTS" -t "$TX" -n 2>&1 | grep -E "^tps"
done
lg sh -c 'for i in 1 2 3 4 5; do
	psql -qc "select 1/0" 2>/dev/null
	psql -qc "select * from missing_table" 2>/dev/null
	psql -qAtc "select pg_sleep(0.2)" >/dev/null
	psql -d pgbouncer -qc "SHOW nonsense" 2>/dev/null
done; true'
echo "== a 100 KB statement (beyond the 64 KiB parser keep cap)"
mkdir -p soak/gen
python3 -c "print(\"select pg_sleep(0.15), length('\" + 'x' * 100000 + \"');\")" > soak/gen/e2e_big.sql
lg psql -qAt -f /soak/gen/e2e_big.sql >/dev/null
echo "== SQLCommenter trace context"
lg psql -qAtc "select 1 /*application='e2e',traceparent='00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01'*/" >/dev/null
echo "== pool pressure: 16 clients on a 2-connection pool"
lg sh -c 'for i in $(seq 1 16); do
	(for n in 1 2 3 4 5; do psql -d tiny -qAtc "select pg_sleep(0.05), '"'"'c$i-$n'"'"'" >/dev/null; done) &
done; wait'

echo "== waiting for export"
sleep 8
stats=$(docker compose logs agent | grep "INFO stats" | tail -1)
echo "agent: ${stats#*INFO }"

python3 ../scripts/e2e_check.py --ratio "$RATIO" --min-traces $((CLIENTS * TX * 7 * 3)) --stats "$stats" --ceiling "${SERIES_CEILING:-8975}"
