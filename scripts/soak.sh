#!/usr/bin/env bash
# Long-running soak test: big JSON inserts/updates/deletes through pgbouncer
# with the agent attached, sampled every minute, checked at the end.
#
#   DURATION=5400 ./scripts/soak.sh        # seconds (default 90 min)
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root/deploy"

DURATION=${DURATION:-5400}
OUT=${OUT:-$root/docs/soak-results/$(date +%Y%m%d-%H%M)}
export BUILDX_BUILDER=${BUILDX_BUILDER:-default}
export PGTRACE_SAMPLE_RATIO=${PGTRACE_SAMPLE_RATIO:-0.1} PGTRACE_STATS_INTERVAL=30s
mkdir -p "$OUT"
lg() { docker compose run --rm -T loadgen "$@"; }

python3 "$root/scripts/soak_gen.py" > "$OUT/scripts.txt"
echo "== fresh stack"
docker compose down --remove-orphans >/dev/null 2>&1 || true
docker compose up -d --build --wait postgres pgbouncer victoriatraces prometheus grafana >/dev/null 2>&1
docker compose up -d --build agent >/dev/null 2>&1
for _ in $(seq 1 30); do docker compose logs agent 2>/dev/null | grep -q "tracing process" && break; sleep 1; done
lg psql -q -f /soak/schema.sql 2>/dev/null
lg pgbench -n -M prepared -c 4 -t 50 -f /soak/gen/ext_insert.sql >/dev/null 2>&1   # seed rows
{
	echo "duration_s: $DURATION"
	echo "started: $(date -Is)"
	echo "sample_ratio: $PGTRACE_SAMPLE_RATIO"
	echo "agent_container: $(docker inspect -f '{{.Id}} {{.State.StartedAt}}' pgtrace-agent-1)"
	cat "$(dirname "$OUT")/../perf-results/host.txt" 2>/dev/null | grep -E "^(cpu|memory|kernel|pgbouncer|postgres):" || true
} > "$OUT/meta.txt"

echo "== starting streams for ${DURATION}s (results in $OUT)"
common=(-n -T "$DURATION" -P 60 --max-tries 20 --failures-detailed)
big=(); for v in 0 1 2 3; do big+=(-f "/soak/gen/big_insert_$v.sql@6"); done
for v in 0 1 2; do big+=(-f "/soak/gen/big_replace_$v.sql@8"); done
big+=(-f /soak/gen/big_delete.sql@22 -f /soak/gen/big_txn.sql@30)
lg pgbench "${common[@]}" -M simple -c 8 -j 4 -R 20 "${big[@]}" > "$OUT/stream-big.log" 2>&1 &
lg pgbench "${common[@]}" -M prepared -c 16 -j 4 -R 150 \
	-f /soak/gen/ext_insert.sql@25 -f /soak/gen/ext_update.sql@20 -f /soak/gen/ext_select.sql@30 \
	-f /soak/gen/ext_jsonpath.sql@15 -f /soak/gen/ext_delete.sql@10 > "$OUT/stream-ext.log" 2>&1 &
lg pgbench "${common[@]}" -M simple -C -c 4 -j 2 -R 20 -f /soak/gen/churn.sql > "$OUT/stream-churn.log" 2>&1 &
# Errors pgbench can't keep running through: invalid JSON (server error) and
# a bad admin-console command (pgbouncer's own error), every 10 s.
lg sh -c "end=\$((\$(date +%s) + $DURATION)); n=0
	while [ \$(date +%s) -lt \$end ]; do
		psql -qc \"select '{bad'::jsonb\" 2>/dev/null; psql -d pgbouncer -qc 'SHOW nonsense' 2>/dev/null; n=\$((n+2)); sleep 10
	done; echo \"errors_sent: \$n\"" > "$OUT/stream-errors.log" 2>&1 &

python3 "$root/scripts/soak_monitor.py" header > "$OUT/samples.csv"
while [ -n "$(jobs -rp)" ]; do
	python3 "$root/scripts/soak_monitor.py" sample >> "$OUT/samples.csv" || true
	sleep 60
done
wait || true
sleep 15
python3 "$root/scripts/soak_monitor.py" sample >> "$OUT/samples.csv" || true
docker compose logs agent > "$OUT/agent.log" 2>&1
echo "finished: $(date -Is)" >> "$OUT/meta.txt"
python3 "$root/scripts/soak_monitor.py" report "$OUT"
