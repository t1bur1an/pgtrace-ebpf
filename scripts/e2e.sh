#!/usr/bin/env bash
# End-to-end test: start the stack, generate traffic through pgbouncer and
# check the spans that reached VictoriaTraces.
set -euo pipefail
cd "$(dirname "$0")/../deploy"

VT=${VT:-http://localhost:10428}
RATIO=${PGTRACE_SAMPLE_RATIO:-0.1}
TX=${TX:-500}
CLIENTS=${CLIENTS:-4}
export PGTRACE_SAMPLE_RATIO=$RATIO PGTRACE_STATS_INTERVAL=2s
# Build on the local daemon, not whatever remote buildx builder is active.
export BUILDX_BUILDER=${BUILDX_BUILDER:-default}

fail=0
check() { # check <description> <condition-exit-status>
	if [ "$2" -eq 0 ]; then echo "PASS  $1"; else echo "FAIL  $1"; fail=1; fi
}
logsql() { curl -fsS "$VT/select/logsql/query" --data-urlencode "query=$1"; }
count() { logsql "$1 | stats count() n" | python3 -c 'import json,sys; t=sys.stdin.read().strip(); print(json.loads(t)["n"] if t else 0)'; }
lg() { docker compose run --rm -T loadgen "$@"; }

echo "== starting stack (fresh)"
docker compose down --remove-orphans >/dev/null 2>&1 || true
docker compose up -d --build --wait postgres pgbouncer victoriatraces >/dev/null
docker compose up -d --build agent >/dev/null
for i in $(seq 1 30); do
	docker compose logs agent 2>/dev/null | grep -q "tracing process" && break
	sleep 1
done
docker compose logs agent | grep -q "tracing process" || { echo "agent never attached"; docker compose logs agent; exit 1; }

echo "== generating traffic"
lg pgbench -i -s 1 -q >/dev/null 2>&1
lg pgbench -M simple -c "$CLIENTS" -t "$TX" -n 2>&1 | grep -E "^(tps|number of transactions actually)"
lg pgbench -M extended -c "$CLIENTS" -t "$TX" -n 2>&1 | grep -E "^(tps|number of transactions actually)"
lg pgbench -M prepared -c "$CLIENTS" -t "$TX" -n 2>&1 | grep -E "^(tps|number of transactions actually)"
lg sh -c 'for i in 1 2 3 4 5; do
	psql -qc "select 1/0" 2>/dev/null
	psql -qc "select * from missing_table" 2>/dev/null
	psql -qAtc "select pg_sleep(0.2)" >/dev/null
done; true'

echo "== waiting for export"
sleep 8
stats=$(docker compose logs agent | grep "INFO stats" | tail -1)
echo "agent: ${stats#*INFO }"
queries=$(sed -E 's/.* queries=([0-9]+).*/\1/' <<<"$stats")
drops=$(sed -E 's/.*kernel_drops=([0-9]+).*/\1/' <<<"$stats")

total=$(count 'name:*')
div0=$(count '"span_attr:db.response.status_code":22012')
missing=$(count '"span_attr:db.response.status_code":"42P01"')
slow=$(count '"span_attr:db.query.text":"select pg_sleep(0.2)" duration:>=200000000')
ratio_kept=$(count '"span_attr:pgtrace.sample_reason":ratio')
extended=$(count '"span_attr:pgtrace.protocol":extended')
ops=$(logsql 'name:* | stats by (name) count() n' | python3 -c 'import json,sys; print(" ".join(sorted(json.loads(l)["name"] for l in sys.stdin if l.strip())))')
# The Jaeger search index is built with a delay; poll for it.
jaeger=0
for i in $(seq 1 45); do
	jaeger=$(curl -fsS "$VT/select/jaeger/api/traces?service=pgbouncer&tags=%7B%22error%22%3A%22true%22%7D&limit=100" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["data"]))')
	[ "$jaeger" -ge 10 ] && break
	sleep 2
done

echo "spans total=$total div0=$div0 missing_table=$missing slow=$slow ratio_kept=$ratio_kept extended=$extended jaeger_errors=$jaeger"
echo "operations: $ops"

check "all 5 division-by-zero errors kept"      $([ "$div0" -eq 5 ]; echo $?)
check "all 5 missing-table errors kept"         $([ "$missing" -eq 5 ]; echo $?)
check "all 5 slow queries kept (>=200ms)"       $([ "$slow" -eq 5 ]; echo $?)
check "jaeger API returns the 10 error traces"  $([ "$jaeger" -eq 10 ]; echo $?)
check "extended-protocol spans present"         $([ "$extended" -gt 0 ]; echo $?)
for op in SELECT UPDATE INSERT; do
	check "operation $op present" $(grep -qw "$op" <<<"$ops"; echo $?)
done
check "no kernel drops"                         $([ "$drops" -eq 0 ]; echo $?)
# pgbench tpcb: 7 statements/tx, 3 modes.
expected=$((CLIENTS * TX * 7 * 3))
check "agent parsed >= $expected queries ($queries)" $([ "$queries" -ge "$expected" ]; echo $?)
check "ratio-sampled share within ±20% of $RATIO" $(python3 -c "
kept, q = $ratio_kept, $queries - $div0 - $missing - $slow
r = kept / q
print(f'  observed ratio {r:.4f} ({kept}/{q})', file=__import__('sys').stderr)
exit(0 if abs(r - $RATIO) <= 0.2 * $RATIO else 1)"; echo $?)

if [ "$fail" -ne 0 ]; then
	echo "E2E FAILED"; docker compose logs agent | tail -20; exit 1
fi
echo "E2E PASSED"
