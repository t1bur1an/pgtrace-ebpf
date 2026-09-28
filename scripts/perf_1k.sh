#!/usr/bin/env bash
# 1,000-client benchmark: agent overhead at high client counts, and the cost
# of attaching pgbouncer's parameter-sync statements. Results: docs/perf-results/1k/.
#
#   DURATION=30 REPEATS=3 ./scripts/perf_1k.sh
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root/deploy"
DURATION=${DURATION:-30}
REPEATS=${REPEATS:-3}
OUT=${OUT:-$root/docs/perf-results/1k}
export BUILDX_BUILDER=${BUILDX_BUILDER:-default} PGTRACE_STATS_INTERVAL=5s PGTRACE_SAMPLE_RATIO=0.1
mkdir -p "$OUT"
csv="$OUT/results.csv"
echo "rep,workload,config,tps,lat_ms,pgbouncer_cpu_pct,agent_cpu_pct,agent_rss_mb,client_q_per_s,traces_per_s,corr_exact,corr_inferred,corr_internal,corr_none,corr_orphan,kernel_drops" > "$csv"

cg() { echo "/sys/fs/cgroup/system.slice/docker-$(docker inspect -f '{{.Id}}' "$1").scope"; }
cpu_usec() { awk '/^usage_usec/ {print $2}' "$(cg "$1")/cpu.stat" 2>/dev/null || echo 0; }
scrape() { curl -fsS localhost:9464/metrics 2>/dev/null || true; }

echo "== fresh stack"
docker compose down --remove-orphans >/dev/null 2>&1 || true
docker compose up -d --build --wait postgres pgbouncer victoriatraces prometheus >/dev/null 2>&1
docker compose build agent >/dev/null 2>&1
docker compose run --rm -T loadgen pgbench -i -s 10 -q >/dev/null 2>&1
{
	echo "date: $(date -Is)"
	echo "cpu: $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | xargs) ($(nproc) threads)"
	echo "kernel: $(uname -r)"
	echo "clients: 1000 (pgbouncer default_pool_size=20, max_client_conn=2000)"
	echo "duration_per_run_s: $DURATION, repeats: $REPEATS"
} > "$OUT/host.txt"

agent() { # agent off | agent <client_tracing> <labels> <attach_param_sync>
	docker compose stop agent >/dev/null 2>&1 || true
	[ "$1" = off ] && return
	PGTRACE_CLIENT_TRACING=$1 PGTRACE_METRICS_LABELS=$2 PGTRACE_ATTACH_PARAM_SYNC=$3 docker compose up -d agent >/dev/null 2>&1
	for _ in $(seq 1 30); do docker compose logs agent --since 60s 2>/dev/null | grep -q "INFO attached" && sleep 2 && return; sleep 1; done
	echo "agent did not start" >&2; exit 1
}

workload() { # single | apps
	if [ "$1" = single ]; then
		docker compose run --rm -T loadgen pgbench -S -M simple -c 1000 -j 16 -T "$DURATION" -n 2>&1
	else
		docker compose run --rm -T loadgen sh -c "for i in 0 1 2 3 4 5 6 7 8 9; do
			PGAPPNAME=app\$i pgbench -S -M simple -c 100 -j 2 -T $DURATION -n > /tmp/o\$i 2>&1 &
		done; wait; cat /tmp/o*"
	fi
}

run() { # run <rep> <workload> <config-name> <agent args...>
	local rep=$1 wl=$2 name=$3; shift 3
	agent "$@"
	local on=$([ "$1" = off ] && echo 0 || echo 1)
	local a0=0 a1=0 p0 p1 sampler="" tmp
	tmp=$(mktemp -d)
	: > "$tmp/m0"; : > "$tmp/m1"; : > "$tmp/mem"
	p0=$(cpu_usec pgtrace-pgbouncer-1)
	if [ "$on" = 1 ]; then
		a0=$(cpu_usec pgtrace-agent-1); scrape > "$tmp/m0"
		( while :; do cat "$(cg pgtrace-agent-1)/memory.current"; sleep 1; done ) > "$tmp/mem" 2>/dev/null &
		sampler=$!
	fi
	workload "$wl" > "$tmp/res"
	p1=$(cpu_usec pgtrace-pgbouncer-1)
	if [ "$on" = 1 ]; then
		a1=$(cpu_usec pgtrace-agent-1); sleep 6; scrape > "$tmp/m1"; kill "$sampler" 2>/dev/null || true
	fi
	python3 "$root/scripts/perf_1k_row.py" "$rep" "$wl" "$name" "$DURATION" "$p0" "$p1" "$a0" "$a1" \
		"$tmp/res" "$tmp/m0" "$tmp/m1" "$([ "$on" = 1 ] && echo "$tmp/mem")" >> "$csv"
	tail -1 "$csv"
	rm -rf "$tmp"
}

for rep in $(seq 1 "$REPEATS"); do
	run "$rep" single off off
	run "$rep" single server-only false "" true
	run "$rep" single client+server true "" true
	run "$rep" single client+server+labels true database,user,client_addr true
	run "$rep" apps off off
	run "$rep" apps attach-param-sync true "" true
	run "$rep" apps no-attach true "" false
done
agent off
echo "results: $csv"
