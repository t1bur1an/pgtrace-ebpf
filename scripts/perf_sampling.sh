#!/usr/bin/env bash
# Sampling-ratio benchmark at 1,000 clients: agent off vs 10 % vs 100 %
# sampling, measuring the agent, the export pipeline and VictoriaTraces.
# Results: docs/perf-results/sampling/.
#
#   DURATION=30 REPEATS=3 ./scripts/perf_sampling.sh
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root/deploy"
DURATION=${DURATION:-30}
REPEATS=${REPEATS:-3}
OUT=${OUT:-$root/docs/perf-results/sampling}
export BUILDX_BUILDER=${BUILDX_BUILDER:-default} PGTRACE_STATS_INTERVAL=5s PGTRACE_PPROF=true
mkdir -p "$OUT/profiles"
csv="$OUT/results.csv"
echo "rep,config,tps,lat_ms,pgbouncer_cpu_pct,agent_cpu_pct,agent_rss_mb,vt_cpu_pct,vt_rss_mb,client_q_per_s,spans_created_per_s,spans_exported_per_s,export_failed_batches,export_backlog,export_dropped_spans,kernel_drops,vt_stored_spans,vt_lag_s" > "$csv"

cg() { echo "/sys/fs/cgroup/system.slice/docker-$(docker inspect -f '{{.Id}}' "$1").scope"; }
cpu_usec() { awk '/^usage_usec/ {print $2}' "$(cg "$1")/cpu.stat" 2>/dev/null || echo 0; }
scrape() { curl -fsS localhost:9464/metrics 2>/dev/null || true; }
vtcount() { curl -fsS http://localhost:10428/select/logsql/query --data-urlencode "query=$1 | stats count() n" | python3 -c 'import json,sys; t=sys.stdin.read().strip(); print(json.loads(t)["n"] if t else 0)'; }

echo "== fresh stack"
docker compose down --remove-orphans >/dev/null 2>&1 || true
docker compose up -d --build --wait postgres pgbouncer victoriatraces prometheus >/dev/null 2>&1
docker compose build agent >/dev/null 2>&1
docker compose run --rm -T loadgen pgbench -i -s 10 -q >/dev/null 2>&1
{
	echo "date: $(date -Is)"
	echo "cpu: $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | xargs) ($(nproc) threads)"
	echo "clients: 1000 select-only simple, duration_per_run_s: $DURATION, repeats: $REPEATS"
	echo "agent: client tracing, labels database,user,client_addr, param-sync attach"
} > "$OUT/host.txt"

agent() { # agent off | agent <ratio>
	docker compose stop agent >/dev/null 2>&1 || true
	[ "$1" = off ] && return
	PGTRACE_SAMPLE_RATIO=$1 docker compose up -d agent >/dev/null 2>&1
	for _ in $(seq 1 30); do docker compose logs agent --since 60s 2>/dev/null | grep -q "INFO attached" && sleep 2 && return; sleep 1; done
	echo "agent did not start" >&2; exit 1
}

run() { # run <rep> <config> <ratio|off> [profile]
	local rep=$1 name=$2 ratio=$3 prof=${4:-}
	agent "$ratio"
	local tmp; tmp=$(mktemp -d)
	: > "$tmp/m0"; : > "$tmp/m1"; : > "$tmp/mem"; : > "$tmp/vtmem"
	local p0 a0=0 v0 sampler vsampler
	local s0; s0=$(vtcount '*')
	p0=$(cpu_usec pgtrace-pgbouncer-1); v0=$(cpu_usec pgtrace-victoriatraces-1)
	( while :; do cat "$(cg pgtrace-victoriatraces-1)/memory.current"; sleep 1; done ) > "$tmp/vtmem" 2>/dev/null & vsampler=$!
	if [ "$ratio" != off ]; then
		a0=$(cpu_usec pgtrace-agent-1); scrape > "$tmp/m0"
		( while :; do cat "$(cg pgtrace-agent-1)/memory.current"; sleep 1; done ) > "$tmp/mem" 2>/dev/null & sampler=$!
	fi
	if [ -n "$prof" ]; then
		( sleep 5; curl -fsS -o "$OUT/profiles/cpu-ratio-$ratio.pb.gz" "http://localhost:9464/debug/pprof/profile?seconds=20" ) &
	fi
	docker compose run --rm -T loadgen pgbench -S -M simple -c 1000 -j 16 -T "$DURATION" -n > "$tmp/res" 2>&1
	local p1 a1=0 v1
	p1=$(cpu_usec pgtrace-pgbouncer-1); v1=$(cpu_usec pgtrace-victoriatraces-1)
	[ "$ratio" != off ] && a1=$(cpu_usec pgtrace-agent-1)
	# The batch processor exports every 2 s; give it and VictoriaTraces a moment.
	sleep 5
	[ "$ratio" != off ] && { scrape > "$tmp/m1"; kill "$sampler" 2>/dev/null || true; }
	local s1; s1=$(vtcount '*')
	# Ingestion lag: how long until VictoriaTraces holds everything exported.
	local lag=0
	if [ "$ratio" != off ]; then
		local want; want=$(python3 -c "import re;t=open('$tmp/m1').read();print(int(sum(float(v) for v in re.findall(r'^pgtrace_export_spans_total\{stage=\"exported\"\} (\S+)$',t,re.M))))")
		local base; base=$s0
		for lag in $(seq 0 60); do
			[ "$(( $(vtcount '*') - base ))" -ge "$(( want - $(python3 -c "import re;t=open('$tmp/m0').read();print(int(sum(float(v) for v in re.findall(r'^pgtrace_export_spans_total\{stage=\"exported\"\} (\S+)$',t,re.M))))") ))" ] && break
			sleep 1
		done
		s1=$(vtcount '*')
	fi
	kill "$vsampler" 2>/dev/null || true
	python3 "$root/scripts/perf_sampling_row.py" "$rep" "$name" "$DURATION" "$p0" "$p1" "$a0" "$a1" "$v0" "$v1" \
		"$tmp/res" "$tmp/m0" "$tmp/m1" "$tmp/mem" "$tmp/vtmem" "$s0" "$s1" "$lag" >> "$csv"
	tail -1 "$csv"
	rm -rf "$tmp"
}

for rep in $(seq 1 "$REPEATS"); do
	run "$rep" off off
	run "$rep" ratio-0.1 0.1
	run "$rep" ratio-1.0 1 "$([ "$rep" = 1 ] && echo profile)"
done
agent off
echo "results: $csv"
