#!/usr/bin/env bash
# Load test: pgbench through pgbouncer with the agent stopped (baseline) and
# running, across workloads and client counts. Writes CSV + host info to
# docs/perf-results/.
#
#   DURATION=20 CLIENTS="1 8 32 64" ./scripts/perf.sh
#   SKIP_MATRIX=1 ./scripts/perf.sh   # only the repeat + breakdown sections
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root/deploy"

DURATION=${DURATION:-20}
CLIENTS=${CLIENTS:-1 8 32 64}
WORKLOADS=${WORKLOADS:-select-simple select-extended tpcb-simple}
STRESS_CLIENTS=${STRESS_CLIENTS:-64}
OUT=${OUT:-$root/docs/perf-results}
VT=${VT:-http://localhost:10428}
export BUILDX_BUILDER=${BUILDX_BUILDER:-default}
export PGTRACE_STATS_INTERVAL=2s PGTRACE_BPF_STATS=${PGTRACE_BPF_STATS:-true}
mkdir -p "$OUT"
csv="$OUT/results.csv"
SKIP_MATRIX=${SKIP_MATRIX:-0}
REPEATS=${REPEATS:-3}
header="workload,mode,clients,agent,ratio,tps,lat_ms,pgbouncer_cpu_pct,agent_cpu_pct,agent_mem_mb,queries_per_s,kept,kernel_drops,bpf_ns_per_run,bpf_runs_per_query"
[ "$SKIP_MATRIX" = 1 ] || echo "$header" > "$csv"

cg() { echo "/sys/fs/cgroup/system.slice/docker-$(docker inspect -f '{{.Id}}' "$1").scope"; }
cpu_usec() { awk '/^usage_usec/ {print $2}' "$(cg "$1")/cpu.stat"; }

{
	echo "date: $(date -Is)"
	echo "cpu: $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | xargs) ($(nproc) threads)"
	echo "memory: $(free -g | awk '/Mem:/ {print $2}') GiB"
	echo "kernel: $(uname -r)"
	echo "docker: $(docker version -f '{{.Server.Version}}')"
	echo "pgbouncer: $(docker compose run --rm -T --entrypoint pgbouncer pgbouncer --version 2>/dev/null | head -1)"
	echo "postgres: $(docker compose run --rm -T loadgen postgres --version 2>/dev/null)"
	echo "duration_per_run_s: $DURATION"
} > "$OUT/host.txt"

echo "== starting stack"
docker compose down --remove-orphans >/dev/null 2>&1 || true
docker compose up -d --build --wait postgres pgbouncer victoriatraces >/dev/null 2>&1
docker compose build agent >/dev/null 2>&1
docker compose run --rm -T loadgen pgbench -i -s 10 -q >/dev/null 2>&1

agent_on() { # agent_on <ratio> [comm] [bpf-stats]
	PGTRACE_SAMPLE_RATIO=$1 PGTRACE_COMM=${2:-pgbouncer} PGTRACE_BPF_STATS=${3:-$PGTRACE_BPF_STATS} \
		docker compose up -d agent >/dev/null 2>&1
	for _ in $(seq 1 30); do
		docker compose logs agent --since 60s 2>/dev/null | grep -q "INFO attached" && return
		sleep 1
	done
	echo "agent did not attach" >&2; exit 1
}
agent_off() { docker compose stop agent >/dev/null 2>&1 || true; }

run_case() { # run_case <workload> <clients> <agent on|off> <ratio>
	local wl=$1 c=$2 on=$3 ratio=$4 mode flags=()
	mode=${wl#*-}
	[[ $wl == select-* ]] && flags+=(-S)
	if [ "$on" = on ]; then agent_off; agent_on "$ratio"; else agent_off; fi
	local start pgb0 ag0=0 mempeak=0 memfile
	start=$(date -u +%Y-%m-%dT%H:%M:%SZ)
	pgb0=$(cpu_usec pgtrace-pgbouncer-1)
	[ "$on" = on ] && ag0=$(cpu_usec pgtrace-agent-1)
	local sampler_pid=""
	memfile=$(mktemp)
	if [ "$on" = on ]; then
		( while :; do cat "$(cg pgtrace-agent-1)/memory.current"; sleep 1; done ) > "$memfile" 2>/dev/null &
		sampler_pid=$!
	fi
	local res
	res=$(docker compose run --rm -T loadgen pgbench "${flags[@]}" -M "$mode" -c "$c" -j $((c < 8 ? c : 8)) -T "$DURATION" -n 2>&1)
	local pgb1 ag1=0
	pgb1=$(cpu_usec pgtrace-pgbouncer-1)
	[ "$on" = on ] && { ag1=$(cpu_usec pgtrace-agent-1); kill "$sampler_pid" 2>/dev/null || true; }
	local tps lat
	tps=$(sed -nE 's/^tps = ([0-9.]+).*/\1/p' <<<"$res")
	lat=$(sed -nE 's/^latency average = ([0-9.]+) ms/\1/p' <<<"$res")
	local qps="" kept="" drops="" bpfns="" bpfrq="" mem=""
	if [ "$on" = on ]; then
		sleep 3 # let the next stats line cover the whole run
		local st
		st=$(docker compose logs agent --since "$start" | grep "INFO stats" | tail -1)
		read -r qps kept drops bpfns bpfrq < <(python3 - "$st" "$DURATION" <<'PY'
import re, sys
kv = dict(re.findall(r'(\w+)=(\S+)', sys.argv[1]))
d = float(sys.argv[2])
q = int(kv["queries"]); runs = int(kv["bpf_runs"]); ns = int(kv["bpf_ns"])
kept = int(kv["kept_error"]) + int(kv["kept_slow"]) + int(kv["kept_ratio"])
print(f'{q/d:.0f} {kept} {kv["kernel_drops"]} {ns/runs if runs else 0:.0f} {runs/q if q else 0:.2f}')
PY
)
		mem=$(sort -n "$memfile" | tail -1 | awk '{printf "%.1f", $1/1048576}')
	fi
	rm -f "$memfile"
	local pgbcpu agcpu
	pgbcpu=$(python3 -c "print(f'{($pgb1-$pgb0)/1e6/$DURATION*100:.1f}')")
	agcpu=$([ "$on" = on ] && python3 -c "print(f'{($ag1-$ag0)/1e6/$DURATION*100:.1f}')" || echo "")
	echo "$wl,$mode,$c,$on,$ratio,$tps,$lat,$pgbcpu,$agcpu,$mem,$qps,$kept,$drops,$bpfns,$bpfrq" | tee -a "$csv"
}

if [ "$SKIP_MATRIX" != 1 ]; then
for wl in $WORKLOADS; do
	for c in $CLIENTS; do
		run_case "$wl" "$c" off ""
		run_case "$wl" "$c" on 0.1
	done
done
echo "== stress: export every query (ratio 1.0)"
for wl in select-simple select-extended; do
	run_case "$wl" "$STRESS_CLIENTS" on 1
done
agent_off

echo "== export completeness"
sleep 5
# Agent counters reset on every restart, so sum the per-run kept column.
kept_total=$(awk -F, 'NR > 1 && $4 == "on" {s += $12} END {print s}' "$csv")
vt_total=$(curl -fsS "$VT/select/logsql/query" --data-urlencode 'query=name:* | stats count() n' | python3 -c 'import json,sys; print(json.load(sys.stdin)["n"])')
echo "spans kept by agent (logged): $kept_total, spans stored in VictoriaTraces: $vt_total" | tee "$OUT/completeness.txt"
fi

if [ "${SKIP_REPEATS:-0}" != 1 ]; then
echo "== repeats: alternating off/on, $REPEATS reps (noise check)"
csv="$OUT/repeats.csv"
echo "rep,$header" > "$csv"
for rep in $(seq 1 "$REPEATS"); do
	for c in 8 32; do
		for on in off on; do
			printf '%s,' "$rep" >> "$csv"
			run_case tpcb-simple "$c" "$on" "$([ $on = on ] && echo 0.1)"
		done
	done
	for on in off on; do
		printf '%s,' "$rep" >> "$csv"
		run_case select-simple 8 "$on" "$([ $on = on ] && echo 0.1)"
	done
done

fi

if [ "${SKIP_NOSYNC:-0}" != 1 ]; then
# Write-heavy workload without commit fsyncs/checkpoints in the way, so the
# result reflects CPU overhead rather than storage variance.
echo "== tpcb with synchronous_commit=off, $REPEATS reps"
docker compose run --rm -T loadgen sh -c "psql -qc 'ALTER SYSTEM SET synchronous_commit = off' && psql -qc 'ALTER SYSTEM SET max_wal_size = \"20GB\"' && psql -qc 'ALTER SYSTEM SET checkpoint_timeout = \"1h\"' && psql -qc 'SELECT pg_reload_conf()' && psql -qc 'CHECKPOINT'" >/dev/null
csv="$OUT/tpcb-nosync.csv"
echo "rep,$header" > "$csv"
for rep in $(seq 1 "$REPEATS"); do
	for c in 8 32; do
		for on in off on; do
			printf '%s,' "$rep" >> "$csv"
			run_case tpcb-simple "$c" "$on" "$([ $on = on ] && echo 0.1)"
		done
	done
done
docker compose run --rm -T loadgen sh -c "psql -qc 'ALTER SYSTEM RESET ALL' && psql -qc 'SELECT pg_reload_conf()'" >/dev/null
fi

if [ "${SKIP_BREAKDOWN:-0}" != 1 ]; then
echo "== overhead breakdown (select-simple, 8 clients, ${DURATION}s, $REPEATS reps)"
bd="$OUT/breakdown.csv"
echo "rep,config,tps" > "$bd"
for rep in $(seq 1 "$REPEATS"); do
	for cfg in off attached-idle traced traced+bpf-stats; do
		agent_off
		case $cfg in
			attached-idle) agent_on 0.1 __nothing__ false ;;
			traced) agent_on 0.1 pgbouncer false ;;
			traced+bpf-stats) agent_on 0.1 pgbouncer true ;;
		esac
		tps=$(docker compose run --rm -T loadgen pgbench -S -M simple -c 8 -j 8 -T "$DURATION" -n 2>&1 | sed -nE 's/^tps = ([0-9.]+).*/\1/p')
		echo "$rep,$cfg,$tps" | tee -a "$bd"
	done
done
agent_off
fi
echo "results in $OUT"
