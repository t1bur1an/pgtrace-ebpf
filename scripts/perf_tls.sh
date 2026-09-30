#!/usr/bin/env bash
# Cost of TLS capture: no TLS / no TLS + agent / TLS / TLS + agent (capture
# off) / TLS + agent (capture on), pgbench -S simple, alternated repetitions.
#   DURATION=20 REPEATS=3 CLIENTS="8 64" ./scripts/perf_tls.sh
# Capture-on runs start once the startup fallback has detached (steady
# state); FALLBACK=on measures with it attached (the first 30 s after start).
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root/deploy"
DURATION=${DURATION:-20}
REPEATS=${REPEATS:-3}
CLIENTS=${CLIENTS:-"8 64"}
OUT=${OUT:-$root/docs/perf-results/tls}
export BUILDX_BUILDER=${BUILDX_BUILDER:-default} PGTRACE_STATS_INTERVAL=5s
mkdir -p "$OUT"
csv="$OUT/results.csv"
echo "rep,config,clients,tps,lat_ms,pgbouncer_cpu_pct,pgbouncer_us_per_q,agent_cpu_pct,client_q_per_s,kernel_drops,tls_dropped" > "$csv"
cg() { echo "/sys/fs/cgroup/system.slice/docker-$(docker inspect -f '{{.Id}}' "$1").scope"; }
cpu_usec() { awk '/^usage_usec/ {print $2}' "$(cg "$1")/cpu.stat" 2>/dev/null || echo 0; }
./tls/gencerts.sh >/dev/null

stack() { # stack plain|tls
	docker compose down --remove-orphans >/dev/null 2>&1 || true
	if [ "$1" = tls ]; then export COMPOSE_FILE=docker-compose.yml:tls/compose.tls.yml; else unset COMPOSE_FILE; fi
	docker compose up -d --build --wait postgres pgbouncer victoriatraces >/dev/null 2>&1
	docker compose build agent >/dev/null 2>&1
	docker compose run --rm -T loadgen pgbench -i -s 10 -q >/dev/null 2>&1
}
agent() { # agent off|plain|tls-off|tls-on
	docker compose stop agent >/dev/null 2>&1 || true
	[ "$1" = off ] && return
	PGTRACE_TLS_CAPTURE=$([ "$1" = tls-on ] && echo true || echo false) docker compose up -d agent >/dev/null 2>&1
	for _ in $(seq 1 30); do docker compose logs agent --since 60s 2>/dev/null | grep -q "INFO attached" && break; sleep 1; done
	docker compose logs agent --since 60s 2>/dev/null | grep -q "INFO attached" || { echo "agent did not start" >&2; exit 1; }
	sleep 2
	# Measure steady state: the fallback for pre-existing TLS sessions is
	# attached at startup and detaches 30 s after it was last needed.
	if [ "$1" = tls-on ] && [ "${FALLBACK:-steady}" = steady ]; then
		for _ in $(seq 1 60); do
			curl -fsS localhost:9464/metrics 2>/dev/null | grep -q '^pgtrace_tls_fallback_attached 0' && return
			sleep 1
		done
		echo "tls fallback did not detach" >&2; exit 1
	fi
}
run() { # run <rep> <config> <clients> <agent mode>
	local rep=$1 cfg=$2 c=$3 mode=$4 p0 p1 a0=0 a1=0 res tps lat start st
	agent "$mode"
	start=$(date -u +%Y-%m-%dT%H:%M:%SZ)
	p0=$(cpu_usec pgtrace-pgbouncer-1); [ "$mode" != off ] && a0=$(cpu_usec pgtrace-agent-1)
	res=$(docker compose run --rm -T loadgen pgbench -S -M simple -c "$c" -j $((c < 8 ? c : 8)) -T "$DURATION" -n 2>&1)
	p1=$(cpu_usec pgtrace-pgbouncer-1); [ "$mode" != off ] && a1=$(cpu_usec pgtrace-agent-1)
	tps=$(sed -nE 's/^tps = ([0-9.]+).*/\1/p' <<<"$res")
	lat=$(sed -nE 's/^latency average = ([0-9.]+) ms/\1/p' <<<"$res")
	st=""; drop=""
	if [ "$mode" != off ]; then
		sleep 6
		st=$(docker compose logs agent --since "$start" | grep "INFO stats" | tail -1)
		drop=$(curl -fsS localhost:9464/metrics | awk '/^pgtrace_tls_unresolved_total\{result="dropped"\}/ {print $2}')
	fi
	python3 - "$rep" "$cfg" "$c" "$tps" "$lat" "$p0" "$p1" "$a0" "$a1" "$DURATION" "$st" "${drop:-}" >> "$csv" <<'PY'
import re, sys
rep, cfg, c, tps, lat, p0, p1, a0, a1, d, st, drop = sys.argv[1:]
tps, d = float(tps), float(d)
pcpu = (int(p1) - int(p0)) / 1e6 / d
kv = dict(re.findall(r"(\w+)=(\S+)", st))
qps = f'{int(kv["traces"]) / d:.0f}' if "traces" in kv else ""
print(",".join([rep, cfg, c, f"{tps:.0f}", lat, f"{pcpu*100:.1f}", f"{pcpu/tps*1e6:.2f}",
                f"{(int(a1)-int(a0))/1e6/d*100:.1f}" if int(a1) else "", qps, kv.get("kernel_drops", ""), drop]))
PY
	tail -1 "$csv"
}

echo "== plain stack"; stack plain
for rep in $(seq 1 "$REPEATS"); do for c in $CLIENTS; do
	run "$rep" notls "$c" off; run "$rep" notls-agent "$c" plain
done; done
echo "== tls stack"; stack tls
for rep in $(seq 1 "$REPEATS"); do for c in $CLIENTS; do
	run "$rep" tls "$c" off; run "$rep" tls-agent-capture-off "$c" tls-off; run "$rep" tls-agent-capture-on "$c" tls-on
done; done
docker compose stop agent >/dev/null 2>&1 || true
{ echo "date: $(date -Is)"; echo "cpu: $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | xargs) ($(nproc) threads)"
  echo "kernel: $(uname -r)"; echo "pgbench -S -M simple, ${DURATION}s x $REPEATS, clients: $CLIENTS"
  echo "tls: TLSv1.3 both hops, client certificates verified (deploy/tls, strict)"; } > "$OUT/host.txt"
echo "results: $csv"
