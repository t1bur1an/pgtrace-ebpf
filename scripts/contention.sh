#!/usr/bin/env bash
# Contention suite: deadlocks, lock waits, lock/statement timeouts,
# serialization failures, pool exhaustion, pgbouncer queue timeouts,
# idle-in-transaction and rejected logins, checked in traces and metrics.
set -euo pipefail
cd "$(dirname "$0")/../deploy"
export BUILDX_BUILDER=${BUILDX_BUILDER:-default} PGTRACE_STATS_INTERVAL=2s
export PGTRACE_SAMPLE_RATIO=${PGTRACE_SAMPLE_RATIO:-0.1}

echo "== starting stack (fresh)"
docker compose down --remove-orphans >/dev/null 2>&1 || true
docker compose up -d --build --wait postgres pgbouncer victoriatraces prometheus grafana >/dev/null 2>&1
docker compose up -d --build agent >/dev/null 2>&1
for _ in $(seq 1 30); do docker compose logs agent 2>/dev/null | grep -q "tracing process" && break; sleep 1; done

echo "== scenarios"
docker compose run --rm -T loadgen sh /contention/scenarios.sh
echo "== waiting for export and a scrape"
sleep 12
python3 ../scripts/contention_check.py
