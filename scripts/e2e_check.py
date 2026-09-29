#!/usr/bin/env python3
"""Assertions for scripts/e2e.sh against VictoriaTraces, the agent's /metrics,
Prometheus and Grafana. Exits non-zero if any check fails."""
import argparse
import json
import os
import re
import subprocess
import sys
import time
import urllib.parse
import urllib.request

VT = "http://localhost:10428"
failures = 0


def check(desc, ok, detail=""):
    global failures
    print(("PASS  " if ok else "FAIL  ") + desc + (f"  ({detail})" if detail else ""))
    if not ok:
        failures += 1


def get(url, data=None):
    body = urllib.parse.urlencode(data).encode() if data else None
    with urllib.request.urlopen(url, body, timeout=30) as r:
        return r.read().decode()


def logsql(query):
    out = get(f"{VT}/select/logsql/query", {"query": query})
    return [json.loads(l) for l in out.splitlines() if l.strip()]


def count(query):
    rows = logsql(query + " | stats count() n")
    return int(rows[0]["n"]) if rows else 0


ap = argparse.ArgumentParser()
ap.add_argument("--ratio", type=float, required=True)
ap.add_argument("--min-traces", type=int, required=True)
ap.add_argument("--stats", required=True)
ap.add_argument("--deploy", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "deploy"))
args = ap.parse_args()
stats = {k: int(v) for k, v in re.findall(r"(\w+)=(\d+)", args.stats)}

ROOT, CHILD = "kind:2", "kind:3"
code = lambda c: f'"span_attr:db.response.status_code":"{c}"'

# --- volume, loss, sampling -------------------------------------------------
check("no kernel drops", stats["kernel_drops"] == 0, f'{stats["kernel_drops"]} drops')
check(f"agent saw >= {args.min_traces} traces", stats["traces"] >= args.min_traces, f'{stats["traces"]}')
kept = stats["kept_error"] + stats["kept_slow"] + stats.get("kept_parent", 0) + stats["kept_ratio"]
exported = count(f'{ROOT} -"span_attr:pgtrace.connection_error":true') + count(f'{CHILD} "span_attr:pgtrace.correlation":none')
check("every kept trace reached VictoriaTraces", exported == kept, f"{exported} stored / {kept} kept")
normal = stats["traces"] - stats["kept_error"] - stats["kept_slow"] - stats.get("kept_parent", 0)
r = stats["kept_ratio"] / normal
check(f"ratio-sampled share within ±20% of {args.ratio}", abs(r - args.ratio) <= 0.2 * args.ratio, f"{r:.4f}")

# --- errors and slow queries ------------------------------------------------
for c, name in (("22012", "division by zero"), ("42P01", "missing table")):
    roots = {x["trace_id"] for x in logsql(f"{ROOT} {code(c)} | fields trace_id")}
    kids = {x["trace_id"] for x in logsql(f"{CHILD} {code(c)} | fields trace_id")}
    check(f"all 5 {name} errors kept as root + child", len(roots) == 5 and roots == kids, f"{len(roots)} roots, {len(kids)} children")
slow = count(f'{ROOT} "span_attr:db.query.text":"select pg_sleep(0.2)" duration:>=200000000')
check("all 5 slow queries kept (>=200ms)", slow == 5, f"{slow}")
admin = logsql(f'{ROOT} "span_attr:db.namespace":pgbouncer status_code:2 | fields trace_id')
admin_ids = {x["trace_id"] for x in admin}
admin_kids = [x for x in logsql(f"{CHILD} | fields trace_id") if x["trace_id"] in admin_ids]
check("pgbouncer-generated errors are client roots without a server child", len(admin_ids) == 5 and not admin_kids,
      f"{len(admin_ids)} roots, {len(admin_kids)} children")

# --- correlation quality ----------------------------------------------------
roots = logsql(f'{ROOT} "span_attr:application_name":pgbench | fields trace_id, span_id, start_time_unix_nano, end_time_unix_nano, "span_attr:db.query.text", "span_attr:pgtrace.correlation"')
children = logsql(f'{CHILD} "span_attr:pgbouncer.internal":false | fields trace_id, parent_span_id, start_time_unix_nano, end_time_unix_nano, "span_attr:db.query.text"')
by_trace = {}
for c in children:
    by_trace.setdefault(c["trace_id"], []).append(c)
linked = sum(1 for x in roots if x["span_attr:pgtrace.correlation"] in ("exact", "inferred"))
check("≥ 99% of sampled pgbench client queries linked to a server query", roots and linked / len(roots) >= 0.99,
      f"{linked}/{len(roots)}")
bad_time = bad_sql = bad_count = 0
for x in roots:
    kids = by_trace.get(x["trace_id"], [])
    if len(kids) != 1:
        bad_count += 1
        continue
    k = kids[0]
    if not (int(x["start_time_unix_nano"]) <= int(k["start_time_unix_nano"]) and int(k["end_time_unix_nano"]) <= int(x["end_time_unix_nano"])):
        bad_time += 1
    if k["span_attr:db.query.text"] != x["span_attr:db.query.text"]:
        bad_sql += 1
check("each pgbench root has exactly one forwarded server child", bad_count <= len(roots) * 0.01, f"{bad_count} exceptions")
check("server child lies within its client root", bad_time == 0, f"{bad_time} violations")
check("server child SQL equals client SQL", bad_sql == 0, f"{bad_sql} mismatches")
inferred = sum(1 for x in roots if x["span_attr:pgtrace.correlation"] == "inferred")
print(f"      correlation: {linked - inferred} exact, {inferred} inferred of {len(roots)} sampled pgbench roots")

tiny = logsql(f'{ROOT} "span_attr:db.namespace":tiny | stats max("span_attr:pgbouncer.pool_wait_ms") mx, count() n')
mx = float(tiny[0]["mx"]) if tiny and tiny[0].get("mx") else 0.0
check("pool waits > 10 ms visible on the undersized pool", mx > 10, f"max {mx:.1f} ms over {tiny[0]['n'] if tiny else 0} traces")

# --- Jaeger API (search index lags ingestion) -------------------------------
jaeger = 0
for _ in range(45):
    q = urllib.parse.quote(json.dumps({"error": "true"}))
    jaeger = len(json.loads(get(f"{VT}/select/jaeger/api/traces?service=pgbouncer&tags={q}&limit=100"))["data"])
    if jaeger >= 15:
        break
    time.sleep(2)
check("Jaeger API returns the 15 error traces", jaeger >= 15, f"{jaeger}")

# --- metrics, Prometheus, Grafana -------------------------------------------
metrics = get("http://localhost:9464/metrics")
val = lambda pat: sum(float(m) for m in re.findall(pat + r"\S* ([0-9.e+]+)$", metrics, re.M))
check("/metrics counts client queries", val(r'^pgtrace_queries_total\{[^}]*side="client"') > 0)
check("/metrics has pool wait observations", val(r"^pgtrace_pool_wait_seconds_count") > 0)
check("/metrics counts correlation results", val(r'^pgtrace_correlation_total\{result="exact"\}') > 0)
targets = json.loads(get("http://localhost:9090/api/v1/targets"))["data"]["activeTargets"]
check("Prometheus scrapes the agent", any(t["labels"]["job"] == "pgtrace-agent" and t["health"] == "up" for t in targets))
dash = json.loads(get("http://localhost:3000/api/dashboards/uid/pgtrace"))
check("Grafana has the pgtrace dashboard", dash["dashboard"]["uid"] == "pgtrace")
for ds in ("prometheus", "victoriatraces"):
    h = json.loads(get(f"http://localhost:3000/api/datasources/uid/{ds}/health"))
    check(f"Grafana datasource {ds} healthy", h.get("status") == "OK", h.get("message", ""))

# --- caps, truncation, labelled metrics, cardinality ------------------------
log = subprocess.run(["docker", "compose", "logs", "agent"], capture_output=True, text=True, cwd=args.deploy).stdout
check("agent loaded BPF with capture_bytes=8192", "capture_bytes=8192" in log and "tracing process" in log)
check("parser truncation counted for the 100 KB statement", val(r'^pgtrace_truncations_total\{layer="parser"\}') >= 2,
      f'{val(r"^pgtrace_truncations_total\{layer=\"parser\"\}"):.0f} (client + server copies)')
big = count('kind:2 "span_attr:pgtrace.truncated":true "span_attr:pgtrace.correlation":exact "span_attr:db.query.text":"select pg_sleep(0.15), length"*')
check("the 100 KB statement is a truncated, exactly linked trace", big == 1, f"{big} matching roots")
check("per-database pool-wait series for the tiny pool", val(r'^pgtrace_client_pool_wait_seconds_count\{[^}]*database="tiny"') > 0)
check("per-client metrics carry database/user/client_addr labels",
      re.search(r'^pgtrace_client_queries_total\{client_addr="[0-9.]+",database="postgres",user="postgres"\}', metrics, re.M) is not None)
nseries = len([l for l in metrics.splitlines() if l.startswith("pgtrace_")])
check("pgtrace series under the documented ceiling (limit 200: 8,962)", nseries <= 8962, f"{nseries} series")

# --- SQLCommenter trace context -----------------------------------------------
TID, PSID = "4bf92f3577b34da6a3ce929d0e0e4736", "00f067aa0ba902b7"
root = logsql(f'kind:2 trace_id:{TID} | fields parent_span_id, "span_attr:pgtrace.trace_context", "span_attr:sqlcommenter.application", "span_attr:pgtrace.sample_reason"')
kids = count(f"kind:3 trace_id:{TID}")
check("SQLCommenter traceparent parents the pgbouncer span (fast query kept: parent sampled)",
      len(root) == 1 and root[0].get("parent_span_id") == PSID and root[0].get("span_attr:pgtrace.trace_context") == "sqlcommenter"
      and root[0].get("span_attr:sqlcommenter.application") == "e2e" and root[0].get("span_attr:pgtrace.sample_reason") == "parent" and kids == 1,
      f"{root} / {kids} child")
check("/metrics counts linked trace contexts", val(r'^pgtrace_trace_context_total\{result="linked"\}') >= 1)

print("E2E PASSED" if failures == 0 else f"E2E FAILED ({failures} checks)")
sys.exit(1 if failures else 0)
