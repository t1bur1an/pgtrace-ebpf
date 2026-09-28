#!/usr/bin/env python3
"""Assertions for scripts/contention.sh: what each kind of contention looks
like in VictoriaTraces spans and agent metrics."""
import json
import re
import sys
import urllib.parse
import urllib.request

VT = "http://localhost:10428/select/logsql/query"
failures = 0


def check(desc, ok, detail=""):
    global failures
    print(("PASS  " if ok else "FAIL  ") + desc + (f"  ({detail})" if detail else ""))
    failures += 0 if ok else 1


def logsql(q):
    out = urllib.request.urlopen(VT, urllib.parse.urlencode({"query": q}).encode(), timeout=60).read().decode()
    return [json.loads(l) for l in out.splitlines() if l.strip()]


FIELDS = ('trace_id, span_id, duration, status_code, status_message, "span_attr:db.response.status_code", '
          '"span_attr:pgbouncer.pool_wait_ms", "span_attr:pgbouncer.idle_in_tx_ms", "span_attr:sqlcommenter.scenario"')


def roots(scenario):
    return logsql(f'kind:2 "span_attr:sqlcommenter.scenario":"{scenario}" | fields {FIELDS}')


def children(trace_ids):
    if not trace_ids:
        return {}
    ids = " or ".join(f"trace_id:{t}" for t in trace_ids)
    out = {}
    for c in logsql(f"kind:3 ({ids}) | fields {FIELDS}"):
        out.setdefault(c["trace_id"], []).append(c)
    return out


ms = lambda s: int(s.get("duration", 0)) / 1e6
f = lambda s, k: float(s.get(k) or 0)
code = lambda s: s.get("span_attr:db.response.status_code", "")

# 1. deadlock
dl = roots("deadlock-a") + roots("deadlock-b")
victim = [r for r in dl if code(r) == "40P01"]
survivor = [r for r in dl if code(r) != "40P01"]
kids = children([r["trace_id"] for r in victim])
check("1 deadlock: one 40P01 root with a 40P01 server child",
      len(victim) == 1 and any(code(c) == "40P01" for c in kids.get(victim[0]["trace_id"], [])), f"{len(victim)} victims")
check("1 deadlock: the survivor's UPDATE waited ≈ deadlock_timeout (kept as slow)",
      len(survivor) == 1 and ms(survivor[0]) >= 900, f"{[round(ms(r)) for r in survivor]} ms")

# 2. row-lock wait
lw = roots("lockwait")
kids = children([r["trace_id"] for r in lw])
srv = kids.get(lw[0]["trace_id"], []) if lw else []
check("2 lock wait: server span ≥ 2 s while pool wait < 100 ms (time spent in postgres, not pgbouncer)",
      len(lw) == 1 and srv and ms(srv[0]) >= 2000 and f(lw[0], "span_attr:pgbouncer.pool_wait_ms") < 100,
      f"server {ms(srv[0]) if srv else 0:.0f} ms, pool wait {f(lw[0], 'span_attr:pgbouncer.pool_wait_ms') if lw else 0:.2f} ms")

# 3. lock_timeout
lt = roots("locktimeout")
check("3 lock timeout: 55P03 after ≈ 500 ms", len(lt) == 1 and code(lt[0]) == "55P03" and 400 <= ms(lt[0]) <= 1500,
      f"{[(code(r), round(ms(r))) for r in lt]}")

# 4. statement_timeout
st = roots("stmttimeout")
check("4 statement timeout: 57014 after ≈ 300 ms", len(st) == 1 and code(st[0]) == "57014" and 250 <= ms(st[0]) <= 1500,
      f"{[(code(r), round(ms(r))) for r in st]}")

# 5. serialization failure
se = roots("serial") + roots("serial-commit")
check("5 serialization failure: a 40001 root", any(code(r) == "40001" for r in se), f"{sorted({code(r) for r in se})}")

# 6. pool exhaustion
pw = roots("poolwait")
kids = children([r["trace_id"] for r in pw])
waits = sorted(f(r, "span_attr:pgbouncer.pool_wait_ms") for r in pw)
p95 = waits[int(len(waits) * 0.95) - 1] if waits else 0
consistent = sum(1 for r in pw for c in kids.get(r["trace_id"], [])[:1]
                 if abs(ms(r) - (f(r, "span_attr:pgbouncer.pool_wait_ms") + ms(c))) < 50)
check("6 pool exhaustion: 16 traces, pool wait p95 ≥ 1 s", len(pw) == 16 and p95 >= 1000, f"{len(pw)} traces, p95 {p95:.0f} ms, max {max(waits or [0]):.0f} ms")
check("6 pool exhaustion: client time = pool wait + server time (±50 ms)", consistent == len(pw), f"{consistent}/{len(pw)}")

# 7. pgbouncer query_wait_timeout
qw = roots("qwt")
errs = [r for r in qw if r.get("status_code") == "2"]
kids = children([r["trace_id"] for r in errs])
check("7 queue timeout: pgbouncer errors as client roots without a server child",
      errs and all(r["trace_id"] not in kids for r in errs) and all("query_wait_timeout" in r.get("status_message", "") for r in errs),
      f"{len(errs)} of {len(qw)} timed out; message {errs[0].get('status_message') if errs else '-'}")

# 8. idle in transaction
ia = roots("idle-after")
vi = roots("idle-victim")
idle = f(ia[0], "span_attr:pgbouncer.idle_in_tx_ms") if ia else 0
check("8 idle in transaction: next query carries idle_in_tx_ms ≈ 5000 (kept though fast)", 4500 <= idle <= 6500, f"{idle:.0f} ms")
vw = max((f(r, "span_attr:pgbouncer.pool_wait_ms") for r in vi), default=0)
check("8 idle in transaction: other clients on the pool waited", vw >= 400, f"max victim pool wait {vw:.0f} ms over {len(vi)} traces")

# B. connection errors
ce = logsql('"span_attr:pgtrace.connection_error":true | fields name, status_code, "span_attr:db.response.status_code", "span_attr:db.namespace", status_message')
check("B rejected logins become 'connect' error spans", len(ce) >= 2 and all(c["name"] == "connect" and c["status_code"] == "2" for c in ce)
      and any(c.get("span_attr:db.namespace") == "nosuchdb" for c in ce),
      "; ".join(f'{c.get("span_attr:db.response.status_code")} {c.get("status_message", "")[:50]}' for c in ce))

# metrics
text = urllib.request.urlopen("http://localhost:9464/metrics", timeout=10).read().decode()
val = lambda pat: sum(float(v) for v in re.findall(pat + r"\S* ([0-9.e+]+)$", text, re.M))
for c, name in (("40P01", "deadlock"), ("55P03", "lock timeout"), ("57014", "statement timeout"), ("40001", "serialization")):
    check(f"metric: server {name} errors ({c}) counted", val(rf'^pgtrace_query_errors_total\{{side="server",sqlstate="{c}"\}}') >= 1)
check("metric: client connection errors counted", val(r'^pgtrace_connection_errors_total\{side="client"') >= 2)
check("metric: idle-in-transaction histogram observed a ≥ 5 s gap",
      val(r"^pgtrace_idle_in_transaction_seconds_sum") >= 4.5)
check("metric: pool wait histogram has multi-second observations", val(r'^pgtrace_pool_wait_seconds_bucket\{le="\+Inf"\}') - val(r'^pgtrace_pool_wait_seconds_bucket\{le="1.953125"\}') >= 1)

# Grafana contention row: every panel query returns data
dash = json.loads(urllib.request.urlopen("http://localhost:3000/api/dashboards/uid/pgtrace").read())["dashboard"]
row, empty = False, []
for p in dash["panels"]:
    if p["type"] == "row":
        row = p["title"] == "Contention"
        continue
    if not row:
        continue
    for t in p["targets"]:
        body = {"queries": [dict(t, datasource=p["datasource"], intervalMs=5000, maxDataPoints=100)], "from": "now-10m", "to": "now"}
        req = urllib.request.Request("http://localhost:3000/api/ds/query", json.dumps(body).encode(), {"Content-Type": "application/json"})
        res = json.load(urllib.request.urlopen(req))["results"][t["refId"]]
        rows = sum(len(fr["data"]["values"][0]) if fr.get("data", {}).get("values") else 0 for fr in res.get("frames", []))
        if res.get("error") or rows == 0:
            empty.append(f'{p["title"]} / {t.get("legendFormat") or t.get("queryType")}')
check("dashboard Contention row: every query returns data", not empty, "; ".join(empty))

print("CONTENTION PASSED" if failures == 0 else f"CONTENTION FAILED ({failures} checks)")
sys.exit(1 if failures else 0)
