#!/usr/bin/env python3
"""TLS assertions for scripts/e2e_tls.sh. Usage: e2e_tls_check.py <strict|mixed|preexisting|nolog> --stats "<agent stats line>"."""
import argparse
import json
import re
import sys
import urllib.parse
import urllib.request

VT, PROM, AGENT = "http://localhost:10428", "http://localhost:9090", "http://localhost:9464/metrics"
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
    return [json.loads(l) for l in get(f"{VT}/select/logsql/query", {"query": query}).splitlines() if l.strip()]


def count(query):
    rows = logsql(query + " | stats count() n")
    return int(rows[0]["n"]) if rows else 0


def prom(expr):
    res = json.loads(get(f"{PROM}/api/v1/query?" + urllib.parse.urlencode({"query": expr})))["data"]["result"]
    return float(res[0]["value"][1]) if res else 0.0


metrics = get(AGENT)
val = lambda pat: sum(float(m) for m in re.findall(pat + r"\S* ([0-9.e+]+)$", metrics, re.M))

ap = argparse.ArgumentParser()
ap.add_argument("mode", choices=["strict", "mixed", "preexisting", "nolog"])
ap.add_argument("--stats", required=True)
ap.add_argument("--app", default="pgbench")
args = ap.parse_args()
stats = {k: int(v) for k, v in re.findall(r"(\w+)=(\d+)", args.stats)}
ROOT, CHILD = "kind:2", "kind:3"
TLS = '"span_attr:tls.protocol.name":tls'

check("no kernel drops", stats["kernel_drops"] == 0, f'{stats["kernel_drops"]}')
check("TLS probes attached to the pgbouncer process", val(r'^pgtrace_tls_processes\{state="attached"\}') == 1
      and val(r'^pgtrace_tls_processes\{state="unsupported"\}') == 0)
dropped = val(r'^pgtrace_tls_unresolved_total\{result="dropped"\}')
resolved = val(r'^pgtrace_tls_unresolved_total\{result="resolved"\}')
maxconn = lambda side, tls: prom(f'max_over_time(pgtrace_connections{{side="{side}",tls="{tls}"}}[10m])')


def app_roots(app, extra=""):
    return count(f'{ROOT} "span_attr:application_name":{app} {extra}')


if args.mode in ("strict", "nolog"):
    roots = app_roots(args.app)
    tls_roots = app_roots(args.app, TLS)
    check("sampled pgbench roots exist", roots > 0, f"{roots}")
    check("every pgbench root carries tls.protocol.name=tls", roots and tls_roots == roots, f"{tls_roots}/{roots}")
    kids = count(f'{CHILD} "span_attr:pgbouncer.internal":false')
    tls_kids = count(f'{CHILD} "span_attr:pgbouncer.internal":false {TLS}')
    check("every server child carries tls.protocol.name=tls", kids and tls_kids == kids, f"{tls_kids}/{kids}")
    versioned = app_roots(args.app, '"span_attr:tls.protocol.version":"1.3" "span_attr:tls.cipher":*')
    if args.mode == "strict":
        check("≥ 99% of pgbench roots carry version 1.3 and a cipher", versioned >= 0.99 * roots, f"{versioned}/{roots}")
    else:
        print(f"INFO  with connection logging off, {versioned}/{roots} roots carry version and cipher (best-effort)")
    check("client and server connections counted as TLS", maxconn("client", "true") > 0 and maxconn("server", "true") > 0)
    check("no plain client connections counted", maxconn("client", "false") == 0)
    check("no socket-less TLS events dropped", dropped == 0, f"{dropped:.0f}")
    resyncs = val(r'^pgtrace_parser_resyncs_total\{side="client"\}')
    check("no client parser resyncs (incl. slow readers: retried SSL_write)", resyncs == 0, f"{resyncs:.0f}")
elif args.mode == "mixed":
    for app, want_tls in (("tls-client", True), ("plain-client", False)):
        roots = app_roots(app)
        tls_roots = app_roots(app, TLS)
        check(f"{app}: every trace kept (ratio 1.0)", roots >= 0.99 * 8400, f"{roots}")
        check(f"{app}: tls attributes {'on every' if want_tls else 'on no'} root",
              tls_roots == (roots if want_tls else 0), f"{tls_roots}/{roots}")
    kids = count(f"{CHILD} {TLS}")
    check("plain server hop: no child carries tls attributes", kids == 0, f"{kids}")
    check("TLS and plain client connections both counted",
          maxconn("client", "true") > 0 and maxconn("client", "false") > 0)
    check("no TLS server connections counted", maxconn("server", "true") == 0)
    check("no socket-less TLS events dropped", dropped == 0, f"{dropped:.0f}")
elif args.mode == "preexisting":
    # Sessions opened before the agent have no startup parameters (no
    # application_name); they are the only traffic in this step.
    roots = count(ROOT)
    tls_roots = count(f"{ROOT} {TLS}")
    linked = count(f'{ROOT} "span_attr:pgtrace.correlation":exact')
    check("queries of sessions opened before the agent are traced", roots > 1000, f"{roots}")
    check("…and marked TLS", tls_roots == roots, f"{tls_roots}/{roots}")
    check("…and ≥ 99% linked exactly", linked >= 0.99 * roots, f"{linked}/{roots}")
    check("fallback attached during the run", prom("max_over_time(pgtrace_tls_fallback_attached[10m])") == 1)
    check("fallback detached after the load ended", val(r"^pgtrace_tls_fallback_attached") == 0)
    print(f"INFO  socket-less events: {resolved:.0f} resolved, {dropped:.0f} dropped (calls of old sessions before the fallback attached)")

print("E2E TLS CHECK " + ("PASSED" if failures == 0 else f"FAILED ({failures})"))
sys.exit(1 if failures else 0)
