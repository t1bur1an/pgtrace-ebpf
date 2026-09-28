#!/usr/bin/env python3
"""Soak test sampling and reporting.

  soak_monitor.py header           CSV header
  soak_monitor.py sample           one CSV row from agent /metrics, cgroups, VictoriaTraces
  soak_monitor.py report <dir>     checks + <dir>/summary.md; exit 1 on failure
"""
import csv
import json
import re
import statistics as st
import subprocess
import sys
import time
import urllib.parse
import urllib.request

VT = "http://localhost:10428/select/logsql/query"
COLS = ["ts", "agent_running", "agent_started", "agent_restarts", "agent_rss", "agent_heap_inuse", "goroutines",
        "agent_cpu_usec", "pgbouncer_cpu_usec", "postgres_cpu_usec", "events", "q_client", "q_server",
        "corr_exact", "corr_inferred", "corr_internal", "corr_none", "corr_orphan",
        "kept_error", "kept_slow", "kept_ratio", "dropped", "kernel_drops", "conns_client", "conns_server",
        "vt_spans_1m", "vt_truncated_1m"]


def sh(*cmd):
    return subprocess.run(cmd, capture_output=True, text=True).stdout.strip()


def cpu(container):
    cid = sh("docker", "inspect", "-f", "{{.Id}}", container)
    try:
        with open(f"/sys/fs/cgroup/system.slice/docker-{cid}.scope/cpu.stat") as f:
            return int(re.search(r"usage_usec (\d+)", f.read()).group(1))
    except OSError:
        return ""


def metrics():
    try:
        text = urllib.request.urlopen("http://localhost:9464/metrics", timeout=10).read().decode()
    except OSError:
        return None
    def s(pat):
        return sum(float(v) for v in re.findall(r"^" + pat + r"(?:\{[^}]*\})? ([0-9.e+-]+)$", text, re.M))
    def lab(name, label):
        return sum(float(v) for v in re.findall(r"^" + name + r"\{[^}]*" + label + r"[^}]*\} ([0-9.e+-]+)$", text, re.M))
    return {
        "agent_rss": s("process_resident_memory_bytes"), "agent_heap_inuse": s("go_memstats_heap_inuse_bytes"),
        "goroutines": s("go_goroutines"), "events": s("pgtrace_events_total"),
        "q_client": lab("pgtrace_queries_total", 'side="client"'), "q_server": lab("pgtrace_queries_total", 'side="server"'),
        **{f"corr_{r}": lab("pgtrace_correlation_total", f'result="{r}"') for r in ("exact", "inferred", "internal", "none", "orphan")},
        **{d: lab("pgtrace_spans_total", f'decision="{d}"') for d in ("kept_error", "kept_slow", "kept_ratio", "dropped")},
        "kernel_drops": s("pgtrace_kernel_drops_total"),
        "conns_client": lab("pgtrace_connections", 'side="client"'), "conns_server": lab("pgtrace_connections", 'side="server"'),
    }


def logsql(q):
    body = urllib.parse.urlencode({"query": q}).encode()
    out = urllib.request.urlopen(VT, body, timeout=120).read().decode()
    return [json.loads(l) for l in out.splitlines() if l.strip()]


def count(q):
    try:
        rows = logsql(q + " | stats count() n")
        return int(rows[0]["n"]) if rows else 0
    except OSError:
        return ""


def sample():
    state = sh("docker", "inspect", "-f", "{{.State.Running}} {{.State.StartedAt}} {{.RestartCount}}", "pgtrace-agent-1").split()
    row = {"ts": int(time.time()), "agent_running": state[0] if state else "", "agent_started": state[1] if len(state) > 1 else "",
           "agent_restarts": state[2] if len(state) > 2 else "",
           "agent_cpu_usec": cpu("pgtrace-agent-1"), "pgbouncer_cpu_usec": cpu("pgtrace-pgbouncer-1"),
           "postgres_cpu_usec": cpu("pgtrace-postgres-1"),
           "vt_spans_1m": count("_time:1m"), "vt_truncated_1m": count('_time:1m "span_attr:pgtrace.truncated":true')}
    row.update(metrics() or {})
    csv.DictWriter(sys.stdout, COLS).writerow({k: row.get(k, "") for k in COLS})


def f(x):
    return float(x) if x not in ("", None) else None


def report(out):
    rows = list(csv.DictReader(open(f"{out}/samples.csv")))
    rows = [r for r in rows if f(r["events"]) is not None]
    agent_log = open(f"{out}/agent.log").read()
    checks, lines = [], []

    def check(desc, ok, detail=""):
        checks.append(ok)
        lines.append(f"| {'PASS' if ok else '**FAIL**'} | {desc} | {detail} |")

    first, last = rows[0], rows[-1]
    hours = (int(last["ts"]) - int(first["ts"])) / 3600
    d = lambda k: f(last[k]) - f(first[k])

    started = {r["agent_started"] for r in rows}
    crashed = re.findall(r"fatal error|panic:|SIGSEGV", agent_log)
    check("agent ran the whole time without crashing or restarting",
          all(r["agent_running"] == "true" for r in rows) and len(started) == 1 and not crashed,
          f"{len(rows)} samples, {len(started)} start time(s), {len(crashed)} crash lines")

    third = max(len(rows) // 3, 1)
    warm = rows[min(10, len(rows) - 1):]  # skip the first ~10 minutes
    early = [f(r["agent_rss"]) for r in warm[:third]]
    late = [f(r["agent_rss"]) for r in warm[-third:]]
    rss_growth = st.median(late) / st.median(early) if early and late else 0
    check("agent memory stable (median RSS last third ≤ 1.3 × first third, after warm-up)", rss_growth <= 1.3,
          f"{st.median(early) / 2**20:.0f} → {st.median(late) / 2**20:.0f} MiB (×{rss_growth:.2f}), max {max(f(r['agent_rss']) for r in rows) / 2**20:.0f} MiB")
    heap_e = st.median(f(r["agent_heap_inuse"]) for r in warm[:third])
    heap_l = st.median(f(r["agent_heap_inuse"]) for r in warm[-third:])
    check("agent heap stable (≤ 1.3×)", heap_l <= 1.3 * heap_e, f"{heap_e / 2**20:.0f} → {heap_l / 2**20:.0f} MiB")
    gor = [f(r["goroutines"]) for r in rows]
    check("goroutines bounded", max(gor) <= min(gor) + 20, f"{min(gor):.0f}–{max(gor):.0f}")
    check("no kernel ringbuf drops", f(last["kernel_drops"]) == 0, f"{f(last['kernel_drops']):.0f}")

    linked = d("corr_exact") + d("corr_inferred")
    denom = linked + d("corr_orphan")
    check("≥ 99.9 % of forwarded server queries linked to their client query", denom and linked / denom >= 0.999,
          f"{d('corr_exact'):.0f} exact, {d('corr_inferred'):.0f} inferred, {d('corr_orphan'):.0f} orphan, "
          f"{d('corr_internal'):.0f} internal, {d('corr_none'):.0f} none")

    kept = sum(f(last[k]) for k in ("kept_error", "kept_slow", "kept_ratio"))
    stored = count("kind:2") + count('kind:3 "span_attr:pgtrace.correlation":none') + count('kind:3 -"span_attr:pgtrace.correlation":none parent_span_id:""')
    check("every kept trace reached VictoriaTraces (±0.1 %)", kept and abs(stored - kept) <= 0.001 * kept, f"{stored} stored / {kept:.0f} kept")
    export_errs = [l for l in agent_log.splitlines() if re.search(r"(?i)export|otlp|invalid utf-8", l) and re.search(r"(?i)error|fail|drop", l)]
    check("no exporter errors in agent log", not export_errs, f"{len(export_errs)} lines" + (f": {export_errs[0][:120]}" if export_errs else ""))

    trunc_roots = count('kind:2 "span_attr:pgtrace.truncated":true')
    trunc_exact = count('kind:2 "span_attr:pgtrace.truncated":true "span_attr:pgtrace.correlation":exact')
    check("big (truncated) statements traced and linked", trunc_roots > 0 and trunc_exact >= 0.99 * trunc_roots,
          f"{trunc_exact}/{trunc_roots} truncated client roots linked exactly")
    bad_json = count('kind:2 "span_attr:db.response.status_code":"22P02"')
    admin = count('kind:2 "span_attr:db.namespace":pgbouncer status_code:2')
    sent = re.search(r"errors_sent: (\d+)", open(f"{out}/stream-errors.log").read())
    sent = int(sent.group(1)) // 2 if sent else 0
    check("every error trace kept (invalid JSON + pgbouncer admin errors)", bad_json >= sent and admin >= sent,
          f"{bad_json} invalid-JSON, {admin} admin-console roots; {sent} of each sent")

    streams = []
    for name in ("big", "ext", "churn"):
        log = open(f"{out}/stream-{name}.log").read()
        g = lambda pat: (re.search(pat, log) or [None, "?"])[1]
        aborted = len(re.findall(r"aborted", log))
        streams.append((name, g(r"tps = ([0-9.]+)"), g(r"number of transactions actually processed: (\d+)"),
                        g(r"number of failed transactions: (\d+)"), g(r"latency average = ([0-9.]+) ms"), aborted))
    check("load streams ran to completion", all(s[5] == 0 for s in streams), ", ".join(f"{s[0]}: {s[5]} aborted" for s in streams))

    cpu_s = lambda k: d(k) / 1e6 / (hours * 3600)
    body = [
        f"# Soak test {out.rstrip('/').split('/')[-1]}", "",
        open(f"{out}/meta.txt").read().strip().replace("\n", "  \n"), "",
        "## Checks", "", "| result | check | detail |", "|---|---|---|", *lines, "",
        "## Load", "", "| stream | tps | transactions | failed (retried out) | avg latency ms |", "|---|---:|---:|---:|---:|",
        *[f"| {s[0]} | {s[1]} | {s[2]} | {s[3]} | {s[4]} |" for s in streams], "",
        "## Resources (averages over the run)", "",
        f"- duration: {hours:.2f} h, {len(rows)} samples",
        f"- client queries: {d('q_client'):.0f} ({d('q_client') / (hours * 3600):.0f}/s), server queries: {d('q_server'):.0f}",
        f"- kernel events: {d('events'):.0f} ({d('events') / (hours * 3600):.0f}/s)",
        f"- agent CPU: {cpu_s('agent_cpu_usec'):.2f} cores; pgbouncer: {cpu_s('pgbouncer_cpu_usec'):.2f}; postgres: {cpu_s('postgres_cpu_usec'):.2f}",
        f"- agent RSS: min {min(f(r['agent_rss']) for r in rows) / 2**20:.0f} MiB, max {max(f(r['agent_rss']) for r in rows) / 2**20:.0f} MiB",
        f"- traces: kept {kept:.0f} (error {f(last['kept_error']):.0f}, slow {f(last['kept_slow']):.0f}, ratio {f(last['kept_ratio']):.0f}), dropped by sampling {f(last['dropped']):.0f}",
        f"- truncated client roots stored: {trunc_roots}",
        "", "Per-minute samples: `samples.csv`. pgbench progress: `stream-*.log`. Agent log: `agent.log`.",
    ]
    open(f"{out}/summary.md", "w").write("\n".join(body) + "\n")
    print("\n".join(body))
    print("SOAK PASSED" if all(checks) else "SOAK FAILED")
    sys.exit(0 if all(checks) else 1)


if __name__ == "__main__":
    cmd = sys.argv[1]
    if cmd == "header":
        print(",".join(COLS))
    elif cmd == "sample":
        sample()
    elif cmd == "report":
        report(sys.argv[2])
