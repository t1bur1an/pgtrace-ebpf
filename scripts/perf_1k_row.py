#!/usr/bin/env python3
"""One CSV row for scripts/perf_1k.sh from pgbench output and agent scrapes."""
import re
import sys

rep, wl, name, d, p0, p1, a0, a1, resf, m0f, m1f, memf = sys.argv[1:]
d = float(d)
read = lambda p: open(p).read() if p else ""
res, m0, m1 = read(resf), read(m0f), read(m1f)
tps = sum(float(x) for x in re.findall(r"^tps = ([0-9.]+)", res, re.M))
lat = [float(x) for x in re.findall(r"^latency average = ([0-9.]+) ms", res, re.M)]
lat = sum(lat) / len(lat) if lat else 0


def val(text, pat):
    return sum(float(v) for v in re.findall("^" + pat + r"\S* ([0-9.e+]+)$", text, re.M))


def delta(pat):
    return val(m1, pat) - val(m0, pat)


on = bool(m1)
rss = max((int(l) for l in open(memf) if l.strip()), default=0) / 2**20 if memf else 0
cells = [rep, wl, name, f"{tps:.0f}", f"{lat:.2f}", f"{(int(p1) - int(p0)) / 1e6 / d * 100:.1f}"]
if on:
    cells += [f"{(int(a1) - int(a0)) / 1e6 / d * 100:.1f}", f"{rss:.0f}",
              f"{delta(r'pgtrace_queries_total\{[^}]*side=\"client\"') / d:.0f}",
              f"{delta(r'pgtrace_spans_total') / d:.0f}"]
    for r in ("exact", "inferred", "internal", "none", "orphan"):
        cells.append(f"{delta('pgtrace_correlation_total\\{result=\"' + r + '\"'):.0f}")
    cells.append(f"{val(m1, 'pgtrace_kernel_drops_total'):.0f}")
else:
    cells += [""] * 10
print(",".join(cells))
