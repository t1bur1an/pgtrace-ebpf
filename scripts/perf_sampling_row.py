#!/usr/bin/env python3
"""One CSV row for scripts/perf_sampling.sh."""
import re
import sys

(rep, name, d, p0, p1, a0, a1, v0, v1, resf, m0f, m1f, memf, vtmemf, s0, s1, lag) = sys.argv[1:]
d = float(d)
read = lambda p: open(p).read()
res, m0, m1 = read(resf), read(m0f), read(m1f)
tps = sum(float(x) for x in re.findall(r"^tps = ([0-9.]+)", res, re.M))
lat = re.findall(r"^latency average = ([0-9.]+) ms", res, re.M)
lat = float(lat[0]) if lat else 0


def val(text, pat):
    return sum(float(v) for v in re.findall("^" + pat + r"(?:\{[^}]*\})? ([0-9.e+-]+)$", text, re.M))


def lab(text, name, label):
    return sum(float(v) for v in re.findall("^" + name + r"\{[^}]*" + label + r"[^}]*\} ([0-9.e+-]+)$", text, re.M))


def dlab(name, label):
    return lab(m1, name, label) - lab(m0, name, label)


peak = lambda f: max((int(l) for l in open(f) if l.strip()), default=0) / 2**20
on = bool(m1)
cells = [rep, name, f"{tps:.0f}", f"{lat:.2f}", f"{(int(p1) - int(p0)) / 1e6 / d * 100:.1f}",
         f"{(int(a1) - int(a0)) / 1e6 / d * 100:.1f}" if on else "", f"{peak(memf):.0f}" if on else "",
         f"{(int(v1) - int(v0)) / 1e6 / d * 100:.1f}", f"{peak(vtmemf):.0f}"]
if on:
    created, exported = dlab("pgtrace_export_spans_total", 'stage="created"'), dlab("pgtrace_export_spans_total", 'stage="exported"')
    cells += [f"{dlab('pgtrace_queries_total', 'side=\"client\"') / d:.0f}", f"{created / d:.0f}", f"{exported / d:.0f}",
              f"{dlab('pgtrace_export_spans_total', 'stage=\"failed_batches\"'):.0f}", f"{created - exported:.0f}",
              f"{dlab('pgtrace_export_spans_total', 'stage=\"dropped\"'):.0f}", f"{val(m1, 'pgtrace_kernel_drops_total'):.0f}", f"{int(s1) - int(s0)}", lag]
else:
    cells += [""] * 9
print(",".join(cells))
