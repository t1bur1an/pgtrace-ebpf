package metrics

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/t1bur1an/pgtrace/internal/correlate"
	"github.com/t1bur1an/pgtrace/internal/pgwire"
	"github.com/t1bur1an/pgtrace/internal/sampler"
)

func q(op string, ms int, code string) pgwire.Query {
	return pgwire.Query{Start: 1_000, End: 1_000 + uint64(time.Duration(ms)*time.Millisecond), Operation: op, Protocol: "simple", ErrorCode: code}
}

func TestObserveTrace(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := New(reg)
	root := q("SELECT", 10, "")
	child := q("SELECT", 4, "")
	child.Start += uint64(3 * time.Millisecond)
	child.End += uint64(3 * time.Millisecond)
	m.ObserveTrace(correlate.Trace{
		Client: &correlate.ClientQuery{Q: root},
		Server: []correlate.ServerQuery{{Q: child, Correlation: "exact"}},
	}, Client{})
	m.ObserveTrace(correlate.Trace{Server: []correlate.ServerQuery{{Q: q("frobnicate", 1, "XX000"), Correlation: "none"}}}, Client{})
	m.ObserveTrace(correlate.Trace{Client: &correlate.ClientQuery{Q: q("SHOW", 1, "08P01-bad")}}, Client{})

	if v := testutil.ToFloat64(m.queries.WithLabelValues("client", "SELECT", "simple")); v != 1 {
		t.Fatalf("client queries %v", v)
	}
	if v := testutil.ToFloat64(m.queries.WithLabelValues("server", "OTHER", "simple")); v != 1 {
		t.Fatalf("server OTHER queries %v", v)
	}
	if v := testutil.ToFloat64(m.errors.WithLabelValues("server", "XX000")); v != 1 {
		t.Fatalf("errors %v", v)
	}
	if v := testutil.ToFloat64(m.errors.WithLabelValues("client", "OTHER")); v != 1 {
		t.Fatalf("bad sqlstate label %v", v)
	}
	if v := testutil.ToFloat64(m.correlation.WithLabelValues("exact")); v != 1 {
		t.Fatalf("correlation %v", v)
	}
	count, sum := histogram(t, reg, "pgtrace_pool_wait_seconds")
	if count != 1 || sum < 0.0029 || sum > 0.0031 {
		t.Fatalf("pool wait count=%d sum=%v", count, sum)
	}
	count, _ = histogram(t, reg, "pgtrace_query_duration_seconds")
	if count != 4 { // client+server of trace 1, lone server, client-only
		t.Fatalf("duration observations %d", count)
	}
}

// histogram sums sample count and sum over all series of a histogram.
func histogram(t *testing.T, reg *prometheus.Registry, name string) (uint64, float64) {
	t.Helper()
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	var count uint64
	var sum float64
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.Metric {
			count += m.Histogram.GetSampleCount()
			sum += m.Histogram.GetSampleSum()
		}
	}
	return count, sum
}

func TestLabels(t *testing.T) {
	cases := map[string]string{"SELECT": "SELECT", "select": "SELECT", "": "OTHER", "VACUUMX": "OTHER", "merge": "MERGE"}
	for in, want := range cases {
		if got := opLabel(in); got != want {
			t.Errorf("opLabel(%q)=%q want %q", in, got, want)
		}
	}
	for in, want := range map[string]string{"22012": "22012", "": "", "abc": "OTHER", "123456": "OTHER"} {
		if got := New(prometheus.NewRegistry()).sqlstateLabel(in); got != want {
			t.Errorf("sqlstateLabel(%q)=%q want %q", in, got, want)
		}
	}
}

func TestTraceContextCounter(t *testing.T) {
	m := New(prometheus.NewRegistry())
	m.TraceContext("linked")
	m.TraceContext("invalid")
	m.TraceContext("linked")
	if testutil.ToFloat64(m.traceContext.WithLabelValues("linked")) != 2 || testutil.ToFloat64(m.traceContext.WithLabelValues("invalid")) != 1 {
		t.Fatal("trace context counts")
	}
}

func TestTruncationCounter(t *testing.T) {
	m := New(prometheus.NewRegistry())
	m.Truncation("kernel")
	m.Truncation("parser")
	m.Truncation("parser")
	if testutil.ToFloat64(m.truncations.WithLabelValues("parser")) != 2 || testutil.ToFloat64(m.truncations.WithLabelValues("kernel")) != 1 {
		t.Fatal("truncation counts")
	}
}

func TestSpanDecisionsAndKernel(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := New(reg)
	m.SpanDecision(sampler.ReasonSlow, true)
	m.SpanDecision(sampler.ReasonNone, false)
	if testutil.ToFloat64(m.spans.WithLabelValues("kept_slow")) != 1 || testutil.ToFloat64(m.spans.WithLabelValues("dropped")) != 1 {
		t.Fatal("span decisions")
	}
	m.RegisterKernel(func() uint64 { return 5 }, func() (time.Duration, uint64) { return 2 * time.Second, 10 }, true)
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]float64{}
	for _, mf := range mfs {
		if len(mf.Metric) == 1 && mf.Metric[0].Counter != nil {
			found[mf.GetName()] = mf.Metric[0].Counter.GetValue()
		}
	}
	if found["pgtrace_kernel_drops_total"] != 5 || found["pgtrace_bpf_run_seconds_total"] != 2 || found["pgtrace_bpf_runs_total"] != 10 {
		t.Fatalf("kernel metrics %v", found)
	}
}

func BenchmarkObserveTrace(b *testing.B) {
	m := New(prometheus.NewRegistry())
	root := q("SELECT", 1, "")
	child := q("SELECT", 1, "")
	tr := correlate.Trace{Client: &correlate.ClientQuery{Q: root}, Server: []correlate.ServerQuery{{Q: child, Correlation: "exact"}}}
	b.ReportAllocs()
	for b.Loop() {
		m.ObserveTrace(tr, Client{})
	}
}
