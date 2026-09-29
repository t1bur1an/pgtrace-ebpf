package metrics

import (
	"fmt"
	"math/rand/v2"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/t1bur1an/pgtrace-ebpf/internal/correlate"
	"github.com/t1bur1an/pgtrace-ebpf/internal/pgwire"
)

// series counts exposed samples: one per counter/gauge, buckets+2 per histogram.
func series(t *testing.T, reg *prometheus.Registry) int {
	t.Helper()
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, mf := range mfs {
		for _, m := range mf.Metric {
			if h := m.Histogram; h != nil {
				n += len(h.Bucket) + 1 + 2 // buckets, +Inf, sum, count
			} else {
				n++
			}
		}
	}
	return n
}

func randomTrace(r *rand.Rand) correlate.Trace {
	q := func() pgwire.Query {
		ops := []string{"SELECT", "select", "garbage" + fmt.Sprint(r.IntN(1e6)), "", "MERGE"}
		code := ""
		if r.IntN(3) == 0 {
			code = fmt.Sprintf("%05d", r.IntN(1e5)) // up to 100k distinct 5-char codes
		}
		return pgwire.Query{Start: 1, End: 1 + uint64(r.IntN(1e9)), Operation: ops[r.IntN(len(ops))], Protocol: []string{"simple", "extended"}[r.IntN(2)], ErrorCode: code}
	}
	return correlate.Trace{
		Client: &correlate.ClientQuery{Q: q()},
		Server: []correlate.ServerQuery{{Q: q(), Correlation: []string{"exact", "inferred", "none"}[r.IntN(3)], Internal: r.IntN(10) == 0}},
	}
}

func TestSeriesBounded(t *testing.T) {
	reg := prometheus.NewRegistry()
	cfg := Config{Labels: []string{"database", "user", "client_addr"}, Limit: 50, TTL: time.Hour}
	m := NewWith(reg, cfg)
	m.RegisterKernel(func() uint64 { return 0 }, func() (time.Duration, uint64) { return 0, 0 }, true)
	r := rand.New(rand.NewPCG(1, 2))
	for i := 0; i < 20000; i++ {
		c := Client{Database: fmt.Sprint("db", r.IntN(1000)), User: fmt.Sprint("u", r.IntN(1000)), Addr: fmt.Sprintf("10.0.%d.%d", r.IntN(256), r.IntN(256))}
		m.ObserveTrace(randomTrace(r), c)
		m.Event([]string{"data", "connect", "accept", "close"}[r.IntN(4)])
		m.Truncation([]string{"kernel", "parser", "export"}[r.IntN(3)])
		m.SpanDecision("ratio", r.IntN(2) == 0)
	}
	for _, side := range []string{"client", "server"} {
		m.SetConnections(side, true, 1)
		m.SetConnections(side, false, 1)
	}
	m.SetTracedProcesses(1)
	got, ceiling := series(t, reg), MaxSeries(cfg)
	t.Logf("series: %d, documented ceiling: %d", got, ceiling)
	if got > ceiling {
		t.Fatalf("%d series exceed the ceiling %d", got, ceiling)
	}
	if v := testutil.ToFloat64(m.overflow); v == 0 {
		t.Fatal("expected label overflow to be counted")
	}
}

func TestLabelledMetricsDisabledByDefault(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := New(reg)
	m.ObserveTrace(randomTrace(rand.New(rand.NewPCG(1, 1))), Client{Database: "shop"})
	mfs, _ := reg.Gather()
	for _, mf := range mfs {
		if mf.GetName() == "pgtrace_client_queries_total" {
			t.Fatal("labelled metrics registered without -metrics-labels")
		}
	}
}

func TestLabelSubsetLimitAndTTL(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewWith(reg, Config{Labels: []string{"database"}, Limit: 2, TTL: time.Minute})
	now := time.Unix(1000, 0)
	m.now = func() time.Time { return now }
	tr := correlate.Trace{Client: &correlate.ClientQuery{Q: pgwire.Query{Start: 1, End: 2, Operation: "SELECT", Protocol: "simple"}},
		Server: []correlate.ServerQuery{{Q: pgwire.Query{Start: 1, End: 2}, Correlation: "exact"}}}
	for _, db := range []string{"a", "b", "c", "a"} {
		m.ObserveTrace(tr, Client{Database: db, User: "ignored", Addr: "10.0.0.1"})
	}
	if v := testutil.ToFloat64(m.labelled.queries.WithLabelValues("a")); v != 2 {
		t.Fatalf("db a: %v", v)
	}
	if v := testutil.ToFloat64(m.labelled.queries.WithLabelValues("other")); v != 1 {
		t.Fatalf("db c should overflow to other: %v", v)
	}
	if v := testutil.ToFloat64(m.labelSets); v != 2 {
		t.Fatalf("label sets %v", v)
	}
	// Only "a" stays active; "b" idles past the TTL and frees its slot.
	now = now.Add(45 * time.Second)
	m.ObserveTrace(tr, Client{Database: "a"})
	now = now.Add(30 * time.Second)
	m.Evict()
	if v := testutil.ToFloat64(m.labelSets); v != 1 {
		t.Fatalf("after eviction: %v sets", v)
	}
	m.ObserveTrace(tr, Client{Database: "c"})
	if v := testutil.ToFloat64(m.labelled.queries.WithLabelValues("c")); v != 1 {
		t.Fatalf("db c should get the freed slot: %v", v)
	}
}

func TestSQLStateCap(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := New(reg)
	for i := 0; i < 1000; i++ {
		m.ObserveTrace(correlate.Trace{Server: []correlate.ServerQuery{{Q: pgwire.Query{ErrorCode: fmt.Sprintf("%05d", i)}, Correlation: "none"}}}, Client{})
	}
	if n := testutil.CollectAndCount(m.errors); n > maxSQLStates+1 {
		t.Fatalf("%d sqlstate series", n)
	}
	if v := testutil.ToFloat64(m.errors.WithLabelValues("server", "OTHER")); v != 1000-maxSQLStates {
		t.Fatalf("OTHER = %v", v)
	}
}

func TestSeriesBoundedWithTLS(t *testing.T) {
	reg := prometheus.NewRegistry()
	cfg := Config{TLS: true}
	m := NewWith(reg, cfg)
	m.RegisterKernel(func() uint64 { return 0 }, func() (time.Duration, uint64) { return 0, 0 }, true)
	progs := map[string]uint64{}
	for _, p := range []string{"exit_sendto", "exit_recvfrom", "exit_connect", "exit_accept4", "enter_close",
		"ssl_write", "ssl_write_ret", "ssl_read_enter", "ssl_read_exit", "ssl_set_rfd", "ssl_free",
		"ssl_ver_enter", "ssl_ver_exit", "ssl_cipher_exit", "fallback_read", "fallback_write"} {
		progs[p] = 1
	}
	m.RegisterRecursionMisses(func() map[string]uint64 { return progs })
	m.RegisterTLS(func() (int, int) { return 1, 0 }, func() bool { return false })
	r := rand.New(rand.NewPCG(3, 4))
	for i := 0; i < 5000; i++ {
		m.ObserveTrace(randomTrace(r), Client{})
		m.Event([]string{"data", "connect", "accept", "close"}[r.IntN(4)])
		m.Truncation([]string{"kernel", "parser", "export"}[r.IntN(3)])
		m.SpanDecision("ratio", r.IntN(2) == 0)
		m.TLSUnresolved([]string{"resolved", "dropped"}[r.IntN(2)])
		m.CaptureGap([]string{"client", "server"}[r.IntN(2)], 1)
		m.ParserResync([]string{"client", "server"}[r.IntN(2)])
	}
	for _, side := range []string{"client", "server"} {
		m.SetConnections(side, true, 1)
		m.SetConnections(side, false, 1)
	}
	m.SetTracedProcesses(1)
	got, ceiling := series(t, reg), MaxSeries(cfg)
	t.Logf("series: %d, ceiling: %d", got, ceiling)
	if got > ceiling {
		t.Fatalf("%d series exceed the ceiling %d", got, ceiling)
	}
	if MaxSeries(Config{}) != 2541 || ceiling != 2557 {
		t.Fatalf("ceilings %d / %d, want 2541 / 2557", MaxSeries(Config{}), ceiling)
	}
}
