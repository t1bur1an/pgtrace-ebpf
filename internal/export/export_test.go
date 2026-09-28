package export

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"

	"github.com/t1bur1an/pgtrace/internal/correlate"
	"github.com/t1bur1an/pgtrace/internal/event"
	"github.com/t1bur1an/pgtrace/internal/pgwire"
	"github.com/t1bur1an/pgtrace/internal/sampler"
	"github.com/t1bur1an/pgtrace/internal/sqlcomment"
)

const (
	monoNow = int64(1_000_000_000)
	wallNow = int64(1_700_000_000_000_000_000)
)

func newTest(t *testing.T) (*Exporter, *tracetest.InMemoryExporter) {
	mem := tracetest.NewInMemoryExporter()
	e := newWithSpanExporter(mem, "pgbouncer", func() (int64, int64) { return monoNow, wallNow })
	t.Cleanup(func() { e.Shutdown(context.Background()) })
	return e, mem
}

func attrs(kv []attribute.KeyValue) map[string]attribute.Value {
	m := map[string]attribute.Value{}
	for _, a := range kv {
		m[string(a.Key)] = a.Value
	}
	return m
}

func TestExportSpan(t *testing.T) {
	e, mem := newTest(t)
	e.Export(Span{
		Q: pgwire.Query{
			Start: uint64(monoNow - 5_000_000), End: uint64(monoNow - 1_000_000),
			SQL: "select * from t", Operation: "SELECT", CommandTag: "SELECT 3", Rows: 3, Protocol: "extended",
		},
		PID: 42, FD: 7, Remote: netip.MustParseAddrPort("10.0.0.2:5432"), Reason: sampler.ReasonRatio,
	})
	spans := mem.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("got %d spans", len(spans))
	}
	s := spans[0]
	if s.Name != "SELECT" || s.SpanKind != trace.SpanKindClient {
		t.Fatalf("name/kind %q %v", s.Name, s.SpanKind)
	}
	if want := time.Unix(0, wallNow-5_000_000); !s.StartTime.Equal(want) {
		t.Fatalf("start %v want %v", s.StartTime, want)
	}
	if want := time.Unix(0, wallNow-1_000_000); !s.EndTime.Equal(want) {
		t.Fatalf("end %v want %v", s.EndTime, want)
	}
	a := attrs(s.Attributes)
	checks := map[string]string{
		"db.system":             "postgresql",
		"db.system.name":        "postgresql",
		"db.query.text":         "select * from t",
		"db.operation.name":     "SELECT",
		"server.address":        "10.0.0.2",
		"pgtrace.protocol":      "extended",
		"pgtrace.sample_reason": "ratio",
		"pgtrace.command_tag":   "SELECT 3",
	}
	for k, v := range checks {
		if a[k].AsString() != v {
			t.Errorf("%s = %q want %q", k, a[k].AsString(), v)
		}
	}
	if a["server.port"].AsInt64() != 5432 || a["db.response.returned_rows"].AsInt64() != 3 ||
		a["pgbouncer.pid"].AsInt64() != 42 || a["pgbouncer.server_fd"].AsInt64() != 7 {
		t.Errorf("int attrs %v", a)
	}
	if s.Status.Code != codes.Unset {
		t.Errorf("status %v", s.Status)
	}
	if s.Resource.Set().Len() == 0 {
		t.Error("no resource")
	}
	if v, _ := s.Resource.Set().Value("service.name"); v.AsString() != "pgbouncer" {
		t.Errorf("service.name %q", v.AsString())
	}
}

func TestExportErrorAndTruncation(t *testing.T) {
	e, mem := newTest(t)
	e.Export(Span{Q: pgwire.Query{
		Start: uint64(monoNow), End: uint64(monoNow), SQL: strings.Repeat("x", 5000),
		ErrorCode: "22012", ErrorMessage: "division by zero", Truncated: true,
	}})
	s := mem.GetSpans()[0]
	if s.Status.Code != codes.Error || s.Status.Description != "division by zero" {
		t.Fatalf("status %+v", s.Status)
	}
	a := attrs(s.Attributes)
	if n := len(a["db.query.text"].AsString()); n != DefaultMaxQueryText {
		t.Fatalf("query text len %d", n)
	}
	if a["db.response.status_code"].AsString() != "22012" || !a["pgtrace.truncated"].AsBool() {
		t.Fatalf("attrs %v", a)
	}
	if s.Name != "query" {
		t.Fatalf("fallback name %q", s.Name)
	}
}

func TestExportTrace(t *testing.T) {
	e, mem := newTest(t)
	client := event.ConnKey{PID: 42, FD: 11}
	server := event.ConnKey{PID: 42, FD: 7}
	tr := correlate.Trace{
		Client: &correlate.ClientQuery{Key: client, Q: pgwire.Query{
			Start: uint64(monoNow - 10_000_000), End: uint64(monoNow - 1_000_000),
			SQL: "select 1", Operation: "SELECT", Protocol: "simple", Rows: 1,
		}},
		Server: []correlate.ServerQuery{
			{Key: server, Correlation: "exact", Internal: true, Q: pgwire.Query{Start: uint64(monoNow - 8_000_000), End: uint64(monoNow - 7_000_000), SQL: "SET application_name='x'", Operation: "SET"}},
			{Key: server, Correlation: "exact", Q: pgwire.Query{Start: uint64(monoNow - 6_000_000), End: uint64(monoNow - 2_000_000), SQL: "select 1", Operation: "SELECT", ErrorCode: "40001", ErrorMessage: "serialization"}},
		},
	}
	info := ClientInfo{Addr: netip.MustParseAddrPort("10.0.0.9:40000"), Params: map[string]string{"user": "alice", "database": "shop", "application_name": "api"}}
	e.ExportTrace(tr, sampler.ReasonError, info, func(event.ConnKey) netip.AddrPort { return netip.MustParseAddrPort("10.0.0.2:5432") })

	spans := mem.GetSpans()
	if len(spans) != 3 {
		t.Fatalf("got %d spans", len(spans))
	}
	var root tracetest.SpanStub
	var children []tracetest.SpanStub
	for _, s := range spans {
		if s.SpanKind == trace.SpanKindServer {
			root = s
		} else {
			children = append(children, s)
		}
	}
	for _, c := range children {
		if c.Parent.SpanID() != root.SpanContext.SpanID() || c.SpanContext.TraceID() != root.SpanContext.TraceID() {
			t.Fatalf("child not under root: %+v", c.Parent)
		}
	}
	ra := attrs(root.Attributes)
	if ra["client.address"].AsString() != "10.0.0.9" || ra["client.port"].AsInt64() != 40000 ||
		ra["db.namespace"].AsString() != "shop" || ra["db.user"].AsString() != "alice" || ra["application_name"].AsString() != "api" ||
		ra["pgbouncer.client_fd"].AsInt64() != 11 || ra["pgtrace.correlation"].AsString() != "exact" {
		t.Fatalf("root attrs %v", ra)
	}
	if ra["pgbouncer.pool_wait_ms"].AsFloat64() != 2 {
		t.Fatalf("pool wait %v", ra["pgbouncer.pool_wait_ms"])
	}
	if root.Name != "SELECT" || !root.StartTime.Equal(time.Unix(0, wallNow-10_000_000)) {
		t.Fatalf("root %q %v", root.Name, root.StartTime)
	}
	var internal, failed int
	for _, c := range children {
		a := attrs(c.Attributes)
		if a["pgbouncer.internal"].AsBool() {
			internal++
		}
		if c.Status.Code == codes.Error {
			failed++
		}
		if a["pgtrace.correlation"].AsString() != "exact" || a["server.port"].AsInt64() != 5432 {
			t.Fatalf("child attrs %v", a)
		}
	}
	if internal != 1 || failed != 1 {
		t.Fatalf("internal=%d failed=%d", internal, failed)
	}
}

func TestExportUncorrelated(t *testing.T) {
	e, mem := newTest(t)
	tr := correlate.Trace{Server: []correlate.ServerQuery{{Key: event.ConnKey{PID: 1, FD: 7}, Correlation: "none", Q: pgwire.Query{Start: 1, End: 2, SQL: "select 1", Operation: "SELECT"}}}}
	e.ExportTrace(tr, sampler.ReasonRatio, ClientInfo{}, func(event.ConnKey) netip.AddrPort { return netip.AddrPort{} })
	spans := mem.GetSpans()
	if len(spans) != 1 || spans[0].SpanKind != trace.SpanKindClient || spans[0].Parent.IsValid() {
		t.Fatalf("got %+v", spans)
	}
	if attrs(spans[0].Attributes)["pgtrace.correlation"].AsString() != "none" {
		t.Fatal("missing correlation attr")
	}
}

func TestTruncatedTextIsValidUTF8(t *testing.T) {
	e, mem := newTest(t)
	// A multi-byte rune straddles the 2048-byte cut, and the captured SQL
	// itself ends mid-rune (as when the parser truncates a long message).
	sql := strings.Repeat("a", DefaultMaxQueryText-1) + "ж" + "tail"
	e.Export(Span{Q: pgwire.Query{Start: 1, End: 2, SQL: sql}})
	e.Export(Span{Q: pgwire.Query{Start: 1, End: 2, SQL: "select '" + string([]byte("жж")[:3])}})
	for _, s := range mem.GetSpans() {
		v := attrs(s.Attributes)["db.query.text"].AsString()
		if !utf8.ValidString(v) {
			t.Fatalf("invalid UTF-8 in db.query.text: %q", v[len(v)-4:])
		}
		if len(v) > DefaultMaxQueryText {
			t.Fatalf("text longer than cap: %d", len(v))
		}
	}
}

func TestMaxQueryTextOption(t *testing.T) {
	mem := tracetest.NewInMemoryExporter()
	cut := 0
	e := newWithSpanExporter(mem, "pgbouncer", func() (int64, int64) { return monoNow, wallNow })
	e.SetOptions(Options{MaxQueryText: 100, OnTruncate: func() { cut++ }})
	e.Export(Span{Q: pgwire.Query{Start: 1, End: 2, SQL: strings.Repeat("s", 500)}})
	e.Export(Span{Q: pgwire.Query{Start: 1, End: 2, SQL: "short"}})
	spans := mem.GetSpans()
	if n := len(attrs(spans[0].Attributes)["db.query.text"].AsString()); n != 100 {
		t.Fatalf("len %d", n)
	}
	if cut != 1 {
		t.Fatalf("truncation hook called %d times", cut)
	}
}

func TestExportTraceWithRemoteParent(t *testing.T) {
	e, mem := newTest(t)
	tr := correlate.Trace{
		Client: &correlate.ClientQuery{Key: event.ConnKey{PID: 1, FD: 3}, Q: pgwire.Query{Start: 1, End: 10, SQL: "select 1 /*...*/", Operation: "SELECT"}},
		Server: []correlate.ServerQuery{{Key: event.ConnKey{PID: 1, FD: 4}, Correlation: "exact", Q: pgwire.Query{Start: 2, End: 9, Operation: "SELECT"}}},
	}
	info := ClientInfo{
		Comment:   sqlcomment.Comment{TraceParent: "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01", TraceState: "congo=t61rcWkgMzE", Valid: true, Attrs: map[string]string{"route": "/orders"}},
		UseParent: true,
	}
	e.ExportTrace(tr, sampler.ReasonParent, info, func(event.ConnKey) netip.AddrPort { return netip.AddrPort{} })
	spans := mem.GetSpans()
	if len(spans) != 2 {
		t.Fatalf("%d spans", len(spans))
	}
	for _, s := range spans {
		if s.SpanContext.TraceID().String() != "4bf92f3577b34da6a3ce929d0e0e4736" {
			t.Fatalf("trace id %s", s.SpanContext.TraceID())
		}
		if s.SpanKind == trace.SpanKindServer {
			if s.Parent.SpanID().String() != "00f067aa0ba902b7" || !s.Parent.IsRemote() {
				t.Fatalf("root parent %v remote=%v", s.Parent.SpanID(), s.Parent.IsRemote())
			}
			a := attrs(s.Attributes)
			if a["pgtrace.trace_context"].AsString() != "sqlcommenter" || a["sqlcommenter.route"].AsString() != "/orders" {
				t.Fatalf("root attrs %v", a)
			}
		}
	}
	// Without UseParent the comment attributes are kept but the span is a root.
	mem.Reset()
	info.UseParent = false
	e.ExportTrace(tr, sampler.ReasonRatio, info, func(event.ConnKey) netip.AddrPort { return netip.AddrPort{} })
	for _, s := range mem.GetSpans() {
		if s.SpanKind == trace.SpanKindServer && (s.Parent.IsValid() || attrs(s.Attributes)["sqlcommenter.route"].AsString() != "/orders") {
			t.Fatalf("not-per-execution comment: parent=%v attrs=%v", s.Parent, attrs(s.Attributes))
		}
	}
}

func TestSampledFlag(t *testing.T) {
	for flags, want := range map[string]bool{"01": true, "00": false, "0b": true, "02": false, "ff": true} {
		c := sqlcomment.Comment{Valid: true, TraceParent: "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-" + flags}
		if Sampled(c) != want {
			t.Errorf("flags %s: sampled=%v", flags, !want)
		}
	}
}

func TestExportConnErrorAndIdle(t *testing.T) {
	e, mem := newTest(t)
	e.ExportConnError(ConnError{Client: true, Key: event.ConnKey{PID: 1, FD: 9}, Start: uint64(monoNow - 3_000_000), End: uint64(monoNow),
		Code: "28P01", Message: "password authentication failed", Addr: netip.MustParseAddrPort("10.0.0.9:5555"),
		Params: map[string]string{"user": "bob", "database": "shop"}})
	s := mem.GetSpans()[0]
	a := attrs(s.Attributes)
	if s.Name != "connect" || s.SpanKind != trace.SpanKindServer || s.Status.Code != codes.Error ||
		a["db.response.status_code"].AsString() != "28P01" || a["db.user"].AsString() != "bob" ||
		a["client.address"].AsString() != "10.0.0.9" || !a["pgtrace.connection_error"].AsBool() ||
		s.EndTime.Sub(s.StartTime) != 3*time.Millisecond {
		t.Fatalf("span %s %v %v attrs %v", s.Name, s.SpanKind, s.Status, a)
	}
	mem.Reset()
	tr := correlate.Trace{Client: &correlate.ClientQuery{Q: pgwire.Query{Start: 1, End: 2, Operation: "COMMIT"}}}
	e.ExportTrace(tr, sampler.ReasonSlow, ClientInfo{IdleInTx: 5 * time.Second}, func(event.ConnKey) netip.AddrPort { return netip.AddrPort{} })
	if v := attrs(mem.GetSpans()[0].Attributes)["pgbouncer.idle_in_tx_ms"].AsFloat64(); v != 5000 {
		t.Fatalf("idle_in_tx_ms %v", v)
	}
}
