package export

import (
	"context"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	coltrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"

	"github.com/t1bur1an/pgtrace-ebpf/internal/correlate"
	"github.com/t1bur1an/pgtrace-ebpf/internal/event"
	"github.com/t1bur1an/pgtrace-ebpf/internal/pgwire"
	"github.com/t1bur1an/pgtrace-ebpf/internal/sampler"
	"github.com/t1bur1an/pgtrace-ebpf/internal/sqlcomment"
)

const (
	monoNow = int64(1_000_000_000)
	wallNow = int64(1_700_000_000_000_000_000)
)

// collector is an OTLP/HTTP endpoint that decodes requests with the
// official protobuf types.
type collector struct {
	mu       sync.Mutex
	reqs     []*coltrace.ExportTraceServiceRequest
	fail     atomic.Bool
	inflight atomic.Int32
	maxIn    atomic.Int32
	delay    time.Duration
}

func (c *collector) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	n := c.inflight.Add(1)
	defer c.inflight.Add(-1)
	for {
		m := c.maxIn.Load()
		if n <= m || c.maxIn.CompareAndSwap(m, n) {
			break
		}
	}
	time.Sleep(c.delay)
	body, _ := io.ReadAll(r.Body)
	if c.fail.Load() {
		http.Error(w, "down", http.StatusServiceUnavailable)
		return
	}
	var req coltrace.ExportTraceServiceRequest
	if err := proto.Unmarshal(body, &req); err != nil || r.Header.Get("Content-Type") != "application/x-protobuf" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	c.mu.Lock()
	c.reqs = append(c.reqs, &req)
	c.mu.Unlock()
}

type decoded struct {
	*tracepb.Span
	resource map[string]string
	scope    string
}

func (c *collector) spans() []decoded {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []decoded
	for _, req := range c.reqs {
		for _, rs := range req.ResourceSpans {
			res := map[string]string{}
			for _, kv := range rs.Resource.Attributes {
				res[kv.Key] = kv.Value.GetStringValue()
			}
			for _, ss := range rs.ScopeSpans {
				for _, s := range ss.Spans {
					out = append(out, decoded{s, res, ss.Scope.GetName()})
				}
			}
		}
	}
	return out
}

func spanAttrs(s *tracepb.Span) map[string]*commonpb.AnyValue {
	m := map[string]*commonpb.AnyValue{}
	for _, kv := range s.Attributes {
		m[kv.Key] = kv.Value
	}
	return m
}

type counts struct{ created, exported, failed, dropped atomic.Int64 }

func (c *counts) hooks() Hooks {
	return Hooks{
		Created:  func(n int) { c.created.Add(int64(n)) },
		Exported: func(n int) { c.exported.Add(int64(n)) },
		Failed:   func(n int) { c.failed.Add(int64(n)) },
		Dropped:  func(n int) { c.dropped.Add(int64(n)) },
	}
}

func newTest(t *testing.T, mod func(*Config)) (*Exporter, *collector, *counts) {
	t.Helper()
	col := &collector{}
	srv := httptest.NewServer(col)
	t.Cleanup(srv.Close)
	cnt := &counts{}
	cfg := Config{Endpoint: srv.URL, Service: "pgbouncer", Hooks: cnt.hooks(), Workers: 1, Interval: 50 * time.Millisecond,
		clock: func() (int64, int64) { return monoNow, wallNow }}
	if mod != nil {
		mod(&cfg)
	}
	e, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return e, col, cnt
}

func drain(t *testing.T, e *Exporter) {
	t.Helper()
	if err := e.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func noAddr(event.ConnKey) ServerConn { return ServerConn{} }

func TestExportSpan(t *testing.T) {
	e, col, _ := newTest(t, nil)
	e.Export(Span{
		Q: pgwire.Query{
			Start: uint64(monoNow - 5_000_000), End: uint64(monoNow - 1_000_000),
			SQL: "select * from t", Operation: "SELECT", CommandTag: "SELECT 3", Rows: 3, Protocol: "extended",
		},
		PID: 42, FD: 7, Remote: netip.MustParseAddrPort("10.0.0.2:5432"), Reason: sampler.ReasonRatio,
	})
	drain(t, e)
	spans := col.spans()
	if len(spans) != 1 {
		t.Fatalf("got %d spans", len(spans))
	}
	s := spans[0]
	if s.Name != "SELECT" || s.Kind != tracepb.Span_SPAN_KIND_CLIENT {
		t.Fatalf("name/kind %q %v", s.Name, s.Kind)
	}
	if s.StartTimeUnixNano != uint64(wallNow-5_000_000) || s.EndTimeUnixNano != uint64(wallNow-1_000_000) {
		t.Fatalf("times %d %d", s.StartTimeUnixNano, s.EndTimeUnixNano)
	}
	if len(s.TraceId) != 16 || len(s.SpanId) != 8 || len(s.ParentSpanId) != 0 {
		t.Fatalf("ids %x %x %x", s.TraceId, s.SpanId, s.ParentSpanId)
	}
	a := spanAttrs(s.Span)
	for k, v := range map[string]string{
		"db.system": "postgresql", "db.system.name": "postgresql", "db.query.text": "select * from t",
		"db.operation.name": "SELECT", "server.address": "10.0.0.2", "pgtrace.protocol": "extended",
		"pgtrace.sample_reason": "ratio", "pgtrace.command_tag": "SELECT 3",
	} {
		if a[k].GetStringValue() != v {
			t.Errorf("%s = %q want %q", k, a[k].GetStringValue(), v)
		}
	}
	if a["server.port"].GetIntValue() != 5432 || a["db.response.returned_rows"].GetIntValue() != 3 ||
		a["pgbouncer.pid"].GetIntValue() != 42 || a["pgbouncer.server_fd"].GetIntValue() != 7 {
		t.Errorf("int attrs %v", a)
	}
	if s.Status != nil && s.Status.Code == tracepb.Status_STATUS_CODE_ERROR {
		t.Errorf("status %v", s.Status)
	}
	if s.resource["service.name"] != "pgbouncer" || s.scope != scopeName {
		t.Errorf("resource %v scope %q", s.resource, s.scope)
	}
}

func TestExportErrorAndTruncation(t *testing.T) {
	e, col, _ := newTest(t, nil)
	e.Export(Span{Q: pgwire.Query{Start: uint64(monoNow), End: uint64(monoNow), SQL: strings.Repeat("x", 5000),
		ErrorCode: "22012", ErrorMessage: "division by zero", Truncated: true}})
	drain(t, e)
	s := col.spans()[0]
	if s.Status.GetCode() != tracepb.Status_STATUS_CODE_ERROR || s.Status.GetMessage() != "division by zero" {
		t.Fatalf("status %+v", s.Status)
	}
	a := spanAttrs(s.Span)
	if n := len(a["db.query.text"].GetStringValue()); n != DefaultMaxQueryText {
		t.Fatalf("query text len %d", n)
	}
	if a["db.response.status_code"].GetStringValue() != "22012" || !a["pgtrace.truncated"].GetBoolValue() {
		t.Fatalf("attrs %v", a)
	}
	if s.Name != "query" {
		t.Fatalf("fallback name %q", s.Name)
	}
}

func TestExportTrace(t *testing.T) {
	e, col, _ := newTest(t, nil)
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
	info := ClientInfo{Addr: netip.MustParseAddrPort("10.0.0.9:40000"), Params: map[string]string{"user": "alice", "database": "shop", "application_name": "api"}, IdleInTx: 5 * time.Second}
	e.ExportTrace(tr, sampler.ReasonError, info, func(event.ConnKey) ServerConn { return ServerConn{Addr: netip.MustParseAddrPort("10.0.0.2:5432")} })
	drain(t, e)
	spans := col.spans()
	if len(spans) != 3 {
		t.Fatalf("got %d spans", len(spans))
	}
	var root decoded
	var children []decoded
	for _, s := range spans {
		if s.Kind == tracepb.Span_SPAN_KIND_SERVER {
			root = s
		} else {
			children = append(children, s)
		}
	}
	for _, c := range children {
		if string(c.ParentSpanId) != string(root.SpanId) || string(c.TraceId) != string(root.TraceId) {
			t.Fatalf("child not under root")
		}
	}
	ra := spanAttrs(root.Span)
	if ra["client.address"].GetStringValue() != "10.0.0.9" || ra["client.port"].GetIntValue() != 40000 ||
		ra["db.namespace"].GetStringValue() != "shop" || ra["db.user"].GetStringValue() != "alice" ||
		ra["application_name"].GetStringValue() != "api" || ra["pgbouncer.client_fd"].GetIntValue() != 11 ||
		ra["pgtrace.correlation"].GetStringValue() != "exact" || ra["pgbouncer.idle_in_tx_ms"].GetDoubleValue() != 5000 {
		t.Fatalf("root attrs %v", ra)
	}
	if ra["pgbouncer.pool_wait_ms"].GetDoubleValue() != 2 {
		t.Fatalf("pool wait %v", ra["pgbouncer.pool_wait_ms"])
	}
	if root.Name != "SELECT" || root.StartTimeUnixNano != uint64(wallNow-10_000_000) {
		t.Fatalf("root %q %d", root.Name, root.StartTimeUnixNano)
	}
	var internal, failed int
	for _, c := range children {
		a := spanAttrs(c.Span)
		if a["pgbouncer.internal"].GetBoolValue() {
			internal++
		}
		if c.Status.GetCode() == tracepb.Status_STATUS_CODE_ERROR {
			failed++
		}
		if a["pgtrace.correlation"].GetStringValue() != "exact" || a["server.port"].GetIntValue() != 5432 {
			t.Fatalf("child attrs %v", a)
		}
	}
	if internal != 1 || failed != 1 {
		t.Fatalf("internal=%d failed=%d", internal, failed)
	}
}

func TestExportUncorrelated(t *testing.T) {
	e, col, _ := newTest(t, nil)
	tr := correlate.Trace{Server: []correlate.ServerQuery{{Key: event.ConnKey{PID: 1, FD: 7}, Correlation: "none", Q: pgwire.Query{Start: 1, End: 2, SQL: "select 1", Operation: "SELECT"}}}}
	e.ExportTrace(tr, sampler.ReasonRatio, ClientInfo{}, noAddr)
	drain(t, e)
	spans := col.spans()
	if len(spans) != 1 || spans[0].Kind != tracepb.Span_SPAN_KIND_CLIENT || len(spans[0].ParentSpanId) != 0 {
		t.Fatalf("got %+v", spans)
	}
	if spanAttrs(spans[0].Span)["pgtrace.correlation"].GetStringValue() != "none" {
		t.Fatal("missing correlation attr")
	}
}

func TestTruncatedTextIsValidUTF8(t *testing.T) {
	e, col, _ := newTest(t, nil)
	e.Export(Span{Q: pgwire.Query{Start: 1, End: 2, SQL: strings.Repeat("a", DefaultMaxQueryText-1) + "ж" + "tail"}})
	e.Export(Span{Q: pgwire.Query{Start: 1, End: 2, SQL: "select '" + string([]byte("жж")[:3])}})
	drain(t, e)
	for _, s := range col.spans() {
		v := spanAttrs(s.Span)["db.query.text"].GetStringValue()
		if !utf8.ValidString(v) || len(v) > DefaultMaxQueryText {
			t.Fatalf("db.query.text %q", v)
		}
	}
	if len(col.spans()) != 2 {
		t.Fatal("a span with cut UTF-8 was rejected")
	}
}

func TestMaxQueryTextOption(t *testing.T) {
	cut := 0
	e, col, _ := newTest(t, func(c *Config) { c.MaxQueryText = 100; c.OnTruncate = func() { cut++ } })
	e.Export(Span{Q: pgwire.Query{Start: 1, End: 2, SQL: strings.Repeat("s", 500)}})
	e.Export(Span{Q: pgwire.Query{Start: 1, End: 2, SQL: "short"}})
	drain(t, e)
	lens := map[int]bool{}
	for _, s := range col.spans() {
		lens[len(spanAttrs(s.Span)["db.query.text"].GetStringValue())] = true
	}
	if !lens[100] || cut != 1 {
		t.Fatalf("lens %v cut %d", lens, cut)
	}
}

func TestExportTraceWithRemoteParent(t *testing.T) {
	e, col, _ := newTest(t, nil)
	tr := correlate.Trace{
		Client: &correlate.ClientQuery{Key: event.ConnKey{PID: 1, FD: 3}, Q: pgwire.Query{Start: 1, End: 10, SQL: "select 1 /*...*/", Operation: "SELECT"}},
		Server: []correlate.ServerQuery{{Key: event.ConnKey{PID: 1, FD: 4}, Correlation: "exact", Q: pgwire.Query{Start: 2, End: 9, Operation: "SELECT"}}},
	}
	info := ClientInfo{
		Comment:   sqlcomment.Comment{TraceParent: "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01", TraceState: "congo=t61rcWkgMzE", Valid: true, Attrs: map[string]string{"route": "/orders"}},
		UseParent: true,
	}
	e.ExportTrace(tr, sampler.ReasonParent, info, noAddr)
	info.UseParent = false
	e.ExportTrace(tr, sampler.ReasonRatio, info, noAddr)
	drain(t, e)
	var withParent, without int
	for _, s := range col.spans() {
		a := spanAttrs(s.Span)
		if s.Kind != tracepb.Span_SPAN_KIND_SERVER {
			continue
		}
		if a["sqlcommenter.route"].GetStringValue() != "/orders" {
			t.Fatalf("root attrs %v", a)
		}
		if hex.EncodeToString(s.TraceId) == "4bf92f3577b34da6a3ce929d0e0e4736" {
			if hex.EncodeToString(s.ParentSpanId) != "00f067aa0ba902b7" || s.TraceState != "congo=t61rcWkgMzE" ||
				a["pgtrace.trace_context"].GetStringValue() != "sqlcommenter" {
				t.Fatalf("remote parent root %+v", s.Span)
			}
			withParent++
		} else {
			if len(s.ParentSpanId) != 0 {
				t.Fatalf("root without UseParent has a parent")
			}
			without++
		}
	}
	if withParent != 1 || without != 1 {
		t.Fatalf("withParent=%d without=%d", withParent, without)
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

func TestExportConnError(t *testing.T) {
	e, col, _ := newTest(t, nil)
	e.ExportConnError(ConnError{Client: true, Key: event.ConnKey{PID: 1, FD: 9}, Start: uint64(monoNow - 3_000_000), End: uint64(monoNow),
		Code: "28P01", Message: "password authentication failed", Addr: netip.MustParseAddrPort("10.0.0.9:5555"),
		Params: map[string]string{"user": "bob", "database": "shop"}})
	drain(t, e)
	s := col.spans()[0]
	a := spanAttrs(s.Span)
	if s.Name != "connect" || s.Kind != tracepb.Span_SPAN_KIND_SERVER || s.Status.GetCode() != tracepb.Status_STATUS_CODE_ERROR ||
		a["db.response.status_code"].GetStringValue() != "28P01" || a["db.user"].GetStringValue() != "bob" ||
		a["client.address"].GetStringValue() != "10.0.0.9" || !a["pgtrace.connection_error"].GetBoolValue() ||
		s.EndTimeUnixNano-s.StartTimeUnixNano != uint64(3*time.Millisecond) {
		t.Fatalf("span %+v attrs %v", s.Span, a)
	}
}

func TestBatchingAndConcurrency(t *testing.T) {
	e, col, cnt := newTest(t, func(c *Config) { c.Workers = 4; c.BatchSpans = 100 })
	col.delay = 20 * time.Millisecond
	for i := 0; i < 5000; i++ {
		e.Export(Span{Q: pgwire.Query{Start: 1, End: 2, SQL: "select 1"}})
	}
	drain(t, e)
	if got := len(col.spans()); got != 5000 {
		t.Fatalf("delivered %d spans", got)
	}
	if cnt.created.Load() != 5000 || cnt.exported.Load() != 5000 || cnt.failed.Load() != 0 || cnt.dropped.Load() != 0 {
		t.Fatalf("counts created=%d exported=%d failed=%d dropped=%d", cnt.created.Load(), cnt.exported.Load(), cnt.failed.Load(), cnt.dropped.Load())
	}
	for _, r := range col.reqs {
		if n := len(r.ResourceSpans[0].ScopeSpans[0].Spans); n > 100 {
			t.Fatalf("batch of %d spans", n)
		}
	}
	if col.maxIn.Load() < 2 {
		t.Fatalf("requests were not concurrent (max in flight %d)", col.maxIn.Load())
	}
}

func TestFailedBatchCounted(t *testing.T) {
	e, col, cnt := newTest(t, nil)
	col.fail.Store(true)
	for i := 0; i < 3; i++ {
		e.Export(Span{Q: pgwire.Query{Start: 1, End: 2, SQL: "select 1"}})
	}
	drain(t, e)
	if cnt.created.Load() != 3 || cnt.exported.Load() != 0 || cnt.failed.Load() != 3 {
		t.Fatalf("created=%d exported=%d failed=%d", cnt.created.Load(), cnt.exported.Load(), cnt.failed.Load())
	}
}

func TestQueueOverflowDropsAndCounts(t *testing.T) {
	block := make(chan struct{})
	e, _, cnt := newTest(t, func(c *Config) {
		c.QueueTraces, c.Workers, c.BatchSpans = 10, 1, 1
		// Stall the only worker inside a request so the queue fills up.
		c.Client = &http.Client{Transport: roundTrip(func(*http.Request) (*http.Response, error) {
			<-block
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(""))}, nil
		})}
	})
	tr := correlate.Trace{Client: &correlate.ClientQuery{Q: pgwire.Query{Start: 1, End: 2}},
		Server: []correlate.ServerQuery{{Q: pgwire.Query{Start: 1, End: 2}, Correlation: "exact"}}}
	for i := 0; i < 50; i++ {
		e.ExportTrace(tr, sampler.ReasonRatio, ClientInfo{}, noAddr)
	}
	if cnt.dropped.Load() == 0 {
		t.Fatal("expected dropped spans when the queue is full")
	}
	if cnt.dropped.Load()%2 != 0 {
		t.Fatalf("dropped %d spans: a trace is 2 spans", cnt.dropped.Load())
	}
	close(block)
	drain(t, e)
	if total := cnt.created.Load() + cnt.dropped.Load(); total != 100 {
		t.Fatalf("created %d + dropped %d != 100", cnt.created.Load(), cnt.dropped.Load())
	}
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// The queue is allocated up front for -export-queue traces, so a slot must
// be a pointer, not a whole job.
func TestQueueSlotIsSmall(t *testing.T) {
	e, _, _ := newTest(t, nil)
	defer drain(t, e)
	if s := reflect.TypeOf(e.jobs).Elem().Size(); s > 8 {
		t.Fatalf("queue slot is %d bytes", s)
	}
}

func TestExportTLSAttributes(t *testing.T) {
	e, col, _ := newTest(t, nil)
	tr := correlate.Trace{
		Client: &correlate.ClientQuery{Key: event.ConnKey{PID: 1, FD: 11}, Q: pgwire.Query{Start: 1, End: 10, SQL: "select 1", Operation: "SELECT"}},
		Server: []correlate.ServerQuery{{Key: event.ConnKey{PID: 1, FD: 7}, Correlation: "exact", Q: pgwire.Query{Start: 2, End: 9, SQL: "select 1", Operation: "SELECT"}}},
	}
	info := ClientInfo{TLS: TLSInfo{On: true, Version: "1.3", Cipher: "TLS_AES_256_GCM_SHA384" + strings.Repeat("x", 100)}}
	// Client hop TLS, server hop plain.
	e.ExportTrace(tr, sampler.ReasonRatio, info, func(event.ConnKey) ServerConn { return ServerConn{} })
	e.ExportConnError(ConnError{Client: true, Key: event.ConnKey{PID: 1, FD: 12}, End: 5, Code: "28P01", TLS: TLSInfo{On: true}})
	drain(t, e)
	var root, child, conn map[string]*commonpb.AnyValue
	for _, s := range col.spans() {
		switch {
		case s.Name == "connect":
			conn = spanAttrs(s.Span)
		case s.Kind == tracepb.Span_SPAN_KIND_SERVER:
			root = spanAttrs(s.Span)
		default:
			child = spanAttrs(s.Span)
		}
	}
	if root["tls.protocol.name"].GetStringValue() != "tls" || root["tls.protocol.version"].GetStringValue() != "1.3" ||
		len(root["tls.cipher"].GetStringValue()) != 64 {
		t.Fatalf("root %v", root)
	}
	for _, k := range []string{"tls.protocol.name", "tls.protocol.version", "tls.cipher"} {
		if _, ok := child[k]; ok {
			t.Fatalf("plain server hop has %s", k)
		}
	}
	if conn["tls.protocol.name"].GetStringValue() != "tls" {
		t.Fatalf("connect span %v", conn)
	}
	if _, ok := conn["tls.protocol.version"]; ok {
		t.Fatal("unknown version exported")
	}
}
