package export

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"

	"github.com/t1bur1an/pgtrace/internal/pgwire"
	"github.com/t1bur1an/pgtrace/internal/sampler"
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
	if n := len(a["db.query.text"].AsString()); n != maxQueryText {
		t.Fatalf("query text len %d", n)
	}
	if a["db.response.status_code"].AsString() != "22012" || !a["pgtrace.truncated"].AsBool() {
		t.Fatalf("attrs %v", a)
	}
	if s.Name != "query" {
		t.Fatalf("fallback name %q", s.Name)
	}
}
