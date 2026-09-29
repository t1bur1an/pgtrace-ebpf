package export

import (
	"context"
	"net/netip"
	"testing"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"

	"github.com/t1bur1an/pgtrace-ebpf/internal/pgwire"
	"github.com/t1bur1an/pgtrace-ebpf/internal/sampler"
)

type discard struct{}

func (discard) ExportSpans(context.Context, []sdktrace.ReadOnlySpan) error { return nil }
func (discard) Shutdown(context.Context) error                             { return nil }

// BenchmarkExport measures span creation plus the batch processor hand-off
// (network export excluded).
func BenchmarkExport(b *testing.B) {
	bsp := sdktrace.NewBatchSpanProcessor(discard{}, sdktrace.WithMaxQueueSize(65536), sdktrace.WithMaxExportBatchSize(2048))
	e := build(bsp, "pgbouncer", clocks)
	defer e.Shutdown(context.Background())
	s := Span{
		Q:   pgwire.Query{Start: 1, End: 2, SQL: "SELECT abalance FROM pgbench_accounts WHERE aid = 12345;", Operation: "SELECT", CommandTag: "SELECT 1", Rows: 1, Protocol: "simple"},
		PID: 42, FD: 7, Remote: netip.MustParseAddrPort("10.0.0.2:5432"), Reason: sampler.ReasonRatio,
	}
	b.ReportAllocs()
	for b.Loop() {
		e.Export(s)
	}
}
