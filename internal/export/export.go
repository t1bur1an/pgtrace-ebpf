// Package export turns sampled queries into OpenTelemetry spans.
package export

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/sys/unix"

	"github.com/t1bur1an/pgtrace/internal/pgwire"
	"github.com/t1bur1an/pgtrace/internal/sampler"
)

const maxQueryText = 2048

// Span is a kept query plus the connection it was seen on.
type Span struct {
	Q      pgwire.Query
	PID    uint32
	FD     int32
	Remote netip.AddrPort
	Reason sampler.Reason
}

type Exporter struct {
	tp     *sdktrace.TracerProvider
	tracer trace.Tracer
	offset int64 // wall - monotonic, ns
}

// New exports over OTLP/HTTP to endpoint, a full URL such as
// http://victoriatraces:10428/insert/opentelemetry/v1/traces.
func New(ctx context.Context, endpoint, service string) (*Exporter, error) {
	sx, err := otlptracehttp.New(ctx, otlptracehttp.WithEndpointURL(endpoint))
	if err != nil {
		return nil, fmt.Errorf("otlp exporter: %w", err)
	}
	// The batch processor drops spans when its queue is full instead of
	// blocking, so a slow collector never stalls capture.
	bsp := sdktrace.NewBatchSpanProcessor(sx,
		sdktrace.WithMaxQueueSize(65536),
		sdktrace.WithMaxExportBatchSize(2048),
		sdktrace.WithBatchTimeout(2*time.Second))
	return build(bsp, service, clocks), nil
}

func newWithSpanExporter(sx sdktrace.SpanExporter, service string, clock func() (mono, wall int64)) *Exporter {
	return build(sdktrace.NewSimpleSpanProcessor(sx), service, clock)
}

func build(sp sdktrace.SpanProcessor, service string, clock func() (mono, wall int64)) *Exporter {
	res := resource.NewSchemaless(attribute.String("service.name", service))
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithResource(res),
		sdktrace.WithSpanProcessor(sp),
		sdktrace.WithSampler(sdktrace.AlwaysSample()), // sampling is done upstream
	)
	mono, wall := clock()
	return &Exporter{tp: tp, tracer: tp.Tracer("github.com/t1bur1an/pgtrace"), offset: wall - mono}
}

func clocks() (mono, wall int64) {
	var ts unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	return ts.Nano(), time.Now().UnixNano()
}

func (e *Exporter) wall(mono uint64) time.Time { return time.Unix(0, int64(mono)+e.offset) }

func (e *Exporter) Export(s Span) {
	q := s.Q
	name := q.Operation
	if name == "" {
		name = "query"
	}
	text := q.SQL
	if len(text) > maxQueryText {
		text = text[:maxQueryText]
	}
	attrs := []attribute.KeyValue{
		attribute.String("db.system", "postgresql"),
		attribute.String("db.system.name", "postgresql"),
		attribute.String("db.query.text", text),
		attribute.String("db.operation.name", q.Operation),
		attribute.Int64("db.response.returned_rows", q.Rows),
		attribute.Int64("pgbouncer.pid", int64(s.PID)),
		attribute.Int64("pgbouncer.server_fd", int64(s.FD)),
		attribute.String("pgtrace.protocol", q.Protocol),
		attribute.String("pgtrace.command_tag", q.CommandTag),
		attribute.Bool("pgtrace.truncated", q.Truncated),
		attribute.String("pgtrace.sample_reason", string(s.Reason)),
	}
	if s.Remote.IsValid() {
		attrs = append(attrs,
			attribute.String("server.address", s.Remote.Addr().String()),
			attribute.Int("server.port", int(s.Remote.Port())))
	}
	if q.ErrorCode != "" {
		attrs = append(attrs, attribute.String("db.response.status_code", q.ErrorCode))
	}
	_, span := e.tracer.Start(context.Background(), name,
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithTimestamp(e.wall(q.Start)),
		trace.WithAttributes(attrs...))
	if q.ErrorCode != "" {
		span.SetStatus(codes.Error, q.ErrorMessage)
	}
	span.End(trace.WithTimestamp(e.wall(q.End)))
}

func (e *Exporter) Shutdown(ctx context.Context) error { return e.tp.Shutdown(ctx) }
