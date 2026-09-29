// Package export turns sampled queries into OpenTelemetry spans.
package export

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/sys/unix"

	"github.com/t1bur1an/pgtrace-ebpf/internal/correlate"
	"github.com/t1bur1an/pgtrace-ebpf/internal/event"
	"github.com/t1bur1an/pgtrace-ebpf/internal/pgwire"
	"github.com/t1bur1an/pgtrace-ebpf/internal/sampler"
	"github.com/t1bur1an/pgtrace-ebpf/internal/sqlcomment"
)

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
	opts   Options
}

// Options tune what goes into spans.
type Options struct {
	MaxQueryText int    // db.query.text length cap (DefaultMaxQueryText if 0)
	OnTruncate   func() // called when db.query.text is shortened
}

// DefaultMaxQueryText is the default db.query.text cap in bytes.
const DefaultMaxQueryText = 2048

// SetOptions must be called before exporting.
func (e *Exporter) SetOptions(o Options) {
	if o.MaxQueryText <= 0 {
		o.MaxQueryText = DefaultMaxQueryText
	}
	e.opts = o
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
	return &Exporter{tp: tp, tracer: tp.Tracer("github.com/t1bur1an/pgtrace-ebpf"), offset: wall - mono,
		opts: Options{MaxQueryText: DefaultMaxQueryText}}
}

func clocks() (mono, wall int64) {
	var ts unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	return ts.Nano(), time.Now().UnixNano()
}

func (e *Exporter) wall(mono uint64) time.Time { return time.Unix(0, int64(mono)+e.offset) }

func (e *Exporter) Export(s Span) {
	e.span(context.Background(), trace.SpanKindClient, s.Q, e.serverAttrs(s))
}

// ClientInfo describes the client connection of a trace's root query.
type ClientInfo struct {
	Addr   netip.AddrPort    // invalid for unix sockets or unknown
	Params map[string]string // startup parameters, if seen
	// Comment is the root query's SQLCommenter comment, if any. Its
	// attributes are always exported; its traceparent becomes the root
	// span's parent only when UseParent is set.
	Comment   sqlcomment.Comment
	UseParent bool
	// IdleInTx is how long the client sat idle inside a transaction (holding
	// its server connection) before sending this query.
	IdleInTx time.Duration
}

// ConnError is an error on a connection with no query in flight: a rejected
// login or a FATAL ending an idle session.
type ConnError struct {
	Client        bool          // client↔pgbouncer (true) or pgbouncer↔postgres
	Key           event.ConnKey //
	Start, End    uint64        // connection start (accept/connect/first data) and error, monotonic ns
	Code, Message string
	Addr          netip.AddrPort    // peer address
	Params        map[string]string // client startup parameters, if seen
}

// ExportConnError exports a connection error as a "connect" span.
func (e *Exporter) ExportConnError(c ConnError) {
	kind := trace.SpanKindClient
	attrs := []attribute.KeyValue{
		attribute.String("db.system", "postgresql"),
		attribute.String("db.system.name", "postgresql"),
		attribute.Bool("pgtrace.connection_error", true),
		attribute.String("db.response.status_code", clean(c.Code, 16)),
		attribute.Int64("pgbouncer.pid", int64(c.Key.PID)),
		attribute.String("pgtrace.sample_reason", string(sampler.ReasonError)),
	}
	addrKey, portKey, fdKey := "server.address", "server.port", "pgbouncer.server_fd"
	if c.Client {
		kind = trace.SpanKindServer
		addrKey, portKey, fdKey = "client.address", "client.port", "pgbouncer.client_fd"
	}
	attrs = append(attrs, attribute.Int64(fdKey, int64(c.Key.FD)))
	if c.Addr.IsValid() {
		attrs = append(attrs, attribute.String(addrKey, c.Addr.Addr().String()), attribute.Int(portKey, int(c.Addr.Port())))
	}
	for key, attr := range map[string]string{"database": "db.namespace", "user": "db.user", "application_name": "application_name"} {
		if v := c.Params[key]; v != "" {
			attrs = append(attrs, attribute.String(attr, clean(v, 256)))
		}
	}
	start := c.Start
	if start == 0 || start > c.End {
		start = c.End
	}
	e.span(context.Background(), kind, pgwire.Query{Start: start, End: c.End, Operation: "connect",
		ErrorCode: c.Code, ErrorMessage: c.Message}, attrs)
}

// ExportTrace exports a client query as a SERVER span (pgbouncer serving the
// client) with its server queries as CLIENT child spans. Traces without a
// client query export each server query as its own trace.
func (e *Exporter) ExportTrace(t correlate.Trace, reason sampler.Reason, client ClientInfo, server func(event.ConnKey) netip.AddrPort) {
	child := func(ctx context.Context, sq correlate.ServerQuery) {
		attrs := append(e.serverAttrs(Span{Q: sq.Q, PID: sq.Key.PID, FD: sq.Key.FD, Remote: server(sq.Key), Reason: reason}),
			attribute.String("pgtrace.correlation", sq.Correlation),
			attribute.Bool("pgbouncer.internal", sq.Internal))
		e.span(ctx, trace.SpanKindClient, sq.Q, attrs)
	}
	if t.Client == nil {
		for _, sq := range t.Server {
			child(context.Background(), sq)
		}
		return
	}

	q := t.Client.Q
	corr := correlate.None
	if len(t.Server) > 0 {
		corr = t.Server[0].Correlation
	}
	attrs := append(e.queryAttrs(q, reason),
		attribute.Int64("pgbouncer.pid", int64(t.Client.Key.PID)),
		attribute.Int64("pgbouncer.client_fd", int64(t.Client.Key.FD)),
		attribute.String("pgtrace.correlation", corr))
	if client.Addr.IsValid() {
		attrs = append(attrs,
			attribute.String("client.address", client.Addr.Addr().String()),
			attribute.Int("client.port", int(client.Addr.Port())))
	}
	for key, attr := range map[string]string{"database": "db.namespace", "user": "db.user", "application_name": "application_name"} {
		if v := client.Params[key]; v != "" {
			attrs = append(attrs, attribute.String(attr, clean(v, 256)))
		}
	}
	if client.IdleInTx > 0 {
		attrs = append(attrs, attribute.Float64("pgbouncer.idle_in_tx_ms", float64(client.IdleInTx)/1e6))
	}
	// Pool wait ends when pgbouncer first talks to the server it was given,
	// which may be an internal parameter sync before the forwarded query.
	if len(t.Server) > 0 && t.Server[0].Q.Start >= q.Start {
		attrs = append(attrs, attribute.Float64("pgbouncer.pool_wait_ms", float64(t.Server[0].Q.Start-q.Start)/1e6))
	}
	for k, v := range client.Comment.Attrs {
		attrs = append(attrs, attribute.String("sqlcommenter."+k, v))
	}
	ctx := context.Background()
	if client.UseParent {
		if sc, ok := remoteParent(client.Comment); ok {
			ctx = trace.ContextWithRemoteSpanContext(ctx, sc)
			attrs = append(attrs, attribute.String("pgtrace.trace_context", "sqlcommenter"))
		}
	}
	ctx, end := e.start(ctx, trace.SpanKindServer, q, attrs)
	for _, sq := range t.Server {
		child(ctx, sq)
	}
	end()
}

// clean makes wire text safe for OTLP: at most max bytes, cut on a rune
// boundary, and valid UTF-8. Protobuf rejects invalid UTF-8 in string fields,
// which would fail the whole export batch; captured text can be cut mid-rune.
func clean(s string, max int) string {
	if len(s) > max {
		cut := max
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		s = s[:cut]
	}
	return strings.ToValidUTF8(s, "\uFFFD")
}

// Sampled reports whether a valid traceparent has the sampled flag set.
func Sampled(c sqlcomment.Comment) bool {
	if !c.Valid {
		return false
	}
	f, err := strconv.ParseUint(c.TraceParent[len(c.TraceParent)-2:], 16, 8)
	return err == nil && f&1 == 1
}

// remoteParent turns a validated traceparent into the span context of the
// application span the query ran under.
func remoteParent(c sqlcomment.Comment) (trace.SpanContext, bool) {
	if !c.Valid {
		return trace.SpanContext{}, false
	}
	p := strings.Split(c.TraceParent, "-")
	tid, err1 := trace.TraceIDFromHex(p[1])
	sid, err2 := trace.SpanIDFromHex(p[2])
	if err1 != nil || err2 != nil {
		return trace.SpanContext{}, false
	}
	flags := trace.TraceFlags(0)
	if Sampled(c) {
		flags = trace.FlagsSampled
	}
	cfg := trace.SpanContextConfig{TraceID: tid, SpanID: sid, TraceFlags: flags, Remote: true}
	if ts, err := trace.ParseTraceState(c.TraceState); err == nil {
		cfg.TraceState = ts
	}
	return trace.NewSpanContext(cfg), true
}

// queryAttrs are the attributes shared by client and server query spans.
func (e *Exporter) queryAttrs(q pgwire.Query, reason sampler.Reason) []attribute.KeyValue {
	text := clean(q.SQL, e.opts.MaxQueryText)
	if len(q.SQL) > e.opts.MaxQueryText && e.opts.OnTruncate != nil {
		e.opts.OnTruncate()
	}
	attrs := []attribute.KeyValue{
		attribute.String("db.system", "postgresql"),
		attribute.String("db.system.name", "postgresql"),
		attribute.String("db.query.text", text),
		attribute.String("db.operation.name", q.Operation),
		attribute.Int64("db.response.returned_rows", q.Rows),
		attribute.String("pgtrace.protocol", q.Protocol),
		attribute.String("pgtrace.command_tag", clean(q.CommandTag, 256)),
		attribute.Bool("pgtrace.truncated", q.Truncated),
		attribute.String("pgtrace.sample_reason", string(reason)),
	}
	if q.ErrorCode != "" {
		attrs = append(attrs, attribute.String("db.response.status_code", clean(q.ErrorCode, 16)))
	}
	return attrs
}

func (e *Exporter) serverAttrs(s Span) []attribute.KeyValue {
	attrs := append(e.queryAttrs(s.Q, s.Reason),
		attribute.Int64("pgbouncer.pid", int64(s.PID)),
		attribute.Int64("pgbouncer.server_fd", int64(s.FD)))
	if s.Remote.IsValid() {
		attrs = append(attrs,
			attribute.String("server.address", s.Remote.Addr().String()),
			attribute.Int("server.port", int(s.Remote.Port())))
	}
	return attrs
}

// start opens a span for q and returns its context and a func ending it.
func (e *Exporter) start(ctx context.Context, kind trace.SpanKind, q pgwire.Query, attrs []attribute.KeyValue) (context.Context, func()) {
	name := q.Operation
	if name == "" {
		name = "query"
	}
	ctx, span := e.tracer.Start(ctx, name,
		trace.WithSpanKind(kind),
		trace.WithTimestamp(e.wall(q.Start)),
		trace.WithAttributes(attrs...))
	if q.ErrorCode != "" {
		span.SetStatus(codes.Error, clean(q.ErrorMessage, DefaultMaxQueryText))
	}
	return ctx, func() { span.End(trace.WithTimestamp(e.wall(q.End))) }
}

func (e *Exporter) span(ctx context.Context, kind trace.SpanKind, q pgwire.Query, attrs []attribute.KeyValue) {
	_, end := e.start(ctx, kind, q, attrs)
	end()
}

func (e *Exporter) Shutdown(ctx context.Context) error { return e.tp.Shutdown(ctx) }
