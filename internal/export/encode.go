package export

import (
	"encoding/hex"
	"math"
	"strings"

	"google.golang.org/protobuf/encoding/protowire"
)

// OTLP protobuf field numbers (opentelemetry-proto, trace/v1 and common/v1).
const (
	fReqResourceSpans = 1 // ExportTraceServiceRequest.resource_spans

	fRSResource   = 1 // ResourceSpans.resource
	fRSScopeSpans = 2 // ResourceSpans.scope_spans
	fResAttrs     = 1 // Resource.attributes
	fSSScope      = 1 // ScopeSpans.scope
	fSSSpans      = 2 // ScopeSpans.spans
	fScopeName    = 1 // InstrumentationScope.name

	fSpanTraceID    = 1
	fSpanSpanID     = 2
	fSpanTraceState = 3
	fSpanParentID   = 4
	fSpanName       = 5
	fSpanKind       = 6
	fSpanStart      = 7
	fSpanEnd        = 8
	fSpanAttrs      = 9
	fSpanStatus     = 15

	fStatusMessage = 2
	fStatusCode    = 3

	fKVKey   = 1
	fKVValue = 2

	fAnyString = 1
	fAnyBool   = 2
	fAnyInt    = 3
	fAnyDouble = 4

	kindServer      = 2 // SPAN_KIND_SERVER
	kindClient      = 3 // SPAN_KIND_CLIENT
	statusCodeError = 2 // STATUS_CODE_ERROR

	scopeName = "github.com/t1bur1an/pgtrace-ebpf"
)

// Sizes are computed up front so nested messages are written in one pass
// without temporary buffers.

func sizeField(num protowire.Number, n int) int {
	return protowire.SizeTag(num) + protowire.SizeBytes(n)
}

func appendMsgHeader(b []byte, num protowire.Number, n int) []byte {
	b = protowire.AppendTag(b, num, protowire.BytesType)
	return protowire.AppendVarint(b, uint64(n))
}

// kv appends one KeyValue attribute (field num) whose AnyValue body has size
// anyLen and is written by value.
func kv(b []byte, num protowire.Number, key string, anyLen int, value func([]byte) []byte) []byte {
	kvLen := sizeField(fKVKey, len(key)) + sizeField(fKVValue, anyLen)
	b = appendMsgHeader(b, num, kvLen)
	b = protowire.AppendTag(b, fKVKey, protowire.BytesType)
	b = protowire.AppendString(b, key)
	b = appendMsgHeader(b, fKVValue, anyLen)
	return value(b)
}

func kvString(b []byte, num protowire.Number, key, v string) []byte {
	return kv(b, num, key, sizeField(fAnyString, len(v)), func(b []byte) []byte {
		b = protowire.AppendTag(b, fAnyString, protowire.BytesType)
		return protowire.AppendString(b, v)
	})
}

func kvInt(b []byte, key string, v int64) []byte {
	n := protowire.SizeTag(fAnyInt) + protowire.SizeVarint(uint64(v))
	return kv(b, fSpanAttrs, key, n, func(b []byte) []byte {
		b = protowire.AppendTag(b, fAnyInt, protowire.VarintType)
		return protowire.AppendVarint(b, uint64(v))
	})
}

func kvFloat(b []byte, key string, v float64) []byte {
	n := protowire.SizeTag(fAnyDouble) + 8
	return kv(b, fSpanAttrs, key, n, func(b []byte) []byte {
		b = protowire.AppendTag(b, fAnyDouble, protowire.Fixed64Type)
		return protowire.AppendFixed64(b, math.Float64bits(v))
	})
}

func kvBool(b []byte, key string, v bool) []byte {
	x := uint64(0)
	if v {
		x = 1
	}
	return kv(b, fSpanAttrs, key, protowire.SizeTag(fAnyBool)+1, func(b []byte) []byte {
		b = protowire.AppendTag(b, fAnyBool, protowire.VarintType)
		return protowire.AppendVarint(b, x)
	})
}

// attrs builds a span's attribute list into a reusable buffer.
type attrs struct{ b []byte }

func (a *attrs) str(k, v string)       { a.b = kvString(a.b, fSpanAttrs, k, v) }
func (a *attrs) i64(k string, v int64) { a.b = kvInt(a.b, k, v) }
func (a *attrs) f64(k string, v float64) {
	a.b = kvFloat(a.b, k, v)
}
func (a *attrs) boolean(k string, v bool) { a.b = kvBool(a.b, k, v) }

// spanData is everything encoded for one span.
type spanData struct {
	traceID    [16]byte
	spanID     [8]byte
	parentID   [8]byte // zero: no parent
	traceState string
	name       string
	kind       uint64
	start, end uint64 // unix ns
	attrs      []byte // encoded attribute fields
	errMsg     string
	failed     bool
}

// appendSpan appends one Span message as ScopeSpans.spans (field 2).
func appendSpan(b []byte, s *spanData) []byte {
	var zero [8]byte
	n := sizeField(fSpanTraceID, 16) + sizeField(fSpanSpanID, 8) +
		sizeField(fSpanName, len(s.name)) +
		protowire.SizeTag(fSpanKind) + protowire.SizeVarint(s.kind) +
		protowire.SizeTag(fSpanStart) + 8 + protowire.SizeTag(fSpanEnd) + 8 +
		len(s.attrs)
	if s.parentID != zero {
		n += sizeField(fSpanParentID, 8)
	}
	if s.traceState != "" {
		n += sizeField(fSpanTraceState, len(s.traceState))
	}
	var statusLen int
	if s.failed {
		statusLen = sizeField(fStatusMessage, len(s.errMsg)) + protowire.SizeTag(fStatusCode) + 1
		n += sizeField(fSpanStatus, statusLen)
	}
	b = appendMsgHeader(b, fSSSpans, n)
	b = protowire.AppendTag(b, fSpanTraceID, protowire.BytesType)
	b = protowire.AppendBytes(b, s.traceID[:])
	b = protowire.AppendTag(b, fSpanSpanID, protowire.BytesType)
	b = protowire.AppendBytes(b, s.spanID[:])
	if s.traceState != "" {
		b = protowire.AppendTag(b, fSpanTraceState, protowire.BytesType)
		b = protowire.AppendString(b, s.traceState)
	}
	if s.parentID != zero {
		b = protowire.AppendTag(b, fSpanParentID, protowire.BytesType)
		b = protowire.AppendBytes(b, s.parentID[:])
	}
	b = protowire.AppendTag(b, fSpanName, protowire.BytesType)
	b = protowire.AppendString(b, s.name)
	b = protowire.AppendTag(b, fSpanKind, protowire.VarintType)
	b = protowire.AppendVarint(b, s.kind)
	b = protowire.AppendTag(b, fSpanStart, protowire.Fixed64Type)
	b = protowire.AppendFixed64(b, s.start)
	b = protowire.AppendTag(b, fSpanEnd, protowire.Fixed64Type)
	b = protowire.AppendFixed64(b, s.end)
	b = append(b, s.attrs...)
	if s.failed {
		b = appendMsgHeader(b, fSpanStatus, statusLen)
		b = protowire.AppendTag(b, fStatusMessage, protowire.BytesType)
		b = protowire.AppendString(b, s.errMsg)
		b = protowire.AppendTag(b, fStatusCode, protowire.VarintType)
		b = protowire.AppendVarint(b, statusCodeError)
	}
	return b
}

// envelope holds the parts of a request that are the same for every batch.
type envelope struct {
	resource []byte // ResourceSpans.resource field, complete
	scope    []byte // ScopeSpans.scope field, complete
}

func newEnvelope(service string) envelope {
	resBody := kvString(nil, fResAttrs, "service.name", service)
	scopeBody := protowire.AppendString(protowire.AppendTag(nil, fScopeName, protowire.BytesType), scopeName)
	return envelope{
		resource: append(appendMsgHeader(nil, fRSResource, len(resBody)), resBody...),
		scope:    append(appendMsgHeader(nil, fSSScope, len(scopeBody)), scopeBody...),
	}
}

// request writes an ExportTraceServiceRequest around the encoded spans.
func (e envelope) request(dst, spans []byte) []byte {
	ss := len(e.scope) + len(spans)
	rs := len(e.resource) + sizeField(fRSScopeSpans, ss)
	dst = appendMsgHeader(dst[:0], fReqResourceSpans, rs)
	dst = append(dst, e.resource...)
	dst = appendMsgHeader(dst, fRSScopeSpans, ss)
	dst = append(dst, e.scope...)
	return append(dst, spans...)
}

// parseTraceparent returns the trace and parent span IDs of a validated
// W3C traceparent ("00-<32 hex>-<16 hex>-<2 hex>").
func parseTraceparent(tp string) (tid [16]byte, sid [8]byte, ok bool) {
	p := strings.Split(tp, "-")
	if len(p) != 4 {
		return tid, sid, false
	}
	if _, err := hex.Decode(tid[:], []byte(p[1])); err != nil {
		return tid, sid, false
	}
	if _, err := hex.Decode(sid[:], []byte(p[2])); err != nil {
		return tid, sid, false
	}
	return tid, sid, true
}
