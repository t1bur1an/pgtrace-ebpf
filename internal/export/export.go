// Package export turns sampled traces into OpenTelemetry spans and sends them
// over OTLP/HTTP.
//
// The agent's event loop only enqueues kept traces (it never blocks); a pool
// of workers encodes OTLP protobuf directly into reusable buffers and posts
// batches concurrently. Every stage is counted, including traces dropped
// because the queue was full.
package export

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/sys/unix"

	"github.com/t1bur1an/pgtrace-ebpf/internal/correlate"
	"github.com/t1bur1an/pgtrace-ebpf/internal/event"
	"github.com/t1bur1an/pgtrace-ebpf/internal/pgwire"
	"github.com/t1bur1an/pgtrace-ebpf/internal/sampler"
	"github.com/t1bur1an/pgtrace-ebpf/internal/sqlcomment"
)

// DefaultMaxQueryText is the default db.query.text cap in bytes.
const DefaultMaxQueryText = 2048

// Hooks observe the export pipeline (all optional).
type Hooks struct {
	Created  func(n int) // n spans were encoded
	Exported func(n int) // n spans were delivered
	Failed   func(n int) // a batch of n spans failed
	Dropped  func(n int) // n spans were dropped because the queue was full
}

// Config configures an Exporter.
type Config struct {
	Endpoint     string        // OTLP/HTTP traces URL
	Service      string        // service.name
	Workers      int           // concurrent encoders/senders (default 4)
	BatchSpans   int           // spans per request (default 8192)
	QueueTraces  int           // queued traces before dropping (default 65536)
	Interval     time.Duration // flush a partial batch after this (default 1s)
	MaxQueryText int           // db.query.text cap (DefaultMaxQueryText if 0)
	OnTruncate   func()        // db.query.text was shortened
	Hooks        Hooks
	Client       *http.Client // default: keep-alive client with a 10 s timeout

	clock func() (mono, wall int64) // tests
}

// Span is a kept query plus the connection it was seen on.
type Span struct {
	Q      pgwire.Query
	PID    uint32
	FD     int32
	Remote netip.AddrPort
	Reason sampler.Reason
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

type jobKind uint8

const (
	jobTrace jobKind = iota
	jobSpan
	jobConnError
)

type job struct {
	kind    jobKind
	trace   correlate.Trace
	reason  sampler.Reason
	client  ClientInfo
	servers []netip.AddrPort // address of each trace.Server entry
	span    Span
	connErr ConnError
}

func (j *job) spans() int {
	switch j.kind {
	case jobTrace:
		n := len(j.trace.Server)
		if j.trace.Client != nil {
			n++
		}
		return n
	default:
		return 1
	}
}

type Exporter struct {
	cfg    Config
	env    envelope
	offset int64 // wall - monotonic, ns
	jobs   chan *job
	wg     sync.WaitGroup
	mu     sync.RWMutex // held for reading while sending on jobs; Shutdown closes it
	closed bool
}

// New starts the export workers.
func New(cfg Config) (*Exporter, error) {
	if cfg.Endpoint == "" {
		return nil, fmt.Errorf("export: empty endpoint")
	}
	if cfg.Workers <= 0 {
		cfg.Workers = 4
	}
	if cfg.BatchSpans <= 0 {
		cfg.BatchSpans = 8192
	}
	if cfg.QueueTraces <= 0 {
		cfg.QueueTraces = 65536
	}
	if cfg.Interval <= 0 {
		cfg.Interval = time.Second
	}
	if cfg.MaxQueryText <= 0 {
		cfg.MaxQueryText = DefaultMaxQueryText
	}
	if cfg.Client == nil {
		cfg.Client = &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
			MaxIdleConnsPerHost: cfg.Workers, IdleConnTimeout: 90 * time.Second}}
	}
	if cfg.clock == nil {
		cfg.clock = clocks
	}
	mono, wall := cfg.clock()
	e := &Exporter{cfg: cfg, env: newEnvelope(cfg.Service), offset: wall - mono, jobs: make(chan *job, cfg.QueueTraces)}
	for i := 0; i < cfg.Workers; i++ {
		e.wg.Add(1)
		go e.worker(uint64(i))
	}
	return e, nil
}

func clocks() (mono, wall int64) {
	var ts unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	return ts.Nano(), time.Now().UnixNano()
}

// QueueLen is the number of traces waiting for a worker.
func (e *Exporter) QueueLen() int { return len(e.jobs) }

// jobs are recycled so queueing a trace doesn't allocate.
var jobPool = sync.Pool{New: func() any { return new(job) }}

func putJob(j *job) {
	*j = job{servers: j.servers[:0]}
	jobPool.Put(j)
}

func (e *Exporter) enqueue(j *job) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if !e.closed {
		select {
		case e.jobs <- j:
			return
		default:
			if h := e.cfg.Hooks.Dropped; h != nil {
				h(j.spans())
			}
		}
	}
	putJob(j)
}

// Export queues a single server-side span (no client query).
func (e *Exporter) Export(s Span) {
	j := jobPool.Get().(*job)
	j.kind, j.span = jobSpan, s
	e.enqueue(j)
}

// ExportConnError queues a connection error as a "connect" span.
func (e *Exporter) ExportConnError(c ConnError) {
	c.Params = copyParams(c.Params)
	j := jobPool.Get().(*job)
	j.kind, j.connErr = jobConnError, c
	e.enqueue(j)
}

// ExportTrace queues a client query (SERVER span) with its server queries
// (CLIENT children). Traces without a client query export each server query
// as its own trace. server is resolved now, on the caller's goroutine.
func (e *Exporter) ExportTrace(t correlate.Trace, reason sampler.Reason, client ClientInfo, server func(event.ConnKey) netip.AddrPort) {
	j := jobPool.Get().(*job)
	for _, sq := range t.Server {
		j.servers = append(j.servers, server(sq.Key))
	}
	client.Params = copyParams(client.Params)
	j.kind, j.trace, j.reason, j.client = jobTrace, t, reason, client
	e.enqueue(j)
}

func copyParams(p map[string]string) map[string]string {
	if len(p) == 0 {
		return nil
	}
	out := make(map[string]string, len(p))
	for k, v := range p {
		out[k] = v
	}
	return out
}

// Shutdown stops accepting work, lets the workers send what is queued and
// waits for them (or ctx).
func (e *Exporter) Shutdown(ctx context.Context) error {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return nil
	}
	e.closed = true
	close(e.jobs)
	e.mu.Unlock()
	done := make(chan struct{})
	go func() { e.wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// worker encodes jobs into batches and sends them.
type worker struct {
	e     *Exporter
	rng   *rand.Rand
	spans []byte // encoded spans of the current batch
	n     int    // spans in the batch
	a     attrs
	req   []byte
}

func (e *Exporter) worker(id uint64) {
	defer e.wg.Done()
	w := &worker{e: e, rng: rand.New(rand.NewPCG(uint64(time.Now().UnixNano()), id))}
	tick := time.NewTicker(e.cfg.Interval)
	defer tick.Stop()
	for {
		select {
		case j, ok := <-e.jobs:
			if !ok {
				w.flush()
				return
			}
			w.encode(j)
			putJob(j)
			if w.n >= e.cfg.BatchSpans {
				w.flush()
			}
		case <-tick.C:
			w.flush()
		}
	}
}

func (w *worker) flush() {
	if w.n == 0 {
		return
	}
	n := w.n
	w.req = w.e.env.request(w.req, w.spans)
	w.spans, w.n = w.spans[:0], 0
	h := w.e.cfg.Hooks
	if err := w.post(); err != nil {
		if h.Failed != nil {
			h.Failed(n)
		}
		return
	}
	if h.Exported != nil {
		h.Exported(n)
	}
}

func (w *worker) post() error {
	req, err := http.NewRequest(http.MethodPost, w.e.cfg.Endpoint, bytes.NewReader(w.req))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-protobuf")
	resp, err := w.e.cfg.Client.Do(req)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("otlp export: HTTP %d", resp.StatusCode)
	}
	return nil
}

func (w *worker) ids() (t [16]byte, s [8]byte) {
	for i := 0; i < 16; i += 8 {
		putU64(t[i:], w.rng.Uint64())
	}
	for {
		putU64(s[:], w.rng.Uint64())
		if s != ([8]byte{}) {
			return
		}
	}
}

func (w *worker) spanID() (s [8]byte) {
	_, s = w.ids()
	return
}

func newRNG() *rand.Rand { return rand.New(rand.NewPCG(uint64(time.Now().UnixNano()), 0)) }

func putU64(b []byte, v uint64) {
	for i := 0; i < 8; i++ {
		b[i] = byte(v >> (56 - 8*i))
	}
}

func (w *worker) wall(mono uint64) uint64 { return uint64(int64(mono) + w.e.offset) }

func (w *worker) add(s *spanData) {
	w.spans = appendSpan(w.spans, s)
	w.n++
	if h := w.e.cfg.Hooks.Created; h != nil {
		h(1)
	}
}

func (w *worker) encode(j *job) {
	switch j.kind {
	case jobSpan:
		tid, sid := w.ids()
		w.serverSpan(tid, sid, [8]byte{}, j.span, "", false, false)
	case jobConnError:
		w.connError(&j.connErr)
	case jobTrace:
		w.trace(j)
	}
}

func (w *worker) trace(j *job) {
	t := j.trace
	child := func(tid [16]byte, parent [8]byte, i int) {
		sq := t.Server[i]
		w.serverSpan(tid, w.spanID(), parent,
			Span{Q: sq.Q, PID: sq.Key.PID, FD: sq.Key.FD, Remote: j.servers[i], Reason: j.reason},
			sq.Correlation, sq.Internal, true)
	}
	if t.Client == nil {
		for i := range t.Server {
			tid, _ := w.ids()
			child(tid, [8]byte{}, i)
		}
		return
	}
	q := t.Client.Q
	tid, root := w.ids()
	var parent [8]byte
	var traceState string
	remote := false
	if j.client.UseParent {
		if ptid, psid, ok := parseTraceparent(j.client.Comment.TraceParent); ok && j.client.Comment.Valid {
			tid, parent, traceState, remote = ptid, psid, j.client.Comment.TraceState, true
		}
	}
	corr := correlate.None
	if len(t.Server) > 0 {
		corr = t.Server[0].Correlation
	}
	a := &w.a
	a.b = a.b[:0]
	w.queryAttrs(q, j.reason)
	a.i64("pgbouncer.pid", int64(t.Client.Key.PID))
	a.i64("pgbouncer.client_fd", int64(t.Client.Key.FD))
	a.str("pgtrace.correlation", corr)
	if j.client.Addr.IsValid() {
		a.str("client.address", j.client.Addr.Addr().String())
		a.i64("client.port", int64(j.client.Addr.Port()))
	}
	w.clientParams(j.client.Params)
	if j.client.IdleInTx > 0 {
		a.f64("pgbouncer.idle_in_tx_ms", float64(j.client.IdleInTx)/1e6)
	}
	// Pool wait ends when pgbouncer first talks to the server it was given,
	// which may be an internal parameter sync before the forwarded query.
	if len(t.Server) > 0 && t.Server[0].Q.Start >= q.Start {
		a.f64("pgbouncer.pool_wait_ms", float64(t.Server[0].Q.Start-q.Start)/1e6)
	}
	for k, v := range j.client.Comment.Attrs {
		a.str("sqlcommenter."+k, v)
	}
	if remote {
		a.str("pgtrace.trace_context", "sqlcommenter")
	}
	w.add(&spanData{traceID: tid, spanID: root, parentID: parent, traceState: traceState,
		name: spanName(q), kind: kindServer, start: w.wall(q.Start), end: w.wall(q.End),
		attrs: a.b, failed: q.ErrorCode != "", errMsg: clean(q.ErrorMessage, DefaultMaxQueryText)})
	for i := range t.Server {
		child(tid, root, i)
	}
}

func (w *worker) serverSpan(tid [16]byte, sid, parent [8]byte, s Span, correlation string, internal, correlated bool) {
	a := &w.a
	a.b = a.b[:0]
	w.queryAttrs(s.Q, s.Reason)
	a.i64("pgbouncer.pid", int64(s.PID))
	a.i64("pgbouncer.server_fd", int64(s.FD))
	if s.Remote.IsValid() {
		a.str("server.address", s.Remote.Addr().String())
		a.i64("server.port", int64(s.Remote.Port()))
	}
	if correlated {
		a.str("pgtrace.correlation", correlation)
		a.boolean("pgbouncer.internal", internal)
	}
	w.add(&spanData{traceID: tid, spanID: sid, parentID: parent, name: spanName(s.Q), kind: kindClient,
		start: w.wall(s.Q.Start), end: w.wall(s.Q.End), attrs: a.b,
		failed: s.Q.ErrorCode != "", errMsg: clean(s.Q.ErrorMessage, DefaultMaxQueryText)})
}

func (w *worker) connError(c *ConnError) {
	a := &w.a
	a.b = a.b[:0]
	a.str("db.system", "postgresql")
	a.str("db.system.name", "postgresql")
	a.boolean("pgtrace.connection_error", true)
	a.str("db.response.status_code", clean(c.Code, 16))
	a.i64("pgbouncer.pid", int64(c.Key.PID))
	a.str("pgtrace.sample_reason", string(sampler.ReasonError))
	kind, addrKey, portKey, fdKey := uint64(kindClient), "server.address", "server.port", "pgbouncer.server_fd"
	if c.Client {
		kind, addrKey, portKey, fdKey = kindServer, "client.address", "client.port", "pgbouncer.client_fd"
	}
	a.i64(fdKey, int64(c.Key.FD))
	if c.Addr.IsValid() {
		a.str(addrKey, c.Addr.Addr().String())
		a.i64(portKey, int64(c.Addr.Port()))
	}
	w.clientParams(c.Params)
	start := c.Start
	if start == 0 || start > c.End {
		start = c.End
	}
	tid, sid := w.ids()
	w.add(&spanData{traceID: tid, spanID: sid, name: "connect", kind: kind, start: w.wall(start), end: w.wall(c.End),
		attrs: a.b, failed: true, errMsg: clean(c.Message, DefaultMaxQueryText)})
}

func (w *worker) clientParams(p map[string]string) {
	for _, pa := range [...][2]string{{"database", "db.namespace"}, {"user", "db.user"}, {"application_name", "application_name"}} {
		if v := p[pa[0]]; v != "" {
			w.a.str(pa[1], clean(v, 256))
		}
	}
}

// queryAttrs appends the attributes shared by client and server query spans.
func (w *worker) queryAttrs(q pgwire.Query, reason sampler.Reason) {
	max := w.e.cfg.MaxQueryText
	if len(q.SQL) > max && w.e.cfg.OnTruncate != nil {
		w.e.cfg.OnTruncate()
	}
	a := &w.a
	a.str("db.system", "postgresql")
	a.str("db.system.name", "postgresql")
	a.str("db.query.text", clean(q.SQL, max))
	a.str("db.operation.name", q.Operation)
	a.i64("db.response.returned_rows", q.Rows)
	a.str("pgtrace.protocol", q.Protocol)
	a.str("pgtrace.command_tag", clean(q.CommandTag, 256))
	a.boolean("pgtrace.truncated", q.Truncated)
	a.str("pgtrace.sample_reason", string(reason))
	if q.ErrorCode != "" {
		a.str("db.response.status_code", clean(q.ErrorCode, 16))
	}
}

func spanName(q pgwire.Query) string {
	if q.Operation == "" {
		return "query"
	}
	return q.Operation
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
	return strings.ToValidUTF8(s, "�")
}

// Sampled reports whether a valid traceparent has the sampled flag set.
func Sampled(c sqlcomment.Comment) bool {
	if !c.Valid {
		return false
	}
	f, err := strconv.ParseUint(c.TraceParent[len(c.TraceParent)-2:], 16, 8)
	return err == nil && f&1 == 1
}
