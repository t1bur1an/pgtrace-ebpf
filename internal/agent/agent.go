// Package agent routes captured events through the wire parsers and the
// correlator, producing one trace per client query.
package agent

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"

	"github.com/t1bur1an/pgtrace-ebpf/internal/connmap"
	"github.com/t1bur1an/pgtrace-ebpf/internal/correlate"
	"github.com/t1bur1an/pgtrace-ebpf/internal/event"
	"github.com/t1bur1an/pgtrace-ebpf/internal/export"
	"github.com/t1bur1an/pgtrace-ebpf/internal/metrics"
	"github.com/t1bur1an/pgtrace-ebpf/internal/pgwire"
)

// HoldTimeout bounds how long a finished server query waits for its client
// query to complete before it is exported as an orphan.
const HoldTimeout = 30 * time.Second

type Stats struct {
	Events  uint64 // events received
	Queries uint64 // queries parsed on either side, before sampling
	Server  uint64 // server connections currently tracked
	Client  uint64 // client connections currently tracked

	ServerTLS, ClientTLS uint64 // …of which use TLS
}

// Filter lets the agent tell the kernel which fds need no payload capture.
type Filter interface {
	Ignore(event.ConnKey) // neither client nor server: stop capturing
	Clear(event.ConnKey)  // unknown again (connect/accept/close)
}

// Sink receives every trace, before sampling, with the root's client details.
type Sink func(correlate.Trace, export.ClientInfo)

type conn struct {
	side  connmap.Side
	p     *pgwire.Conn
	addr  netip.AddrPort
	start uint64 // accept/connect time, or first data

	inTxSince uint64                   // end of the last query that left a transaction open
	idle      map[uint64]time.Duration // client query id → idle-in-transaction gap before it
	recent    []recorded               // flight recorder ring (DumpDir only)
	recentPos int

	nextSeq [2]uint32 // expected TCP stream offset per direction
	haveSeq [2]bool

	tls                   bool // negotiated TLS ('S' answer, or TLS events)
	tlsVersion, tlsCipher string
}

type recorded struct {
	ts       uint64
	dir      event.Dir
	total    uint32
	captured int // bytes the kernel copied (may be < total)
	seq      uint32
	hasSeq   bool
	head     []byte
}

const recorderEvents, recorderBytes = 64, 1024

// TLSFallback is told when TLS plaintext arrives for a session whose socket
// isn't known yet, so the capture can attach its socket-finding fallback.
type TLSFallback interface{ TLSNeedFallback() }

type Agent struct {
	Filter  Filter           // optional
	Metrics *metrics.Metrics // optional: event counts, truncations
	Parser  pgwire.Options   // per-connection parser options
	// OnConnError receives errors that arrive with no query in flight.
	OnConnError func(export.ConnError)
	// Fallback, if set, is told about TLS events without a socket.
	Fallback TLSFallback
	// DumpDir enables the flight recorder: the last events of every
	// connection are kept, and the first orphaned query of a server
	// connection dumps both connections' history there (diagnostics).
	DumpDir string
	dumps   map[string]int

	cm     *connmap.Map
	sink   Sink
	cor    *correlate.Correlator
	conns  map[event.ConnKey]*conn
	opened map[event.ConnKey]uint64 // accept/connect time of sockets without data yet

	held       map[uint32]event.Data           // pid → SSL_write event waiting for its socket
	tlsPending map[event.ConnKey]event.TLSAttr // version/cipher that arrived before the connection's first data

	events, queries, nserver, nclient atomic.Uint64
	nserverTLS, nclientTLS            atomic.Uint64
}

func New(cm *connmap.Map, sink Sink) *Agent {
	a := &Agent{cm: cm, sink: sink, conns: map[event.ConnKey]*conn{}, opened: map[event.ConnKey]uint64{},
		held: map[uint32]event.Data{}, tlsPending: map[event.ConnKey]event.TLSAttr{}}
	a.cor = correlate.New(a.emit, HoldTimeout)
	return a
}

func (a *Agent) emit(tr correlate.Trace) {
	if a.DumpDir != "" && tr.Client == nil {
		for _, sq := range tr.Server {
			if sq.Correlation != correlate.None {
				a.dumpOrphan(sq)
			}
		}
	}
	info := export.ClientInfo{}
	if tr.Client != nil {
		if c := a.conns[tr.Client.Key]; c != nil {
			info = export.ClientInfo{Addr: c.addr, Params: c.p.Params(), IdleInTx: c.idle[tr.Client.Q.ID], TLS: c.tlsInfo()}
			delete(c.idle, tr.Client.Q.ID)
		}
	}
	a.sink(tr, info)
}

// Run processes events until the channel closes or ctx is done. It must be
// called from a single goroutine.
func (a *Agent) Run(ctx context.Context, events <-chan any) {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			a.cor.Tick(monotonic())
			if a.Metrics != nil {
				a.Metrics.SetCorrelatorEntries(a.cor.Entries())
			}
		case ev, ok := <-events:
			if !ok {
				return
			}
			a.handle(ev)
		}
	}
}

func monotonic() uint64 {
	var ts unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	return uint64(ts.Nano())
}

func (a *Agent) event(kind string) {
	a.events.Add(1)
	if a.Metrics != nil {
		a.Metrics.Event(kind)
	}
}

func (a *Agent) handle(ev any) {
	if len(a.held) > 0 {
		a.settle(ev)
	}
	switch ev := ev.(type) {
	case event.Connect:
		a.event("connect")
		a.drop(ev.Key)
		a.cm.OnConnect(ev.Key, ev.Addr)
		a.opened[ev.Key] = ev.TS
		a.classified(ev.Key)
	case event.Accept:
		a.event("accept")
		a.drop(ev.Key)
		a.cm.OnAccept(ev.Key, ev.Addr)
		a.opened[ev.Key] = ev.TS
		a.classified(ev.Key)
	case event.Close:
		a.event("close")
		if c := a.conns[ev.Key]; c != nil && c.inTxSince > 0 && ev.TS > c.inTxSince && a.Metrics != nil {
			a.Metrics.IdleInTransaction(time.Duration(ev.TS - c.inTxSince)) // closed while holding a transaction
		}
		delete(a.opened, ev.Key)
		delete(a.tlsPending, ev.Key)
		a.drop(ev.Key)
		a.cm.OnClose(ev.Key)
		// Also undoes an Ignore issued for this fd number by data events that
		// were still queued when the kernel saw the close.
		a.clear(ev.Key)
	case event.Data:
		a.event("data")
		if ev.TLS && ev.Key.FD < 0 {
			a.unresolved(ev)
			return
		}
		a.data(ev)
	case event.TLSFD:
		a.events.Add(1) // only matters to a held event; settle handled it
	case event.TLSAttr:
		a.events.Add(1)
		a.tlsAttr(ev)
	}
}

func pidOf(ev any) (uint32, bool) {
	switch ev := ev.(type) {
	case event.Data:
		return ev.Key.PID, true
	case event.Connect:
		return ev.Key.PID, true
	case event.Accept:
		return ev.Key.PID, true
	case event.Close:
		return ev.Key.PID, true
	case event.TLSFD:
		return ev.Key.PID, true
	case event.TLSAttr:
		return ev.Key.PID, true
	}
	return 0, false
}

// settle feeds or drops the held SSL_write event of ev's process. Only the
// socket mapping from the same SSL_write call may follow it: pgbouncer is
// single-threaded, so anything else means the mapping isn't coming, and
// feeding the event later would reorder it against other connections.
func (a *Agent) settle(ev any) {
	pid, ok := pidOf(ev)
	if !ok {
		return
	}
	h, ok := a.held[pid]
	if !ok {
		return
	}
	delete(a.held, pid)
	if m, ok := ev.(event.TLSFD); ok && m.Session == h.Session {
		h.Key.FD, h.Session = m.Key.FD, 0
		a.tlsUnresolved("resolved")
		a.data(h)
		return
	}
	a.tlsUnresolved("dropped")
}

// unresolved handles TLS plaintext captured before its socket was known.
func (a *Agent) unresolved(ev event.Data) {
	if a.Fallback != nil {
		a.Fallback.TLSNeedFallback()
	}
	if ev.Dir != event.DirSend {
		// SSL_read: its ciphertext read already happened; the next call on
		// the session will be mapped.
		a.tlsUnresolved("dropped")
		return
	}
	a.held[ev.Key.PID] = ev
}

func (a *Agent) tlsUnresolved(result string) {
	if a.Metrics != nil {
		a.Metrics.TLSUnresolved(result)
	}
}

// tlsAttr records a session's TLS version or cipher.
func (a *Agent) tlsAttr(ev event.TLSAttr) {
	if ev.Key.FD < 0 {
		return
	}
	if c := a.conns[ev.Key]; c != nil {
		c.setTLSAttr(ev)
		a.markTLS(c)
		return
	}
	p := a.tlsPending[ev.Key]
	if ev.Version != "" {
		p.Version = ev.Version
	}
	if ev.Cipher != "" {
		p.Cipher = ev.Cipher
	}
	a.tlsPending[ev.Key] = p
}

func (c *conn) setTLSAttr(ev event.TLSAttr) {
	if ev.Version != "" {
		c.tlsVersion = tlsVersion(ev.Version)
	}
	if ev.Cipher != "" {
		c.tlsCipher = ev.Cipher
	}
}

// tlsVersion turns OpenSSL's version name into the OpenTelemetry value:
// "TLSv1.3" → "1.3", "TLSv1" → "1.0".
func tlsVersion(s string) string {
	v, ok := strings.CutPrefix(s, "TLSv")
	if !ok {
		return s
	}
	if v == "1" {
		return "1.0"
	}
	return v
}

func (c *conn) tlsInfo() export.TLSInfo {
	if !c.tls {
		return export.TLSInfo{}
	}
	return export.TLSInfo{On: true, Version: c.tlsVersion, Cipher: c.tlsCipher}
}

// markTLS records that a connection uses TLS.
func (a *Agent) markTLS(c *conn) {
	if c.tls {
		return
	}
	c.tls = true
	a.countTLS(c.side, 1)
}

// TLSInfo returns a tracked connection's TLS. Call it from the Run
// goroutine, e.g. inside the sink.
func (a *Agent) TLSInfo(k event.ConnKey) export.TLSInfo {
	if c := a.conns[k]; c != nil {
		return c.tlsInfo()
	}
	return export.TLSInfo{}
}

func (a *Agent) countTLS(side connmap.Side, delta int64) {
	switch side {
	case connmap.SideServer:
		a.nserverTLS.Add(uint64(delta))
	case connmap.SideClient:
		a.nclientTLS.Add(uint64(delta))
	}
}

// classified tells the kernel whether to keep capturing a new socket.
func (a *Agent) classified(k event.ConnKey) {
	if a.cm.Lookup(k).Side == connmap.SideNone {
		a.ignore(k)
	} else {
		a.clear(k)
	}
}

// drop forgets a connection's parser and correlation state.
func (a *Agent) drop(k event.ConnKey) {
	c := a.conns[k]
	if c == nil {
		return
	}
	switch c.side {
	case connmap.SideClient:
		// Queries that failed without a ReadyForQuery (pgbouncer errors
		// followed by a disconnect) complete now.
		for _, q := range c.p.Close() {
			a.queries.Add(1)
			a.cor.ClientDone(k, q)
		}
		a.cor.ClientClosed(k)
	case connmap.SideServer:
		a.cor.ServerClosed(k)
	}
	if c.tls {
		a.countTLS(c.side, -1)
	}
	delete(a.conns, k)
	a.count(c.side, -1)
}

func (a *Agent) data(ev event.Data) {
	c := a.conns[ev.Key]
	if c == nil {
		info := a.cm.Lookup(ev.Key)
		switch info.Side {
		case connmap.SideServer:
			c = &conn{side: info.Side, p: pgwire.NewConnWith(false, a.Parser), addr: info.Remote}
		case connmap.SideClient:
			c = &conn{side: info.Side, p: pgwire.NewConnWith(true, a.Parser), addr: info.Remote}
		default:
			a.ignore(ev.Key)
			return
		}
		c.start = ev.TS
		if t, ok := a.opened[ev.Key]; ok {
			c.start = t
			delete(a.opened, ev.Key)
		}
		c.idle = map[uint64]time.Duration{}
		a.conns[ev.Key] = c
		a.count(c.side, 1)
		if p, ok := a.tlsPending[ev.Key]; ok {
			c.setTLSAttr(p)
			a.markTLS(c)
			delete(a.tlsPending, ev.Key)
		}
	}
	if ev.TLS {
		a.markTLS(c)
	}
	if a.DumpDir != "" {
		r := recorded{ts: ev.TS, dir: ev.Dir, total: ev.TotalLen, captured: len(ev.Payload), seq: ev.Seq, hasSeq: ev.HasSeq, head: append([]byte(nil), ev.Payload[:min(len(ev.Payload), recorderBytes)]...)}
		if len(c.recent) < recorderEvents {
			c.recent = append(c.recent, r)
		} else {
			c.recent[c.recentPos] = r
			c.recentPos = (c.recentPos + 1) % recorderEvents
		}
	}
	pid := ev.Key.PID
	a.cor.Event(pid)
	if c.side == connmap.SideClient && ev.Dir == event.DirRecv {
		a.cor.ClientRecv(pid, ev.Key, ev.TS)
	}
	side := map[connmap.Side]string{connmap.SideServer: "server", connmap.SideClient: "client"}[c.side]
	// A jump in the TCP stream offset means the kernel skipped capture
	// events (e.g. fentry/fexit recursion protection): skip those bytes.
	if ev.HasSeq && ev.Dir <= event.DirRecv {
		d := ev.Dir
		if gap := ev.Seq - c.nextSeq[d]; c.haveSeq[d] && gap != 0 && gap < 1<<31 {
			if a.Metrics != nil {
				a.Metrics.CaptureGap(side, int(gap))
			}
			a.process(ev, c, pid, side, c.p.Skip(d, ev.TS, int(gap)))
		}
		c.nextSeq[d], c.haveSeq[d] = ev.Seq+ev.TotalLen, true
	}
	a.process(ev, c, pid, side, c.p.Feed(ev.Dir, ev.TS, ev.Payload, ev.TotalLen))
	if !c.tls && c.p.TLS() {
		a.markTLS(c) // the server accepted an SSLRequest
	}
}

// process hands one parser result to the correlator and metrics.
func (a *Agent) process(ev event.Data, c *conn, pid uint32, side string, r pgwire.Result) {
	if a.Metrics != nil {
		if uint32(len(ev.Payload)) < ev.TotalLen {
			a.Metrics.Truncation("kernel")
		}
		for i := 0; i < r.Truncated; i++ {
			a.Metrics.Truncation("parser")
		}
		if r.Resynced {
			a.Metrics.ParserResync(side)
		}
	}
	if r.Resynced && a.DumpDir != "" {
		a.dump(fmt.Sprintf("resync: %v (%s) parser lost its place", ev.Key, c.side), "resync", ev.Key)
	}
	for _, st := range r.Started {
		if c.side == connmap.SideServer {
			a.cor.ServerStarted(pid, ev.Key, st)
			continue
		}
		if c.inTxSince > 0 && st.TS > c.inTxSince {
			gap := time.Duration(st.TS - c.inTxSince)
			c.idle[st.ID] = gap
			if a.Metrics != nil {
				a.Metrics.IdleInTransaction(gap)
			}
		}
		c.inTxSince = 0
		a.cor.ClientStarted(pid, ev.Key, st)
	}
	for _, q := range r.Done {
		a.queries.Add(1)
		if c.side == connmap.SideServer {
			a.cor.ServerDone(ev.Key, q)
			continue
		}
		if q.TxStatus == 'T' || q.TxStatus == 'E' {
			c.inTxSince = q.End
		} else {
			c.inTxSince = 0
		}
		a.cor.ClientDone(ev.Key, q)
	}
	for _, ce := range r.ConnErrors {
		if a.Metrics != nil {
			a.Metrics.ConnectionError(side, ce.Code)
		}
		if a.OnConnError != nil {
			a.OnConnError(export.ConnError{Client: c.side == connmap.SideClient, Key: ev.Key, Start: c.start, End: ce.TS,
				Code: ce.Code, Message: ce.Message, Addr: c.addr, Params: c.p.Params(), TLS: c.tlsInfo()})
		}
	}
}

// count adjusts the per-side connection gauges.
func (a *Agent) count(side connmap.Side, delta int64) {
	switch side {
	case connmap.SideServer:
		a.nserver.Add(uint64(delta))
	case connmap.SideClient:
		a.nclient.Add(uint64(delta))
	}
}

func (a *Agent) ignore(k event.ConnKey) {
	if a.Filter != nil {
		a.Filter.Ignore(k)
	}
}

func (a *Agent) clear(k event.ConnKey) {
	if a.Filter != nil {
		a.Filter.Clear(k)
	}
}

func (a *Agent) Stats() Stats {
	return Stats{Events: a.events.Load(), Queries: a.queries.Load(), Server: a.nserver.Load(), Client: a.nclient.Load(),
		ServerTLS: a.nserverTLS.Load(), ClientTLS: a.nclientTLS.Load()}
}

// SetAttachParamSync toggles attaching pgbouncer's parameter-sync statements
// to the client query they were issued for. Call before Run.
func (a *Agent) SetAttachParamSync(on bool) { a.cor.AttachParamSync = on }

// CorrelationStats returns the correlator's counters.
func (a *Agent) CorrelationStats() map[string]uint64 { return a.cor.Stats() }

// dumpOrphan writes the flight recorder of an orphaned query's server and
// client connections, once per server connection.
func (a *Agent) dumpOrphan(sq correlate.ServerQuery) {
	head := fmt.Sprintf("orphan: server %v query q%d %q start=%d end=%d tx=%q attributed to client %v (%s)\n\n%s",
		sq.Key, sq.Q.ID, trunc(sq.Q.SQL, 80), sq.Q.Start, sq.Q.End, sq.Q.TxStatus, sq.Client, sq.Correlation,
		a.cor.Debug(sq.Key, sq.Client))
	a.dump(head, "orphan", sq.Key, sq.Client)
}

// dump writes the recent events and parser state of the given connections,
// once per first connection and kind, at most 20 files per kind.
func (a *Agent) dump(head, kind string, keys ...event.ConnKey) {
	if a.dumps == nil {
		a.dumps = map[string]int{}
	}
	id := fmt.Sprint(kind, keys[0])
	if a.dumps[id] > 0 || a.dumps[kind] >= 20 {
		return
	}
	a.dumps[id]++
	a.dumps[kind]++
	var b strings.Builder
	b.WriteString(head)
	b.WriteString("\n")
	for _, k := range keys {
		c := a.conns[k]
		if c == nil {
			fmt.Fprintf(&b, "\n== %v: no parser state\n", k)
			continue
		}
		fmt.Fprintf(&b, "\n== %v (%s) parser: %s", k, c.side, c.p.DebugState())
		n := len(c.recent)
		for i := 0; i < n; i++ {
			r := c.recent[(c.recentPos+i)%n]
			dir := "send"
			if r.dir == event.DirRecv {
				dir = "recv"
			}
			fmt.Fprintf(&b, "%d %s total=%d captured=%d seq=%d hasSeq=%v shown=%d\n%s\n", r.ts, dir, r.total, r.captured, r.seq, r.hasSeq, len(r.head), hex.Dump(r.head))
		}
	}
	name := filepath.Join(a.DumpDir, fmt.Sprintf("%s-pid%d-fd%d-%d.txt", kind, keys[0].PID, keys[0].FD, time.Now().UnixNano()))
	if err := os.WriteFile(name, []byte(b.String()), 0o644); err != nil {
		slog.Warn("flight recorder dump", "err", err)
		return
	}
	slog.Warn("flight recorder dumped", "kind", kind, "file", name)
}

func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
