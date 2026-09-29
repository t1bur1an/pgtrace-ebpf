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
}

type recorded struct {
	ts    uint64
	dir   event.Dir
	total uint32
	head  []byte
}

const recorderEvents, recorderBytes = 64, 1024

type Agent struct {
	Filter  Filter           // optional
	Metrics *metrics.Metrics // optional: event counts, truncations
	Parser  pgwire.Options   // per-connection parser options
	// OnConnError receives errors that arrive with no query in flight.
	OnConnError func(export.ConnError)
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

	events, queries, nserver, nclient atomic.Uint64
}

func New(cm *connmap.Map, sink Sink) *Agent {
	a := &Agent{cm: cm, sink: sink, conns: map[event.ConnKey]*conn{}, opened: map[event.ConnKey]uint64{}}
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
			info = export.ClientInfo{Addr: c.addr, Params: c.p.Params(), IdleInTx: c.idle[tr.Client.Q.ID]}
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
		a.drop(ev.Key)
		a.cm.OnClose(ev.Key)
		// Also undoes an Ignore issued for this fd number by data events that
		// were still queued when the kernel saw the close.
		a.clear(ev.Key)
	case event.Data:
		a.event("data")
		a.data(ev)
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
	}
	if a.DumpDir != "" {
		r := recorded{ts: ev.TS, dir: ev.Dir, total: ev.TotalLen, head: append([]byte(nil), ev.Payload[:min(len(ev.Payload), recorderBytes)]...)}
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
	r := c.p.Feed(ev.Dir, ev.TS, ev.Payload, ev.TotalLen)
	if a.Metrics != nil {
		if uint32(len(ev.Payload)) < ev.TotalLen {
			a.Metrics.Truncation("kernel")
		}
		for i := 0; i < r.Truncated; i++ {
			a.Metrics.Truncation("parser")
		}
		if r.Resynced {
			a.Metrics.ParserResync(map[connmap.Side]string{connmap.SideServer: "server", connmap.SideClient: "client"}[c.side])
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
		side := "server"
		if c.side == connmap.SideClient {
			side = "client"
		}
		if a.Metrics != nil {
			a.Metrics.ConnectionError(side, ce.Code)
		}
		if a.OnConnError != nil {
			a.OnConnError(export.ConnError{Client: c.side == connmap.SideClient, Key: ev.Key, Start: c.start, End: ce.TS,
				Code: ce.Code, Message: ce.Message, Addr: c.addr, Params: c.p.Params()})
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
	return Stats{Events: a.events.Load(), Queries: a.queries.Load(), Server: a.nserver.Load(), Client: a.nclient.Load()}
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
			fmt.Fprintf(&b, "%d %s total=%d captured=%d\n%s\n", r.ts, dir, r.total, len(r.head), hex.Dump(r.head))
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
