// Package agent routes captured events through the wire parsers and the
// correlator, producing one trace per client query.
package agent

import (
	"context"
	"net/netip"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"

	"github.com/t1bur1an/pgtrace/internal/connmap"
	"github.com/t1bur1an/pgtrace/internal/correlate"
	"github.com/t1bur1an/pgtrace/internal/event"
	"github.com/t1bur1an/pgtrace/internal/export"
	"github.com/t1bur1an/pgtrace/internal/metrics"
	"github.com/t1bur1an/pgtrace/internal/pgwire"
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
}

type Agent struct {
	Filter  Filter           // optional
	Metrics *metrics.Metrics // optional: event counts, truncations
	Parser  pgwire.Options   // per-connection parser options
	// OnConnError receives errors that arrive with no query in flight.
	OnConnError func(export.ConnError)

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

// CorrelationStats returns the correlator's counters.
func (a *Agent) CorrelationStats() map[string]uint64 { return a.cor.Stats() }
