// Package agent routes captured events through the wire parser and sampler.
package agent

import (
	"context"
	"sync/atomic"

	"github.com/t1bur1an/pgtrace/internal/connmap"
	"github.com/t1bur1an/pgtrace/internal/event"
	"github.com/t1bur1an/pgtrace/internal/export"
	"github.com/t1bur1an/pgtrace/internal/pgwire"
	"github.com/t1bur1an/pgtrace/internal/sampler"
)

type Stats struct {
	Events  uint64 // events received
	Queries uint64 // queries parsed, before sampling
	Conns   uint64 // server connections currently tracked
}

// Filter lets the agent tell the kernel which fds need no payload capture.
type Filter interface {
	Ignore(event.ConnKey) // not a server connection: stop capturing
	Clear(event.ConnKey)  // unknown again (connect/close)
}

type Agent struct {
	Filter Filter // optional

	cm    *connmap.Map
	smp   *sampler.Sampler
	sink  func(export.Span)
	conns map[event.ConnKey]*pgwire.Conn

	events, queries, nconns atomic.Uint64
}

func New(cm *connmap.Map, smp *sampler.Sampler, sink func(export.Span)) *Agent {
	return &Agent{cm: cm, smp: smp, sink: sink, conns: map[event.ConnKey]*pgwire.Conn{}}
}

// Run processes events until the channel closes or ctx is done. It must be
// called from a single goroutine.
func (a *Agent) Run(ctx context.Context, events <-chan any) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-events:
			if !ok {
				return
			}
			a.events.Add(1)
			a.handle(ev)
		}
	}
}

func (a *Agent) handle(ev any) {
	switch ev := ev.(type) {
	case event.Connect:
		a.cm.OnConnect(ev.Key, ev.Addr)
		delete(a.conns, ev.Key)
		if a.cm.Lookup(ev.Key).Server {
			a.clear(ev.Key)
		} else {
			a.ignore(ev.Key)
		}
	case event.Close:
		a.cm.OnClose(ev.Key)
		delete(a.conns, ev.Key)
		// Also undoes an Ignore issued for this fd number by data events that
		// were still queued when the kernel saw the close.
		a.clear(ev.Key)
	case event.Data:
		info := a.cm.Lookup(ev.Key)
		if !info.Server {
			a.ignore(ev.Key)
			return
		}
		c := a.conns[ev.Key]
		if c == nil {
			c = pgwire.NewConn()
			a.conns[ev.Key] = c
		}
		for _, q := range c.Feed(ev.Dir, ev.TS, ev.Payload, ev.TotalLen).Done {
			a.queries.Add(1)
			if keep, reason := a.smp.Decide(q); keep {
				a.sink(export.Span{Q: q, PID: ev.Key.PID, FD: ev.Key.FD, Remote: info.Remote, Reason: reason})
			}
		}
	}
	a.nconns.Store(uint64(len(a.conns)))
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
	return Stats{Events: a.events.Load(), Queries: a.queries.Load(), Conns: a.nconns.Load()}
}
