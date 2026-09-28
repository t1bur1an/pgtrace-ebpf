// Package correlate links the queries pgbouncer runs on server connections to
// the client queries they were forwarded from.
//
// pgbouncer is single-threaded, so the agent sees its reads and writes in
// order. A server connection is linked to one client at a time: from the
// first query forwarded for that client until the server reports an idle
// transaction status (transaction pooling returns it to the pool then). A
// query starting on an unlinked server is matched against the oldest
// not-yet-forwarded query of each waiting client by signature (SQL plus bind
// values, so statement renaming by pgbouncer doesn't matter).
package correlate

import (
	"slices"
	"time"

	"github.com/t1bur1an/pgtrace/internal/event"
	"github.com/t1bur1an/pgtrace/internal/pgwire"
)

// Correlation results.
const (
	Exact    = "exact"    // unambiguous
	Inferred = "inferred" // several clients waited with the same signature
	None     = "none"     // not linked to any client query
)

type ClientQuery struct {
	Key event.ConnKey
	Q   pgwire.Query
}

type ServerQuery struct {
	Key         event.ConnKey
	Q           pgwire.Query
	Correlation string
	Internal    bool // issued by pgbouncer itself, not forwarded from the client
}

// Trace is one client query with the server queries it caused. Client is nil
// for server queries that couldn't be linked or whose client query was never
// completed (orphans).
type Trace struct {
	Client *ClientQuery
	Server []ServerQuery
}

type pending struct {
	id, sig, bindSig uint64
	known            bool
	ts               uint64
}

func (p pending) matches(s pgwire.Start) bool {
	if p.sig == s.Sig {
		return true
	}
	return (!p.known || !s.SQLKnown) && p.bindSig != 0 && p.bindSig == s.BindSig
}

type held struct {
	children []ServerQuery
	since    uint64 // monotonic ns of the first child's completion
}

type client struct {
	queue   []pending // queries read from the client, not yet seen on a server
	held    map[uint64]*held
	servers map[event.ConnKey]bool // servers currently linked to this client
}

type attribution struct {
	client      event.ConnKey
	qid         uint64 // client query id
	correlation string
	internal    bool
}

type server struct {
	linked       bool
	link         event.ConnKey
	linkQID      uint64 // client query most recently forwarded on this link
	attr         map[uint64]attribution
	unattributed []uint64 // server query ids started with no client match
}

type Correlator struct {
	sink    func(Trace)
	hold    uint64
	clients map[event.ConnKey]*client
	servers map[event.ConnKey]*server
	waiting map[event.ConnKey]bool   // clients with a non-empty queue
	lastRd  map[uint32]event.ConnKey // per pid: client most recently read from
	stats   map[string]uint64
}

func New(sink func(Trace), holdTimeout time.Duration) *Correlator {
	return &Correlator{
		sink:    sink,
		hold:    uint64(holdTimeout),
		clients: map[event.ConnKey]*client{},
		servers: map[event.ConnKey]*server{},
		waiting: map[event.ConnKey]bool{},
		lastRd:  map[uint32]event.ConnKey{},
		stats:   map[string]uint64{},
	}
}

func (c *Correlator) client(k event.ConnKey) *client {
	cl := c.clients[k]
	if cl == nil {
		cl = &client{held: map[uint64]*held{}, servers: map[event.ConnKey]bool{}}
		c.clients[k] = cl
	}
	return cl
}

func (c *Correlator) server(k event.ConnKey) *server {
	s := c.servers[k]
	if s == nil {
		s = &server{attr: map[uint64]attribution{}}
		c.servers[k] = s
	}
	return s
}

// ClientRecv records that pgbouncer just read from client k.
func (c *Correlator) ClientRecv(pid uint32, k event.ConnKey, ts uint64) {
	c.lastRd[pid] = k
}

// ClientStarted records a query read from a client.
func (c *Correlator) ClientStarted(pid uint32, k event.ConnKey, st pgwire.Start) {
	cl := c.client(k)
	cl.queue = append(cl.queue, pending{id: st.ID, sig: st.Sig, bindSig: st.BindSig, known: st.SQLKnown, ts: st.TS})
	c.waiting[k] = true
}

func (c *Correlator) pop(k event.ConnKey, cl *client, n int) {
	cl.queue = cl.queue[n:]
	if len(cl.queue) == 0 {
		cl.queue = nil
		delete(c.waiting, k)
	}
}

// ServerStarted attributes a query pgbouncer sent on server connection k.
func (c *Correlator) ServerStarted(pid uint32, k event.ConnKey, st pgwire.Start) {
	s := c.server(k)
	if s.linked {
		if cl := c.clients[s.link]; cl != nil {
			if i := slices.IndexFunc(cl.queue, func(p pending) bool { return p.matches(st) }); i >= 0 {
				s.linkQID = cl.queue[i].id
				s.attr[st.ID] = attribution{client: s.link, qid: s.linkQID, correlation: Exact}
				c.stats[Exact]++
				c.pop(s.link, cl, i+1)
				return
			}
		}
		s.attr[st.ID] = attribution{client: s.link, qid: s.linkQID, correlation: Exact, internal: true}
		c.stats["internal"]++
		return
	}

	var cands []event.ConnKey
	for ck := range c.waiting {
		if ck.PID == pid && c.clients[ck].queue[0].matches(st) {
			cands = append(cands, ck)
		}
	}
	if len(cands) == 0 {
		s.unattributed = append(s.unattributed, st.ID)
		return
	}
	pick, corr := cands[0], Exact
	if len(cands) > 1 {
		corr = Inferred
		if last, ok := c.lastRd[pid]; ok && slices.Contains(cands, last) {
			pick = last
		} else {
			for _, ck := range cands[1:] {
				if c.clients[ck].queue[0].ts < c.clients[pick].queue[0].ts {
					pick = ck
				}
			}
		}
	}
	cl := c.clients[pick]
	s.linked, s.link, s.linkQID = true, pick, cl.queue[0].id
	cl.servers[k] = true
	s.attr[st.ID] = attribution{client: pick, qid: s.linkQID, correlation: corr}
	c.stats[corr]++
	c.pop(pick, cl, 1)
	// Queries pgbouncer sent on this server just before forwarding (e.g.
	// parameter-sync SETs) belong to this client query.
	for _, id := range s.unattributed {
		s.attr[id] = attribution{client: pick, qid: s.linkQID, correlation: Exact, internal: true}
		c.stats["internal"]++
	}
	s.unattributed = nil
}

// ServerDone takes a completed server query.
func (c *Correlator) ServerDone(k event.ConnKey, q pgwire.Query) {
	s := c.server(k)
	a, ok := s.attr[q.ID]
	delete(s.attr, q.ID)
	if q.TxStatus == 'I' && s.linked {
		c.unlink(k, s)
	}
	if !ok {
		s.unattributed = slices.DeleteFunc(s.unattributed, func(id uint64) bool { return id == q.ID })
		c.stats[None]++
		c.sink(Trace{Server: []ServerQuery{{Key: k, Q: q, Correlation: None}}})
		return
	}
	sq := ServerQuery{Key: k, Q: q, Correlation: a.correlation, Internal: a.internal}
	cl := c.clients[a.client]
	if cl == nil {
		c.orphan([]ServerQuery{sq})
		return
	}
	h := cl.held[a.qid]
	if h == nil {
		h = &held{since: q.End}
		cl.held[a.qid] = h
	}
	h.children = append(h.children, sq)
}

func (c *Correlator) unlink(k event.ConnKey, s *server) {
	if cl := c.clients[s.link]; cl != nil {
		delete(cl.servers, k)
	}
	s.linked = false
}

// ClientDone takes a completed client query and emits its trace.
func (c *Correlator) ClientDone(k event.ConnKey, q pgwire.Query) {
	cl := c.client(k)
	var children []ServerQuery
	if h := cl.held[q.ID]; h != nil {
		children = h.children
		delete(cl.held, q.ID)
		slices.SortStableFunc(children, func(a, b ServerQuery) int {
			switch {
			case a.Q.Start < b.Q.Start:
				return -1
			case a.Q.Start > b.Q.Start:
				return 1
			}
			return 0
		})
	}
	// A query pgbouncer answered itself was never forwarded; don't let it
	// block the queue.
	if i := slices.IndexFunc(cl.queue, func(p pending) bool { return p.id == q.ID }); i >= 0 {
		cl.queue = slices.Delete(cl.queue, i, i+1)
		if len(cl.queue) == 0 {
			cl.queue = nil
			delete(c.waiting, k)
		}
	}
	c.sink(Trace{Client: &ClientQuery{Key: k, Q: q}, Server: children})
}

func (c *Correlator) orphan(children []ServerQuery) {
	c.stats["orphan"]++
	c.sink(Trace{Server: children})
}

// ClientClosed flushes a disconnected client's held server queries as orphans.
func (c *Correlator) ClientClosed(k event.ConnKey) {
	cl := c.clients[k]
	if cl == nil {
		return
	}
	for _, h := range cl.held {
		c.orphan(h.children)
	}
	for sk := range cl.servers {
		if s := c.servers[sk]; s != nil && s.link == k {
			s.linked = false
		}
	}
	delete(c.clients, k)
	delete(c.waiting, k)
	for pid, last := range c.lastRd {
		if last == k {
			delete(c.lastRd, pid)
		}
	}
}

// ServerClosed forgets a server connection; its in-flight queries never complete.
func (c *Correlator) ServerClosed(k event.ConnKey) {
	if s := c.servers[k]; s != nil && s.linked {
		c.unlink(k, s)
	}
	delete(c.servers, k)
}

// Tick flushes server queries held longer than the hold timeout, for client
// queries whose completion was never seen.
func (c *Correlator) Tick(now uint64) {
	for _, cl := range c.clients {
		for id, h := range cl.held {
			if now > h.since && now-h.since > c.hold {
				c.orphan(h.children)
				delete(cl.held, id)
			}
		}
	}
}

// Stats returns counters: exact, inferred, internal, none, orphan.
func (c *Correlator) Stats() map[string]uint64 {
	out := make(map[string]uint64, len(c.stats))
	for k, v := range c.stats {
		out[k] = v
	}
	return out
}

// Size is the number of queries currently tracked (queued, in flight, held).
func (c *Correlator) Size() int {
	n := 0
	for _, cl := range c.clients {
		n += len(cl.queue)
		for _, h := range cl.held {
			n += len(h.children)
		}
	}
	for _, s := range c.servers {
		n += len(s.attr) + len(s.unattributed)
	}
	return n
}
