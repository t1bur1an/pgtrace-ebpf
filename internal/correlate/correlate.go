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
	"fmt"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/t1bur1an/pgtrace-ebpf/internal/event"
	"github.com/t1bur1an/pgtrace-ebpf/internal/pgwire"
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
	Client      event.ConnKey // client the query was attributed to (zero if none)
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
	unattributed []uint64      // server query ids started with no client match
	held         []ServerQuery // completed parameter-sync statements awaiting the next query
	heldSince    uint64
}

// paramSyncHold bounds how long completed SET/RESET statements wait for the
// client query they were issued for.
const paramSyncHold = uint64(5 * time.Second)

func isParamSync(q pgwire.Query) bool { return q.Operation == "SET" || q.Operation == "RESET" }

type lastRead struct {
	key event.ConnKey
	seq uint64
}

type Correlator struct {
	// AttachParamSync holds completed, unlinked SET/RESET statements on a
	// server until its next query starts; if that query is linked to a client
	// query, they become its internal children (pgbouncer's parameter sync).
	AttachParamSync bool

	sink    func(Trace)
	hold    uint64
	clients map[event.ConnKey]*client
	servers map[event.ConnKey]*server
	// Clients with a non-empty queue, indexed by the signature (and bind
	// signature) of their oldest unforwarded query, so a server query finds
	// its candidates without scanning every waiting client.
	bySig  map[uint64]map[event.ConnKey]struct{}
	byBind map[uint64]map[event.ConnKey]struct{}
	lastRd map[uint32]lastRead // per pid: client most recently read from
	seq    map[uint32]uint64   // per pid: data events seen
	// stats is read by other goroutines (stats log, metrics); everything else
	// is owned by the goroutine calling the methods above.
	stats map[string]*atomic.Uint64
}

var statNames = []string{Exact, Inferred, None, "internal", "orphan"}

func New(sink func(Trace), holdTimeout time.Duration) *Correlator {
	return &Correlator{
		AttachParamSync: true,
		sink:            sink,
		hold:            uint64(holdTimeout),
		clients:         map[event.ConnKey]*client{},
		servers:         map[event.ConnKey]*server{},
		bySig:           map[uint64]map[event.ConnKey]struct{}{},
		byBind:          map[uint64]map[event.ConnKey]struct{}{},
		lastRd:          map[uint32]lastRead{},
		seq:             map[uint32]uint64{},
		stats:           newStats(),
	}
}

func newStats() map[string]*atomic.Uint64 {
	m := make(map[string]*atomic.Uint64, len(statNames))
	for _, n := range statNames {
		m[n] = new(atomic.Uint64)
	}
	return m
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
	c.lastRd[pid] = lastRead{key: k, seq: c.seq[pid]}
}

// ClientStarted records a query read from a client.
func (c *Correlator) ClientStarted(pid uint32, k event.ConnKey, st pgwire.Start) {
	cl := c.client(k)
	cl.queue = append(cl.queue, pending{id: st.ID, sig: st.Sig, bindSig: st.BindSig, known: st.SQLKnown, ts: st.TS})
	if len(cl.queue) == 1 {
		c.index(k, cl)
	}
}

func addKey(m map[uint64]map[event.ConnKey]struct{}, sig uint64, k event.ConnKey) {
	set := m[sig]
	if set == nil {
		set = map[event.ConnKey]struct{}{}
		m[sig] = set
	}
	set[k] = struct{}{}
}

func delKey(m map[uint64]map[event.ConnKey]struct{}, sig uint64, k event.ConnKey) {
	if set := m[sig]; set != nil {
		delete(set, k)
		if len(set) == 0 {
			delete(m, sig)
		}
	}
}

// index / unindex (re)register a client under its queue head. Call unindex
// before changing the head and index after.
func (c *Correlator) index(k event.ConnKey, cl *client) {
	if len(cl.queue) == 0 {
		return
	}
	h := cl.queue[0]
	addKey(c.bySig, h.sig, k)
	if h.bindSig != 0 {
		addKey(c.byBind, h.bindSig, k)
	}
}

func (c *Correlator) unindex(k event.ConnKey, cl *client) {
	if len(cl.queue) == 0 {
		return
	}
	h := cl.queue[0]
	delKey(c.bySig, h.sig, k)
	if h.bindSig != 0 {
		delKey(c.byBind, h.bindSig, k)
	}
}

func (c *Correlator) pop(k event.ConnKey, cl *client, n int) {
	c.unindex(k, cl)
	cl.queue = cl.queue[n:]
	if len(cl.queue) == 0 {
		cl.queue = nil
	}
	c.index(k, cl)
}

// ServerStarted attributes a query pgbouncer sent on server connection k.
// Parameter-sync statements held on k are adopted by the client query this
// one belongs to, or reported as unlinked if it belongs to none.
func (c *Correlator) ServerStarted(pid uint32, k event.ConnKey, st pgwire.Start) {
	s := c.server(k)
	sync := s.held
	s.held, s.heldSince = nil, 0
	a, ok := c.attribute(pid, k, s, st)
	if len(sync) == 0 {
		return
	}
	cl := c.clients[a.client]
	if !ok || cl == nil {
		c.flushNone(sync)
		return
	}
	h := cl.held[a.qid]
	if h == nil {
		h = &held{since: sync[0].Q.End}
		cl.held[a.qid] = h
	}
	for _, sq := range sync {
		sq.Correlation, sq.Internal, sq.Client = Exact, true, a.client
		h.children = append(h.children, sq)
		c.stats["internal"].Add(1)
	}
}

func (c *Correlator) flushNone(qs []ServerQuery) {
	for _, sq := range qs {
		c.stats[None].Add(1)
		c.sink(Trace{Server: []ServerQuery{sq}})
	}
}

// attribute decides which client query server query st belongs to.
func (c *Correlator) attribute(pid uint32, k event.ConnKey, s *server, st pgwire.Start) (attribution, bool) {
	if s.linked {
		if cl := c.clients[s.link]; cl != nil {
			if i := slices.IndexFunc(cl.queue, func(p pending) bool { return p.matches(st) }); i >= 0 {
				s.linkQID = cl.queue[i].id
				a := attribution{client: s.link, qid: s.linkQID, correlation: Exact}
				s.attr[st.ID] = a
				c.stats[Exact].Add(1)
				c.pop(s.link, cl, i+1)
				return a, true
			}
		}
	}

	var cands []event.ConnKey
	consider := func(set map[event.ConnKey]struct{}) {
		for ck := range set {
			if ck.PID == pid && c.clients[ck].queue[0].matches(st) && !slices.Contains(cands, ck) {
				cands = append(cands, ck)
			}
		}
	}
	consider(c.bySig[st.Sig])
	if st.BindSig != 0 {
		consider(c.byBind[st.BindSig])
	}
	if len(cands) == 0 {
		if s.linked {
			// Not the linked client's query and nobody else's: pgbouncer's
			// own query inside the linked client's transaction.
			a := attribution{client: s.link, qid: s.linkQID, correlation: Exact, internal: true}
			s.attr[st.ID] = a
			c.stats["internal"].Add(1)
			return a, true
		}
		s.unattributed = append(s.unattributed, st.ID)
		return attribution{}, false
	}
	if s.linked {
		// Another client's query arrived: the idle ReadyForQuery that should
		// have ended the link was missed (e.g. tracing started mid-transaction).
		c.unlink(k, s)
	}
	pick, corr := cands[0], Exact
	if len(cands) > 1 {
		corr = Inferred
		// pgbouncer forwards a query in the same step it reads it when a
		// server is free; otherwise the query waits and pgbouncer serves
		// waiting clients oldest first when a server is released.
		if last, ok := c.lastRd[pid]; ok && last.seq == c.seq[pid]-1 && slices.Contains(cands, last.key) {
			pick = last.key
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
	a := attribution{client: pick, qid: s.linkQID, correlation: corr}
	s.attr[st.ID] = a
	c.stats[corr].Add(1)
	c.pop(pick, cl, 1)
	// Queries pgbouncer sent on this server just before forwarding (e.g.
	// parameter-sync SETs) belong to this client query.
	for _, id := range s.unattributed {
		s.attr[id] = attribution{client: pick, qid: s.linkQID, correlation: Exact, internal: true}
		c.stats["internal"].Add(1)
	}
	s.unattributed = nil
	return a, true
}

// ServerDone takes a completed server query.
func (c *Correlator) ServerDone(k event.ConnKey, q pgwire.Query) {
	s := c.server(k)
	a, ok := s.attr[q.ID]
	delete(s.attr, q.ID)
	// Queries on one connection complete in order: anything older that is
	// still tracked was lost (e.g. the parser resynchronised) and never will.
	for id := range s.attr {
		if id < q.ID {
			delete(s.attr, id)
		}
	}
	s.unattributed = slices.DeleteFunc(s.unattributed, func(id uint64) bool { return id < q.ID })
	if q.TxStatus == 'I' && s.linked {
		c.unlink(k, s)
	}
	if !ok {
		s.unattributed = slices.DeleteFunc(s.unattributed, func(id uint64) bool { return id == q.ID })
		sq := ServerQuery{Key: k, Q: q, Correlation: None}
		if c.AttachParamSync && isParamSync(q) {
			if len(s.held) == 0 {
				s.heldSince = q.End
			}
			s.held = append(s.held, sq)
			return
		}
		c.flushNone([]ServerQuery{sq})
		return
	}
	sq := ServerQuery{Key: k, Client: a.client, Q: q, Correlation: a.correlation, Internal: a.internal}
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
	// block the queue. Client queries complete in order, so older entries
	// still queued or held belong to queries whose completion was lost.
	c.unindex(k, cl)
	cl.queue = slices.DeleteFunc(cl.queue, func(p pending) bool { return p.id <= q.ID })
	if len(cl.queue) == 0 {
		cl.queue = nil
	}
	c.index(k, cl)
	for id, h := range cl.held {
		if id < q.ID {
			c.orphan(h.children)
			delete(cl.held, id)
		}
	}
	c.sink(Trace{Client: &ClientQuery{Key: k, Q: q}, Server: children})
}

func (c *Correlator) orphan(children []ServerQuery) {
	c.stats["orphan"].Add(1)
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
	c.unindex(k, cl)
	delete(c.clients, k)
	for pid, last := range c.lastRd {
		if last.key == k {
			delete(c.lastRd, pid)
		}
	}
}

// ServerClosed forgets a server connection; its in-flight queries never complete.
func (c *Correlator) ServerClosed(k event.ConnKey) {
	if s := c.servers[k]; s != nil {
		c.flushNone(s.held)
		if s.linked {
			c.unlink(k, s)
		}
	}
	delete(c.servers, k)
}

// Tick flushes server queries held longer than the hold timeout, for client
// queries whose completion was never seen.
func (c *Correlator) Tick(now uint64) {
	for _, s := range c.servers {
		if len(s.held) > 0 && now > s.heldSince && now-s.heldSince > paramSyncHold {
			c.flushNone(s.held)
			s.held, s.heldSince = nil, 0
		}
	}
	// A client query with a server query still running isn't lost, only
	// slow: its earlier children (e.g. parameter sync) keep waiting.
	running := map[attribution]bool{}
	for _, s := range c.servers {
		for _, a := range s.attr {
			running[attribution{client: a.client, qid: a.qid}] = true
		}
	}
	for ck, cl := range c.clients {
		for id, h := range cl.held {
			if running[attribution{client: ck, qid: id}] {
				continue
			}
			if now > h.since && now-h.since > c.hold {
				c.orphan(h.children)
				delete(cl.held, id)
			}
		}
	}
}

// Stats returns counters: exact, inferred, internal, none, orphan. It is safe
// to call from any goroutine.
func (c *Correlator) Stats() map[string]uint64 {
	out := make(map[string]uint64, len(c.stats))
	for k, v := range c.stats {
		out[k] = v.Load()
	}
	return out
}

// Size is the number of queries currently tracked (queued, in flight, held).
func (c *Correlator) Size() int {
	n := 0
	for _, v := range c.Entries() {
		n += v
	}
	return n
}

// Entries breaks Size down: queued (client queries not yet seen on a server),
// held (completed server queries waiting for their client query), inflight
// (server queries started, not completed), unattributed, paramsync (held
// SET/RESET), plus the number of clients and servers tracked. Call from the
// correlator's goroutine.
func (c *Correlator) Entries() map[string]int {
	e := map[string]int{"queued": 0, "held": 0, "inflight": 0, "unattributed": 0, "paramsync": 0}
	for _, cl := range c.clients {
		e["queued"] += len(cl.queue)
		for _, h := range cl.held {
			e["held"] += len(h.children)
		}
	}
	for _, s := range c.servers {
		e["inflight"] += len(s.attr)
		e["unattributed"] += len(s.unattributed)
		e["paramsync"] += len(s.held)
	}
	return e
}

// Event marks one pgbouncer data event (any send/recv) of process pid. It
// must be called before the event is processed, so ServerStarted can tell
// whether the client read happened immediately before (an immediate forward)
// or earlier (the client waited for a server).
func (c *Correlator) Event(pid uint32) { c.seq[pid]++ }

// Debug describes the correlator's state for a server and a client
// connection (diagnostics). Call from the correlator's goroutine.
func (c *Correlator) Debug(server, client event.ConnKey) string {
	var b strings.Builder
	if s := c.servers[server]; s != nil {
		ids := make([]uint64, 0, len(s.attr))
		for id := range s.attr {
			ids = append(ids, id)
		}
		slices.Sort(ids)
		fmt.Fprintf(&b, "server %v: linked=%v link=%v linkQID=%d inflight=%v unattributed=%v paramsync=%d\n",
			server, s.linked, s.link, s.linkQID, ids, s.unattributed, len(s.held))
		for _, id := range ids {
			a := s.attr[id]
			fmt.Fprintf(&b, "  server q%d -> client %v q%d %s internal=%v\n", id, a.client, a.qid, a.correlation, a.internal)
		}
	} else {
		fmt.Fprintf(&b, "server %v: not tracked\n", server)
	}
	if cl := c.clients[client]; cl != nil {
		var q []uint64
		for _, p := range cl.queue {
			q = append(q, p.id)
		}
		var h []uint64
		for id := range cl.held {
			h = append(h, id)
		}
		slices.Sort(h)
		fmt.Fprintf(&b, "client %v: queued=%v held=%v servers=%d\n", client, q, h, len(cl.servers))
	} else {
		fmt.Fprintf(&b, "client %v: not tracked\n", client)
	}
	if lr, ok := c.lastRd[server.PID]; ok {
		fmt.Fprintf(&b, "last read: %v at seq %d (now %d)\n", lr.key, lr.seq, c.seq[server.PID])
	}
	return b.String()
}
