package correlate

import (
	"testing"
	"time"

	"github.com/t1bur1an/pgtrace/internal/event"
	"github.com/t1bur1an/pgtrace/internal/pgwire"
)

const pid = 7

var (
	C1 = event.ConnKey{PID: pid, FD: 101}
	C2 = event.ConnKey{PID: pid, FD: 102}
	C3 = event.ConnKey{PID: pid, FD: 103}
	C4 = event.ConnKey{PID: pid, FD: 104}
	S1 = event.ConnKey{PID: pid, FD: 201}
	S2 = event.ConnKey{PID: pid, FD: 202}
)

type rec struct {
	c      *Correlator
	traces []Trace
}

func newRec() *rec {
	r := &rec{}
	r.c = New(func(t Trace) { r.traces = append(r.traces, t) }, 30*time.Second)
	return r
}

// Per-connection query ids, like pgwire assigns them.
var ids = map[event.ConnKey]uint64{}

func st(k event.ConnKey, ts uint64, sig uint64) pgwire.Start {
	ids[k]++
	return pgwire.Start{ID: ids[k], Sig: sig, SQLKnown: true, TS: ts, SQL: "q"}
}

func done(s pgwire.Start, end uint64, tx byte) pgwire.Query {
	return pgwire.Query{ID: s.ID, Start: s.TS, End: end, Sig: s.Sig, SQL: s.SQL, TxStatus: tx}
}

// query runs a whole client query forwarded to server s without interference.
func (r *rec) query(c, s event.ConnKey, ts, sig uint64, tx byte) {
	cs := st(c, ts, sig)
	r.recv(c, ts)
	r.c.ClientStarted(pid, c, cs)
	ss := st(s, ts+1, sig)
	r.serverStart(s, ss)
	r.c.ServerDone(s, done(ss, ts+5, tx))
	r.c.ClientDone(c, done(cs, ts+6, tx))
}

// recv / serverStart model pgbouncer's data events: each is one event in
// pgbouncer's single-threaded loop.
func (r *rec) recv(k event.ConnKey, ts uint64) {
	r.c.Event(pid)
	r.c.ClientRecv(pid, k, ts)
}

func (r *rec) serverStart(k event.ConnKey, s pgwire.Start) {
	r.c.Event(pid)
	r.c.ServerStarted(pid, k, s)
}

// reply models pgbouncer receiving a server's reply (an event that isn't a
// client read).
func (r *rec) reply() { r.c.Event(pid) }

func (r *rec) last(t *testing.T) Trace {
	t.Helper()
	if len(r.traces) == 0 {
		t.Fatal("no traces")
	}
	return r.traces[len(r.traces)-1]
}

func expectLinked(t *testing.T, tr Trace, client event.ConnKey, server event.ConnKey, corr string) {
	t.Helper()
	if tr.Client == nil || tr.Client.Key != client {
		t.Fatalf("root %+v, want client %v", tr.Client, client)
	}
	if len(tr.Server) != 1 || tr.Server[0].Key != server || tr.Server[0].Correlation != corr || tr.Server[0].Internal {
		t.Fatalf("children %+v, want one on %v (%s)", tr.Server, server, corr)
	}
}

func TestImmediateForward(t *testing.T) {
	r := newRec()
	r.query(C1, S1, 100, 1, 'I')
	expectLinked(t, r.last(t), C1, S1, "exact")
}

func TestPoolWait(t *testing.T) {
	r := newRec()
	// C1 holds S1 in a transaction; C2's query waits for a server.
	c1 := st(C1, 10, 1)
	r.recv(C1, 10)
	r.c.ClientStarted(pid, C1, c1)
	s1 := st(S1, 11, 1)
	r.serverStart(S1, s1)

	c2 := st(C2, 12, 2)
	r.recv(C2, 12)
	r.c.ClientStarted(pid, C2, c2)

	r.c.ServerDone(S1, done(s1, 20, 'I')) // S1 back in the pool
	r.c.ClientDone(C1, done(c1, 21, 'I'))
	expectLinked(t, r.last(t), C1, S1, "exact")

	// pgbouncer hands S1 to the waiting C2; the last client read was C2 long ago.
	r.recv(C1, 22)
	s2 := st(S1, 23, 2)
	r.serverStart(S1, s2)
	r.c.ServerDone(S1, done(s2, 30, 'I'))
	r.c.ClientDone(C2, done(c2, 31, 'I'))
	tr := r.last(t)
	expectLinked(t, tr, C2, S1, "exact")
	if tr.Server[0].Q.Start-tr.Client.Q.Start != 11 {
		t.Fatalf("pool wait %d", tr.Server[0].Q.Start-tr.Client.Q.Start)
	}
}

func TestBindSigFallback(t *testing.T) {
	r := newRec()
	c := pgwire.Start{ID: 1, Sig: 11, BindSig: 99, SQLKnown: true, TS: 1}
	r.recv(C1, 1)
	r.c.ClientStarted(pid, C1, c)
	// Server-side statement was prepared before the agent started.
	s := pgwire.Start{ID: 1, Sig: 55, BindSig: 99, SQLKnown: false, TS: 2}
	r.serverStart(S1, s)
	r.c.ServerDone(S1, pgwire.Query{ID: 1, Start: 2, End: 3, TxStatus: 'I'})
	r.c.ClientDone(C1, pgwire.Query{ID: 1, Start: 1, End: 4, TxStatus: 'I'})
	expectLinked(t, r.last(t), C1, S1, "exact")
}

func TestSameSQLDifferentBinds(t *testing.T) {
	r := newRec()
	a := st(C1, 1, 100)
	b := st(C2, 2, 200)
	r.recv(C1, 1)
	r.c.ClientStarted(pid, C1, a)
	r.recv(C2, 2)
	r.c.ClientStarted(pid, C2, b)
	// Forwarded in the opposite order to two servers.
	sb := st(S1, 3, 200)
	sa := st(S2, 4, 100)
	r.serverStart(S1, sb)
	r.serverStart(S2, sa)
	r.c.ServerDone(S1, done(sb, 5, 'I'))
	r.c.ServerDone(S2, done(sa, 6, 'I'))
	r.c.ClientDone(C1, done(a, 7, 'I'))
	expectLinked(t, r.last(t), C1, S2, "exact")
	r.c.ClientDone(C2, done(b, 8, 'I'))
	expectLinked(t, r.last(t), C2, S1, "exact")
}

func TestIdenticalSignaturesInferred(t *testing.T) {
	r := newRec()
	a := st(C1, 1, 5)
	b := st(C2, 2, 5)
	r.recv(C1, 1)
	r.c.ClientStarted(pid, C1, a)
	r.recv(C2, 2)
	r.c.ClientStarted(pid, C2, b)
	s := st(S1, 3, 5) // last read was C2: pgbouncer forwarded C2 right after reading it
	r.serverStart(S1, s)
	r.c.ServerDone(S1, done(s, 4, 'I'))
	r.c.ClientDone(C2, done(b, 5, 'I'))
	expectLinked(t, r.last(t), C2, S1, "inferred")
	// C1 is still queued, and is the only candidate for the next start.
	s2 := st(S1, 6, 5)
	r.serverStart(S1, s2)
	r.c.ServerDone(S1, done(s2, 7, 'I'))
	r.c.ClientDone(C1, done(a, 8, 'I'))
	expectLinked(t, r.last(t), C1, S1, "exact")
}

func TestTransactionKeepsLink(t *testing.T) {
	r := newRec()
	r.query(C1, S1, 10, 1, 'T') // BEGIN
	// Same statement text queued by C2 must not steal S1 while C1's transaction is open.
	c2 := st(C2, 15, 2)
	r.recv(C2, 15)
	r.c.ClientStarted(pid, C2, c2)
	r.query(C1, S1, 20, 2, 'T')
	expectLinked(t, r.last(t), C1, S1, "exact")
	r.query(C1, S1, 30, 3, 'I') // COMMIT
	expectLinked(t, r.last(t), C1, S1, "exact")
}

func TestInternalSetBeforeForward(t *testing.T) {
	r := newRec()
	c := st(C1, 1, 9)
	r.recv(C1, 1)
	r.c.ClientStarted(pid, C1, c)
	set := st(S1, 2, 777) // pgbouncer syncs a parameter first
	r.serverStart(S1, set)
	q := st(S1, 2, 9)
	r.serverStart(S1, q)
	r.c.ServerDone(S1, done(set, 3, 'I'))
	r.c.ServerDone(S1, done(q, 4, 'I'))
	r.c.ClientDone(C1, done(c, 5, 'I'))
	tr := r.last(t)
	if tr.Client == nil || len(tr.Server) != 2 || !tr.Server[0].Internal || tr.Server[1].Internal || tr.Server[1].Correlation != "exact" {
		t.Fatalf("got %+v", tr)
	}
}

func TestAdminConsoleQueryDoesNotBlockQueue(t *testing.T) {
	r := newRec()
	c := st(C1, 1, 42)
	r.recv(C1, 1)
	r.c.ClientStarted(pid, C1, c)
	r.c.ClientDone(C1, done(c, 2, 'I')) // answered by pgbouncer itself
	tr := r.last(t)
	if tr.Client == nil || len(tr.Server) != 0 {
		t.Fatalf("got %+v", tr)
	}
	r.query(C1, S1, 10, 43, 'I')
	expectLinked(t, r.last(t), C1, S1, "exact")
}

func TestServerOnlyQuery(t *testing.T) {
	r := newRec()
	s := st(S1, 1, 1234) // server_check_query
	r.serverStart(S1, s)
	r.c.ServerDone(S1, done(s, 2, 'I'))
	tr := r.last(t)
	if tr.Client != nil || len(tr.Server) != 1 || tr.Server[0].Correlation != "none" {
		t.Fatalf("got %+v", tr)
	}
}

func TestClientClosesMidQuery(t *testing.T) {
	r := newRec()
	c := st(C1, 1, 5)
	r.recv(C1, 1)
	r.c.ClientStarted(pid, C1, c)
	s := st(S1, 2, 5)
	r.serverStart(S1, s)
	r.c.ServerDone(S1, done(s, 3, 'I'))
	r.c.ClientClosed(C1)
	tr := r.last(t)
	if tr.Client != nil || len(tr.Server) != 1 || tr.Server[0].Correlation != "exact" {
		t.Fatalf("got %+v", tr)
	}
	if st := r.c.Stats(); st["orphan"] != 1 {
		t.Fatalf("stats %v", st)
	}
	// Server finishing after its client is gone is an orphan too.
	c2 := st(C2, 10, 6)
	r.recv(C2, 10)
	r.c.ClientStarted(pid, C2, c2)
	s2 := st(S2, 11, 6)
	r.serverStart(S2, s2)
	r.c.ClientClosed(C2)
	r.c.ServerDone(S2, done(s2, 12, 'I'))
	if tr := r.last(t); tr.Client != nil || len(tr.Server) != 1 {
		t.Fatalf("late server done: %+v", tr)
	}
	if r.c.Size() != 0 {
		t.Fatalf("state left behind: %d", r.c.Size())
	}
}

func TestHoldTimeout(t *testing.T) {
	r := newRec()
	c := st(C1, 1, 5)
	r.recv(C1, 1)
	r.c.ClientStarted(pid, C1, c)
	s := st(S1, 2, 5)
	r.serverStart(S1, s)
	r.c.ServerDone(S1, done(s, 3, 'I'))
	r.c.Tick(3 + uint64(10*time.Second))
	if len(r.traces) != 0 {
		t.Fatal("flushed too early")
	}
	r.c.Tick(3 + uint64(31*time.Second))
	if len(r.traces) != 1 || r.traces[0].Client != nil {
		t.Fatalf("got %+v", r.traces)
	}
}

func TestStaleLinkRecovers(t *testing.T) {
	r := newRec()
	// C1 is linked to S1 and the agent never sees S1 go idle (e.g. it attached
	// mid-transaction or lost the ReadyForQuery).
	c1 := st(C1, 1, 1)
	r.recv(C1, 1)
	r.c.ClientStarted(pid, C1, c1)
	s1 := st(S1, 2, 1)
	r.serverStart(S1, s1)
	r.c.ServerDone(S1, done(s1, 3, 'T'))
	r.c.ClientDone(C1, done(c1, 4, 'T'))

	// S1 is handed to C2; its query must go to C2, not be an internal child of C1.
	c2 := st(C2, 10, 2)
	r.recv(C2, 10)
	r.c.ClientStarted(pid, C2, c2)
	s2 := st(S1, 11, 2)
	r.serverStart(S1, s2)
	r.c.ServerDone(S1, done(s2, 12, 'I'))
	r.c.ClientDone(C2, done(c2, 13, 'I'))
	expectLinked(t, r.last(t), C2, S1, "exact")
	if st := r.c.Stats(); st["internal"] != 0 {
		t.Fatalf("stats %v", st)
	}
}

func TestStateCleanedAfterLostQueries(t *testing.T) {
	r := newRec()
	// A client query whose server side never completes (parser lost its place).
	lost := st(C1, 1, 1)
	r.recv(C1, 1)
	r.c.ClientStarted(pid, C1, lost)
	ls := st(S1, 2, 1)
	r.serverStart(S1, ls)
	// ... and the client never saw its reply either. Later queries complete.
	for i := uint64(0); i < 3; i++ {
		r.query(C1, S1, 10+i*10, 100+i, 'I')
	}
	if n := r.c.Size(); n != 0 {
		t.Fatalf("%d stale entries kept after later queries completed", n)
	}
}

func TestStatsSafeForConcurrentReaders(t *testing.T) {
	r := newRec()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 1000; i++ {
			_ = r.c.Stats()
		}
	}()
	for i := uint64(0); i < 1000; i++ {
		r.query(C1, S1, 10+i*10, 5000+i, 'I')
	}
	<-done
}

func TestPoolWaitIdenticalQueriesServedOldestFirst(t *testing.T) {
	r := newRec()
	// C1 runs on the only server; C2, C3 and C4 then queue the same query.
	c1 := st(C1, 10, 7)
	r.recv(C1, 10)
	r.c.ClientStarted(pid, C1, c1)
	s1 := st(S1, 11, 7)
	r.serverStart(S1, s1)
	var waiting []pgwire.Start
	for i, k := range []event.ConnKey{C2, C3, C4} {
		w := st(k, uint64(20+i), 7)
		r.recv(k, uint64(20+i))
		r.c.ClientStarted(pid, k, w)
		waiting = append(waiting, w)
	}
	// S1 replies to C1, pgbouncer forwards the reply, then hands S1 to the
	// oldest waiter. The last client read (C4) is NOT the one served.
	r.reply()
	r.c.ServerDone(S1, done(s1, 30, 'I'))
	r.c.Event(pid) // pgbouncer sends the reply to C1
	r.c.ClientDone(C1, done(c1, 31, 'I'))
	for i, k := range []event.ConnKey{C2, C3, C4} {
		s := st(S1, uint64(40+10*i), 7)
		r.serverStart(S1, s)
		r.reply()
		r.c.ServerDone(S1, done(s, uint64(45+10*i), 'I'))
		r.c.Event(pid)
		r.c.ClientDone(k, done(waiting[i], uint64(46+10*i), 'I'))
		tr := r.last(t)
		if tr.Client == nil || tr.Client.Key != k || len(tr.Server) != 1 || tr.Server[0].Q.Start != s.TS {
			t.Fatalf("waiter %d: got %+v", i+2, tr)
		}
	}
	if st := r.c.Stats(); st["orphan"] != 0 {
		t.Fatalf("stats %v", st)
	}
}

func setQ(s pgwire.Start, end uint64) pgwire.Query {
	q := done(s, end, 'I')
	q.SQL, q.Operation = "SET application_name='app7';", "SET"
	return q
}

func TestParamSyncAttachedToNextClientQuery(t *testing.T) {
	r := newRec()
	c := st(C1, 10, 42)
	r.recv(C1, 10)
	r.c.ClientStarted(pid, C1, c)
	// pgbouncer syncs application_name first and waits for the reply ...
	set := st(S1, 11, 999)
	r.serverStart(S1, set)
	r.reply()
	r.c.ServerDone(S1, setQ(set, 12))
	if len(r.traces) != 0 {
		t.Fatalf("SET emitted before the forwarded query: %+v", r.traces)
	}
	// ... then forwards the client's query.
	q := st(S1, 13, 42)
	r.serverStart(S1, q)
	r.reply()
	r.c.ServerDone(S1, done(q, 20, 'I'))
	r.c.Event(pid)
	r.c.ClientDone(C1, done(c, 21, 'I'))
	tr := r.last(t)
	if tr.Client == nil || len(tr.Server) != 2 || !tr.Server[0].Internal || tr.Server[0].Q.Operation != "SET" || tr.Server[1].Internal {
		t.Fatalf("got %+v", tr)
	}
	if st := r.c.Stats(); st["internal"] != 1 || st[None] != 0 {
		t.Fatalf("stats %v", st)
	}
}

func TestHeldParamSyncFlushedWhenNotFollowedByClientQuery(t *testing.T) {
	r := newRec()
	set := st(S1, 1, 999)
	r.serverStart(S1, set)
	r.reply()
	r.c.ServerDone(S1, setQ(set, 2))
	check := st(S1, 3, 555) // server_check_query: unattributed
	r.serverStart(S1, check)
	if len(r.traces) != 1 || r.traces[0].Client != nil || r.traces[0].Server[0].Correlation != None || r.traces[0].Server[0].Q.Operation != "SET" {
		t.Fatalf("held SET not flushed as none: %+v", r.traces)
	}
	// A held SET on a server that closes is flushed too.
	set2 := st(S2, 5, 999)
	r.serverStart(S2, set2)
	r.reply()
	r.c.ServerDone(S2, setQ(set2, 6))
	r.c.ServerClosed(S2)
	if len(r.traces) != 2 {
		t.Fatalf("held SET lost on close: %+v", r.traces)
	}
	// And after the hold timeout.
	set3 := st(S1, 7, 999)
	r.c.ServerDone(S1, done(check, 7, 'I'))
	r.serverStart(S1, set3)
	r.reply()
	r.c.ServerDone(S1, setQ(set3, 8))
	n := len(r.traces)
	r.c.Tick(8 + uint64(6*time.Second))
	if len(r.traces) != n+1 {
		t.Fatalf("held SET not flushed by Tick")
	}
	if r.c.Size() != 0 {
		t.Fatalf("state left: %d", r.c.Size())
	}
}

func TestParamSyncAttachDisabled(t *testing.T) {
	r := newRec()
	r.c.AttachParamSync = false
	set := st(S1, 1, 999)
	r.serverStart(S1, set)
	r.reply()
	r.c.ServerDone(S1, setQ(set, 2))
	if len(r.traces) != 1 || r.traces[0].Server[0].Correlation != None {
		t.Fatalf("disabled: %+v", r.traces)
	}
}
