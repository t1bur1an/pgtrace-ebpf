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
	r.c.ClientRecv(pid, c, ts)
	r.c.ClientStarted(pid, c, cs)
	ss := st(s, ts+1, sig)
	r.c.ServerStarted(pid, s, ss)
	r.c.ServerDone(s, done(ss, ts+5, tx))
	r.c.ClientDone(c, done(cs, ts+6, tx))
}

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
	r.c.ClientRecv(pid, C1, 10)
	r.c.ClientStarted(pid, C1, c1)
	s1 := st(S1, 11, 1)
	r.c.ServerStarted(pid, S1, s1)

	c2 := st(C2, 12, 2)
	r.c.ClientRecv(pid, C2, 12)
	r.c.ClientStarted(pid, C2, c2)

	r.c.ServerDone(S1, done(s1, 20, 'I')) // S1 back in the pool
	r.c.ClientDone(C1, done(c1, 21, 'I'))
	expectLinked(t, r.last(t), C1, S1, "exact")

	// pgbouncer hands S1 to the waiting C2; the last client read was C2 long ago.
	r.c.ClientRecv(pid, C1, 22)
	s2 := st(S1, 23, 2)
	r.c.ServerStarted(pid, S1, s2)
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
	r.c.ClientRecv(pid, C1, 1)
	r.c.ClientStarted(pid, C1, c)
	// Server-side statement was prepared before the agent started.
	s := pgwire.Start{ID: 1, Sig: 55, BindSig: 99, SQLKnown: false, TS: 2}
	r.c.ServerStarted(pid, S1, s)
	r.c.ServerDone(S1, pgwire.Query{ID: 1, Start: 2, End: 3, TxStatus: 'I'})
	r.c.ClientDone(C1, pgwire.Query{ID: 1, Start: 1, End: 4, TxStatus: 'I'})
	expectLinked(t, r.last(t), C1, S1, "exact")
}

func TestSameSQLDifferentBinds(t *testing.T) {
	r := newRec()
	a := st(C1, 1, 100)
	b := st(C2, 2, 200)
	r.c.ClientRecv(pid, C1, 1)
	r.c.ClientStarted(pid, C1, a)
	r.c.ClientRecv(pid, C2, 2)
	r.c.ClientStarted(pid, C2, b)
	// Forwarded in the opposite order to two servers.
	sb := st(S1, 3, 200)
	sa := st(S2, 4, 100)
	r.c.ServerStarted(pid, S1, sb)
	r.c.ServerStarted(pid, S2, sa)
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
	r.c.ClientRecv(pid, C1, 1)
	r.c.ClientStarted(pid, C1, a)
	r.c.ClientRecv(pid, C2, 2)
	r.c.ClientStarted(pid, C2, b)
	s := st(S1, 3, 5) // last read was C2: pgbouncer forwarded C2 right after reading it
	r.c.ServerStarted(pid, S1, s)
	r.c.ServerDone(S1, done(s, 4, 'I'))
	r.c.ClientDone(C2, done(b, 5, 'I'))
	expectLinked(t, r.last(t), C2, S1, "inferred")
	// C1 is still queued, and is the only candidate for the next start.
	s2 := st(S1, 6, 5)
	r.c.ServerStarted(pid, S1, s2)
	r.c.ServerDone(S1, done(s2, 7, 'I'))
	r.c.ClientDone(C1, done(a, 8, 'I'))
	expectLinked(t, r.last(t), C1, S1, "exact")
}

func TestTransactionKeepsLink(t *testing.T) {
	r := newRec()
	r.query(C1, S1, 10, 1, 'T') // BEGIN
	// Same statement text queued by C2 must not steal S1 while C1's transaction is open.
	c2 := st(C2, 15, 2)
	r.c.ClientRecv(pid, C2, 15)
	r.c.ClientStarted(pid, C2, c2)
	r.query(C1, S1, 20, 2, 'T')
	expectLinked(t, r.last(t), C1, S1, "exact")
	r.query(C1, S1, 30, 3, 'I') // COMMIT
	expectLinked(t, r.last(t), C1, S1, "exact")
}

func TestInternalSetBeforeForward(t *testing.T) {
	r := newRec()
	c := st(C1, 1, 9)
	r.c.ClientRecv(pid, C1, 1)
	r.c.ClientStarted(pid, C1, c)
	set := st(S1, 2, 777) // pgbouncer syncs a parameter first
	r.c.ServerStarted(pid, S1, set)
	q := st(S1, 2, 9)
	r.c.ServerStarted(pid, S1, q)
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
	r.c.ClientRecv(pid, C1, 1)
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
	r.c.ServerStarted(pid, S1, s)
	r.c.ServerDone(S1, done(s, 2, 'I'))
	tr := r.last(t)
	if tr.Client != nil || len(tr.Server) != 1 || tr.Server[0].Correlation != "none" {
		t.Fatalf("got %+v", tr)
	}
}

func TestClientClosesMidQuery(t *testing.T) {
	r := newRec()
	c := st(C1, 1, 5)
	r.c.ClientRecv(pid, C1, 1)
	r.c.ClientStarted(pid, C1, c)
	s := st(S1, 2, 5)
	r.c.ServerStarted(pid, S1, s)
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
	r.c.ClientRecv(pid, C2, 10)
	r.c.ClientStarted(pid, C2, c2)
	s2 := st(S2, 11, 6)
	r.c.ServerStarted(pid, S2, s2)
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
	r.c.ClientRecv(pid, C1, 1)
	r.c.ClientStarted(pid, C1, c)
	s := st(S1, 2, 5)
	r.c.ServerStarted(pid, S1, s)
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
