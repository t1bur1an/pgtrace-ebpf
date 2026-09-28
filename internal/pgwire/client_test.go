package pgwire

import (
	"testing"

	"github.com/t1bur1an/pgtrace/internal/event"
)

func startupParams(kv ...string) []byte {
	body := i32(196608)
	for _, s := range kv {
		body = append(body, cstr(s)...)
	}
	body = append(body, 0)
	return cat(i32(int32(len(body)+4)), body)
}

func TestClientDirection(t *testing.T) {
	c := NewClientConn()
	// On a client socket pgbouncer receives the frontend messages.
	r := c.Feed(event.DirRecv, 10, fQuery("select 1"), uint32(len(fQuery("select 1"))))
	if len(r.Started) != 1 || r.Started[0].SQL != "select 1" || r.Started[0].TS != 10 {
		t.Fatalf("started %+v", r.Started)
	}
	be := cat(selectResult(1), bReady())
	r = c.Feed(event.DirSend, 20, be, uint32(len(be)))
	if len(r.Done) != 1 || r.Done[0].SQL != "select 1" || r.Done[0].End != 20 || r.Done[0].ID != r.Done[0].ID {
		t.Fatalf("done %+v", r.Done)
	}
}

func TestStartupParams(t *testing.T) {
	c := NewClientConn()
	p := startupParams("user", "alice", "database", "shop", "application_name", "api")
	c.Feed(event.DirRecv, 1, p, uint32(len(p)))
	got := c.Params()
	if got["user"] != "alice" || got["database"] != "shop" || got["application_name"] != "api" {
		t.Fatalf("params %v", got)
	}
}

func extended(stmt, sql, bindVal string) []byte {
	bind := m('B', cstr(""), cstr(stmt), i16(0), i16(1), i32(int32(len(bindVal))), []byte(bindVal), i16(0))
	return cat(fParse(stmt, sql), bind, fExecute(""), fSync())
}

func TestSignatureIgnoresStatementName(t *testing.T) {
	a, b := NewClientConn(), NewConn()
	ca := extended("s1", "select $1", "42")
	cb := extended("PGBOUNCER_7", "select $1", "42")
	ra := a.Feed(event.DirRecv, 1, ca, uint32(len(ca)))
	rb := b.Feed(event.DirSend, 1, cb, uint32(len(cb)))
	if ra.Started[0].Sig == 0 || ra.Started[0].Sig != rb.Started[0].Sig || ra.Started[0].BindSig != rb.Started[0].BindSig {
		t.Fatalf("sigs differ: %+v vs %+v", ra.Started[0], rb.Started[0])
	}
	if !ra.Started[0].SQLKnown || ra.Started[0].BindSig == 0 {
		t.Fatalf("start %+v", ra.Started[0])
	}
}

func TestSignatureDiffersByBindValues(t *testing.T) {
	c := NewConn()
	x, y := extended("", "select $1", "1"), extended("", "select $1", "2")
	rx := c.Feed(event.DirSend, 1, x, uint32(len(x)))
	ry := c.Feed(event.DirSend, 2, y, uint32(len(y)))
	if rx.Started[0].Sig == ry.Started[0].Sig {
		t.Fatal("different bind values produced equal signatures")
	}
	q1, q2 := NewConn(), NewConn()
	a := q1.Feed(event.DirSend, 1, fQuery("select 1"), uint32(len(fQuery("select 1"))))
	b := q2.Feed(event.DirSend, 1, fQuery("select 1"), uint32(len(fQuery("select 1"))))
	if a.Started[0].Sig != b.Started[0].Sig || a.Started[0].BindSig != 0 {
		t.Fatal("identical simple queries must share a signature")
	}
}

func TestUnknownStatementBindSigFallback(t *testing.T) {
	c := NewConn()
	bind := m('B', cstr(""), cstr("PGBOUNCER_3"), i16(0), i16(1), i32(2), []byte("42"), i16(0))
	p := cat(bind, fExecute(""), fSync())
	r := c.Feed(event.DirSend, 1, p, uint32(len(p)))
	if r.Started[0].SQLKnown || r.Started[0].BindSig == 0 {
		t.Fatalf("start %+v", r.Started[0])
	}
	cc := NewClientConn()
	ce := extended("s1", "select $1", "42")
	rc := cc.Feed(event.DirRecv, 1, ce, uint32(len(ce)))
	if rc.Started[0].BindSig != r.Started[0].BindSig {
		t.Fatal("bind signatures must match regardless of statement")
	}
}

func TestStartedIDsMatchDoneAndTxStatus(t *testing.T) {
	c := NewConn()
	fe := cat(fQuery("begin"), fQuery("select 1"))
	r := c.Feed(event.DirSend, 1, fe, uint32(len(fe)))
	if len(r.Started) != 2 || r.Started[0].ID == r.Started[1].ID {
		t.Fatalf("started %+v", r.Started)
	}
	be := cat(bComplete("BEGIN"), m('Z', []byte{'T'}), selectResult(1), m('Z', []byte{'T'}))
	r2 := c.Feed(event.DirRecv, 2, be, uint32(len(be)))
	if len(r2.Done) != 2 || r2.Done[0].ID != r.Started[0].ID || r2.Done[1].ID != r.Started[1].ID {
		t.Fatalf("done %+v", r2.Done)
	}
	if r2.Done[0].TxStatus != 'T' {
		t.Fatalf("tx status %q", r2.Done[0].TxStatus)
	}
	// Extended queries report the status of the Z that closes their group.
	x := extended("", "commit", "")
	c.Feed(event.DirSend, 3, x, uint32(len(x)))
	be = cat(bParseDone(), bBindDone(), bComplete("COMMIT"), bReady())
	r3 := c.Feed(event.DirRecv, 4, be, uint32(len(be)))
	if len(r3.Done) != 1 || r3.Done[0].TxStatus != 'I' || r3.Done[0].End != 4 {
		t.Fatalf("extended done %+v", r3.Done)
	}
}

func TestPerExecution(t *testing.T) {
	c := NewClientConn()
	run := func(fe []byte) Query {
		t.Helper()
		c.Feed(event.DirRecv, 1, fe, uint32(len(fe)))
		be := cat(bParseDone(), bBindDone(), bComplete("SELECT 1"), bReady())
		r := c.Feed(event.DirSend, 2, be, uint32(len(be)))
		if len(r.Done) != 1 {
			t.Fatalf("done %+v", r.Done)
		}
		return r.Done[0]
	}
	sq := func(sql string) Query {
		c.Feed(event.DirRecv, 1, fQuery(sql), uint32(len(fQuery(sql))))
		be := cat(bComplete("SELECT 1"), bReady())
		return c.Feed(event.DirSend, 2, be, uint32(len(be))).Done[0]
	}
	if !sq("select 1").PerExecution {
		t.Error("simple query must be per-execution")
	}
	if !run(cat(fParse("", "select 1"), fBind("", ""), fExecute(""), fSync())).PerExecution {
		t.Error("unnamed Parse in the same group must be per-execution")
	}
	if !run(cat(fParse("s1", "select 1"), fBind("", "s1"), fExecute(""), fSync())).PerExecution {
		t.Error("named Parse in the same group must be per-execution")
	}
	if run(cat(fBind("", "s1"), fExecute(""), fSync())).PerExecution {
		t.Error("reused named statement must not be per-execution")
	}
}
