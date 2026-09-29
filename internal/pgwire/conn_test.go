package pgwire

import (
	"reflect"
	"strings"
	"testing"

	"github.com/t1bur1an/pgtrace-ebpf/internal/event"
)

const (
	S = event.DirSend
	R = event.DirRecv
)

// core drops the correlation fields so tests can compare query content.
func core(qs []Query) []Query {
	out := make([]Query, len(qs))
	for i, q := range qs {
		q.ID, q.Sig, q.BindSig, q.SQLKnown, q.TxStatus, q.PerExecution = 0, 0, 0, false, 0, false
		out[i] = q
	}
	return out
}

// feed sends each chunk whole (payload == total).
func feed(c *Conn, dir event.Dir, ts uint64, b []byte) []Query {
	return c.Feed(dir, ts, b, uint32(len(b))).Done
}

func TestSimpleQuery(t *testing.T) {
	c := NewConn()
	if got := feed(c, S, 100, fQuery("SELECT 1")); len(got) != 0 {
		t.Fatalf("premature emit: %+v", got)
	}
	got := core(feed(c, R, 250, cat(selectResult(1), bReady())))
	want := []Query{{Start: 100, End: 250, SQL: "SELECT 1", Operation: "SELECT", CommandTag: "SELECT 1", Rows: 1, Protocol: "simple"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
}

func TestSimpleQueryUpdateRows(t *testing.T) {
	c := NewConn()
	feed(c, S, 1, fQuery("  update t set a=1"))
	got := feed(c, R, 2, cat(bComplete("UPDATE 3"), bReady()))
	if len(got) != 1 || got[0].Rows != 3 || got[0].Operation != "UPDATE" {
		t.Fatalf("got %+v", got)
	}
}

func TestSimpleQueryError(t *testing.T) {
	c := NewConn()
	feed(c, S, 10, fQuery("SELECT 1/0"))
	got := feed(c, R, 20, cat(bError("22012", "division by zero"), bReady()))
	if len(got) != 1 {
		t.Fatalf("want 1 query, got %+v", got)
	}
	q := got[0]
	if q.ErrorCode != "22012" || q.ErrorMessage != "division by zero" || q.End != 20 || q.SQL != "SELECT 1/0" {
		t.Fatalf("got %+v", q)
	}
}

func TestExtendedNamedAndUnnamed(t *testing.T) {
	c := NewConn()
	sql := "select * from t where id=$1"
	feed(c, S, 5, cat(fParse("s1", sql), fBind("", "s1"), fDescribe(""), fExecute(""), fSync()))
	got := core(feed(c, R, 9, cat(bParseDone(), bBindDone(), bRowDesc(), bRow("a"), bRow("b"), bComplete("SELECT 2"), bReady())))
	want := []Query{{Start: 5, End: 9, SQL: sql, Operation: "SELECT", CommandTag: "SELECT 2", Rows: 2, Protocol: "extended"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
	// Re-use the named statement later without a new Parse.
	feed(c, S, 20, cat(fBind("", "s1"), fExecute(""), fSync()))
	got = feed(c, R, 30, cat(bBindDone(), bComplete("SELECT 0"), bReady()))
	if len(got) != 1 || got[0].SQL != sql || got[0].Start != 20 || got[0].End != 30 {
		t.Fatalf("reuse: got %+v", got)
	}
	// Unnamed statement.
	feed(c, S, 40, cat(fParse("", "insert into t values(1)"), fBind("", ""), fExecute(""), fSync()))
	got = feed(c, R, 50, cat(bParseDone(), bBindDone(), bComplete("INSERT 0 1"), bReady()))
	if len(got) != 1 || got[0].Operation != "INSERT" || got[0].Rows != 1 {
		t.Fatalf("unnamed: got %+v", got)
	}
}

func TestExtendedPipelineError(t *testing.T) {
	c := NewConn()
	feed(c, S, 1, cat(
		fParse("", "select 1/0"), fBind("", ""), fExecute(""),
		fParse("", "select 2"), fBind("", ""), fExecute(""),
		fSync()))
	got := feed(c, R, 2, cat(bParseDone(), bBindDone(), bError("22012", "division by zero"), bReady()))
	if len(got) != 1 || got[0].ErrorCode != "22012" || got[0].SQL != "select 1/0" {
		t.Fatalf("got %+v", got)
	}
	// Connection is still usable afterwards.
	feed(c, S, 3, fQuery("select 3"))
	got = feed(c, R, 4, cat(selectResult(1), bReady()))
	if len(got) != 1 || got[0].SQL != "select 3" {
		t.Fatalf("after error: got %+v", got)
	}
}

func TestExtendedTwoExecutesOneSync(t *testing.T) {
	c := NewConn()
	feed(c, S, 1, cat(
		fParse("", "select 1"), fBind("", ""), fExecute(""),
		fParse("", "select 2"), fBind("", ""), fExecute(""),
		fSync()))
	got := feed(c, R, 2, cat(bParseDone(), bBindDone(), bComplete("SELECT 1"), bParseDone(), bBindDone(), bComplete("SELECT 1"), bReady()))
	if len(got) != 2 || got[0].SQL != "select 1" || got[1].SQL != "select 2" {
		t.Fatalf("got %+v", got)
	}
}

func TestUnknownPreparedStatement(t *testing.T) {
	c := NewConn()
	feed(c, S, 1, cat(fBind("", "stmtX"), fExecute(""), fSync()))
	got := feed(c, R, 2, cat(bBindDone(), bComplete("SELECT 0"), bReady()))
	if len(got) != 1 || got[0].SQL != `<unknown prepared statement "stmtX">` {
		t.Fatalf("got %+v", got)
	}
}

func TestCloseStatementForgetsIt(t *testing.T) {
	c := NewConn()
	feed(c, S, 1, cat(fParse("s1", "select 1"), fSync()))
	feed(c, R, 2, cat(bParseDone(), bReady()))
	feed(c, S, 3, cat(fCloseStmt("s1"), fBind("", "s1"), fExecute(""), fSync()))
	got := feed(c, R, 4, cat(m('3'), bBindDone(), bComplete("SELECT 1"), bReady()))
	if len(got) != 1 || !strings.HasPrefix(got[0].SQL, "<unknown") {
		t.Fatalf("got %+v", got)
	}
}

// threeQueries returns frontend and backend streams for three simple queries.
func threeQueries() (fe, be []byte) {
	for _, s := range []string{"select a", "select b", "select c"} {
		fe = append(fe, fQuery(s)...)
		be = append(be, cat(selectResult(2), bReady())...)
	}
	return
}

func TestFragmentedByteByByte(t *testing.T) {
	fe, be := threeQueries()
	c := NewConn()
	for i := range fe {
		if got := c.Feed(S, 1, fe[i:i+1], 1).Done; len(got) != 0 {
			t.Fatalf("unexpected emit")
		}
	}
	var got []Query
	for i := range be {
		got = append(got, c.Feed(R, 2, be[i:i+1], 1).Done...)
	}
	if len(got) != 3 || got[0].SQL != "select a" || got[2].SQL != "select c" || got[1].Rows != 2 {
		t.Fatalf("got %+v", got)
	}
}

func TestCoalesced(t *testing.T) {
	fe, be := threeQueries()
	c := NewConn()
	feed(c, S, 1, fe)
	got := feed(c, R, 2, be)
	if len(got) != 3 || got[0].SQL != "select a" || got[1].SQL != "select b" || got[2].SQL != "select c" {
		t.Fatalf("got %+v", got)
	}
}

func TestTruncatedPayload(t *testing.T) {
	c := NewConn()
	long := "insert into t values ('" + strings.Repeat("x", 10000) + "')"
	msg := fQuery(long)
	// Kernel captured only the first 4096 bytes of the syscall.
	if got := c.Feed(S, 1, msg[:4096], uint32(len(msg))).Done; len(got) != 0 {
		t.Fatalf("unexpected emit %+v", got)
	}
	got := feed(c, R, 2, cat(bComplete("INSERT 0 1"), bReady()))
	if len(got) != 1 || !got[0].Truncated || !strings.HasPrefix(got[0].SQL, "insert into t values ('xxx") || got[0].Operation != "INSERT" {
		t.Fatalf("got %+v", got)
	}
	// Message split over two syscalls, the first truncated.
	msg2 := fQuery(long)
	c.Feed(S, 3, msg2[:4096], 6000)
	c.Feed(S, 3, msg2[6000:], uint32(len(msg2)-6000))
	feed(c, S, 4, fQuery("select 1"))
	got = feed(c, R, 5, cat(bComplete("INSERT 0 1"), bReady(), selectResult(1), bReady()))
	if len(got) != 2 || !got[0].Truncated || got[1].SQL != "select 1" || got[1].Truncated {
		t.Fatalf("split: got %+v", got)
	}
}

func TestMidStreamStart(t *testing.T) {
	c := NewConn()
	// Tail of a DataRow from a result we never saw the start of.
	tail := bRow("some-value-that-is-long")[7:]
	if got := feed(c, R, 1, tail); len(got) != 0 {
		t.Fatalf("garbage emitted: %+v", got)
	}
	// Leftover ReadyForQuery of the unseen query must not produce a span.
	if got := feed(c, R, 2, bReady()); len(got) != 0 {
		t.Fatalf("orphan Z emitted: %+v", got)
	}
	feed(c, S, 3, fQuery("select 42"))
	got := feed(c, R, 4, cat(selectResult(1), bReady()))
	if len(got) != 1 || got[0].SQL != "select 42" {
		t.Fatalf("got %+v", got)
	}
}

func TestStartupSkipped(t *testing.T) {
	c := NewConn()
	feed(c, S, 1, startup("app"))
	feed(c, R, 2, cat(bAuthOK(), bParam("server_version", "17"), m('K', i32(1), i32(2)), bReady()))
	feed(c, S, 3, fQuery("select 1"))
	got := feed(c, R, 4, cat(selectResult(1), bReady()))
	if len(got) != 1 || got[0].SQL != "select 1" || got[0].Start != 3 {
		t.Fatalf("got %+v", got)
	}
}

func TestSSLRequestRefused(t *testing.T) {
	c := NewConn()
	feed(c, S, 1, sslRequest())
	feed(c, R, 2, []byte{'N'})
	feed(c, S, 3, startup("app"))
	feed(c, R, 4, cat(bAuthOK(), bReady()))
	feed(c, S, 5, fQuery("select 1"))
	got := feed(c, R, 6, cat(selectResult(1), bReady()))
	if len(got) != 1 || got[0].SQL != "select 1" {
		t.Fatalf("got %+v", got)
	}
}

func TestOperation(t *testing.T) {
	cases := map[string]string{
		"select 1": "SELECT",
		"  \n\tWITH x AS (select 1) select * from x": "WITH",
		"/* app=1 */ update t set a=1":               "UPDATE",
		"-- hi\nDELETE FROM t":                       "DELETE",
		"(select 1)":                                 "SELECT",
		"":                                           "",
	}
	for in, want := range cases {
		if got := operation(in, ""); got != want {
			t.Errorf("operation(%q)=%q want %q", in, got, want)
		}
	}
	if got := operation("", "BEGIN"); got != "BEGIN" {
		t.Errorf("tag fallback: %q", got)
	}
}

func TestHugeMessagesAreNotBuffered(t *testing.T) {
	c := NewConn()
	big := strings.Repeat("v", 10<<20) // 10 MiB DataRow
	longSQL := "select '" + strings.Repeat("q", 1<<20) + "'"
	fe := fQuery(longSQL)
	be := cat(bRowDesc(), bRow(big), bComplete("SELECT 1"), bReady())
	maxBuf := 0
	for i := 0; i < len(fe); i += 4096 {
		chunk := fe[i:min(i+4096, len(fe))]
		c.Feed(S, 1, chunk, uint32(len(chunk)))
		maxBuf = max(maxBuf, cap(c.fe.buf))
	}
	var got []Query
	for i := 0; i < len(be); i += 4096 {
		chunk := be[i:min(i+4096, len(be))]
		got = append(got, c.Feed(R, 2, chunk, uint32(len(chunk))).Done...)
		maxBuf = max(maxBuf, cap(c.be.buf))
	}
	if maxBuf > 256<<10 {
		t.Fatalf("stream buffered %d bytes", maxBuf)
	}
	if len(got) != 1 || got[0].Rows != 1 || !got[0].Truncated || !strings.HasPrefix(longSQL, got[0].SQL) || len(got[0].SQL) < 32<<10 {
		t.Fatalf("got rows=%d truncated=%v sqllen=%d n=%d", got[0].Rows, got[0].Truncated, len(got[0].SQL), len(got))
	}
	// Still in sync afterwards.
	feed(c, S, 3, fQuery("select 2"))
	got = feed(c, R, 4, cat(selectResult(1), bReady()))
	if len(got) != 1 || got[0].SQL != "select 2" {
		t.Fatalf("after: %+v", got)
	}
}
