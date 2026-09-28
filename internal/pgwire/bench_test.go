package pgwire

import "testing"

// BenchmarkConnSimpleQuery measures one simple-protocol round trip
// (Q → T,D,C,Z), each direction delivered as one syscall chunk.
func BenchmarkConnSimpleQuery(b *testing.B) {
	fe := fQuery("SELECT abalance FROM pgbench_accounts WHERE aid = 12345;")
	be := cat(selectResult(1), bReady())
	c := NewConn()
	b.SetBytes(int64(len(fe) + len(be)))
	b.ReportAllocs()
	for i := 0; b.Loop(); i++ {
		c.Feed(S, uint64(i), fe, uint32(len(fe)))
		if len(c.Feed(R, uint64(i), be, uint32(len(be))).Done) != 1 {
			b.Fatal("no query")
		}
	}
}

// BenchmarkConnExtendedQuery measures Parse/Bind/Describe/Execute/Sync with
// its responses, as pgbench -M extended sends it.
func BenchmarkConnExtendedQuery(b *testing.B) {
	fe := cat(fParse("", "SELECT abalance FROM pgbench_accounts WHERE aid = $1;"), fBind("", ""), fDescribe(""), fExecute(""), fSync())
	be := cat(bParseDone(), bBindDone(), selectResult(1), bReady())
	c := NewConn()
	b.SetBytes(int64(len(fe) + len(be)))
	b.ReportAllocs()
	for i := 0; b.Loop(); i++ {
		c.Feed(S, uint64(i), fe, uint32(len(fe)))
		if len(c.Feed(R, uint64(i), be, uint32(len(be))).Done) != 1 {
			b.Fatal("no query")
		}
	}
}
