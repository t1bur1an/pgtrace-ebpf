package pgwire

import (
	"strings"
	"testing"

	"github.com/t1bur1an/pgtrace/internal/event"
)

// feedChunks feeds b in chunks of n bytes and returns the largest buffer
// capacity the frontend stream held.
func feedChunks(c *Conn, dir event.Dir, b []byte, n int) (maxCap int, r Result) {
	for i := 0; i < len(b); i += n {
		chunk := b[i:min(i+n, len(b))]
		rr := c.Feed(dir, 1, chunk, uint32(len(chunk)))
		r.Started = append(r.Started, rr.Started...)
		r.Done = append(r.Done, rr.Done...)
		r.Truncated += rr.Truncated
		maxCap = max(maxCap, cap(c.fe.buf), cap(c.be.buf))
	}
	return
}

func TestAllocationSizedToMessage(t *testing.T) {
	c := NewConnWith(false, Options{MaxMessage: 64 << 10})
	big := fQuery("select '" + strings.Repeat("x", 1<<20) + "'")
	maxCap, r := feedChunks(c, S, big, 4096)
	if maxCap > 64<<10 {
		t.Fatalf("buffered up to %d bytes for a 64 KiB cap", maxCap)
	}
	if r.Truncated != 1 || len(r.Started) != 1 || len(r.Started[0].SQL) != 64<<10-5 {
		t.Fatalf("truncated=%d started=%d sql=%d", r.Truncated, len(r.Started), len(r.Started[0].SQL))
	}
	small := fQuery("select " + strings.Repeat("1", 290))
	maxCap, r = feedChunks(c, S, small, 100)
	if maxCap != len(small) {
		t.Fatalf("300-byte query allocated %d bytes", maxCap)
	}
	if r.Truncated != 0 || r.Started[0].SQL != "select "+strings.Repeat("1", 290) {
		t.Fatalf("small query mangled: %+v", r)
	}
}

func TestMaxMessageKeepsWholeStatement(t *testing.T) {
	c := NewConnWith(true, Options{MaxMessage: 1 << 20})
	sql := "insert into t values ('" + strings.Repeat("ж", 225000) + "')" // ~450 KB
	_, r := feedChunks(c, event.DirRecv, fQuery(sql), 4096)
	if r.Truncated != 0 || len(r.Started) != 1 || r.Started[0].SQL != sql {
		t.Fatalf("truncated=%d len=%d", r.Truncated, len(r.Started[0].SQL))
	}
	_, r = feedChunks(c, event.DirSend, cat(bComplete("INSERT 0 1"), bReady()), 4096)
	if len(r.Done) != 1 || r.Done[0].Truncated {
		t.Fatalf("done %+v", r.Done)
	}
}

func TestZeroLengthBodyAtChunkEnd(t *testing.T) {
	c := NewConn()
	c.Feed(S, 1, fQuery("select 1"), uint32(len(fQuery("select 1"))))
	be := cat(bComplete("SELECT 1"), bReady())
	// Split so a chunk ends exactly after a header with nothing else to read.
	parts := [][]byte{be[:len(be)-6], be[len(be)-6:]}
	var done []Query
	for _, p := range parts {
		done = append(done, c.Feed(R, 2, p, uint32(len(p))).Done...)
	}
	if len(done) != 1 {
		t.Fatalf("got %+v", done)
	}
}
