package agent

import (
	"context"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/t1bur1an/pgtrace/internal/connmap"
	"github.com/t1bur1an/pgtrace/internal/event"
	"github.com/t1bur1an/pgtrace/internal/export"
	"github.com/t1bur1an/pgtrace/internal/sampler"
)

func msg(typ byte, body string) []byte {
	b := []byte{typ, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(b[1:], uint32(len(body)+4))
	return append(b, body...)
}

func data(k event.ConnKey, dir event.Dir, ts uint64, p []byte) event.Data {
	return event.Data{TS: ts, Key: k, Dir: dir, TotalLen: uint32(len(p)), Payload: p}
}

func TestRunEmitsOnlyServerQueries(t *testing.T) {
	server := event.ConnKey{PID: 1, FD: 10}
	client := event.ConnKey{PID: 1, FD: 11}
	q := msg('Q', "select 1\x00")
	resp := append(msg('C', "SELECT 1\x00"), msg('Z', "I")...)

	events := make(chan any, 16)
	events <- event.Connect{Key: server, Addr: netip.MustParseAddrPort("10.0.0.2:5432")}
	events <- event.Connect{Key: client, Addr: netip.MustParseAddrPort("10.0.0.9:6432")}
	events <- data(client, event.DirRecv, 1, q) // client→pgbouncer, ignored
	events <- data(server, event.DirSend, 2, q)
	events <- data(server, event.DirRecv, 3, resp)
	events <- data(client, event.DirSend, 4, resp)
	events <- event.Close{Key: server}
	close(events)

	var got []export.Span
	a := New(connmap.New(t.TempDir(), 5432), sampler.New(1, time.Second, 1), func(s export.Span) { got = append(got, s) })
	a.Run(context.Background(), events)

	if len(got) != 1 {
		t.Fatalf("got %d spans: %+v", len(got), got)
	}
	s := got[0]
	if s.Q.SQL != "select 1" || s.PID != 1 || s.FD != 10 || s.Remote.Port() != 5432 || s.Reason != sampler.ReasonRatio {
		t.Fatalf("span %+v", s)
	}
	st := a.Stats()
	if st.Events != 7 || st.Queries != 1 || st.Conns != 0 {
		t.Fatalf("stats %+v", st)
	}
}

func TestRunDropsUnsampled(t *testing.T) {
	server := event.ConnKey{PID: 1, FD: 10}
	events := make(chan any, 4)
	events <- event.Connect{Key: server, Addr: netip.MustParseAddrPort("10.0.0.2:5432")}
	events <- data(server, event.DirSend, 2, msg('Q', "select 1\x00"))
	events <- data(server, event.DirRecv, 3, append(msg('C', "SELECT 1\x00"), msg('Z', "I")...))
	close(events)
	n := 0
	a := New(connmap.New(t.TempDir(), 5432), sampler.New(0, time.Second, 1), func(export.Span) { n++ })
	a.Run(context.Background(), events)
	if n != 0 || a.Stats().Queries != 1 {
		t.Fatalf("n=%d stats=%+v", n, a.Stats())
	}
}
