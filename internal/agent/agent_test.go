package agent

import (
	"context"
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/t1bur1an/pgtrace/internal/connmap"
	"github.com/t1bur1an/pgtrace/internal/correlate"
	"github.com/t1bur1an/pgtrace/internal/event"
	"github.com/t1bur1an/pgtrace/internal/export"
)

func msg(typ byte, body string) []byte {
	b := []byte{typ, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(b[1:], uint32(len(body)+4))
	return append(b, body...)
}

func data(k event.ConnKey, dir event.Dir, ts uint64, p []byte) event.Data {
	return event.Data{TS: ts, Key: k, Dir: dir, TotalLen: uint32(len(p)), Payload: p}
}

type fakeFilter struct{ ignored, cleared []event.ConnKey }

func (f *fakeFilter) Ignore(k event.ConnKey) { f.ignored = append(f.ignored, k) }
func (f *fakeFilter) Clear(k event.ConnKey)  { f.cleared = append(f.cleared, k) }

var (
	server = event.ConnKey{PID: 1, FD: 10}
	client = event.ConnKey{PID: 1, FD: 11}
	peer   = netip.MustParseAddrPort("10.0.0.9:40000")
	q      = msg('Q', "select 1\x00")
	resp   = append(msg('C', "SELECT 1\x00"), msg('Z', "I")...)
)

type got struct {
	tr   correlate.Trace
	info export.ClientInfo
}

func run(t *testing.T, clientTracing bool, f Filter, evs ...any) []got {
	t.Helper()
	events := make(chan any, len(evs))
	for _, e := range evs {
		events <- e
	}
	close(events)
	var out []got
	cm := connmap.New(connmap.Config{ProcRoot: t.TempDir(), PGPort: 5432, ListenPort: 6432, ClientTracing: clientTracing})
	a := New(cm, func(tr correlate.Trace, info export.ClientInfo) { out = append(out, got{tr, info}) })
	a.Filter = f
	a.Run(context.Background(), events)
	return out
}

func TestRunCorrelatesClientAndServer(t *testing.T) {
	out := run(t, true, nil,
		event.Accept{Key: client, Addr: peer},
		event.Connect{Key: server, Addr: netip.MustParseAddrPort("10.0.0.2:5432")},
		data(client, event.DirRecv, 1, q),
		data(server, event.DirSend, 2, q),
		data(server, event.DirRecv, 3, resp),
		data(client, event.DirSend, 4, resp),
	)
	if len(out) != 1 {
		t.Fatalf("got %d traces: %+v", len(out), out)
	}
	tr := out[0].tr
	if tr.Client == nil || tr.Client.Key != client || tr.Client.Q.SQL != "select 1" || tr.Client.Q.Start != 1 || tr.Client.Q.End != 4 {
		t.Fatalf("root %+v", tr.Client)
	}
	if len(tr.Server) != 1 || tr.Server[0].Key != server || tr.Server[0].Correlation != correlate.Exact || tr.Server[0].Q.Start != 2 {
		t.Fatalf("children %+v", tr.Server)
	}
	if out[0].info.Addr != peer {
		t.Fatalf("client info %+v", out[0].info)
	}
}

func TestClientTracingOff(t *testing.T) {
	f := &fakeFilter{}
	out := run(t, false, f,
		event.Accept{Key: client, Addr: peer},
		event.Connect{Key: server, Addr: netip.MustParseAddrPort("10.0.0.2:5432")},
		data(client, event.DirRecv, 1, q),
		data(server, event.DirSend, 2, q),
		data(server, event.DirRecv, 3, resp),
		data(client, event.DirSend, 4, resp),
	)
	if len(out) != 1 || out[0].tr.Client != nil || out[0].tr.Server[0].Correlation != correlate.None {
		t.Fatalf("got %+v", out)
	}
	if len(f.ignored) == 0 || f.ignored[0] != client {
		t.Fatalf("client not ignored in kernel: %v", f.ignored)
	}
}

func TestFilterCalls(t *testing.T) {
	other := event.ConnKey{PID: 1, FD: 12}
	unknown := event.ConnKey{PID: 1, FD: 13}
	f := &fakeFilter{}
	run(t, true, f,
		event.Connect{Key: server, Addr: netip.MustParseAddrPort("10.0.0.2:5432")},
		event.Connect{Key: other, Addr: netip.MustParseAddrPort("10.0.0.3:53")},
		event.Accept{Key: client, Addr: peer},
		data(unknown, event.DirRecv, 1, q), // not in /proc: ignored
		event.Close{Key: client},
	)
	if len(f.ignored) != 2 || f.ignored[0] != other || f.ignored[1] != unknown {
		t.Fatalf("ignored %v", f.ignored)
	}
	if len(f.cleared) != 3 || f.cleared[0] != server || f.cleared[1] != client || f.cleared[2] != client {
		t.Fatalf("cleared %v", f.cleared)
	}
}
