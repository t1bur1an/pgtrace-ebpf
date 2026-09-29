package agent

import (
	"context"
	"encoding/binary"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/t1bur1an/pgtrace-ebpf/internal/connmap"
	"github.com/t1bur1an/pgtrace-ebpf/internal/correlate"
	"github.com/t1bur1an/pgtrace-ebpf/internal/event"
	"github.com/t1bur1an/pgtrace-ebpf/internal/export"
	"github.com/t1bur1an/pgtrace-ebpf/internal/metrics"
	"github.com/t1bur1an/pgtrace-ebpf/internal/pgwire"
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
	server        = event.ConnKey{PID: 1, FD: 10}
	client        = event.ConnKey{PID: 1, FD: 11}
	peer          = netip.MustParseAddrPort("10.0.0.9:40000")
	q             = msg('Q', "select 1\x00")
	resp          = append(msg('C', "SELECT 1\x00"), msg('Z', "I")...)
	sslRequestMsg = []byte{0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f} // SSLRequest (80877103)
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

// The stats logger reads counters from another goroutine while Run works.
func TestStatsReadConcurrently(t *testing.T) {
	cm := connmap.New(connmap.Config{ProcRoot: t.TempDir(), PGPort: 5432, ListenPort: 6432, ClientTracing: true})
	a := New(cm, func(correlate.Trace, export.ClientInfo) {})
	events := make(chan any, 64)
	go func() {
		events <- event.Accept{Key: client, Addr: peer}
		events <- event.Connect{Key: server, Addr: netip.MustParseAddrPort("10.0.0.2:5432")}
		for i := uint64(0); i < 2000; i++ {
			ts := i * 10
			events <- data(client, event.DirRecv, ts, q)
			events <- data(server, event.DirSend, ts+1, q)
			events <- data(server, event.DirRecv, ts+2, resp)
			events <- data(client, event.DirSend, ts+3, resp)
		}
		close(events)
	}()
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
				_, _ = a.Stats(), a.CorrelationStats()
			}
		}
	}()
	a.Run(context.Background(), events)
	close(stop)
	if st := a.CorrelationStats(); st[correlate.Exact] != 2000 {
		t.Fatalf("stats %v", st)
	}
	if st := a.Stats(); st.Client != 1 || st.Server != 1 {
		t.Fatalf("conn gauges %+v", st)
	}
}

func TestTruncationsCounted(t *testing.T) {
	reg := prometheus.NewRegistry()
	met := metrics.New(reg)
	cm := connmap.New(connmap.Config{ProcRoot: t.TempDir(), PGPort: 5432, ListenPort: 6432, ClientTracing: true})
	a := New(cm, func(correlate.Trace, export.ClientInfo) {})
	a.Metrics = met
	a.Parser = pgwire.Options{MaxMessage: 64}
	long := msg('Q', "select '"+strings.Repeat("x", 200)+"'\x00")
	events := make(chan any, 4)
	events <- event.Connect{Key: server, Addr: netip.MustParseAddrPort("10.0.0.2:5432")}
	events <- data(server, event.DirSend, 1, long) // cut by the parser at 64 bytes
	// The kernel copied only part of this send.
	events <- event.Data{TS: 2, Key: server, Dir: event.DirSend, TotalLen: uint32(len(long)), Payload: long[:40]}
	close(events)
	a.Run(context.Background(), events)
	got := map[string]float64{}
	mfs, _ := reg.Gather()
	for _, mf := range mfs {
		if mf.GetName() == "pgtrace_truncations_total" {
			for _, m := range mf.Metric {
				got[m.Label[0].GetValue()] = m.Counter.GetValue()
			}
		}
	}
	if got["kernel"] != 1 || got["parser"] != 1 {
		t.Fatalf("truncations %v", got)
	}
}

func startup(kv ...string) []byte {
	body := []byte{0, 3, 0, 0}
	for _, s := range kv {
		body = append(append(body, s...), 0)
	}
	body = append(body, 0)
	b := binary.BigEndian.AppendUint32(nil, uint32(len(body)+4))
	return append(b, body...)
}

func TestConnectionErrorReported(t *testing.T) {
	cm := connmap.New(connmap.Config{ProcRoot: t.TempDir(), PGPort: 5432, ListenPort: 6432, ClientTracing: true})
	a := New(cm, func(correlate.Trace, export.ClientInfo) {})
	var got []export.ConnError
	a.OnConnError = func(e export.ConnError) { got = append(got, e) }
	events := make(chan any, 4)
	events <- event.Accept{TS: 100, Key: client, Addr: peer}
	events <- data(client, event.DirRecv, 110, startup("user", "bob", "database", "nosuchdb"))
	events <- data(client, event.DirSend, 150, msg('E', "SFATAL\x00C08P01\x00Mno such database: nosuchdb\x00\x00"))
	close(events)
	a.Run(context.Background(), events)
	if len(got) != 1 {
		t.Fatalf("got %+v", got)
	}
	e := got[0]
	if e.Client != true || e.Start != 100 || e.End != 150 || e.Code != "08P01" || e.Addr != peer || e.Params["database"] != "nosuchdb" || e.Params["user"] != "bob" {
		t.Fatalf("event %+v", e)
	}
}

func TestIdleInTransaction(t *testing.T) {
	cm := connmap.New(connmap.Config{ProcRoot: t.TempDir(), PGPort: 5432, ListenPort: 6432, ClientTracing: true})
	var traces []got
	a := New(cm, func(tr correlate.Trace, info export.ClientInfo) { traces = append(traces, got{tr, info}) })
	inTx := append(msg('C', "BEGIN\x00"), msg('Z', "T")...)
	idle := append(msg('C', "COMMIT\x00"), msg('Z', "I")...)
	events := make(chan any, 16)
	events <- event.Accept{TS: 1, Key: client, Addr: peer}
	events <- event.Connect{TS: 1, Key: server, Addr: netip.MustParseAddrPort("10.0.0.2:5432")}
	step := func(ts uint64, sql string, reply []byte) {
		qq := msg('Q', sql+"\x00")
		events <- data(client, event.DirRecv, ts, qq)
		events <- data(server, event.DirSend, ts+1, qq)
		events <- data(server, event.DirRecv, ts+2, reply)
		events <- data(client, event.DirSend, ts+3, reply)
	}
	step(1000, "begin", inTx)
	step(5_000_001_000, "commit", idle) // client sat idle ~5 s inside the transaction
	close(events)
	a.Run(context.Background(), events)
	if len(traces) != 2 {
		t.Fatalf("%d traces", len(traces))
	}
	if traces[0].info.IdleInTx != 0 {
		t.Fatalf("first query idle %v", traces[0].info.IdleInTx)
	}
	if d := traces[1].info.IdleInTx; d < 4999*time.Millisecond || d > 5001*time.Millisecond {
		t.Fatalf("idle in transaction %v", d)
	}
}

func TestFlightRecorderDumpsOnOrphan(t *testing.T) {
	cm := connmap.New(connmap.Config{ProcRoot: t.TempDir(), PGPort: 5432, ListenPort: 6432, ClientTracing: true})
	a := New(cm, func(correlate.Trace, export.ClientInfo) {})
	a.DumpDir = t.TempDir()
	events := make(chan any, 8)
	events <- event.Accept{Key: client, Addr: peer}
	events <- event.Connect{Key: server, Addr: netip.MustParseAddrPort("10.0.0.2:5432")}
	events <- data(client, event.DirRecv, 1, q)
	events <- data(server, event.DirSend, 2, q)
	events <- event.Close{Key: client} // client gone before the server replies
	events <- data(server, event.DirRecv, 3, resp)
	close(events)
	a.Run(context.Background(), events)
	files, _ := os.ReadDir(a.DumpDir)
	if len(files) != 1 {
		t.Fatalf("%d dump files", len(files))
	}
	b, _ := os.ReadFile(filepath.Join(a.DumpDir, files[0].Name()))
	for _, want := range []string{"orphan: server", "parser: groups=", "send total="} {
		if !strings.Contains(string(b), want) {
			t.Fatalf("dump lacks %q:\n%s", want, b)
		}
	}
}

func seqData(k event.ConnKey, dir event.Dir, ts uint64, seq uint32, p []byte) event.Data {
	d := data(k, dir, ts, p)
	d.Seq, d.HasSeq = seq, true
	return d
}

// A capture event the kernel skipped (recursion miss) shows up as a jump in
// the TCP stream offset; the bytes are skipped and the query still traced.
func TestCaptureGapSkipped(t *testing.T) {
	reg := prometheus.NewRegistry()
	met := metrics.New(reg)
	cm := connmap.New(connmap.Config{ProcRoot: t.TempDir(), PGPort: 5432, ListenPort: 6432, ClientTracing: true})
	var out []got
	a := New(cm, func(tr correlate.Trace, info export.ClientInfo) { out = append(out, got{tr, info}) })
	a.Metrics = met
	big := msg('D', "\x00\x01\x00\x00\x4e\x20"+strings.Repeat("x", 20000))
	reply := append(append(append([]byte{}, msg('T', "\x00\x01c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x17\x00\x04\xff\xff\xff\xff\x00\x00")...), big...), resp...)
	events := make(chan any, 16)
	events <- event.Accept{Key: client, Addr: peer}
	events <- event.Connect{Key: server, Addr: netip.MustParseAddrPort("10.0.0.2:5432")}
	events <- seqData(client, event.DirRecv, 1, 100, q)
	events <- seqData(server, event.DirSend, 2, 500, q)
	// Server reply in three reads; the middle one was skipped by the kernel.
	events <- seqData(server, event.DirRecv, 3, 9000, reply[:4096])
	events <- seqData(server, event.DirRecv, 5, 9000+8192, reply[8192:])
	events <- seqData(client, event.DirSend, 6, 700, reply)
	close(events)
	a.Run(context.Background(), events)
	if len(out) != 1 || out[0].tr.Client == nil || len(out[0].tr.Server) != 1 || out[0].tr.Server[0].Q.Rows != 1 {
		t.Fatalf("got %+v", out)
	}
	mfs, _ := reg.Gather()
	gaps := map[string]float64{}
	for _, mf := range mfs {
		for _, m := range mf.Metric {
			switch mf.GetName() {
			case "pgtrace_capture_gaps_total":
				gaps["n"] += m.Counter.GetValue()
			case "pgtrace_capture_gap_bytes_total":
				gaps["bytes"] += m.Counter.GetValue()
			case "pgtrace_parser_resyncs_total":
				gaps["resync"] += m.Counter.GetValue()
			}
		}
	}
	if gaps["n"] != 1 || gaps["bytes"] != 4096 || gaps["resync"] != 0 {
		t.Fatalf("gap metrics %v", gaps)
	}
}
