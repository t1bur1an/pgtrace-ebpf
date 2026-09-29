package agent

import (
	"context"
	"net/netip"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/t1bur1an/pgtrace-ebpf/internal/connmap"
	"github.com/t1bur1an/pgtrace-ebpf/internal/correlate"
	"github.com/t1bur1an/pgtrace-ebpf/internal/event"
	"github.com/t1bur1an/pgtrace-ebpf/internal/export"
	"github.com/t1bur1an/pgtrace-ebpf/internal/metrics"
)

type fakeFallback struct{ n int }

func (f *fakeFallback) TLSNeedFallback() { f.n++ }

func tlsData(k event.ConnKey, dir event.Dir, ts uint64, p []byte) event.Data {
	d := data(k, dir, ts, p)
	d.TLS = true
	return d
}

// runTLS runs events through an agent with TLS metrics; it returns the
// traces, the agent and the unresolved counters.
func runTLS(t *testing.T, fb TLSFallback, evs ...any) ([]got, *Agent, map[string]float64) {
	t.Helper()
	reg := prometheus.NewRegistry()
	met := metrics.NewWith(reg, metrics.Config{TLS: true})
	cm := connmap.New(connmap.Config{ProcRoot: t.TempDir(), PGPort: 5432, ListenPort: 6432, ClientTracing: true})
	var out []got
	var a *Agent
	a = New(cm, func(tr correlate.Trace, info export.ClientInfo) {
		// The server connections' TLS as the exporter would resolve it.
		for _, sq := range tr.Server {
			info.Params = map[string]string{"server_tls": map[bool]string{true: "on", false: "off"}[a.TLSInfo(sq.Key).On]}
		}
		out = append(out, got{tr, info})
	})
	a.Metrics = met
	a.Fallback = fb
	events := make(chan any, len(evs))
	for _, e := range evs {
		events <- e
	}
	close(events)
	a.Run(context.Background(), events)
	counts := map[string]float64{}
	mfs, _ := reg.Gather()
	for _, mf := range mfs {
		if mf.GetName() == "pgtrace_tls_unresolved_total" {
			for _, m := range mf.Metric {
				counts[m.Label[0].GetValue()] = m.Counter.GetValue()
			}
		}
	}
	return out, a, counts
}

var sslAnswer = []byte{'S'}

func TestTLSTraceWithAttributes(t *testing.T) {
	out, _, _ := runTLS(t, nil,
		event.Accept{Key: client, Addr: peer},
		event.Connect{Key: server, Addr: netip.MustParseAddrPort("10.0.0.2:5432")},
		data(client, event.DirRecv, 1, sslRequestMsg),
		data(client, event.DirSend, 2, sslAnswer),
		event.TLSAttr{Key: client, Version: "TLSv1.3"},
		event.TLSAttr{Key: client, Cipher: "TLS_AES_256_GCM_SHA384"},
		tlsData(client, event.DirRecv, 3, q),
		data(server, event.DirSend, 4, q), // plain server hop
		data(server, event.DirRecv, 5, resp),
		tlsData(client, event.DirSend, 6, resp),
	)
	if len(out) != 1 || out[0].tr.Client == nil || len(out[0].tr.Server) != 1 {
		t.Fatalf("got %+v", out)
	}
	if want := (export.TLSInfo{On: true, Version: "1.3", Cipher: "TLS_AES_256_GCM_SHA384"}); out[0].info.TLS != want {
		t.Fatalf("client TLS %+v", out[0].info.TLS)
	}
	if out[0].info.Params["server_tls"] != "off" {
		t.Fatalf("server hop reported as TLS")
	}
}

func TestTLSFromSSLAnswerWithoutCapture(t *testing.T) {
	_, a, _ := runTLS(t, nil,
		event.Accept{Key: client, Addr: peer},
		data(client, event.DirRecv, 1, sslRequestMsg),
		data(client, event.DirSend, 2, sslAnswer),
	)
	if st := a.Stats(); st.Client != 1 || st.ClientTLS != 1 {
		t.Fatalf("stats %+v", st)
	}
	if !a.TLSInfo(client).On {
		t.Fatal("connection not marked TLS")
	}
}

func TestTLSStateClearedOnClose(t *testing.T) {
	_, a, _ := runTLS(t, nil,
		event.Accept{Key: client, Addr: peer},
		tlsData(client, event.DirRecv, 1, q),
		event.TLSAttr{Key: client, Version: "TLSv1.3"},
		event.Close{Key: client},
		event.Accept{Key: client, Addr: peer}, // fd reused by a plain connection
		data(client, event.DirRecv, 2, q),
	)
	if a.TLSInfo(client).On {
		t.Fatal("plain connection inherited TLS state")
	}
	if st := a.Stats(); st.ClientTLS != 0 || st.Client != 1 {
		t.Fatalf("stats %+v", st)
	}
}

func TestHeldEventResolvedByItsMapping(t *testing.T) {
	fb := &fakeFallback{}
	unknownClient := event.ConnKey{PID: client.PID, FD: -1}
	held := tlsData(unknownClient, event.DirSend, 6, resp)
	held.Session = 0xabc
	out, _, counts := runTLS(t, fb,
		event.Accept{Key: client, Addr: peer},
		event.Connect{Key: server, Addr: netip.MustParseAddrPort("10.0.0.2:5432")},
		tlsData(client, event.DirRecv, 1, q),
		data(server, event.DirSend, 2, q),
		data(server, event.DirRecv, 3, resp),
		held,
		event.TLSFD{Key: client, Session: 0xabc},
	)
	if len(out) != 1 || out[0].tr.Client == nil || out[0].tr.Client.Q.End != 6 {
		t.Fatalf("got %+v", out)
	}
	if counts["resolved"] != 1 || counts["dropped"] != 0 || fb.n == 0 {
		t.Fatalf("counts %v fallback %d", counts, fb.n)
	}
}

func TestHeldEventDroppedWhenOtherEventFirst(t *testing.T) {
	unknown := event.ConnKey{PID: client.PID, FD: -1}
	h1 := tlsData(unknown, event.DirSend, 2, resp)
	h1.Session = 0xabc
	h2 := tlsData(unknown, event.DirSend, 4, resp)
	h2.Session = 0xdef
	_, _, counts := runTLS(t, &fakeFallback{},
		event.Accept{Key: client, Addr: peer},
		h1,
		data(server, event.DirSend, 3, q), // another event of the process first
		h2,
		event.TLSFD{Key: client, Session: 0x999}, // a mapping for a different session
	)
	if counts["dropped"] != 2 || counts["resolved"] != 0 {
		t.Fatalf("counts %v", counts)
	}
}

func TestSocketlessReadDropped(t *testing.T) {
	fb := &fakeFallback{}
	r := tlsData(event.ConnKey{PID: 1, FD: -1}, event.DirRecv, 1, q)
	r.Session = 1
	_, _, counts := runTLS(t, fb, r)
	if counts["dropped"] != 1 || fb.n != 1 {
		t.Fatalf("counts %v fallback %d", counts, fb.n)
	}
}

func TestTLSVersionNormalised(t *testing.T) {
	for in, want := range map[string]string{"TLSv1.3": "1.3", "TLSv1.2": "1.2", "TLSv1": "1.0", "": "", "SSLv3": "SSLv3"} {
		if got := tlsVersion(in); got != want {
			t.Errorf("tlsVersion(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestTLSAttrBeforeFirstData(t *testing.T) {
	_, a, _ := runTLS(t, nil,
		event.Connect{Key: server, Addr: netip.MustParseAddrPort("10.0.0.2:5432")},
		event.TLSAttr{Key: server, Cipher: "TLS_AES_128_GCM_SHA256"},
		tlsData(server, event.DirSend, 1, q),
	)
	if got := a.TLSInfo(server); !got.On || got.Cipher != "TLS_AES_128_GCM_SHA256" {
		t.Fatalf("got %+v", got)
	}
}
