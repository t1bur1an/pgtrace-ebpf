package agent

import (
	"net/netip"
	"testing"

	"github.com/t1bur1an/pgtrace/internal/connmap"
	"github.com/t1bur1an/pgtrace/internal/correlate"
	"github.com/t1bur1an/pgtrace/internal/event"
	"github.com/t1bur1an/pgtrace/internal/export"
)

// BenchmarkPipeline pushes one correlated query (client recv, server send,
// server recv, client send) through connmap → parsers → correlator into a
// no-op sink. It reports the agent's userspace cost per client query,
// excluding decode, sampling and export.
func BenchmarkPipeline(b *testing.B) {
	server := event.ConnKey{PID: 1, FD: 10}
	client := event.ConnKey{PID: 1, FD: 11}
	q := msg('Q', "SELECT abalance FROM pgbench_accounts WHERE aid = 12345;\x00")
	resp := append(append(append(msg('T', "\x00\x01abalance\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x17\x00\x04\xff\xff\xff\xff\x00\x00"),
		msg('D', "\x00\x01\x00\x00\x00\x010")...), msg('C', "SELECT 1\x00")...), msg('Z', "I")...)

	n := 0
	a := New(connmap.New(connmap.Config{ProcRoot: b.TempDir(), PGPort: 5432, ListenPort: 6432, ClientTracing: true}),
		func(correlate.Trace, export.ClientInfo) { n++ })
	a.handle(event.Connect{Key: server, Addr: netip.MustParseAddrPort("10.0.0.2:5432")})
	a.handle(event.Accept{Key: client, Addr: netip.MustParseAddrPort("10.0.0.9:40000")})
	b.ReportAllocs()
	for i := 0; b.Loop(); i++ {
		ts := uint64(i) * 10
		a.handle(event.Data{TS: ts, Key: client, Dir: event.DirRecv, TotalLen: uint32(len(q)), Payload: q})
		a.handle(event.Data{TS: ts + 1, Key: server, Dir: event.DirSend, TotalLen: uint32(len(q)), Payload: q})
		a.handle(event.Data{TS: ts + 2, Key: server, Dir: event.DirRecv, TotalLen: uint32(len(resp)), Payload: resp})
		a.handle(event.Data{TS: ts + 3, Key: client, Dir: event.DirSend, TotalLen: uint32(len(resp)), Payload: resp})
	}
	if n == 0 {
		b.Fatal("no traces")
	}
}
