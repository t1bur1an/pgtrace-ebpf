package agent

import (
	"net/netip"
	"testing"
	"time"

	"github.com/t1bur1an/pgtrace/internal/connmap"
	"github.com/t1bur1an/pgtrace/internal/event"
	"github.com/t1bur1an/pgtrace/internal/export"
	"github.com/t1bur1an/pgtrace/internal/sampler"
)

// BenchmarkPipeline pushes simple-query round trips (2 data events per query)
// through connmap → parser → sampler (ratio 0.1) into a no-op sink. It reports
// the agent's userspace cost per query, excluding decode and export.
func BenchmarkPipeline(b *testing.B) {
	key := event.ConnKey{PID: 1, FD: 10}
	q := msg('Q', "SELECT abalance FROM pgbench_accounts WHERE aid = 12345;\x00")
	resp := append(append(append(msg('T', "\x00\x01abalance\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x17\x00\x04\xff\xff\xff\xff\x00\x00"),
		msg('D', "\x00\x01\x00\x00\x00\x010")...), msg('C', "SELECT 1\x00")...), msg('Z', "I")...)

	a := New(connmap.New(connmap.Config{ProcRoot: b.TempDir(), PGPort: 5432}), sampler.New(0.1, time.Second, 1), func(export.Span) {})
	a.handle(event.Connect{Key: key, Addr: netip.MustParseAddrPort("10.0.0.2:5432")})
	b.ReportAllocs()
	for i := 0; b.Loop(); i++ {
		a.handle(event.Data{TS: uint64(i), Key: key, Dir: event.DirSend, TotalLen: uint32(len(q)), Payload: q})
		a.handle(event.Data{TS: uint64(i), Key: key, Dir: event.DirRecv, TotalLen: uint32(len(resp)), Payload: resp})
	}
	if a.Stats().Queries == 0 {
		b.Fatal("no queries")
	}
}
