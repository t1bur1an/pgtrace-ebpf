package correlate

import (
	"fmt"
	"testing"
	"time"

	"github.com/t1bur1an/pgtrace-ebpf/internal/event"
	"github.com/t1bur1an/pgtrace-ebpf/internal/pgwire"
)

// BenchmarkServerStartWithWaiting measures attributing one server query while
// n other clients are queued for a server (pool exhausted), each with its own
// signature.
func BenchmarkServerStartWithWaiting(b *testing.B) {
	for _, n := range []int{10, 100, 1000} {
		b.Run(fmt.Sprint(n, "_waiting"), func(b *testing.B) {
			c := New(func(Trace) {}, time.Minute)
			for i := 0; i < n; i++ {
				k := event.ConnKey{PID: 1, FD: int32(1000 + i)}
				c.ClientStarted(1, k, pgwire.Start{ID: 1, Sig: uint64(1e6 + i), SQLKnown: true, TS: uint64(i)})
			}
			me := event.ConnKey{PID: 1, FD: 1}
			srv := event.ConnKey{PID: 1, FD: 2}
			b.ReportAllocs()
			for i := 0; b.Loop(); i++ {
				id := uint64(i + 1)
				c.ClientStarted(1, me, pgwire.Start{ID: id, Sig: 7, SQLKnown: true, TS: id})
				c.ServerStarted(1, srv, pgwire.Start{ID: id, Sig: 7, SQLKnown: true, TS: id})
				c.ServerDone(srv, pgwire.Query{ID: id, Start: id, End: id, TxStatus: 'I'})
				c.ClientDone(me, pgwire.Query{ID: id, Start: id, End: id, TxStatus: 'I'})
			}
		})
	}
}
