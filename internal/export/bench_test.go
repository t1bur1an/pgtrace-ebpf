package export

import (
	"net/netip"
	"testing"

	"github.com/t1bur1an/pgtrace-ebpf/internal/correlate"
	"github.com/t1bur1an/pgtrace-ebpf/internal/event"
	"github.com/t1bur1an/pgtrace-ebpf/internal/pgwire"
	"github.com/t1bur1an/pgtrace-ebpf/internal/sampler"
)

// BenchmarkEncodeTrace measures encoding one client+server trace (2 spans)
// into a worker's batch buffer (no network).
func BenchmarkEncodeTrace(b *testing.B) {
	e := &Exporter{cfg: Config{MaxQueryText: DefaultMaxQueryText}, env: newEnvelope("pgbouncer")}
	w := &worker{e: e, rng: nil}
	w.rng = newRNG()
	q := pgwire.Query{Start: 1, End: 2, SQL: "SELECT abalance FROM pgbench_accounts WHERE aid = 12345;", Operation: "SELECT", CommandTag: "SELECT 1", Rows: 1, Protocol: "simple"}
	j := job{kind: jobTrace, reason: sampler.ReasonRatio,
		trace: correlate.Trace{Client: &correlate.ClientQuery{Key: event.ConnKey{PID: 1, FD: 11}, Q: q},
			Server: []correlate.ServerQuery{{Key: event.ConnKey{PID: 1, FD: 7}, Q: q, Correlation: "exact"}}},
		client:  ClientInfo{Addr: netip.MustParseAddrPort("10.0.0.9:40000"), Params: map[string]string{"user": "u", "database": "d"}},
		servers: []netip.AddrPort{netip.MustParseAddrPort("10.0.0.2:5432")}}
	b.ReportAllocs()
	for b.Loop() {
		w.encode(&j)
		if w.n >= 8192 {
			w.req = e.env.request(w.req, w.spans)
			w.spans, w.n = w.spans[:0], 0
		}
	}
}
