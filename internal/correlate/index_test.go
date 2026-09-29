package correlate

import (
	"math/rand/v2"
	"testing"
	"time"

	"github.com/t1bur1an/pgtrace-ebpf/internal/event"
	"github.com/t1bur1an/pgtrace-ebpf/internal/pgwire"
)

// checkIndex verifies the waiting-client indexes match the clients' queues:
// every client with a non-empty queue is indexed under its head's signature
// (and bind signature), and nothing else is indexed.
func checkIndex(t *testing.T, c *Correlator) {
	t.Helper()
	want := 0
	for k, cl := range c.clients {
		if len(cl.queue) == 0 {
			continue
		}
		want++
		h := cl.queue[0]
		if _, ok := c.bySig[h.sig][k]; !ok {
			t.Fatalf("client %v head sig %d not indexed", k, h.sig)
		}
		if h.bindSig != 0 {
			if _, ok := c.byBind[h.bindSig][k]; !ok {
				t.Fatalf("client %v head bind sig not indexed", k)
			}
		}
	}
	got := 0
	for sig, set := range c.bySig {
		if len(set) == 0 {
			t.Fatalf("empty set left for sig %d", sig)
		}
		for k := range set {
			cl := c.clients[k]
			if cl == nil || len(cl.queue) == 0 || cl.queue[0].sig != sig {
				t.Fatalf("stale index entry %v under sig %d", k, sig)
			}
			got++
		}
	}
	if got != want {
		t.Fatalf("indexed %d clients, %d waiting", got, want)
	}
	for bs, set := range c.byBind {
		for k := range set {
			cl := c.clients[k]
			if cl == nil || len(cl.queue) == 0 || cl.queue[0].bindSig != bs {
				t.Fatalf("stale bind index entry %v", k)
			}
		}
	}
}

func TestIndexStaysConsistent(t *testing.T) {
	r := rand.New(rand.NewPCG(7, 9))
	c := New(func(Trace) {}, time.Second)
	ids := map[event.ConnKey]uint64{}
	var ts uint64
	next := func(k event.ConnKey) uint64 { ids[k]++; return ids[k] }
	clientKeys := func() event.ConnKey { return event.ConnKey{PID: 1, FD: int32(100 + r.IntN(30))} }
	serverKeys := func() event.ConnKey { return event.ConnKey{PID: 1, FD: int32(10 + r.IntN(5))} }
	started := map[event.ConnKey][]pgwire.Start{}
	for i := 0; i < 20000; i++ {
		ts++
		c.Event(1)
		switch r.IntN(7) {
		case 0, 1: // client query read
			k := clientKeys()
			s := pgwire.Start{ID: next(k), Sig: uint64(r.IntN(6)), BindSig: uint64(r.IntN(3)), SQLKnown: r.IntN(4) != 0, TS: ts}
			c.ClientRecv(1, k, ts)
			c.ClientStarted(1, k, s)
			started[k] = append(started[k], s)
		case 2: // server query started
			k := serverKeys()
			s := pgwire.Start{ID: next(k), Sig: uint64(r.IntN(6)), BindSig: uint64(r.IntN(3)), SQLKnown: r.IntN(4) != 0, TS: ts}
			c.ServerStarted(1, k, s)
			started[k] = append(started[k], s)
		case 3: // server query done
			k := serverKeys()
			if q := started[k]; len(q) > 0 {
				c.ServerDone(k, pgwire.Query{ID: q[0].ID, Start: q[0].TS, End: ts, TxStatus: "IT"[r.IntN(2)]})
				started[k] = q[1:]
			}
		case 4: // client query done
			k := clientKeys()
			if q := started[k]; len(q) > 0 {
				c.ClientDone(k, pgwire.Query{ID: q[0].ID, Start: q[0].TS, End: ts})
				started[k] = q[1:]
			}
		case 5:
			k := clientKeys()
			c.ClientClosed(k)
			delete(started, k)
		case 6:
			k := serverKeys()
			c.ServerClosed(k)
			delete(started, k)
		}
		checkIndex(t, c)
	}
}
