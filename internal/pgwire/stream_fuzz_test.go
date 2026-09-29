package pgwire

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/rand/v2"
	"testing"
)

type wantMsg struct {
	typ  byte
	body []byte // expected body (nil if not read)
	cut  bool
}

// genStream builds a random sequence of typed messages for one direction and
// the messages the stream must report for it.
func genStream(r *rand.Rand, frontend bool, keep int) ([]byte, []wantMsg) {
	types := []byte("CDTZEISN12")
	if frontend {
		types = []byte("QPBEDSCH")
	}
	s := stream{frontend: frontend, keep: keep}
	var raw []byte
	var want []wantMsg
	for i := 0; i < 40; i++ {
		typ := types[r.IntN(len(types))]
		var n int
		switch r.IntN(6) {
		case 0:
			n = 0
		case 1:
			n = r.IntN(10)
		case 2, 3:
			n = r.IntN(5000)
		case 4:
			n = keep - 5 + r.IntN(10) // around the keep cap
		default:
			n = r.IntN(200_000)
		}
		if n < 0 {
			n = 0
		}
		if lo, hi := lengthBounds(frontend, typ); n+4 < lo || n+4 > hi {
			n = lo - 4 + r.IntN(min(hi, lo+64)-lo+1)
		}
		body := make([]byte, n)
		for j := range body {
			body[j] = byte(r.IntN(256))
		}
		m := []byte{typ, 0, 0, 0, 0}
		binary.BigEndian.PutUint32(m[1:], uint32(n+4))
		raw = append(raw, append(m, body...)...)
		w := wantMsg{typ: typ}
		if s.needBody(typ) {
			k := min(1+4+n, max(keep, 64)) - 5
			w.body, w.cut = body[:k], k < n
		}
		want = append(want, w)
	}
	return raw, want
}

func TestStreamRandomChunking(t *testing.T) {
	for seed := uint64(0); seed < 300; seed++ {
		r := rand.New(rand.NewPCG(seed, 99))
		frontend := seed%2 == 0
		keep := []int{64, 100, 4096, 65536}[r.IntN(4)]
		raw, want := genStream(r, frontend, keep)
		s := stream{frontend: frontend, keep: keep}
		var got []msg
		for off := 0; off < len(raw); {
			n := 1 + r.IntN(4096)
			if r.IntN(10) == 0 {
				n = 1 + r.IntN(8) // tiny chunks: headers split across reads
			}
			n = min(n, len(raw)-off)
			msgs, desync := s.feed(raw[off:off+n], n)
			if desync {
				t.Fatalf("seed %d: desync at offset %d", seed, off)
			}
			got = append(got, msgs...)
			off += n
		}
		if len(got) != len(want) {
			t.Fatalf("seed %d (frontend=%v keep=%d): got %d messages, want %d", seed, frontend, keep, len(got), len(want))
		}
		for i := range want {
			g, w := got[i], want[i]
			if g.typ != w.typ || g.cut != w.cut || (w.body != nil && !bytes.Equal(g.body, w.body)) {
				t.Fatalf("seed %d msg %d: got typ %q cut %v len %d, want typ %q cut %v len %d%s", seed, i,
					g.typ, g.cut, len(g.body), w.typ, w.cut, len(w.body), fmt.Sprint())
			}
		}
		if len(s.buf) != 0 || s.discard != 0 {
			t.Fatalf("seed %d: leftover buf %d discard %d", seed, len(s.buf), s.discard)
		}
	}
}

func TestImplausibleLengthIsDesync(t *testing.T) {
	cases := []struct {
		frontend bool
		typ      byte
		length   uint32
	}{
		{false, 'Z', 777_668_160}, // ReadyForQuery is always 5 bytes
		{false, 'Z', 6},
		{false, '2', 5},        // BindComplete is always 4
		{false, 'C', 5 << 20},  // command tags are short
		{false, 'E', 50 << 20}, // error messages are not tens of MB
		{true, 'S', 8},         // Sync is always 4
		{true, 'E', 10 << 20},  // Execute carries only a portal name
	}
	for _, c := range cases {
		s := stream{frontend: c.frontend, synced: true, keep: DefaultMaxMessage}
		hdr := []byte{c.typ, 0, 0, 0, 0}
		binary.BigEndian.PutUint32(hdr[1:], c.length)
		p := append(hdr, make([]byte, 20)...)
		if _, desync := s.feed(p, len(p)); !desync {
			t.Errorf("%q length %d accepted", c.typ, c.length)
		}
	}
	// Large lengths stay legal where the protocol allows them.
	for _, c := range []struct {
		frontend bool
		typ      byte
	}{{false, 'D'}, {true, 'Q'}, {true, 'P'}, {true, 'B'}, {false, 'd'}} {
		s := stream{frontend: c.frontend, synced: true, keep: DefaultMaxMessage}
		hdr := []byte{c.typ, 0, 0, 0, 0}
		binary.BigEndian.PutUint32(hdr[1:], 500<<20)
		if _, desync := s.feed(hdr, 5); desync {
			t.Errorf("%q with a 500 MB length rejected", c.typ)
		}
	}
}
