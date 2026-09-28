package sampler

import (
	"testing"
	"time"

	"github.com/t1bur1an/pgtrace/internal/correlate"
	"github.com/t1bur1an/pgtrace/internal/pgwire"
)

func fast() pgwire.Query { return pgwire.Query{Start: 0, End: uint64(time.Millisecond)} }

func TestErrorsAlwaysKept(t *testing.T) {
	s := New(0, 100*time.Millisecond, 1)
	q := fast()
	q.ErrorCode = "22012"
	if keep, r := s.Decide(q); !keep || r != ReasonError {
		t.Fatalf("got %v %q", keep, r)
	}
}

func TestSlowAlwaysKept(t *testing.T) {
	s := New(0, 100*time.Millisecond, 1)
	q := pgwire.Query{Start: 5, End: 5 + uint64(100*time.Millisecond)}
	if keep, r := s.Decide(q); !keep || r != ReasonSlow {
		t.Fatalf("got %v %q", keep, r)
	}
}

func TestRatio(t *testing.T) {
	for _, tc := range []struct {
		ratio    float64
		min, max int
	}{{0, 0, 0}, {1, 100000, 100000}, {0.1, 9400, 10600}} {
		s := New(tc.ratio, 100*time.Millisecond, 42)
		kept := 0
		for i := 0; i < 100000; i++ {
			if keep, r := s.Decide(fast()); keep {
				if r != ReasonRatio {
					t.Fatalf("reason %q", r)
				}
				kept++
			}
		}
		if kept < tc.min || kept > tc.max {
			t.Errorf("ratio %v kept %d, want [%d,%d]", tc.ratio, kept, tc.min, tc.max)
		}
		st := s.Stats()
		if st["seen"] != 100000 || st["kept_ratio"] != uint64(kept) {
			t.Errorf("stats %v", st)
		}
	}
}

func TestDecideTrace(t *testing.T) {
	s := New(0, 100*time.Millisecond, 1)
	root := &correlate.ClientQuery{Q: fast()}
	child := correlate.ServerQuery{Q: fast()}
	child.Q.ErrorCode = "40001"
	if keep, r := s.DecideTrace(correlate.Trace{Client: root, Server: []correlate.ServerQuery{child}}); !keep || r != ReasonError {
		t.Fatalf("error in child: %v %q", keep, r)
	}
	slow := &correlate.ClientQuery{Q: pgwire.Query{Start: 0, End: uint64(150 * time.Millisecond)}}
	if keep, r := s.DecideTrace(correlate.Trace{Client: slow, Server: []correlate.ServerQuery{{Q: fast()}}}); !keep || r != ReasonSlow {
		t.Fatalf("slow root: %v %q", keep, r)
	}
	if keep, _ := s.DecideTrace(correlate.Trace{Client: root}); keep {
		t.Fatal("fast root kept at ratio 0")
	}
	lone := correlate.Trace{Server: []correlate.ServerQuery{{Q: pgwire.Query{Start: 0, End: uint64(time.Second)}}}}
	if keep, r := s.DecideTrace(lone); !keep || r != ReasonSlow {
		t.Fatalf("slow lone server query: %v %q", keep, r)
	}
}
