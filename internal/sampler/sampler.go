// Package sampler decides which queries are exported.
package sampler

import (
	"math/rand/v2"
	"sync"
	"time"

	"github.com/t1bur1an/pgtrace/internal/correlate"
	"github.com/t1bur1an/pgtrace/internal/pgwire"
)

// Reason explains why a query was kept.
type Reason string

const (
	ReasonNone  Reason = ""
	ReasonError Reason = "error"
	ReasonSlow  Reason = "slow"
	ReasonRatio Reason = "ratio"
	// ReasonParent: the application's sampled trace (SQLCommenter traceparent) includes this query.
	ReasonParent Reason = "parent"
)

// Sampler keeps every failed or slow query and a random fraction of the rest.
type Sampler struct {
	ratio float64
	slow  time.Duration

	mu    sync.Mutex
	rng   *rand.Rand
	stats map[string]uint64
}

func New(ratio float64, slow time.Duration, seed uint64) *Sampler {
	return &Sampler{
		ratio: ratio,
		slow:  slow,
		rng:   rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15)),
		stats: map[string]uint64{},
	}
}

func (s *Sampler) Decide(q pgwire.Query) (bool, Reason) {
	return s.decide(q.ErrorCode != "", q, false)
}

// DecideTrace samples a whole trace: an error anywhere or a slow root keeps it.
// The root is the client query, or the first server query when there is none.
func (s *Sampler) DecideTrace(t correlate.Trace) (bool, Reason) {
	return s.DecideTraceParent(t, false)
}

// DecideTraceParent is DecideTrace for a trace whose application parent span
// is sampled (parentSampled): such traces are always kept, reason "parent",
// unless an error or slowness is the better reason.
func (s *Sampler) DecideTraceParent(t correlate.Trace, parentSampled bool) (bool, Reason) {
	return s.DecideTraceIdle(t, parentSampled, 0)
}

// DecideTraceIdle also treats an idle-in-transaction gap before the root query
// as slowness: a client that held its server idle for at least the slow
// threshold is as interesting as a slow query.
func (s *Sampler) DecideTraceIdle(t correlate.Trace, parentSampled bool, idle time.Duration) (bool, Reason) {
	var root pgwire.Query
	failed := false
	if t.Client != nil {
		root = t.Client.Q
		failed = root.ErrorCode != ""
	} else if len(t.Server) > 0 {
		root = t.Server[0].Q
	}
	for _, c := range t.Server {
		failed = failed || c.Q.ErrorCode != ""
	}
	if idle >= s.slow && s.slow > 0 {
		root.End = root.Start + uint64(max(idle, time.Duration(root.End-root.Start)))
	}
	return s.decide(failed, root, parentSampled)
}

func (s *Sampler) decide(failed bool, root pgwire.Query, parentSampled bool) (bool, Reason) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats["seen"]++
	r := ReasonNone
	switch {
	case failed:
		r = ReasonError
	case root.End >= root.Start && time.Duration(root.End-root.Start) >= s.slow:
		r = ReasonSlow
	case parentSampled:
		r = ReasonParent
	case s.ratio > 0 && s.rng.Float64() < s.ratio:
		r = ReasonRatio
	default:
		return false, ReasonNone
	}
	s.stats["kept_"+string(r)]++
	return true, r
}

// Stats returns a snapshot of the counters: seen, kept_error, kept_slow, kept_ratio.
func (s *Sampler) Stats() map[string]uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]uint64, len(s.stats))
	for k, v := range s.stats {
		out[k] = v
	}
	return out
}
