// Package sampler decides which queries are exported.
package sampler

import (
	"math/rand/v2"
	"sync"
	"time"

	"github.com/t1bur1an/pgtrace/internal/pgwire"
)

// Reason explains why a query was kept.
type Reason string

const (
	ReasonNone  Reason = ""
	ReasonError Reason = "error"
	ReasonSlow  Reason = "slow"
	ReasonRatio Reason = "ratio"
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
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats["seen"]++
	r := ReasonNone
	switch {
	case q.ErrorCode != "":
		r = ReasonError
	case q.End >= q.Start && time.Duration(q.End-q.Start) >= s.slow:
		r = ReasonSlow
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
