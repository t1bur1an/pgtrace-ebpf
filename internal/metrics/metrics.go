// Package metrics exposes Prometheus metrics computed from every query the
// agent sees, independent of span sampling. Every label has a bounded set of
// values, so the number of series doesn't grow with run time; see MaxSeries
// and docs/metrics.md.
package metrics

import (
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/t1bur1an/pgtrace/internal/correlate"
	"github.com/t1bur1an/pgtrace/internal/pgwire"
	"github.com/t1bur1an/pgtrace/internal/sampler"
)

var buckets = prometheus.ExponentialBuckets(50e-6, 2.5, 12) // 50 µs … ~3 s

// operations bounds the operation label; anything else is OTHER.
var operations = map[string]bool{}

func init() {
	for _, op := range strings.Fields(`SELECT INSERT UPDATE DELETE BEGIN COMMIT END ROLLBACK SET SHOW WITH COPY
		CREATE ALTER DROP TRUNCATE VACUUM ANALYZE EXPLAIN CALL DO FETCH DECLARE CLOSE DISCARD LISTEN
		NOTIFY PREPARE EXECUTE DEALLOCATE RESET LOCK GRANT REVOKE COMMENT MERGE`) {
		operations[op] = true
	}
}

// maxSQLStates bounds distinct sqlstate label values; later new codes are
// counted as OTHER. PostgreSQL defines about 260 codes.
const maxSQLStates = 300

// Label names for opt-in per-client metrics, in label order.
var LabelNames = []string{"database", "user", "client_addr"}

// Config enables the per-client labelled metrics.
type Config struct {
	Labels []string      // subset of LabelNames; empty disables labelled metrics
	Limit  int           // most distinct label combinations tracked at once
	TTL    time.Duration // idle combinations are deleted after this long
}

// Client identifies the client of a trace for labelled metrics.
type Client struct {
	Database, User, Addr string
}

type labelled struct {
	names    []string
	queries  *prometheus.CounterVec
	errors   *prometheus.CounterVec
	duration *prometheus.HistogramVec
	poolWait *prometheus.HistogramVec
}

type Metrics struct {
	queries     *prometheus.CounterVec
	duration    *prometheus.HistogramVec
	errors      *prometheus.CounterVec
	poolWait    prometheus.Histogram
	correlation *prometheus.CounterVec
	spans       *prometheus.CounterVec
	events      *prometheus.CounterVec
	truncations *prometheus.CounterVec
	conns       *prometheus.GaugeVec
	processes   prometheus.Gauge
	reg         prometheus.Registerer

	cfg       Config
	labelled  *labelled
	labelSets prometheus.Gauge
	overflow  prometheus.Counter
	now       func() time.Time

	mu        sync.Mutex
	sqlstates map[string]bool
	sets      map[string]time.Time // label combination (joined) → last seen
	setVals   map[string][]string
}

// New registers the base metrics (no per-client labels).
func New(reg prometheus.Registerer) *Metrics { return NewWith(reg, Config{}) }

// NewWith registers the base metrics and, if cfg.Labels is set, the
// per-client labelled families.
func NewWith(reg prometheus.Registerer, cfg Config) *Metrics {
	m := &Metrics{
		reg: reg, cfg: cfg, now: time.Now,
		sqlstates: map[string]bool{}, sets: map[string]time.Time{}, setVals: map[string][]string{},
		queries: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "pgtrace_queries_total", Help: "Queries seen, by side (client: client↔pgbouncer, server: pgbouncer↔postgres).",
		}, []string{"side", "operation", "protocol"}),
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "pgtrace_query_duration_seconds", Help: "Query duration as seen by pgbouncer, by side.", Buckets: buckets,
		}, []string{"side", "operation"}),
		errors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "pgtrace_query_errors_total", Help: "Queries that returned an error, by side and SQLSTATE.",
		}, []string{"side", "sqlstate"}),
		poolWait: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name: "pgtrace_pool_wait_seconds", Help: "Time from pgbouncer reading a client query to sending it to a server.", Buckets: buckets,
		}),
		correlation: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "pgtrace_correlation_total", Help: "Server queries by how they were linked to a client query.",
		}, []string{"result"}),
		spans: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "pgtrace_spans_total", Help: "Trace sampling decisions.",
		}, []string{"decision"}),
		events: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "pgtrace_events_total", Help: "Kernel events received, by kind.",
		}, []string{"kind"}),
		truncations: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "pgtrace_truncations_total",
			Help: "Truncations by layer: kernel (capture-bytes per syscall), parser (max-message-bytes), export (max-query-text).",
		}, []string{"layer"}),
		conns: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "pgtrace_connections", Help: "Tracked pgbouncer sockets, by side.",
		}, []string{"side"}),
		processes: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "pgtrace_traced_processes", Help: "pgbouncer processes being traced.",
		}),
	}
	reg.MustRegister(m.queries, m.duration, m.errors, m.poolWait, m.correlation, m.spans, m.events, m.truncations, m.conns, m.processes)
	if len(cfg.Labels) > 0 {
		m.registerLabelled()
	}
	return m
}

func (m *Metrics) registerLabelled() {
	var names []string
	for _, n := range LabelNames { // fixed order regardless of flag order
		for _, want := range m.cfg.Labels {
			if n == want {
				names = append(names, n)
			}
		}
	}
	m.labelled = &labelled{
		names: names,
		queries: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "pgtrace_client_queries_total", Help: "Client queries by the enabled client labels.",
		}, names),
		errors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "pgtrace_client_errors_total", Help: "Failed client queries by the enabled client labels.",
		}, names),
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "pgtrace_client_query_duration_seconds", Help: "Client query duration by the enabled client labels.", Buckets: buckets,
		}, names),
		poolWait: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "pgtrace_client_pool_wait_seconds", Help: "Pool wait by the enabled client labels.", Buckets: buckets,
		}, names),
	}
	m.labelSets = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "pgtrace_metrics_label_sets", Help: "Client label combinations currently tracked (at most -metrics-label-limit, plus 'other').",
	})
	m.overflow = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "pgtrace_metrics_label_overflow_total", Help: "Observations recorded under 'other' because the label-combination limit was reached.",
	})
	l := m.labelled
	m.reg.MustRegister(l.queries, l.errors, l.duration, l.poolWait, m.labelSets, m.overflow)
}

// SeriesPerLabelSet is the number of series one label combination creates:
// two counters and two histograms (buckets, +Inf, sum, count).
var SeriesPerLabelSet = 2 + 2*(len(buckets)+3)

// MaxSeries is the ceiling on series this package exposes (Go and process
// collectors excluded) for a configuration.
func MaxSeries(cfg Config) int {
	h := len(buckets) + 3
	ops := len(operations) + 1
	n := 2*ops*2 + // queries_total: side × operation × protocol
		2*ops*h + // query_duration_seconds
		2*(maxSQLStates+1) + // query_errors_total: side × sqlstate (+OTHER)
		h + // pool_wait_seconds
		5 + 4 + 4 + 3 + 2 + 1 + // correlation, spans, events, truncations, connections, traced_processes
		1 + 2 // kernel drops, bpf run time/runs
	if len(cfg.Labels) > 0 {
		n += (cfg.Limit+1)*SeriesPerLabelSet + 2 // +1 for 'other'; label_sets, overflow
	}
	return n
}

func seconds(q pgwire.Query) float64 {
	if q.End < q.Start {
		return 0
	}
	return time.Duration(q.End - q.Start).Seconds()
}

func (m *Metrics) observe(side string, q pgwire.Query) {
	op := opLabel(q.Operation)
	m.queries.WithLabelValues(side, op, q.Protocol).Inc()
	m.duration.WithLabelValues(side, op).Observe(seconds(q))
	if q.ErrorCode != "" {
		m.errors.WithLabelValues(side, m.sqlstateLabel(q.ErrorCode)).Inc()
	}
}

// ObserveTrace records every query of a trace (called before sampling).
func (m *Metrics) ObserveTrace(t correlate.Trace, c Client) {
	wait := -1.0
	if t.Client != nil {
		m.observe("client", t.Client.Q)
		if len(t.Server) > 0 && t.Server[0].Q.Start >= t.Client.Q.Start {
			wait = time.Duration(t.Server[0].Q.Start - t.Client.Q.Start).Seconds()
			m.poolWait.Observe(wait)
		}
		if m.labelled != nil {
			m.observeLabelled(t.Client.Q, wait, c)
		}
	} else if len(t.Server) > 0 && t.Server[0].Correlation != correlate.None {
		m.correlation.WithLabelValues("orphan").Add(float64(len(t.Server)))
	}
	for _, sq := range t.Server {
		m.observe("server", sq.Q)
		switch {
		case sq.Internal:
			m.correlation.WithLabelValues("internal").Inc()
		case t.Client != nil || sq.Correlation == correlate.None:
			m.correlation.WithLabelValues(sq.Correlation).Inc()
		}
	}
}

func (m *Metrics) observeLabelled(q pgwire.Query, wait float64, c Client) {
	vals := m.labelValues(c)
	l := m.labelled
	l.queries.WithLabelValues(vals...).Inc()
	l.duration.WithLabelValues(vals...).Observe(seconds(q))
	if q.ErrorCode != "" {
		l.errors.WithLabelValues(vals...).Inc()
	}
	if wait >= 0 {
		l.poolWait.WithLabelValues(vals...).Observe(wait)
	}
}

// labelValues maps a client to its label values, or to 'other' when the
// combination limit is reached.
func (m *Metrics) labelValues(c Client) []string {
	orUnknown := func(s string) string {
		if s == "" {
			return "unknown"
		}
		return s
	}
	var vals []string
	for _, n := range m.labelled.names {
		switch n {
		case "database":
			vals = append(vals, orUnknown(c.Database))
		case "user":
			vals = append(vals, orUnknown(c.User))
		case "client_addr":
			vals = append(vals, orUnknown(c.Addr))
		}
	}
	key := strings.Join(vals, "\x00")
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.sets[key]; !ok && len(m.sets) >= m.cfg.Limit {
		m.overflow.Inc()
		other := make([]string, len(vals))
		for i := range other {
			other[i] = "other"
		}
		return other
	}
	m.sets[key] = m.now()
	m.setVals[key] = vals
	m.labelSets.Set(float64(len(m.sets)))
	return vals
}

// Evict deletes label combinations idle longer than the TTL, freeing their
// slots. Called periodically.
func (m *Metrics) Evict() {
	if m.labelled == nil || m.cfg.TTL <= 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	cutoff := m.now().Add(-m.cfg.TTL)
	l := m.labelled
	for key, seen := range m.sets {
		if seen.Before(cutoff) {
			vals := m.setVals[key]
			l.queries.DeleteLabelValues(vals...)
			l.errors.DeleteLabelValues(vals...)
			l.duration.DeleteLabelValues(vals...)
			l.poolWait.DeleteLabelValues(vals...)
			delete(m.sets, key)
			delete(m.setVals, key)
		}
	}
	m.labelSets.Set(float64(len(m.sets)))
}

func (m *Metrics) SpanDecision(reason sampler.Reason, kept bool) {
	if !kept {
		m.spans.WithLabelValues("dropped").Inc()
		return
	}
	m.spans.WithLabelValues("kept_" + string(reason)).Inc()
}

func (m *Metrics) Event(kind string)                 { m.events.WithLabelValues(kind).Inc() }
func (m *Metrics) Truncation(layer string)           { m.truncations.WithLabelValues(layer).Inc() }
func (m *Metrics) SetConnections(side string, n int) { m.conns.WithLabelValues(side).Set(float64(n)) }
func (m *Metrics) SetTracedProcesses(n int)          { m.processes.Set(float64(n)) }

// RegisterKernel exposes kernel-side counters read on scrape.
func (m *Metrics) RegisterKernel(drops func() uint64, bpf func() (time.Duration, uint64), bpfStats bool) {
	m.reg.MustRegister(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Name: "pgtrace_kernel_drops_total", Help: "Events the BPF program could not enqueue (ringbuf full).",
	}, func() float64 { return float64(drops()) }))
	if !bpfStats {
		return
	}
	m.reg.MustRegister(
		prometheus.NewCounterFunc(prometheus.CounterOpts{
			Name: "pgtrace_bpf_run_seconds_total", Help: "Kernel time spent in pgtrace BPF programs (needs -bpf-stats).",
		}, func() float64 { d, _ := bpf(); return d.Seconds() }),
		prometheus.NewCounterFunc(prometheus.CounterOpts{
			Name: "pgtrace_bpf_runs_total", Help: "pgtrace BPF program runs (needs -bpf-stats).",
		}, func() float64 { _, n := bpf(); return float64(n) }),
	)
}

func opLabel(op string) string {
	op = strings.ToUpper(op)
	if operations[op] {
		return op
	}
	return "OTHER"
}

// sqlstateLabel keeps valid 5-character codes, at most maxSQLStates distinct
// ones per process; everything else is OTHER.
func (m *Metrics) sqlstateLabel(code string) string {
	if code == "" {
		return ""
	}
	if len(code) != 5 {
		return "OTHER"
	}
	for i := 0; i < 5; i++ {
		c := code[i]
		if !(c >= '0' && c <= '9' || c >= 'A' && c <= 'Z') {
			return "OTHER"
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.sqlstates[code] {
		if len(m.sqlstates) >= maxSQLStates {
			return "OTHER"
		}
		m.sqlstates[code] = true
	}
	return code
}
