// Package metrics exposes Prometheus metrics computed from every query the
// agent sees, independent of span sampling.
package metrics

import (
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/t1bur1an/pgtrace/internal/correlate"
	"github.com/t1bur1an/pgtrace/internal/pgwire"
	"github.com/t1bur1an/pgtrace/internal/sampler"
)

var buckets = prometheus.ExponentialBuckets(50e-6, 2.5, 12) // 50µs … ~1.2s·2.5

// operations bounds the operation label; anything else is OTHER.
var operations = map[string]bool{}

func init() {
	for _, op := range strings.Fields(`SELECT INSERT UPDATE DELETE BEGIN COMMIT END ROLLBACK SET SHOW WITH COPY
		CREATE ALTER DROP TRUNCATE VACUUM ANALYZE EXPLAIN CALL DO FETCH DECLARE CLOSE DISCARD LISTEN
		NOTIFY PREPARE EXECUTE DEALLOCATE RESET LOCK GRANT REVOKE COMMENT MERGE`) {
		operations[op] = true
	}
}

type Metrics struct {
	queries     *prometheus.CounterVec
	duration    *prometheus.HistogramVec
	errors      *prometheus.CounterVec
	poolWait    prometheus.Histogram
	correlation *prometheus.CounterVec
	spans       *prometheus.CounterVec
	events      *prometheus.CounterVec
	conns       *prometheus.GaugeVec
	processes   prometheus.Gauge
	reg         prometheus.Registerer
}

func New(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		reg: reg,
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
		conns: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "pgtrace_connections", Help: "Tracked pgbouncer sockets, by side.",
		}, []string{"side"}),
		processes: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "pgtrace_traced_processes", Help: "pgbouncer processes being traced.",
		}),
	}
	reg.MustRegister(m.queries, m.duration, m.errors, m.poolWait, m.correlation, m.spans, m.events, m.conns, m.processes)
	return m
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
		m.errors.WithLabelValues(side, sqlstateLabel(q.ErrorCode)).Inc()
	}
}

// ObserveTrace records every query of a trace (called before sampling).
func (m *Metrics) ObserveTrace(t correlate.Trace) {
	if t.Client != nil {
		m.observe("client", t.Client.Q)
		if len(t.Server) > 0 && t.Server[0].Q.Start >= t.Client.Q.Start {
			m.poolWait.Observe(time.Duration(t.Server[0].Q.Start - t.Client.Q.Start).Seconds())
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

func (m *Metrics) SpanDecision(reason sampler.Reason, kept bool) {
	if !kept {
		m.spans.WithLabelValues("dropped").Inc()
		return
	}
	m.spans.WithLabelValues("kept_" + string(reason)).Inc()
}

func (m *Metrics) Event(kind string)                 { m.events.WithLabelValues(kind).Inc() }
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

func sqlstateLabel(code string) string {
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
	return code
}
