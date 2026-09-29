// Command pgtrace-agent traces queries through pgbouncer with eBPF, links
// client queries to the server queries they cause, exports sampled traces over
// OTLP/HTTP and serves Prometheus metrics for every query.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/pprof"
	"net/netip"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/t1bur1an/pgtrace-ebpf/internal/agent"
	"github.com/t1bur1an/pgtrace-ebpf/internal/capture"
	"github.com/t1bur1an/pgtrace-ebpf/internal/connmap"
	"github.com/t1bur1an/pgtrace-ebpf/internal/correlate"
	"github.com/t1bur1an/pgtrace-ebpf/internal/event"
	"github.com/t1bur1an/pgtrace-ebpf/internal/export"
	"github.com/t1bur1an/pgtrace-ebpf/internal/metrics"
	"github.com/t1bur1an/pgtrace-ebpf/internal/pgwire"
	"github.com/t1bur1an/pgtrace-ebpf/internal/sampler"
	"github.com/t1bur1an/pgtrace-ebpf/internal/sqlcomment"
)

// version is set at build time: -ldflags "-X main.version=v1.2.3".
var version = "dev"

type config struct {
	comm, procRoot     string
	pgPort, listenPort uint
	clientTracing      bool
	ratio              float64
	slowMS             int
	endpoint, service  string
	statsEvery         time.Duration
	bpfStats           bool
	metricsAddr        string
	captureBytes       int
	maxMessage         int
	maxQueryText       int
	metricsLabels      string
	labelLimit         int
	labelTTL           time.Duration
	sqlcommenter       bool
	parentSampling     bool
	attachParamSync    bool
	pprof              bool
	debugDumpDir       string
}

func main() {
	var c config
	flag.StringVar(&c.comm, "comm", "pgbouncer", "process name to trace")
	flag.StringVar(&c.procRoot, "proc", "/proc", "procfs root (host pid namespace)")
	flag.UintVar(&c.pgPort, "pg-port", 5432, "postgres server port")
	flag.UintVar(&c.listenPort, "listen-port", 6432, "pgbouncer listen port (identifies client sockets)")
	flag.BoolVar(&c.clientTracing, "client-tracing", true, "trace client connections and link them to server queries")
	flag.Float64Var(&c.ratio, "sample-ratio", 0.1, "fraction of normal traces to keep")
	flag.IntVar(&c.slowMS, "slow-ms", 100, "always keep traces at least this slow")
	flag.StringVar(&c.endpoint, "otlp-endpoint", "http://victoriatraces:10428/insert/opentelemetry/v1/traces", "OTLP/HTTP traces URL")
	flag.StringVar(&c.service, "service-name", "pgbouncer", "service.name resource attribute")
	flag.DurationVar(&c.statsEvery, "stats-interval", 10*time.Second, "stats log interval")
	flag.BoolVar(&c.bpfStats, "bpf-stats", false, "enable kernel BPF run-time accounting")
	flag.StringVar(&c.metricsAddr, "metrics-addr", ":9464", "Prometheus /metrics listen address (empty disables)")
	flag.IntVar(&c.captureBytes, "capture-bytes", capture.DefaultCaptureBytes,
		fmt.Sprintf("payload bytes copied by the kernel per send/recv (%d…%d)", capture.MinCaptureBytes, capture.MaxCaptureBytes))
	flag.IntVar(&c.maxMessage, "max-message-bytes", pgwire.DefaultMaxMessage, "most bytes of one protocol message kept by the parser (memory is allocated per message, up to this)")
	flag.IntVar(&c.maxQueryText, "max-query-text", export.DefaultMaxQueryText, "most bytes of SQL in db.query.text")
	flag.StringVar(&c.metricsLabels, "metrics-labels", "", "opt-in per-client metric labels: comma list of database,user,client_addr")
	flag.IntVar(&c.labelLimit, "metrics-label-limit", 200, "most distinct client label combinations tracked; extra ones are recorded as 'other'")
	flag.DurationVar(&c.labelTTL, "metrics-label-ttl", 30*time.Minute, "client label combinations idle this long are removed")
	flag.BoolVar(&c.sqlcommenter, "sqlcommenter", true, "read SQLCommenter comments; a traceparent makes the application span the parent of the pgbouncer span")
	flag.BoolVar(&c.parentSampling, "sqlcommenter-parent-sampling", true, "always keep traces whose SQLCommenter parent is sampled")
	flag.StringVar(&c.debugDumpDir, "debug-dump-dir", "", "diagnostics: keep recent events per connection and dump them here when a server query is orphaned")
	flag.BoolVar(&c.pprof, "pprof", false, "serve Go profiling endpoints at /debug/pprof/ on -metrics-addr (diagnostics only)")
	flag.BoolVar(&c.attachParamSync, "attach-param-sync", true, "attach pgbouncer's parameter-sync SET/RESET statements to the client query they precede")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println("pgtrace-agent", version)
		return
	}
	applyEnv()

	if err := run(c); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

// applyEnv lets PGTRACE_<FLAG_NAME> override flags that were not set on the
// command line, e.g. PGTRACE_SAMPLE_RATIO=0.5.
func applyEnv() {
	set := map[string]bool{}
	flag.Visit(func(f *flag.Flag) { set[f.Name] = true })
	flag.VisitAll(func(f *flag.Flag) {
		env := "PGTRACE_" + strings.ToUpper(strings.ReplaceAll(f.Name, "-", "_"))
		if v, ok := os.LookupEnv(env); ok && !set[f.Name] {
			if err := f.Value.Set(v); err != nil {
				slog.Error("bad env value", "env", env, "err", err)
				os.Exit(2)
			}
		}
	})
}

func (c config) validate() ([]string, error) {
	if c.maxMessage < 64 {
		return nil, fmt.Errorf("-max-message-bytes must be at least 64")
	}
	if c.maxQueryText < 16 {
		return nil, fmt.Errorf("-max-query-text must be at least 16")
	}
	var labels []string
	for _, l := range strings.Split(c.metricsLabels, ",") {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		if !slices.Contains(metrics.LabelNames, l) {
			return nil, fmt.Errorf("-metrics-labels: unknown label %q (want %s)", l, strings.Join(metrics.LabelNames, ","))
		}
		labels = append(labels, l)
	}
	if len(labels) > 0 && c.labelLimit < 1 {
		return nil, fmt.Errorf("-metrics-label-limit must be at least 1")
	}
	return labels, nil
}

func run(c config) error {
	labels, err := c.validate()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	reg := prometheus.NewRegistry()
	reg.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	met := metrics.NewWith(reg, metrics.Config{Labels: labels, Limit: c.labelLimit, TTL: c.labelTTL})
	created, exported, failed := met.ExportHooks()
	hooks := export.Hooks{Created: created, Exported: exported, Failed: failed}
	exp, err := export.New(ctx, c.endpoint, c.service, hooks)
	if err != nil {
		return err
	}
	defer func() {
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := exp.Shutdown(sctx); err != nil {
			slog.Warn("exporter shutdown", "err", err)
		}
	}()

	capt, err := capture.Start(ctx, capture.Config{Comm: c.comm, ProcRoot: c.procRoot, RescanEvery: 5 * time.Second,
		BPFStats: c.bpfStats, CaptureBytes: c.captureBytes})
	if err != nil {
		return fmt.Errorf("start capture (needs CAP_BPF/CAP_PERFMON or privileged): %w", err)
	}
	defer capt.Close()

	exp.SetOptions(export.Options{MaxQueryText: c.maxQueryText, OnTruncate: func() { met.Truncation("export") }, Hooks: hooks})
	met.RegisterKernel(capt.Drops, capt.ProgStats, c.bpfStats)
	if c.metricsAddr != "" {
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
		if c.pprof {
			mux.HandleFunc("/debug/pprof/", pprof.Index)
			mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
			mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
			mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
		}
		srv := &http.Server{Addr: c.metricsAddr, Handler: mux}
		go func() {
			if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				slog.Error("metrics server", "err", err)
			}
		}()
		defer srv.Close()
	}

	cm := connmap.New(connmap.Config{ProcRoot: c.procRoot, PGPort: uint16(c.pgPort), ListenPort: uint16(c.listenPort), ClientTracing: c.clientTracing})
	// Peek, not Lookup: an orphan's server may already be closed, and
	// resolving its fd number again could cache a reused fd's details.
	serverAddr := func(k event.ConnKey) netip.AddrPort { info, _ := cm.Peek(k); return info.Remote }
	smp := sampler.New(c.ratio, time.Duration(c.slowMS)*time.Millisecond, uint64(time.Now().UnixNano()))
	ag := agent.New(cm, func(tr correlate.Trace, client export.ClientInfo) {
		met.ObserveTrace(tr, metricsClient(client))
		if c.sqlcommenter && tr.Client != nil {
			client = withComment(client, tr.Client.Q, met)
		}
		keep, reason := smp.DecideTraceIdle(tr, c.parentSampling && client.UseParent && export.Sampled(client.Comment), client.IdleInTx)
		met.SpanDecision(reason, keep)
		if keep {
			exp.ExportTrace(tr, reason, client, serverAddr)
		}
	})
	ag.Filter = capt
	ag.Metrics = met
	ag.Parser = pgwire.Options{MaxMessage: c.maxMessage}
	ag.OnConnError = exp.ExportConnError // always exported: errors are always kept
	ag.SetAttachParamSync(c.attachParamSync)
	ag.DumpDir = c.debugDumpDir
	slog.Info("attached", "version", version, "comm", c.comm, "pids", capt.Pids(), "client_tracing", c.clientTracing,
		"sample_ratio", c.ratio, "slow_ms", c.slowMS, "endpoint", c.endpoint, "metrics", c.metricsAddr,
		"capture_bytes", c.captureBytes, "max_message_bytes", c.maxMessage, "max_query_text", c.maxQueryText,
		"metrics_labels", labels, "metrics_label_limit", c.labelLimit, "sqlcommenter", c.sqlcommenter, "attach_param_sync", c.attachParamSync)

	go func() {
		t := time.NewTicker(c.statsEvery)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				st, ss, cs := ag.Stats(), smp.Stats(), ag.CorrelationStats()
				met.SetTracedProcesses(len(capt.Pids()))
				met.Evict()
				met.SetConnections("server", int(st.Server))
				met.SetConnections("client", int(st.Client))
				bpfTime, bpfRuns := capt.ProgStats()
				slog.Info("stats", "events", st.Events, "queries", st.Queries,
					"server_conns", st.Server, "client_conns", st.Client, "traces", ss["seen"],
					"kept_error", ss["kept_error"], "kept_slow", ss["kept_slow"], "kept_parent", ss["kept_parent"], "kept_ratio", ss["kept_ratio"],
					"corr_exact", cs[correlate.Exact], "corr_inferred", cs[correlate.Inferred], "corr_none", cs[correlate.None],
					"corr_internal", cs["internal"], "corr_orphan", cs["orphan"],
					"kernel_drops", capt.Drops(), "bpf_runs", bpfRuns, "bpf_ns", bpfTime.Nanoseconds())
			}
		}
	}()

	ag.Run(ctx, capt.Events)
	slog.Info("shutting down")
	return nil
}

// metricsClient maps a trace's client details to metric label values. Clients
// without an address are unix-socket clients.
func metricsClient(c export.ClientInfo) metrics.Client {
	addr := "unix"
	if c.Addr.IsValid() {
		addr = c.Addr.Addr().String()
	}
	return metrics.Client{Database: c.Params["database"], User: c.Params["user"], Addr: addr}
}

// withComment attaches the client query's SQLCommenter comment. Its trace
// context is used only if the SQL was sent for this execution: a traceparent
// inside a reused prepared statement belongs to whichever request prepared it.
func withComment(client export.ClientInfo, q pgwire.Query, met *metrics.Metrics) export.ClientInfo {
	cm, ok := sqlcomment.Parse(q.SQL)
	if !ok {
		return client
	}
	client.Comment = cm
	switch {
	case cm.Valid && q.PerExecution:
		client.UseParent = true
		met.TraceContext("linked")
	case cm.Valid:
		met.TraceContext("not_per_execution")
	case cm.HadContext:
		met.TraceContext("invalid")
	}
	return client
}
