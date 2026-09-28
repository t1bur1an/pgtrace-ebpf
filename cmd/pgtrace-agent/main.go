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
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/t1bur1an/pgtrace/internal/agent"
	"github.com/t1bur1an/pgtrace/internal/capture"
	"github.com/t1bur1an/pgtrace/internal/connmap"
	"github.com/t1bur1an/pgtrace/internal/correlate"
	"github.com/t1bur1an/pgtrace/internal/event"
	"github.com/t1bur1an/pgtrace/internal/export"
	"github.com/t1bur1an/pgtrace/internal/metrics"
	"github.com/t1bur1an/pgtrace/internal/sampler"
)

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
	flag.Parse()
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

func run(c config) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	exp, err := export.New(ctx, c.endpoint, c.service)
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

	capt, err := capture.Start(ctx, capture.Config{Comm: c.comm, ProcRoot: c.procRoot, RescanEvery: 5 * time.Second, BPFStats: c.bpfStats})
	if err != nil {
		return fmt.Errorf("start capture (needs CAP_BPF/CAP_PERFMON or privileged): %w", err)
	}
	defer capt.Close()

	reg := prometheus.NewRegistry()
	reg.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	met := metrics.New(reg)
	met.RegisterKernel(capt.Drops, capt.ProgStats, c.bpfStats)
	if c.metricsAddr != "" {
		srv := &http.Server{Addr: c.metricsAddr, Handler: promhttp.HandlerFor(reg, promhttp.HandlerOpts{})}
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
		met.ObserveTrace(tr)
		keep, reason := smp.DecideTrace(tr)
		met.SpanDecision(reason, keep)
		if keep {
			exp.ExportTrace(tr, reason, client, serverAddr)
		}
	})
	ag.Filter = capt
	ag.Metrics = met
	slog.Info("attached", "comm", c.comm, "pids", capt.Pids(), "client_tracing", c.clientTracing,
		"sample_ratio", c.ratio, "slow_ms", c.slowMS, "endpoint", c.endpoint, "metrics", c.metricsAddr)

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
				met.SetConnections("server", int(st.Server))
				met.SetConnections("client", int(st.Client))
				bpfTime, bpfRuns := capt.ProgStats()
				slog.Info("stats", "events", st.Events, "queries", st.Queries,
					"server_conns", st.Server, "client_conns", st.Client, "traces", ss["seen"],
					"kept_error", ss["kept_error"], "kept_slow", ss["kept_slow"], "kept_ratio", ss["kept_ratio"],
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
