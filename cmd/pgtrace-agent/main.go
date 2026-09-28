// Command pgtrace-agent traces pgbouncer→postgres queries with eBPF and
// exports sampled spans over OTLP/HTTP.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/t1bur1an/pgtrace/internal/agent"
	"github.com/t1bur1an/pgtrace/internal/capture"
	"github.com/t1bur1an/pgtrace/internal/connmap"
	"github.com/t1bur1an/pgtrace/internal/export"
	"github.com/t1bur1an/pgtrace/internal/sampler"
)

func main() {
	var (
		comm       = flag.String("comm", "pgbouncer", "process name to trace")
		procRoot   = flag.String("proc", "/proc", "procfs root (host pid namespace)")
		pgPort     = flag.Uint("pg-port", 5432, "postgres server port")
		ratio      = flag.Float64("sample-ratio", 0.1, "fraction of normal queries to keep")
		slowMS     = flag.Int("slow-ms", 100, "always keep queries at least this slow")
		endpoint   = flag.String("otlp-endpoint", "http://victoriatraces:10428/insert/opentelemetry/v1/traces", "OTLP/HTTP traces URL")
		service    = flag.String("service-name", "pgbouncer", "service.name resource attribute")
		statsEvery = flag.Duration("stats-interval", 10*time.Second, "stats log interval")
		bpfStats   = flag.Bool("bpf-stats", false, "enable kernel BPF run-time accounting and log it")
	)
	flag.Parse()
	applyEnv()

	if err := run(*comm, *procRoot, uint16(*pgPort), *ratio, time.Duration(*slowMS)*time.Millisecond, *endpoint, *service, *statsEvery, *bpfStats); err != nil {
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

func run(comm, procRoot string, pgPort uint16, ratio float64, slow time.Duration, endpoint, service string, statsEvery time.Duration, bpfStats bool) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	exp, err := export.New(ctx, endpoint, service)
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

	capt, err := capture.Start(ctx, capture.Config{Comm: comm, ProcRoot: procRoot, RescanEvery: 5 * time.Second, BPFStats: bpfStats})
	if err != nil {
		return fmt.Errorf("start capture (needs CAP_BPF/CAP_PERFMON or privileged): %w", err)
	}
	defer capt.Close()

	smp := sampler.New(ratio, slow, uint64(time.Now().UnixNano()))
	ag := agent.New(connmap.New(procRoot, pgPort), smp, exp.Export)
	ag.Filter = capt
	slog.Info("attached", "comm", comm, "pids", capt.Pids(), "sample_ratio", ratio, "slow", slow, "endpoint", endpoint)

	go func() {
		t := time.NewTicker(statsEvery)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				st, ss := ag.Stats(), smp.Stats()
				bpfTime, bpfRuns := capt.ProgStats()
				slog.Info("stats", "events", st.Events, "queries", st.Queries, "server_conns", st.Conns,
					"kept_error", ss["kept_error"], "kept_slow", ss["kept_slow"], "kept_ratio", ss["kept_ratio"],
					"kernel_drops", capt.Drops(), "bpf_runs", bpfRuns, "bpf_ns", bpfTime.Nanoseconds())
			}
		}
	}()

	ag.Run(ctx, capt.Events)
	slog.Info("shutting down")
	return nil
}
