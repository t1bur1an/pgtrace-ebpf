// Package capture loads the BPF program, keeps its target pid set in sync with
// the running pgbouncer processes and streams decoded events.
package capture

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/t1bur1an/pgtrace/internal/event"
	"golang.org/x/sys/unix"
)

type Config struct {
	Comm        string        // process name to trace, e.g. "pgbouncer"
	ProcRoot    string        // usually /proc (host pid namespace)
	RescanEvery time.Duration // pid discovery interval
	BPFStats    bool          // enable kernel run-time accounting (small per-run cost)
}

// pollInterval bounds how long events wait in the ring: the BPF side only
// wakes the reader when a lot of data is pending.
const pollInterval = 20 * time.Millisecond

const classIgnore = uint8(2)

// fdKey matches struct fd_key in bpf/pgtrace.bpf.c.
type fdKey struct {
	TGID uint32
	FD   int32
}

// Capture delivers event.Data, event.Connect, event.Accept and event.Close
// values on Events.
type Capture struct {
	Events <-chan any

	objs   pgtraceObjects
	links  []link.Link
	progs  []*ebpf.Program
	stats  io.Closer // keeps kernel BPF run-time accounting enabled
	reader *ringbuf.Reader
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu   sync.Mutex
	pids map[uint32]bool
}

func Start(ctx context.Context, cfg Config) (*Capture, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}
	c := &Capture{pids: map[uint32]bool{}}
	if err := loadPgtraceObjects(&c.objs, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return nil, fmt.Errorf("load bpf: %+v", ve)
		}
		return nil, fmt.Errorf("load bpf: %w", err)
	}
	for _, prog := range []*ebpf.Program{c.objs.ExitSendto, c.objs.ExitRecvfrom, c.objs.ExitConnect, c.objs.ExitAccept4, c.objs.EnterClose} {
		l, err := link.AttachTracing(link.TracingOptions{Program: prog})
		if err != nil {
			c.Close()
			return nil, fmt.Errorf("attach %s: %w", prog, err)
		}
		c.links = append(c.links, l)
		c.progs = append(c.progs, prog)
	}
	// Run-time accounting costs two clock reads per program run; it is only
	// used for the stats log, so failure to enable it is not fatal.
	if cfg.BPFStats {
		if st, err := ebpf.EnableStats(uint32(unix.BPF_STATS_RUN_TIME)); err != nil {
			slog.Warn("bpf run-time stats unavailable", "err", err)
		} else {
			c.stats = st
		}
	}
	rd, err := ringbuf.NewReader(c.objs.Events)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("ringbuf reader: %w", err)
	}
	c.reader = rd

	ctx, c.cancel = context.WithCancel(ctx)
	events := make(chan any, 65536)
	c.Events = events
	c.rescan(cfg)
	c.wg.Add(2)
	go func() {
		defer c.wg.Done()
		t := time.NewTicker(cfg.RescanEvery)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				c.rescan(cfg)
			}
		}
	}()
	go func() {
		defer c.wg.Done()
		defer close(events)
		var rec ringbuf.Record
		rd.SetDeadline(time.Now().Add(pollInterval))
		for {
			if err := rd.ReadInto(&rec); err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				if errors.Is(err, os.ErrDeadlineExceeded) {
					rd.SetDeadline(time.Now().Add(pollInterval))
					continue
				}
				slog.Warn("ringbuf read", "err", err)
				continue
			}
			ev, err := decode(rec.RawSample)
			if err != nil {
				slog.Warn("decode event", "err", err)
				continue
			}
			select {
			case events <- ev:
			case <-ctx.Done():
				return
			}
		}
	}()
	return c, nil
}

// rescan updates the kernel's target pid set from /proc/*/comm.
func (c *Capture) rescan(cfg Config) {
	found := map[uint32]bool{}
	entries, err := os.ReadDir(cfg.ProcRoot)
	if err != nil {
		slog.Warn("scan proc", "err", err)
		return
	}
	for _, e := range entries {
		pid, err := strconv.ParseUint(e.Name(), 10, 32)
		if err != nil {
			continue
		}
		comm, err := os.ReadFile(filepath.Join(cfg.ProcRoot, e.Name(), "comm"))
		if err == nil && strings.TrimSpace(string(comm)) == cfg.Comm {
			found[uint32(pid)] = true
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	one := uint8(1)
	for pid := range found {
		if !c.pids[pid] {
			if err := c.objs.TargetPids.Put(pid, one); err != nil {
				slog.Warn("add target pid", "pid", pid, "err", err)
				continue
			}
			slog.Info("tracing process", "comm", cfg.Comm, "pid", pid)
		}
	}
	for pid := range c.pids {
		if !found[pid] {
			_ = c.objs.TargetPids.Delete(pid)
			slog.Info("process gone", "pid", pid)
		}
	}
	c.pids = found
}

// Pids returns the currently traced pids.
func (c *Capture) Pids() []uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]uint32, 0, len(c.pids))
	for p := range c.pids {
		out = append(out, p)
	}
	return out
}

// Ignore stops payload capture for a socket that is not a server connection.
func (c *Capture) Ignore(k event.ConnKey) {
	_ = c.objs.FdClass.Put(fdKey{k.PID, k.FD}, classIgnore)
}

// Clear makes a socket unclassified again.
func (c *Capture) Clear(k event.ConnKey) {
	_ = c.objs.FdClass.Delete(fdKey{k.PID, k.FD})
}

// Drops returns the number of events the kernel failed to enqueue.
func (c *Capture) Drops() uint64 {
	var perCPU []uint64
	if err := c.objs.Drops.Lookup(uint32(0), &perCPU); err != nil {
		return 0
	}
	var sum uint64
	for _, v := range perCPU {
		sum += v
	}
	return sum
}

// ProgStats returns total kernel time spent in, and number of runs of, all
// attached programs. Both are zero when run-time stats are unavailable.
func (c *Capture) ProgStats() (runtime time.Duration, runs uint64) {
	for _, p := range c.progs {
		if st, err := p.Stats(); err == nil {
			runtime += st.Runtime
			runs += st.RunCount
		}
	}
	return
}

func (c *Capture) Close() error {
	if c.stats != nil {
		c.stats.Close()
	}
	if c.cancel != nil {
		c.cancel()
	}
	for _, l := range c.links {
		l.Close()
	}
	if c.reader != nil {
		c.reader.Close()
	}
	c.wg.Wait()
	return c.objs.Close()
}
