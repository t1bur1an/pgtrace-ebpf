// Package capture loads the BPF program, keeps its target pid set in sync with
// the running pgbouncer processes and streams decoded events.
package capture

import (
	"context"
	"errors"
	"fmt"
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
)

type Config struct {
	Comm        string        // process name to trace, e.g. "pgbouncer"
	ProcRoot    string        // usually /proc (host pid namespace)
	RescanEvery time.Duration // pid discovery interval
}

// Capture delivers event.Data, event.Connect and event.Close values on Events.
type Capture struct {
	Events <-chan any

	objs   pgtraceObjects
	links  []link.Link
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
	progs := map[string]*ebpf.Program{
		"sys_enter_sendto":   c.objs.EnterSendto,
		"sys_exit_sendto":    c.objs.ExitSendto,
		"sys_enter_recvfrom": c.objs.EnterRecvfrom,
		"sys_exit_recvfrom":  c.objs.ExitRecvfrom,
		"sys_enter_write":    c.objs.EnterWrite,
		"sys_exit_write":     c.objs.ExitWrite,
		"sys_enter_read":     c.objs.EnterRead,
		"sys_exit_read":      c.objs.ExitRead,
		"sys_enter_connect":  c.objs.EnterConnect,
		"sys_exit_connect":   c.objs.ExitConnect,
		"sys_enter_close":    c.objs.EnterClose,
	}
	for name, prog := range progs {
		l, err := link.Tracepoint("syscalls", name, prog, nil)
		if err != nil {
			c.Close()
			return nil, fmt.Errorf("attach %s: %w", name, err)
		}
		c.links = append(c.links, l)
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
		for {
			if err := rd.ReadInto(&rec); err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
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

func (c *Capture) Close() error {
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
