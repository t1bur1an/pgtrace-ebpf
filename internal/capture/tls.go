package capture

import (
	"bufio"
	"debug/elf"
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
)

// fallbackIdle is how long the socket-finding fallback stays attached after
// the last TLS event without a socket.
const fallbackIdle = 30 * time.Second

// tlsProcess is the probes attached to one pgbouncer process.
type tlsProcess interface{ Close() error }

type tlsProc struct {
	ex    *link.Executable
	links []link.Link
	ret   link.Link // SSL_write return probe, only while the fallback is on
}

func (p *tlsProc) Close() error {
	for _, l := range p.links {
		l.Close()
	}
	if p.ret != nil {
		p.ret.Close()
	}
	return nil
}

// tlsCapture attaches the TLS plaintext probes to every traced process and
// runs the fallback for sessions opened before the agent.
type tlsCapture struct {
	objs     tlsObjects
	procRoot string
	attach   func(pid uint32) (tlsProcess, error)

	mu          sync.Mutex
	procs       map[uint32]tlsProcess
	unsupported map[uint32]bool
	fallback    []link.Link // fentry ksys_read/ksys_write
	fbOn        bool
	lastNeed    time.Time
}

func newTLSCapture(c *Capture, procRoot string, captureBytes int) (*tlsCapture, error) {
	spec, err := loadTls()
	if err != nil {
		return nil, fmt.Errorf("load tls spec: %w", err)
	}
	if err := spec.Variables["capture_bytes"].Set(uint32(captureBytes)); err != nil {
		return nil, fmt.Errorf("set capture_bytes: %w", err)
	}
	t := &tlsCapture{procRoot: procRoot, procs: map[uint32]tlsProcess{}, unsupported: map[uint32]bool{}}
	opts := &ebpf.CollectionOptions{MapReplacements: map[string]*ebpf.Map{
		"target_pids": c.objs.TargetPids, "fd_class": c.objs.FdClass, "events": c.objs.Events,
		"scratch": c.objs.Scratch, "drops": c.objs.Drops,
	}}
	if err := spec.LoadAndAssign(&t.objs, opts); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return nil, fmt.Errorf("load tls bpf: %+v", ve)
		}
		return nil, fmt.Errorf("load tls bpf: %w", err)
	}
	t.attach = t.attachProcess
	return t, nil
}

func (t *tlsCapture) programs() []*ebpf.Program {
	o := &t.objs
	return []*ebpf.Program{o.SslWrite, o.SslWriteRet, o.SslReadEnter, o.SslReadExit, o.SslSetRfd, o.SslFree,
		o.SslVerEnter, o.SslVerExit, o.SslCipherExit, o.FallbackRead, o.FallbackWrite}
}

// attachProcess attaches the probes to one pgbouncer process's libssl.
func (t *tlsCapture) attachProcess(pid uint32) (tlsProcess, error) {
	dir := filepath.Join(t.procRoot, strconv.FormatUint(uint64(pid), 10))
	ok, err := importsAll(filepath.Join(dir, "exe"), "SSL_read", "SSL_write")
	if err != nil {
		return nil, fmt.Errorf("read executable: %w", err)
	}
	if !ok {
		return nil, errors.New("unsupported TLS API (pgbouncer doesn't import SSL_read/SSL_write)")
	}
	f, err := os.Open(filepath.Join(dir, "maps"))
	if err != nil {
		return nil, err
	}
	lib, found := libsslPath(f)
	f.Close()
	if !found {
		return nil, errors.New("no libssl mapped")
	}
	ex, err := link.OpenExecutable(filepath.Join(dir, "root", lib))
	if err != nil {
		return nil, err
	}
	p := &tlsProc{ex: ex}
	opt := &link.UprobeOptions{PID: int(pid)}
	o := &t.objs
	for _, a := range []struct {
		sym  string
		prog *ebpf.Program
		ret  bool
	}{
		{"SSL_set_rfd", o.SslSetRfd, false}, {"SSL_free", o.SslFree, false},
		{"SSL_read", o.SslReadEnter, false}, {"SSL_read", o.SslReadExit, true},
		{"SSL_get_version", o.SslVerEnter, false}, {"SSL_get_version", o.SslVerExit, true},
		{"SSL_CIPHER_get_name", o.SslCipherExit, true},
		{"SSL_write", o.SslWrite, false},
	} {
		var l link.Link
		if a.ret {
			l, err = ex.Uretprobe(a.sym, a.prog, opt)
		} else {
			l, err = ex.Uprobe(a.sym, a.prog, opt)
		}
		if err != nil {
			p.Close()
			return nil, fmt.Errorf("attach %s: %w", a.sym, err)
		}
		p.links = append(p.links, l)
	}
	return p, nil
}

// sync attaches to new pids and detaches from gone ones. Unsupported pids
// are remembered and not retried.
func (t *tlsCapture) sync(pids map[uint32]bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for pid := range pids {
		if t.procs[pid] != nil || t.unsupported[pid] {
			continue
		}
		p, err := t.attach(pid)
		if err != nil {
			slog.Warn("tls capture unavailable for process", "pid", pid, "err", err)
			t.unsupported[pid] = true
			continue
		}
		t.procs[pid] = p
		if t.fbOn {
			t.attachRet(pid, p)
		}
		slog.Info("tls probes attached", "pid", pid)
	}
	for pid, p := range t.procs {
		if !pids[pid] {
			p.Close()
			delete(t.procs, pid)
		}
	}
	for pid := range t.unsupported {
		if !pids[pid] {
			delete(t.unsupported, pid)
		}
	}
}

func (t *tlsCapture) counts() (attached, unsupported int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.procs), len(t.unsupported)
}

func (t *tlsCapture) attachRet(pid uint32, p tlsProcess) {
	tp, ok := p.(*tlsProc)
	if !ok || tp.ret != nil {
		return
	}
	l, err := tp.ex.Uretprobe("SSL_write", t.objs.SslWriteRet, &link.UprobeOptions{PID: int(pid)})
	if err != nil {
		slog.Warn("tls fallback: attach SSL_write return", "pid", pid, "err", err)
		return
	}
	tp.ret = l
}

// need attaches the fallback, or keeps it attached.
func (t *tlsCapture) need(now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.lastNeed = now
	if t.fbOn {
		return
	}
	// A call interrupted by an earlier detach may have left a stale entry.
	var k uint64
	var keys []uint64
	it := t.objs.TlsCurrent.Iterate()
	var v tlsCur
	for it.Next(&k, &v) {
		keys = append(keys, k)
	}
	for _, k := range keys {
		_ = t.objs.TlsCurrent.Delete(k)
	}
	for _, prog := range []*ebpf.Program{t.objs.FallbackRead, t.objs.FallbackWrite} {
		l, err := link.AttachTracing(link.TracingOptions{Program: prog})
		if err != nil {
			slog.Warn("tls fallback unavailable: sessions opened before the agent stay untraced", "err", err)
			t.detachLocked()
			t.lastNeed = now.Add(24 * time.Hour) // don't retry on every event
			return
		}
		t.fallback = append(t.fallback, l)
	}
	for pid, p := range t.procs {
		t.attachRet(pid, p)
	}
	_ = t.objs.TlsFallback.Put(uint32(0), uint32(1))
	t.fbOn = true
	slog.Info("tls fallback attached")
}

// expire detaches the fallback after fallbackIdle without a need.
func (t *tlsCapture) expire(now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.fbOn && now.Sub(t.lastNeed) > fallbackIdle {
		t.detachLocked()
		slog.Info("tls fallback detached")
	}
}

func (t *tlsCapture) detachLocked() {
	_ = t.objs.TlsFallback.Put(uint32(0), uint32(0))
	for _, l := range t.fallback {
		l.Close()
	}
	t.fallback = nil
	for _, p := range t.procs {
		if tp, ok := p.(*tlsProc); ok && tp.ret != nil {
			tp.ret.Close()
			tp.ret = nil
		}
	}
	t.fbOn = false
}

func (t *tlsCapture) fallbackAttached() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.fbOn
}

func (t *tlsCapture) close() {
	t.mu.Lock()
	t.detachLocked()
	for pid, p := range t.procs {
		p.Close()
		delete(t.procs, pid)
	}
	t.mu.Unlock()
	t.objs.Close()
}

// libsslPath returns the path of the first libssl.so* in a /proc/<pid>/maps
// listing, as seen inside the process's mount namespace.
func libsslPath(maps io.Reader) (string, bool) {
	s := bufio.NewScanner(maps)
	for s.Scan() {
		f := strings.Fields(s.Text())
		if len(f) >= 6 && strings.HasPrefix(filepath.Base(f[5]), "libssl.so") {
			return f[5], true
		}
	}
	return "", false
}

// importsAll reports whether the ELF file imports every named dynamic symbol.
func importsAll(path string, names ...string) (bool, error) {
	f, err := elf.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	syms, err := f.ImportedSymbols()
	if err != nil {
		return false, err
	}
	have := map[string]bool{}
	for _, s := range syms {
		have[s.Name] = true
	}
	for _, n := range names {
		if !have[n] {
			return false, nil
		}
	}
	return true, nil
}
