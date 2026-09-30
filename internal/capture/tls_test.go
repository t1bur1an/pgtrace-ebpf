package capture

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
)

func TestLibsslPath(t *testing.T) {
	maps := `55d0a0a00000-55d0a0a2c000 r--p 00000000 00:3a 1234 /usr/bin/pgbouncer
7f1c2a000000-7f1c2a05f000 r--p 00000000 00:3a 5678 /usr/lib/libcrypto.so.3
7f1c2b000000-7f1c2b01f000 r--p 00000000 00:3a 9012 /usr/lib/libssl.so.3
7f1c2b01f000-7f1c2b07f000 r-xp 0001f000 00:3a 9012 /usr/lib/libssl.so.3
7ffd00000000-7ffd00021000 rw-p 00000000 00:00 0 [stack]
`
	if p, ok := libsslPath(strings.NewReader(maps)); !ok || p != "/usr/lib/libssl.so.3" {
		t.Fatalf("got %q %v", p, ok)
	}
	if _, ok := libsslPath(strings.NewReader("7f1c2a000000-7f1c2a05f000 r--p 00000000 00:3a 5678 /usr/lib/libcrypto.so.3\n")); ok {
		t.Fatal("found libssl in a listing without it")
	}
}

func TestImportsAll(t *testing.T) {
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("no C compiler")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "fx.c")
	os.WriteFile(src, []byte("int SSL_read(void*,void*,int); int SSL_write(void*,const void*,int);\n"+
		"int f(void){ return SSL_read(0,0,0) + SSL_write(0,0,0); }\n"), 0o644)
	so := filepath.Join(dir, "fx.so")
	if out, err := exec.Command(cc, "-shared", "-fPIC", "-o", so, src).CombinedOutput(); err != nil {
		t.Skipf("cc failed: %v %s", err, out)
	}
	if ok, err := importsAll(so, "SSL_read", "SSL_write"); err != nil || !ok {
		t.Fatalf("got %v %v", ok, err)
	}
	if ok, _ := importsAll(so, "SSL_read", "SSL_read_ex"); ok {
		t.Fatal("reported an import the object doesn't have")
	}
}

type fakeProc struct{ closed *int }

func (f fakeProc) Close() error { *f.closed++; return nil }

func TestTLSSyncAttachesAndDetaches(t *testing.T) {
	closed := 0
	tc := &tlsCapture{procs: map[uint32]tlsProcess{}, unsupported: map[uint32]bool{}}
	tc.attach = func(pid uint32) (tlsProcess, error) {
		if pid == 3 {
			return nil, errors.New("no libssl")
		}
		return fakeProc{&closed}, nil
	}
	tc.sync(map[uint32]bool{1: true, 2: true, 3: true}, time.Unix(0, 0))
	if a, u := tc.counts(); a != 2 || u != 1 {
		t.Fatalf("attached %d unsupported %d", a, u)
	}
	// pgbouncer 2 restarted as 4; 3 exited.
	tc.sync(map[uint32]bool{1: true, 4: true}, time.Unix(0, 0))
	if a, u := tc.counts(); a != 2 || u != 0 || closed != 1 {
		t.Fatalf("attached %d unsupported %d closed %d", a, u, closed)
	}
	// An unsupported pid is not retried on every rescan.
	calls := 0
	tc.attach = func(uint32) (tlsProcess, error) { calls++; return nil, errors.New("x") }
	tc.sync(map[uint32]bool{1: true, 4: true, 5: true}, time.Unix(0, 0))
	tc.sync(map[uint32]bool{1: true, 4: true, 5: true}, time.Unix(0, 0))
	if calls != 1 {
		t.Fatalf("attach called %d times for one unsupported pid", calls)
	}
}

// Session state of a pgbouncer that exits without SSL_free (killed,
// restarted) must not fill the maps for good: they evict the oldest entries.
func TestTLSMapsEvictOldEntries(t *testing.T) {
	spec, err := loadTls()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"tls_sessions", "tls_current", "tls_info_ssl"} {
		if typ := spec.Maps[name].Type; typ != ebpf.LRUHash {
			t.Errorf("%s is %v, want LRUHash", name, typ)
		}
	}
}

func TestFallbackAttachFailureNotRetried(t *testing.T) {
	calls := 0
	tc := &tlsCapture{procs: map[uint32]tlsProcess{}, unsupported: map[uint32]bool{}}
	tc.attachFallback = func() (func(), error) { calls++; return nil, errors.New("ksys_read not attachable") }
	now := time.Unix(1000, 0)
	for i := 0; i < 100; i++ {
		tc.need(now.Add(time.Duration(i) * time.Millisecond))
	}
	if calls != 1 || tc.fallbackAttached() {
		t.Fatalf("attach tried %d times, attached=%v", calls, tc.fallbackAttached())
	}
	// Retried only after a long back-off.
	tc.need(now.Add(fallbackRetry + time.Second))
	if calls != 2 {
		t.Fatalf("attach tried %d times after the back-off", calls)
	}
}

func TestFallbackAttachAndExpire(t *testing.T) {
	calls, closed := 0, 0
	tc := &tlsCapture{procs: map[uint32]tlsProcess{}, unsupported: map[uint32]bool{}}
	tc.attachFallback = func() (func(), error) { calls++; return func() { closed++ }, nil }
	now := time.Unix(1000, 0)
	tc.need(now)
	tc.need(now.Add(10 * time.Second))
	tc.expire(now.Add(35 * time.Second)) // 25 s after the last need: stays
	if calls != 1 || !tc.fallbackAttached() {
		t.Fatalf("calls %d attached %v", calls, tc.fallbackAttached())
	}
	tc.expire(now.Add(41 * time.Second))
	if tc.fallbackAttached() || closed != 1 {
		t.Fatalf("attached %v closed %d", tc.fallbackAttached(), closed)
	}
}

// A pgbouncer caught before ld.so mapped libssl (comm is set at exec) is
// retried; only a lasting failure makes it unsupported.
func TestTransientAttachFailureRetried(t *testing.T) {
	closed, calls := 0, 0
	tc := &tlsCapture{procs: map[uint32]tlsProcess{}, unsupported: map[uint32]bool{}}
	tc.attach = func(uint32) (tlsProcess, error) {
		calls++
		if calls == 1 {
			return nil, fmt.Errorf("%w: no libssl mapped", errTransient)
		}
		return fakeProc{&closed}, nil
	}
	now := time.Unix(1000, 0)
	tc.sync(map[uint32]bool{7: true}, now)
	if a, u := tc.counts(); a != 0 || u != 0 {
		t.Fatalf("after a transient failure: attached %d unsupported %d", a, u)
	}
	tc.sync(map[uint32]bool{7: true}, now.Add(5*time.Second))
	if a, u := tc.counts(); a != 1 || u != 0 {
		t.Fatalf("after the retry: attached %d unsupported %d", a, u)
	}
	// A failure that keeps being transient gives up after transientRetry.
	tc.attach = func(uint32) (tlsProcess, error) { return nil, fmt.Errorf("%w: no libssl mapped", errTransient) }
	tc.sync(map[uint32]bool{7: true, 8: true}, now)
	tc.sync(map[uint32]bool{7: true, 8: true}, now.Add(transientRetry+time.Second))
	if a, u := tc.counts(); a != 1 || u != 1 {
		t.Fatalf("attached %d unsupported %d", a, u)
	}
}

// A return probe attached after its entry probe could miss the return of a
// call already in progress, leaving a stale per-thread entry.
func TestReturnProbesAttachedBeforeEntries(t *testing.T) {
	seenEntry := map[string]bool{}
	for _, p := range tlsProbes(&tlsObjects{}) {
		if p.ret && seenEntry[p.sym] {
			t.Errorf("%s: return probe attached after its entry probe", p.sym)
		}
		if !p.ret {
			seenEntry[p.sym] = true
		}
	}
}
