package connmap

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/t1bur1an/pgtrace/internal/event"
)

const tcp4 = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:A1B2 0200000A:1538 01 00000000:00000000 00:00000000 00000000    70        0 12345 1 0000000000000000 20 4 30 10 -1
   1: 00000000:1924 00000000:0000 0A 00000000:00000000 00:00000000 00000000    70        0 222 1 0000000000000000 100 0 0 10 0
   2: 0300000A:1924 0400000A:D431 01 00000000:00000000 00:00000000 00000000    70        0 333 1 0000000000000000 20 4 30 10 -1
`

const tcp6 = `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000001000000:A000 00000000000000000000000001000000:1538 01 00000000:00000000 00:00000000 00000000    70        0 777 1 0000000000000000 20 4 30 10 -1
`

func TestParseProcNetTCP(t *testing.T) {
	m, err := parseProcNetTCP(strings.NewReader(tcp4), false)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := m[12345], netip.MustParseAddrPort("10.0.0.2:5432"); got != want {
		t.Fatalf("got %v want %v", got, want)
	}
	if got, want := m[333], netip.MustParseAddrPort("10.0.0.4:54321"); got != want {
		t.Fatalf("got %v want %v", got, want)
	}
	m6, err := parseProcNetTCP(strings.NewReader(tcp6), true)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := m6[777], netip.MustParseAddrPort("[::1]:5432"); got != want {
		t.Fatalf("v6 got %v want %v", got, want)
	}
}

func TestConnectAndClose(t *testing.T) {
	m := New(t.TempDir(), 5432)
	k := event.ConnKey{PID: 1, FD: 5}
	m.OnConnect(k, netip.MustParseAddrPort("10.0.0.2:5432"))
	if info := m.Lookup(k); !info.Server || info.Remote.Port() != 5432 {
		t.Fatalf("got %+v", info)
	}
	k2 := event.ConnKey{PID: 1, FD: 6}
	m.OnConnect(k2, netip.MustParseAddrPort("10.0.0.2:6432"))
	if m.Lookup(k2).Server {
		t.Fatal("6432 must not be a server conn")
	}
	m.OnClose(k)
	if m.Lookup(k).Server {
		t.Fatal("closed fd still server")
	}
}

func TestLookupFromProc(t *testing.T) {
	root := t.TempDir()
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(root, "42/fd"), 0o755))
	must(os.MkdirAll(filepath.Join(root, "42/net"), 0o755))
	must(os.Symlink("socket:[12345]", filepath.Join(root, "42/fd/7")))
	must(os.Symlink("socket:[333]", filepath.Join(root, "42/fd/8")))
	must(os.Symlink("/dev/null", filepath.Join(root, "42/fd/9")))
	must(os.WriteFile(filepath.Join(root, "42/net/tcp"), []byte(tcp4), 0o644))
	must(os.WriteFile(filepath.Join(root, "42/net/tcp6"), []byte(tcp6), 0o644))

	m := New(root, 5432)
	if info := m.Lookup(event.ConnKey{PID: 42, FD: 7}); !info.Server || info.Remote != netip.MustParseAddrPort("10.0.0.2:5432") {
		t.Fatalf("fd7 got %+v", info)
	}
	if m.Lookup(event.ConnKey{PID: 42, FD: 8}).Server {
		t.Fatal("client socket classified as server")
	}
	if m.Lookup(event.ConnKey{PID: 42, FD: 9}).Server {
		t.Fatal("non-socket classified as server")
	}
}
