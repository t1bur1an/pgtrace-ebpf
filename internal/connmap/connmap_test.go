package connmap

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/t1bur1an/pgtrace-ebpf/internal/event"
)

const tcp4 = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:A1B2 0200000A:1538 01 00000000:00000000 00:00000000 00000000    70        0 12345 1 0000000000000000 20 4 30 10 -1
   1: 00000000:1924 00000000:0000 0A 00000000:00000000 00:00000000 00000000    70        0 222 1 0000000000000000 100 0 0 10 0
   2: 0300000A:1924 0400000A:D431 01 00000000:00000000 00:00000000 00000000    70        0 333 1 0000000000000000 20 4 30 10 -1
`

const tcp6 = `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000001000000:A000 00000000000000000000000001000000:1538 01 00000000:00000000 00:00000000 00000000    70        0 777 1 0000000000000000 20 4 30 10 -1
`

const unix = `Num       RefCount Protocol Flags    Type St Inode Path
0000000000000000: 00000002 00000000 00010000 0001 01 444 /tmp/.s.PGSQL.6432
0000000000000000: 00000003 00000000 00000000 0001 03 555 /tmp/.s.PGSQL.6432
0000000000000000: 00000003 00000000 00000000 0001 03 666
0000000000000000: 00000003 00000000 00000000 0001 03 888 /run/other.sock
`

func TestParseProcNetTCP(t *testing.T) {
	m, err := parseProcNetTCP(strings.NewReader(tcp4), false)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := m[12345].Remote, netip.MustParseAddrPort("10.0.0.2:5432"); got != want {
		t.Fatalf("got %v want %v", got, want)
	}
	if got, want := m[333].Local, netip.MustParseAddrPort("10.0.0.3:6436"); got != want {
		t.Fatalf("local got %v want %v", got, want)
	}
	if got, want := m[333].Remote, netip.MustParseAddrPort("10.0.0.4:54321"); got != want {
		t.Fatalf("got %v want %v", got, want)
	}
	m6, err := parseProcNetTCP(strings.NewReader(tcp6), true)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := m6[777].Remote, netip.MustParseAddrPort("[::1]:5432"); got != want {
		t.Fatalf("v6 got %v want %v", got, want)
	}
}

func TestParseProcNetUnix(t *testing.T) {
	m, err := parseProcNetUnix(strings.NewReader(unix))
	if err != nil {
		t.Fatal(err)
	}
	if m[555] != "/tmp/.s.PGSQL.6432" || m[666] != "" || m[888] != "/run/other.sock" {
		t.Fatalf("got %v", m)
	}
}

func cfg(root string) Config {
	return Config{ProcRoot: root, PGPort: 5432, ListenPort: 6436, ClientTracing: true}
}

func TestConnectAcceptAndClose(t *testing.T) {
	m := New(cfg(t.TempDir()))
	k := event.ConnKey{PID: 1, FD: 5}
	m.OnConnect(k, netip.MustParseAddrPort("10.0.0.2:5432"))
	if info := m.Lookup(k); info.Side != SideServer || info.Remote.Port() != 5432 {
		t.Fatalf("got %+v", info)
	}
	k2 := event.ConnKey{PID: 1, FD: 6}
	m.OnConnect(k2, netip.MustParseAddrPort("10.0.0.2:53"))
	if m.Lookup(k2).Side != SideNone {
		t.Fatal("port 53 must be ignored")
	}
	k3 := event.ConnKey{PID: 1, FD: 7}
	m.OnAccept(k3, netip.MustParseAddrPort("10.0.0.9:40000"))
	if info := m.Lookup(k3); info.Side != SideClient || info.Remote.Port() != 40000 {
		t.Fatalf("accept got %+v", info)
	}
	k4 := event.ConnKey{PID: 1, FD: 8}
	m.OnAccept(k4, netip.AddrPort{}) // unix socket
	if m.Lookup(k4).Side != SideClient {
		t.Fatal("unix accept must be a client")
	}
	m.OnClose(k)
	if m.Lookup(k).Side != SideNone {
		t.Fatal("closed fd still classified")
	}
}

func TestClientTracingDisabled(t *testing.T) {
	c := cfg(t.TempDir())
	c.ClientTracing = false
	m := New(c)
	k := event.ConnKey{PID: 1, FD: 7}
	m.OnAccept(k, netip.MustParseAddrPort("10.0.0.9:40000"))
	if m.Lookup(k).Side != SideNone {
		t.Fatal("clients must be ignored when client tracing is off")
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
	for fd, target := range map[string]string{"7": "socket:[12345]", "8": "socket:[333]", "9": "/dev/null", "10": "socket:[555]", "11": "socket:[666]", "12": "socket:[888]"} {
		must(os.Symlink(target, filepath.Join(root, "42/fd", fd)))
	}
	must(os.WriteFile(filepath.Join(root, "42/net/tcp"), []byte(tcp4), 0o644))
	must(os.WriteFile(filepath.Join(root, "42/net/tcp6"), []byte(tcp6), 0o644))
	must(os.WriteFile(filepath.Join(root, "42/net/unix"), []byte(unix), 0o644))

	c := cfg(root)
	c.ListenPort = 6436
	m := New(c)
	want := map[int32]Side{7: SideServer, 8: SideClient, 9: SideNone, 12: SideNone, 11: SideNone}
	for fd, side := range want {
		if got := m.Lookup(event.ConnKey{PID: 42, FD: fd}).Side; got != side {
			t.Errorf("fd %d: side %v want %v", fd, got, side)
		}
	}
	// Unix socket accepted on pgbouncer's listener path .s.PGSQL.<listen-port>.
	c.ListenPort = 6432
	m = New(c)
	if got := m.Lookup(event.ConnKey{PID: 42, FD: 10}).Side; got != SideClient {
		t.Errorf("unix listener socket: %v", got)
	}
	if got := m.Lookup(event.ConnKey{PID: 42, FD: 8}).Side; got != SideNone {
		t.Errorf("port 6436 with listen-port 6432: %v", got)
	}
}
