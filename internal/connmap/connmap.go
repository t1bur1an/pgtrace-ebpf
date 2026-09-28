// Package connmap decides which sockets of the traced process are connections
// to postgres (server side) and which are client connections to pgbouncer.
package connmap

import (
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/t1bur1an/pgtrace/internal/event"
)

type Side uint8

const (
	SideNone   Side = iota // not traced
	SideServer             // pgbouncer → postgres
	SideClient             // client → pgbouncer
)

func (s Side) String() string {
	switch s {
	case SideServer:
		return "server"
	case SideClient:
		return "client"
	}
	return "none"
}

// Info describes one fd of a traced process.
type Info struct {
	Side          Side
	Remote, Local netip.AddrPort // Remote is invalid for unix sockets
}

type Config struct {
	ProcRoot      string // procfs of the host pid namespace
	PGPort        uint16 // postgres port: sockets connected to it are server side
	ListenPort    uint16 // pgbouncer's listen port: sockets on it are clients
	ClientTracing bool   // classify client sockets (otherwise they are ignored)
}

// Map caches fd classifications. Entries come from connect/accept events or
// are resolved lazily from procfs for sockets opened before tracing started.
type Map struct {
	cfg Config

	mu    sync.Mutex
	cache map[event.ConnKey]Info
}

func New(cfg Config) *Map {
	return &Map{cfg: cfg, cache: map[event.ConnKey]Info{}}
}

func (m *Map) set(k event.ConnKey, info Info) {
	m.mu.Lock()
	m.cache[k] = info
	m.mu.Unlock()
}

func (m *Map) OnConnect(k event.ConnKey, a netip.AddrPort) {
	info := Info{Remote: a}
	if a.Port() == m.cfg.PGPort {
		info.Side = SideServer
	}
	m.set(k, info)
}

// OnAccept records a client connection accepted by pgbouncer. An invalid peer
// means a unix socket.
func (m *Map) OnAccept(k event.ConnKey, peer netip.AddrPort) {
	info := Info{Remote: peer}
	if m.cfg.ClientTracing {
		info.Side = SideClient
	}
	m.set(k, info)
}

func (m *Map) OnClose(k event.ConnKey) {
	m.mu.Lock()
	delete(m.cache, k)
	m.mu.Unlock()
}

func (m *Map) Lookup(k event.ConnKey) Info {
	m.mu.Lock()
	info, ok := m.cache[k]
	m.mu.Unlock()
	if ok {
		return info
	}
	info = m.resolve(k)
	m.set(k, info)
	return info
}

// Count returns the number of classified fds per side.
func (m *Map) Count() map[Side]int {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[Side]int{}
	for _, info := range m.cache {
		out[info.Side]++
	}
	return out
}

func (m *Map) resolve(k event.ConnKey) Info {
	pid := strconv.FormatUint(uint64(k.PID), 10)
	link, err := os.Readlink(filepath.Join(m.cfg.ProcRoot, pid, "fd", strconv.Itoa(int(k.FD))))
	if err != nil || !strings.HasPrefix(link, "socket:[") {
		return Info{}
	}
	inode, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]"), 10, 64)
	if err != nil {
		return Info{}
	}
	for _, f := range []struct {
		name string
		v6   bool
	}{{"tcp", false}, {"tcp6", true}} {
		fh, err := os.Open(filepath.Join(m.cfg.ProcRoot, pid, "net", f.name))
		if err != nil {
			continue
		}
		socks, err := parseProcNetTCP(fh, f.v6)
		fh.Close()
		if err != nil {
			continue
		}
		if a, ok := socks[inode]; ok {
			info := Info{Remote: a.Remote, Local: a.Local}
			switch {
			case a.Remote.Port() == m.cfg.PGPort:
				info.Side = SideServer
			case a.Local.Port() == m.cfg.ListenPort && m.cfg.ClientTracing:
				info.Side = SideClient
			}
			return info
		}
	}
	// Unix sockets accepted by pgbouncer carry its listener's path;
	// pgbouncer's own outbound unix connections have none.
	if fh, err := os.Open(filepath.Join(m.cfg.ProcRoot, pid, "net", "unix")); err == nil {
		socks, err := parseProcNetUnix(fh)
		fh.Close()
		if err == nil && m.cfg.ClientTracing &&
			strings.HasSuffix(socks[inode], ".s.PGSQL."+strconv.Itoa(int(m.cfg.ListenPort))) {
			return Info{Side: SideClient}
		}
	}
	return Info{}
}
