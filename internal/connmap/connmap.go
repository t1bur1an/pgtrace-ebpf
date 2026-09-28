// Package connmap decides which sockets of the traced process are connections
// to postgres.
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

// Info describes one fd of a traced process.
type Info struct {
	Server bool
	Remote netip.AddrPort
}

// Map caches fd classifications. Entries come from connect events or are
// resolved lazily from procfs for sockets opened before tracing started.
type Map struct {
	procRoot string
	port     uint16

	mu    sync.Mutex
	cache map[event.ConnKey]Info
}

func New(procRoot string, pgPort uint16) *Map {
	return &Map{procRoot: procRoot, port: pgPort, cache: map[event.ConnKey]Info{}}
}

func (m *Map) OnConnect(k event.ConnKey, a netip.AddrPort) {
	m.mu.Lock()
	m.cache[k] = Info{Server: a.Port() == m.port, Remote: a}
	m.mu.Unlock()
}

func (m *Map) OnClose(k event.ConnKey) {
	m.mu.Lock()
	delete(m.cache, k)
	m.mu.Unlock()
}

// Forget drops all entries of a process that exited.
func (m *Map) Forget(pid uint32) {
	m.mu.Lock()
	for k := range m.cache {
		if k.PID == pid {
			delete(m.cache, k)
		}
	}
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
	m.mu.Lock()
	m.cache[k] = info
	m.mu.Unlock()
	return info
}

func (m *Map) resolve(k event.ConnKey) Info {
	pid := strconv.FormatUint(uint64(k.PID), 10)
	link, err := os.Readlink(filepath.Join(m.procRoot, pid, "fd", strconv.Itoa(int(k.FD))))
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
		fh, err := os.Open(filepath.Join(m.procRoot, pid, "net", f.name))
		if err != nil {
			continue
		}
		socks, err := parseProcNetTCP(fh, f.v6)
		fh.Close()
		if err != nil {
			continue
		}
		if remote, ok := socks[inode]; ok {
			return Info{Server: remote.Port() == m.port, Remote: remote}
		}
	}
	return Info{}
}
