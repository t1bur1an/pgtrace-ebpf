// Package event defines the decoded kernel events shared by capture and the agent.
package event

import "net/netip"

// Dir is the direction of a data chunk relative to pgbouncer.
type Dir uint8

const (
	DirSend Dir = 0 // pgbouncer → peer
	DirRecv Dir = 1 // peer → pgbouncer
)

// ConnKey identifies a socket inside a traced process.
type ConnKey struct {
	PID uint32
	FD  int32
}

// Data is a chunk of bytes moved by a send/recv/read/write syscall.
// len(Payload) <= TotalLen; the difference was not captured by the kernel.
type Data struct {
	TS       uint64 // CLOCK_MONOTONIC ns
	Key      ConnKey
	Dir      Dir
	TotalLen uint32
	Payload  []byte
}

// Connect is an outbound connect() on a socket.
type Connect struct {
	TS   uint64
	Key  ConnKey
	Addr netip.AddrPort
}

// Close is a close() of a file descriptor.
type Close struct {
	TS  uint64
	Key ConnKey
}

// Accept is a connection accepted by the traced process. Addr is the peer
// address, invalid for unix sockets.
type Accept struct {
	TS   uint64
	Key  ConnKey
	Addr netip.AddrPort
}
