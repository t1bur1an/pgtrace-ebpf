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
	// Seq is the TCP stream offset of the first byte (write_seq for sends,
	// copied_seq for receives), valid if HasSeq. Consecutive events of one
	// direction are contiguous unless the capture skipped some.
	Seq    uint32
	HasSeq bool
	// TLS: plaintext captured inside pgbouncer's TLS library (SSL_read /
	// SSL_write), not at the socket. Such events have no stream offset.
	TLS bool
	// Session is the TLS session pointer when the socket isn't known yet
	// (Key.FD == -1); zero otherwise.
	Session uint64
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

// TLSFD maps a TLS session to its socket; emitted by the fallback that finds
// the sockets of sessions opened before the agent started.
type TLSFD struct {
	TS      uint64
	Key     ConnKey // Key.FD is the session's socket
	Session uint64
}

// TLSAttr is the TLS version or cipher of a session, as pgbouncer asked
// OpenSSL for it. Exactly one of Version and Cipher is set. Key.FD is -1 if
// the session's socket isn't known.
type TLSAttr struct {
	TS              uint64
	Key             ConnKey
	Session         uint64
	Version, Cipher string
}
