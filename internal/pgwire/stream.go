package pgwire

import "encoding/binary"

// DefaultMaxMessage is how much of one message body is kept by default;
// longer messages are passed on truncated.
const DefaultMaxMessage = 64 << 10

const (
	maxMsgLen = 1 << 30

	codeProtocol3 = 196608
	codeSSL       = 80877103
	codeGSSEnc    = 80877104
	codeCancel    = 80877102
)

// Message types that may appear in each direction; used to recognise message
// boundaries when (re)synchronising and to detect desync.
var (
	frontendTypes = typeSet("QPBEDSCHXpFdcf")
	backendTypes  = typeSet("RSKZTDCEIN123nstAGHWdcVvc")

	// Messages whose body the parser reads; all others are skipped by length
	// without buffering (DataRow, CopyData, RowDescription, ...).
	frontendBody = typeSet("QPBEC")
	backendBody  = typeSet("CEZ")
)

func typeSet(s string) (t [256]bool) {
	for i := 0; i < len(s); i++ {
		t[s[i]] = true
	}
	return
}

// msg is one protocol message. typ 0 is an untyped startup-phase packet whose
// code is in startupCode.
type msg struct {
	typ         byte
	body        []byte
	truncated   bool // body incomplete (kernel capture cap or keep cap)
	cut         bool // body shortened by the keep cap (counted as a parser truncation)
	startupCode uint32
}

// stream reassembles one direction of a connection into messages.
type stream struct {
	frontend  bool
	synced    bool
	expectSSL bool   // backend: next byte is the single-byte SSL/GSS reply
	keep      int    // most bytes of one message kept (header included)
	buf       []byte // the message in progress; sized once its length is known
	discard   int    // bytes of the current message still to be skipped
}

func (s *stream) valid(typ byte) bool {
	if s.frontend {
		return frontendTypes[typ]
	}
	return backendTypes[typ]
}

func (s *stream) needBody(typ byte) bool {
	if s.frontend {
		return frontendBody[typ]
	}
	return backendBody[typ]
}

func (s *stream) reset() {
	s.synced, s.expectSSL, s.buf, s.discard = false, false, nil, 0
}

// plausibleStart reports whether p looks like it begins at a message boundary.
func (s *stream) plausibleStart(p []byte) bool {
	if s.frontend && len(p) >= 8 && p[0] == 0 {
		return isStartupCode(binary.BigEndian.Uint32(p[4:8]))
	}
	if len(p) < 5 || !s.valid(p[0]) {
		return false
	}
	l := binary.BigEndian.Uint32(p[1:5])
	return l >= 4 && l <= maxMsgLen
}

func isStartupCode(c uint32) bool {
	return c == codeProtocol3 || c == codeSSL || c == codeGSSEnc || c == codeCancel
}

// header returns the header size of the message starting in buf/p: 8 for
// untyped startup-phase packets, 5 for typed messages.
func (s *stream) headerSize(first byte) int {
	if s.frontend && first == 0 {
		return 8
	}
	return 5
}

// feed consumes one captured syscall chunk. p is the captured prefix of a
// transfer of total bytes. desync is true when the stream lost its place and
// was reset; the caller should forget in-flight state.
//
// Bytes are consumed exactly: once a message header is known, a buffer of
// min(message length, keep) is allocated once and filled; the rest of the
// message, and every message whose body isn't read, is skipped by length.
func (s *stream) feed(p []byte, total int) (msgs []msg, desync bool) {
	missing := max(total-len(p), 0)
	if !s.synced && s.discard == 0 {
		probe := append(s.buf, p...)
		// Resynchronise only at a chunk start that looks like a message
		// header; a header split across chunks is buffered until complete.
		switch {
		case missing == 0 && len(probe) < 8 && len(probe) > 0 && (s.valid(probe[0]) || s.frontend && probe[0] == 0):
			if len(probe) < 5 || probe[0] == 0 {
				s.buf = probe
				return nil, false
			}
			fallthrough
		default:
			if !s.plausibleStart(probe) {
				s.buf = nil
				return nil, false
			}
		}
		s.synced, s.buf, p = true, nil, probe
	}

	for {
		if s.discard > 0 {
			if len(p) == 0 {
				break
			}
			n := min(s.discard, len(p))
			p, s.discard = p[n:], s.discard-n
			continue
		}
		if s.expectSSL {
			if len(p) == 0 {
				break
			}
			p, s.expectSSL = p[1:], false
			continue
		}
		if len(s.buf) == 0 && len(p) == 0 {
			break
		}
		// Complete the header.
		if hdr := s.headerSize(p0(s.buf, p)); len(s.buf) < hdr {
			n := min(hdr-len(s.buf), len(p))
			s.buf, p = append(s.buf, p[:n]...), p[n:]
			if len(s.buf) < hdr {
				break
			}
		}
		size, keep, ok := s.sizes()
		if !ok {
			s.reset()
			return msgs, true
		}
		if keep == 0 { // body not read: report the message, skip its bytes
			msgs = append(msgs, msg{typ: s.buf[0]})
			s.discard, s.buf = size-len(s.buf), nil
			continue
		}
		if cap(s.buf) < keep {
			nb := make([]byte, len(s.buf), keep)
			copy(nb, s.buf)
			s.buf = nb
		}
		n := min(len(p), keep-len(s.buf))
		s.buf, p = append(s.buf, p[:n]...), p[n:]
		if len(s.buf) == size {
			msgs = append(msgs, s.message(false))
			s.buf = nil
			continue
		}
		if len(s.buf) == keep { // longer than the keep cap
			m := s.message(true)
			m.cut = true
			msgs = append(msgs, m)
			s.discard, s.buf = size-keep, nil
			continue
		}
		break // p exhausted mid-message
	}

	if missing > 0 {
		// The kernel didn't copy the last `missing` bytes of this chunk. They
		// are only recoverable if they all belong to the message in progress.
		switch {
		case s.discard > 0:
			if missing > s.discard {
				s.reset()
				return msgs, true
			}
			s.discard -= missing
		case len(s.buf) >= 5 && s.buf[0] != 0:
			size, _, _ := s.sizes()
			need := size - len(s.buf)
			if missing > need {
				s.reset()
				return msgs, true
			}
			msgs = append(msgs, s.message(true))
			s.buf, s.discard = nil, need-missing
		default:
			s.reset()
			return msgs, true
		}
	}
	return msgs, false
}

// p0 is the first byte of the message in progress.
func p0(buf, p []byte) byte {
	if len(buf) > 0 {
		return buf[0]
	}
	return p[0]
}

// sizes validates the buffered header and returns the full message size and
// how many bytes of it to keep (0: body not read).
func (s *stream) sizes() (size, keep int, ok bool) {
	if s.frontend && s.buf[0] == 0 {
		l := int(binary.BigEndian.Uint32(s.buf[0:4]))
		if l < 8 || l > 10000 || !isStartupCode(binary.BigEndian.Uint32(s.buf[4:8])) {
			return 0, 0, false
		}
		return l, l, true
	}
	typ, l := s.buf[0], int(binary.BigEndian.Uint32(s.buf[1:5]))
	if !s.valid(typ) || l < 4 || l > maxMsgLen {
		return 0, 0, false
	}
	if !s.needBody(typ) {
		return 1 + l, 0, true
	}
	return 1 + l, min(1+l, max(s.keep, 64)), true
}

// message builds a msg from the buffered bytes. The buffer is handed over
// (not copied); callers drop their reference.
func (s *stream) message(truncated bool) msg {
	if s.frontend && s.buf[0] == 0 {
		return msg{startupCode: binary.BigEndian.Uint32(s.buf[4:8]), body: s.buf[8:]}
	}
	return msg{typ: s.buf[0], body: s.buf[5:], truncated: truncated}
}

func clone(b []byte) []byte { return append([]byte(nil), b...) }
