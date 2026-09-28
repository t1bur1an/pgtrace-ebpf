package pgwire

import "encoding/binary"

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
	truncated   bool
	startupCode uint32
}

// stream reassembles one direction of a connection into messages.
type stream struct {
	frontend  bool
	synced    bool
	expectSSL bool // backend: next byte is the single-byte SSL/GSS reply
	buf       []byte
	discard   int // bytes of a truncated message still to be dropped
}

func (s *stream) valid(typ byte) bool {
	if s.frontend {
		return frontendTypes[typ]
	}
	return backendTypes[typ]
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

// feed consumes one captured syscall chunk. p is the captured prefix of a
// transfer of total bytes. desync is true when the stream lost its place and
// was reset; the caller should forget in-flight state.
func (s *stream) feed(p []byte, total int) (msgs []msg, desync bool) {
	missing := total - len(p)
	if missing < 0 {
		missing = 0
	}
	if s.discard > 0 {
		n := min(s.discard, len(p))
		p, s.discard = p[n:], s.discard-n
		if s.discard > 0 {
			if missing > s.discard {
				s.reset()
				return nil, true
			}
			s.discard -= missing
			return nil, false
		}
	}
	s.buf = append(s.buf, p...)
	if !s.synced {
		// Resynchronise only at a chunk start that looks like a message
		// header; a header split across chunks is buffered until complete.
		switch {
		case missing == 0 && len(s.buf) < 8 && len(s.buf) > 0 && (s.valid(s.buf[0]) || s.frontend && s.buf[0] == 0):
			if len(s.buf) < 5 || s.buf[0] == 0 {
				return nil, false
			}
			fallthrough
		default:
			if !s.plausibleStart(s.buf) {
				s.buf = nil
				return nil, false
			}
		}
		s.synced = true
	}

	for {
		if s.expectSSL {
			if len(s.buf) == 0 {
				break
			}
			s.buf, s.expectSSL = s.buf[1:], false
			continue
		}
		if s.frontend && len(s.buf) > 0 && s.buf[0] == 0 {
			if len(s.buf) < 8 {
				break
			}
			l := int(binary.BigEndian.Uint32(s.buf[0:4]))
			code := binary.BigEndian.Uint32(s.buf[4:8])
			if l < 8 || l > 10000 || !isStartupCode(code) {
				s.reset()
				return msgs, true
			}
			if len(s.buf) < l {
				break
			}
			msgs = append(msgs, msg{startupCode: code})
			s.buf = s.buf[l:]
			continue
		}
		if len(s.buf) < 5 {
			break
		}
		typ, l := s.buf[0], int(binary.BigEndian.Uint32(s.buf[1:5]))
		if !s.valid(typ) || l < 4 || l > maxMsgLen {
			s.reset()
			return msgs, true
		}
		if len(s.buf) < 1+l {
			break
		}
		msgs = append(msgs, msg{typ: typ, body: clone(s.buf[5 : 1+l])})
		s.buf = s.buf[1+l:]
	}

	if missing > 0 {
		// The kernel dropped the last `missing` bytes of this chunk. They are
		// only recoverable if they all belong to the message in progress.
		if len(s.buf) < 5 || s.buf[0] == 0 {
			s.reset()
			return msgs, true
		}
		need := 1 + int(binary.BigEndian.Uint32(s.buf[1:5])) - len(s.buf)
		if missing > need {
			s.reset()
			return msgs, true
		}
		msgs = append(msgs, msg{typ: s.buf[0], body: clone(s.buf[5:]), truncated: true})
		s.buf, s.discard = nil, need-missing
	}
	if len(s.buf) == 0 {
		s.buf = nil // release the backing array between messages
	}
	return msgs, false
}

func clone(b []byte) []byte { return append([]byte(nil), b...) }
