package capture

import (
	"encoding/binary"
	"fmt"
	"net/netip"

	"github.com/t1bur1an/pgtrace-ebpf/internal/event"
)

// headerSize is offsetof(struct event, payload) in bpf/pgtrace.bpf.c.
const headerSize = 56

const flagSeq = 1

const (
	kindData    = 0
	kindConnect = 1
	kindClose   = 2
	kindAccept  = 3

	afUnix  = 1
	afInet  = 2
	afInet6 = 10
)

// decode turns one ringbuf record into event.Data, event.Connect or event.Close.
func decode(raw []byte) (any, error) {
	if len(raw) < headerSize {
		return nil, fmt.Errorf("short record: %d bytes", len(raw))
	}
	le := binary.LittleEndian
	ts := le.Uint64(raw[0:])
	key := event.ConnKey{PID: le.Uint32(raw[8:]), FD: int32(le.Uint32(raw[12:]))}
	switch raw[24] {
	case kindData:
		capLen := int(le.Uint32(raw[20:]))
		if headerSize+capLen > len(raw) {
			return nil, fmt.Errorf("cap_len %d exceeds record of %d bytes", capLen, len(raw))
		}
		return event.Data{
			TS:       ts,
			Key:      key,
			Dir:      event.Dir(raw[25]),
			TotalLen: le.Uint32(raw[16:]),
			Payload:  append([]byte(nil), raw[headerSize:headerSize+capLen]...),
			Seq:      le.Uint32(raw[48:]),
			HasSeq:   le.Uint32(raw[52:])&flagSeq != 0,
		}, nil
	case kindConnect:
		addr, err := sockAddr(raw)
		if err != nil {
			return nil, err
		}
		return event.Connect{TS: ts, Key: key, Addr: addr}, nil
	case kindAccept:
		if le.Uint16(raw[26:]) == afUnix {
			return event.Accept{TS: ts, Key: key}, nil
		}
		addr, err := sockAddr(raw)
		if err != nil {
			return nil, err
		}
		return event.Accept{TS: ts, Key: key, Addr: addr}, nil
	case kindClose:
		return event.Close{TS: ts, Key: key}, nil
	}
	return nil, fmt.Errorf("unknown event kind %d", raw[24])
}

func sockAddr(raw []byte) (netip.AddrPort, error) {
	port := binary.BigEndian.Uint16(raw[28:])
	switch fam := binary.LittleEndian.Uint16(raw[26:]); fam {
	case afInet:
		return netip.AddrPortFrom(netip.AddrFrom4([4]byte(raw[32:36])), port), nil
	case afInet6:
		return netip.AddrPortFrom(netip.AddrFrom16([16]byte(raw[32:48])).Unmap(), port), nil
	default:
		return netip.AddrPort{}, fmt.Errorf("unsupported family %d", fam)
	}
}
