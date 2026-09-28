package capture

import (
	"encoding/binary"
	"fmt"
	"net/netip"

	"github.com/t1bur1an/pgtrace/internal/event"
)

// headerSize is offsetof(struct event, payload) in bpf/pgtrace.bpf.c.
const headerSize = 48

const (
	kindData    = 0
	kindConnect = 1
	kindClose   = 2

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
		}, nil
	case kindConnect:
		port := binary.BigEndian.Uint16(raw[28:])
		var addr netip.Addr
		switch le.Uint16(raw[26:]) {
		case afInet:
			addr = netip.AddrFrom4([4]byte(raw[32:36]))
		case afInet6:
			addr = netip.AddrFrom16([16]byte(raw[32:48])).Unmap()
		default:
			return nil, fmt.Errorf("unsupported family %d", le.Uint16(raw[26:]))
		}
		return event.Connect{TS: ts, Key: key, Addr: netip.AddrPortFrom(addr, port)}, nil
	case kindClose:
		return event.Close{TS: ts, Key: key}, nil
	}
	return nil, fmt.Errorf("unknown event kind %d", raw[24])
}
