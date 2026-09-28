package capture

import (
	"encoding/binary"
	"net/netip"
	"reflect"
	"testing"

	"github.com/t1bur1an/pgtrace/internal/event"
)

func header(kind, dir uint8, fd int32, total, capLen uint32) []byte {
	b := make([]byte, headerSize)
	binary.LittleEndian.PutUint64(b[0:], 777)
	binary.LittleEndian.PutUint32(b[8:], 42)
	binary.LittleEndian.PutUint32(b[12:], uint32(fd))
	binary.LittleEndian.PutUint32(b[16:], total)
	binary.LittleEndian.PutUint32(b[20:], capLen)
	b[24], b[25] = kind, dir
	return b
}

func TestDecodeData(t *testing.T) {
	raw := append(header(0, 1, 7, 10, 3), 'a', 'b', 'c')
	got, err := decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	want := event.Data{TS: 777, Key: event.ConnKey{PID: 42, FD: 7}, Dir: event.DirRecv, TotalLen: 10, Payload: []byte("abc")}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v", got)
	}
}

func TestDecodeConnect(t *testing.T) {
	raw := header(1, 0, 9, 0, 0)
	binary.LittleEndian.PutUint16(raw[26:], 2) // AF_INET
	raw[28], raw[29] = 0x15, 0x38              // 5432
	copy(raw[32:], []byte{10, 0, 0, 2})
	got, err := decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	want := event.Connect{TS: 777, Key: event.ConnKey{PID: 42, FD: 9}, Addr: netip.MustParseAddrPort("10.0.0.2:5432")}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v", got)
	}

	raw6 := header(1, 0, 9, 0, 0)
	binary.LittleEndian.PutUint16(raw6[26:], 10) // AF_INET6
	raw6[28], raw6[29] = 0x15, 0x38
	raw6[47] = 1 // ::1
	got, _ = decode(raw6)
	if got.(event.Connect).Addr != netip.MustParseAddrPort("[::1]:5432") {
		t.Fatalf("v6 got %+v", got)
	}
}

func TestDecodeClose(t *testing.T) {
	got, err := decode(header(2, 0, 11, 0, 0))
	if err != nil {
		t.Fatal(err)
	}
	if got != (event.Close{TS: 777, Key: event.ConnKey{PID: 42, FD: 11}}) {
		t.Fatalf("got %+v", got)
	}
}

func TestDecodeShort(t *testing.T) {
	if _, err := decode(make([]byte, 10)); err == nil {
		t.Fatal("want error")
	}
	if _, err := decode(header(0, 0, 1, 5, 5)); err == nil {
		t.Fatal("want error for cap_len beyond record")
	}
}

func TestDecodeAccept(t *testing.T) {
	raw := header(3, 0, 12, 0, 0)
	binary.LittleEndian.PutUint16(raw[26:], 2) // AF_INET
	raw[28], raw[29] = 0x9c, 0x40              // 40000
	copy(raw[32:], []byte{10, 0, 0, 9})
	got, err := decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	want := event.Accept{TS: 777, Key: event.ConnKey{PID: 42, FD: 12}, Addr: netip.MustParseAddrPort("10.0.0.9:40000")}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v", got)
	}

	rawUnix := header(3, 0, 13, 0, 0)
	binary.LittleEndian.PutUint16(rawUnix[26:], 1) // AF_UNIX
	got, err = decode(rawUnix)
	if err != nil {
		t.Fatal(err)
	}
	if a := got.(event.Accept); a.Addr.IsValid() || a.Key.FD != 13 {
		t.Fatalf("unix accept %+v", a)
	}
}

func TestValidateCaptureBytes(t *testing.T) {
	for n, ok := range map[int]bool{0: true, 64: true, 4096: true, 16384: true, 63: false, 16385: false, -1: false} {
		if err := validateCaptureBytes(n); (err == nil) != ok {
			t.Errorf("validateCaptureBytes(%d) = %v", n, err)
		}
	}
}
