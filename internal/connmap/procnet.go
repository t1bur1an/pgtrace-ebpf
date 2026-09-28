package connmap

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"
)

// parseProcNetTCP reads /proc/<pid>/net/tcp{,6} and maps socket inode to the
// remote address.
func parseProcNetTCP(r io.Reader, v6 bool) (map[uint64]netip.AddrPort, error) {
	out := map[uint64]netip.AddrPort{}
	sc := bufio.NewScanner(r)
	sc.Scan() // header
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 10 {
			continue
		}
		remote, err := parseHexAddr(f[2], v6)
		if err != nil {
			return nil, fmt.Errorf("parse %q: %w", f[2], err)
		}
		inode, err := strconv.ParseUint(f[9], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("parse inode %q: %w", f[9], err)
		}
		out[inode] = remote
	}
	return out, sc.Err()
}

// parseHexAddr decodes "0100007F:1538". The address is a sequence of 32-bit
// words in host (little-endian) order; the port is plain hex.
func parseHexAddr(s string, v6 bool) (netip.AddrPort, error) {
	addrHex, portHex, ok := strings.Cut(s, ":")
	if !ok {
		return netip.AddrPort{}, fmt.Errorf("missing port")
	}
	raw, err := hex.DecodeString(addrHex)
	if err != nil {
		return netip.AddrPort{}, err
	}
	if (v6 && len(raw) != 16) || (!v6 && len(raw) != 4) {
		return netip.AddrPort{}, fmt.Errorf("bad address length %d", len(raw))
	}
	for i := 0; i < len(raw); i += 4 {
		binary.BigEndian.PutUint32(raw[i:], binary.LittleEndian.Uint32(raw[i:]))
	}
	port, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return netip.AddrPort{}, err
	}
	addr, _ := netip.AddrFromSlice(raw)
	return netip.AddrPortFrom(addr.Unmap(), uint16(port)), nil
}
