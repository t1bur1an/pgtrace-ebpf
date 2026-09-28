package pgwire

import (
	"encoding/binary"
	"strconv"
)

// m builds a typed wire message.
func m(typ byte, body ...[]byte) []byte {
	var b []byte
	for _, p := range body {
		b = append(b, p...)
	}
	out := []byte{typ, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(out[1:], uint32(len(b)+4))
	return append(out, b...)
}

func cstr(s string) []byte { return append([]byte(s), 0) }

func i16(v int16) []byte { return binary.BigEndian.AppendUint16(nil, uint16(v)) }

func i32(v int32) []byte { return binary.BigEndian.AppendUint32(nil, uint32(v)) }

func cat(parts ...[]byte) []byte {
	var b []byte
	for _, p := range parts {
		b = append(b, p...)
	}
	return b
}

// Frontend messages.
func fQuery(sql string) []byte       { return m('Q', cstr(sql)) }
func fParse(name, sql string) []byte { return m('P', cstr(name), cstr(sql), i16(0)) }
func fBind(portal, stmt string) []byte {
	return m('B', cstr(portal), cstr(stmt), i16(0), i16(0), i16(0))
}
func fDescribe(portal string) []byte { return m('D', []byte{'P'}, cstr(portal)) }
func fExecute(portal string) []byte  { return m('E', cstr(portal), i32(0)) }
func fSync() []byte                  { return m('S') }
func fCloseStmt(name string) []byte  { return m('C', []byte{'S'}, cstr(name)) }
func startup(user string) []byte {
	body := cat(i32(196608), cstr("user"), cstr(user), []byte{0})
	return cat(i32(int32(len(body)+4)), body)
}
func sslRequest() []byte { return cat(i32(8), i32(80877103)) }

// Backend messages.
func bRowDesc() []byte {
	return m('T', i16(1), cstr("c"), i32(0), i16(0), i32(23), i16(4), i32(-1), i16(0))
}
func bRow(v string) []byte        { return m('D', i16(1), i32(int32(len(v))), []byte(v)) }
func bComplete(tag string) []byte { return m('C', cstr(tag)) }
func bReady() []byte              { return m('Z', []byte{'I'}) }
func bParseDone() []byte          { return m('1') }
func bBindDone() []byte           { return m('2') }
func bError(code, msg string) []byte {
	return m('E', []byte{'S'}, cstr("ERROR"), []byte{'C'}, cstr(code), []byte{'M'}, cstr(msg), []byte{0})
}
func bAuthOK() []byte           { return m('R', i32(0)) }
func bParam(k, v string) []byte { return m('S', cstr(k), cstr(v)) }

func selectResult(n int) []byte {
	b := bRowDesc()
	for i := 0; i < n; i++ {
		b = append(b, bRow(strconv.Itoa(i))...)
	}
	return append(b, bComplete("SELECT "+strconv.Itoa(n))...)
}
