// Package pgwire turns the captured bytes of one postgres server connection
// into completed queries.
package pgwire

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"

	"github.com/t1bur1an/pgtrace/internal/event"
)

// Query is one completed statement execution observed on a server connection.
type Query struct {
	Start, End   uint64 // CLOCK_MONOTONIC ns
	SQL          string
	Operation    string
	CommandTag   string
	Rows         int64
	ErrorCode    string
	ErrorMessage string
	Protocol     string // "simple" | "extended"
	Truncated    bool
}

// group is the work between two ReadyForQuery messages: one simple Query, or
// the Executes sent before a Sync.
type group struct {
	simple  bool
	queries []*Query
	next    int  // index of the query the backend is currently answering
	failed  bool // extended: an error aborted the rest of the pipeline
}

// Conn tracks one server connection. It is not safe for concurrent use.
type Conn struct {
	fe, be  stream
	stmts   map[string]string
	stmtTr  map[string]bool
	portals map[string]string
	groups  []*group
	open    *group // extended group collecting Executes until Sync
}

func NewConn() *Conn {
	return &Conn{
		fe:      stream{frontend: true},
		stmts:   map[string]string{},
		stmtTr:  map[string]bool{},
		portals: map[string]string{},
	}
}

// Feed consumes one captured chunk and returns queries completed by it.
func (c *Conn) Feed(dir event.Dir, ts uint64, payload []byte, totalLen uint32) []Query {
	if dir == event.DirSend {
		msgs, desync := c.fe.feed(payload, int(totalLen))
		if desync {
			c.forget()
		}
		for _, m := range msgs {
			c.frontend(ts, m)
		}
		return nil
	}
	msgs, desync := c.be.feed(payload, int(totalLen))
	var out []Query
	for _, m := range msgs {
		out = c.backend(ts, m, out)
	}
	if desync {
		c.forget()
	}
	return out
}

// forget drops in-flight queries after a stream lost its place.
func (c *Conn) forget() {
	c.groups, c.open = nil, nil
}

func (c *Conn) frontend(ts uint64, m msg) {
	switch m.typ {
	case 0:
		if m.startupCode == codeSSL || m.startupCode == codeGSSEnc {
			c.be.synced, c.be.expectSSL = true, true
		}
	case 'Q':
		sql, _ := cstring(m.body)
		c.open = nil
		c.groups = append(c.groups, &group{simple: true, queries: []*Query{
			{Start: ts, SQL: sql, Protocol: "simple", Truncated: m.truncated},
		}})
	case 'P':
		name, rest := cstring(m.body)
		sql, _ := cstring(rest)
		c.stmts[name], c.stmtTr[name] = sql, m.truncated
	case 'B':
		portal, rest := cstring(m.body)
		stmt, _ := cstring(rest)
		c.portals[portal] = stmt
	case 'E':
		portal, _ := cstring(m.body)
		stmt := c.portals[portal]
		sql, ok := c.stmts[stmt]
		if !ok {
			sql = fmt.Sprintf("<unknown prepared statement %q>", stmt)
		}
		if c.open == nil {
			c.open = &group{}
			c.groups = append(c.groups, c.open)
		}
		c.open.queries = append(c.open.queries, &Query{
			Start: ts, SQL: sql, Protocol: "extended", Truncated: c.stmtTr[stmt],
		})
	case 'S':
		if c.open == nil {
			c.groups = append(c.groups, &group{})
		}
		c.open = nil
	case 'C':
		if len(m.body) > 0 {
			name, _ := cstring(m.body[1:])
			if m.body[0] == 'S' {
				delete(c.stmts, name)
				delete(c.stmtTr, name)
			} else {
				delete(c.portals, name)
			}
		}
	}
}

func (c *Conn) backend(ts uint64, m msg, out []Query) []Query {
	var g *group
	var q *Query
	if len(c.groups) > 0 {
		g = c.groups[0]
		if g.next < len(g.queries) {
			q = g.queries[g.next]
		}
	}
	switch m.typ {
	case 'C':
		if q == nil || g.failed {
			break
		}
		tag, _ := cstring(m.body)
		q.CommandTag = tag
		q.Rows += tagRows(tag)
		if !g.simple {
			out = c.finish(q, ts, out)
			g.next++
		}
	case 'I', 's': // EmptyQueryResponse, PortalSuspended complete an Execute
		if q != nil && !g.simple && !g.failed {
			out = c.finish(q, ts, out)
			g.next++
		}
	case 'E':
		if q == nil || g.failed {
			break
		}
		q.ErrorCode, q.ErrorMessage = errorFields(m.body)
		if !g.simple {
			out = c.finish(q, ts, out)
			g.failed = true // postgres skips the rest until Sync
		}
	case 'Z':
		if g == nil {
			break
		}
		if g.simple && q != nil {
			out = c.finish(q, ts, out)
		}
		c.groups = c.groups[1:]
		if g == c.open {
			c.open = nil
		}
	}
	return out
}

func (c *Conn) finish(q *Query, ts uint64, out []Query) []Query {
	q.End = ts
	q.Operation = operation(q.SQL, q.CommandTag)
	return append(out, *q)
}

// cstring splits a NUL-terminated string off b. A missing terminator (truncated
// capture) yields all of b.
func cstring(b []byte) (string, []byte) {
	i := bytes.IndexByte(b, 0)
	if i < 0 {
		return string(b), nil
	}
	return string(b[:i]), b[i+1:]
}

func errorFields(b []byte) (code, message string) {
	for len(b) > 0 && b[0] != 0 {
		f := b[0]
		var v string
		v, b = cstring(b[1:])
		switch f {
		case 'C':
			code = v
		case 'M':
			message = v
		}
	}
	return
}

// tagRows extracts the row count from a CommandComplete tag such as
// "SELECT 5", "UPDATE 3" or "INSERT 0 1".
func tagRows(tag string) int64 {
	i := strings.LastIndexByte(tag, ' ')
	if i < 0 {
		return 0
	}
	n, err := strconv.ParseInt(tag[i+1:], 10, 64)
	if err != nil {
		return 0
	}
	return n
}

// operation returns the leading SQL keyword, upper-cased, falling back to the
// first word of the command tag.
func operation(sql, tag string) string {
	s := sql
	for {
		s = strings.TrimLeft(s, " \t\r\n(")
		switch {
		case strings.HasPrefix(s, "--"):
			if i := strings.IndexByte(s, '\n'); i >= 0 {
				s = s[i+1:]
				continue
			}
			s = ""
		case strings.HasPrefix(s, "/*"):
			if i := strings.Index(s, "*/"); i >= 0 {
				s = s[i+2:]
				continue
			}
			s = ""
		}
		break
	}
	end := 0
	for end < len(s) && (s[end]|0x20 >= 'a' && s[end]|0x20 <= 'z' || s[end] == '_') {
		end++
	}
	if end > 0 {
		return strings.ToUpper(s[:end])
	}
	if f := strings.Fields(tag); len(f) > 0 {
		return f[0]
	}
	return ""
}
