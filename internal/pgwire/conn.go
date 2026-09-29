// Package pgwire turns the captured bytes of one postgres connection, as seen
// from pgbouncer, into queries.
package pgwire

import (
	"bytes"
	"fmt"
	"hash/fnv"
	"strconv"
	"strings"

	"github.com/t1bur1an/pgtrace-ebpf/internal/event"
)

// Query is one completed statement execution.
type Query struct {
	ID           uint64 // per-Conn, equals the Start.ID reported when it began
	Start, End   uint64 // CLOCK_MONOTONIC ns
	SQL          string
	Operation    string
	CommandTag   string
	Rows         int64
	ErrorCode    string
	ErrorMessage string
	Protocol     string // "simple" | "extended"
	Truncated    bool
	Sig, BindSig uint64
	SQLKnown     bool
	TxStatus     byte // status of the ReadyForQuery that closed its group: I, T or E
	// PerExecution: the SQL text was sent for this execution (simple query,
	// or Parse in the same Sync group), not reused from an earlier Parse.
	PerExecution bool
}

// Start reports a query the moment its Query or Execute message is seen.
type Start struct {
	ID       uint64
	Sig      uint64 // hash of the SQL (and bind values for extended queries)
	BindSig  uint64 // extended only: hash of the bind values alone
	SQLKnown bool
	TS       uint64
	SQL      string
}

// Result is what one Feed call produced.
type Result struct {
	Started    []Start
	Done       []Query
	Truncated  int         // messages cut at Options.MaxMessage
	Resynced   bool        // a stream lost its place and was reset
	ConnErrors []ConnError // errors not answering any query
}

// ConnError is an ErrorResponse with no query in flight: a rejected login
// (unknown database, authentication, too many connections) or a FATAL that
// ends an idle session.
type ConnError struct {
	TS            uint64
	Code, Message string
}

// Options tune a Conn.
type Options struct {
	// MaxMessage is the most bytes of one message kept (DefaultMaxMessage if
	// 0). Memory is allocated per message: min(message length, MaxMessage).
	MaxMessage int
}

// group is the work between two ReadyForQuery messages: one simple Query, or
// the Executes sent before a Sync.
type group struct {
	simple  bool
	queries []*Query
	next    int  // index of the query the backend is currently answering
	failed  bool // extended: an error aborted the rest of the pipeline
}

type portal struct {
	stmt string
	bind []byte // Bind body after the statement name
}

// maxInflightGroups bounds unanswered query groups per connection. Real
// clients pipeline a handful; more means the replies are not being seen,
// and the oldest are dropped so memory stays bounded.
const maxInflightGroups = 1024

// Conn tracks one connection. It is not safe for concurrent use.
type Conn struct {
	feDir   event.Dir // direction carrying frontend (client→server) messages
	fe, be  stream
	params  map[string]string
	stmts   map[string]string
	stmtTr  map[string]bool
	portals map[string]portal
	groups  []*group
	open    *group // extended group collecting Executes until Sync
	nextID  uint64
	parsed  map[string]bool // statements parsed since the last Sync
}

// NewConn parses a pgbouncer→postgres connection: pgbouncer sends the
// frontend messages.
func NewConn() *Conn { return NewConnWith(false, Options{}) }

// NewClientConn parses a client→pgbouncer connection: pgbouncer receives the
// frontend messages.
func NewClientConn() *Conn { return NewConnWith(true, Options{}) }

// NewConnWith parses a client (client=true) or server connection.
func NewConnWith(client bool, o Options) *Conn {
	feDir := event.DirSend
	if client {
		feDir = event.DirRecv
	}
	keep := o.MaxMessage
	if keep <= 0 {
		keep = DefaultMaxMessage
	}
	return &Conn{
		feDir:   feDir,
		fe:      stream{frontend: true, keep: keep},
		be:      stream{keep: keep},
		params:  map[string]string{},
		stmts:   map[string]string{},
		stmtTr:  map[string]bool{},
		portals: map[string]portal{},
		parsed:  map[string]bool{},
	}
}

// Params returns the startup parameters (user, database, ...) if the startup
// packet was seen.
func (c *Conn) Params() map[string]string { return c.params }

// Feed consumes one captured chunk.
func (c *Conn) Feed(dir event.Dir, ts uint64, payload []byte, totalLen uint32) Result {
	var r Result
	if dir == c.feDir {
		msgs, desync := c.fe.feed(payload, int(totalLen))
		if desync {
			c.forget()
			r.Resynced = true
		}
		for _, m := range msgs {
			if m.cut {
				r.Truncated++
			}
			c.frontend(ts, m, &r)
		}
		return r
	}
	msgs, desync := c.be.feed(payload, int(totalLen))
	for _, m := range msgs {
		if m.cut {
			r.Truncated++
		}
		c.backend(ts, m, &r)
	}
	if desync {
		c.forget()
		r.Resynced = true
	}
	return r
}

// forget drops in-flight queries after a stream lost its place.
func (c *Conn) forget() {
	c.groups, c.open = nil, nil
}

func (c *Conn) start(q *Query, r *Result) {
	c.nextID++
	q.ID = c.nextID
	r.Started = append(r.Started, Start{ID: q.ID, Sig: q.Sig, BindSig: q.BindSig, SQLKnown: q.SQLKnown, TS: q.Start, SQL: q.SQL})
}

func (c *Conn) frontend(ts uint64, m msg, r *Result) {
	switch m.typ {
	case 0:
		switch m.startupCode {
		case codeSSL, codeGSSEnc:
			c.be.synced, c.be.expectSSL = true, true
		case codeProtocol3:
			for b := m.body; len(b) > 0 && b[0] != 0; {
				var k, v string
				k, b = cstring(b)
				v, b = cstring(b)
				c.params[k] = v
			}
		}
	case 'Q':
		sql, _ := cstring(m.body)
		c.open = nil
		clear(c.parsed)
		q := &Query{Start: ts, SQL: sql, Protocol: "simple", Truncated: m.truncated, Sig: hash(sql), SQLKnown: true, PerExecution: true}
		c.addGroup(&group{simple: true, queries: []*Query{q}}, r)
		c.start(q, r)
	case 'P':
		name, rest := cstring(m.body)
		sql, _ := cstring(rest)
		c.stmts[name], c.stmtTr[name] = sql, m.truncated
		c.parsed[name] = true
	case 'B':
		name, rest := cstring(m.body)
		stmt, rest := cstring(rest)
		c.portals[name] = portal{stmt: stmt, bind: clone(rest)}
	case 'E':
		name, _ := cstring(m.body)
		p := c.portals[name]
		sql, known := c.stmts[p.stmt]
		if !known {
			sql = fmt.Sprintf("<unknown prepared statement %q>", p.stmt)
		}
		if c.open == nil {
			c.open = &group{}
			c.addGroup(c.open, r)
		}
		q := &Query{
			Start: ts, SQL: sql, Protocol: "extended", Truncated: c.stmtTr[p.stmt],
			Sig: hash(sql, p.bind), BindSig: hash(p.bind), SQLKnown: known,
			PerExecution: c.parsed[p.stmt],
		}
		c.open.queries = append(c.open.queries, q)
		c.start(q, r)
	case 'S':
		clear(c.parsed)
		if c.open == nil {
			c.addGroup(&group{}, r)
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

// addGroup queues a group, dropping the oldest beyond maxInflightGroups.
func (c *Conn) addGroup(g *group, r *Result) {
	c.groups = append(c.groups, g)
	if n := len(c.groups) - maxInflightGroups; n > 0 {
		c.groups = append([]*group(nil), c.groups[n:]...)
		r.Resynced = true
	}
}

func (c *Conn) backend(ts uint64, m msg, r *Result) {
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
			q.End = ts
			g.next++
		}
	case 'I', 's': // EmptyQueryResponse, PortalSuspended complete an Execute
		if q != nil && !g.simple && !g.failed {
			q.End = ts
			g.next++
		}
	case 'E':
		if g == nil {
			code, msg := errorFields(m.body)
			r.ConnErrors = append(r.ConnErrors, ConnError{TS: ts, Code: code, Message: msg})
			break
		}
		if q == nil || g.failed {
			break
		}
		q.ErrorCode, q.ErrorMessage = errorFields(m.body)
		q.End = ts // provisional for simple queries; ReadyForQuery sets the final end
		if !g.simple {
			q.End = ts
			g.next++
			g.failed = true // postgres skips the rest until Sync
		}
	case 'Z':
		if g == nil {
			break
		}
		status := byte(0)
		if len(m.body) > 0 {
			status = m.body[0]
		}
		// Queries are reported when their group ends, so each carries the
		// transaction status the server is left in.
		for i, gq := range g.queries {
			if g.simple {
				gq.End = ts
			} else if i >= g.next {
				break // not executed: an earlier Execute failed
			}
			gq.TxStatus = status
			gq.Operation = operation(gq.SQL, gq.CommandTag)
			r.Done = append(r.Done, *gq)
		}
		c.groups = c.groups[1:]
		if g == c.open {
			c.open = nil
		}
	}
}

// Close is called when the connection ends. It returns queries that received
// an error but never a ReadyForQuery: pgbouncer answers some failures (e.g.
// query_wait_timeout) with an error and then closes the connection.
func (c *Conn) Close() []Query {
	var out []Query
	for _, g := range c.groups {
		for _, q := range g.queries {
			if q.ErrorCode != "" {
				q.Operation = operation(q.SQL, q.CommandTag)
				out = append(out, *q)
			}
		}
	}
	c.groups, c.open = nil, nil
	return out
}

func hash(parts ...any) uint64 {
	h := fnv.New64a()
	for i, p := range parts {
		if i > 0 {
			h.Write([]byte{0})
		}
		switch v := p.(type) {
		case string:
			h.Write([]byte(v))
		case []byte:
			h.Write(v)
		}
	}
	return h.Sum64()
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

// DebugState describes in-flight parser state (diagnostics).
func (c *Conn) DebugState() string {
	var b strings.Builder
	fmt.Fprintf(&b, "groups=%d open=%v nextID=%d fe{synced=%v buf=%d discard=%d} be{synced=%v buf=%d discard=%d}\n",
		len(c.groups), c.open != nil, c.nextID, c.fe.synced, len(c.fe.buf), c.fe.discard, c.be.synced, len(c.be.buf), c.be.discard)
	for i, g := range c.groups {
		fmt.Fprintf(&b, "  group %d: simple=%v next=%d failed=%v queries=", i, g.simple, g.next, g.failed)
		for _, q := range g.queries {
			sql := q.SQL
			if len(sql) > 40 {
				sql = sql[:40]
			}
			fmt.Fprintf(&b, "[q%d %q end=%d] ", q.ID, sql, q.End)
		}
		b.WriteString("\n")
	}
	return b.String()
}
