# TLS Capture Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Opt-in `-tls-capture` makes pgtrace trace TLS connections through pgbouncer by capturing plaintext with uprobes on pgbouncer's libssl, feeding the existing parser/correlator/export pipeline unchanged.

**Architecture:** A second BPF object (`bpf/tls.bpf.c`) shares the first object's maps (ring buffer, target pids, fd classes) and is loaded only when TLS capture is on. It emits the existing data event format with a TLS flag, tagged with the socket learned from `SSL_set_rfd`, or from a temporary `ksys_read`/`ksys_write` fallback for sessions opened before the agent. The agent treats TLS events as ordinary data. It holds at most one socket-less `SSL_write` event per process until its mapping arrives, tracks TLS state per connection, and passes `tls.*` attributes to export.

**Tech Stack:** Go 1.27, cilium/ebpf (bpf2go, uprobes, fentry), clang/libbpf, Prometheus client, docker compose, pgbench, OpenSSL 3.

**Spec:** `docs/superpowers/specs/2026-09-30-tls-capture-design.md`

## Global Constraints

- `-tls-capture` (env `PGTRACE_TLS_CAPTURE`) defaults to `false`. When off, the TLS BPF object is not loaded and nothing new is attached.
- Probes are attached per process with a PID filter. Never attach a libssl uprobe without a PID.
- Only `SSL_read`/`SSL_write` are supported. A pgbouncer that doesn't import both is `unsupported`.
- Plaintext events: kind data, flag `F_TLS` (2), no `F_SEQ`. `fd` = −1 plus the session pointer in `addr[0:8]` when the socket is unknown.
- New event kinds: `K_TLS_FD` = 4, `K_TLS_INFO` = 5 (`dir` 0 = version, 1 = cipher; text in the payload, ≤ 32 bytes).
- The agent holds at most one socket-less event per process. It feeds that event only if the process's next event is the matching `K_TLS_FD`; otherwise it drops and counts it. Socket-less `SSL_read` events are dropped and counted.
- The fallback detaches 30 s after the last socket-less event.
- Span attributes: `tls.protocol.name` = `tls`, `tls.protocol.version` (e.g. `1.3`), `tls.cipher`. They are set only on TLS connections, per hop.
- `pgtrace_connections{side,tls}`. When TLS capture is on, also: `pgtrace_tls_processes{state}`, `pgtrace_tls_fallback_attached`, `pgtrace_tls_unresolved_total{result}`, and 11 new recursion-miss programs.
- Series ceilings: base 2,541 with TLS capture off, 2,557 with it on. With the default label limit (200): 8,975 and 8,991.
- The generated BPF objects (`*_bpfel.o`, `*_bpfel.go`) are committed, as today.
- BPF program names are unique within their first 15 characters (the kernel truncates names; recursion-miss metrics are keyed by them).
- Commit messages end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

1. **pgbouncer restarts, or several pgbouncer processes, while the agent runs.** Probes follow each pid: new pids get attached, gone pids get detached, and failures are counted. Pinned by `TestTLSSyncAttachesAndDetaches` (Task 6) and e2e step 5 (Task 8).
2. **fd reuse after a TLS connection closes.** A plain connection on the same fd number must not inherit TLS state or attributes. Pinned by `TestTLSStateClearedOnClose` (Task 5).
3. **TLS traffic with capture off.** Connections are still labelled `tls="true"` from the `S` answer, and nothing breaks. Pinned by `TestTLSFromSSLAnswerWithoutCapture` (Task 5).
4. **A held event followed by an unrelated event of the same process**, including a mapping for a different session. It is dropped, never fed late. Pinned by `TestHeldEventDroppedWhenOtherEventFirst` (Task 5).
5. **Odd version/cipher strings from OpenSSL** (`TLSv1`, empty, long or non-UTF-8 text). These are normalised or cleaned, never exported raw. Pinned by `TestTLSVersionNormalised` (Task 5) and `TestExportTLSAttributes` (Task 3).

---

### Task 1: pgwire reports a TLS-accepted connection

**Files:**
- Modify: `internal/pgwire/stream.go` (the `stream` struct, the `expectSSL` block in `feed`)
- Modify: `internal/pgwire/conn.go` (add `TLS()`)
- Test: `internal/pgwire/conn_test.go`

**Interfaces:**
- Produces: `func (c *Conn) TLS() bool`. It is true once the backend stream consumed an `S` answer to an SSLRequest.

- [ ] **Step 1: Write the failing tests** (append to `internal/pgwire/conn_test.go`)

```go
func TestSSLAcceptedThenPlaintext(t *testing.T) {
	c := NewConn()
	feed(c, S, 1, sslRequest())
	feed(c, R, 2, []byte{'S'})
	if !c.TLS() {
		t.Fatal("TLS() false after an 'S' answer")
	}
	// With TLS capture the next events on the socket are the plaintext.
	feed(c, S, 3, startup("app"))
	feed(c, R, 4, cat(bAuthOK(), bReady()))
	feed(c, S, 5, fQuery("select 1"))
	got := feed(c, R, 6, cat(selectResult(1), bReady()))
	if len(got) != 1 || got[0].SQL != "select 1" {
		t.Fatalf("got %+v", got)
	}
}

func TestSSLAcceptedClientSide(t *testing.T) {
	c := NewClientConn()
	c.Feed(R, 1, sslRequest(), 8)
	c.Feed(S, 2, []byte{'S'}, 1)
	p := startupParams("user", "alice", "database", "shop")
	c.Feed(R, 3, p, uint32(len(p)))
	if !c.TLS() || c.Params()["user"] != "alice" {
		t.Fatalf("tls=%v params=%v", c.TLS(), c.Params())
	}
}
```

Also add a line at the end of the existing `TestSSLRequestRefused`, before its closing brace:

```go
	if c.TLS() {
		t.Fatal("TLS() true after an 'N' answer")
	}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/pgwire -run 'TestSSL' -count=1`
Expected: FAIL to compile with `c.TLS undefined`.

- [ ] **Step 3: Implement**

In `internal/pgwire/stream.go`, add a field to `stream` after `expectSSL`:

```go
	tls       bool   // backend: consumed an 'S' answer; the rest of the connection is TLS
```

In `feed`, replace the `expectSSL` block's consume line:

```go
			if p[0] == 'N' || p[0] == 'S' || p[0] == 'G' {
				s.tls = s.tls || p[0] == 'S'
				p = p[1:]
			}
```

`reset()` must not clear `tls`: a resync doesn't make a connection plain.

In `internal/pgwire/conn.go`, after `Params()`:

```go
// TLS reports whether the connection negotiated TLS (the server answered an
// SSLRequest with 'S'). Its later bytes are only seen with TLS capture.
func (c *Conn) TLS() bool { return c.be.tls }
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/pgwire -count=1`
Expected: `ok`.

- [ ] **Step 5: Commit**

```bash
git add internal/pgwire
git commit -m "pgwire: report connections that accepted TLS

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2: Event format for TLS (shared BPF header, decode, event types)

**Files:**
- Create: `bpf/pgtrace.h` (common definitions moved out of `bpf/pgtrace.bpf.c`)
- Modify: `bpf/pgtrace.bpf.c` (include the header; no behaviour change)
- Modify: `internal/event/event.go`
- Modify: `internal/capture/decode.go`
- Regenerate: `internal/capture/pgtrace_x86_bpfel.{go,o}`
- Test: `internal/capture/decode_test.go`

**Interfaces:**
- Produces:
  - `event.Data` gains `TLS bool` and `Session uint64` (set when `Key.FD == -1`).
  - `type event.TLSFD struct { TS uint64; Key ConnKey; Session uint64 }`
  - `type event.TLSAttr struct { TS uint64; Key ConnKey; Session uint64; Version, Cipher string }` (exactly one of Version/Cipher set).
  - C: `bpf/pgtrace.h` defines `struct event`, `K_TLS_FD`, `K_TLS_INFO`, `F_SEQ`, `F_TLS`, the maps `target_pids`, `fd_class`, `events`, `scratch`, `drops`, and the helpers `traced`, `count_drop`, `rb_flags`, `ignored`, `new_event`.

- [ ] **Step 1: Write the failing decode tests** (append to `internal/capture/decode_test.go`)

```go
func TestDecodeTLSData(t *testing.T) {
	raw := append(header(0, 0, -1, 5, 5), "hello"...)
	binary.LittleEndian.PutUint64(raw[32:], 0xdeadbeef)
	binary.LittleEndian.PutUint32(raw[52:], flagTLS)
	got, err := decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	want := event.Data{TS: 777, Key: event.ConnKey{PID: 42, FD: -1}, Dir: event.DirSend, TotalLen: 5,
		Payload: []byte("hello"), TLS: true, Session: 0xdeadbeef}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v", got)
	}
	// With a known fd the session is not reported.
	raw = append(header(0, 1, 7, 2, 2), "ok"...)
	binary.LittleEndian.PutUint64(raw[32:], 0xdeadbeef)
	binary.LittleEndian.PutUint32(raw[52:], flagTLS)
	got, _ = decode(raw)
	if d := got.(event.Data); !d.TLS || d.Session != 0 || d.Key.FD != 7 || d.HasSeq {
		t.Fatalf("got %+v", d)
	}
}

func TestDecodeTLSFD(t *testing.T) {
	raw := header(4, 0, 9, 0, 0)
	binary.LittleEndian.PutUint64(raw[32:], 0xabc)
	got, err := decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if want := (event.TLSFD{TS: 777, Key: event.ConnKey{PID: 42, FD: 9}, Session: 0xabc}); got != want {
		t.Fatalf("got %+v", got)
	}
}

func TestDecodeTLSInfo(t *testing.T) {
	raw := append(header(5, 0, 9, 0, 7), "TLSv1.3"...)
	binary.LittleEndian.PutUint64(raw[32:], 0xabc)
	got, _ := decode(raw)
	if want := (event.TLSAttr{TS: 777, Key: event.ConnKey{PID: 42, FD: 9}, Session: 0xabc, Version: "TLSv1.3"}); got != want {
		t.Fatalf("got %+v", got)
	}
	raw = append(header(5, 1, 9, 0, 22), "TLS_AES_256_GCM_SHA384"...)
	got, _ = decode(raw)
	if a := got.(event.TLSAttr); a.Cipher != "TLS_AES_256_GCM_SHA384" || a.Version != "" {
		t.Fatalf("got %+v", a)
	}
	if _, err := decode(header(5, 0, 9, 0, 40)); err == nil {
		t.Fatal("expected error for cap_len beyond the record")
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/capture -run TestDecodeTLS -count=1`
Expected: FAIL to compile (`flagTLS`, `event.TLSFD`, `event.TLSAttr` undefined; unknown fields `TLS`, `Session`).

- [ ] **Step 3: Add the event types** (`internal/event/event.go`)

Add to `Data`, after `HasSeq bool`:

```go
	// TLS: plaintext captured inside pgbouncer's TLS library (SSL_read /
	// SSL_write), not at the socket. Such events have no stream offset.
	TLS bool
	// Session is the TLS session pointer when the socket isn't known yet
	// (Key.FD == -1); zero otherwise.
	Session uint64
```

Append:

```go
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
```

- [ ] **Step 4: Decode them** (`internal/capture/decode.go`)

Replace `const flagSeq = 1` with:

```go
const (
	flagSeq = 1
	flagTLS = 2
)
```

Add to the kind constants:

```go
	kindTLSFD   = 4
	kindTLSInfo = 5
```

In `decode`, replace the `case kindData:` block with:

```go
	case kindData:
		capLen := int(le.Uint32(raw[20:]))
		if headerSize+capLen > len(raw) {
			return nil, fmt.Errorf("cap_len %d exceeds record of %d bytes", capLen, len(raw))
		}
		flags := le.Uint32(raw[52:])
		d := event.Data{
			TS:       ts,
			Key:      key,
			Dir:      event.Dir(raw[25]),
			TotalLen: le.Uint32(raw[16:]),
			Payload:  append([]byte(nil), raw[headerSize:headerSize+capLen]...),
			Seq:      le.Uint32(raw[48:]),
			HasSeq:   flags&flagSeq != 0,
			TLS:      flags&flagTLS != 0,
		}
		if d.TLS && key.FD < 0 {
			d.Session = le.Uint64(raw[32:])
		}
		return d, nil
	case kindTLSFD:
		return event.TLSFD{TS: ts, Key: key, Session: le.Uint64(raw[32:])}, nil
	case kindTLSInfo:
		capLen := int(le.Uint32(raw[20:]))
		if headerSize+capLen > len(raw) {
			return nil, fmt.Errorf("cap_len %d exceeds record of %d bytes", capLen, len(raw))
		}
		a := event.TLSAttr{TS: ts, Key: key, Session: le.Uint64(raw[32:])}
		s := string(raw[headerSize : headerSize+capLen])
		if raw[25] == 0 {
			a.Version = s
		} else {
			a.Cipher = s
		}
		return a, nil
```

Update the `decode` doc comment to: `// decode turns one ringbuf record into an event.Data, Connect, Accept, Close, TLSFD or TLSAttr.`

- [ ] **Step 5: Run the decode tests**

Run: `go test ./internal/capture -count=1`
Expected: `ok`.

- [ ] **Step 6: Move common BPF definitions into `bpf/pgtrace.h`**

Create `bpf/pgtrace.h` with everything that `pgtrace.bpf.c` currently defines from its first `#include` up to and including `new_event()`. Leave out the CO-RE kernel structs (`fdtable` … `tcp_sock`), `RCV_SHUTDOWN` and `IPPROTO_TCP`, which stay in `pgtrace.bpf.c`. Make these changes as you move it:

```c
// SPDX-License-Identifier: (MIT OR GPL-2.0-only)
// Definitions shared by pgtrace.bpf.c (socket capture) and tls.bpf.c (TLS
// plaintext capture). Both objects declare these maps; the agent loads the
// TLS object with the socket object's maps, so they are the same maps.
#ifndef PGTRACE_H
#define PGTRACE_H

#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

/* … MAX_PAYLOAD, EINPROGRESS, AF_*, WAKEUP_BYTES, CLASS_IGNORE, capture_bytes as today … */

enum kind { K_DATA = 0, K_CONNECT = 1, K_CLOSE = 2, K_ACCEPT = 3, K_TLS_FD = 4, K_TLS_INFO = 5 };
enum dir { D_SEND = 0, D_RECV = 1 };

/* struct event exactly as today; comment the addr field: */
	__u8 addr[16]; // peer address; for TLS events with fd == -1 and K_TLS_*: the session pointer in addr[0:8]

#define F_SEQ 1
#define F_TLS 2 // plaintext from the TLS library, no stream offset

/* target_pids, struct fd_key, fd_class, events, scratch, drops, traced(),
   count_drop(), rb_flags(), ignored() exactly as today */

static __always_inline struct event *new_event(__u64 pid_tgid, __s32 fd, __u8 kind)
{
	__u32 zero = 0;
	struct event *e = bpf_map_lookup_elem(&scratch, &zero);
	if (!e)
		return NULL;
	e->ts = bpf_ktime_get_ns();
	e->tgid = pid_tgid >> 32;
	e->fd = fd;
	e->kind = kind;
	e->dir = 0;
	e->family = 0;
	e->total_len = 0;
	e->cap_len = 0;
	e->seq = 0;
	e->flags = 0;
	return e;
}

#endif
```

In `bpf/pgtrace.bpf.c`, replace the moved block with `#include "pgtrace.h"` (after the file's top comment), and delete its own `#define F_SEQ 1`. `new_event` now zeroes `seq`/`flags`; `emit_data` still sets them afterwards, so its behaviour is unchanged.

- [ ] **Step 7: Regenerate and run the whole suite**

Run: `go generate ./internal/capture && go vet ./... && go test -race -count=1 ./...`
Expected: generate succeeds; all packages `ok`.

- [ ] **Step 8: Commit**

```bash
git add bpf internal/event internal/capture
git commit -m "Event format for TLS: shared BPF header, TLS data flag, TLS fd and info events

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3: Export `tls.*` attributes per hop

**Files:**
- Modify: `internal/export/export.go`
- Modify: `internal/export/export_test.go`, `internal/export/bench_test.go`

**Interfaces:**
- Produces:

```go
type TLSInfo struct {
	On      bool
	Version string // "1.3", "1.2", …; empty if unknown
	Cipher  string // e.g. "TLS_AES_256_GCM_SHA384"; empty if unknown
}
type ServerConn struct {
	Addr netip.AddrPort
	TLS  TLSInfo
}
// ClientInfo.TLS, Span.TLS, ConnError.TLS TLSInfo
func (e *Exporter) ExportTrace(t correlate.Trace, reason sampler.Reason, client ClientInfo, server func(event.ConnKey) ServerConn)
```

- [ ] **Step 1: Write the failing test** (append to `internal/export/export_test.go`)

```go
func TestExportTLSAttributes(t *testing.T) {
	e, col, _ := newTest(t, nil)
	tr := correlate.Trace{
		Client: &correlate.ClientQuery{Key: event.ConnKey{PID: 1, FD: 11}, Q: pgwire.Query{Start: 1, End: 10, SQL: "select 1", Operation: "SELECT"}},
		Server: []correlate.ServerQuery{{Key: event.ConnKey{PID: 1, FD: 7}, Correlation: "exact", Q: pgwire.Query{Start: 2, End: 9, SQL: "select 1", Operation: "SELECT"}}},
	}
	info := ClientInfo{TLS: TLSInfo{On: true, Version: "1.3", Cipher: "TLS_AES_256_GCM_SHA384" + strings.Repeat("x", 100)}}
	// Client hop TLS, server hop plain.
	e.ExportTrace(tr, sampler.ReasonRatio, info, func(event.ConnKey) ServerConn { return ServerConn{} })
	e.ExportConnError(ConnError{Client: true, Key: event.ConnKey{PID: 1, FD: 12}, End: 5, Code: "28P01", TLS: TLSInfo{On: true}})
	drain(t, e)
	var root, child, conn map[string]*commonpb.AnyValue
	for _, s := range col.spans() {
		switch {
		case s.Name == "connect":
			conn = spanAttrs(s.Span)
		case s.Kind == tracepb.Span_SPAN_KIND_SERVER:
			root = spanAttrs(s.Span)
		default:
			child = spanAttrs(s.Span)
		}
	}
	if root["tls.protocol.name"].GetStringValue() != "tls" || root["tls.protocol.version"].GetStringValue() != "1.3" ||
		len(root["tls.cipher"].GetStringValue()) != 64 {
		t.Fatalf("root %v", root)
	}
	for _, k := range []string{"tls.protocol.name", "tls.protocol.version", "tls.cipher"} {
		if _, ok := child[k]; ok {
			t.Fatalf("plain server hop has %s", k)
		}
	}
	if conn["tls.protocol.name"].GetStringValue() != "tls" {
		t.Fatalf("connect span %v", conn)
	}
	if _, ok := conn["tls.protocol.version"]; ok {
		t.Fatal("unknown version exported")
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/export -run TestExportTLSAttributes -count=1`
Expected: FAIL to compile (`TLSInfo`, `ServerConn` undefined).

- [ ] **Step 3: Implement** (`internal/export/export.go`)

Add after the `Span` type:

```go
// TLSInfo describes a connection's TLS, if any. Version and Cipher are
// best-effort (known when pgbouncer asked OpenSSL for them).
type TLSInfo struct {
	On      bool
	Version string // "1.3", "1.2", …; empty if unknown
	Cipher  string // e.g. "TLS_AES_256_GCM_SHA384"; empty if unknown
}

// ServerConn describes the server connection of one server query.
type ServerConn struct {
	Addr netip.AddrPort
	TLS  TLSInfo
}
```

Add a field `TLS TLSInfo` to `Span`, to `ClientInfo` (comment: `// TLS of the client connection`) and to `ConnError`.

Change `job.servers` to `servers []ServerConn // server connection of each trace.Server entry`.

Change `ExportTrace`'s signature and doc:

```go
// ExportTrace queues a client query (SERVER span) with its server queries
// (CLIENT children). Traces without a client query export each server query
// as its own trace. server is resolved now, on the caller's goroutine.
func (e *Exporter) ExportTrace(t correlate.Trace, reason sampler.Reason, client ClientInfo, server func(event.ConnKey) ServerConn) {
```

Its loop body stays `j.servers = append(j.servers, server(sq.Key))`.

In `trace()`, change the child span literal to:

```go
			Span{Q: sq.Q, PID: sq.Key.PID, FD: sq.Key.FD, Remote: j.servers[i].Addr, TLS: j.servers[i].TLS, Reason: j.reason},
```

In `trace()`, after `w.clientParams(j.client.Params)`, add `w.tlsAttrs(j.client.TLS)`.

In `serverSpan()`, after the `if s.Remote.IsValid() { … }` block, add `w.tlsAttrs(s.TLS)`.

In `connError()`, after `w.clientParams(c.Params)`, add `w.tlsAttrs(c.TLS)`.

Add, after `clientParams`:

```go
// tlsAttrs adds the OpenTelemetry tls.* attributes of a TLS connection.
func (w *worker) tlsAttrs(t TLSInfo) {
	if !t.On {
		return
	}
	w.a.str("tls.protocol.name", "tls")
	if t.Version != "" {
		w.a.str("tls.protocol.version", clean(t.Version, 16))
	}
	if t.Cipher != "" {
		w.a.str("tls.cipher", clean(t.Cipher, 64))
	}
}
```

- [ ] **Step 4: Update the existing tests for the new resolver type**

In `internal/export/export_test.go`:
- `func noAddr(event.ConnKey) netip.AddrPort { return netip.AddrPort{} }` becomes `func noAddr(event.ConnKey) ServerConn { return ServerConn{} }`.
- In `TestExportTrace`, the resolver becomes `func(event.ConnKey) ServerConn { return ServerConn{Addr: netip.MustParseAddrPort("10.0.0.2:5432")} }`.

In `internal/export/bench_test.go`, `servers: []netip.AddrPort{netip.MustParseAddrPort("10.0.0.2:5432")}` becomes `servers: []ServerConn{{Addr: netip.MustParseAddrPort("10.0.0.2:5432")}}`.

- [ ] **Step 5: Run the export tests**

Run: `go test -race -count=1 ./internal/export`
Expected: `ok`. The other packages don't compile until Task 5 updates the resolver in `cmd/pgtrace-agent`; `go vet ./internal/export` must pass.

- [ ] **Step 6: Commit**

```bash
git add internal/export
git commit -m "export: tls.* attributes per hop; server resolver returns address and TLS

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 4: Metrics for TLS

**Files:**
- Modify: `internal/metrics/metrics.go`
- Test: `internal/metrics/metrics_test.go`, `internal/metrics/cardinality_test.go`

**Interfaces:**
- Produces:

```go
// metrics.Config gains: TLS bool // -tls-capture: register the TLS series
func (m *Metrics) SetConnections(side string, tls bool, n int)
func (m *Metrics) TLSUnresolved(result string) // "resolved" | "dropped"; no-op unless Config.TLS
func (m *Metrics) RegisterTLS(processes func() (attached, unsupported int), fallback func() bool)
```

- [ ] **Step 1: Write the failing tests**

Append to `internal/metrics/metrics_test.go`:

```go
func TestTLSMetrics(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewWith(reg, Config{TLS: true})
	m.SetConnections("client", true, 3)
	m.SetConnections("client", false, 2)
	m.TLSUnresolved("resolved")
	m.TLSUnresolved("resolved")
	m.TLSUnresolved("dropped")
	m.RegisterTLS(func() (int, int) { return 2, 1 }, func() bool { return true })
	got := map[string]float64{}
	mfs, _ := reg.Gather()
	for _, mf := range mfs {
		for _, mm := range mf.Metric {
			key := mf.GetName()
			for _, l := range mm.Label {
				key += "," + l.GetName() + "=" + l.GetValue()
			}
			got[key] = mm.GetGauge().GetValue() + mm.GetCounter().GetValue()
		}
	}
	want := map[string]float64{
		"pgtrace_connections,side=client,tls=true":         3,
		"pgtrace_connections,side=client,tls=false":        2,
		"pgtrace_tls_unresolved_total,result=resolved":     2,
		"pgtrace_tls_unresolved_total,result=dropped":      1,
		"pgtrace_tls_processes,state=attached":             2,
		"pgtrace_tls_processes,state=unsupported":          1,
		"pgtrace_tls_fallback_attached":                    1,
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %v, want %v", k, got[k], v)
		}
	}
}

func TestTLSUnresolvedNoopWithoutTLS(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := New(reg)
	m.TLSUnresolved("dropped")
	mfs, _ := reg.Gather()
	for _, mf := range mfs {
		if strings.HasPrefix(mf.GetName(), "pgtrace_tls_") {
			t.Fatalf("%s registered without TLS capture", mf.GetName())
		}
	}
}
```

Add `"strings"` to that file's imports if it isn't there.

In `internal/metrics/cardinality_test.go`, replace the two `m.SetConnections(...)` lines with:

```go
	for _, side := range []string{"client", "server"} {
		m.SetConnections(side, true, 1)
		m.SetConnections(side, false, 1)
	}
```

Then append:

```go
func TestSeriesBoundedWithTLS(t *testing.T) {
	reg := prometheus.NewRegistry()
	cfg := Config{TLS: true}
	m := NewWith(reg, cfg)
	m.RegisterKernel(func() uint64 { return 0 }, func() (time.Duration, uint64) { return 0, 0 }, true)
	progs := map[string]uint64{}
	for _, p := range []string{"exit_sendto", "exit_recvfrom", "exit_connect", "exit_accept4", "enter_close",
		"ssl_write", "ssl_write_ret", "ssl_read_enter", "ssl_read_exit", "ssl_set_rfd", "ssl_free",
		"ssl_ver_enter", "ssl_ver_exit", "ssl_cipher_exit", "fallback_read", "fallback_write"} {
		progs[p] = 1
	}
	m.RegisterRecursionMisses(func() map[string]uint64 { return progs })
	m.RegisterTLS(func() (int, int) { return 1, 0 }, func() bool { return false })
	r := rand.New(rand.NewPCG(3, 4))
	for i := 0; i < 5000; i++ {
		m.ObserveTrace(randomTrace(r), Client{})
		m.Event([]string{"data", "connect", "accept", "close"}[r.IntN(4)])
		m.Truncation([]string{"kernel", "parser", "export"}[r.IntN(3)])
		m.SpanDecision("ratio", r.IntN(2) == 0)
		m.TLSUnresolved([]string{"resolved", "dropped"}[r.IntN(2)])
		m.CaptureGap([]string{"client", "server"}[r.IntN(2)], 1)
		m.ParserResync([]string{"client", "server"}[r.IntN(2)])
	}
	for _, side := range []string{"client", "server"} {
		m.SetConnections(side, true, 1)
		m.SetConnections(side, false, 1)
	}
	m.SetTracedProcesses(1)
	got, ceiling := series(t, reg), MaxSeries(cfg)
	t.Logf("series: %d, ceiling: %d", got, ceiling)
	if got > ceiling {
		t.Fatalf("%d series exceed the ceiling %d", got, ceiling)
	}
	if MaxSeries(Config{}) != 2541 || ceiling != 2557 {
		t.Fatalf("ceilings %d / %d, want 2541 / 2557", MaxSeries(Config{}), ceiling)
	}
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `go test ./internal/metrics -count=1`
Expected: FAIL to compile (`Config.TLS`, `TLSUnresolved`, `RegisterTLS` undefined; wrong `SetConnections` arity).

- [ ] **Step 3: Implement** (`internal/metrics/metrics.go`)

- Add `TLS bool // -tls-capture: register the TLS series` to `Config`.
- Add a field `tlsUnresolved *prometheus.CounterVec` to `Metrics`, after `gapBytes`.
- Change the `conns` definition to:

```go
		conns: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "pgtrace_connections", Help: "Tracked pgbouncer sockets, by side and whether they use TLS.",
		}, []string{"side", "tls"}),
```

- In `NewWith`, after `reg.MustRegister(...)`:

```go
	if cfg.TLS {
		m.tlsUnresolved = prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "pgtrace_tls_unresolved_total",
			Help: "TLS plaintext events whose socket wasn't known when captured: fed once their socket was found (resolved) or dropped.",
		}, []string{"result"})
		reg.MustRegister(m.tlsUnresolved)
	}
```

- Replace `SetConnections`:

```go
func (m *Metrics) SetConnections(side string, tls bool, n int) {
	m.conns.WithLabelValues(side, strconv.FormatBool(tls)).Set(float64(n))
}
```

(add `"strconv"` to the imports if missing)

- Add after `SetTracedProcesses`:

```go
// TLSUnresolved counts a socket-less TLS event: "resolved" or "dropped".
func (m *Metrics) TLSUnresolved(result string) {
	if m.tlsUnresolved != nil {
		m.tlsUnresolved.WithLabelValues(result).Inc()
	}
}

// RegisterTLS exposes TLS capture state, read on scrape.
func (m *Metrics) RegisterTLS(processes func() (attached, unsupported int), fallback func() bool) {
	proc := func(state string, pick func(a, u int) int) prometheus.Collector {
		return prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "pgtrace_tls_processes", Help: "pgbouncer processes with TLS probes attached, or whose TLS can't be captured.",
			ConstLabels: prometheus.Labels{"state": state},
		}, func() float64 { a, u := processes(); return float64(pick(a, u)) })
	}
	m.reg.MustRegister(
		proc("attached", func(a, _ int) int { return a }),
		proc("unsupported", func(_, u int) int { return u }),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "pgtrace_tls_fallback_attached", Help: "1 while the socket-finding fallback for pre-existing TLS sessions is attached.",
		}, func() float64 {
			if fallback() {
				return 1
			}
			return 0
		}),
	)
}
```

- In `MaxSeries`, change the connections term in the summed line from `2` to `4`, and update its comment (`… capture_gaps(+bytes), connections (side × tls), traced_processes`). Before `if len(cfg.Labels) > 0`, add:

```go
	if cfg.TLS {
		n += 2 + 1 + 2 + 11 // tls_processes, tls_fallback_attached, tls_unresolved, recursion misses of the TLS programs
	}
```

- [ ] **Step 4: Run the metrics tests**

Run: `go test -race -count=1 ./internal/metrics`
Expected: `ok`.

- [ ] **Step 5: Commit**

```bash
git add internal/metrics
git commit -m "metrics: tls label on connections; TLS processes, fallback and unresolved series

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 5: Agent: TLS state, held events, attributes; wire main

**Files:**
- Modify: `internal/agent/agent.go`
- Modify: `cmd/pgtrace-agent/main.go`
- Test: `internal/agent/tls_test.go` (new)

**Interfaces:**
- Consumes:
  - `pgwire.(*Conn).TLS()` (Task 1);
  - `event.TLSFD`, `event.TLSAttr`, `event.Data.TLS/Session` (Task 2);
  - `export.TLSInfo`, `export.ServerConn` (Task 3);
  - `Metrics.TLSUnresolved`, `SetConnections(side, tls, n)` (Task 4).
- Produces:

```go
type TLSFallback interface{ TLSNeedFallback() }
// Agent.Fallback TLSFallback (optional)
func (a *Agent) TLSInfo(k event.ConnKey) export.TLSInfo // call from the Run goroutine (e.g. in the sink)
// Stats gains ServerTLS, ClientTLS uint64
```

- [ ] **Step 1: Write the failing tests** (create `internal/agent/tls_test.go`)

```go
package agent

import (
	"context"
	"net/netip"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/t1bur1an/pgtrace-ebpf/internal/connmap"
	"github.com/t1bur1an/pgtrace-ebpf/internal/correlate"
	"github.com/t1bur1an/pgtrace-ebpf/internal/event"
	"github.com/t1bur1an/pgtrace-ebpf/internal/export"
	"github.com/t1bur1an/pgtrace-ebpf/internal/metrics"
)

type fakeFallback struct{ n int }

func (f *fakeFallback) TLSNeedFallback() { f.n++ }

func tlsData(k event.ConnKey, dir event.Dir, ts uint64, p []byte) event.Data {
	d := data(k, dir, ts, p)
	d.TLS = true
	return d
}

// runTLS runs events through an agent with TLS metrics; it returns the
// traces, the agent and the unresolved counters.
func runTLS(t *testing.T, fb TLSFallback, evs ...any) ([]got, *Agent, map[string]float64) {
	t.Helper()
	reg := prometheus.NewRegistry()
	met := metrics.NewWith(reg, metrics.Config{TLS: true})
	cm := connmap.New(connmap.Config{ProcRoot: t.TempDir(), PGPort: 5432, ListenPort: 6432, ClientTracing: true})
	var out []got
	var a *Agent
	a = New(cm, func(tr correlate.Trace, info export.ClientInfo) {
		// The server connections' TLS as the exporter would resolve it.
		for _, sq := range tr.Server {
			info.Params = map[string]string{"server_tls": map[bool]string{true: "on", false: "off"}[a.TLSInfo(sq.Key).On]}
		}
		out = append(out, got{tr, info})
	})
	a.Metrics = met
	a.Fallback = fb
	events := make(chan any, len(evs))
	for _, e := range evs {
		events <- e
	}
	close(events)
	a.Run(context.Background(), events)
	counts := map[string]float64{}
	mfs, _ := reg.Gather()
	for _, mf := range mfs {
		if mf.GetName() == "pgtrace_tls_unresolved_total" {
			for _, m := range mf.Metric {
				counts[m.Label[0].GetValue()] = m.Counter.GetValue()
			}
		}
	}
	return out, a, counts
}

var sslAnswer = []byte{'S'}

func TestTLSTraceWithAttributes(t *testing.T) {
	out, _, _ := runTLS(t, nil,
		event.Accept{Key: client, Addr: peer},
		event.Connect{Key: server, Addr: netip.MustParseAddrPort("10.0.0.2:5432")},
		data(client, event.DirRecv, 1, sslRequestMsg),
		data(client, event.DirSend, 2, sslAnswer),
		event.TLSAttr{Key: client, Version: "TLSv1.3"},
		event.TLSAttr{Key: client, Cipher: "TLS_AES_256_GCM_SHA384"},
		tlsData(client, event.DirRecv, 3, q),
		data(server, event.DirSend, 4, q), // plain server hop
		data(server, event.DirRecv, 5, resp),
		tlsData(client, event.DirSend, 6, resp),
	)
	if len(out) != 1 || out[0].tr.Client == nil || len(out[0].tr.Server) != 1 {
		t.Fatalf("got %+v", out)
	}
	if want := (export.TLSInfo{On: true, Version: "1.3", Cipher: "TLS_AES_256_GCM_SHA384"}); out[0].info.TLS != want {
		t.Fatalf("client TLS %+v", out[0].info.TLS)
	}
	if out[0].info.Params["server_tls"] != "off" {
		t.Fatalf("server hop reported as TLS")
	}
}

func TestTLSFromSSLAnswerWithoutCapture(t *testing.T) {
	_, a, _ := runTLS(t, nil,
		event.Accept{Key: client, Addr: peer},
		data(client, event.DirRecv, 1, sslRequestMsg),
		data(client, event.DirSend, 2, sslAnswer),
	)
	if st := a.Stats(); st.Client != 1 || st.ClientTLS != 1 {
		t.Fatalf("stats %+v", st)
	}
	if !a.TLSInfo(client).On {
		t.Fatal("connection not marked TLS")
	}
}

func TestTLSStateClearedOnClose(t *testing.T) {
	_, a, _ := runTLS(t, nil,
		event.Accept{Key: client, Addr: peer},
		tlsData(client, event.DirRecv, 1, q),
		event.TLSAttr{Key: client, Version: "TLSv1.3"},
		event.Close{Key: client},
		event.Accept{Key: client, Addr: peer}, // fd reused by a plain connection
		data(client, event.DirRecv, 2, q),
	)
	if a.TLSInfo(client).On {
		t.Fatal("plain connection inherited TLS state")
	}
	if st := a.Stats(); st.ClientTLS != 0 || st.Client != 1 {
		t.Fatalf("stats %+v", st)
	}
}

func TestHeldEventResolvedByItsMapping(t *testing.T) {
	fb := &fakeFallback{}
	unknownClient := event.ConnKey{PID: client.PID, FD: -1}
	held := tlsData(unknownClient, event.DirSend, 6, resp)
	held.Session = 0xabc
	out, _, counts := runTLS(t, fb,
		event.Accept{Key: client, Addr: peer},
		event.Connect{Key: server, Addr: netip.MustParseAddrPort("10.0.0.2:5432")},
		tlsData(client, event.DirRecv, 1, q),
		data(server, event.DirSend, 2, q),
		data(server, event.DirRecv, 3, resp),
		held,
		event.TLSFD{Key: client, Session: 0xabc},
	)
	if len(out) != 1 || out[0].tr.Client == nil || out[0].tr.Client.Q.End != 6 {
		t.Fatalf("got %+v", out)
	}
	if counts["resolved"] != 1 || counts["dropped"] != 0 || fb.n == 0 {
		t.Fatalf("counts %v fallback %d", counts, fb.n)
	}
}

func TestHeldEventDroppedWhenOtherEventFirst(t *testing.T) {
	unknown := event.ConnKey{PID: client.PID, FD: -1}
	h1 := tlsData(unknown, event.DirSend, 2, resp)
	h1.Session = 0xabc
	h2 := tlsData(unknown, event.DirSend, 4, resp)
	h2.Session = 0xdef
	_, _, counts := runTLS(t, &fakeFallback{},
		event.Accept{Key: client, Addr: peer},
		h1,
		data(server, event.DirSend, 3, q),            // another event of the process first
		h2,
		event.TLSFD{Key: client, Session: 0x999},     // a mapping for a different session
	)
	if counts["dropped"] != 2 || counts["resolved"] != 0 {
		t.Fatalf("counts %v", counts)
	}
}

func TestSocketlessReadDropped(t *testing.T) {
	fb := &fakeFallback{}
	r := tlsData(event.ConnKey{PID: 1, FD: -1}, event.DirRecv, 1, q)
	r.Session = 1
	_, _, counts := runTLS(t, fb, r)
	if counts["dropped"] != 1 || fb.n != 1 {
		t.Fatalf("counts %v fallback %d", counts, fb.n)
	}
}

func TestTLSVersionNormalised(t *testing.T) {
	for in, want := range map[string]string{"TLSv1.3": "1.3", "TLSv1.2": "1.2", "TLSv1": "1.0", "": "", "SSLv3": "SSLv3"} {
		if got := tlsVersion(in); got != want {
			t.Errorf("tlsVersion(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestTLSAttrBeforeFirstData(t *testing.T) {
	_, a, _ := runTLS(t, nil,
		event.Connect{Key: server, Addr: netip.MustParseAddrPort("10.0.0.2:5432")},
		event.TLSAttr{Key: server, Cipher: "TLS_AES_128_GCM_SHA256"},
		tlsData(server, event.DirSend, 1, q),
	)
	if got := a.TLSInfo(server); !got.On || got.Cipher != "TLS_AES_128_GCM_SHA256" {
		t.Fatalf("got %+v", got)
	}
}
```

Add to `internal/agent/agent_test.go`'s `var (...)` block:

```go
	sslRequestMsg = []byte{0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f} // SSLRequest (80877103)
```

- [ ] **Step 2: Run them to verify they fail**

Run: `go test ./internal/agent -run 'TLS|Held|Socketless' -count=1`
Expected: FAIL to compile (`Fallback`, `TLSInfo`, `ClientTLS`, `tlsVersion` undefined).

- [ ] **Step 3: Implement the agent** (`internal/agent/agent.go`)

Add `ServerTLS, ClientTLS uint64 // …of which use TLS` to `Stats`.

Add to `conn`:

```go
	tls                   bool // negotiated TLS ('S' answer, or TLS events)
	tlsVersion, tlsCipher string
```

Add before `type Agent`:

```go
// TLSFallback is told when TLS plaintext arrives for a session whose socket
// isn't known yet, so the capture can attach its socket-finding fallback.
type TLSFallback interface{ TLSNeedFallback() }
```

Add fields to `Agent` (after `OnConnError`):

```go
	// Fallback, if set, is told about TLS events without a socket.
	Fallback TLSFallback
	held       map[uint32]event.Data           // pid → SSL_write event waiting for its socket
	tlsPending map[event.ConnKey]event.TLSAttr // version/cipher that arrived before the connection's first data
```

and `nserverTLS, nclientTLS atomic.Uint64` next to the other counters.

In `New`, initialise `held: map[uint32]event.Data{}, tlsPending: map[event.ConnKey]event.TLSAttr{}` in the literal.

In `emit()`, extend the ClientInfo literal: `info = export.ClientInfo{Addr: c.addr, Params: c.p.Params(), IdleInTx: c.idle[tr.Client.Q.ID], TLS: c.tlsInfo()}`.

Replace `handle` with:

```go
func (a *Agent) handle(ev any) {
	if len(a.held) > 0 {
		a.settle(ev)
	}
	switch ev := ev.(type) {
	case event.Connect:
		a.event("connect")
		a.drop(ev.Key)
		a.cm.OnConnect(ev.Key, ev.Addr)
		a.opened[ev.Key] = ev.TS
		a.classified(ev.Key)
	case event.Accept:
		a.event("accept")
		a.drop(ev.Key)
		a.cm.OnAccept(ev.Key, ev.Addr)
		a.opened[ev.Key] = ev.TS
		a.classified(ev.Key)
	case event.Close:
		a.event("close")
		if c := a.conns[ev.Key]; c != nil && c.inTxSince > 0 && ev.TS > c.inTxSince && a.Metrics != nil {
			a.Metrics.IdleInTransaction(time.Duration(ev.TS - c.inTxSince)) // closed while holding a transaction
		}
		delete(a.opened, ev.Key)
		delete(a.tlsPending, ev.Key)
		a.drop(ev.Key)
		a.cm.OnClose(ev.Key)
		// Also undoes an Ignore issued for this fd number by data events that
		// were still queued when the kernel saw the close.
		a.clear(ev.Key)
	case event.Data:
		a.event("data")
		if ev.TLS && ev.Key.FD < 0 {
			a.unresolved(ev)
			return
		}
		a.data(ev)
	case event.TLSFD:
		a.events.Add(1) // only matters to a held event; settle handled it
	case event.TLSAttr:
		a.events.Add(1)
		a.tlsAttr(ev)
	}
}

func pidOf(ev any) (uint32, bool) {
	switch ev := ev.(type) {
	case event.Data:
		return ev.Key.PID, true
	case event.Connect:
		return ev.Key.PID, true
	case event.Accept:
		return ev.Key.PID, true
	case event.Close:
		return ev.Key.PID, true
	case event.TLSFD:
		return ev.Key.PID, true
	case event.TLSAttr:
		return ev.Key.PID, true
	}
	return 0, false
}

// settle feeds or drops the held SSL_write event of ev's process. Only the
// socket mapping from the same SSL_write call may follow it: pgbouncer is
// single-threaded, so anything else means the mapping isn't coming, and
// feeding the event later would reorder it against other connections.
func (a *Agent) settle(ev any) {
	pid, ok := pidOf(ev)
	if !ok {
		return
	}
	h, ok := a.held[pid]
	if !ok {
		return
	}
	delete(a.held, pid)
	if m, ok := ev.(event.TLSFD); ok && m.Session == h.Session {
		h.Key.FD, h.Session = m.Key.FD, 0
		a.tlsUnresolved("resolved")
		a.data(h)
		return
	}
	a.tlsUnresolved("dropped")
}

// unresolved handles TLS plaintext captured before its socket was known.
func (a *Agent) unresolved(ev event.Data) {
	if a.Fallback != nil {
		a.Fallback.TLSNeedFallback()
	}
	if ev.Dir != event.DirSend {
		// SSL_read: its ciphertext read already happened; the next call on
		// the session will be mapped.
		a.tlsUnresolved("dropped")
		return
	}
	a.held[ev.Key.PID] = ev
}

func (a *Agent) tlsUnresolved(result string) {
	if a.Metrics != nil {
		a.Metrics.TLSUnresolved(result)
	}
}

// tlsAttr records a session's TLS version or cipher.
func (a *Agent) tlsAttr(ev event.TLSAttr) {
	if ev.Key.FD < 0 {
		return
	}
	if c := a.conns[ev.Key]; c != nil {
		c.setTLSAttr(ev)
		a.markTLS(c)
		return
	}
	p := a.tlsPending[ev.Key]
	if ev.Version != "" {
		p.Version = ev.Version
	}
	if ev.Cipher != "" {
		p.Cipher = ev.Cipher
	}
	a.tlsPending[ev.Key] = p
}

func (c *conn) setTLSAttr(ev event.TLSAttr) {
	if ev.Version != "" {
		c.tlsVersion = tlsVersion(ev.Version)
	}
	if ev.Cipher != "" {
		c.tlsCipher = ev.Cipher
	}
}

// tlsVersion turns OpenSSL's version name into the OpenTelemetry value:
// "TLSv1.3" → "1.3", "TLSv1" → "1.0".
func tlsVersion(s string) string {
	v, ok := strings.CutPrefix(s, "TLSv")
	if !ok {
		return s
	}
	if v == "1" {
		return "1.0"
	}
	return v
}

func (c *conn) tlsInfo() export.TLSInfo {
	if !c.tls {
		return export.TLSInfo{}
	}
	return export.TLSInfo{On: true, Version: c.tlsVersion, Cipher: c.tlsCipher}
}

// markTLS records that a connection uses TLS.
func (a *Agent) markTLS(c *conn) {
	if c.tls {
		return
	}
	c.tls = true
	a.countTLS(c.side, 1)
}

// TLSInfo returns a tracked connection's TLS. Call it from the Run
// goroutine, e.g. inside the sink.
func (a *Agent) TLSInfo(k event.ConnKey) export.TLSInfo {
	if c := a.conns[k]; c != nil {
		return c.tlsInfo()
	}
	return export.TLSInfo{}
}

func (a *Agent) countTLS(side connmap.Side, delta int64) {
	switch side {
	case connmap.SideServer:
		a.nserverTLS.Add(uint64(delta))
	case connmap.SideClient:
		a.nclientTLS.Add(uint64(delta))
	}
}
```

In `drop()`, before `delete(a.conns, k)`, add:

```go
	if c.tls {
		a.countTLS(c.side, -1)
	}
```

In `data()`, right after `a.count(c.side, 1)` inside the new-connection block, add:

```go
		if p, ok := a.tlsPending[ev.Key]; ok {
			c.setTLSAttr(p)
			a.markTLS(c)
			delete(a.tlsPending, ev.Key)
		}
```

After the closing brace of that block, add:

```go
	if ev.TLS {
		a.markTLS(c)
	}
```

At the end of `data()`, after the final `a.process(...)` call, add:

```go
	if !c.tls && c.p.TLS() {
		a.markTLS(c) // the server accepted an SSLRequest
	}
```

In `process()`, add `TLS: c.tlsInfo()` to the `export.ConnError` literal.

Replace `Stats()`:

```go
func (a *Agent) Stats() Stats {
	return Stats{Events: a.events.Load(), Queries: a.queries.Load(), Server: a.nserver.Load(), Client: a.nclient.Load(),
		ServerTLS: a.nserverTLS.Load(), ClientTLS: a.nclientTLS.Load()}
}
```

- [ ] **Step 4: Run the agent tests**

Run: `go test -race -count=1 ./internal/agent`
Expected: `ok`. The existing tests still pass because plain events carry `TLS=false`.

- [ ] **Step 5: Wire main** (`cmd/pgtrace-agent/main.go`)

Replace the resolver and agent construction:

```go
	// Peek, not Lookup: an orphan's server may already be closed, and
	// resolving its fd number again could cache a reused fd's details.
	var ag *agent.Agent
	serverConn := func(k event.ConnKey) export.ServerConn {
		info, _ := cm.Peek(k)
		return export.ServerConn{Addr: info.Remote, TLS: ag.TLSInfo(k)}
	}
	smp := sampler.New(c.ratio, time.Duration(c.slowMS)*time.Millisecond, uint64(time.Now().UnixNano()))
	ag = agent.New(cm, func(tr correlate.Trace, client export.ClientInfo) {
```

In that closure, change `exp.ExportTrace(tr, reason, client, serverAddr)` to `exp.ExportTrace(tr, reason, client, serverConn)`.

Replace the two `met.SetConnections` lines:

```go
				met.SetConnections("server", true, int(st.ServerTLS))
				met.SetConnections("server", false, int(st.Server-st.ServerTLS))
				met.SetConnections("client", true, int(st.ClientTLS))
				met.SetConnections("client", false, int(st.Client-st.ClientTLS))
```

In the stats `slog.Info`, add `"server_tls", st.ServerTLS, "client_tls", st.ClientTLS` after `"client_conns", st.Client`.

- [ ] **Step 6: Build and test everything**

Run: `go vet ./... && go test -race -count=1 ./...`
Expected: all `ok`.

- [ ] **Step 7: Commit**

```bash
git add internal/agent cmd/pgtrace-agent
git commit -m "agent: TLS connection state, held socket-less events, tls attributes per hop

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 6: TLS capture: BPF programs, discovery, attach, fallback; `-tls-capture`

**Files:**
- Create: `bpf/tls.bpf.c`
- Create: `internal/capture/tls.go`
- Create: `internal/capture/tls_test.go`
- Modify: `internal/capture/gen.go` (second bpf2go line)
- Modify: `internal/capture/capture.go` (Config.TLS, load, rescan hook, progs, Close)
- Modify: `cmd/pgtrace-agent/main.go` (flag, config, metrics, fallback)
- Modify: `deploy/docker-compose.yml` (agent env)
- Generated: `internal/capture/tls_x86_bpfel.{go,o}`

**Interfaces:**
- Consumes: `bpf/pgtrace.h` (Task 2); `agent.TLSFallback` (Task 5); `metrics.RegisterTLS`, `metrics.Config.TLS` (Task 4).
- Produces:

```go
// capture.Config gains: TLS bool // capture plaintext of pgbouncer's TLS connections (libssl uprobes)
func (c *Capture) TLSNeedFallback()
func (c *Capture) TLSProcesses() (attached, unsupported int)
func (c *Capture) TLSFallbackAttached() bool
func libsslPath(maps io.Reader) (string, bool)
func importsAll(path string, names ...string) (bool, error)
```

- [ ] **Step 1: Write the failing unit tests** (create `internal/capture/tls_test.go`)

```go
package capture

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestLibsslPath(t *testing.T) {
	maps := `55d0a0a00000-55d0a0a2c000 r--p 00000000 00:3a 1234 /usr/bin/pgbouncer
7f1c2a000000-7f1c2a05f000 r--p 00000000 00:3a 5678 /usr/lib/libcrypto.so.3
7f1c2b000000-7f1c2b01f000 r--p 00000000 00:3a 9012 /usr/lib/libssl.so.3
7f1c2b01f000-7f1c2b07f000 r-xp 0001f000 00:3a 9012 /usr/lib/libssl.so.3
7ffd00000000-7ffd00021000 rw-p 00000000 00:00 0 [stack]
`
	if p, ok := libsslPath(strings.NewReader(maps)); !ok || p != "/usr/lib/libssl.so.3" {
		t.Fatalf("got %q %v", p, ok)
	}
	if _, ok := libsslPath(strings.NewReader("7f1c2a000000-7f1c2a05f000 r--p 00000000 00:3a 5678 /usr/lib/libcrypto.so.3\n")); ok {
		t.Fatal("found libssl in a listing without it")
	}
}

func TestImportsAll(t *testing.T) {
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("no C compiler")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "fx.c")
	os.WriteFile(src, []byte("int SSL_read(void*,void*,int); int SSL_write(void*,const void*,int);\n"+
		"int f(void){ return SSL_read(0,0,0) + SSL_write(0,0,0); }\n"), 0o644)
	so := filepath.Join(dir, "fx.so")
	if out, err := exec.Command(cc, "-shared", "-fPIC", "-o", so, src).CombinedOutput(); err != nil {
		t.Skipf("cc failed: %v %s", err, out)
	}
	if ok, err := importsAll(so, "SSL_read", "SSL_write"); err != nil || !ok {
		t.Fatalf("got %v %v", ok, err)
	}
	if ok, _ := importsAll(so, "SSL_read", "SSL_read_ex"); ok {
		t.Fatal("reported an import the object doesn't have")
	}
}

type fakeProc struct{ closed *int }

func (f fakeProc) Close() error { *f.closed++; return nil }

func TestTLSSyncAttachesAndDetaches(t *testing.T) {
	closed := 0
	tc := &tlsCapture{procs: map[uint32]tlsProcess{}, unsupported: map[uint32]bool{}}
	tc.attach = func(pid uint32) (tlsProcess, error) {
		if pid == 3 {
			return nil, errors.New("no libssl")
		}
		return fakeProc{&closed}, nil
	}
	tc.sync(map[uint32]bool{1: true, 2: true, 3: true})
	if a, u := tc.counts(); a != 2 || u != 1 {
		t.Fatalf("attached %d unsupported %d", a, u)
	}
	// pgbouncer 2 restarted as 4; 3 exited.
	tc.sync(map[uint32]bool{1: true, 4: true})
	if a, u := tc.counts(); a != 2 || u != 0 || closed != 1 {
		t.Fatalf("attached %d unsupported %d closed %d", a, u, closed)
	}
	// An unsupported pid is not retried on every rescan.
	calls := 0
	tc.attach = func(uint32) (tlsProcess, error) { calls++; return nil, errors.New("x") }
	tc.sync(map[uint32]bool{1: true, 4: true, 5: true})
	tc.sync(map[uint32]bool{1: true, 4: true, 5: true})
	if calls != 1 {
		t.Fatalf("attach called %d times for one unsupported pid", calls)
	}
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `go test ./internal/capture -run 'Libssl|Imports|TLSSync' -count=1`
Expected: FAIL to compile (`libsslPath`, `importsAll`, `tlsCapture` undefined).

- [ ] **Step 3: Write the BPF program** (create `bpf/tls.bpf.c`)

```c
// SPDX-License-Identifier: (MIT OR GPL-2.0-only)
// TLS plaintext capture (-tls-capture): uprobes on the SSL_read/SSL_write of
// pgbouncer's libssl, attached per process. Loaded with the socket capture's
// maps, so events share its ring buffer and target pid set.
#include <asm/ptrace.h>
#include "pgtrace.h"

#define INFO_MAX 32

struct sess_key {
	__u32 tgid;
	__u32 pad;
	__u64 ssl;
};

// TLS session → socket fd; from SSL_set_rfd, or from the fallback.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, struct sess_key);
	__type(value, __s32);
} tls_sessions SEC(".maps");

struct cur {
	__u64 ssl;
	__u64 buf;
};

// Thread → the SSL_read/SSL_write call it is in.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);
	__type(value, struct cur);
} tls_current SEC(".maps");

// Thread → session last passed to SSL_get_version (for the cipher name that
// pgbouncer asks for right after).
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u64);
	__type(value, __u64);
} tls_info_ssl SEC(".maps");

// [0] = 1 while the fallback programs are attached.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} tls_fallback SEC(".maps");

static __always_inline __s32 session_fd(__u32 tgid, __u64 ssl)
{
	struct sess_key k = { .tgid = tgid, .ssl = ssl };
	__s32 *fd = bpf_map_lookup_elem(&tls_sessions, &k);
	return fd ? *fd : -1;
}

static __always_inline int fallback_on(void)
{
	__u32 zero = 0;
	__u32 *on = bpf_map_lookup_elem(&tls_fallback, &zero);
	return on && *on;
}

static __always_inline void put_session(struct event *e, __u64 ssl)
{
	__builtin_memset(e->addr, 0, sizeof(e->addr));
	__builtin_memcpy(e->addr, &ssl, sizeof(ssl));
}

static __always_inline void emit_tls(__u64 id, __u64 ssl, const void *buf, int len, __u8 dir)
{
	if (len <= 0)
		return;
	__s32 fd = session_fd(id >> 32, ssl);
	if (fd >= 0 && ignored(id, fd))
		return;
	struct event *e = new_event(id, fd, K_DATA);
	if (!e)
		return;
	__u32 n = (__u32)len;
	if (n > capture_bytes)
		n = capture_bytes;
	if (n > MAX_PAYLOAD)
		n = MAX_PAYLOAD;
	e->dir = dir;
	e->total_len = len;
	e->flags = F_TLS;
	put_session(e, ssl);
	if (bpf_probe_read_user(e->payload, n, buf) != 0)
		n = 0;
	e->cap_len = n;
	__u64 size = offsetof(struct event, payload) + n;
	if (size > sizeof(*e))
		size = sizeof(*e);
	if (bpf_ringbuf_output(&events, e, size, rb_flags()) != 0)
		count_drop();
}

SEC("uprobe")
int BPF_UPROBE(ssl_write, void *ssl, const void *buf, int num)
{
	__u64 id = bpf_get_current_pid_tgid();
	if (!traced(id))
		return 0;
	if (fallback_on() && session_fd(id >> 32, (__u64)ssl) < 0) {
		struct cur c = { .ssl = (__u64)ssl };
		bpf_map_update_elem(&tls_current, &id, &c, BPF_ANY);
	}
	emit_tls(id, (__u64)ssl, buf, num, D_SEND);
	return 0;
}

// Attached only with the fallback: ends the SSL_write call for the fallback.
SEC("uretprobe")
int BPF_URETPROBE(ssl_write_ret)
{
	__u64 id = bpf_get_current_pid_tgid();
	bpf_map_delete_elem(&tls_current, &id);
	return 0;
}

SEC("uprobe")
int BPF_UPROBE(ssl_read_enter, void *ssl, void *buf, int num)
{
	__u64 id = bpf_get_current_pid_tgid();
	if (!traced(id))
		return 0;
	struct cur c = { .ssl = (__u64)ssl, .buf = (__u64)buf };
	bpf_map_update_elem(&tls_current, &id, &c, BPF_ANY);
	return 0;
}

SEC("uretprobe")
int BPF_URETPROBE(ssl_read_exit, int ret)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct cur *p = bpf_map_lookup_elem(&tls_current, &id);
	if (!p)
		return 0;
	struct cur c = *p;
	bpf_map_delete_elem(&tls_current, &id);
	emit_tls(id, c.ssl, (const void *)c.buf, ret, D_RECV);
	return 0;
}

// pgbouncer attaches a session's socket with SSL_set_rfd and SSL_set_wfd
// (same fd); one of them is enough.
SEC("uprobe")
int BPF_UPROBE(ssl_set_rfd, void *ssl, int fd)
{
	__u64 id = bpf_get_current_pid_tgid();
	if (!traced(id))
		return 0;
	struct sess_key k = { .tgid = id >> 32, .ssl = (__u64)ssl };
	__s32 v = fd;
	bpf_map_update_elem(&tls_sessions, &k, &v, BPF_ANY);
	return 0;
}

SEC("uprobe")
int BPF_UPROBE(ssl_free, void *ssl)
{
	__u64 id = bpf_get_current_pid_tgid();
	if (!traced(id))
		return 0;
	struct sess_key k = { .tgid = id >> 32, .ssl = (__u64)ssl };
	bpf_map_delete_elem(&tls_sessions, &k);
	return 0;
}

SEC("uprobe")
int BPF_UPROBE(ssl_ver_enter, void *ssl)
{
	__u64 id = bpf_get_current_pid_tgid();
	if (!traced(id))
		return 0;
	__u64 s = (__u64)ssl;
	bpf_map_update_elem(&tls_info_ssl, &id, &s, BPF_ANY);
	return 0;
}

// dir 0: version, 1: cipher.
static __always_inline void emit_info(__u64 id, const char *text, __u8 which)
{
	__u64 *ssl = bpf_map_lookup_elem(&tls_info_ssl, &id);
	if (!ssl || !text)
		return;
	__u64 s = *ssl;
	struct event *e = new_event(id, session_fd(id >> 32, s), K_TLS_INFO);
	if (!e)
		return;
	e->dir = which;
	put_session(e, s);
	long n = bpf_probe_read_user_str(e->payload, INFO_MAX, text);
	if (n <= 1)
		return;
	e->cap_len = n - 1;
	if (bpf_ringbuf_output(&events, e, offsetof(struct event, payload) + INFO_MAX, rb_flags()) != 0)
		count_drop();
}

SEC("uretprobe")
int BPF_URETPROBE(ssl_ver_exit, const char *ret)
{
	emit_info(bpf_get_current_pid_tgid(), ret, 0);
	return 0;
}

SEC("uretprobe")
int BPF_URETPROBE(ssl_cipher_exit, const char *ret)
{
	emit_info(bpf_get_current_pid_tgid(), ret, 1);
	return 0;
}

// Fallback for sessions opened before the agent: inside SSL_read/SSL_write,
// the ciphertext read/write on the session's socket reveals its fd.
static __always_inline void map_current(unsigned int fd)
{
	__u64 id = bpf_get_current_pid_tgid();
	if (!traced(id))
		return;
	struct cur *c = bpf_map_lookup_elem(&tls_current, &id);
	if (!c)
		return;
	struct sess_key k = { .tgid = id >> 32, .ssl = c->ssl };
	if (bpf_map_lookup_elem(&tls_sessions, &k))
		return;
	__s32 v = fd;
	bpf_map_update_elem(&tls_sessions, &k, &v, BPF_ANY);
	struct event *e = new_event(id, v, K_TLS_FD);
	if (!e)
		return;
	put_session(e, c->ssl);
	if (bpf_ringbuf_output(&events, e, offsetof(struct event, payload), rb_flags()) != 0)
		count_drop();
}

SEC("fentry/ksys_read")
int BPF_PROG(fallback_read, unsigned int fd, char *buf, __u64 count)
{
	map_current(fd);
	return 0;
}

SEC("fentry/ksys_write")
int BPF_PROG(fallback_write, unsigned int fd, const char *buf, __u64 count)
{
	map_current(fd);
	return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
```

Append to `internal/capture/gen.go`:

```go
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target amd64 tls ../../bpf/tls.bpf.c -- -O2 -g -Wall -I/usr/include/x86_64-linux-gnu
```

Run: `go generate ./internal/capture`
Expected: `tls_x86_bpfel.go` and `tls_x86_bpfel.o` are created, with no warnings.

- [ ] **Step 4: Write `internal/capture/tls.go`**

```go
package capture

import (
	"bufio"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// fallbackIdle is how long the socket-finding fallback stays attached after
// the last TLS event without a socket.
const fallbackIdle = 30 * time.Second

// tlsProcess is the probes attached to one pgbouncer process.
type tlsProcess interface{ Close() error }

type tlsProc struct {
	ex    *link.Executable
	links []link.Link
	ret   link.Link // SSL_write return probe, only while the fallback is on
}

func (p *tlsProc) Close() error {
	for _, l := range p.links {
		l.Close()
	}
	if p.ret != nil {
		p.ret.Close()
	}
	return nil
}

// tlsCapture attaches the TLS plaintext probes to every traced process and
// runs the fallback for sessions opened before the agent.
type tlsCapture struct {
	objs     tlsObjects
	procRoot string
	attach   func(pid uint32) (tlsProcess, error)

	mu          sync.Mutex
	procs       map[uint32]tlsProcess
	unsupported map[uint32]bool
	fallback    []link.Link // fentry ksys_read/ksys_write
	fbOn        bool
	lastNeed    time.Time
}

func newTLSCapture(c *Capture, procRoot string, captureBytes int) (*tlsCapture, error) {
	spec, err := loadTls()
	if err != nil {
		return nil, fmt.Errorf("load tls spec: %w", err)
	}
	if err := spec.Variables["capture_bytes"].Set(uint32(captureBytes)); err != nil {
		return nil, fmt.Errorf("set capture_bytes: %w", err)
	}
	t := &tlsCapture{procRoot: procRoot, procs: map[uint32]tlsProcess{}, unsupported: map[uint32]bool{}}
	opts := &ebpf.CollectionOptions{MapReplacements: map[string]*ebpf.Map{
		"target_pids": c.objs.TargetPids, "fd_class": c.objs.FdClass, "events": c.objs.Events,
		"scratch": c.objs.Scratch, "drops": c.objs.Drops,
	}}
	if err := spec.LoadAndAssign(&t.objs, opts); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return nil, fmt.Errorf("load tls bpf: %+v", ve)
		}
		return nil, fmt.Errorf("load tls bpf: %w", err)
	}
	t.attach = t.attachProcess
	return t, nil
}

func (t *tlsCapture) programs() []*ebpf.Program {
	o := &t.objs
	return []*ebpf.Program{o.SslWrite, o.SslWriteRet, o.SslReadEnter, o.SslReadExit, o.SslSetRfd, o.SslFree,
		o.SslVerEnter, o.SslVerExit, o.SslCipherExit, o.FallbackRead, o.FallbackWrite}
}

// attachProcess attaches the probes to one pgbouncer process's libssl.
func (t *tlsCapture) attachProcess(pid uint32) (tlsProcess, error) {
	dir := filepath.Join(t.procRoot, strconv.FormatUint(uint64(pid), 10))
	ok, err := importsAll(filepath.Join(dir, "exe"), "SSL_read", "SSL_write")
	if err != nil {
		return nil, fmt.Errorf("read executable: %w", err)
	}
	if !ok {
		return nil, errors.New("unsupported TLS API (pgbouncer doesn't import SSL_read/SSL_write)")
	}
	f, err := os.Open(filepath.Join(dir, "maps"))
	if err != nil {
		return nil, err
	}
	lib, found := libsslPath(f)
	f.Close()
	if !found {
		return nil, errors.New("no libssl mapped")
	}
	ex, err := link.OpenExecutable(filepath.Join(dir, "root", lib))
	if err != nil {
		return nil, err
	}
	p := &tlsProc{ex: ex}
	opt := &link.UprobeOptions{PID: int(pid)}
	o := &t.objs
	for _, a := range []struct {
		sym  string
		prog *ebpf.Program
		ret  bool
	}{
		{"SSL_set_rfd", o.SslSetRfd, false}, {"SSL_free", o.SslFree, false},
		{"SSL_read", o.SslReadEnter, false}, {"SSL_read", o.SslReadExit, true},
		{"SSL_get_version", o.SslVerEnter, false}, {"SSL_get_version", o.SslVerExit, true},
		{"SSL_CIPHER_get_name", o.SslCipherExit, true},
		{"SSL_write", o.SslWrite, false},
	} {
		var l link.Link
		if a.ret {
			l, err = ex.Uretprobe(a.sym, a.prog, opt)
		} else {
			l, err = ex.Uprobe(a.sym, a.prog, opt)
		}
		if err != nil {
			p.Close()
			return nil, fmt.Errorf("attach %s: %w", a.sym, err)
		}
		p.links = append(p.links, l)
	}
	return p, nil
}

// sync attaches to new pids and detaches from gone ones. Unsupported pids
// are remembered and not retried.
func (t *tlsCapture) sync(pids map[uint32]bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for pid := range pids {
		if t.procs[pid] != nil || t.unsupported[pid] {
			continue
		}
		p, err := t.attach(pid)
		if err != nil {
			slog.Warn("tls capture unavailable for process", "pid", pid, "err", err)
			t.unsupported[pid] = true
			continue
		}
		t.procs[pid] = p
		if t.fbOn {
			t.attachRet(pid, p)
		}
		slog.Info("tls probes attached", "pid", pid)
	}
	for pid, p := range t.procs {
		if !pids[pid] {
			p.Close()
			delete(t.procs, pid)
		}
	}
	for pid := range t.unsupported {
		if !pids[pid] {
			delete(t.unsupported, pid)
		}
	}
}

func (t *tlsCapture) counts() (attached, unsupported int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.procs), len(t.unsupported)
}

func (t *tlsCapture) attachRet(pid uint32, p tlsProcess) {
	tp, ok := p.(*tlsProc)
	if !ok || tp.ret != nil {
		return
	}
	l, err := tp.ex.Uretprobe("SSL_write", t.objs.SslWriteRet, &link.UprobeOptions{PID: int(pid)})
	if err != nil {
		slog.Warn("tls fallback: attach SSL_write return", "pid", pid, "err", err)
		return
	}
	tp.ret = l
}

// need attaches the fallback, or keeps it attached.
func (t *tlsCapture) need(now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.lastNeed = now
	if t.fbOn {
		return
	}
	// A call interrupted by an earlier detach may have left a stale entry.
	var k uint64
	var keys []uint64
	it := t.objs.TlsCurrent.Iterate()
	var v tlsCur
	for it.Next(&k, &v) {
		keys = append(keys, k)
	}
	for _, k := range keys {
		_ = t.objs.TlsCurrent.Delete(k)
	}
	for _, prog := range []*ebpf.Program{t.objs.FallbackRead, t.objs.FallbackWrite} {
		l, err := link.AttachTracing(link.TracingOptions{Program: prog})
		if err != nil {
			slog.Warn("tls fallback unavailable: sessions opened before the agent stay untraced", "err", err)
			t.detachLocked()
			t.lastNeed = now.Add(24 * time.Hour) // don't retry on every event
			return
		}
		t.fallback = append(t.fallback, l)
	}
	for pid, p := range t.procs {
		t.attachRet(pid, p)
	}
	_ = t.objs.TlsFallback.Put(uint32(0), uint32(1))
	t.fbOn = true
	slog.Info("tls fallback attached")
}

// expire detaches the fallback after fallbackIdle without a need.
func (t *tlsCapture) expire(now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.fbOn && now.Sub(t.lastNeed) > fallbackIdle {
		t.detachLocked()
		slog.Info("tls fallback detached")
	}
}

func (t *tlsCapture) detachLocked() {
	_ = t.objs.TlsFallback.Put(uint32(0), uint32(0))
	for _, l := range t.fallback {
		l.Close()
	}
	t.fallback = nil
	for _, p := range t.procs {
		if tp, ok := p.(*tlsProc); ok && tp.ret != nil {
			tp.ret.Close()
			tp.ret = nil
		}
	}
	t.fbOn = false
}

func (t *tlsCapture) fallbackAttached() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.fbOn
}

func (t *tlsCapture) close() {
	t.mu.Lock()
	t.detachLocked()
	for pid, p := range t.procs {
		p.Close()
		delete(t.procs, pid)
	}
	t.mu.Unlock()
	t.objs.Close()
}

// libsslPath returns the path of the first libssl.so* in a /proc/<pid>/maps
// listing, as seen inside the process's mount namespace.
func libsslPath(maps io.Reader) (string, bool) {
	s := bufio.NewScanner(maps)
	for s.Scan() {
		f := strings.Fields(s.Text())
		if len(f) >= 6 && strings.HasPrefix(filepath.Base(f[5]), "libssl.so") {
			return f[5], true
		}
	}
	return "", false
}

// importsAll reports whether the ELF file imports every named dynamic symbol.
func importsAll(path string, names ...string) (bool, error) {
	f, err := elf.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	syms, err := f.ImportedSymbols()
	if err != nil {
		return false, err
	}
	have := map[string]bool{}
	for _, s := range syms {
		have[s.Name] = true
	}
	for _, n := range names {
		if !have[n] {
			return false, nil
		}
	}
	return true, nil
}
```

`tlsCur` is the Go type bpf2go generates for `struct cur`. If the generator names it differently, use the generated name; `grep 'type tls' internal/capture/tls_x86_bpfel.go` shows it.

- [ ] **Step 5: Hook it into `Capture`** (`internal/capture/capture.go`)

- Add to `Config`: `TLS bool // capture plaintext of pgbouncer's TLS connections (uprobes on its libssl)`.
- Add a field `tls *tlsCapture` to `Capture`.
- In `Start`, after the loop that attaches the socket programs:

```go
	if cfg.TLS {
		t, err := newTLSCapture(c, cfg.ProcRoot, cfg.CaptureBytes)
		if err != nil {
			c.Close()
			return nil, err
		}
		c.tls = t
		c.progs = append(c.progs, t.programs()...)
		// Sessions that already exist need the fallback to find their sockets.
		t.need(time.Now())
	}
```

- At the end of `rescan`, after `c.pids = found`, add:

```go
	if c.tls != nil {
		c.tls.sync(found)
		c.tls.expire(time.Now())
	}
```

`rescan` holds `c.mu`, and the tls methods take their own lock, so there's no deadlock.

- In `Close`, before `c.wg.Wait()`, add:

```go
	if c.tls != nil {
		c.tls.close()
	}
```

- Add the public methods:

```go
// TLSNeedFallback is called when TLS plaintext arrives for a session whose
// socket isn't known: it attaches the socket-finding fallback, or keeps it.
func (c *Capture) TLSNeedFallback() {
	if c.tls != nil {
		c.tls.need(time.Now())
	}
}

// TLSProcesses returns how many traced processes have TLS probes attached,
// and how many can't be TLS-captured.
func (c *Capture) TLSProcesses() (attached, unsupported int) {
	if c.tls == nil {
		return 0, 0
	}
	return c.tls.counts()
}

// TLSFallbackAttached reports whether the fallback is attached.
func (c *Capture) TLSFallbackAttached() bool { return c.tls != nil && c.tls.fallbackAttached() }
```

- [ ] **Step 6: Run the capture tests**

Run: `go vet ./internal/capture && go test -race -count=1 ./internal/capture`
Expected: `ok`. `TestImportsAll` passes, or skips only where there is no C compiler; CI's Ubuntu runner has `cc`.

- [ ] **Step 7: Wire the flag** (`cmd/pgtrace-agent/main.go`, `deploy/docker-compose.yml`)

In `config`, add `tlsCapture bool`. With the other flags:

```go
	flag.BoolVar(&c.tlsCapture, "tls-capture", false, "capture plaintext of pgbouncer's TLS connections with uprobes on its libssl (costs pgbouncer CPU per TLS query)")
```

Change the metrics config to `metrics.Config{Labels: labels, Limit: c.labelLimit, TTL: c.labelTTL, TLS: c.tlsCapture}`, and the capture config to include `TLS: c.tlsCapture`.

After `met.RegisterRecursionMisses(capt.RecursionMisses)`:

```go
	if c.tlsCapture {
		met.RegisterTLS(capt.TLSProcesses, capt.TLSFallbackAttached)
	}
```

After `ag.Metrics = met`:

```go
	if c.tlsCapture {
		ag.Fallback = capt
	}
```

Add `"tls_capture", c.tlsCapture` to the `attached` log line.

In `deploy/docker-compose.yml`, agent `environment`, after `PGTRACE_DEBUG_DUMP_DIR`:

```yaml
      PGTRACE_TLS_CAPTURE: "${PGTRACE_TLS_CAPTURE:-false}"
```

- [ ] **Step 8: Build and run all unit tests**

Run: `go vet ./... && go test -race -count=1 ./... && go build ./cmd/pgtrace-agent`
Expected: all `ok`, and the binary builds.

- [ ] **Step 9: Check that capture off changes nothing (plain e2e)**

Run: `SERIES_CEILING=8975 ./scripts/e2e.sh` (this needs Task 8's `--ceiling` flag; if Task 8 isn't done yet, run `./scripts/e2e.sh` and expect the one ceiling check to fail with ≤ 8975 series and every other check to pass).
Expected: `E2E PASSED`, apart from the ceiling caveat above.

- [ ] **Step 10: Commit**

```bash
git add bpf/tls.bpf.c internal/capture cmd/pgtrace-agent deploy/docker-compose.yml
git commit -m "TLS capture: libssl uprobes per process, socket fallback, -tls-capture

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 7: TLS deployment for tests (PKI, pgbouncer and postgres configs)

**Files:**
- Create: `deploy/tls/gencerts.sh`, `deploy/tls/pgbouncer.strict.ini`, `deploy/tls/pgbouncer.mixed.ini`, `deploy/tls/pg_hba.conf`, `deploy/tls/compose.tls.yml`, `deploy/tls/.gitignore`

**Interfaces:**
- Produces:
  - `COMPOSE_FILE=docker-compose.yml:tls/compose.tls.yml`, run from `deploy/`, gives TLS on both hops.
  - `PGBOUNCER_TLS_INI` selects the ini, relative to `deploy/tls/` (default `pgbouncer.strict.ini`).
  - `loadgen` has `PGSSLMODE=verify-full` plus client-certificate env vars, which can be overridden per command.

- [ ] **Step 1: Generate the PKI**

Create `deploy/tls/gencerts.sh` from the spike's `deploy/tls-spike/gencerts.sh` (branch `spike/tls-uprobes`), with the header comment changed to:

```bash
# Test PKI for scripts/e2e_tls.sh, perf_tls.sh and the TLS soak: root CA ->
# intermediate -> server certs (pgbouncer, postgres) and client certs (user
# "postgres": pgbench -> pgbouncer and pgbouncer -> postgres). Written to
# ./certs (git-ignored). Test use only.
```

Get it with `git show spike/tls-uprobes:deploy/tls-spike/gencerts.sh > deploy/tls/gencerts.sh`, then edit the comment and `chmod +x`.

`deploy/tls/.gitignore`:

```
certs/
generated/
```

- [ ] **Step 2: Write the configs**

`deploy/tls/pg_hba.conf`:

```
# TLS test stack: TLS connections need a verified client certificate plus
# the password; plain connections (mixed mode) need the password.
local     all all                          trust
hostssl   all all all scram-sha-256 clientcert=verify-full
hostnossl all all all scram-sha-256
```

`deploy/tls/pgbouncer.strict.ini` (same pools as `deploy/pgbouncer/pgbouncer.ini`):

```ini
; Strict TLS: both hops TLS, certificates verified both ways.
[databases]
; Deliberately undersized pool to demonstrate pool waits.
tiny = host=postgres port=5432 dbname=postgres pool_size=2
* = host=postgres port=5432

[pgbouncer]
listen_addr = 0.0.0.0
listen_port = 6432
auth_type = scram-sha-256
auth_file = /etc/pgbouncer/userlist.txt
pool_mode = transaction
max_client_conn = 2000
default_pool_size = 20
max_prepared_statements = 200
ignore_startup_parameters = extra_float_digits
admin_users = postgres

client_tls_sslmode = verify-full
client_tls_key_file = /certs/pgbouncer.key
client_tls_cert_file = /certs/pgbouncer.crt
client_tls_ca_file = /certs/root.crt

server_tls_sslmode = verify-full
server_tls_ca_file = /certs/root.crt
server_tls_key_file = /certs/pgb-client.key
server_tls_cert_file = /certs/pgb-client.crt
```

`deploy/tls/pgbouncer.mixed.ini`: identical except the header comment and the TLS block:

```ini
; Mixed: clients choose TLS or plain; plain server hop.
…
client_tls_sslmode = prefer
client_tls_key_file = /certs/pgbouncer.key
client_tls_cert_file = /certs/pgbouncer.crt
client_tls_ca_file = /certs/root.crt

server_tls_sslmode = disable
```

`deploy/tls/compose.tls.yml`:

```yaml
# TLS on both hops for tests:
#   cd deploy && COMPOSE_FILE=docker-compose.yml:tls/compose.tls.yml docker compose ...
# PGBOUNCER_TLS_INI picks the pgbouncer config in deploy/tls (default: strict).
services:
  postgres:
    volumes:
      - ./tls/certs:/certs-src:ro
      - ./tls/pg_hba.conf:/etc/postgresql/pg_hba.conf:ro
    # postgres requires its key to be owned by it with mode 0600.
    entrypoint: ["sh", "-c", "mkdir -p /tls && cp /certs-src/postgres.key /certs-src/postgres.crt /certs-src/root.crt /tls/ && chown postgres /tls/* && chmod 600 /tls/postgres.key && exec docker-entrypoint.sh \"$$@\"", "--"]
    command: ["postgres", "-c", "max_connections=200", "-c", "ssl=on",
              "-c", "ssl_cert_file=/tls/postgres.crt", "-c", "ssl_key_file=/tls/postgres.key",
              "-c", "ssl_ca_file=/tls/root.crt", "-c", "hba_file=/etc/postgresql/pg_hba.conf"]
  pgbouncer:
    volumes:
      - ./tls/${PGBOUNCER_TLS_INI:-pgbouncer.strict.ini}:/etc/pgbouncer/pgbouncer.ini:ro
      - ./pgbouncer/userlist.txt:/etc/pgbouncer/userlist.txt:ro
      - ./tls/certs:/certs:ro
  loadgen:
    environment:
      PGSSLMODE: verify-full
      PGSSLROOTCERT: /certs/root.crt
      PGSSLCERT: /certs/client.crt
      PGSSLKEY: /certs/client.key
    volumes:
      - ./tls/certs:/certs:ro
```

- [ ] **Step 3: Verify the stack**

Run:

```bash
cd deploy && ./tls/gencerts.sh && export COMPOSE_FILE=docker-compose.yml:tls/compose.tls.yml BUILDX_BUILDER=default
docker compose down --remove-orphans; docker compose up -d --wait postgres pgbouncer
docker compose run --rm -T loadgen psql -Atc "select ssl, version from pg_stat_ssl where pid = pg_backend_pid()"
docker compose run --rm -T -e PGSSLCERT=/nonexistent -e PGSSLKEY=/nonexistent loadgen psql -Atc "select 1"
PGBOUNCER_TLS_INI=pgbouncer.mixed.ini docker compose up -d --wait pgbouncer
docker compose run --rm -T -e PGSSLMODE=disable loadgen psql -Atc "select ssl from pg_stat_ssl where pid = pg_backend_pid()"
docker compose down --remove-orphans
```

Expected:
- `openssl verify` lines ending in `OK`;
- `t|TLSv1.3`;
- `certificate required` for the client without a certificate;
- `f` for the plain client through the mixed config (server hop plain).

- [ ] **Step 4: Commit**

```bash
git add deploy/tls
git commit -m "TLS test deployment: PKI, strict and mixed pgbouncer configs, compose override

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 8: End-to-end TLS tests

**Files:**
- Create: `scripts/e2e_tls.sh`, `scripts/e2e_tls_check.py`
- Modify: `scripts/e2e.sh`, `scripts/e2e_check.py` (series ceiling as an argument)
- Modify: `Makefile` (target `e2e-tls`)

**Interfaces:**
- Consumes: Tasks 6 and 7 (flag, compose override, configs).
- Produces: `./scripts/e2e_tls.sh` prints `E2E TLS PASSED` on success. `e2e_check.py --ceiling N`.

- [ ] **Step 1: Make the e2e ceiling an argument**

In `scripts/e2e_check.py`, add `ap.add_argument("--ceiling", type=int, default=8975)` and replace the ceiling check with:

```python
check(f"pgtrace series under the documented ceiling ({args.ceiling:,})", nseries <= args.ceiling, f"{nseries} series")
```

In `scripts/e2e.sh`, change the last line to:

```bash
python3 ../scripts/e2e_check.py --ratio "$RATIO" --min-traces $((CLIENTS * TX * 7 * 3)) --stats "$stats" --ceiling "${SERIES_CEILING:-8975}"
```

- [ ] **Step 2: Write `scripts/e2e_tls_check.py`**

```python
#!/usr/bin/env python3
"""TLS assertions for scripts/e2e_tls.sh. Usage: e2e_tls_check.py <strict|mixed|preexisting|nolog> --stats "<agent stats line>"."""
import argparse
import json
import re
import sys
import urllib.parse
import urllib.request

VT, PROM, AGENT = "http://localhost:10428", "http://localhost:9090", "http://localhost:9464/metrics"
failures = 0


def check(desc, ok, detail=""):
    global failures
    print(("PASS  " if ok else "FAIL  ") + desc + (f"  ({detail})" if detail else ""))
    if not ok:
        failures += 1


def get(url, data=None):
    body = urllib.parse.urlencode(data).encode() if data else None
    with urllib.request.urlopen(url, body, timeout=30) as r:
        return r.read().decode()


def logsql(query):
    return [json.loads(l) for l in get(f"{VT}/select/logsql/query", {"query": query}).splitlines() if l.strip()]


def count(query):
    rows = logsql(query + " | stats count() n")
    return int(rows[0]["n"]) if rows else 0


def prom(expr):
    res = json.loads(get(f"{PROM}/api/v1/query?" + urllib.parse.urlencode({"query": expr})))["data"]["result"]
    return float(res[0]["value"][1]) if res else 0.0


metrics = get(AGENT)
val = lambda pat: sum(float(m) for m in re.findall(pat + r"\S* ([0-9.e+]+)$", metrics, re.M))

ap = argparse.ArgumentParser()
ap.add_argument("mode", choices=["strict", "mixed", "preexisting", "nolog"])
ap.add_argument("--stats", required=True)
ap.add_argument("--app", default="pgbench")
args = ap.parse_args()
stats = {k: int(v) for k, v in re.findall(r"(\w+)=(\d+)", args.stats)}
ROOT, CHILD = "kind:2", "kind:3"
TLS = '"span_attr:tls.protocol.name":tls'

check("no kernel drops", stats["kernel_drops"] == 0, f'{stats["kernel_drops"]}')
check("TLS probes attached to the pgbouncer process", val(r'^pgtrace_tls_processes\{state="attached"\}') == 1
      and val(r'^pgtrace_tls_processes\{state="unsupported"\}') == 0)
dropped = val(r'^pgtrace_tls_unresolved_total\{result="dropped"\}')
resolved = val(r'^pgtrace_tls_unresolved_total\{result="resolved"\}')
maxconn = lambda side, tls: prom(f'max_over_time(pgtrace_connections{{side="{side}",tls="{tls}"}}[10m])')


def app_roots(app, extra=""):
    return count(f'{ROOT} "span_attr:application_name":{app} {extra}')


if args.mode in ("strict", "nolog"):
    roots = app_roots(args.app)
    tls_roots = app_roots(args.app, TLS)
    check("sampled pgbench roots exist", roots > 0, f"{roots}")
    check("every pgbench root carries tls.protocol.name=tls", roots and tls_roots == roots, f"{tls_roots}/{roots}")
    kids = count(f'{CHILD} "span_attr:pgbouncer.internal":false')
    tls_kids = count(f'{CHILD} "span_attr:pgbouncer.internal":false {TLS}')
    check("every server child carries tls.protocol.name=tls", kids and tls_kids == kids, f"{tls_kids}/{kids}")
    versioned = app_roots(args.app, '"span_attr:tls.protocol.version":"1.3" "span_attr:tls.cipher":*')
    if args.mode == "strict":
        check("≥ 99% of pgbench roots carry version 1.3 and a cipher", versioned >= 0.99 * roots, f"{versioned}/{roots}")
    else:
        print(f"INFO  with connection logging off, {versioned}/{roots} roots carry version and cipher (best-effort)")
    check("client and server connections counted as TLS", maxconn("client", "true") > 0 and maxconn("server", "true") > 0)
    check("no plain client connections counted", maxconn("client", "false") == 0)
    check("no socket-less TLS events dropped", dropped == 0, f"{dropped:.0f}")
elif args.mode == "mixed":
    for app, want_tls in (("tls-client", True), ("plain-client", False)):
        roots = app_roots(app)
        tls_roots = app_roots(app, TLS)
        check(f"{app}: every trace kept (ratio 1.0)", roots >= 0.99 * 8400, f"{roots}")
        check(f"{app}: tls attributes {'on every' if want_tls else 'on no'} root",
              tls_roots == (roots if want_tls else 0), f"{tls_roots}/{roots}")
    kids = count(f"{CHILD} {TLS}")
    check("plain server hop: no child carries tls attributes", kids == 0, f"{kids}")
    check("TLS and plain client connections both counted",
          maxconn("client", "true") > 0 and maxconn("client", "false") > 0)
    check("no TLS server connections counted", maxconn("server", "true") == 0)
    check("no socket-less TLS events dropped", dropped == 0, f"{dropped:.0f}")
elif args.mode == "preexisting":
    roots = app_roots("pre")
    tls_roots = app_roots("pre", TLS)
    linked = app_roots("pre", '"span_attr:pgtrace.correlation":exact')
    check("queries of sessions opened before the agent are traced", roots > 1000, f"{roots}")
    check("…and marked TLS", tls_roots == roots, f"{tls_roots}/{roots}")
    check("…and ≥ 99% linked exactly", linked >= 0.99 * roots, f"{linked}/{roots}")
    check("fallback attached during the run", prom("max_over_time(pgtrace_tls_fallback_attached[10m])") == 1)
    check("fallback detached after the load ended", val(r"^pgtrace_tls_fallback_attached") == 0)
    check("socket-less SSL_write events resolved", resolved > 0, f"{resolved:.0f}")
    print(f"INFO  socket-less events dropped: {dropped:.0f} (first calls of old sessions before the fallback attached)")

print("E2E TLS CHECK " + ("PASSED" if failures == 0 else f"FAILED ({failures})"))
sys.exit(1 if failures else 0)
```

- [ ] **Step 3: Write `scripts/e2e_tls.sh`**

```bash
#!/usr/bin/env bash
# End-to-end tests for -tls-capture (TLS test PKI, deploy/tls):
#   1. strict: the full e2e suite with TLS on both hops, plus TLS checks
#   2. mixed: TLS and plain clients in one run, plain server hop
#   3. sessions opened before the agent started (socket-finding fallback)
#   4. pgbouncer connection logging off (version/cipher are best-effort)
#   5. pgbouncer restart: probes follow the new process
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root/deploy"
export BUILDX_BUILDER=${BUILDX_BUILDER:-default}
export COMPOSE_FILE=docker-compose.yml:tls/compose.tls.yml PGTRACE_TLS_CAPTURE=true PGTRACE_STATS_INTERVAL=2s
./tls/gencerts.sh >/dev/null
lg() { docker compose run --rm -T loadgen "$@"; }
stats() { docker compose logs agent | grep "INFO stats" | tail -1; }
check() { python3 "$root/scripts/e2e_tls_check.py" "$@" --stats "$(stats)"; }
fresh() { # fresh <pgbouncer ini>: stack without the agent, pgbench initialised
	docker compose down --remove-orphans >/dev/null 2>&1 || true
	PGBOUNCER_TLS_INI=$1 docker compose up -d --build --wait postgres pgbouncer victoriatraces prometheus >/dev/null
	lg pgbench -i -s 1 -q >/dev/null 2>&1
}
agent_up() {
	docker compose up -d --build agent >/dev/null
	for _ in $(seq 1 30); do docker compose logs agent 2>/dev/null | grep -q "tls probes attached" && return; sleep 1; done
	echo "TLS probes never attached"; docker compose logs agent; exit 1
}

echo "== 1. strict TLS: the full e2e suite"
PGBOUNCER_TLS_INI=pgbouncer.strict.ini SERIES_CEILING=8991 "$root/scripts/e2e.sh"
check strict

echo "== 2. mixed TLS and plain clients, plain server hop"
export PGTRACE_SAMPLE_RATIO=1.0
fresh pgbouncer.mixed.ini
agent_up
lg env PGSSLMODE=disable PGAPPNAME=plain-client pgbench -c 4 -t 300 -n | grep -E "^tps"
lg env PGAPPNAME=tls-client pgbench -c 4 -t 300 -n | grep -E "^tps"
sleep 10
check mixed

echo "== 3. sessions opened before the agent"
fresh pgbouncer.strict.ini
lg env PGAPPNAME=pre pgbench -c 4 -T 90 -n | grep -E "^tps" &
load=$!
sleep 10
agent_up
wait $load
echo "   waiting for the fallback to detach"
sleep 45
check preexisting

echo "== 4. pgbouncer connection logging off"
mkdir -p tls/generated
sed 's/^\[pgbouncer\]$/[pgbouncer]\nlog_connections = 0\nlog_disconnections = 0/' tls/pgbouncer.strict.ini > tls/generated/pgbouncer.nolog.ini
unset PGTRACE_SAMPLE_RATIO
fresh generated/pgbouncer.nolog.ini
agent_up
lg pgbench -c 4 -t 300 -n | grep -E "^tps"
sleep 10
check nolog

echo "== 5. pgbouncer restart: probes follow the new process"
docker compose restart pgbouncer >/dev/null
sleep 12 # two rescans
lg env PGAPPNAME=after-restart pgbench -c 2 -t 200 -n | grep -E "^tps"
sleep 10
check nolog --app after-restart

echo "E2E TLS PASSED"
```

`chmod +x scripts/e2e_tls.sh scripts/e2e_tls_check.py`. Add to the `Makefile`, next to the `e2e` target:

```make
e2e-tls:
	./scripts/e2e_tls.sh
```

(add `e2e-tls` to `.PHONY` if the Makefile has one)

- [ ] **Step 4: Run it**

Run: `./scripts/e2e_tls.sh 2>&1 | tee /tmp/e2e_tls.log | grep -E "PASS|FAIL|INFO|=="`
Expected:
- every `PASS`, `E2E PASSED` for step 1, and `E2E TLS PASSED` at the end;
- the `INFO` lines report the dropped count and the version coverage with logging off. Record both.

If a check fails, use superpowers:systematic-debugging. The flight recorder (`PGTRACE_DEBUG_DUMP_DIR=/dumps`) and `docker compose logs agent` are the first tools.

- [ ] **Step 5: Run the plain e2e and the contention suite (regression)**

Run: `./scripts/e2e.sh && ./scripts/contention.sh`
Expected: `E2E PASSED`, `CONTENTION PASSED`.

- [ ] **Step 6: Commit**

```bash
git add scripts/e2e_tls.sh scripts/e2e_tls_check.py scripts/e2e.sh scripts/e2e_check.py Makefile
git commit -m "End-to-end TLS tests: strict, mixed, pre-existing sessions, logging off, restart

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 9: TLS performance benchmark and soak

**Files:**
- Create: `scripts/perf_tls.sh`
- Create (outputs): `docs/perf-results/tls/results.csv`, `docs/perf-results/tls/host.txt`, `docs/soak-results/tls-<date>/…`

**Interfaces:**
- Consumes: Tasks 6–8.
- Produces: the numbers for Task 10's docs.

- [ ] **Step 1: Write `scripts/perf_tls.sh`**

```bash
#!/usr/bin/env bash
# Cost of TLS capture: no TLS / no TLS + agent / TLS / TLS + agent (capture
# off) / TLS + agent (capture on), pgbench -S simple, alternated repetitions.
#   DURATION=20 REPEATS=3 CLIENTS="8 64" ./scripts/perf_tls.sh
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root/deploy"
DURATION=${DURATION:-20}
REPEATS=${REPEATS:-3}
CLIENTS=${CLIENTS:-"8 64"}
OUT=${OUT:-$root/docs/perf-results/tls}
export BUILDX_BUILDER=${BUILDX_BUILDER:-default} PGTRACE_STATS_INTERVAL=5s
mkdir -p "$OUT"
csv="$OUT/results.csv"
echo "rep,config,clients,tps,lat_ms,pgbouncer_cpu_pct,pgbouncer_us_per_q,agent_cpu_pct,client_q_per_s,kernel_drops,tls_dropped" > "$csv"
cg() { echo "/sys/fs/cgroup/system.slice/docker-$(docker inspect -f '{{.Id}}' "$1").scope"; }
cpu_usec() { awk '/^usage_usec/ {print $2}' "$(cg "$1")/cpu.stat" 2>/dev/null || echo 0; }
./tls/gencerts.sh >/dev/null

stack() { # stack plain|tls
	docker compose down --remove-orphans >/dev/null 2>&1 || true
	if [ "$1" = tls ]; then export COMPOSE_FILE=docker-compose.yml:tls/compose.tls.yml; else unset COMPOSE_FILE; fi
	docker compose up -d --build --wait postgres pgbouncer victoriatraces >/dev/null 2>&1
	docker compose build agent >/dev/null 2>&1
	docker compose run --rm -T loadgen pgbench -i -s 10 -q >/dev/null 2>&1
}
agent() { # agent off|plain|tls-off|tls-on
	docker compose stop agent >/dev/null 2>&1 || true
	[ "$1" = off ] && return
	PGTRACE_TLS_CAPTURE=$([ "$1" = tls-on ] && echo true || echo false) docker compose up -d agent >/dev/null 2>&1
	for _ in $(seq 1 30); do docker compose logs agent --since 60s 2>/dev/null | grep -q "INFO attached" && sleep 2 && return; sleep 1; done
	echo "agent did not start" >&2; exit 1
}
run() { # run <rep> <config> <clients> <agent mode>
	local rep=$1 cfg=$2 c=$3 mode=$4 p0 p1 a0=0 a1=0 res tps lat start st
	agent "$mode"
	start=$(date -u +%Y-%m-%dT%H:%M:%SZ)
	p0=$(cpu_usec pgtrace-pgbouncer-1); [ "$mode" != off ] && a0=$(cpu_usec pgtrace-agent-1)
	res=$(docker compose run --rm -T loadgen pgbench -S -M simple -c "$c" -j $((c < 8 ? c : 8)) -T "$DURATION" -n 2>&1)
	p1=$(cpu_usec pgtrace-pgbouncer-1); [ "$mode" != off ] && a1=$(cpu_usec pgtrace-agent-1)
	tps=$(sed -nE 's/^tps = ([0-9.]+).*/\1/p' <<<"$res")
	lat=$(sed -nE 's/^latency average = ([0-9.]+) ms/\1/p' <<<"$res")
	st=""; drop=""
	if [ "$mode" != off ]; then
		sleep 6
		st=$(docker compose logs agent --since "$start" | grep "INFO stats" | tail -1)
		drop=$(curl -fsS localhost:9464/metrics | awk '/^pgtrace_tls_unresolved_total\{result="dropped"\}/ {print $2}')
	fi
	python3 - "$rep" "$cfg" "$c" "$tps" "$lat" "$p0" "$p1" "$a0" "$a1" "$DURATION" "$st" "${drop:-}" >> "$csv" <<'PY'
import re, sys
rep, cfg, c, tps, lat, p0, p1, a0, a1, d, st, drop = sys.argv[1:]
tps, d = float(tps), float(d)
pcpu = (int(p1) - int(p0)) / 1e6 / d
kv = dict(re.findall(r"(\w+)=(\S+)", st))
qps = f'{int(kv["traces"]) / d:.0f}' if "traces" in kv else ""
print(",".join([rep, cfg, c, f"{tps:.0f}", lat, f"{pcpu*100:.1f}", f"{pcpu/tps*1e6:.2f}",
                f"{(int(a1)-int(a0))/1e6/d*100:.1f}" if int(a1) else "", qps, kv.get("kernel_drops", ""), drop]))
PY
	tail -1 "$csv"
}

echo "== plain stack"; stack plain
for rep in $(seq 1 "$REPEATS"); do for c in $CLIENTS; do
	run "$rep" notls "$c" off; run "$rep" notls-agent "$c" plain
done; done
echo "== tls stack"; stack tls
for rep in $(seq 1 "$REPEATS"); do for c in $CLIENTS; do
	run "$rep" tls "$c" off; run "$rep" tls-agent-capture-off "$c" tls-off; run "$rep" tls-agent-capture-on "$c" tls-on
done; done
docker compose stop agent >/dev/null 2>&1 || true
{ echo "date: $(date -Is)"; echo "cpu: $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | xargs) ($(nproc) threads)"
  echo "kernel: $(uname -r)"; echo "pgbench -S -M simple, ${DURATION}s x $REPEATS, clients: $CLIENTS"
  echo "tls: TLSv1.3 both hops, client certificates verified (deploy/tls, strict)"; } > "$OUT/host.txt"
echo "results: $csv"
```

The stats line's `traces` counts client queries (roots) seen by the agent. With the agent on, `client_q_per_s` should match `tps`.

- [ ] **Step 2: Run the benchmark**

Run: `chmod +x scripts/perf_tls.sh && ./scripts/perf_tls.sh`
Expected: 30 rows. For every `tls-agent-capture-on` row:
- `client_q_per_s` within 1 % of `tps` (the agent sees every client query);
- `kernel_drops` = 0.

For `tls-agent-capture-off`, `client_q_per_s` is ~0 (TLS traffic isn't seen). Record the means per config.

- [ ] **Step 3: Run the TLS soak (30 min)**

Run:

```bash
cd deploy && ./tls/gencerts.sh >/dev/null && cd ..
COMPOSE_FILE=docker-compose.yml:tls/compose.tls.yml PGTRACE_TLS_CAPTURE=true DURATION=1800 \
  OUT="$PWD/docs/soak-results/tls-$(date +%Y%m%d-%H%M)" ./scripts/soak.sh
```

Expected: `SOAK PASSED`; `summary.md` passes every check.

- [ ] **Step 4: Commit the results**

```bash
git add scripts/perf_tls.sh docs/perf-results/tls docs/soak-results/tls-*
git commit -m "TLS capture benchmark and 30-minute TLS soak

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 10: Documentation

**Files:**
- Modify: `README.md`, `docs/performance.md`, `docs/metrics.md`

- [ ] **Step 1: README**

- **Flags table:** add after `-attach-param-sync`:

```markdown
| `-tls-capture` | `false` | trace TLS connections: capture plaintext with uprobes on pgbouncer's libssl (OpenSSL 3, dynamically linked). Costs pgbouncer CPU on every TLS query; see `docs/performance.md` |
```

- **Metrics table:** change the `pgtrace_connections` row's labels to `` `side`, `tls` ``. Add:

```markdown
| `pgtrace_tls_processes` | `state` | with `-tls-capture`: processes with TLS probes `attached` / `unsupported` |
| `pgtrace_tls_unresolved_total` | `result` | with `-tls-capture`: TLS events whose socket wasn't known yet, `resolved` / `dropped` |
```

- **Ceilings:** update the series-ceiling sentence to "2,541 without client labels and 8,975 with the default label limit (2,557 / 8,991 with `-tls-capture`)".

- **Limitations:** replace "No TLS on either side (payloads would be encrypted)." with:

```markdown
- TLS is traced only with `-tls-capture`, for pgbouncer builds that call
  OpenSSL 3's `SSL_read`/`SSL_write` from a dynamically linked `libssl`.
  Without it, TLS connections are counted (`pgtrace_connections{tls="true"}`)
  but their queries aren't seen. Version and cipher attributes are
  best-effort (present when pgbouncer asks OpenSSL for them, e.g. for its
  connection log). Sessions opened before the agent started are picked up
  by a temporary fallback on `read`/`write`; the first call of such a
  session can be lost. The cost: 4 uprobe traps per TLS query in pgbouncer,
  see `docs/performance.md`.
```

- **Quick start:** add `./scripts/e2e_tls.sh   # the same over TLS: strict, mixed, pre-existing sessions` after `make e2e`.

- [ ] **Step 2: performance.md**

Add a `## TLS capture` section after `## Export pipeline`, and a TL;DR row `| TLS capture (opt-in) | … |`. Both come from `docs/perf-results/tls/results.csv`, using the means per config and client count, formatted like the Export pipeline table:

| clients | config | TPS | vs TLS | pgbouncer µs/query | agent CPU |
|---|---|---:|---:|---:|---:|

Add three lines of explanation:
- where the cost comes from (uprobe traps in pgbouncer, measured in the spike: empty probes vs copying);
- that plain connections keep today's cost;
- the soak result.

Add `./scripts/perf_tls.sh` and `./scripts/e2e_tls.sh` to *Reproduce*.

Add a *Limits* bullet: TLS capture adds ≈ X µs of pgbouncer CPU per TLS query (X from the results), and pgbouncer is single-threaded.

- [ ] **Step 3: metrics.md**

- Base table: change `pgtrace_connections` to `` `side` × `tls` `` with 4 series. Base ceiling 2 541, and the ceiling table rows +2: 2 541 / 4 175 / 8 975 / 34 575.
- Add a section `## With -tls-capture` listing `pgtrace_tls_processes{state}` (2), `pgtrace_tls_fallback_attached` (1), `pgtrace_tls_unresolved_total{result}` (2) and 11 more `pgtrace_bpf_recursion_misses_total` programs. The ceiling is +16: 2 557 base, 8 991 at limit 200.

- [ ] **Step 4: Check that the numbers match the code**

Run: `go test -count=1 -run 'TestSeriesBounded' -v ./internal/metrics | grep ceiling`
Expected: the logged ceilings match the docs (2541 base, 2557 with TLS).

- [ ] **Step 5: Commit**

```bash
git add README.md docs/performance.md docs/metrics.md
git commit -m "Docs: TLS capture flag, cost, limitations and metrics

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```
