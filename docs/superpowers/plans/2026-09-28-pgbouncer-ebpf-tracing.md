# pgbouncer eBPF Query Tracing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Go agent that traces pgbouncer→postgres queries with eBPF, samples them, and exports spans to VictoriaTraces over OTLP/HTTP.

**Architecture:** A CO-RE BPF program on syscall tracepoints (sendto/recvfrom/read/write/connect/close) filtered by pgbouncer tgid streams payload chunks into a ringbuf. The Go agent classifies fds as server connections, reassembles the PG wire protocol per connection into `Query` records, samples them, and exports them as OTel spans. docker compose runs postgres, pgbouncer, VictoriaTraces and the agent; a shell e2e script drives pgbench and checks VictoriaTraces.

**Tech Stack:** Go 1.27, github.com/cilium/ebpf (bpf2go), clang 22 + libbpf headers, go.opentelemetry.io/otel SDK + otlptracehttp, docker compose, postgres:17, edoburu/pgbouncer, victoriametrics/victoria-traces.

**Spec:** `docs/superpowers/specs/2026-09-28-pgbouncer-ebpf-tracing-design.md`

## Global Constraints

- Module path: `github.com/t1bur1an/pgtrace`.
- Server-side (pgbouncer → postgres) only; plaintext TCP; no TLS.
- Payload capture cap: 4096 bytes per syscall event; `db.query.text` cap 2048 chars.
- Defaults: `--sample-ratio=0.1`, `--slow-ms=100`, `--pg-port=5432`, `--comm=pgbouncer`, `--service-name=pgbouncer`, `--otlp-endpoint=http://victoriatraces:10428/insert/opentelemetry/v1/traces`.
- VictoriaTraces query API: `http://<host>:10428/select/jaeger/api/traces?service=...`.
- No vmlinux.h: BPF uses minimal hand-written tracepoint context structs (bpftool on host is broken).
- Exporter failure must never block capture.

## Review Focus

1. Messages split across syscalls and many messages coalesced in one syscall — parser must produce identical results to one-message-per-read (Task 2: byte-by-byte and whole-stream feed tests).
2. Payload truncated by the 4 KB kernel cap (large INSERT / big result rows) — parser must skip the missing bytes and stay in sync (Task 2: truncation test).
3. Connections opened before the agent started — parser starts mid-stream; must resync at a plausible message boundary rather than emitting garbage spans (Task 2: mid-stream start test).
4. Extended protocol with a statement prepared before the agent started — span text `<unknown prepared statement "name">` (Task 2 test).
5. Error in the middle of an extended-protocol pipeline (postgres skips until Sync) — exactly one span with error status (Task 2 test).

---

### Task 1: Module scaffold + event types

**Files:**
- Create: `go.mod`, `Makefile`, `.gitignore`, `internal/event/event.go`

**Interfaces:**
- Produces:
  ```go
  package event
  type Dir uint8 // DirSend=0 (pgbouncer→peer), DirRecv=1
  type ConnKey struct{ PID uint32; FD int32 }
  type Data struct{ TS uint64; Key ConnKey; Dir Dir; TotalLen uint32; Payload []byte } // len(Payload) <= TotalLen
  type Connect struct{ TS uint64; Key ConnKey; Addr netip.AddrPort }
  type Close struct{ TS uint64; Key ConnKey }
  ```
- [ ] Step 1: `go mod init github.com/t1bur1an/pgtrace`, write types, Makefile targets `generate`, `build`, `test`, `e2e`.
- [ ] Step 2: `go build ./...` passes. Commit.

### Task 2: `internal/pgwire` streaming parser (TDD)

**Files:**
- Create: `internal/pgwire/stream.go` (framing), `internal/pgwire/conn.go` (query lifecycle), `internal/pgwire/conn_test.go`, `internal/pgwire/testutil_test.go` (message builders)

**Interfaces:**
- Consumes: `event.Dir`
- Produces:
  ```go
  type Query struct {
      Start, End uint64           // monotonic ns
      SQL, Operation, CommandTag  string
      Rows int64
      ErrorCode, ErrorMessage string
      Protocol string             // "simple" | "extended"
      Truncated bool
  }
  type Conn struct{ /* per server connection */ }
  func NewConn() *Conn
  func (c *Conn) Feed(dir event.Dir, ts uint64, payload []byte, totalLen uint32) []Query
  ```
- Framing: frontend (DirSend) and backend (DirRecv) each keep a buffer. A message is `type byte + int32 len (includes itself) + body`. When `totalLen > len(payload)` the missing bytes are recorded as a pending skip: the parser consumes them against the current message's length without data (message marked truncated). If a message header is implausible (unknown type byte, or len < 4 or > 1 GiB), the stream is reset (buffer dropped) and parsing resumes at the next syscall chunk that begins with a plausible header — this also covers mid-stream start.
- Untyped startup packets on the frontend (first message on a fresh conn: int32 len + int32 code 196608/80877103/80877102) are skipped. Backend `R`/`S`/`K` messages are ignored.
- Lifecycle:
  - Frontend `Q`: push pending query {SQL, simple, Start=ts}.
  - Frontend `P` (name, sql): `stmts[name]=sql`. `B` (portal, stmt): `portals[portal]=stmt`. `E` (portal): push pending query {SQL of portal's stmt, extended, Start=ts of first E since last Sync}. Multiple Executes before one Sync produce one query each. Unknown name → `<unknown prepared statement "name">`. Frontend `C` (Close 'S' name) deletes stmt.
  - Backend `D`: rows++ on current query. `C`: set CommandTag, parse row count from tag's last number, complete current extended query (End=ts) → moves to done. `E`: set error on current query; in extended mode mark all remaining pending queries until Sync as not executed (drop them). `Z`: End=ts; completes current simple query; emits all done.
  - Queries are emitted in order when finished.
- Operation: first SQL keyword upper-cased (skip leading whitespace/comments/`(`); if empty use first word of CommandTag.

- [ ] Step 1: Write tests (all must fail first):
  - `TestSimpleQuery`: Q "SELECT 1" → T,D,C "SELECT 1",Z ⇒ one Query{SQL "SELECT 1", Operation SELECT, Rows 1, CommandTag "SELECT 1", Protocol simple, Start/End from ts}.
  - `TestSimpleQueryError`: Q "SELECT 1/0" → E(SQLSTATE 22012, msg "division by zero"), Z ⇒ ErrorCode 22012.
  - `TestExtendedNamedAndUnnamed`: P("s1","select * from t where id=$1"),B("","s1"),D,E(""),S → 1,2,T,D,D,C "SELECT 2",Z ⇒ Query{Rows 2, Protocol extended, Operation SELECT}.
  - `TestExtendedPipelineError`: two Executes in one Sync; first fails ⇒ exactly one Query with error.
  - `TestUnknownPreparedStatement`: B("","stmtX"),E,S without P ⇒ SQL `<unknown prepared statement "stmtX">`.
  - `TestFragmentedByteByByte` / `TestCoalesced`: feed a stream of 3 simple queries byte-by-byte and all at once ⇒ same result as normal feed.
  - `TestTruncatedPayload`: Q with 10 KB SQL delivered as payload[:4096], totalLen=10 KB+5, then next Q normally ⇒ first Query Truncated=true, SQL prefix preserved; second query correct.
  - `TestMidStreamStart`: feed tail of a D message then normal Q/Z cycle ⇒ exactly the later query, no garbage.
  - `TestStartupSkipped`: startup packet + auth backend msgs then Q ⇒ one query.
- [ ] Step 2: `go test ./internal/pgwire/` → FAIL (undefined).
- [ ] Step 3: Implement.
- [ ] Step 4: `go test ./internal/pgwire/ -race` → PASS. Commit.

### Task 3: `internal/sampler` (TDD)

**Files:** Create `internal/sampler/sampler.go`, `internal/sampler/sampler_test.go`

**Interfaces:**
- Produces:
  ```go
  type Reason string // "error","slow","ratio",""
  type Sampler struct{ /* Ratio float64; Slow time.Duration; rand; counters */ }
  func New(ratio float64, slow time.Duration, seed uint64) *Sampler
  func (s *Sampler) Decide(q pgwire.Query) (keep bool, reason Reason)
  func (s *Sampler) Stats() map[string]uint64 // "seen","kept_error","kept_slow","kept_ratio"
  ```
- [ ] Step 1: Tests: errors always kept with ratio 0; slow kept with ratio 0; ratio 0.1 over 100000 fast queries keeps 10000±600; ratio 1 keeps all; ratio 0 keeps none of normal.
- [ ] Step 2: run → FAIL. Step 3: implement (mutex-guarded math/rand/v2 PCG). Step 4: PASS. Commit.

### Task 4: `internal/connmap` (TDD)

**Files:** Create `internal/connmap/connmap.go`, `internal/connmap/procnet.go`, `internal/connmap/connmap_test.go`, `internal/connmap/testdata/proc/...`

**Interfaces:**
- Produces:
  ```go
  type Info struct{ Server bool; Remote netip.AddrPort }
  type Map struct{ /* procRoot string; port uint16; cache map[event.ConnKey]Info */ }
  func New(procRoot string, pgPort uint16) *Map
  func (m *Map) OnConnect(k event.ConnKey, a netip.AddrPort)
  func (m *Map) OnClose(k event.ConnKey)
  func (m *Map) Lookup(k event.ConnKey) Info  // resolves via /proc lazily and caches (negative too)
  func parseProcNetTCP(r io.Reader, v6 bool) (map[uint64]netip.AddrPort /*inode→remote*/, error)
  ```
- [ ] Step 1: Tests: OnConnect to :5432 → Server; to :6432 → not; OnClose removes; `parseProcNetTCP` on fixture lines (v4 and v6 little-endian hex) returns correct remote addr; Lookup with fixture procRoot (`proc/42/fd/7` symlink → `socket:[12345]`, `proc/42/net/tcp` containing inode 12345 remote port 0x1538) → Server.
- [ ] Step 2 FAIL, Step 3 implement, Step 4 PASS. Commit.

### Task 5: BPF program + `internal/capture`

**Files:** Create `bpf/pgtrace.bpf.c`, `internal/capture/gen.go` (`//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target amd64 -type event pgtrace ../../bpf/pgtrace.bpf.c -- -I/usr/include -O2 -g`), `internal/capture/capture.go`, `internal/capture/decode.go`, `internal/capture/decode_test.go`, generated `pgtrace_x86_bpfel.{go,o}`

**Interfaces:**
- Consumes: `event.*`
- Produces:
  ```go
  type Config struct{ Comm string; RescanEvery time.Duration }
  type Capture struct{ Events <-chan any /* event.Data|event.Connect|event.Close */ }
  func Start(ctx context.Context, cfg Config) (*Capture, error)
  func (c *Capture) Drops() uint64
  func (c *Capture) Close() error
  func decode(raw []byte) (any, error)  // pure, unit-tested
  ```
- BPF event layout (packed, little-endian): `u8 kind(0 data,1 connect,2 close); u8 dir; u16 family; u32 tgid; s32 fd; u32 total_len; u32 cap_len; u16 port(host order); u8 addr[16]; u64 ts; u8 payload[4096]` — ringbuf reserve is `sizeof(header)+4096` fixed-size.
- Tracepoint contexts: `struct sys_enter_ctx { u64 pad; long id; unsigned long args[6]; }`, `struct sys_exit_ctx { u64 pad; long id; long ret; }`.
- Enter probes stash `{fd, buf, kind}` in `active` keyed by pid_tgid (only if tgid in `target_pids`); exit probes emit if ret>0 (connect: ret==0 or -EINPROGRESS(-115); read addr at enter from user sockaddr).
- read/write events: userspace drops them unless connmap says server (same as send/recv).
- `drops` = per-CPU array counter incremented when ringbuf reserve fails.
- pid discovery: scan `/proc/*/comm` == cfg.Comm every RescanEvery, update `target_pids`.
- [ ] Step 1: decode test with hand-built bytes for each kind. FAIL. Step 2: write BPF C + `go generate` + capture.go. Step 3: `go test ./internal/capture/` PASS, `go vet ./...`. Commit.

### Task 6: `internal/export`

**Files:** Create `internal/export/export.go`, `internal/export/export_test.go`

**Interfaces:**
- Produces:
  ```go
  type Span struct{ Q pgwire.Query; PID uint32; FD int32; Remote netip.AddrPort; Reason sampler.Reason }
  type Exporter struct{}
  func New(ctx context.Context, endpoint, service string) (*Exporter, error)
  func newWithSpanExporter(sx sdktrace.SpanExporter, service string, clock func() (mono, wall int64)) *Exporter // tests
  func (e *Exporter) Export(s Span)
  func (e *Exporter) Shutdown(ctx context.Context) error
  ```
- Time conversion: offset = wall_now - mono_now measured once (`unix.ClockGettime(CLOCK_MONOTONIC)`); wall = mono + offset.
- [ ] Step 1: test with `tracetest.InMemoryExporter`: exported span has name "SELECT", kind Client, attributes listed in spec, start/end = mono+offset, error status on ErrorCode != "", `db.query.text` truncated to 2048. FAIL. Step 2 implement. Step 3 PASS. Commit.

### Task 7: agent main wiring

**Files:** Create `cmd/pgtrace-agent/main.go`, `internal/agent/agent.go`, `internal/agent/agent_test.go`

**Interfaces:**
- Produces: `func Run(ctx context.Context, events <-chan any, cm *connmap.Map, smp *sampler.Sampler, sink func(export.Span))` — single goroutine: Connect→cm.OnConnect; Close→cm.OnClose + delete parser; Data→if cm.Lookup(key).Server feed per-key `pgwire.Conn`, run each Query through sampler, sink kept.
- main: flags from Global Constraints, env overrides `PGTRACE_*`, periodic stats log every 10 s (events, queries, sampler stats, drops), SIGINT/SIGTERM shutdown flushing exporter.
- [ ] Step 1: agent test: feed Connect(:5432) + data events for one simple query + a non-server fd's data ⇒ sink receives exactly one Span. FAIL. Step 2 implement. Step 3 PASS; `go build ./cmd/pgtrace-agent`. Commit.

### Task 8: docker compose stack + e2e

**Files:** Create `Dockerfile`, `deploy/docker-compose.yml`, `deploy/pgbouncer/pgbouncer.ini`, `deploy/pgbouncer/userlist.txt`, `scripts/e2e.sh`, `README.md`

- Dockerfile: multi-stage `golang` + clang/libbpf-dev → `go generate && go build`; runtime `debian:stable-slim`.
- compose: postgres (POSTGRES_PASSWORD=postgres, healthcheck), pgbouncer (transaction pool, listen 6432, `auth_type=scram-sha-256` or md5 via userlist), victoriatraces (port 10428), agent (`privileged`, `pid: host`, volumes `/sys/kernel/debug`, `/sys/fs/bpf`, env `PGTRACE_SAMPLE_RATIO=0.1`, `PGTRACE_SLOW_MS=100`).
- e2e.sh:
  1. `docker compose up -d --build`, wait for pg + vt + agent log "attached".
  2. `pgbench -i -s 1` via pgbouncer; `pgbench -M simple -c 4 -t 500`; `pgbench -M extended -c 4 -t 500`.
  3. 5× `SELECT 1/0`, 5× `SELECT * FROM missing_table`, 5× `SELECT pg_sleep(0.2)` via psql through pgbouncer.
  4. sleep 10; query `/select/jaeger/api/traces?service=pgbouncer&limit=...` and `tags={"error":"true"}` / `minDuration=150ms`.
  5. Assert with jq: ≥10 error spans (22012 and 42P01 present), ≥5 spans with duration ≥200ms and SQL containing pg_sleep, operations include SELECT/UPDATE/INSERT, total spans between 5% and 20% of pgbench statements (+ forced ones).
  Print PASS/FAIL summary; exit non-zero on failure.
- [ ] Step 1: write files. Step 2: `make e2e` passes. Step 3: README with usage. Commit.
