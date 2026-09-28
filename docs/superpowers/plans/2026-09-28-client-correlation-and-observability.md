# Client Correlation, Metrics and Grafana Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Trace client queries through pgbouncer linked to their server queries (one trace per client query), expose Prometheus metrics for all queries, and ship Prometheus + Grafana (dashboard + VictoriaTraces datasource) in the compose stack.

**Architecture:** Capture client sockets too (new accept probe). Parse both sides with pgwire, which now reports query starts with signatures. A new `correlate` package links server query starts to client queues (link per server connection, signature matching, last-read/oldest tie-break) and emits Traces. The sampler and exporter work on Traces. A `metrics` package observes every query. Compose gains prometheus and grafana with provisioning.

**Tech Stack:** Go 1.27, cilium/ebpf, OTel SDK, prometheus/client_golang, Prometheus 3.15, Grafana 13.2.

**Spec:** `docs/superpowers/specs/2026-09-28-client-correlation-and-observability-design.md`

## Global Constraints

- Metrics endpoint `-metrics-addr` default `:9464`; `-listen-port` default 6432; `-client-tracing` default true; hold timeout 30 s.
- Grafana on host port 3000 (anonymous Admin), Prometheus on 9090; datasource uids `prometheus`, `victoriatraces`; VictoriaTraces Jaeger URL `http://victoriatraces:10428/select/jaeger`.
- Operation label restricted to the fixed list in the spec, else `OTHER`; sqlstate label must be 5 chars, else `OTHER`.
- Histogram buckets: `prometheus.ExponentialBuckets(50e-6, 2.5, 12)`.
- Correlator runs on the agent goroutine: no locks.
- Keep all existing tests and e2e assertions passing.

## Review Focus

1. Client queries that pgbouncer answers itself must not block the pending queue (removed on ClientDone) — correlate test 8.
2. Pool-wait path: the queued client is served after another's `Z I`; attribution must go to the waiting client — correlate test 2.
3. Identical concurrent pgbench extended queries differ only in bind values — pgwire signature test + correlate test 3.
4. Agent restart with live connections: server Parse unknown → BindSig fallback — correlate test 2b.
5. Client disconnect while its server query runs → orphan, no leak — correlate tests 10, 11.

---

### Task 1: pgwire — client direction, startup params, signatures, starts

**Files:** Modify `internal/pgwire/conn.go`, `internal/pgwire/stream.go`; test `internal/pgwire/conn_test.go`, `internal/pgwire/client_test.go` (new); update callers (`internal/agent/agent.go`, benchmarks).

**Interfaces (produces):**
```go
type Start struct { ID, Sig, BindSig uint64; SQLKnown bool; TS uint64; SQL string }
type Result struct { Started []Start; Done []Query }
func NewConn() *Conn        // server side (DirSend = frontend)
func NewClientConn() *Conn  // client side (DirRecv = frontend)
func (c *Conn) Feed(dir event.Dir, ts uint64, payload []byte, totalLen uint32) Result
func (c *Conn) Params() map[string]string
// Query gains: ID, Sig, BindSig uint64; SQLKnown bool; TxStatus byte
```
- Startup message kept (typ 0 with body) and parsed into params.
- Sig: FNV-1a over Q text, or over SQL + 0x00 + bind body after stmt name. BindSig: FNV-1a over bind body after stmt name (0 for simple).
- [ ] Tests first: `TestClientDirection`, `TestStartupParams`, `TestSignatureIgnoresStatementName`, `TestSignatureDiffersByBindValues`, `TestStartedIDsMatchDone`, `TestTxStatus`. Existing tests adapt to `.Done`.
- [ ] Implement; `go test -race ./internal/pgwire` PASS; commit.

### Task 2: connmap — sides, local addr, unix sockets

**Files:** Modify `internal/connmap/connmap.go`, `procnet.go`; tests.
**Interfaces:**
```go
type Side uint8 // SideNone, SideServer, SideClient
type Info struct { Side Side; Remote, Local netip.AddrPort }
type Config struct { ProcRoot string; PGPort, ListenPort uint16; ClientTracing bool }
func New(cfg Config) *Map
func (m *Map) OnConnect(k event.ConnKey, a netip.AddrPort)
func (m *Map) OnAccept(k event.ConnKey, peer netip.AddrPort) // invalid peer = unix
func parseProcNetTCP(r io.Reader, v6 bool) (map[uint64]sockAddrs, error) // local+remote
func parseProcNetUnix(r io.Reader) (map[uint64]bool, error)
```
- [ ] Tests: accept→client; accept with ClientTracing=false → none; local port 6432 via /proc → client; unix inode → client; existing tests adapted. Implement; PASS; commit.

### Task 3: BPF accept probe + decode

**Files:** `bpf/pgtrace.bpf.c`, `internal/event/event.go` (add `Accept{TS; Key; Addr netip.AddrPort}`), `internal/capture/decode.go`, `capture.go`, `decode_test.go`; regenerate.
- fexit `__sys_accept4(int fd, void *upeer, int *upeer_len, int flags, int ret)`: ret ≥ 0, traced → K_ACCEPT (3) with fd=ret; if upeer non-null read family/port/addr (AF_UNIX → family 1, no addr).
- decode: kind 3 → `event.Accept`; family 1 → invalid AddrPort.
- [ ] Test decode accept v4 and unix first; implement; `go generate`; tests PASS; commit.

### Task 4: correlate package

**Files:** Create `internal/correlate/correlate.go`, `correlate_test.go`.
**Interfaces:** exactly as in spec (`New`, `ClientStarted`, `ClientRecv`, `ServerStarted`, `ServerDone`, `ClientDone`, `ClientClosed`, `ServerClosed`, `Tick`, `Trace`, `ClientQuery`, `ServerQuery`), plus `Stats() map[string]uint64` (exact/inferred/none/orphan/internal).
- [ ] Tests 1–11 (+2b) from the spec as table-driven sequences asserting emitted Traces. Implement; PASS with -race; commit.

### Task 5: sampler + export on traces

**Files:** `internal/sampler/sampler.go` (+test), `internal/export/export.go` (+test).
**Interfaces:**
```go
func (s *Sampler) DecideTrace(t correlate.Trace) (bool, Reason) // replaces Decide use in agent; Decide kept for pgwire.Query
type ClientInfo struct { Addr netip.AddrPort; Params map[string]string }
func (e *Exporter) ExportTrace(t correlate.Trace, reason sampler.Reason, client ClientInfo, server func(event.ConnKey) netip.AddrPort)
```
- Root span SERVER + children CLIENT via parent context; attributes per spec; uncorrelated → single CLIENT span.
- [ ] Tests: DecideTrace error in child → error; slow root → slow. Export: parent/child relation, pool_wait_ms, attributes, orphan export. PASS; commit.

### Task 6: metrics package

**Files:** Create `internal/metrics/metrics.go`, `metrics_test.go`.
**Interfaces:**
```go
type Metrics struct{ ... }
func New(reg prometheus.Registerer) *Metrics
func (m *Metrics) ObserveTrace(t correlate.Trace)            // queries, durations, errors, pool wait, correlation
func (m *Metrics) Event(kind string)
func (m *Metrics) SpanDecision(reason sampler.Reason, kept bool)
func (m *Metrics) SetConnections(side string, n int)
func (m *Metrics) SetTracedProcesses(n int)
func (m *Metrics) RegisterKernel(drops func() uint64, bpf func() (time.Duration, uint64), bpfStats bool)
func opLabel(op string) string; func sqlstateLabel(s string) string
```
- [ ] Tests with a fresh registry + `testutil.ToFloat64`/`CollectAndCount`. PASS; commit.

### Task 7: agent + main wiring

**Files:** `internal/agent/agent.go` (+tests, bench), `cmd/pgtrace-agent/main.go`, `internal/capture/capture.go` (TracedCount).
- Agent keeps client conns and server conns; routes per Side; calls correlator; sink receives Traces → metrics.ObserveTrace, sampler.DecideTrace, exporter.ExportTrace. Filter: ignore SideNone only. Tick each second.
- main: flags `-listen-port`, `-client-tracing`, `-metrics-addr`; HTTP server with promhttp.
- [ ] Agent tests: client+server sequence emits one correlated Trace; client-tracing off emits uncorrelated server traces. PASS; `go build`; commit.

### Task 8: compose — Prometheus, Grafana, dashboard, pgbouncer tiny pool

**Files:** `deploy/docker-compose.yml`, `deploy/prometheus/prometheus.yml`, `deploy/grafana/provisioning/datasources/datasources.yml`, `deploy/grafana/provisioning/dashboards/dashboards.yml`, `deploy/grafana/dashboards/pgtrace.json`, `deploy/pgbouncer/pgbouncer.ini` (add `tiny = host=postgres port=5432 dbname=postgres pool_size=2`).
- [ ] Stack up; `curl localhost:9464/metrics`; Prometheus target up; Grafana API: dashboard exists, datasources health OK; commit.

### Task 9: e2e extension

**Files:** `scripts/e2e.sh`.
- Assertions per spec (correlation ≥ 99 %, child within root, SQL equality, pool wait > 10 ms in tiny phase, error trace root+child, admin-console error root without child, metrics/Prometheus/Grafana checks).
- [ ] `make e2e` passes; commit.

### Task 10: performance + docs

**Files:** `scripts/perf.sh` (client-tracing on/off section), `docs/performance.md`, `README.md`.
- [ ] Run section; update docs with measured numbers; commit.
