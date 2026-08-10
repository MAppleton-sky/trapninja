# TrapDojo — Low Level Design: TrapNinja Load Test Rig

**Status:** Draft for review
**Version:** 0.1
**Last Updated:** August 2026
**Companion to:** [HighLevel-TestRig.md](HighLevel-TestRig.md)

---

## Table of Contents

- [Purpose of This Document](#purpose-of-this-document)
- [Scope of This LLD](#scope-of-this-lld)
- [Repository Layout](#repository-layout)
- [Package & Module Map](#package--module-map)
- [Runtime Process Model](#runtime-process-model)
- [Wire Format (Byte-Exact)](#wire-format-byte-exact)
- [Run Manifest](#run-manifest)
- [Generator — Detailed Design](#generator--detailed-design)
- [Sink — Detailed Design](#sink--detailed-design)
- [Orchestrator — Detailed Design](#orchestrator--detailed-design)
- [Reporter — Detailed Design](#reporter--detailed-design)
- [Scenario File Schema](#scenario-file-schema)
- [Report Schema](#report-schema)
- [CLI Specification](#cli-specification)
- [Configuration Files](#configuration-files)
- [Error Handling & Failure Modes](#error-handling--failure-modes)
- [Security & Safety Interlocks](#security--safety-interlocks)
- [Observability of the Rig Itself](#observability-of-the-rig-itself)
- [Testing Strategy](#testing-strategy)
- [Performance Budgets & Validation](#performance-budgets--validation)
- [Deferred to R2+](#deferred-to-r2)
- [Open Design Questions](#open-design-questions)

---

## Purpose of This Document

The HLD defines *what* TrapDojo does and *why*. This LLD defines *how* it is implemented, at the level a developer can begin coding against:

- Concrete module boundaries with responsibilities, dependencies, and line-count guidance.
- Byte-exact wire format for sequence-tagged traps.
- Class/function signatures for the hot paths.
- File schemas for scenarios, run manifests, and reports.
- Concurrency model (processes, threads, sockets, shared state) and where the boundaries lie.
- Failure semantics per component.

TrapDojo lives in its own repository. This LLD is written to be portable there; where it references TrapNinja modules, it does so only via TrapNinja's public surface (CLI + `.prom` files + SSH-invoked actions).

---

## Scope of This LLD

This document is deep on **R1 (Generator + Sink)** and **R2 (Orchestrator + Reporter)** — the pieces that must exist for any credible loss-accounting result. R3–R5 (bursts, action injection, SNMPv3, comparison) are outlined at interface level only; their detailed design happens after R2 has shipped and the reconciliation model is proven against real TrapNinja runs.

**In scope for this document:**
- Generator: template builder, rate control, send workers, per-worker accounting, IPC.
- Sink: multi-process listener, sequence/gap tracker, own-drop monitor, per-destination reports.
- Orchestrator: scenario runner, SUT metric collector, timeline recorder.
- Reporter: reconciliation math, `report.json`, `report.md`.
- File formats, CLI surface, config layout.

**Out of scope (deferred):**
- SNMPv3 template generation and its rate ceiling (open question 5 in the HLD).
- Multi-generator-host coordination protocol (additive to run manifest; specified at R3).
- `--compare` regression report format (R5).
- Ansible role structure beyond a stub.

---

## Repository Layout

```
trapdojo/
├── src/
│   ├── trapdojo.py                       # setuptools entry point
│   ├── VERSION
│   └── trapdojo/
│       ├── __init__.py
│       ├── __version__.py
│       ├── main.py                       # argparse dispatch → cli.registry
│       ├── core/
│       │   ├── constants.py              # OIDs, defaults, magic bytes
│       │   ├── exceptions.py             # TrapDojoError hierarchy
│       │   ├── manifest.py               # RunManifest read/write
│       │   ├── template.py               # SNMP trap byte templates
│       │   └── wire.py                   # (run_id, stream_id, seq) codec
│       ├── generator/
│       │   ├── __init__.py
│       │   ├── coordinator.py            # Forks workers, aggregates counters
│       │   ├── worker.py                 # Send loop (one process per worker)
│       │   ├── rate.py                   # Token bucket, profile drivers
│       │   ├── sendmmsg.py               # ctypes binding + fallback
│       │   ├── sources.py                # Spoofed-source IP pool / NIC alias fallback
│       │   ├── profiles.py               # constant/ramp/burst/replay profile classes
│       │   └── accounting.py             # WorkerCounters, flush to manifest
│       ├── sink/
│       │   ├── __init__.py
│       │   ├── listener.py               # SO_REUSEPORT UDP listener process
│       │   ├── extractor.py              # Fixed-offset (run,stream,seq) extraction
│       │   ├── gap_tracker.py            # Interval-set gap tracker per (stream,dest)
│       │   ├── drop_monitor.py           # /proc/net/udp poller
│       │   ├── ring.py                   # Optional latency ring buffer
│       │   └── aggregator.py             # Merges per-listener counters → report
│       ├── orchestrator/
│       │   ├── __init__.py
│       │   ├── scenario.py               # Scenario loader + validator
│       │   ├── runner.py                 # Lifecycle: warmup/measure/drain/teardown
│       │   ├── collector.py              # SUT metric polling (prom + JSON)
│       │   ├── injector.py               # SSH action executor
│       │   ├── failure.py                # Per-dwell-step failure evaluator
│       │   └── timeline.py               # Event log with monotonic timestamps
│       ├── reporting/
│       │   ├── __init__.py
│       │   ├── reconcile.py              # Loss-accounting equation
│       │   ├── report_json.py            # Machine-readable output
│       │   └── report_md.py              # Human-readable output
│       ├── cli/
│       │   ├── __init__.py
│       │   ├── registry.py               # Command registry pattern (TrapNinja-style)
│       │   ├── generate.py               # `trapdojo generate`
│       │   ├── sink.py                   # `trapdojo sink`
│       │   ├── orchestrate.py            # `trapdojo orchestrate`
│       │   ├── report.py                 # `trapdojo report`
│       │   └── selfcheck.py              # `trapdojo selfcheck` (rig self-benchmark)
│       └── util/
│           ├── logging.py                # Structured logs, stderr-only in hot paths
│           ├── clock.py                  # monotonic_ns wrappers
│           └── ipc.py                    # Coordinator↔worker pipe helpers
├── scenarios/                            # Ships example scenarios
├── config.example/
├── ansible/                              # Stub in R1; fleshed out at R4
├── dev/tests/
└── docs/
    ├── ARCHITECTURE.md
    ├── SCENARIOS.md
    ├── WIRE_FORMAT.md
    └── OPERATIONS.md
```

Module size guidance mirrors TrapNinja: 300–500 lines per file, split at genuine seams.

---

## Package & Module Map

| Package | Responsibility | Depends on | Target size |
|---|---|---|---|
| `core` | Immutable primitives: wire codec, templates, run manifest, constants, exceptions | stdlib only | 4 modules × ~200 LOC |
| `generator` | Turn a rate profile into UDP packets on the wire | `core`, `util`, ctypes | 7 modules × ~250 LOC |
| `sink` | Turn arriving UDP packets into per-stream counters and gap sets | `core`, `util` | 6 modules × ~250 LOC |
| `orchestrator` | Drive a scenario end-to-end, poll SUT, inject actions | `core`, `util`, `paramiko` (SSH) | 6 modules × ~300 LOC |
| `reporting` | Reconcile counters into a verdict | `core` | 3 modules × ~300 LOC |
| `cli` | Argparse subcommands → package APIs | all above | thin — < 150 LOC each |
| `util` | Structured logging, clocks, pipe IPC | stdlib | 3 modules × ~150 LOC |

**Dependency rule:** `core` and `util` are leaves. `generator`, `sink`, `orchestrator`, `reporting` may depend on `core`/`util` and **not on each other** — the orchestrator talks to the other two over the wire (SSH/exec + files), never by import. This keeps the process boundary honest and lets the sink run on a host that has never installed the generator.

---

## Runtime Process Model

Each TrapDojo command is a distinct OS process tree.

**`trapdojo generate` (one per generator host):**

```
coordinator (main proc)
 ├── worker-0 (stream_id=0)   ── raw UDP socket, sendmmsg loop
 ├── worker-1 (stream_id=1)   ── raw UDP socket, sendmmsg loop
 ├── ...
 └── worker-N-1               ── raw UDP socket, sendmmsg loop

IPC:
 - coordinator → worker:   os.pipe() write end, one per worker; commands = start/pause/rate/stop
 - worker → coordinator:   os.pipe() read end, one per worker; counter snapshots every 1s
```

- Workers are `multiprocessing.Process` children with `start_method='fork'` (Linux only; RHEL 8/9 target).
- Each worker owns a distinct `stream_id`; sequence spaces never overlap.
- No worker↔worker communication.

**`trapdojo sink` (one per sink host):**

```
supervisor (main proc)
 ├── listener-0 (SO_REUSEPORT on :162)   ── recvmmsg loop → shared_counters (mmap)
 ├── listener-1 (SO_REUSEPORT on :162)
 ├── ...
 ├── listener-K-1
 ├── drop_monitor (thread in supervisor) ── /proc/net/udp every 1s
 └── aggregator (thread in supervisor)   ── merges shared_counters, writes partial report every N s
```

- Listeners share a POSIX shm segment (via `multiprocessing.shared_memory`) sized for per-stream counter tables + gap-interval arenas. Locking is per-stream (fine-grained) using a small pool of `multiprocessing.Lock` — contended only during segment allocation, not on every packet.
- The gap tracker is thread-safe within a listener; cross-listener merging happens in the aggregator, not on the packet path.

**`trapdojo orchestrate` (single process):**

- Single asyncio event loop.
- Subprocess wrappers for `ssh` (no long-lived shells; each poll is a discrete SSH invocation with a connection-multiplex socket controlled by ssh's `ControlMaster`).
- Timeline events written append-only to `timeline.jsonl` under the run directory.

---

## Wire Format (Byte-Exact)

Every generated trap carries an **identity varbind** at a **known offset** from the start of the UDP payload. Both generator (patch) and sink (extract) reach the identity bytes without ASN.1 parsing.

### Identity varbind

- OID: `.1.3.6.1.4.1.99999.1.1` (final enterprise arc TBD before code freeze; placeholder in HLD).
- Type: `OCTET STRING`, fixed length 32 bytes.

Payload layout (network byte order, big-endian):

| Offset (in varbind value) | Size | Field | Notes |
|---|---|---|---|
| 0 | 8 | `run_id` | ASCII lowercase, right-padded with `0x00` if shorter than 8 chars. Truncated form of scenario run id (e.g. `2607rmp1`) |
| 8 | 4 | `stream_id` | uint32, per generator worker |
| 12 | 8 | `seq` | uint64, monotonic per stream, starts at 1 |
| 20 | 8 | `send_ts_ns` | uint64 monotonic-ns at send (0 if disabled) |
| 28 | 4 | `magic` | `0x54 0x44 0x4A 0x30` (`"TDJ0"`) — sink sanity check |

Total: 32 bytes.

### Template shape

Templates are constructed once at generator startup with fully-serialized ASN.1 BER for:

- SNMPv2c trap-PDU with:
  - `sysUpTime.0` = static (0)
  - `snmpTrapOID.0` = one of the OIDs from the OID pool
  - `trapdojoIdentity` (the identity varbind above)
  - 3–8 vendor-shaped payload varbinds (OCTET STRING, INTEGER, IpAddress, TimeTicks) with random-but-fixed values chosen at template build time to yield the target average trap size (default: ~200 bytes)

The identity varbind is placed **last** in the varbind list so its value bytes land at a template-specific but pre-computed offset. Each template exports its offset table:

```python
@dataclass(frozen=True)
class Template:
    payload: bytes                  # complete SNMP message ready for sendto
    identity_offset: int            # start of identity value bytes within payload
    template_id: int                # index into per-worker template array
    version: int                    # 1=v1, 2=v2c, 3=v3
    approx_size: int                # for accounting
```

### Patch operation (hot path)

For each send, the worker:

1. Picks the next template (round-robin or weighted, decided at manifest build).
2. `payload = bytearray(template.payload)` — one allocation.
3. Writes `stream_id`, `seq`, and (optional) `send_ts_ns` into `payload[template.identity_offset + 8 : template.identity_offset + 28]` via `struct.pack_into`.
4. Emits via `sendmmsg`.

`run_id` and `magic` are baked into the template — never patched.

### Extract operation (hot path)

Sink extracts identity by scanning for the 4-byte `magic` in the last 64 bytes of the UDP payload (bounded scan, O(1) amortised — templates are stable per run), then reads the 32 bytes ending at magic. This survives small template changes without renegotiating offsets per template. Fallback: if the run manifest carries a per-template offset table (present when the sink is co-launched with the generator), the offset is exact.

---

## Run Manifest

Written by the orchestrator (or by `trapdojo generate` when run standalone) at run start. Read by generator (to build templates), by sink (to know what stream_ids/dests to expect), and by the reporter (as the source of truth about what the run *intended*).

**File:** `<report-dir>/<run-id>/manifest.json`

```jsonc
{
  "run_id": "2026-08-10-ramp-01",
  "run_id_wire": "260810r1",              // 8-byte truncation used on the wire
  "created_utc": "2026-08-10T12:00:00Z",
  "trapdojo_version": "0.1.0",
  "scenario_ref": "scenarios/ramp-to-failure-ebpf.json",
  "scenario_sha256": "…",

  "wire": {
    "identity_oid": "1.3.6.1.4.1.99999.1.1",
    "identity_len": 32,
    "magic": "TDJ0"
  },

  "generator": {
    "host": "gen-01",
    "workers": 8,
    "streams": [0,1,2,3,4,5,6,7],
    "templates": [
      { "template_id": 0, "version": 2, "approx_size": 210, "identity_offset": 162 },
      // ...
    ],
    "sources": {
      "mode": "spoof",                    // or "alias"
      "pool_size": 5000,
      "pool_cidr": "10.234.100.0/20"
    },
    "profile": { /* copied from scenario */ }
  },

  "sink": {
    "host": "sink-01",
    "listeners": [
      { "bind": "10.234.83.140:162",  "reuseport_workers": 4, "destination_label": "primary-noc" },
      { "bind": "10.234.83.140:1162", "reuseport_workers": 2, "destination_label": "voice-noc" }
    ]
  },

  "sut": {
    "primary_host": "trapninja-p",
    "secondary_host": "trapninja-s",
    "capture_mode_expected": "ebpf",
    "trapninja_version": "0.8.1"
  }
}
```

`scenario_sha256` binds every counter file, timeline, and report to the exact scenario that produced them — the reporter refuses to reconcile mismatched files.

---

## Generator — Detailed Design

### 1. Template builder (`core/template.py`)

- Runs **once** at coordinator startup, before workers fork.
- Uses `pysnmp.hlapi` **or** a hand-rolled BER encoder (decision at implementation start; hand-rolled avoids the pysnmp import cost and gives precise byte control — likely choice).
- Produces `List[Template]` for the version mix and OID pool declared in the manifest.
- The list is passed to workers via inherited memory (fork COW) — no serialisation needed.

### 2. Rate profiles (`generator/profiles.py`)

Abstract interface:

```python
class RateProfile(Protocol):
    def target_rate(self, t_elapsed_s: float) -> float: ...
    def is_finished(self, t_elapsed_s: float) -> bool: ...
```

Implementations:

- `ConstantProfile(rate, duration_s)`
- `RampProfile(start_rate, end_rate, step, dwell_s)` — step-wise, holds each step for `dwell_s`.
- `BurstProfile(baseline_rate, spike_rate, spike_duration_s, spike_period_s, count)`
- `ReplayProfile(csv_path)` — `(t_s, rate_tps)` rows, linearly interpolated.

The coordinator polls `target_rate()` every 100 ms and broadcasts the new per-worker rate over the command pipe as a single 8-byte double.

### 3. Token bucket (`generator/rate.py`)

Per-worker, in-process, single-threaded.

```python
class TokenBucket:
    def __init__(self, rate: float, burst: int) -> None: ...
    def set_rate(self, rate: float) -> None: ...     # called on pipe message
    def acquire(self, n: int) -> int:                # returns count granted (≤ n)
        """Non-blocking. Returns 0 if empty; caller sleeps for the deficit."""
```

The worker send loop asks for a batch (`SENDMMSG_BATCH`, default 128), sends what was granted, and sleeps the remainder using `time.sleep(max(0, 1/rate * deficit))`. Sleep is only allowed *between* batches — never inside a batch send.

### 4. sendmmsg binding (`generator/sendmmsg.py`)

- `ctypes.CDLL("libc.so.6", use_errno=True)`.
- Declares `struct iovec`, `struct msghdr`, `struct mmsghdr`.
- Exposes `send_batch(fd: int, payloads: Sequence[bytes], dest: Tuple[str,int]) -> int` returning number of messages the kernel accepted.
- On `EINTR` retries; on `ENOBUFS`/`EAGAIN` returns partial count without raising — the caller increments `send_defer` counters and re-queues the remainder.
- Detected once at import: if the symbol resolves and a smoke test on a `SOCK_DGRAM` succeeds, `USE_SENDMMSG=True`; otherwise the fallback `sendto` loop is used and a warning is logged **once**.

Never allocates in the hot loop: iovec/mmsghdr arrays are sized to `SENDMMSG_BATCH` and reused (memoryview into a preallocated `ctypes` array).

### 5. Spoofed sources (`generator/sources.py`)

Two modes, selected at manifest build:

**`spoof`** (preferred): raw socket with `IP_HDRINCL`, generator builds the IP header itself.

- Worker owns `AF_INET` `SOCK_RAW` with `IPPROTO_UDP`.
- Source IP is chosen per packet from the pool via a fast linear index (not RNG — deterministic per stream_id makes replay easier).
- IP header checksum computed once per source IP and cached in the source-pool table.
- UDP checksum computed per packet (pseudo-header depends on source IP).

**`alias`** (fallback when uRPF blocks spoof):

- The rig-installer configures N `ip addr add … dev …` aliases at deploy time.
- Worker binds N sockets, one per alias, and round-robins.
- Capped pool size, documented in the scenario report.

Selection: coordinator probes at startup by sending one spoofed packet to the sink and checking the sink's per-stream counters within 2 s. If not observed, degrades to `alias` and logs a manifest annotation.

### 6. Worker send loop (`generator/worker.py`)

```python
def run(cfg: WorkerCfg, cmd_pipe, ctr_pipe) -> None:
    templates = cfg.templates                        # inherited via fork
    bucket    = TokenBucket(cfg.initial_rate, burst=cfg.batch_size * 4)
    seq       = 1
    batch_buf = [bytearray(t.payload) for t in _prepare_batch_slots(cfg.batch_size)]
    counters  = WorkerCounters()
    next_tick = monotonic_ns() + 1_000_000_000       # 1s counter flush

    while True:
        _drain_cmd_pipe(cmd_pipe, bucket)            # non-blocking rate updates
        grant = bucket.acquire(cfg.batch_size)
        if grant == 0:
            _sleep_until_bucket_refill(bucket)
            continue

        for i in range(grant):
            tmpl = _next_template(templates, i)
            _patch_identity(batch_buf[i], tmpl, cfg.stream_id, seq)
            seq += 1

        sent = send_batch(cfg.raw_fd, batch_buf[:grant], cfg.dest)
        counters.sent   += sent
        counters.defer  += grant - sent

        if monotonic_ns() >= next_tick:
            _flush(counters, ctr_pipe)
            counters.reset_delta()
            next_tick += 1_000_000_000

        if cfg.profile_finished():
            break
```

Guarantees:
- Zero heap allocation inside the loop after warm-up (buffers, iovecs, counters all preallocated).
- No `logger.debug()` calls on the hot path — logs are counter names + values, batched to stderr from the coordinator.
- `seq` is worker-local — no cross-worker synchronisation.

### 7. Accounting (`generator/accounting.py`)

Per-worker counters flushed once per second to the coordinator, coordinator writes `sent_by_second.jsonl` under the run dir. Fields per row:

```
{ "t_s": 42, "worker": 3, "stream_id": 3,
  "sent": 30125, "defer_enobufs": 12, "defer_eagain": 0,
  "target_rate": 30000 }
```

`sent` here is **post-syscall success** (kernel accepted the packet). Anything the kernel refused is `defer_*` and is excluded from offered load in the reconciliation equation.

---

## Sink — Detailed Design

### 1. Listener process (`sink/listener.py`)

- Bound with `SO_REUSEPORT` so the kernel distributes incoming packets across K listener processes.
- `SO_RCVBUF` set to `RCVBUF_TARGET` (default 32 MiB); if kernel refuses (system max), retries in halving steps and logs the final value in the manifest.
- Uses `recvmmsg` via the same ctypes binding shape as generator's sendmmsg (shared `util/mmsg.py`).
- Hot loop:

```python
def run(cfg: ListenerCfg, shm_view) -> None:
    bufs = [bytearray(2048) for _ in range(RECVMMSG_BATCH)]
    while not _stop.is_set():
        got, srcs = recv_batch(cfg.fd, bufs)
        for i in range(got):
            ident = extract_identity(bufs[i])       # bounded scan for magic
            if ident is None:
                shm_view.foreign += 1                # not from this run — counted, dropped
                continue
            _record(shm_view, ident.stream_id, ident.seq,
                    dest=cfg.destination_label,
                    src_ip=srcs[i], size=len(bufs[i]))
```

- `extract_identity` returns `None` when the magic isn't in the last 64 bytes; those packets are counted as `foreign` (traps from other sources, useful for lab hygiene).

### 2. Gap tracker (`sink/gap_tracker.py`)

Data structure: **sorted list of `(lo, hi)` inclusive integer intervals of *received* sequences per stream** (not per gap). Chosen so a 100M-trap soak stays bounded at O(number of gaps), not O(number of traps).

Operations:

- `record(seq)`:
  - Binary-search insertion point.
  - If `seq` extends an existing interval (`seq == hi + 1` or `seq == lo - 1`), extend and merge with the neighbour if adjacent.
  - Else insert `(seq, seq)`.
  - Duplicate (`seq` within an existing interval): increment `duplicate_count`, do not modify.
- `finalize(expected_max_seq) -> GapReport`:
  - Computes the complement of the received-intervals set within `[1, expected_max_seq]`.
  - Returns `(received_count, duplicate_count, gap_ranges: List[Tuple[int,int]])`.

Memory bound: the gap list length is bounded by the number of loss events, not the trap volume. A run with 50 gaps holds 50 tuples per stream.

Concurrency: **not** thread-safe; each stream is owned by exactly one listener process (partitioning of `stream_id % K`). Cross-listener merge happens once at end-of-run in `aggregator.py`.

Wait — `SO_REUSEPORT` distributes by kernel hash, not by `stream_id`. To keep gap tracking per-listener without cross-process locking, the sink pins each `stream_id` to a listener by having listeners publish a "not mine" fast-path skip; the packet is re-queued to the correct listener via a lock-free MPMC ring in shared memory. **Deferred to R2 implementation** — R1 uses a single listener process (simpler, adequate for < 100k tps in initial validation), and multi-listener is enabled once we have baseline numbers.

### 3. Own-drop monitor (`sink/drop_monitor.py`)

- Thread in the supervisor process.
- Every 1 s reads `/proc/net/udp` and `/proc/net/udp6`, parses the `drops` column for the sink's bound sockets (matched by local port hex + inode).
- Delta-based: first read is baseline; every subsequent read adds the delta to `sink_kernel_drops` in shared memory.
- **Any non-zero delta invalidates the run for the affected destination.** The reconciliation report flags `sink_bottleneck=true` and refuses PASS.

### 4. Aggregator (`sink/aggregator.py`)

- Runs in the supervisor process.
- Every `AGGREGATOR_INTERVAL_S` (default 10 s) reads shared counters, writes a partial JSON snapshot to `<report-dir>/<run-id>/sink_partial.jsonl` (one line per snapshot).
- At end-of-run, invokes `gap_tracker.finalize(expected_max_seq_per_stream)` using per-stream max sequences read from the generator's `sent_by_second.jsonl` (the orchestrator supplies this file; when the sink runs standalone, `finalize` is deferred to `trapdojo report`).

Output at end of run: `<report-dir>/<run-id>/sink_final.json`.

---

## Orchestrator — Detailed Design

### 1. Scenario runner (`orchestrator/runner.py`)

Lifecycle state machine:

```
LOAD → VALIDATE → PROBE_SUT → START_SINK → START_GENERATOR
     → WARMUP → MEASURE (per dwell step) → DRAIN → TEARDOWN → REPORT
```

Each state transition emits a `TimelineEvent`. Any exception in `START_*` triggers `TEARDOWN` cleanly (sink and generator receive SIGTERM, orchestrator waits for their `report.json` sentinels).

State details:

- **VALIDATE**: schema-check the scenario, expand hostnames, resolve `destructive` interlock (see [Security & Safety Interlocks](#security--safety-interlocks)).
- **PROBE_SUT**: SSH to primary and secondary, capture `trapninja --version`, HA state, capture mode. Written into the manifest.
- **START_SINK**: SSH to sink host, `trapdojo sink … --run-id …`, wait for its ready-line on stdout (or fail after `READY_TIMEOUT_S`).
- **START_GENERATOR**: SSH to generator host(s), spawn with the scenario's profile.
- **WARMUP**: hold at scenario's warmup rate for `warmup_s`; discard counters from the measurement window.
- **MEASURE**: for each dwell step, poll SUT metrics every `POLL_INTERVAL_S` (default 5 s), evaluate failure criteria at end of step. Stop ramp on first sustained breach.
- **DRAIN**: drop generator rate to 0; poll SUT queue depth until it returns to baseline or `DRAIN_TIMEOUT_S` elapses.
- **TEARDOWN**: signal sink and generator to stop, collect their final files via SFTP.
- **REPORT**: invoke `reporting.reconcile.run(manifest_path, run_dir)`.

### 2. Collector (`orchestrator/collector.py`)

Two collection paths, tried in order per SUT host:

1. **`.prom` file over SSH** — `ssh sut "cat /var/lib/prometheus/node-exporter/trapninja.prom"` piped into a text parser (`prometheus_client.parser` is optional; a small hand parser avoids the dep).
2. **`trapninja metrics show --json`** — invoked on SUT via SSH.

For each metric family: `{ counter_name → { labels_key → (value, ts_monotonic) } }`. The collector computes **deltas** between consecutive polls (no reset needed on the SUT — see HLD prerequisite). Deltas are written to `<run-dir>/sut_<host>.jsonl`, one row per poll.

**SSH efficiency:** all SSH invocations use `-o ControlMaster=auto -o ControlPath=<sock> -o ControlPersist=60s` — a single TCP+auth handshake per SUT host for the entire run. Falls back to per-invocation SSH if `ControlMaster` fails.

### 3. Injector (`orchestrator/injector.py`)

An `Action` is a small dataclass:

```python
@dataclass(frozen=True)
class Action:
    at_s: float                  # seconds from start of MEASURE
    host: str                    # scenario-declared alias, resolved to hostname
    command: str                 # from a whitelist keyed by action_type
    action_type: str             # "ha_failover" | "stop_primary" | "stop_redis" | ...
    expect_recovery_within_s: float
```

- Commands are **not** freeform strings from the scenario — the scenario names `action_type`; the injector maps to a whitelisted command string. This prevents scenario files from becoming remote-code-execution vectors.
- Actions are dispatched at their `at_s` mark and their exit status is recorded in the timeline.

Action whitelist for R2:

| `action_type` | Resolved command | Notes |
|---|---|---|
| `ha_failover` | `sudo trapninja ha force-failover --yes` | Requires sudoers entry on SUT |
| `stop_primary` | `sudo systemctl stop trapninja` | Only if `destructive=true` in scenario |
| `start_primary` | `sudo systemctl start trapninja` | |
| `stop_redis` | `sudo systemctl stop redis` | |
| `start_redis` | `sudo systemctl start redis` | |

`stop_primary`, `stop_redis`, `nft`-based split-brain are deferred to R4 with the destructive interlock in place.

### 4. Failure evaluator (`orchestrator/failure.py`)

At end of each dwell step, computes:

- End-to-end loss ratio = `1 - (received / offered)` where `offered = sent_by_second - defer_*`.
- Queue-depth trend = linear regression slope over the step's poll samples. Fails if slope > 0 and depth > 0.5 × `queue_size` at step end.
- `queue_wait p99` = maximum p99 sample in the step.
- RSS growth = `(rss_end - rss_start) / duration_min`.
- Health = presence of any WORKER_CRASH or HA_FLAP event in the timeline during the step.

Returns `StepVerdict(status: {"pass","fail"}, breaches: List[str], metrics: Dict[str,float])`. Persisted to `<run-dir>/step_verdicts.jsonl`.

---

## Reporter — Detailed Design

### `reporting/reconcile.py`

Reads: `manifest.json`, `sent_by_second.jsonl`, `sut_*.jsonl`, `step_verdicts.jsonl`, `sink_final.json`, `timeline.jsonl`.

Computes per stream and per destination:

```
offered      = Σ sent
sut_kernel   = Σ Δ trapninja_socket_drops_total          (or ebpf lost samples)
sut_queue    = Σ Δ trapninja_queue_drops_total
sut_blocked  = Σ Δ trapninja_blocked_total
sut_fwderr   = Σ Δ trapninja_dest_failures_total
received     = sink_final.received_count
duplicates   = sink_final.duplicate_count
unexplained  = offered - (sut_kernel + sut_queue + sut_blocked + sut_fwderr + received)
```

`unexplained ≠ 0` is a first-class finding. The reporter renders it prominently and refuses PASS if the scenario does not explicitly permit it.

### `reporting/report_json.py`

Emits `<run-dir>/report.json` with:

```jsonc
{
  "run_id": "…",
  "scenario_ref": "…",
  "verdict": "pass" | "fail",
  "breaking_point_rate_tps": 42500,           // null if not a ramp
  "first_failing_stage": "queue",             // null if PASS
  "loss_attribution": {
    "offered": 12345678,
    "sut_kernel_drops": 0,
    "sut_queue_drops": 234,
    "sut_blocked": 12000,           // expected by config
    "sut_forward_failures": 0,
    "received_at_sink": 12333444,
    "duplicates": 0,
    "unexplained": 0
  },
  "streams": [ /* per-stream breakdown, same shape */ ],
  "destinations": [ /* per-destination */ ],
  "sut_snapshot": {
    "trapninja_version": "0.8.1",
    "capture_mode": "ebpf",
    "queue_wait_p99_ms_max": 340,
    "rss_growth_pct_per_min": 0.03
  },
  "timeline_ref": "timeline.jsonl",
  "sink_bottleneck": false
}
```

### `reporting/report_md.py`

Same content, rendered as markdown with:
- Header block (verdict, breaking point, scenario, versions)
- Loss attribution table
- Per-step verdicts table (for ramps)
- Timeline of injected events + failure detections
- Explicit "sink health" section — if `sink_bottleneck=true`, the report leads with it.

---

## Scenario File Schema

`scenarios/*.json`. Validated by `orchestrator/scenario.py` before any process is started.

```jsonc
{
  "$schema": "trapdojo-scenario-0.1",
  "name": "ramp-to-failure-ebpf",
  "description": "Ramp v2c load until first failure with eBPF capture.",
  "destructive": false,
  "lab_allowlist": ["trapninja-lab-a", "trapninja-lab-b"],

  "hosts": {
    "generator": ["gen-01"],
    "sink":      "sink-01",
    "sut_primary":   "trapninja-p",
    "sut_secondary": "trapninja-s"
  },

  "generator": {
    "target": "10.234.83.133",
    "port":   162,
    "workers": 8,
    "profile": {
      "type": "ramp",
      "start_rate": 5000,
      "end_rate":   80000,
      "step":       5000,
      "dwell_s":    60,
      "warmup_s":   30,
      "drain_s":    60
    },
    "sources": { "pool_size": 5000, "pool_cidr": "10.234.100.0/20" },
    "oid_mix_ref": "oid-mixes/fibre-cut.json",
    "version_mix": { "v1": 0, "v2c": 100, "v3": 0 },
    "malformed_pct": 0.0
  },

  "sink": {
    "listeners": [
      { "bind": "10.234.83.140:162",  "reuseport_workers": 1, "destination_label": "primary-noc" }
    ]
  },

  "sut": {
    "expected_capture_mode": "ebpf",
    "poll_interval_s": 5
  },

  "failure_criteria": {
    "loss_pct_max": 0.1,
    "unexplained_max": 0,
    "queue_wait_p99_ms_max": 1000,
    "rss_growth_pct_per_min_max": 5,
    "queue_saturation_stop_ramp": true
  },

  "actions": []       // R4+
}
```

Validation rules (fail-closed):
- All host aliases must resolve to entries in the deploy inventory.
- `destructive=true` requires `lab_allowlist` intersection with the deploy inventory's `lab` tag.
- `oid_mix_ref` and other paths must be relative to the scenario file and inside the scenarios directory (no `..`).
- No unknown top-level keys (strict).

---

## Report Schema

Defined by `report.json` above. Bumped via `report_schema_version` field (starts at `1`). The `--compare` reporter (R5) refuses to compare across major schema bumps.

---

## CLI Specification

Command registry pattern, mirroring TrapNinja. Root parser dispatches `trapdojo <verb> [noun] [flags]`.

```
trapdojo generate <flags>
    --target <ip> --port <int> --workers <int>
    --profile constant|ramp|burst|replay
    --rate | --start-rate/--end-rate/--step/--dwell
    --sources <int> --pool-cidr <cidr>
    --version-mix v1=…,v2c=…,v3=…
    --oid-mix <path>
    --run-id <str>
    --run-dir <path>                (default /var/lib/trapdojo/runs)
    [--manifest <path>]              (skip auto-manifest, use supplied one — orchestrator mode)

trapdojo sink <flags>
    --listen <ip:port>               (repeatable)
    --reuseport <int>                (per --listen)
    --run-id <str>
    --run-dir <path>
    --rcvbuf <bytes>                 (default 32M)

trapdojo orchestrate <flags>
    --scenario <path>
    --run-id <str>                   (default: auto-generated)
    --run-dir <path>
    [--dry-run]                      (validate + print action list, do not execute)

trapdojo report <flags>
    --run-id <str>
    --run-dir <path>
    [--compare <run-id>]             (R5)
    [--format json|md|both]          (default both)

trapdojo selfcheck <flags>
    --loopback | --to <ip:port>
    --workers <int> --duration <s>
    (Generator + sink on the same host or generator → sink; proves the rig itself)
```

---

## Configuration Files

R1 keeps configuration minimal. Everything about a *run* lives in the scenario file. Everything about a *host* lives in `~/.config/trapdojo/config.json`:

```jsonc
{
  "log_level": "INFO",
  "run_dir_default": "/var/lib/trapdojo/runs",
  "ssh": {
    "user": "trapdojo",
    "identity_file": "~/.ssh/trapdojo_ed25519",
    "control_persist_s": 60
  },
  "inventory": {
    "hosts": {
      "gen-01":       { "address": "10.234.90.11",  "tags": ["lab-a", "generator"] },
      "sink-01":      { "address": "10.234.90.20",  "tags": ["lab-a", "sink"] },
      "trapninja-p":  { "address": "10.234.83.133", "tags": ["lab-a", "sut"], "sudo": true },
      "trapninja-s":  { "address": "10.234.83.134", "tags": ["lab-a", "sut"], "sudo": true }
    }
  }
}
```

---

## Error Handling & Failure Modes

Follows TrapNinja's principle: **fail fast, log precisely, never proceed on ambiguous state**.

| Component | Failure | Response |
|---|---|---|
| Generator | `sendmmsg` returns error other than `EINTR`/`ENOBUFS`/`EAGAIN` | Worker exits with structured error; coordinator terminates run and marks manifest `aborted:true` |
| Generator | Raw socket refused (no `CAP_NET_RAW`) | Startup error; coordinator refuses to fork workers; suggests `alias` mode |
| Generator | uRPF blocks spoofed sources (no packets at sink within 2 s) | Auto-fallback to alias mode with annotation; warning in report |
| Sink | `recvmmsg` error | Listener exits; supervisor restarts once; second failure aborts run |
| Sink | `/proc/net/udp` drops observed | Continues collecting, but final report marks destination as `sink_bottleneck=true`, refuses PASS |
| Sink | Foreign packets on listener port | Counted separately, does not affect PASS/FAIL |
| Orchestrator | SSH failure to SUT | Poll interval marked missing; three consecutive failures abort the run |
| Orchestrator | Scenario schema invalid | Refuses to start; prints exact JSON pointer of first violation |
| Orchestrator | Destructive action without allowlist | Refuses to start (see Security section) |
| Reporter | Missing input file | Names the file and expected producer, exits non-zero |
| Reporter | `unexplained > 0` and scenario disallows it | Verdict = fail, `first_failing_stage = "unexplained"` |

No component uses bare `except:` or `except Exception: pass`. All swallowed exceptions are logged at WARNING or above with their type and message.

---

## Security & Safety Interlocks

The orchestrator can stop services and (later) inject `nft` rules on SUT hosts. Guardrails:

1. **Destructive flag.** Scenarios with any action in `{stop_primary, stop_redis, nft_*}` **must** carry `"destructive": true` at the top level. The scenario schema enforces this.
2. **Lab allowlist.** Every destructive scenario declares a `lab_allowlist` set. Each SUT host resolved from the scenario must carry at least one matching tag in the host inventory. Mismatch → refuse to start. A missing `lab_allowlist` in a destructive scenario → refuse to start.
3. **SSH least privilege.** The `trapdojo` SSH user on SUT hosts uses a sudoers entry restricted to the exact command strings in the action whitelist. No shell escape possible from the scenario file.
4. **No freeform commands.** The scenario names `action_type`; the injector maps to a hard-coded command. Adding an action requires code + review, not just scenario JSON.
5. **Dry run.** `trapdojo orchestrate --dry-run` prints every SSH invocation the run would perform, including action commands, without executing any of them.
6. **No credentials in logs.** SNMPv3 credentials never appear in generator output. Templates are constructed from a credentials file readable only by the `trapdojo` user; log lines reference credentials by name, never by material.

---

## Observability of the Rig Itself

The rig is under test-conditions-worth of pressure and must be introspectable:

- `trapdojo generate` writes `sent_by_second.jsonl` continuously and a summary on SIGTERM.
- `trapdojo sink` writes `sink_partial.jsonl` every 10 s and `sink_final.json` on stop.
- Both components expose a `--stats-port <int>` (optional) that serves a tiny HTTP endpoint returning current counters as JSON — useful for `curl` during a run, not scraped by anything by default.
- All processes log to stderr in a fixed key=value structured format; no rotation logic in R1 (systemd + journald handle it).

---

## Testing Strategy

`dev/tests/` mirrors TrapNinja layout. Two tiers:

**Unit (fast, no sockets):**
- `test_wire.py` — pack/unpack identity varbind, offset table correctness for every template shape.
- `test_gap_tracker.py` — insert/dup/finalize; property tests using `hypothesis` if available offline, else hand-rolled cases.
- `test_rate.py` — token bucket accuracy under simulated clocks.
- `test_profiles.py` — ramp/burst/replay produce expected rate schedules.
- `test_scenario.py` — schema validation accepts good files, rejects bad ones (one test per rule).
- `test_reconcile.py` — feeds synthetic manifest + counter files, asserts loss attribution math.

**Integration (localhost loopback):**
- `test_loopback_baseline.py` — generator → sink on 127.0.0.1, 1k tps × 10 s, asserts `received == sent` and `unexplained == 0`.
- `test_loopback_ramp.py` — ramp 1k → 10k, asserts monotonic sent and no gaps.
- `test_sink_drop_visibility.py` — deliberately undersized `SO_RCVBUF`, asserts `sink_bottleneck` is flagged.
- `test_orchestrator_dry_run.py` — dry-run of every shipped scenario produces the expected action list.

**Not tested in R1:**
- Real SSH, real SUT, real Redis. Those are R2 targets and require a lab.

---

## Performance Budgets & Validation

Budgets validated by `trapdojo selfcheck` before any SUT conclusions are trusted:

| Component | Metric | Target |
|---|---|---|
| Generator | Per-worker send rate (128-batch sendmmsg, 200-byte packets, loopback) | ≥ 30k tps |
| Generator | Aggregate send rate, 8 workers, loopback | ≥ 100k tps |
| Generator | Steady-state RSS growth | 0 (post warm-up) |
| Sink | Per-listener recv rate (recvmmsg-64, single process, loopback) | ≥ 120k tps |
| Sink | End-to-end `unexplained` in loopback selfcheck | 0 |
| Sink | Own kernel drops in loopback selfcheck at 100k tps | 0 |
| Orchestrator | SUT poll overhead (SSH multiplex + parse) | < 100 ms per poll |

Selfcheck must PASS on the actual lab hardware **before** the R2 exit criterion (`ramp-to-failure` produces a defensible breaking point) is claimed.

---

## Deferred to R2+

- **Multi-listener sink with stream-pinning MPMC ring** (R2 if single-listener ceiling < 100k tps).
- **Multi-generator-host coordination** — the manifest already partitions by `stream_id`; the coordination is orchestrator-side (start N generators, disjoint stream ranges).
- **Action injector for destructive scenarios** (R4).
- **SNMPv3 templates and rate ceiling exploration** (R5, gated by open question 5).
- **`--compare` regression report** (R5).
- **Ansible role fleshed out** (R4 alongside destructive scenarios, so lab allowlists are provisioned as part of the deploy).

---

## Open Design Questions

Carried forward from HLD; each must be resolved before its dependent phase begins:

1. **Enterprise OID arc for the identity varbind.** Placeholder `.1.3.6.1.4.1.99999.1.1` is not registered. Decision needed before code freeze — either register or pick an arc already reserved for lab use.
2. **Hand-rolled BER encoder vs pysnmp for template construction.** Hand-rolled is proposed here for byte control and zero pysnmp import cost. Reviewer to confirm before implementation.
3. **`multiprocessing.shared_memory` availability.** Python 3.9 has it. Confirm it works under RHEL 8's kernel/glibc without surprises for the sink's shared counter table — fall back to `mmap`+`struct` if not.
4. **SNMPv3 template pre-encryption vs per-packet encryption.** HLD flagged as largest open question. R5 detailed design will pick a lane; R1–R4 do not depend on it.
5. **Sink stream-pinning strategy.** Whether the R2 multi-listener design uses in-kernel `SO_ATTACH_REUSEPORT_CBPF` (BPF program hashing `stream_id` bytes to a fixed listener index) or userspace re-queue. eBPF path is faster but has a higher implementation cost and RHEL 8 kernel-version caveats.

---

*Next step: review this LLD, resolve open questions 1 and 2, then produce the R1 implementation prompt for `core/` + `generator/` + `sink/` + `selfcheck`.*
