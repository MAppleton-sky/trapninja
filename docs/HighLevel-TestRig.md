# TrapDojo — High Level Design: TrapNinja Load Test Rig

**Status:** Draft for review
**Version:** 0.1
**Last Updated:** July 2026
**Working name:** TrapDojo (placeholder — where a ninja trains; rename freely)

---

## Table of Contents

- [Purpose & Goals](#purpose--goals)
- [Relationship to the Existing Load-Test Initiative](#relationship-to-the-existing-load-test-initiative)
- [Scope & Non-Goals](#scope--non-goals)
- [Test Topology](#test-topology)
- [Core Design Principle: Closed-Loop Loss Accounting](#core-design-principle-closed-loop-loss-accounting)
- [Component 1: Trap Generator](#component-1-trap-generator)
- [Component 2: Trap Sink / Verifier](#component-2-trap-sink--verifier)
- [Component 3: Orchestrator & Reporter](#component-3-orchestrator--reporter)
- [Sequence-Tagged Trap Format](#sequence-tagged-trap-format)
- [Loss Accounting & Reconciliation Model](#loss-accounting--reconciliation-model)
- [Failure Criteria (Defining "the Breaking Point")](#failure-criteria-defining-the-breaking-point)
- [Test Scenarios](#test-scenarios)
- [TrapNinja-Side Requirements](#trapninja-side-requirements)
- [Technology Constraints & Generator Performance Strategy](#technology-constraints--generator-performance-strategy)
- [Deployment Model](#deployment-model)
- [Proposed Repository Structure](#proposed-repository-structure)
- [Build Phasing](#build-phasing)
- [Risks & Open Questions](#risks--open-questions)

---

## Purpose & Goals

TrapDojo is a **standalone product** that load-tests TrapNinja as a black box over the network, exactly as production network elements would. Its goals:

1. **Find the breaking point.** Ramp offered trap load until TrapNinja begins to fail, and identify *which* stage fails first (kernel socket buffer, packet queue, worker pool, forwarder).
2. **Establish throughput thresholds.** Produce defensible numbers per capture mode (eBPF / socket / sniff) for: maximum sustained rate with zero loss, maximum burst absorption, and recovery time after a burst.
3. **Prove production readiness.** Demonstrate the headline claims (10k+ sustained, 100k burst, <3s failover, zero trap loss) with evidence, not assertion — including under HA failover, SNMPv3 decryption load, and Redis outage conditions.
4. **Make results repeatable.** Every run is a scripted scenario with a machine-readable report, so regressions between TrapNinja versions are detectable ("v0.8.x sustained 42k tps zero-loss; v0.9.0 sustained 44k").

## Relationship to the Existing Load-Test Initiative

The load-test initiative was planned as five phases. This HLD supersedes and absorbs the external phases:

| Original Phase | Status | Disposition under this HLD |
|---|---|---|
| 1 — Pipeline timing & visibility instrumentation | **Implemented in TrapNinja** | Prerequisite — TrapDojo consumes its output (latency percentiles, socket/eBPF drop counters, resource telemetry, `trapninja metrics show`) |
| 2 — In-process synthetic injector | Designed, not built | **Out of scope for TrapDojo.** Remains an optional TrapNinja micro-benchmark tool; it bypasses capture and cannot prove end-to-end throughput |
| 3 — External network-level trap generator | Designed, not built | **Becomes TrapDojo Generator** |
| 4 — Ramp / failure-detection orchestrator | Designed, not built | **Becomes TrapDojo Orchestrator** |
| 5 — Burst / HA-failover scenarios | Designed, not built | **Becomes TrapDojo scenario library** |

The key addition beyond the original phase plan is the **Trap Sink** (Component 2). Without an independent receiver counting what TrapNinja actually forwards, "zero trap loss" cannot be proven — TrapNinja's own counters could be wrong in exactly the ways we are testing for.

## Scope & Non-Goals

**In scope:**
- SNMPv1/v2c/v3 trap generation at line rate, from many simulated source IPs
- End-to-end delivery verification with per-trap sequence accounting
- Scenario orchestration, failure detection, and reporting
- Driving TrapNinja HA failover and dependency-failure scenarios

**Non-goals:**
- Not a general SNMP tester (no GET/SET/walk, no MIB compilation at runtime)
- Not a monitoring product — it runs for the duration of a test and stops
- Does not modify TrapNinja's forwarding behaviour in any way; TrapNinja under test is a standard production build with standard configs
- Does not attempt microsecond-precision one-way latency measurement across hosts (requires PTP; see Risks)

## Test Topology

```
┌────────────────────┐         ┌──────────────────────────┐         ┌────────────────────┐
│  GENERATOR HOST(S) │  UDP    │   SYSTEM UNDER TEST      │  UDP    │    SINK HOST       │
│                    │  :162   │                          │ :162    │                    │
│  trapdojo generate ├────────►│  TrapNinja PRIMARY       ├────────►│  trapdojo sink     │
│  (1..N processes,  │         │  TrapNinja SECONDARY     │         │  (per-destination  │
│  M spoofed src IPs)│         │  (standard HA pair,      │         │   listeners,       │
│                    │         │   Redis, prod configs)   │         │   seq verification)│
└─────────┬──────────┘         └────────────┬─────────────┘         └─────────┬──────────┘
          │                                 │  .prom / metrics show --json    │
          │                                 ▼                                 │
          │                    ┌──────────────────────────┐                   │
          └───────────────────►│  ORCHESTRATOR            │◄──────────────────┘
              run control /    │  trapdojo orchestrate    │    run control /
              counters         │  (scenario driver,       │    counters
                               │   metric collection,     │
                               │   failure detection,     │
                               │   report generation)     │
                               └──────────────────────────┘
```

**Placement rules (non-negotiable for valid results):**

- Generator and Sink must **not** run on the SUT hosts. CPU contention from the generator would invalidate every measurement. Sink and Generator may share a host at lower rates, but at ≥50k tps they should be separate.
- The Orchestrator is lightweight and can run on the sink host or a fourth box.
- Network path between generator and SUT should be ≥1 Gbps (a 200-byte trap at 100k tps is ~160 Mbps; leave headroom for bursts) and, ideally, a switch — not a router doing its own policing.
- The sink's destination IPs/ports are configured in TrapNinja's `destinations.json` exactly like a real NOC destination. TrapNinja needs no test-specific code path.

## Core Design Principle: Closed-Loop Loss Accounting

Every generated trap carries a **(run_id, stream_id, sequence_number)** identity. The Generator knows exactly what it sent; the Sink knows exactly what arrived; TrapNinja's Phase 1 instrumentation explains what happened in between. A run is only trusted when the books balance:

```
sent = kernel_drops + queue_drops + blocked + forward_failures + received_at_sink + unexplained
```

`unexplained` is itself a first-class result. A breaking point where `unexplained > 0` is a **worse** finding than one where all loss is attributed — it means an invisible drop path exists, which violates the "no silent trap loss" pillar and must be chased down before production sign-off.

## Component 1: Trap Generator

**Role:** Sustain an exact, controllable offered load of well-formed SNMP traps toward the SUT.

**Key capabilities:**

| Capability | Design approach |
|---|---|
| Rate control | Token-bucket per worker process; target rate divided across processes. Accuracy target: ±2% of requested rate at steady state |
| Rate profiles | `constant`, `ramp` (start/end/step/dwell), `burst` (baseline + spike amplitude/duration/repeat), `replay` (rate series from file) |
| Packet efficiency | Traps are **pre-encoded byte templates** built once at startup (SNMPv2c fast, SNMPv3 encrypted templates pre-computed per credential). The hot loop only patches the sequence-number bytes at a fixed offset and calls send — zero per-packet ASN.1 encoding |
| Batched send | `sendmmsg(2)` via `ctypes` (RHEL 8/9, Python 3.9 stdlib has no binding) to send 64–512 packets per syscall. Fallback: plain `sendto` loop |
| Multi-source simulation | Raw socket with `IP_HDRINCL` and spoofed source IPs (mirrors TrapNinja's own forwarding technique), cycling through a configurable pool (e.g. 5,000 addresses) so per-IP stats, LRU bounds, and filtering behave as they would with a real estate. Fallback: secondary IP aliases on the generator NIC when spoofing is blocked by network policy |
| Trap realism | Configurable OID pools (weighted mix, e.g. linkDown-heavy to simulate a fibre cut), varbind payload size distribution, SNMPv1/v2c/v3 mix ratios, and deliberately malformed packets at a configurable percentage (parser slow-path and robustness exercise) |
| Multi-process scaling | One Python process realistically sustains ~30–60k small-packet sends/sec even with `sendmmsg`; the generator is therefore a coordinator that forks N send workers, each owning a stream_id and its own sequence space |
| Accounting | Each worker records `sent` per second (post-syscall success), flushed to a run manifest the Orchestrator collects. Send-side `ENOBUFS`/`EAGAIN` are counted separately — traps never offered to the wire must not be blamed on TrapNinja |

**CLI sketch:**

```
trapdojo generate --target 10.234.83.133 --port 162 \
    --profile ramp --start-rate 5000 --end-rate 80000 --step 5000 --dwell 60 \
    --sources 5000 --oid-mix fibre-cut.json --version-mix v2c=90,v3=10 \
    --run-id 2026-07-21-ramp-01
```

## Component 2: Trap Sink / Verifier

**Role:** Independently prove what TrapNinja actually delivered.

**Key capabilities:**

| Capability | Design approach |
|---|---|
| Listeners | One UDP listener per configured TrapNinja destination (IP:port), each registered in the SUT's `destinations.json`. Supports multiple destinations to test fan-out and redirection routing |
| Faster than the SUT | The sink must never be the bottleneck. It does **no SNMP parsing** on the hot path: it extracts `(run_id, stream_id, seq)` from a fixed byte offset (guaranteed by the template format), increments counters, and optionally records arrival time into a ring buffer. Large `SO_RCVBUF`, multiple listener processes with `SO_REUSEPORT` |
| Own drop visibility | The sink monitors its own `/proc/net/udp` drop counters (same technique as TrapNinja Phase 1 B1). Sink-side kernel drops invalidate a run and are reported as such — never silently folded into "TrapNinja lost it" |
| Sequence verification | Per (stream_id, destination): received count, duplicate count, gap list (missing sequence ranges). Gap ranges are the primary loss evidence and also localise loss in time when correlated with the rate profile |
| Duplicate detection | Duplicates matter for failover-replay scenarios (replay may legitimately re-send; the report must distinguish "lost", "delivered once", "delivered ≥ twice") |
| Latency (coarse) | Optional: generator embeds a send timestamp; sink computes one-way delay. Only meaningful when generator and sink share a host or are NTP/PTP-disciplined — reported with an explicit accuracy caveat (see Risks) |
| Memory bounds | Gap tracking uses interval sets (ranges), not per-sequence bitmaps, so a 100M-trap soak run stays bounded |

**CLI sketch:**

```
trapdojo sink --listen 10.234.83.140:162 --listen 10.234.83.140:1162 \
    --run-id 2026-07-21-ramp-01 --report-dir /var/lib/trapdojo/runs
```

## Component 3: Orchestrator & Reporter

**Role:** Turn generator + sink + TrapNinja metrics into a scripted experiment with a verdict.

**Responsibilities:**

1. **Scenario execution.** Reads a scenario file (JSON, consistent with TrapNinja config style), starts sink, starts generator(s) with the scenario's rate profile, and manages run lifecycle (warm-up, measurement window, cool-down/drain, teardown).
2. **SUT metric collection.** Polls TrapNinja during the run via, in preference order: the node-exporter `.prom` files (scraped over SSH or a shared path), or `trapninja metrics show --json` over SSH. Collects: received/forwarded/blocked/failure counters, queue depth, pipeline timing percentiles, socket/eBPF drop counters, RSS/FD telemetry, HA state.
3. **SUT action injection.** For failure scenarios, executes controlled actions over SSH: `trapninja ha force-failover`, `systemctl stop trapninja` on PRIMARY, `systemctl stop redis`, `nft` rule insertion to black-hole the peer (split-brain), etc. All actions and their timestamps land in the run timeline.
4. **Failure detection.** During ramp scenarios, evaluates the failure criteria (next section) at each dwell step and stops the ramp at first sustained breach — the breaking point is a first-class output, not something read off a graph afterwards.
5. **Reconciliation & reporting.** After drain, runs the loss-accounting equation per stream and destination, and emits:
   - `report.json` — machine-readable, for regression comparison between TrapNinja versions
   - `report.md` — human-readable summary: breaking point, loss attribution table, latency percentiles vs offered rate, resource curves, timeline of injected events, and a PASS/FAIL verdict against the scenario's stated criteria

**CLI sketch:**

```
trapdojo orchestrate --scenario scenarios/ramp-to-failure-ebpf.json
trapdojo report --run-id 2026-07-21-ramp-01 [--compare 2026-06-30-ramp-04]
```

## Sequence-Tagged Trap Format

Generated traps are fully valid SNMP traps that any receiver would accept, with the test identity carried in a dedicated varbind:

- A reserved OID under a private enterprise arc (e.g. `.1.3.6.1.4.1.99999.1.1`) whose value is a fixed-length OCTET STRING: `run_id (8 bytes) | stream_id (4 bytes) | seq (8 bytes) | send_ts (8 bytes, optional)`.
- Because templates are pre-encoded with fixed-length fields, this varbind sits at a **known byte offset per template**, letting both the generator (patch) and sink (extract) touch it without ASN.1 work. The sink receives the offset table in the run manifest.
- The remaining varbinds are realistic (sysUpTime, snmpTrapOID, vendor-style payload varbinds) so TrapNinja's parser, filters, per-OID stats, and redirection rules exercise their production code paths.
- For SNMPv3 scenarios the identity varbind is inside the encrypted scopedPDU; the sink extracts it from TrapNinja's **decrypted v2c output**, which simultaneously verifies the decryption path end-to-end.

## Loss Accounting & Reconciliation Model

Loss can occur at seven places. Each has an owner and a counter:

| # | Stage | Evidence source | Owner |
|---|---|---|---|
| 1 | Generator send failure | Generator `ENOBUFS`/`EAGAIN` counters | Rig (excluded from offered load) |
| 2 | Network / NIC | Switch counters (manual), inferred as `unexplained` otherwise | Environment |
| 3 | SUT kernel socket buffer | `trapninja_socket_drops_total` (Phase 1 B1) / eBPF lost samples (Phase 1 B2) | TrapNinja visibility |
| 4 | packet_queue full | Queue drop counters (`QueueStats`) | TrapNinja |
| 5 | Filtering (deliberate) | `blocked` counters — scenario-dependent expected value | TrapNinja (by design) |
| 6 | Forwarder send failure | `trapninja_dest_failures_total{reason=...}` (forward-failure metrics fix) | TrapNinja |
| 7 | Sink kernel buffer | Sink's own `/proc/net/udp` monitor | Rig (invalidates the run) |

The report attributes every missing sequence to a stage where possible. Time-correlation (gap ranges vs metric deltas per collection interval) localises loss even when counters are aggregate.

## Failure Criteria (Defining "the Breaking Point")

A dwell step **fails** — and the ramp stops — when any of the following holds for the whole measurement window at that step:

| Criterion | Default threshold | Rationale |
|---|---|---|
| End-to-end loss | > 0 traps unaccounted-for, or > 0.1% total loss | "Every alarm matters"; 0.1% matches the stated drop-rate target |
| Queue saturation | Queue depth monotonically increasing across the window | Depth that never drains means the worker pool is beyond capacity even if the 200k buffer hasn't overflowed *yet* |
| Latency | `queue_wait p99` > 1s sustained | An alarm delayed multiple seconds under sustained (non-burst) load is operationally degraded |
| Resource runaway | RSS growth > configurable %/min, or FD count climbing | Predicts failure beyond the window; also catches leaks under load |
| Process health | Worker/service crash, HA state flap | Immediate fail |

Burst scenarios use different criteria: transient queue growth and elevated latency are *expected*; the pass conditions are zero loss, full queue drain within a recovery-time budget, and return of p99 to baseline.

All thresholds live in the scenario file, not in code (configuration over code changes).

## Test Scenarios

| Scenario | Shape | Proves |
|---|---|---|
| `baseline` | 1k tps constant, 10 min | Rig sanity: zero loss, books balance, accounting works |
| `ramp-to-failure` | Ramp per capture mode (eBPF / socket / sniff) | Per-mode maximum sustained zero-loss rate; first failing stage |
| `sustained-soak` | 80% of found max, 8–24 h | Leak detection, counter stability, `.prom` export stability |
| `fibre-cut-burst` | 5k baseline + 100k spike for 30–60 s, repeated | Burst absorption, queue drain, recovery time (the headline production claim) |
| `ha-failover-under-load` | Sustained load + forced failover / PRIMARY kill | <3s failover, gap detection, failover replay correctness (lost vs duplicated accounting) |
| `redis-outage` | Sustained load + Redis stop/start | Graceful degradation: forwarding unaffected, cache recovers |
| `snmpv3-load` | Ramp with high v3 ratio | Decryption throughput cost; correct decrypt-and-convert at rate |
| `filter-heavy` | Ramp with large blocked/redirect config loaded | Config-scale impact on the hot path |
| `malformed-mix` | Sustained load + 1–5% malformed packets | Slow-path resilience; no worker stalls; malformed counted, not silently eaten |
| `many-sources` | Ramp with 50k+ distinct source IPs | GranularStats LRU behaviour and memory bounds at estate scale |

## TrapNinja-Side Requirements

The design deliberately requires **no test-specific code in TrapNinja** — the SUT is a production build. What it does require is complete observability, most of which exists:

| Requirement | Status |
|---|---|
| Pipeline latency percentiles (queue_wait, processing) | ✅ Phase 1 Part A — implemented |
| Kernel socket drop visibility (`/proc/net/udp`) | ✅ Phase 1 Part B1 — implemented |
| eBPF perf-buffer lost-sample counter | ✅ Phase 1 Part B2 — implemented |
| Resource telemetry (RSS, FDs, GC) | ✅ Phase 1 Part C — implemented |
| `trapninja metrics show` (JSON) for orchestrator polling | ✅ Implemented |
| **Forward-failure metrics** (`trapninja_dest_failures_total` with `reason` label; forwarded counter honouring `forward_packet()` return) | ⚠️ **Prerequisite.** Prompt exists (`.github/prompts/trapninja-forward-failure-metrics.prompt.md`) but must be implemented and released before any rig run is trusted — otherwise stage 6 loss is invisible and every failed forward pollutes `unexplained` |
| Queue drop counters exposed in metrics export | Verify: `QueueStats` drops must appear in the `.prom` export, not only in `daemon queue-stats` |
| Counter reset or run-delta capability | Preferred approach: orchestrator computes **deltas** between snapshots rather than requiring resets — no TrapNinja change needed, and it works against a long-running production-like process. `stats reset` remains available but is not relied upon |

One candidate enhancement (optional, decide at detailed design): a `trapninja metrics snapshot --json` that atomically dumps all counters in one call, if it turns out the unified export interval (and split-snapshot risk between `.prom` files and CLI reads) makes delta computation noisy at short dwell windows. The unified-timer work may already make this unnecessary — verify before building anything.

## Technology Constraints & Generator Performance Strategy

- **Python 3.9, RHEL 8/9, air-gapped** — same constraints as TrapNinja. Dependencies bundled via the existing `download-packages.sh` / `install-packages.sh` pattern.
- **Stdlib-first.** The hot paths (generator send loop, sink receive loop) are stdlib + `ctypes` (`sendmmsg`/`recvmmsg`). Scapy/pysnmp are used only **offline at startup** for template construction and are lazy-imported (import-cost awareness), never in the send/receive loop.
- **Throughput budget.** Per-process targets to validate in rig Phase 1: ≥30k tps send per worker with `sendmmsg`, linear scaling to 4–8 workers → 100k+ tps aggregate from one generator host. If a single host cannot reach the target against the SUT, the orchestrator supports multiple generator hosts, each owning disjoint stream_ids (the accounting model is already per-stream, so this is additive, not a redesign).
- **Escape hatch.** If Python cannot reach the required rate on available hardware, the template-based design degrades gracefully to pcap generation + `tcpreplay` for raw-rate scenarios, with the sink and accounting unchanged (sequence numbers pre-baked into the pcap). This is a documented fallback, not the primary path — it sacrifices dynamic rate profiles.

## Deployment Model

- **Separate git repository** (standalone product), mirroring TrapNinja conventions: `src/` layout, `dev/`, `docs/`, `ansible/`, `config.example/`.
- **Ansible role** deploys `trapdojo` to designated generator/sink hosts (never to SUT hosts) and templates host-role config (generator vs sink vs orchestrator).
- **Privileges:** generator needs `CAP_NET_RAW` (spoofed sources); sink needs to bind its ports and read its own `/proc/net/udp`; orchestrator needs SSH access to SUT hosts for metric collection and action injection. Least privilege per role — the orchestrator's SSH account should be limited (command-restricted key or sudo whitelist) since it can stop services.
- **Safety interlock:** the orchestrator refuses to run destructive scenarios (service stop, nft injection) unless the scenario file carries an explicit `"destructive": true` flag *and* the target hosts match a configured lab allowlist. Pointing a ramp-to-failure at a production HA pair by typo must be structurally impossible.

## Proposed Repository Structure

```
trapdojo/
├── src/
│   ├── trapdojo.py                 # Entry point
│   ├── VERSION
│   └── trapdojo/
│       ├── generator/              # Template builder, send workers, rate control
│       ├── sink/                   # Listeners, seq/gap tracking, drop monitor
│       ├── orchestrator/           # Scenario runner, SUT collector, action injector
│       ├── reporting/              # Reconciliation, report.json / report.md
│       ├── cli/                    # Subcommand structure (registry pattern, as TrapNinja)
│       └── core/                   # Trap templates, run manifest, constants
├── scenarios/                      # Scenario definition files (JSON)
├── config.example/
├── ansible/
├── dev/tests/
└── docs/
```

## Build Phasing

| Rig Phase | Deliverable | Exit criteria |
|---|---|---|
| R1 | Generator (v2c only, constant + ramp profiles) + Sink + manual runs | `baseline` scenario passes: books balance at 5k tps for 10 min, rig-side loss = 0 |
| R2 | Orchestrator (scenario runner, SUT metric collection, reconciliation report) | `ramp-to-failure` produces a breaking point + attributed loss table automatically |
| R3 | Burst profiles, multi-source spoofing at scale, malformed mix | `fibre-cut-burst` and `many-sources` runnable |
| R4 | Action injection (failover, Redis outage) + destructive-scenario interlock | `ha-failover-under-load` and `redis-outage` produce PASS/FAIL verdicts |
| R5 | SNMPv3 templates, soak tooling, report comparison (`--compare`) | Full scenario matrix runnable; version-to-version regression report |

TrapNinja prerequisite before R2 results are trusted: the forward-failure metrics fix, plus verification that queue drops are in the `.prom` export.

## Risks & Open Questions

1. **Python send-rate ceiling.** The 100k tps aggregate target from one host is plausible with `sendmmsg` + multi-process but unproven on the actual lab hardware. R1 includes a generator self-benchmark (send to a null sink) before any SUT conclusions are drawn. Mitigations: multi-host generation, tcpreplay fallback.
2. **Source-IP spoofing may be blocked** by lab network uRPF/anti-spoofing. Fallback (NIC IP aliases) caps the distinct-source count lower; confirm lab network policy early.
3. **One-way latency accuracy.** Without PTP, cross-host generator→sink timestamps are only NTP-accurate (ms-level). The design treats cross-host latency as indicative and relies on TrapNinja's internal (same-clock) pipeline percentiles for precise stage timing. Decide whether PTP in the lab is worth it.
4. **Metrics polling granularity.** The unified export interval bounds how finely loss can be time-localised. Short dwell steps may need the optional `metrics snapshot` command — defer until R2 shows whether it's needed.
5. **SNMPv3 template pre-encryption** assumes per-credential deterministic-enough construction to patch sequence bytes post-encryption — it is not (CBC/CFB diffusion). v3 traps will therefore need per-packet encryption in the send loop, which will be slower; the v3 scenario's rate targets must be set accordingly, or v3 identity moves to an unencrypted correlation method. **This is the largest open design question for detailed design.**
6. **Sink as hidden bottleneck.** Mitigated by design (no parsing, `SO_REUSEPORT`, own drop monitor), but R1 must include a sink self-benchmark proving it sustains > the maximum rate any scenario will offer.

---

*Next step: review this HLD, resolve open questions 2 and 5, then produce the R1 detailed design / implementation prompt for the Generator and Sink.*
