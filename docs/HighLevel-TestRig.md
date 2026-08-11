# TrapDojo — High Level Design: TrapNinja Load Test Rig

**Status:** Draft for review (post design-review v0.2)
**Version:** 0.2
**Last Updated:** August 2026
**Working name:** TrapDojo (placeholder — where a ninja trains; rename freely)
**Companion:** [LowLevel-TestRig.md](LowLevel-TestRig.md)
**Supersedes:** HLD v0.1

> **New to TrapDojo?** Start with the plain-language [Overview](Overview-TestRig.md) — designed to be read in ten minutes, no engineering background required. Come back here for design decisions and rationale.

> **Design-review status.** This HLD reflects the v0.2 design after the loss-accounting, sequence-semantics, sink-safety, clock-model, and phase-gate corrections. The full change summary, decision log, and traceability table live in the [LLD](LowLevel-TestRig.md#change-summary-v01--v02).

**Key structural changes from v0.1:**

- Single loss equation replaced by **two related models**: *input accounting* (per generated input) and *delivery-obligation accounting* (per unique `(run_token, generator_id, stream_id, epoch_id, seq, destination)` obligation).
- Every attributed loss carries an explicit **confidence level** (`proven | aggregate_accounted | temporally_correlated | unexplained`). Aggregate SUT counters can never be presented as per-sequence attribution.
- Wire identity redesigned around a **128-bit random run token** plus an **`epoch_id`** so warm-up cannot pollute measurement and settlement is well-defined.
- Generator maintains a **successful-sequence ledger**; partial `sendmmsg()` retries with the same sequence numbers; abandoned ranges are recorded, not silently skipped.
- Sink extraction is **length-safe**; identity is validated against magic **and** run token **and** known generator/stream ids **and** OID and bounds.
- Verdict model is **`PASS | FAIL | INVALID | ABORTED`**. Rig failures, sink drops, generator underachievement, and clock uncertainty produce `INVALID` — never a TrapNinja `FAIL`.
- **R0 accounting-proof phase added** before R1 implementation. R1 is narrowed to v2c generator + single-process sink + selfcheck. v3 is blocked until R5.

---

## Table of Contents

- [Purpose & Goals](#purpose--goals)
- [Terminology](#terminology)
- [Relationship to the Existing Load-Test Initiative](#relationship-to-the-existing-load-test-initiative)
- [Scope & Non-Goals](#scope--non-goals)
- [Test Topology](#test-topology)
- [Core Design Principle: Closed-Loop Loss Accounting](#core-design-principle-closed-loop-loss-accounting)
- [Component 1: Trap Generator](#component-1-trap-generator)
- [Component 2: Trap Sink / Verifier](#component-2-trap-sink--verifier)
- [Component 3: Orchestrator & Reporter](#component-3-orchestrator--reporter)
- [Sequence-Tagged Trap Format](#sequence-tagged-trap-format)
- [Loss Accounting & Reconciliation Model](#loss-accounting--reconciliation-model)
- [Failure Criteria (Defining "the Breaking Point")](#verdict-model--failure-criteria)
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

## Terminology

These terms are used throughout both this HLD and the LLD.

| Term | Meaning |
|---|---|
| **SUT** | **System Under Test.** The thing being load-tested. For TrapDojo, the SUT is the TrapNinja HA pair (primary + secondary) plus its Redis and any dependencies. TrapDojo never runs on SUT hosts. |
| **Rig** | TrapDojo itself — generator + sink + orchestrator + reporter. "Rig-side" faults are TrapDojo's problem; "SUT-side" faults are TrapNinja's problem. |
| **Generator** | The TrapDojo component that produces SNMP traps at a controlled offered rate. |
| **Sink** | The TrapDojo component that receives traps forwarded by TrapNinja and independently verifies what arrived. |
| **Orchestrator** | The TrapDojo component that drives a scenario end-to-end, polls SUT metrics, and produces the run's verdict. |
| **Reporter** | The TrapDojo component that reconciles evidence into `report.json` and `report.md`. |
| **NOC** | **Network Operations Centre.** The production destination TrapNinja normally forwards traps to. In TrapDojo runs, the sink stands in for a NOC. |
| **Offered rate** | Traps per second the generator successfully hands to the kernel (post-`sendmmsg` acceptance). Not the same as configured target rate. |
| **Delivery obligation** | A unique `(run_token, generator_id, stream_id, epoch_id, seq, destination)` tuple that the frozen TrapNinja config says should be delivered. |
| **Epoch** | A distinct measurement phase of a run (probe, warmup, dwell step, burst, recovery, cooldown). Every generated trap carries its `epoch_id` on the wire. |
| **Settlement barrier** | End-of-epoch wait for all in-flight traps to arrive (or timeout) before evaluating loss for that epoch. |
| **Verdict** | `PASS \| FAIL \| INVALID \| ABORTED` with a `scope` of `sut`, `rig`, `environment`, or `evidence`. Rig or environment problems never render as a SUT `FAIL`. |

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
- SNMPv2c trap generation at line rate, from many simulated source IPs (SNMPv1 R3; **SNMPv3 blocked until R5 contract**)
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
- **Runtime independence.** Generator, sink, and orchestrator each run as either a container (default) or a bare-metal process; the runtime is recorded per host in the manifest, and comparison across runtime types is refused. See [LLD § Containerised Deployment](LowLevel-TestRig.md#containerised-deployment).

## Core Design Principle: Closed-Loop Loss Accounting

Every generated trap carries a wire identity of `(wire_version, run_token, generator_id, stream_id, epoch_id, seq)` at a fixed offset. The generator knows exactly which sequences the kernel accepted (its **successful-sequence ledger**); the sink knows exactly which arrived (validated against the ledger); TrapNinja's Phase 1 instrumentation explains what happened in between.

A run's books balance only when both of two related models balance:

### Model A — Input accounting (per stream, per epoch)

```
G_offered  =  I_kernel_lost  +  I_queue_lost  +  I_parse_rejected
           +  I_blocked      +  I_accepted_for_forwarding
           +  I_unexplained
```

Accounts for what happened to every input that TrapNinja could observe. Uses generator ledger (`G_offered`) and TrapNinja aggregate counters. `I_unexplained` is a first-class result.

### Model B — Delivery-obligation accounting (per obligation)

For every unique tuple `(run_token, generator_id, stream_id, epoch_id, seq, destination)`, derived from the **frozen** TrapNinja forwarding/filter/redirection config:

```
obligations = delivered_exactly_once     +  delivered_multiple_times
            + missing                    +  not_expected_filtered
            + not_expected_redirected_away
            + destination_forward_failure  (aggregate, temporally correlated)
            + unexplained
```

Accounts for what actually reached each destination that was supposed to receive it.

### Rules

- Global SUT counters can support **aggregate** attribution across an epoch. They cannot bind a specific sequence to a specific stage.
- A duplicate never compensates for a missing sequence. Six precise duplicate/missing counters replace the ambiguous "duplicates" of v0.1 (defined in the [LLD](LowLevel-TestRig.md#duplicate-semantics)).
- Every attributed loss row carries a **confidence** level: `proven`, `aggregate_accounted`, `temporally_correlated`, or `unexplained`. Temporal correlation is never rendered as per-sequence attribution.
- Both models are evaluated **per epoch, after settlement** — a dwell is never declared lossy merely because packets remain queued at wall-clock end of dwell.

An `unexplained` value in either model is worse than an attributed value at the same threshold — it means an invisible drop path exists, which violates the "no silent trap loss" pillar and must be chased down before production sign-off.

## Component 1: Trap Generator

**Role:** Sustain an exact, controllable offered load of well-formed SNMP traps toward the SUT, with a byte-exact record of which sequences the kernel actually accepted.

**Key capabilities:**

| Capability | Design approach |
|---|---|
| Rate control | Absolute-monotonic-deadline pacer per worker (no cumulative sleep drift). Records requested vs achieved offered rate; breaking-point analysis uses **achieved offered rate**, not the configured target |
| Rate profiles | `constant`, `ramp`, `burst`, `replay`, all carrying an explicit `epoch_id` on the wire at every phase boundary |
| Packet efficiency | Traps are **pre-encoded byte templates** built once at startup (v2c only in R1). The hot loop patches only the mutable identity fields (`epoch_id`, `seq`, optional `send_ts`) at a fixed offset. Zero-allocation on the hot path is a measured optimisation target, not a guarantee |
| Batched send | `sendmmsg(2)` via `ctypes`; fallback to `sendto` loop is recorded in the manifest, not silent |
| Partial-send correctness | On partial `sendmmsg()` acceptance, the worker **retains the unsent tail with the same sequence numbers** and retries. Only kernel-accepted sequences enter the ledger. Ranges abandoned after `abandon_after_retries` are recorded as rig-side send failures, not blamed on TrapNinja |
| Successful-sequence ledger | Per-worker, per-stream, per-epoch record of exactly which sequences the kernel accepted and which were abandoned. This ledger — not `[1, max_seq]` — is the source of truth for what the sink should have received |
| Multi-source simulation | Raw socket with `IP_HDRINCL` and spoofed source IPs from a scenario-declared pool. **Fallback is opt-in only:** if the probe fails and `allow_source_mode_fallback: false`, the run aborts with `ABORTED` and no silent switch. When fallback is allowed, effective mode and source count are recorded prominently |
| Trap realism | Configurable OID pools (weighted mix, e.g. linkDown-heavy to simulate a fibre cut), varbind payload size distribution, SNMP version mix (v2c in R1; v1 R3; v3 blocked until R5), and malformed traffic with declared classes and expected TrapNinja counter reactions |
| Multi-process scaling | Coordinator forks N send workers, each owning one `stream_id` under a per-host `generator_id`. Sequence spaces never overlap between workers, epochs, or hosts |
| Accounting | Each worker records ledger updates and achieved-rate statistics (requested vs achieved, pacing lateness p99, batch-size histogram, CPU utilisation, socket errors) per second and per epoch |

**CLI sketch:**

```
trapdojo generate --scenario scenarios/ramp-to-failure-ebpf.json \
    --run-id 2026-08-10-ramp-01 --generator-id 1
```

## Component 2: Trap Sink / Verifier

**Role:** Independently prove what TrapNinja actually delivered.

**Key capabilities:**

| Capability | Design approach |
|---|---|
| Listeners | R1 uses a **single listener process** per bind, with a documented and validated `qualified_ceiling_tps` written into every manifest. Scenarios whose required receive rate exceeds ceiling are refused at scenario-load. Multi-listener scaling options (offline union → per-port partition → BPF dispatch) are evaluated in that order at R3; MPMC ring is not the default |
| Length safety | `recvmmsg` returns per-message length, source, and flags. The sink processes only `memoryview(buf)[:msg_len]`. Messages with `MSG_TRUNC`, short lengths, or malformed BER are rejected into dedicated counters — never into the delivery accounting |
| Identity validation | Extractor validates magic **and** exact 128-bit run token **and** known `(generator_id, stream_id)` **and** identity-field length **and** `epoch_id` **and** sequence bounds **and** the identity OID via a minimal BER walker. Magic alone is never sufficient; the 128-bit run token is what makes cross-run false accepts vanishingly unlikely |
| Own drop visibility | 1 Hz `/proc/net/udp` monitor. **Any non-zero delta invalidates the run** (verdict `INVALID`, scope `rig`) — the sink cannot claim what did or did not arrive when its own buffer overflowed. Sink-side loss is never rendered as a TrapNinja failure |
| Sequence verification | Per `(stream_id, epoch_id, destination)`: received count, distinct-sequences count, six precise duplicate/missing counters, and gap ranges computed **against the generator ledger** — never against `[1, max_seq]` |
| Duplicate detection | `datagrams_received`, `duplicate_datagrams`, `sequences_delivered_exactly_once`, `sequences_delivered_multiple_times`, `missing_sequences`, and `unique_delivery_obligations_satisfied` are all reported separately. HA replay uses an independent `expected_duplicate_max_fraction` acceptance criterion |
| Latency | Cross-host one-way latency uses `CLOCK_TAI` (or disciplined `CLOCK_REALTIME`). Sync-source and offset are recorded at run start and after settlement on every host. If clock uncertainty exceeds threshold, latency is marked `INVALID` — not merely caveated. Same-clock pipeline latency (TrapNinja internal) is always available |
| Memory bounds | Gap tracking uses interval sets, bounded by the number of loss events (not trap volume) |

**CLI sketch:**

```
trapdojo sink --scenario scenarios/ramp-to-failure-ebpf.json \
    --run-id 2026-08-10-ramp-01
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

Generated traps are fully valid SNMP traps that any receiver would accept, with the test identity carried in a dedicated varbind. **Byte-exact layout lives in the [LLD](LowLevel-TestRig.md#wire-format-byte-exact-v2)**; the essentials:

- OID `.1.3.6.1.3.5850.1.1` under the **IANA-reserved experimental subtree** (`1.3.6.1.3`, per RFC 1155). Value is a **fixed 48-byte OCTET STRING** with layout: `wire_version (2) | flags (2) | run_token (16, random 128-bit) | generator_id (2) | stream_id (2) | epoch_id (4) | seq (8) | send_ts_tai_ns (8) | integrity_marker "TDJ2" (4)`.
- Templates are pre-encoded once at startup with `wire_version`, `flags`, `run_token`, `generator_id`, `stream_id`, and `integrity_marker` baked in. Only `epoch_id`, `seq`, and `send_ts_tai_ns` are patched per packet.
- The 128-bit `run_token` prevents cross-run false-accepts; the 4-byte integrity marker is a fast sanity check but is never sufficient on its own.
- The remaining varbinds are realistic (sysUpTime, snmpTrapOID, vendor-shaped payload varbinds) so TrapNinja's parser, filters, per-OID stats, and redirection rules exercise their production code paths.
- `epoch_id` distinguishes probe, warmup, dwell steps, burst, recovery, and cooldown — warm-up traffic cannot pollute measurement.
- SNMPv3 is not supported until R5 (patching an encrypted identity per packet is not valid; the R5 contract must specify per-packet USM encryption, engine boots/time behaviour, and how the identity survives TrapNinja's v3→v2c conversion).

## Loss Accounting & Reconciliation Model

Loss can occur at eight places. Each has an owner, a counter, and an **attribution confidence ceiling** — SUT counters can only ever bind *aggregate* attribution to a stage, never per-sequence. The [LLD](LowLevel-TestRig.md#accounting-model) contains the canonical model; the summary:

| # | Stage | Evidence source | Model | Confidence ceiling | Owner |
|---|---|---|---|---|---|
| 1 | Generator send failure (abandoned or ENOBUFS) | Generator ledger `abandoned_ranges` | Excluded from `G_offered` | `proven` | Rig |
| 2 | Network / NIC | Switch counters (manual), otherwise `unexplained` | A + B | `temporally_correlated` at best | Environment |
| 3 | SUT kernel socket buffer | `trapninja_socket_drops_total` / eBPF lost samples | A: `I_kernel_lost` | `aggregate_accounted` | TrapNinja |
| 4 | packet_queue full | Queue drop counters | A: `I_queue_lost` | `aggregate_accounted` | TrapNinja |
| 5 | Parse rejection | `trapninja_parse_rejected_total{reason=...}` | A: `I_parse_rejected` | `aggregate_accounted` | TrapNinja |
| 6 | Filtering (deliberate) | `trapninja_blocked_total` and B classification | A: `I_blocked`; B: `not_expected_filtered` | `aggregate_accounted` (A), `proven` (B) | TrapNinja (by design) |
| 7 | Forwarder send failure per destination | `trapninja_dest_failures_total{destination=...}` | B: `destination_forward_failure` | `temporally_correlated` | TrapNinja |
| 8 | Sink kernel buffer | Sink's own `/proc/net/udp` monitor | Invalidates run | — | Rig |

The reporter classifies every obligation exactly once in Model B and every input in Model A. Each row carries its `confidence`. Time-correlation is never rendered as per-sequence attribution.

## Verdict Model & Failure Criteria

Every epoch and every run has one of four verdicts:

| Verdict | Meaning | Scope |
|---|---|---|
| `PASS` | Evidence complete, thresholds met | `sut` |
| `FAIL` | Evidence complete and valid, TrapNinja breached a threshold | `sut` |
| `INVALID` | Evidence incomplete or unreliable — sink drops, generator underachievement, missing SUT metrics, clock uncertainty, ambiguous counter deltas | `rig` / `environment` / `evidence` |
| `ABORTED` | Run terminated before evidence collection could complete — crash, SIGINT, SUT unreachable | any |

**Rig or environment failure is never rendered as `FAIL`.** `INVALID` and `ABORTED` never carry `scope = "sut"`.

### Threshold criteria (dwell step FAIL — only after settlement)

| Criterion | Default threshold | Rationale |
|---|---|---|
| Input `I_unexplained` | 0 count | Any invisible input drop violates "every alarm matters" |
| Delivery `missing_max_fraction` | 0.001 (0.1%) | Matches TrapNinja's stated drop target |
| Delivery `unexplained_max_fraction` | 0.0 | No obligation may fail without attribution |
| Delivery `multi_delivery_max_fraction` | 0.0 (unless HA replay allows) | Independent of missing threshold |
| Latency | `queue_wait_p99_ms_max: 1000` | An alarm delayed multiple seconds under sustained (non-burst) load is operationally degraded |
| Resource runaway | `rss_growth_fraction_per_min_max: 0.05` | Predicts failure beyond the window; also catches leaks under load |
| Process health | Worker/service crash, HA state flap | Immediate fail |

### Ramp-control (may stop ramp; does not decide loss for current epoch)

| Signal | Effect |
|---|---|
| Queue depth monotonically increasing AND > 0.5 × queue size at end of dwell | Stop ramp after settlement of the current epoch |

Burst scenarios use different criteria: transient queue growth and elevated latency are *expected*; the pass conditions are zero loss after settlement, full queue drain within a recovery-time budget, and return of `queue_wait_p99_ms` to baseline.

All thresholds live in the scenario file, expressed as fractions (never percentages) with unit-bearing field names.

## Test Scenarios

All scenarios express thresholds as fractions (`loss_fraction_max: 0.001`), all rates in `tps`, all durations in `_s`, all sizes in `_bytes` (see the [LLD Units Policy](LowLevel-TestRig.md#units-policy)).

| Scenario | Phase | Shape | Proves |
|---|---|---|---|
| `baseline` | R1 | 1k tps constant, 10 min | Rig sanity: `I_unexplained = 0`, `missing = 0`, books balance in both models |
| `ramp-to-failure` | R2 | Ramp per capture mode (eBPF / socket / sniff) | Per-mode maximum sustained zero-loss achieved rate; first failing stage with confidence label |
| `sustained-soak` | R3 | 80% of found max, 8–24 h | Leak detection, counter stability, `.prom` export stability |
| `fibre-cut-burst` | R3 | 5k baseline + 100k spike for 30–60 s, repeated | Burst absorption, queue drain, recovery time (the headline production claim) |
| `filter-heavy` | R3 | Ramp with large blocked/redirect config loaded | Config-scale impact on the hot path; delivery-obligation accounting under filtering/redirection |
| `many-sources` | R3 | Ramp with 50k+ distinct source IPs (`allow_source_mode_fallback: false`) | GranularStats LRU behaviour and memory bounds at estate scale |
| `malformed-mix` | R3 | Sustained load + declared malformed classes | Per-class TrapNinja counter reactions match expectations; malformed excluded from delivery obligations |
| `ha-failover-under-load` | R4 | Sustained load + forced failover / PRIMARY kill | <3s failover, correct delivery-obligation classification across the transition, `expected_duplicate_max_fraction` respected |
| `redis-outage` | R4 | Sustained load + Redis stop/start | Graceful degradation: forwarding unaffected, cache recovers |
| `snmpv3-load` | R5 | Ramp with v3 mix | Only after R5 v3 contract is signed and implemented |

## TrapNinja-Side Requirements

The design deliberately requires **no test-specific code in TrapNinja** — the SUT is a production build. What it does require is complete observability and a few small additions surfaced by the v0.2 review:

| Requirement | Status |
|---|---|
| Pipeline latency percentiles (queue_wait, processing) | ✅ Phase 1 Part A — implemented |
| Kernel socket drop visibility (`/proc/net/udp`) | ✅ Phase 1 Part B1 — implemented |
| eBPF perf-buffer lost-sample counter | ✅ Phase 1 Part B2 — implemented |
| Resource telemetry (RSS, FDs, GC) | ✅ Phase 1 Part C — implemented |
| `trapninja metrics show` (JSON) for orchestrator polling | ✅ Implemented |
| **Forward-failure metrics** (`trapninja_dest_failures_total` with `destination` and `reason` labels; forwarded counter honouring `forward_packet()` return) | ⚠️ **Prerequisite.** Must be implemented before R2 orchestrator work — otherwise stage 7 loss is invisible and every failed forward pollutes `unexplained` in delivery accounting |
| Queue drop counters exposed in metrics export | Verify: `QueueStats` drops must appear in the `.prom` export, not only in `daemon queue-stats` |
| **P1. `trapninja_process_start_tai_ns` gauge** | ⚠️ **REQUIRED before R2.** Value = process start time in `CLOCK_TAI` nanoseconds. Lets the orchestrator detect process restart atomically and reset delta baselines. Without it, restart-across-poll silently corrupts deltas or invalidates healthy epochs. |
| **P2. `trapninja_metrics_snapshot_id` counter** | ⚠️ **REQUIRED before R2.** Increments on every export write. Lets the collector detect torn `.prom` reads; without it, non-atomic snapshots occasionally produce impossible counter relationships that force `INVALID` verdicts on healthy runs. |
| **P3. `trapninja config show --json --canonical`** | ⚠️ **REQUIRED before R2.** Deterministic canonical JSON of forwarding, filter, redirection, destinations, and SNMPv3 credentials-by-name. Lets TrapDojo hash the frozen forwarding config and derive the expected delivery-obligation set reproducibly. Without it, comparison reports either misfire or force TrapDojo to reimplement TrapNinja's config semantics itself. |
| Counter reset or run-delta capability | Orchestrator computes **deltas** between snapshots. Counter-uncertainty rules (reset, restart, wraparound, label change, missing sample, delayed `.prom`, non-atomic snapshot, HA role change) each have a defined response in the LLD — ambiguous intervals are invalidated, not silently trusted |

P1–P3 are TrapDojo's normative TrapNinja prerequisites. Full purpose and failure-mode detail in [LLD § SUT Counter Uncertainty Handling](LowLevel-TestRig.md#sut-counter-uncertainty-handling).

## Technology Constraints & Generator Performance Strategy

- **Python 3.9, RHEL 8/9, air-gapped** — same constraints as TrapNinja. Dependencies bundled via the existing `download-packages.sh` / `install-packages.sh` pattern.
- **Stdlib-first.** The hot paths (generator send loop, sink receive loop) are stdlib + `ctypes` (`sendmmsg`/`recvmmsg`). Hand-rolled BER encoder for v2c templates avoids the pysnmp import cost and gives byte-exact control. Templates are constructed offline at startup, never on the hot path.
- **Throughput budget.** Per-process targets to validate in R0/R1 selfcheck: ≥30k tps send per worker with `sendmmsg`, linear scaling to 4–8 workers → 100k+ tps aggregate from one generator host. Single sink-listener qualified ceiling ≥ 120k tps. Multi-generator-host coordination is additive (already partitioned by `generator_id` and `stream_id`).
- **Raw network qualification.** MTU, fragmentation policy, IP/UDP checksum, IP ID, port selection, and NIC offload interactions are documented and validated via generator-egress pcap in selfcheck. See the [LLD Raw-Network Qualification section](LowLevel-TestRig.md#raw-network-qualification).
- **Escape hatch.** If Python cannot reach the required rate on lab hardware, the template-based design degrades gracefully to pcap generation + `tcpreplay` for raw-rate scenarios; sequence numbers are pre-baked into the pcap and the ledger is derived from the same template stream. This is a documented fallback, not the primary path — it sacrifices dynamic rate profiles.

## Deployment Model

- **Separate git repository** (standalone product), mirroring TrapNinja conventions: `src/` layout, `dev/`, `docs/`, `ansible/`, `config.example/`.
- **Canonical artefact: one OCI image** containing all four subcommands (`generate`, `sink`, `orchestrate`, `report`, `selfcheck`). Built once, signed, shipped as a tarball into the air-gap. Bare-metal Python venv deployment remains supported but is not the default. See [LLD § Containerised Deployment](LowLevel-TestRig.md#containerised-deployment) for the exact flag list, host prep, and manifest recording.
- **Ansible role** prepares each generator/sink host (sysctls, CPU governor, container engine, image load) and never installs on SUT hosts. Same role handles bare-metal deployments where operators explicitly need them.
- **Privileges (container or bare-metal):** generator needs `CAP_NET_RAW` + `CAP_NET_ADMIN` (spoofed sources, pcap, `ethtool`); sink needs `CAP_NET_ADMIN` (`/proc/net/udp` visibility under host netns); orchestrator needs SSH access to SUT hosts only. Least privilege per role — the orchestrator's SSH account uses command-restricted keys and a sudoers entry whitelisted to the exact action commands. **`--privileged` is never used**; every capability is explicit and recorded in the manifest.
- **Security posture in the air-gap:** the OCI image runs with Docker/podman **default seccomp and AppArmor profiles**; TrapDojo's syscalls (`socket`, `sendmmsg`, `recvmmsg`, `sched_setaffinity`, ordinary file I/O) are all in the default allow list with `CAP_NET_RAW` granted. Selfcheck confirms this on the target runtime; narrow relaxation is documented per-host if ever needed.
- **Runtime axis in the reproducibility manifest.** `environment.<host>.runtime` records the runtime type, engine version, image digest, capability set, seccomp/apparmor profile, cpuset, and bind mounts. `--compare` refuses to compare across runtime types (same discipline as source-mode and NIC differences).
- **Container-vs-bare-metal parity is measured, not assumed.** R0/R1 selfcheck runs the same loopback baseline in the container and bare-metal on the same host; the delta on achieved offered rate, pacing lateness p99, sink received rate, and RSS growth is recorded. ≤ 1% delta → one qualified ceiling. > 1% delta → two ceilings (per runtime).

### Safety interlocks (extended in v0.2 to cover traffic targets)

High-rate or malformed UDP generation is potentially disruptive; safety controls cover traffic targets as well as SSH actions.

- **Inventory-derived targets.** `generator.target_ip:target_port`, `sources.pool_cidr`, and every `sink.listeners[i].bind_ip` must resolve to inventory entries whose tags intersect the scenario's `safety.lab_allowlist`. Freeform IPs that do not resolve to inventory are refused.
- **Per-capability acknowledgements.** Scenario must explicitly acknowledge every disruptive capability it uses. Missing acknowledgement → refuse to start:
  - `ramp_to_failure` (may cause SUT saturation)
  - `malformed_traffic` (may trigger slow paths)
  - `spoofing_enabled` (may interact with lab uRPF/anti-spoofing)
  - `rate_above_safe_ceiling_tps` (any epoch above `safety.safe_rate_ceiling_tps`)
  - `disruptive_actions` (SSH-injected service stops, HA failover, `nft`)
- **No silent source-mode fallback.** A failed spoof probe requires `allow_source_mode_fallback: true` to switch to alias mode. Otherwise the run aborts as `ABORTED`.
- **Dry-run mandatory before destructive scenarios.** `trapdojo orchestrate --dry-run` prints every SSH invocation, every action, every target validation, without executing anything.

Pointing a ramp-to-failure at a production HA pair by typo must be structurally impossible.

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
├── containers/                     # OCI Dockerfile, entrypoint, host sysctl drop-ins
├── ansible/
├── dev/tests/
└── docs/
```

## Build Phasing

R0 is a new gate added in v0.2. R1 implementation does not begin until R0 exits, so the accounting contract is proven on synthetic evidence before it is exercised against a real SUT.

| Rig Phase | Deliverable | Exit criteria |
|---|---|---|
| **R0** | Final wire format v2, `core/` (ledger, obligation, wire, template v2c), reconciliation modules, synthetic reconciliation tests, partial-send tests, epoch-boundary tests | Every synthetic edge case produces an unambiguous correct verdict (PASS/FAIL/INVALID/ABORTED with correct scope). Duplicate-plus-missing test produces FAIL. Fan-out, redirection, filter obligation classifications correct. |
| **R1** | v2c generator (constant + ramp) + single-process sink + selfcheck with pcap validation | Rig sustains its qualified ceiling on lab hardware with zero unexplained input loss and zero rig-side drops, verified by egress pcap. Loopback baseline books balance in both models. |
| **R2** | Orchestrator (scenario runner, SUT metric collection with counter-uncertainty rules, settlement barriers, verdict classification) + reporter | `ramp-to-failure` produces a defensible, reproducible breaking point with confidence-labelled attribution and correct PASS/FAIL/INVALID classification. |
| **R3** | Scale: multi-source spoofing at estate scale, malformed classes, burst profiles, multi-destination routing (fan-out + redirection), SNMPv1 implementation, sink multi-listener (offline-union) | `fibre-cut-burst`, `many-sources`, `filter-heavy`, `malformed-mix` runnable. |
| **R4** | Action injector for destructive scenarios (with R2 safety controls proven) | `ha-failover-under-load`, `redis-outage` produce correct PASS/FAIL/INVALID verdicts. |
| **R5** | SNMPv3 (contract signed off before code) + comparison reporting (`--compare` with incompatible-environment refusal) | Full scenario matrix runnable; version-to-version regression report. |

TrapNinja prerequisites (must land before the phase named):
- Before **R2**: forward-failure metrics, `trapninja_process_start_tai_ns`, `trapninja_metrics_snapshot_id`, `trapninja config show --json --canonical`, queue drops in `.prom` export.

## Risks & Open Questions

Product review on 2026-08-11 closed four v0.2 items. What remains is one genuine open decision plus one deferred contract; everything else on this list is a known operational risk with a defined mitigation.

### Genuine open decisions

1. **`hypothesis` in the offline dependency bundle.** Property-based tests are strongly desired for interval math (ledger vs received vs obligation set) and reconciliation invariants. Decide inclusion in `download-packages.sh` before R0 test bring-up. Concrete example tests exist to inform the decision.
2. **SNMPv3 contract (R5).** Per-packet USM encryption cost, engine boots/time behaviour, salt/IV policy, credential lifecycle, and how the identity survives TrapNinja's v3→v2c conversion are all unresolved. Deferred until R5; no v3 code before contract sign-off.

### Known operational risks with defined mitigations

3. **Python send-rate ceiling.** The 100k tps aggregate target from one host is plausible but unproven on the actual lab hardware. R1 selfcheck measures this before any SUT conclusion. Mitigations: multi-host generation (additive; already supported by `generator_id`), tcpreplay fallback (documented in Technology Constraints).
4. **Sink qualified ceiling is a hard scenario gate.** R1 uses a single listener; scenarios above ceiling are refused, not silently degraded. If the measured ceiling is inadequate for headline claims (100k tps burst), R3 introduces multi-listener via offline-union — implementation cost that is only paid if needed.

### Resolved (2026-08-11)

| # | Question | Resolution |
|---|---|---|
| — | Identity OID arc | `.1.3.6.1.3.5850.1.1` under IANA experimental subtree `1.3.6.1.3` (RFC 1155). Baked into templates. See [LLD § Wire Format](LowLevel-TestRig.md#wire-format-byte-exact-v2). |
| — | `CLOCK_TAI` in the lab | `chronyd` confirmed running on every host. `chronyc tracking` and `chronyc sources -v` are the sync-health source. TAI-offset application is verified per host and recorded in the manifest. See [LLD § Clock Model](LowLevel-TestRig.md#clock-model). |
| — | TrapNinja metrics prerequisites (P1, P2) | **REQUIRED** additions to TrapNinja before R2. See TrapNinja-Side Requirements above. |
| — | TrapNinja canonical-config CLI (P3) | **REQUIRED** addition to TrapNinja before R2. See TrapNinja-Side Requirements above. |

---

*Next step: decide on `hypothesis` bundle inclusion, then produce the R0 detailed design / implementation prompt for `core/` + reconciliation + the synthetic-test harness.*
