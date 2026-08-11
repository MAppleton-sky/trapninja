# TrapDojo — Low Level Design: TrapNinja Load Test Rig

**Status:** Draft for review (post design-review v0.2)
**Version:** 0.2
**Last Updated:** August 2026
**Companion to:** [HighLevel-TestRig.md](HighLevel-TestRig.md)
**Supersedes:** LLD v0.1

---

## Table of Contents

- [Change Summary (v0.1 → v0.2)](#change-summary-v01--v02)
- [Design-Review Decision Log](#design-review-decision-log)
- [Traceability: Review Item → Section](#traceability-review-item--section)
- [Purpose of This Document](#purpose-of-this-document)
- [Terminology](#terminology)
- [Scope of This LLD](#scope-of-this-lld)
- [Units Policy](#units-policy)
- [Repository Layout](#repository-layout)
- [Package & Module Map](#package--module-map)
- [Runtime Process Model](#runtime-process-model)
- [Wire Format (Byte-Exact, v2)](#wire-format-byte-exact-v2)
- [Clock Model](#clock-model)
- [Measurement Epochs & Settlement Protocol](#measurement-epochs--settlement-protocol)
- [Accounting Model](#accounting-model)
- [Attribution Confidence Levels](#attribution-confidence-levels)
- [Duplicate Semantics](#duplicate-semantics)
- [Run Manifest](#run-manifest)
- [Generator — Detailed Design](#generator--detailed-design)
- [Sink — Detailed Design](#sink--detailed-design)
- [Orchestrator — Detailed Design](#orchestrator--detailed-design)
- [Reporter — Detailed Design](#reporter--detailed-design)
- [Verdict Model: PASS / FAIL / INVALID / ABORTED](#verdict-model-pass--fail--invalid--aborted)
- [Scenario File Schema](#scenario-file-schema)
- [Report Schema](#report-schema)
- [CLI Specification](#cli-specification)
- [Configuration Files](#configuration-files)
- [Containerised Deployment](#containerised-deployment)
- [SNMP Version Handling](#snmp-version-handling)
- [Malformed Traffic Accounting](#malformed-traffic-accounting)
- [Raw-Network Qualification](#raw-network-qualification)
- [Source Simulation Mode Discipline](#source-simulation-mode-discipline)
- [Traffic-Target Safety Validation](#traffic-target-safety-validation)
- [SUT Counter Uncertainty Handling](#sut-counter-uncertainty-handling)
- [Reproducibility Evidence](#reproducibility-evidence)
- [Observability of the Rig Itself](#observability-of-the-rig-itself)
- [Testing Strategy](#testing-strategy)
- [Performance Budgets & Validation](#performance-budgets--validation)
- [Build Phases & Gates](#build-phases--gates)
- [Open Design Questions](#open-design-questions)

---

## Change Summary (v0.1 → v0.2)

The design review is accepted in full. Structural changes below apply consistently across HLD and LLD.

1. **Loss-accounting model split.** The single-equation model is replaced with two related models: *input accounting* (per generated input) and *delivery-obligation accounting* (per unique `(run_token, generator_id, stream_id, sequence, destination)` obligation, derived from a frozen forwarding configuration). Global SUT counters are used for aggregate attribution only, never per-sequence attribution.
2. **Attribution confidence levels.** Every loss row now carries one of `proven | aggregate_accounted | temporally_correlated | unexplained`. Temporal correlation is never described as per-sequence attribution.
3. **Sequence semantics fixed.** Generator maintains an explicit **successful-sequence ledger** per stream/epoch. Partial `sendmmsg()` completion causes retry of the exact unsent tail with the same sequence numbers; abandoned ranges are recorded, not silently skipped. Sink computes missing sequences against the ledger, not against `[1, max_seq]`.
4. **Length-safe sink.** `recvmmsg()` returns per-message length, source, and flags; the sink processes only `memoryview(buf)[:msg_len]`. `MSG_TRUNC` messages are counted and rejected. Identity extraction validates magic **and** exact 128-bit run token **and** known `generator_id`/`stream_id` **and** identity-field length **and** sequence bounds **and** expected identity OID.
5. **Clock model corrected.** Monotonic clocks are only used for local scheduling and local deltas. Cross-host timestamps use `CLOCK_TAI` (or disciplined `CLOCK_REALTIME`) with sync-source and offset recorded pre/post run. If clock uncertainty exceeds threshold, one-way latency is marked `INVALID` — not merely caveated.
6. **Epoch + settlement protocol.** Wire identity now carries an `epoch_id`. Every phase (probe/warmup/dwell/burst/recovery/cooldown) has explicit boundaries. Delivery loss for an epoch is only evaluated after settlement (last-offered watermark received or timeout).
7. **Duplicate semantics precise.** Six distinct counters replace the ambiguous "duplicates" field. A duplicate never compensates for a missing sequence. HA replay has a configurable duplicate acceptance criterion independent of loss criteria.
8. **Sink scaling simplified.** R1 uses a **single listener process** with a documented qualified ceiling; scenarios above ceiling are refused. Multi-listener options (offline union, per-port partition, BPF dispatch) are ordered for later evaluation; MPMC ring is no longer the default.
9. **Source-mode discipline.** Failed spoof probe never silently falls back. Fallback requires `allow_source_mode_fallback: true` in the scenario. Every run records requested vs effective source mode, source count, and probe evidence.
10. **Traffic-target safety.** All targets (generator destination IP:port, spoofed source CIDR, sink listen addresses) are validated against inventory allowlist. Ramp-to-failure, malformed traffic, spoofing, rates > safe ceiling, and disruptive HA actions each require an independent scenario acknowledgement flag.
11. **Verdict states expanded.** `PASS | FAIL | INVALID | ABORTED` with structured reasons. Sink drops, generator underachievement, missing metrics, and clock invalidity produce `INVALID` — not a TrapNinja `FAIL`.
12. **Units policy.** Every schema field name or description declares its unit. `loss_pct_max: 0.1` → `loss_fraction_max: 0.001`. Rates, sizes, durations, latency, slopes, RSS growth all follow the naming rule.
13. **Rate control claims revised.** "Zero heap allocation" is a measured optimisation target, not a guarantee. Absolute monotonic deadlines replace additive sleeps. Reports include requested vs achieved offered rate; breaking-point uses achieved offered rate.
14. **SUT counter uncertainty handled.** Counter reset, restart, wraparound, label-set change, HA role change, missing samples, delayed `.prom` update, non-atomic snapshots, and export-interval skew all have defined behaviour. Negative or ambiguous deltas invalidate the affected interval.
15. **SNMP version behaviour accurate.** v1 gets its own template design (v1 Trap-PDU differs from v2c). v3 is **not supported until R5** and its design work is gated on a separate contract.
16. **Malformed accounting separated.** Malformed traffic has explicit classes and expected TrapNinja counter responses; it is excluded from normal delivery obligations.
17. **Raw-network qualification.** MTU, fragmentation, IP/UDP checksum, IP ID, source/dest port selection, and NIC offload interactions are explicitly documented and validated via egress pcap in selfcheck.
18. **Reproducibility evidence expanded.** Manifest and report carry TrapDojo/TrapNinja versions, scenario/config hashes, OS/kernel, CPU/NIC details, offload state, IRQ pinning, socket buffer config, link counters pre/post, and effective source mode/count. Comparison reports flag incompatible environments.
19. **Identity redesigned.** Random 128-bit run token replaces the 8-byte ASCII truncation. Identity varbind now carries protocol version, run token, generator_id, stream_id, epoch_id, sequence, optional send timestamp, and an integrity marker at a fixed length.
20. **Phases regated.** New **R0 (accounting and protocol proof)** must complete before R1 implementation. R1 scope narrowed to v2c generation + single-process sink + loopback + two-host selfcheck + pcap validation.

---

## Design-Review Decision Log

| # | Review item | Decision |
|---|---|---|
| 1 | Redesign loss accounting | **Adopted in full.** Input accounting + delivery-obligation accounting are separate models with distinct pass conditions. See [Accounting Model](#accounting-model). |
| 2 | Correct generator sequence semantics | **Adopted — preferred approach.** Successful-sequence ledger; retry unsent tail with same seq; record abandoned ranges. See [Generator — Detailed Design](#generator--detailed-design). |
| 3 | Length-safe sink extraction | **Adopted.** `recvmmsg` msg_len used exclusively; strict identity validation (magic + run_token + gen_id + stream_id + oid + bounds). See [Sink — Detailed Design](#sink--detailed-design). |
| 4 | Correct clock model | **Adopted.** No cross-host monotonic comparisons. `CLOCK_TAI` preferred; sync health recorded; latency marked `INVALID` above threshold. See [Clock Model](#clock-model). |
| 5 | Measurement epochs & settlement | **Adopted.** `epoch_id` in wire identity; explicit settlement barrier at epoch end. See [Measurement Epochs](#measurement-epochs--settlement-protocol). |
| 6 | Duplicate semantics | **Adopted.** Six counters; duplicate never offsets missing; HA replay uses independent duplicate criterion. See [Duplicate Semantics](#duplicate-semantics). |
| 7 | Simplify multi-listener sink | **Adopted.** R1 single listener; MPMC ring dropped from default; ordered options for later. See [Sink — Detailed Design](#sink--detailed-design) §Scaling. |
| 8 | No silent source-mode change | **Adopted.** Requires `allow_source_mode_fallback: true`. See [Source Simulation Mode Discipline](#source-simulation-mode-discipline). |
| 9 | Extend safety to traffic targets | **Adopted.** Target/source/sink validated against inventory; per-capability acknowledgements. See [Traffic-Target Safety Validation](#traffic-target-safety-validation). |
| 10 | Failure/validity states | **Adopted.** `PASS/FAIL/INVALID/ABORTED` with structured reasons and scope. See [Verdict Model](#verdict-model-pass--fail--invalid--aborted). |
| 11 | Resolve percentage units | **Adopted.** Fractions with unit-bearing names. See [Units Policy](#units-policy). |
| 12 | Revise rate-control claims | **Adopted.** Absolute deadlines; measured allocation; achieved rate reported and used for verdicts. See [Generator — Detailed Design](#generator--detailed-design) §Rate. |
| 13 | Handle SUT counter uncertainty | **Adopted.** Explicit rules per event; ambiguous intervals invalidated. See [SUT Counter Uncertainty Handling](#sut-counter-uncertainty-handling). |
| 14 | SNMP version behaviour | **Adopted.** Separate v1 template; v3 blocked until R5 contract. See [SNMP Version Handling](#snmp-version-handling). |
| 15 | Malformed accounting | **Adopted.** Classes + counters; excluded from delivery obligations. See [Malformed Traffic Accounting](#malformed-traffic-accounting). |
| 16 | Raw-network qualification | **Adopted.** Documented and validated via pcap. See [Raw-Network Qualification](#raw-network-qualification). |
| 17 | Reproducibility evidence | **Adopted.** Expanded manifest and report. See [Reproducibility Evidence](#reproducibility-evidence). |
| 18 | Expand test strategy | **Adopted.** Enumerated cases + property-based tests for interval math and reconciliation. See [Testing Strategy](#testing-strategy). |
| 19 | Resolve identity design | **Adopted.** 128-bit random run token; layout redesigned. See [Wire Format](#wire-format-byte-exact-v2). |
| 20 | Update phase gates | **Adopted.** New R0 gate; R1 narrowed. See [Build Phases & Gates](#build-phases--gates). |

---

## Traceability: Review Item → Section

| Review item | HLD section | LLD section |
|---|---|---|
| 1 Loss accounting | Core Design Principle; Loss Accounting & Reconciliation Model | [Accounting Model](#accounting-model), [Reporter](#reporter--detailed-design) |
| 2 Sequence semantics | Component 1 (updated) | [Generator](#generator--detailed-design) §Ledger, [Wire Format](#wire-format-byte-exact-v2) |
| 3 Sink length-safe | Component 2 (updated) | [Sink](#sink--detailed-design) §Extractor |
| 4 Clock model | Risks (updated), Component 2 | [Clock Model](#clock-model) |
| 5 Epochs | Test Scenarios (updated) | [Measurement Epochs](#measurement-epochs--settlement-protocol) |
| 6 Duplicates | Loss Accounting (updated) | [Duplicate Semantics](#duplicate-semantics) |
| 7 Multi-listener | Component 2 (updated) | [Sink](#sink--detailed-design) §Scaling |
| 8 Source-mode | Component 1 (updated) | [Source Simulation Mode Discipline](#source-simulation-mode-discipline) |
| 9 Traffic-target safety | Deployment Model (updated) | [Traffic-Target Safety Validation](#traffic-target-safety-validation) |
| 10 Verdict states | Failure Criteria (updated) | [Verdict Model](#verdict-model-pass--fail--invalid--aborted) |
| 11 Units | Failure Criteria; Scenarios | [Units Policy](#units-policy) |
| 12 Rate control | Component 1; Failure Criteria | [Generator](#generator--detailed-design) §Rate |
| 13 SUT counters | TrapNinja-Side Requirements (updated) | [SUT Counter Uncertainty Handling](#sut-counter-uncertainty-handling) |
| 14 SNMP versions | Scope; Test Scenarios | [SNMP Version Handling](#snmp-version-handling) |
| 15 Malformed | Test Scenarios (updated) | [Malformed Traffic Accounting](#malformed-traffic-accounting) |
| 16 Raw network | Technology Constraints (updated) | [Raw-Network Qualification](#raw-network-qualification) |
| 17 Reproducibility | (new) Reproducibility Evidence | [Reproducibility Evidence](#reproducibility-evidence), [Run Manifest](#run-manifest) |
| 18 Tests | Build Phasing (updated) | [Testing Strategy](#testing-strategy) |
| 19 Identity | Sequence-Tagged Trap Format | [Wire Format](#wire-format-byte-exact-v2) |
| 20 Phases | Build Phasing (updated) | [Build Phases & Gates](#build-phases--gates) |

---

## Purpose of This Document

The HLD defines *what* TrapDojo does and *why*. This LLD defines *how* it is implemented, at the level a developer can begin coding against, and how it is prevented from producing a misleading PASS/FAIL:

- Byte-exact wire format with 128-bit run token and epoch.
- Two-part accounting model with attribution confidence levels.
- Length-safe hot paths for both generator and sink.
- Explicit settlement protocol so end-of-dwell queue residue is not miscounted as loss.
- Structured validity states so rig or environment failures never masquerade as SUT failures.

Where this LLD references TrapNinja modules, it does so only via TrapNinja's public surface (CLI + `.prom` files + SSH-invoked actions on an allowlisted host).

---

## Terminology

These terms are used throughout this LLD. Full definitions live in the [HLD Terminology section](HighLevel-TestRig.md#terminology); this table is the quick-reference so a developer reading this document alone is not blocked by an acronym.

| Term | Meaning |
|---|---|
| **SUT** | **System Under Test.** The TrapNinja HA pair (primary + secondary) plus its Redis and any dependencies. TrapDojo never runs on SUT hosts. |
| **Rig** | TrapDojo itself. Rig-side faults are TrapDojo's problem; SUT-side faults are TrapNinja's problem. |
| **NOC** | **Network Operations Centre** — the production trap destination that TrapNinja normally forwards to. In TrapDojo runs, the sink stands in for a NOC. |
| **Offered rate** | Traps per second the generator's `sendmmsg` accepted (kernel-accepted, ledger-recorded), not the configured target rate. Breaking-point analysis uses this. |
| **Delivery obligation** | A unique `(run_token, generator_id, stream_id, epoch_id, seq, destination)` tuple that the frozen forwarding config says should be delivered. |
| **Epoch** | A distinct measurement phase (probe, warmup, dwell step, burst, recovery, cooldown), carried as `epoch_id` on the wire. |
| **Settlement barrier** | End-of-epoch wait for last-offered watermark to arrive at the sink (or timeout) before loss is evaluated. |
| **Verdict** | `PASS \| FAIL \| INVALID \| ABORTED` with a `scope` of `sut`, `rig`, `environment`, or `evidence`. |
| **Ledger** | The generator's per-stream, per-epoch record of exactly which sequences the kernel accepted and which were abandoned. Source of truth for what the sink should have received. |

---

## Scope of This LLD

Deep on **R0 (accounting and protocol proof)** and **R1 (v2c generator + single-process sink + selfcheck)**. **R2 (orchestrator + reporter)** is specified at contract level. R3+ is deferred.

**In scope:**
- Wire identity v2, accounting model, epoch/settlement, verdict model, units policy — all normative for every phase.
- Generator: v2c template builder, rate control with absolute deadlines, send workers, successful-sequence ledger, partial-send handling, per-worker accounting.
- Sink: single listener, length-safe extraction with full identity validation, gap tracker against the ledger, own-drop monitor.
- Orchestrator: scenario runner lifecycle, SUT metric collection with counter-uncertainty rules, timeline recorder, verdict classification.
- Reporter: input accounting + delivery-obligation accounting, attribution confidence, `report.json`, `report.md`.
- Scenario schema, run manifest, safety interlocks, reproducibility evidence.

**Out of scope (deferred to R3+):**
- SNMPv1 template implementation (design specified, implementation gated).
- SNMPv3 template design and implementation (contract gated).
- Multi-generator-host coordination protocol.
- Multi-listener sink scaling.
- Redirection/fan-out with more than one destination *implementation* (the accounting model already handles it; qualifying it with real traffic is R3).
- HA failover and Redis outage action injection.
- Comparison reports (`--compare`).

---

## Units Policy

Every schema field name declares its unit; every field description restates it. This applies to scenarios, manifest, and report.

**Naming conventions (normative):**

| Quantity | Suffix | Example |
|---|---|---|
| Duration in seconds | `_s` | `dwell_s: 60` |
| Duration in milliseconds | `_ms` | `queue_wait_p99_ms_max: 1000` |
| Duration in nanoseconds | `_ns` | `send_ts_ns` |
| Rate in traps per second | `_tps` | `start_rate_tps: 5000` |
| Size in bytes | `_bytes` | `rcvbuf_bytes: 33554432` |
| Fraction (0.0–1.0) | `_fraction` | `loss_fraction_max: 0.001` (0.1%) |
| Percentage (0–100) — banned in schemas | — | Not used; convert to `_fraction` |
| Slope of a fraction per minute | `_fraction_per_min` | `rss_growth_fraction_per_min_max: 0.05` |
| Count | `_count` | `pool_ip_count: 5000` |
| CPU count | `_cpus` | `worker_cpus: 8` |

Human-facing rendered reports (`report.md`) may present percentages for readability; the machine-readable JSON never uses percentages.

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
│       │   ├── constants.py              # OIDs, defaults, integrity marker
│       │   ├── exceptions.py             # TrapDojoError hierarchy
│       │   ├── manifest.py               # RunManifest read/write
│       │   ├── ledger.py                 # SuccessfulSequenceLedger + interval math
│       │   ├── obligation.py             # ObligationSet builder (frozen fwd config)
│       │   ├── template.py               # SNMP trap byte templates (v2c in R1)
│       │   ├── template_v1.py            # SNMPv1 Trap-PDU (design; impl R3)
│       │   ├── wire.py                   # v2 identity codec
│       │   └── clocks.py                 # clock model helpers (TAI, monotonic)
│       ├── generator/
│       │   ├── coordinator.py
│       │   ├── worker.py                 # send loop with ledger + retry
│       │   ├── rate.py                   # deadline-based pacing
│       │   ├── mmsg.py                   # sendmmsg + recvmmsg ctypes bindings
│       │   ├── sources.py                # spoof / alias with strict mode
│       │   ├── profiles.py               # constant/ramp/burst/replay
│       │   ├── epoch.py                  # epoch transitions on wire
│       │   └── accounting.py             # ledger flushes + achieved-rate stats
│       ├── sink/
│       │   ├── listener.py               # single-process recvmmsg loop
│       │   ├── extractor.py              # length-safe strict identity validator
│       │   ├── gap_tracker.py            # interval-set tracker against ledger
│       │   ├── drop_monitor.py           # /proc/net/udp monitor
│       │   └── aggregator.py             # partial + final report writers
│       ├── orchestrator/
│       │   ├── scenario.py               # loader + schema + safety validators
│       │   ├── runner.py                 # lifecycle state machine
│       │   ├── collector.py              # SUT metric polling with uncertainty rules
│       │   ├── injector.py               # SSH action whitelist executor
│       │   ├── failure.py                # per-epoch verdict evaluator
│       │   └── timeline.py               # append-only jsonl event log
│       ├── reporting/
│       │   ├── reconcile_input.py        # input-accounting equation
│       │   ├── reconcile_delivery.py     # obligation-set reconciliation
│       │   ├── confidence.py             # attribution confidence assignment
│       │   ├── report_json.py
│       │   └── report_md.py
│       ├── cli/
│       │   ├── registry.py
│       │   ├── generate.py
│       │   ├── sink.py
│       │   ├── orchestrate.py
│       │   ├── report.py
│       │   └── selfcheck.py
│       └── util/
│           ├── logging.py
│           ├── ipc.py
│           └── platform_probe.py         # CPU/NIC/kernel/offload facts
├── scenarios/
├── config.example/
├── containers/
│   ├── Dockerfile                         # one image, all four subcommands
│   ├── entrypoint.sh                      # dispatches to trapdojo <verb>
│   └── profiles/                          # host-prep systemd units, sysctl drop-ins
├── ansible/                              # role stubs; fleshed out at R3+
├── dev/tests/
└── docs/
    ├── ARCHITECTURE.md
    ├── ACCOUNTING.md                     # the accounting-model spec (canonical)
    ├── WIRE_FORMAT.md
    ├── SCENARIOS.md
    └── OPERATIONS.md
```

---

## Package & Module Map

| Package | Responsibility | Depends on | Target size |
|---|---|---|---|
| `core` | Wire codec, templates, ledger/interval math, obligation set, manifest, clocks, constants, exceptions | stdlib only | 9 modules × ~250 LOC |
| `generator` | Rate profile → UDP packets on the wire with an accurate ledger | `core`, `util`, ctypes | 8 modules × ~250 LOC |
| `sink` | UDP packets → validated identities → per-stream counters/gaps | `core`, `util` | 5 modules × ~250 LOC |
| `orchestrator` | Drive scenario, poll SUT, inject actions, classify verdict | `core`, `util`, `paramiko` | 6 modules × ~300 LOC |
| `reporting` | Two-part reconciliation, confidence assignment, report emission | `core` | 5 modules × ~250 LOC |
| `cli` | Thin argparse dispatchers | all above | < 150 LOC each |
| `util` | Structured logging, IPC, platform probe | stdlib | 3 modules × ~200 LOC |

Dependency rule: `core`/`util` are leaves. `generator`, `sink`, `orchestrator`, `reporting` do not import each other; they communicate over files and SSH.

---

## Runtime Process Model

**`trapdojo generate`** (per generator host): coordinator + N worker processes; per-worker pipes for command (rate/epoch) and counter flushes. Fork-based; each worker owns one `stream_id` under one `generator_id`.

**`trapdojo sink`** (R1): single supervisor process + one listener process + one drop_monitor thread + one aggregator thread.

- Rationale: `SO_REUSEPORT` does not partition by `stream_id`, and per-stream cross-listener locking has real cost and correctness risk. R1 declares and validates a **single-listener qualified ceiling**. Scenarios whose required receive rate exceeds the ceiling are refused at scenario-load time.

**`trapdojo orchestrate`** (single process): asyncio loop; SSH invocations reuse a single `ControlMaster` socket per SUT host for the whole run.

---

## Wire Format (Byte-Exact, v2)

Every generated trap carries an **identity varbind** in a fixed location. Generator patches it in place; sink extracts and fully validates it.

### Identity varbind

- **OID:** `.1.3.6.1.3.5850.1.1`, under the IANA-reserved **experimental** subtree (`iso.org.dod.internet.experimental` = `1.3.6.1.3`, per RFC 1155). The experimental branch is explicitly reserved for experimental and lab use; the sub-arc `5850` is chosen as a stable TrapDojo-local identifier and is baked into every wire template. Any receiver that is not TrapDojo will treat this OID as an unknown vendor varbind and ignore it, so lab traffic never presents itself as a claimed production enterprise.
- **Type:** `OCTET STRING`, fixed length **48 bytes**.

Payload layout (network byte order, big-endian):

| Offset | Size (bytes) | Field | Notes |
|---|---|---|---|
| 0 | 2 | `wire_version` | uint16; `0x0002` for v2 |
| 2 | 2 | `flags` | uint16 bitfield; bit 0 = send_ts present, bits 1–15 reserved (must be zero) |
| 4 | 16 | `run_token` | 128-bit random, generated once per run |
| 20 | 2 | `generator_id` | uint16; unique per generator host in the run |
| 22 | 2 | `stream_id` | uint16; unique per worker under a `generator_id` |
| 24 | 4 | `epoch_id` | uint32; monotonic per stream, advances at each phase boundary |
| 28 | 8 | `seq` | uint64; monotonic per `(stream_id, epoch_id)`, starts at 1 |
| 36 | 8 | `send_ts_tai_ns` | int64 `CLOCK_TAI` nanoseconds; `INT64_MIN` if `flags.bit0 == 0` |
| 44 | 4 | `integrity_marker` | `0x54 0x44 0x4A 0x32` (`"TDJ2"`) |

Total: 48 bytes.

**Design notes:**

- The integrity marker is necessary but **not sufficient** for identity acceptance. A packet is accepted only when magic **and** run_token **and** known `(generator_id, stream_id)` **and** the identity OID/length are all correct. A 4-byte marker can appear coincidentally in unrelated payloads; the 128-bit run_token is what makes the sink reject other-run traffic with vanishing false-accept probability.
- `run_token` is generated with `secrets.token_bytes(16)` at manifest build time.
- `epoch_id = 0` is reserved for `probe`; measurement epochs start at `1`.
- The layout is stable for the life of wire version 2. Additive changes bump `wire_version`; sinks reject unknown wire versions and count them separately.

### Template shape (SNMPv2c, R1)

Templates are constructed once at generator startup with fully-serialised ASN.1 BER for a well-formed SNMPv2c `snmpV2-Trap` PDU containing:

- `sysUpTime.0` = static
- `snmpTrapOID.0` = one of the OIDs from the OID pool
- `trapdojoIdentity` (identity varbind above) — placed at a fixed index so its 48 value bytes land at a per-template precomputed offset
- 3–8 vendor-shaped payload varbinds so parser/filter code paths are realistic

Each template exports:

```python
@dataclass(frozen=True)
class Template:
    payload: bytes                  # complete SNMP message
    identity_offset: int            # start of identity value within payload
    identity_length: int            # 48
    template_id: int
    snmp_version: int               # 2 for v2c in R1
    approx_bytes: int
```

### Patch operation

For each accepted send slot the worker:

1. Selects the next template (round-robin or weighted per manifest).
2. Copies the template payload into a preallocated per-slot bytearray.
3. `struct.pack_into(">IQq", slot, off+24, epoch_id, seq, send_ts_tai_ns_or_min)` — three writes cover epoch/seq/timestamp. `wire_version`, `flags`, `run_token`, `generator_id`, `stream_id`, and `integrity_marker` are baked into the template at build time (they never change during a run).
4. `sendmmsg` submits the batch.

### Extract operation

Sink extracts identity by:

1. Reading only `memoryview(buf)[:msg_len]` returned by `recvmmsg`.
2. Locating the identity varbind by known OID via a minimal BER walker; identity_offset varies per SNMP version and per template, so the sink walks the outermost sequence, snmpTrapOID and following varbinds until the identity OID is matched. The walker enforces length safety at every level and rejects malformed BER.
3. Verifying the OCTET STRING length is exactly 48.
4. Verifying `wire_version == 2`, `integrity_marker == "TDJ2"`, `run_token == manifest.run_token`, and `(generator_id, stream_id)` is in the manifest's declared set.
5. Verifying `seq` and `epoch_id` are within declared bounds (per manifest and per stream's ledger high-water mark ± safety margin).

Any check failing routes the packet to a specific counter (see [Sink — Detailed Design](#sink--detailed-design) §Rejection classes) — none of which affect delivery accounting.

---

## Clock Model

**Rule:** monotonic clocks are host-local and are never compared across hosts.

### Local uses (monotonic)

- Rate-control deadlines in a generator worker.
- Elapsed-time measurements inside a single host.
- Log timestamps for local ordering.

Uses `time.monotonic_ns()`.

### Cross-host uses (TAI-preferred)

For `send_ts_tai_ns` (embedded in the wire identity) and for any cross-host event correlation (orchestrator timeline of generator/sink events), TrapDojo uses:

- `CLOCK_TAI` via `time.clock_gettime(time.CLOCK_TAI)` when available and disciplined.
- Otherwise disciplined `CLOCK_REALTIME`, with an explicit degradation flag in the manifest.

**Assumed sync daemon: `chronyd`.** The lab confirmed `chronyd` is the running time daemon on every host. TrapDojo therefore treats `chronyc` as the primary source of truth for sync health. `chronyd` drives `CLOCK_TAI` correctly when it has a leap-second source (usually its upstream stratum-1 servers publish this); the sync-health capture below records whether the TAI offset has actually been applied via `chronyc tracking` and `chronyc sourcestats`. If `CLOCK_TAI == CLOCK_REALTIME + 0`, TrapDojo flags the manifest with `tai_offset_applied: false` and degrades to `CLOCK_REALTIME` for cross-host timestamps.

### Sync-health capture

At run start and again after settlement, on every host (generator, sink, orchestrator, and SUT via SSH), TrapDojo captures:

- `time.clock_gettime` for `CLOCK_REALTIME`, `CLOCK_TAI`, `CLOCK_MONOTONIC`.
- `chronyc tracking` output: source, stratum, `System time` offset, `Root delay`, `Root dispersion`, `Update interval`, `Leap status`.
- `chronyc sources -v` output: selected source(s), stratum, offset.
- Any step events since the previous capture (via `journalctl -u chronyd --since` bounded by the previous capture's TAI timestamp).

Persisted to `<run-dir>/clocks/<host>.json`.

### Latency validity threshold

Scenario declares:

```jsonc
"clock": {
  "latency_max_offset_ns": 500000,     // 0.5 ms
  "require_tai": true
}
```

- If any host's estimated maximum error exceeds `latency_max_offset_ns` **at run start or after settlement**, one-way latency for that run is marked `INVALID` and the `report.md` shows `latency: INVALID` with the reason (which host, what offset).
- Same-clock pipeline latency from TrapNinja's own metrics (queue_wait, processing p99) is always reported and is unaffected by clock validity — it never leaves a single host.
- If TrapDojo cannot obtain sync health from any host (e.g. `chronyc` not on `PATH` or the daemon not responding), `require_tai: true` refuses to start; `require_tai: false` marks latency `INVALID` and continues with delivery accounting only.

---

## Measurement Epochs & Settlement Protocol

Every phase of a run is an epoch with a distinct `epoch_id` on the wire. This eliminates the ambiguity of "warm-up traffic counted alongside measurement traffic in one sequence space", and makes end-of-dwell settlement well-defined.

### Phases

| Phase | `epoch_id` policy | Purpose |
|---|---|---|
| `probe` | 0 | Rig-vs-sink handshake; source-mode probe |
| `warmup` | 1 | Reach steady-state generator behaviour; discarded from measurement |
| `dwell_k` | 2, 3, 4, … | Sustained measurement step (constant or ramp step) |
| `burst_k` | separate range | Burst spike epoch |
| `recovery_k` | separate range | Drain and stabilisation after burst |
| `cooldown` | last | Final drain to allow all offered traps to settle |

Each phase carries its `epoch_id` in the wire identity of every packet it emits, so the sink accounts for each epoch independently and warm-up cannot pollute measurement.

### Settlement barrier

At the end of every measurement epoch:

1. Generator records the **last successfully offered sequence per stream** for that epoch (its ledger high-water mark).
2. Generator transitions to the next epoch (either the next dwell step or `recovery`/`cooldown`).
3. Orchestrator waits for either:
   - The sink to report received `seq == high_water` (or higher) for every stream, for that epoch — **watermark met**.
   - `settlement_timeout_s` to elapse — **settlement expired**.
4. Orchestrator collects final SUT counter snapshots for the epoch window.
5. `reporter` evaluates delivery-obligation loss for that epoch.

Queue-depth saturation and RSS runaway may **stop the ramp immediately**, but final delivery loss for the epoch is only decided after settlement. A dwell is never declared lossy merely because packets remain in-flight at wall-clock end of dwell.

---

## Accounting Model

Two related but distinct models. Both are computed by the reporter after settlement of every epoch.

### Model A: Input Accounting

Per stream, per epoch, accounts for what happened to every offered input:

```
G_offered            = ledger.successfully_offered_seq_count
G_send_defer         = ledger.abandoned_seq_count + ledger.send_failed_seq_count
                      (rig-side; excluded from any TrapNinja judgment)

I_kernel_lost        = Δ trapninja_socket_drops_total (or eBPF lost samples)
I_queue_lost         = Δ trapninja_queue_drops_total
I_parse_rejected     = Δ trapninja_parse_rejected_total
I_blocked            = Δ trapninja_blocked_total       (deliberate filtering)
I_accepted_for_fwd   = Δ trapninja_accepted_forward_total

I_accounted          = I_kernel_lost + I_queue_lost + I_parse_rejected
                     + I_blocked + I_accepted_for_fwd

I_unexplained        = G_offered - I_accounted
```

**Interpretation:** `I_unexplained ≠ 0` indicates an invisible drop path inside TrapNinja's input stages, or a counter uncertainty (see [SUT Counter Uncertainty Handling](#sut-counter-uncertainty-handling)). It is reported prominently and blocks PASS unless the scenario explicitly permits `input_unexplained_max_count > 0`.

**Confidence:** all input-accounting terms except `G_offered` are `aggregate_accounted` at best — SUT counters cannot bind a specific `seq` to a specific stage. The `report.json` records this explicitly.

### Model B: Delivery-Obligation Accounting

For every unique **delivery obligation** — the tuple

```
(run_token, generator_id, stream_id, epoch_id, seq, destination)
```

— the reporter classifies:

| Classification | Meaning |
|---|---|
| `delivery_expected` | Obligation exists per the frozen forwarding config |
| `not_expected_filtered` | Filter suppresses this `(src_ip, oid)` pair for this destination |
| `not_expected_redirected_away` | Redirection sends this obligation to a different destination |
| `delivered_exactly_once` | Sink observed exactly one arrival at this destination |
| `delivered_multiple_times` | Sink observed ≥ 2 arrivals at this destination |
| `destination_forward_failure` | TrapNinja recorded a per-destination forward failure covering this window (aggregate — assigned by temporal correlation only) |
| `missing` | Expected but no arrival and no attributable failure |

**Deriving the expected obligation set.** At scenario freeze time (before `warmup`), the orchestrator captures TrapNinja's forwarding, filter, redirection, and destinations configuration via `trapninja config show --json --canonical` and hashes it (`fwd_config_sha256` in the manifest). The obligation set is computed from:

- The generator's OID pool and source-IP pool (declared in the manifest).
- The captured TrapNinja config (frozen — the orchestrator refuses to run if any config-changing action is scheduled inside a measurement epoch).

For each `(src_ip, oid)` combination that will actually be emitted, and each destination in `destinations.json`, the model evaluates filters/redirections deterministically to yield `delivery_expected` or a `not_expected_*` classification.

### Verdict inputs

The scenario declares its acceptance criteria for both models independently:

```jsonc
"acceptance": {
  "input": {
    "unexplained_max_count": 0,
    "kernel_lost_max_fraction": 0.0,
    "queue_lost_max_fraction": 0.0,
    "parse_rejected_max_fraction": 0.0
  },
  "delivery": {
    "missing_max_fraction": 0.0,
    "multi_delivery_max_fraction": 0.0,
    "unexplained_max_fraction": 0.0
  },
  "ha_replay": {
    "expected_duplicate_max_fraction": 0.02
  }
}
```

Loss values that would cross either input or delivery threshold produce `FAIL`.

---

## Attribution Confidence Levels

Every counted loss (or duplicate) row in `report.json` carries a `confidence` field:

| Level | Meaning | Typical source |
|---|---|---|
| `proven` | Bound to a specific `(stream_id, epoch_id, seq)` by direct evidence | Sink observed it (`delivered_multiple_times`, `delivered_exactly_once`); ledger recorded an abandoned range |
| `aggregate_accounted` | The stage is known to have lost N inputs in the epoch, but individual sequences cannot be identified | SUT counter deltas within one epoch |
| `temporally_correlated` | The stage's counter increment occurred inside the epoch, but neither per-sequence identity nor exclusivity to this stream is established | `trapninja_dest_failures_total` label match by destination when multiple streams share the destination |
| `unexplained` | Difference remains after all attribution rules have been applied | Reported directly; never hidden |

The reporter must **never** render aggregate SUT counter values as if they were per-sequence attribution. `report.md` presents attribution tables with the `confidence` column always visible.

---

## Duplicate Semantics

Six counters replace the ambiguous v0.1 `duplicates` field. All are computed per `(stream_id, epoch_id, destination)` and then aggregated:

| Counter | Definition |
|---|---|
| `datagrams_received` | Every UDP datagram that passed identity validation |
| `unique_delivery_obligations_satisfied` | Distinct `(seq, destination)` pairs for which at least one arrival was observed |
| `duplicate_datagrams` | `datagrams_received - unique_delivery_obligations_satisfied` |
| `sequences_delivered_exactly_once` | `seq` values with an arrival count of exactly 1 at the destination |
| `sequences_delivered_multiple_times` | `seq` values with an arrival count of ≥ 2 |
| `missing_sequences` | Expected obligations for which no arrival was observed |

**Invariant:** a duplicate never compensates for a missing sequence. The reconciliation code MUST NOT compute anything like `net_loss = missing - duplicates`. Tests enforce this (see [Testing Strategy](#testing-strategy)).

**HA replay:** when TrapNinja's failover replay is expected to re-send a subset of traps, the scenario declares `acceptance.ha_replay.expected_duplicate_max_fraction`. This threshold is checked **only against `delivered_multiple_times`** and is independent of the delivery-obligation `missing_max_fraction`.

---

## Run Manifest

Written by the orchestrator (or by `trapdojo generate` when standalone) at run start. Read by generator (templates + epochs), sink (identity validation + declared streams), and reporter (source of truth).

**File:** `<report-dir>/<run-id>/manifest.json`

```jsonc
{
  "manifest_schema_version": 1,
  "run_id": "2026-08-10-ramp-01",
  "run_token_hex": "9c8a...ffee",          // 128-bit, hex-encoded
  "created_utc": "2026-08-10T12:00:00Z",
  "trapdojo": { "version": "0.2.0", "git_commit": "…" },
  "scenario_ref": "scenarios/ramp-to-failure-ebpf.json",
  "scenario_sha256": "…",

  "wire": {
    "wire_version": 2,
    "identity_oid": "1.3.6.1.3.5850.1.1",
    "identity_length_bytes": 48,
    "integrity_marker_hex": "54444a32"     // "TDJ2"
  },

  "epochs": [
    { "epoch_id": 0, "name": "probe",   "target_rate_tps": 100,   "duration_s": 5 },
    { "epoch_id": 1, "name": "warmup",  "target_rate_tps": 5000,  "duration_s": 30 },
    { "epoch_id": 2, "name": "dwell_1", "target_rate_tps": 5000,  "duration_s": 60 },
    { "epoch_id": 3, "name": "dwell_2", "target_rate_tps": 10000, "duration_s": 60 }
    // ...
  ],

  "generator": {
    "host": "gen-01",
    "generator_id": 1,
    "worker_count": 8,
    "streams": [
      { "stream_id": 0, "worker_pid_hint": null, "template_ids": [0,1,2] }
    ],
    "templates": [
      { "template_id": 0, "snmp_version": 2, "approx_bytes": 210, "identity_offset": 162 }
    ],
    "sources": {
      "requested_mode": "spoof",
      "effective_mode": "spoof",           // filled at probe end
      "pool_ip_count_requested": 5000,
      "pool_ip_count_effective": 5000,
      "pool_cidr": "10.234.100.0/20",
      "allow_source_mode_fallback": false,
      "probe": { "packets_sent": 100, "packets_observed_at_sink": 100 }
    }
  },

  "sink": {
    "host": "sink-01",
    "listener_count": 1,
    "qualified_ceiling_tps": 120000,
    "listeners": [
      { "bind": "10.234.83.140:162", "destination_label": "primary-noc", "rcvbuf_bytes": 33554432 }
    ]
  },

  "sut": {
    "primary_host": "trapninja-p",
    "secondary_host": "trapninja-s",
    "trapninja_version": "0.8.1",
    "trapninja_git_commit": "…",
    "capture_mode_expected": "ebpf",
    "capture_mode_observed": "ebpf",
    "fwd_config_sha256": "…",
    "filter_config_sha256": "…",
    "destinations_config_sha256": "…"
  },

  "environment": {
    "generator": { /* see Reproducibility Evidence */ },
    "sink":      { /* … */ },
    "sut_primary":   { /* … */ },
    "sut_secondary": { /* … */ }
  },

  "clock": {
    "policy": { "require_tai": true, "latency_max_offset_ns": 500000 },
    "samples": [
      { "host": "gen-01",  "phase": "run_start", "source": "chrony", "offset_ns_est_max": 120000, "tai_available": true },
      { "host": "sink-01", "phase": "run_start", "source": "chrony", "offset_ns_est_max": 110000, "tai_available": true }
    ]
  },

  "acknowledgements": {
    "ramp_to_failure": true,
    "malformed_traffic": false,
    "spoofing_enabled": true,
    "rate_above_safe_ceiling_tps": null,
    "disruptive_actions": false
  }
}
```

`manifest_schema_version` gates report comparison. `run_token_hex`, `wire_version`, and `epoch_id` bind every downstream file to this manifest.

---

## Generator — Detailed Design

### 1. Template builder (`core/template.py`)

- Runs once at coordinator startup, before workers fork.
- Hand-rolled BER encoder for v2c (avoids pysnmp import cost and gives precise byte control). The encoder is small (~200 LOC) and covers exactly the subset needed for SNMPv2c notifications.
- Emits `List[Template]` whose payloads bake in `wire_version`, `flags`, `run_token`, `generator_id`, `stream_id` (per worker), and `integrity_marker`. Only `epoch_id`, `seq`, and `send_ts_tai_ns` are patched per packet.
- SNMPv1 template code lives in `template_v1.py` and is a separate class hierarchy — the v1 Trap-PDU has a different top-level shape from v2c and shares no encoder state. R1 does not build v1 templates.
- Passed to workers via inherited memory (fork COW).

### 2. Rate profiles (`generator/profiles.py`)

Interface (unchanged from v0.1):

```python
class RateProfile(Protocol):
    def target_rate_tps(self, t_elapsed_s: float) -> float: ...
    def is_finished(self, t_elapsed_s: float) -> bool: ...
    def current_epoch_id(self, t_elapsed_s: float) -> int: ...
```

Implementations: `ConstantProfile`, `RampProfile`, `BurstProfile`, `ReplayProfile`. Every profile is responsible for advancing `epoch_id` at phase boundaries; the coordinator broadcasts the new `(target_rate_tps, epoch_id)` tuple to workers.

### 3. Deadline-based pacing (`generator/rate.py`)

Absolute monotonic deadlines instead of additive sleeps to avoid cumulative drift:

```python
class DeadlinePacer:
    def __init__(self, rate_tps: float) -> None:
        self._interval_ns = int(1e9 / rate_tps)
        self._next_deadline_ns = time.monotonic_ns()

    def set_rate_tps(self, rate_tps: float) -> None:
        self._interval_ns = int(1e9 / rate_tps)

    def budget_now(self, batch_size: int) -> int:
        now_ns = time.monotonic_ns()
        if now_ns < self._next_deadline_ns:
            return 0
        elapsed = now_ns - self._next_deadline_ns
        # returns integer count granted; deadline advances by exactly the granted amount
        granted = 1 + min(batch_size - 1, elapsed // self._interval_ns)
        self._next_deadline_ns += granted * self._interval_ns
        return granted
```

- No cumulative drift: deadline is advanced by *exactly* what was granted, regardless of scheduling lateness.
- The worker records `pacing_lateness_ns = now_ns - self._next_deadline_ns` per second so late scheduling is visible in reports (not a silent inaccuracy).

**Claim discipline.** "Zero heap allocation on the hot path" is a **measured target**, not a guarantee. R0 selfcheck includes a `tracemalloc`-based allocation-rate measurement over 30 seconds of steady-state generation; the report includes the value. Batch slicing (`batch_buf[:granted]`) and other apparent allocations must be verified as no-op views or eliminated.

### 4. sendmmsg binding (`generator/mmsg.py`)

- `ctypes.CDLL("libc.so.6", use_errno=True)`.
- Reused for `recvmmsg` in the sink.
- `send_batch(fd: int, iov_array, msghdr_array, count: int) -> int` returns the number of messages the kernel accepted.
- On `EINTR`: retry. On `ENOBUFS`/`EAGAIN`: return partial accepted count without raising. On any other errno: raise a specific `SendmmsgError` that carries the errno.
- Import-time smoke test: `sendmmsg` symbol resolves and a smoke send on a `SOCK_DGRAM` succeeds. Failure → the coordinator uses a `sendto` loop and records this in the manifest (`generator.sendmmsg_available: false`), not silently.

### 5. Successful-sequence ledger (`core/ledger.py`)

**Every worker maintains a per-stream, per-epoch ledger of exactly which sequences the kernel accepted.**

```python
class SuccessfulSequenceLedger:
    def __init__(self, stream_id: int, epoch_id: int) -> None: ...
    def record_accepted(self, seq_low: int, seq_high: int) -> None: ...   # inclusive
    def record_abandoned(self, seq_low: int, seq_high: int, reason: str) -> None: ...
    def high_water(self) -> int: ...                                       # last accepted seq
    def flush(self, out: TextIO) -> None: ...                              # append to jsonl
```

Backed by two sorted interval-of-integers lists (`accepted`, `abandoned`) with amortised O(log n) inserts. Adjacent ranges are merged. Memory is bounded by the number of gap events, not the trap volume.

### 6. Worker send loop (`generator/worker.py`)

Corrected to handle partial `sendmmsg` completion without falsifying the ledger:

```python
def run(cfg: WorkerCfg, cmd_pipe, ctr_pipe) -> None:
    templates = cfg.templates
    pacer     = DeadlinePacer(cfg.initial_rate_tps)
    seq_next  = 1
    epoch_id  = 0
    ledger    = SuccessfulSequenceLedger(cfg.stream_id, epoch_id)
    slots     = _preallocate_slots(cfg.batch_size)             # bytearrays + iov/mmsghdr
    pending: Optional[PendingBatch] = None                     # unsent tail from prior call
    counters  = WorkerCounters()

    while True:
        rate_tps, new_epoch = _drain_cmd_pipe(cmd_pipe)
        if rate_tps is not None:
            pacer.set_rate_tps(rate_tps)
        if new_epoch is not None and new_epoch != epoch_id:
            ledger.flush(cfg.ledger_path)
            epoch_id = new_epoch
            seq_next = 1
            ledger = SuccessfulSequenceLedger(cfg.stream_id, epoch_id)

        if pending is not None:
            sent = _send_pending(pending, cfg.raw_fd)
            _account_partial(pending, sent, ledger, counters)
            pending = _remainder_or_none(pending, sent, cfg.abandon_after_retries)
            continue                                            # do not allocate new seqs while tail remains

        granted = pacer.budget_now(cfg.batch_size)
        if granted == 0:
            _sleep_until_deadline(pacer)                        # bounded, absolute
            continue

        first_seq = seq_next
        for i in range(granted):
            tmpl = _next_template(templates, i)
            _patch_identity(slots[i], tmpl, epoch_id, seq_next, _send_ts_or_min(cfg))
            seq_next += 1

        sent = send_batch(cfg.raw_fd, slots, granted)
        if sent == granted:
            ledger.record_accepted(first_seq, first_seq + granted - 1)
            counters.sent_count += sent
        else:
            # Preferred approach: retain tail with same sequence numbers
            if sent > 0:
                ledger.record_accepted(first_seq, first_seq + sent - 1)
                counters.sent_count += sent
            pending = PendingBatch(
                slots       = slots,
                first_seq   = first_seq + sent,
                remaining   = granted - sent,
                retry_count = 0,
                errno       = _last_errno(),
            )
            counters.send_defer_count += pending.remaining

        _maybe_flush(counters, ledger, ctr_pipe)

        if cfg.profile_finished():
            break

    ledger.flush(cfg.ledger_path)
    _final_flush(counters, ctr_pipe)
```

**Guarantees:**

- Sequence numbers `first_seq + sent` … `first_seq + granted - 1` are held on the retry tail and are only accepted (recorded in the ledger) when the kernel actually accepts them. They are never marked "sent" prematurely, so the sink cannot see a false gap.
- Abandonment after `cfg.abandon_after_retries` records the exact `(low, high, reason=ENOBUFS)` range in the ledger's abandoned interval set. These are counted as **rig-side send failures**, isolated from any TrapNinja judgment.
- Epoch changes flush the ledger and restart `seq_next = 1`. Sequences within one `(stream_id, epoch_id)` are always monotonic and start at 1.

### 7. Accounting outputs (`generator/accounting.py`)

Per worker, per epoch, flushed at 1 Hz and at epoch boundary:

`<run-dir>/generator/<generator_id>/<stream_id>_ledger.jsonl`:

```jsonc
{
  "epoch_id": 2, "t_epoch_s": 15,
  "accepted_ranges": [[1, 30000], [30015, 45000]],
  "abandoned_ranges": [[30001, 30014, "ENOBUFS"]],
  "first_accepted_seq": 1, "last_accepted_seq": 45000,
  "attempted_seq_count": 45014,
  "accepted_seq_count": 44986,
  "abandoned_seq_count": 14,
  "bytes_accepted": 9447060,
  "requested_rate_tps": 45000,
  "achieved_offered_rate_tps": 44986,
  "pacing_lateness_ns_p99": 220000,
  "batch_size_hist": { "1": 12, "128": 340, "…": "…" },
  "sendmmsg_partials_count": 3,
  "worker_cpu_pct": 62.4
}
```

The reporter uses `achieved_offered_rate_tps` (not `requested_rate_tps`) for breaking-point determination.

---

## Sink — Detailed Design

### 1. Listener process (`sink/listener.py`)

R1: **single listener process** per bind. Multi-listener scaling is deferred (see [§Scaling](#5-scaling-r2)).

- `SO_RCVBUF` set to `scenario.sink.listeners[i].rcvbuf_bytes`; kernel-clamped value recorded in the manifest.
- `recvmmsg` batch size = `RECVMMSG_BATCH` (default 128).

Hot loop, length-safe:

```python
def run(cfg: ListenerCfg, shm) -> None:
    bufs = [bytearray(2048) for _ in range(RECVMMSG_BATCH)]
    while not _stop.is_set():
        got, msg_lens, srcs, flags = recv_batch(cfg.fd, bufs)
        for i in range(got):
            if flags[i] & MSG_TRUNC:
                shm.rej_truncated_count += 1
                continue
            if msg_lens[i] < MIN_IDENTITY_ENCLOSING_BYTES:
                shm.rej_short_count += 1
                continue
            view = memoryview(bufs[i])[:msg_lens[i]]
            ident = extract_and_validate_identity(view, cfg.expected)
            if ident is None:
                # rejection already counted by extractor into shm
                continue
            _record(shm, ident, dest=cfg.destination_label,
                    datagram_bytes=msg_lens[i], src_ip=srcs[i])
```

The receive buffer is never scanned past `msg_lens[i]`. Stale buffer contents cannot influence identity extraction.

### 2. Extractor (`sink/extractor.py`)

`extract_and_validate_identity(view, expected)` performs, in order:

1. Minimal BER walk to locate the OCTET STRING varbind with the identity OID. Each length is bounded by the enclosing length; malformed BER → `rej_ber_malformed_count`.
2. Verify OCTET STRING length == 48. Else → `rej_identity_length_count`.
3. Read `wire_version`. If ≠ 2 → `rej_wire_version_count` (labelled with the version).
4. Read `integrity_marker`. If ≠ `"TDJ2"` → `rej_integrity_marker_count`.
5. Read `run_token`. If ≠ `expected.run_token` → `rej_wrong_run_count`.
6. Read `generator_id`, `stream_id`. If not in `expected.declared_streams` → `rej_unknown_stream_count`.
7. Read `epoch_id`. If not in `expected.declared_epochs` → `rej_unknown_epoch_count`.
8. Read `seq`. If `seq == 0` or `seq > expected.max_seq_hint(stream_id, epoch_id) + SAFETY_MARGIN` → `rej_seq_out_of_range_count`.
9. Read `send_ts_tai_ns` when `flags.bit0 == 1`.

Any check failure returns `None` and counts into a dedicated bucket (visible in the report as a separate table so they are not confused with delivery loss).

### 3. Gap tracker against the ledger (`sink/gap_tracker.py`)

Data structure per `(stream_id, epoch_id, destination)`: sorted list of `(lo, hi)` inclusive intervals of **received** sequences.

- `record(seq)`: binary-search insert; extend + merge on adjacency; increment `duplicate_datagrams` on already-covered `seq`; increment `sequences_delivered_multiple_times` only on transition from 1 to ≥ 2 arrivals for that `seq` (tracked in a compact set of "seen ≥ 2" seqs, or a bloom filter with exact fallback).
- `finalize(ledger)`: computes:
  - `unique_delivery_obligations_satisfied` = size of received-interval union intersected with the ledger's `accepted_ranges`.
  - `missing_sequences` = `accepted_ranges` minus received-interval union, subject to obligation-expectation classification by the reporter.
  - Duplicates and multi-delivery counters as above.

**The ledger, not `[1, max_seq]`, defines what "should have arrived".** Sequences the ledger records as `abandoned` are never "missing" — they were never sent.

### 4. Own-drop monitor (`sink/drop_monitor.py`)

- Thread in the supervisor.
- 1 Hz `/proc/net/udp` + `/proc/net/udp6` read; per-bound-socket drop delta recorded to `<run-dir>/sink/drops.jsonl`.
- **Any non-zero delta invalidates the run** for that destination — verdict becomes `INVALID`, not `FAIL`, because the sink cannot claim what did or did not arrive when its own buffer overflowed.

### 5. Scaling (R2+, not R1)

R1 declares a **qualified single-listener ceiling** measured by `trapdojo selfcheck` on the actual lab hardware (see [Performance Budgets](#performance-budgets--validation)). Scenarios whose required sustained receive rate exceeds this ceiling by any margin are refused at scenario-load time with an explicit message.

For R3 the ordered options, in increasing complexity, are:

1. **Multi-listener, independent interval sets, offline union.** Each listener owns its own gap tracker; the aggregator unions them at end-of-run. Correctness is straightforward; the ledger-based reconciliation absorbs duplicate observations correctly (a `seq` observed by two listeners is `duplicate_datagrams += 1`, not `missing -= 1`).
2. **Deterministic partition by destination port.** Traffic to different destinations goes to different listeners bound to different ports. Requires TrapNinja config to fan out by destination-port already, so mostly relevant to multi-destination scenarios.
3. **Reuse-port BPF dispatch.** `SO_ATTACH_REUSEPORT_CBPF` (or eBPF) to hash `(generator_id, stream_id)` bytes at a fixed packet offset to a listener index. Requires proven kernel compatibility and template-stable offsets. Highest performance, highest implementation cost.

**Not adopted as default:** userspace MPMC ring between one dispatcher and multiple worker listeners. It is only reconsidered if options 1–3 are inadequate, and any such design must specify capacity, overflow accounting, memory ordering, shutdown behaviour, added latency, and how ring overflow marks the run `INVALID`.

### 6. Aggregator (`sink/aggregator.py`)

- Supervisor thread.
- Writes `<run-dir>/sink/partial.jsonl` every `AGGREGATOR_INTERVAL_S` (default 5 s).
- At end of run (or on receipt of `EPOCH_SETTLE` from orchestrator), invokes `gap_tracker.finalize(...)` per `(stream, epoch, destination)`, writes `<run-dir>/sink/final.json`.

---

## Orchestrator — Detailed Design

### 1. Lifecycle state machine

```
LOAD_SCENARIO → VALIDATE_SCHEMA → VALIDATE_SAFETY → PROBE_HOSTS
  → CAPTURE_SUT_CONFIG → CAPTURE_ENV_START → CAPTURE_CLOCKS_START
  → START_SINK → START_GENERATOR
  → EPOCH_PROBE → EPOCH_WARMUP
  → for epoch in measurement_epochs:
        RUN_EPOCH → SETTLEMENT_BARRIER → COLLECT_EPOCH_METRICS → EVALUATE_STEP
  → EPOCH_COOLDOWN → SETTLEMENT_BARRIER_FINAL
  → CAPTURE_ENV_END → CAPTURE_CLOCKS_END → TEARDOWN → REPORT
```

Every transition emits a timeline event to `<run-dir>/timeline.jsonl`.

- `SETTLEMENT_BARRIER`: waits for sink's per-stream watermark to match generator's per-stream `high_water` for the just-ended epoch, or `settlement_timeout_s`.
- On any hard failure in `START_*`, `PROBE_HOSTS`, or `CAPTURE_*`, the run enters `TEARDOWN` and reports `ABORTED` — not `FAIL`.

### 2. Collector (`orchestrator/collector.py`)

Two paths per SUT host, tried in order per poll:

1. `.prom` file over SSH.
2. `trapninja metrics show --json` over SSH.

Both include a `trapninja_process_start_tai_ns` gauge (added by the TrapNinja prerequisite, see [SUT Counter Uncertainty Handling](#sut-counter-uncertainty-handling)) so the collector can detect process restarts and reset its delta baseline atomically.

Records per-poll: raw counter values, `process_start_tai_ns`, `poll_tai_ns_start`, `poll_tai_ns_end` (poll straddles wall time — recorded so the reporter knows the sample width and can invalidate an epoch whose bounding polls are too far apart).

### 3. Injector (`orchestrator/injector.py`)

Whitelist-only actions (unchanged from v0.1). Each action requires two independent flags: the top-level `destructive: true` and `acknowledgements.disruptive_actions: true`. R1 does not exercise the injector (safety scenarios move to R3).

### 4. Failure evaluator (`orchestrator/failure.py`)

At each epoch boundary (post-settlement), computes:

- Input accounting acceptance (per §Accounting Model).
- Delivery acceptance (once obligations are reconciled by the reporter).
- Queue-depth trend inside the epoch (linear regression over dwell samples only).
- `queue_wait_p99_ms` from the epoch window.
- `rss_growth_fraction_per_min` from delta across the epoch.
- Health signals (crashes, HA flaps) from timeline.

Ramp control: monotonically increasing queue depth AND depth > 0.5 × declared queue size at end-of-dwell stops the ramp **for further steps** but does not decide delivery loss for the ended step — that still awaits settlement.

---

## Reporter — Detailed Design

### `reporting/reconcile_input.py`

Consumes: `manifest.json`, `generator/**/ledger.jsonl`, `sut_<host>.jsonl`, `timeline.jsonl`. Emits per stream per epoch:

- `G_offered = Σ accepted_seq_count`
- Per input stage: `Σ Δ counter` restricted to the epoch's tai time window, with counter-uncertainty rules applied (see [SUT Counter Uncertainty Handling](#sut-counter-uncertainty-handling)). Any invalidated interval propagates `epoch_verdict = INVALID`.
- `I_accounted`, `I_unexplained`.

### `reporting/reconcile_delivery.py`

Consumes: `manifest.json`, `generator/**/ledger.jsonl`, `sink/final.json`, and the frozen forwarding config hashes.

Builds the **expected obligation set** per epoch by evaluating filters/redirection over `(src_ip, oid)` for every accepted sequence.

Assigns each obligation exactly one classification (see [Model B](#accounting-model)). Records confidence per row.

### `reporting/confidence.py`

Central mapping table:

| Evidence | Confidence |
|---|---|
| Sink observed the arrival | `proven` |
| Ledger recorded abandonment | `proven` |
| SUT counter delta matches epoch, only one stream/destination present | `aggregate_accounted` |
| SUT counter delta matches epoch, multiple streams/destinations share the counter | `temporally_correlated` |
| No evidence bounds this sequence | `unexplained` |

### `reporting/report_json.py`

```jsonc
{
  "report_schema_version": 1,
  "run_id": "…",
  "run_token_hex": "…",
  "scenario_ref": "…",
  "trapdojo_version": "0.2.0",
  "trapninja_version": "0.8.1",

  "verdict": "PASS",                        // PASS | FAIL | INVALID | ABORTED
  "verdict_reasons": [],
  "verdict_scope": null,                    // "sut" | "rig" | "environment" | "evidence"

  "epochs": [
    {
      "epoch_id": 2,
      "name": "dwell_1",
      "verdict": "PASS",
      "input_accounting": {
        "G_offered": 12000000,
        "I_kernel_lost":    { "count": 0,    "confidence": "aggregate_accounted" },
        "I_queue_lost":     { "count": 234,  "confidence": "aggregate_accounted" },
        "I_parse_rejected": { "count": 0,    "confidence": "aggregate_accounted" },
        "I_blocked":        { "count": 12000,"confidence": "aggregate_accounted" },
        "I_accepted_for_fwd":{"count": 11987766,"confidence": "aggregate_accounted" },
        "I_unexplained":    { "count": 0 }
      },
      "delivery_accounting": {
        "obligations_total_count": 11987766,
        "delivered_exactly_once_count": 11987766,
        "delivered_multiple_times_count": 0,
        "missing_count": 0,
        "not_expected_filtered_count": 12000,
        "not_expected_redirected_away_count": 0,
        "destination_forward_failure_count": 0,
        "unexplained_count": 0
      },
      "duplicates": {
        "datagrams_received": 11987766,
        "duplicate_datagrams": 0,
        "sequences_delivered_multiple_times": 0
      },
      "rate": {
        "requested_target_tps": 5000,
        "achieved_offered_tps": 4999.7,
        "pacing_lateness_ns_p99": 220000
      },
      "clock_validity": "valid",
      "sink_health": { "kernel_drops_delta_count": 0, "rej_truncated_count": 0 }
    }
  ],

  "breaking_point": {
    "achieved_offered_tps": 42500,
    "first_failing_stage": "queue",         // per input-accounting classification
    "confidence": "aggregate_accounted"
  },

  "environment_diff": { /* start vs end */ },
  "clock_summary": { "worst_offset_ns_est_max": 130000, "policy_ok": true }
}
```

### `reporting/report_md.py`

Human-readable rendering. Leads with `verdict` **and** `verdict_scope` — a big red banner for `INVALID` explicitly states "this does not indicate a TrapNinja failure" and names the responsible component.

---

## Verdict Model: PASS / FAIL / INVALID / ABORTED

| State | Meaning | Example causes |
|---|---|---|
| `PASS` | All acceptance thresholds met, all evidence complete, all validity checks green | Ramp completes without breaching input or delivery thresholds |
| `FAIL` | Evidence is complete and valid, and TrapNinja breached a threshold | Input or delivery loss over threshold; queue saturation stopping a ramp; RSS growth over budget; forward failure > threshold |
| `INVALID` | Evidence is incomplete or unreliable through no fault of TrapNinja | Sink kernel drops; generator underachievement of requested rate; missing SUT metrics; clock uncertainty above threshold; ambiguous counter deltas |
| `ABORTED` | Run terminated before evidence collection could complete | Operator SIGINT; sink/generator/orchestrator crash; SUT host unreachable mid-run |

`verdict_scope` names the responsible component: `sut`, `rig`, `environment`, `evidence`. `INVALID` and `ABORTED` never appear with scope `sut`.

`verdict_reasons` is a list of structured objects: `{code, message, evidence_ref}`.

Ramp scenarios can produce a per-epoch verdict without producing a whole-run `FAIL` — the breaking point is the first epoch with `verdict == FAIL`; earlier epochs remain `PASS`.

---

## Scenario File Schema

```jsonc
{
  "$schema": "trapdojo-scenario-0.2",
  "name": "ramp-to-failure-ebpf",
  "description": "Ramp v2c load until first failure with eBPF capture.",

  "hosts": {
    "generator": ["gen-01"],
    "sink":      "sink-01",
    "sut_primary":   "trapninja-p",
    "sut_secondary": "trapninja-s"
  },

  "safety": {
    "lab_allowlist": ["trapninja-lab-a"],
    "safe_rate_ceiling_tps": 100000
  },

  "acknowledgements": {
    "ramp_to_failure": true,
    "malformed_traffic": false,
    "spoofing_enabled": true,
    "rate_above_safe_ceiling_tps": null,
    "disruptive_actions": false
  },

  "generator": {
    "target_ip": "10.234.83.133",
    "target_port": 162,
    "worker_count": 8,
    "profile": {
      "type": "ramp",
      "warmup_s": 30,
      "start_rate_tps": 5000,
      "end_rate_tps":   80000,
      "step_tps":       5000,
      "dwell_s":        60,
      "settlement_timeout_s": 30,
      "cooldown_s":     60
    },
    "sources": {
      "requested_mode": "spoof",
      "allow_source_mode_fallback": false,
      "pool_ip_count": 5000,
      "pool_cidr": "10.234.100.0/20"
    },
    "oid_mix_ref": "oid-mixes/fibre-cut.json",
    "version_mix": { "v1": 0, "v2c": 100, "v3": 0 },
    "malformed": {
      "enabled": false,
      "classes": []
    },
    "abandon_after_retries": 3
  },

  "sink": {
    "listeners": [
      { "bind_ip": "10.234.83.140", "bind_port": 162, "destination_label": "primary-noc", "rcvbuf_bytes": 33554432 }
    ]
  },

  "sut": {
    "expected_capture_mode": "ebpf",
    "poll_interval_s": 5,
    "freeze_config_check": true
  },

  "clock": {
    "require_tai": true,
    "latency_max_offset_ns": 500000
  },

  "acceptance": {
    "input": {
      "unexplained_max_count": 0,
      "kernel_lost_max_fraction": 0.0,
      "queue_lost_max_fraction": 0.0,
      "parse_rejected_max_fraction": 0.0
    },
    "delivery": {
      "missing_max_fraction": 0.001,
      "multi_delivery_max_fraction": 0.0,
      "unexplained_max_fraction": 0.0
    },
    "queue_saturation_stop_ramp": true,
    "queue_wait_p99_ms_max": 1000,
    "rss_growth_fraction_per_min_max": 0.05,
    "ha_replay": {
      "expected_duplicate_max_fraction": 0.0
    }
  },

  "actions": []
}
```

**Validation (fail-closed):**

- Ramp-to-failure requires `acknowledgements.ramp_to_failure = true`.
- Malformed traffic requires `acknowledgements.malformed_traffic = true` **and** `generator.malformed.enabled = true` (both, so a scenario cannot request malformed without acknowledging).
- Spoofing requires `acknowledgements.spoofing_enabled = true`.
- Any epoch `target_rate_tps > safety.safe_rate_ceiling_tps` requires `acknowledgements.rate_above_safe_ceiling_tps` set to the exact value.
- All target/sink/CIDR fields must resolve to inventory entries whose `tags` intersect `safety.lab_allowlist`.
- `hosts.sut_*` must intersect `safety.lab_allowlist`.
- Freeform IPs that do not resolve to inventory are rejected.

---

## Report Schema

Defined by `report.json` above. Bumped via `report_schema_version` (starts at 1). Manifest and report schemas are versioned independently; the reporter refuses to render a report from a mismatched manifest schema.

---

## CLI Specification

```
trapdojo generate
    --scenario <path>          # normally driven by orchestrator; standalone allowed
    --run-id <str>
    --run-dir <path>
    --generator-id <int>       # required for multi-host generation
    [--dry-run]                # build templates, print manifest slice, do not send

trapdojo sink
    --scenario <path>
    --run-id <str>
    --run-dir <path>

trapdojo orchestrate
    --scenario <path>
    --run-id <str>              # default: auto-generated
    --run-dir <path>
    [--dry-run]                 # validate scenario + print planned SSH invocations

trapdojo report
    --run-id <str>
    --run-dir <path>
    [--format json|md|both]
    [--compare <run-id>]        # R3+; refuses across incompatible manifests

trapdojo selfcheck
    --loopback | --to <ip:port>
    --duration_s <int>
    --workers <int>
    (runs generator + sink on same or two hosts, measures ceilings, validates raw-network correctness)
```

---

## Configuration Files

Per-host `~/.config/trapdojo/config.json` (unchanged from v0.1 concept, expanded):

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
      "gen-01":       { "address_ip": "10.234.90.11",  "tags": ["trapninja-lab-a", "generator"] },
      "sink-01":      { "address_ip": "10.234.90.20",  "tags": ["trapninja-lab-a", "sink"] },
      "trapninja-p":  { "address_ip": "10.234.83.133", "tags": ["trapninja-lab-a", "sut"], "sudo": true, "trap_port": 162, "trap_vip": "10.234.83.133" },
      "trapninja-s":  { "address_ip": "10.234.83.134", "tags": ["trapninja-lab-a", "sut"], "sudo": true, "trap_port": 162 }
    }
  }
}
```

`trap_vip` and `trap_port` participate in [Traffic-Target Safety Validation](#traffic-target-safety-validation).

---

## Containerised Deployment

TrapDojo's canonical air-gap deployment artefact is a **single OCI image** built from `containers/Dockerfile` and containing all four subcommands (`generate`, `sink`, `orchestrate`, `report`, `selfcheck`). The same image runs every component. The image is signed and shipped as a tarball into the air-gap.

Bare-metal (Python venv + wheels) deployment remains supported for hosts where the operator explicitly needs it, but is not the default. Every claim below applies equally to both runtimes; only the invocation differs.

### Design principle

**The container adds no capability the bare-metal deployment does not have, and takes no capability away.** Every measurement is valid in either runtime provided the runtime is recorded in the manifest. `--compare` refuses to compare across runtime types.

### Security posture

- **Never `--privileged`.** Always the explicit capability list below. `--privileged` grants strictly more than TrapDojo needs and is opaque to the reproducibility manifest.
- **Default seccomp and AppArmor profiles are kept.** TrapDojo's syscalls (`socket`, `sendmmsg`, `recvmmsg`, `sched_setaffinity`, ordinary file I/O) are all allowed by Docker's default seccomp profile with `CAP_NET_RAW` granted, and by the `docker-default` AppArmor profile. Selfcheck confirms this on the target runtime; if a specific denial is observed, the offending profile is relaxed narrowly and the reason recorded in the deployment README.
- The air-gapped environment eliminates the network-borne threat models seccomp/AppArmor primarily defend against, but keeping the default profiles is strictly cheaper than relaxing them and gives operators one fewer thing to justify in an audit.

### Component-by-component container flags

**Orchestrator** — low-privilege by default:

```
docker run --rm \
    --user trapdojo:trapdojo \
    -v ~/.ssh:/home/trapdojo/.ssh:ro \
    -v /var/lib/trapdojo/runs:/var/lib/trapdojo/runs:rw \
    -v /var/lib/trapdojo/ssh-control:/var/lib/trapdojo/ssh-control:rw \
    -v /etc/trapdojo:/etc/trapdojo:ro \
    trapdojo:0.2.0 orchestrate --scenario /etc/trapdojo/scenarios/ramp-to-failure-ebpf.json
```

No host network, no elevated caps, no host bind-mounts beyond SSH keys and the run directory.

**Generator** — host network + `NET_RAW` for spoofing:

```
docker run --rm \
    --name trapdojo-gen \
    --network=host \
    --cap-add=NET_RAW \
    --cap-add=NET_ADMIN \
    --cpuset-cpus=0-7 \
    --ulimit rtprio=99 \
    --cap-add=SYS_NICE \
    -v /etc/trapdojo:/etc/trapdojo:ro \
    -v /var/lib/trapdojo/runs:/var/lib/trapdojo/runs:rw \
    -v /proc:/host/proc:ro \
    -v /sys:/host/sys:ro \
    -v /etc/os-release:/host/etc/os-release:ro \
    -v /var/run/chrony:/var/run/chrony:ro \
    -e TRAPDOJO_HOST_PROC=/host/proc \
    -e TRAPDOJO_HOST_SYS=/host/sys \
    -e TRAPDOJO_HOST_OS_RELEASE=/host/etc/os-release \
    trapdojo:0.2.0 generate --scenario /etc/trapdojo/scenarios/... --run-id ... --generator-id 1
```

Capability notes:

- `NET_RAW` enables raw sockets + `IP_HDRINCL` for spoofed sources.
- `NET_ADMIN` enables `ethtool -k` / `-S` and pcap operations required by selfcheck.
- `SYS_NICE` + `--ulimit rtprio=99` is reserved for future pacer real-time scheduling; harmless if unused.
- `--network=host` places the container in the host network namespace so spoofed IPs egress correctly and `/proc/net/*` reflects the real path.
- `/host/proc`, `/host/sys`, `/host/etc/os-release` bind mounts let `platform_probe.py` populate the reproducibility manifest with host values (kernel version, CPU model, NIC model, offload state, IRQ affinity) rather than container-local values.
- `/var/run/chrony` bind mount lets `chronyc tracking` / `chronyc sources -v` reach the host's chrony daemon.

**Sink** — host network + `NET_ADMIN` for `/proc/net/udp` visibility:

```
docker run --rm \
    --name trapdojo-sink \
    --network=host \
    --cap-add=NET_ADMIN \
    --cpuset-cpus=8-11 \
    -v /etc/trapdojo:/etc/trapdojo:ro \
    -v /var/lib/trapdojo/runs:/var/lib/trapdojo/runs:rw \
    -v /proc:/host/proc:ro \
    -v /sys:/host/sys:ro \
    -v /etc/os-release:/host/etc/os-release:ro \
    -v /var/run/chrony:/var/run/chrony:ro \
    -e TRAPDOJO_HOST_PROC=/host/proc \
    -e TRAPDOJO_HOST_SYS=/host/sys \
    -e TRAPDOJO_HOST_OS_RELEASE=/host/etc/os-release \
    trapdojo:0.2.0 sink --scenario /etc/trapdojo/scenarios/... --run-id ...
```

The sink does not need `NET_RAW` (no raw sockets), only `NET_ADMIN` for reading per-socket drop counters exposed under the host netns.

### Host preparation

These items must be set on the *host* at deploy time. They are identical to what bare-metal deployment would need, so the Ansible role that provisions the host is unchanged:

| Item | Value | Set by |
|---|---|---|
| `net.core.rmem_max` | `≥ 33554432` (32 MiB) | sysctl drop-in in `containers/profiles/` |
| `net.core.wmem_max` | `≥ 33554432` | sysctl drop-in |
| CPU governor on measurement hosts | `performance` | systemd unit or Ansible task |
| `chronyd` running with a good source | — | Existing lab config |
| NIC offload state | Per scenario (documented per run) | `ethtool -K` at host prep time |
| Firewall / uRPF permitting spoofed egress | — | Lab network config |
| `trapdojo` UID/GID on host | For `--user` and bind-mount ownership | Ansible task |

The container never modifies host sysctls or firewall state at runtime.

### Manifest `runtime` field

`environment.<host>` gains a `runtime` block populated at run start:

```jsonc
"runtime": {
  "type": "container",                          // "container" | "bare_metal"
  "container_engine": "docker",                 // "docker" | "podman" | "containerd"
  "container_engine_version": "25.0.3",
  "image_ref": "trapdojo:0.2.0",
  "image_digest": "sha256:…",
  "network_mode": "host",
  "cap_add": ["NET_RAW", "NET_ADMIN", "SYS_NICE"],
  "cap_drop": [],
  "seccomp_profile": "default",                 // or "unconfined" if relaxed
  "apparmor_profile": "docker-default",         // or "unconfined"
  "cpuset_cpus": "0-7",
  "host_bind_mounts": [
    "/proc:/host/proc:ro",
    "/sys:/host/sys:ro",
    "/etc/os-release:/host/etc/os-release:ro",
    "/var/run/chrony:/var/run/chrony:ro"
  ]
}
```

Bare-metal runs record `{"type": "bare_metal", "container_engine": null, ...}` — the same schema, so the reporter never branches on runtime.

### `--compare` refusal rule

The comparison reporter (R5) refuses to compare two runs whose `runtime.type`, `runtime.container_engine`, `runtime.container_engine_version`, `runtime.seccomp_profile`, or `runtime.apparmor_profile` differ. Runs may be re-baselined (a fresh selfcheck ceiling on the new runtime) before comparison resumes. This is the same discipline already applied to source-mode and NIC differences.

### Container-vs-bare-metal parity experiment

R0/R1 selfcheck adds a mandatory parity measurement on lab hardware:

1. Run `trapdojo selfcheck --loopback --duration_s 300 --workers 8` on bare-metal.
2. Run the same selfcheck under the container image on the same host, same flags.
3. Compare achieved offered rate, pacing lateness p99, sink received rate, and RSS growth.

Acceptance:

- Delta ≤ 1% of ceiling on all four metrics → publish one qualified ceiling; runtime overhead is documented as noise.
- Delta > 1% → publish two ceilings (container / bare-metal); scenarios choose the runtime they require; `--compare` refusal already prevents cross-comparison.

The delta measurement itself becomes part of the R1 exit artefact.

### What the container does NOT change

- Wire format, accounting model, verdict semantics, safety interlocks — all identical.
- Scenario schema, manifest schema, report schema — identical; only the `runtime` block is added.
- CLI commands and flags — identical.
- The Ansible role that provisions the host — essentially identical (still installs the sysctl drop-in and governor unit; adds container-engine install and image load; drops the venv install).

---

## SNMP Version Handling

**R1: v2c only.** All templates emitted by R1 are SNMPv2c `snmpV2-Trap` PDUs.

**v1 (design specified; implementation R3).** SNMPv1 uses a distinct top-level Trap-PDU with fields (enterprise, agent-addr, generic-trap, specific-trap, time-stamp, variable-bindings). It is not a superficial variant of v2c. `template_v1.py` will implement it with its own encoder. The identity varbind semantics are unchanged.

**v3 (blocked until R5 contract).** Patching an encrypted identity per packet is not valid due to CBC/CFB diffusion. R1–R4 do not emit v3 traps. The R5 contract must specify, before any v3 code is written:

- USM engine ID selection.
- Engine boots/time behaviour.
- Authentication protocol.
- Privacy protocol.
- Salt/IV uniqueness policy at generator rates.
- Per-packet encryption cost budget.
- Replay behaviour on the wire.
- How the identity survives TrapNinja's v3→v2c conversion (which is where the sink normally observes it).
- Credential storage and end-of-run cleanup.

Any TrapDojo scenario with `version_mix.v3 > 0` before R5 is refused at scenario load.

---

## Malformed Traffic Accounting

Malformed traffic is opt-in and is **excluded from delivery obligations**. It exists to exercise TrapNinja's slow-path and robustness.

### Malformed classes (R3 implementation; classes reserved now)

| Class | Definition | TrapNinja expected counter |
|---|---|---|
| `invalid_ber_length` | Length prefix declares more bytes than the datagram carries | `trapninja_parse_rejected_total{reason="ber_length"}` |
| `truncated_message` | Datagram shorter than declared SNMP message length | `trapninja_parse_rejected_total{reason="truncated"}` |
| `unsupported_version` | SNMP version byte is not 0/1/3 | `trapninja_parse_rejected_total{reason="version"}` |
| `bad_community` | Community string not in TrapNinja's allowed set | `trapninja_blocked_total{reason="community"}` |
| `invalid_v3_auth` | v3 message with bad HMAC | `trapninja_parse_rejected_total{reason="v3_auth"}` |
| `oversized_datagram` | UDP payload > TrapNinja receive buffer | Kernel drop or `parse_rejected` (documented per case) |
| `valid_identity_bad_pdu` | Identity varbind valid, surrounding PDU malformed | Sink counts identity in a `foreign_valid_identity` bucket; not a delivery obligation |

For each enabled class the scenario declares:

```jsonc
"malformed": {
  "enabled": true,
  "classes": [
    { "class": "invalid_ber_length", "fraction_of_traffic": 0.01, "expected_trapninja_reason": "ber_length" },
    { "class": "unsupported_version","fraction_of_traffic": 0.005, "expected_trapninja_reason": "version" }
  ]
}
```

The reporter cross-checks that each class's expected counter incremented by approximately the offered malformed count in the epoch (within tolerance). No malformed traffic ever enters delivery-obligation accounting.

---

## Raw-Network Qualification

### Documented behaviour (generator)

| Aspect | Policy |
|---|---|
| MTU | Default 1500. Traps built to ≤ `mtu_bytes - 28` (IPv4 + UDP headers). |
| Fragmentation | Not permitted for well-formed traffic. IP DF bit set. Oversized traps are only produced by the `oversized_datagram` malformed class. |
| Maximum supported trap bytes | `mtu_bytes - 28`; validated at template build time; over-budget templates → refuse-to-start. |
| IP total-length | Computed correctly per packet in raw-socket path. |
| IP ID | Random-per-packet in raw-socket path (never zero). |
| IP header checksum | Computed correctly per packet; not offloaded because raw socket bypasses tx offload for the IP header. |
| UDP checksum | Computed correctly per packet (pseudo-header depends on source IP for spoofed sources). Verified in R0 selfcheck via pcap. |
| Source port | Random per stream, stable within a stream, to keep RSS/hash behaviour predictable. |
| Destination port | Scenario `target_port`. |
| NIC offloads | Selfcheck detects (`ethtool -k`) and records: `tx-checksum-*`, `tso`, `gso`, `gro`, `rx-checksum`. Any offload that could rewrite headers on raw egress produces a manifest warning. |
| Spoofing egress | Egress interface is recorded; anti-spoofing (uRPF) state on adjacent switch is not observable by TrapDojo but its effect is measured by the probe. |

### Qualification (selfcheck)

`trapdojo selfcheck --to <ip:port> --duration_s 30 --capture /tmp/gen.pcap` produces a pcap at generator egress. The selfcheck reporter validates:

- Every captured packet is a valid IP/UDP frame with correct checksums.
- SNMP payload parses back to the identity we intended.
- Observed wire packet rate matches `achieved_offered_rate_tps` from the ledger within tolerance (default 1%).

R2 selfcheck extends this by taking a pcap at SUT ingress and cross-checking arrival count.

---

## Source Simulation Mode Discipline

### Modes

- **`spoof`** — raw socket with `IP_HDRINCL`, generator writes IP header, source IP chosen from `pool_cidr` deterministically per `(stream_id, seq)` for reproducibility.
- **`alias`** — N `ip addr add` aliases on the generator NIC; worker binds one AF_INET UDP socket per alias and round-robins.
- **`localhost`** — for selfcheck only; single source.

### Probe

At `EPOCH_PROBE` (epoch_id 0) the generator emits `probe.packets_sent` packets and the sink reports observed count. Manifest records both.

### Fallback discipline

If `requested_mode == spoof` and the probe observes < 95% of sent probe packets **and** `allow_source_mode_fallback == false`, the orchestrator aborts with `ABORTED` and a structured reason. It does not silently switch.

If `allow_source_mode_fallback == true`, the orchestrator retries in `alias` mode. Effective mode, effective source count, and fallback reason are recorded in the manifest and displayed prominently in `report.md`.

### Comparison discipline

Comparison reports (`--compare`) refuse to compare two runs whose `effective_mode` differ or whose `pool_ip_count_effective` differ by more than a scenario-declared tolerance. Silent "apples-to-oranges" comparison is impossible.

---

## Traffic-Target Safety Validation

Before `START_GENERATOR`, the orchestrator validates:

1. `generator.target_ip:generator.target_port` matches `trap_vip:trap_port` (or `address_ip:trap_port`) of a host in inventory whose `tags` intersect `safety.lab_allowlist`.
2. `generator.sources.pool_cidr` is entirely contained in a CIDR block declared for the lab in inventory (`inventory.labs.<name>.source_cidrs`). Freeform CIDRs outside any declared lab block are refused.
3. Every `sink.listeners[i].bind_ip` resolves to `sink-01`'s address (as declared in inventory).
4. `scenario.acknowledgements` covers every capability the scenario intends to use (ramp-to-failure, malformed, spoofing, rate above ceiling, disruptive actions). Missing acknowledgement → refuse.
5. `scenario.safety.safe_rate_ceiling_tps` is present. Any epoch above ceiling requires `acknowledgements.rate_above_safe_ceiling_tps` set to the exact ceiling override.

`trapdojo orchestrate --dry-run` prints the validation table (each check with `ok/fail` + reason) and every SSH invocation that would run.

---

## SUT Counter Uncertainty Handling

The orchestrator's collector handles the following events **explicitly** — no interval is treated as merely "somewhat trustworthy":

| Event | Detection | Response |
|---|---|---|
| Counter reset (delta < 0) | Delta computation | Invalidate the interval; mark epoch `INVALID` if any critical counter is affected |
| Process restart | `trapninja_process_start_tai_ns` changed | Reset baseline; invalidate the interval that straddles the restart |
| Counter wraparound | Wrap detected via type width (`uint64` never wraps in practice; treat any observed wrap as reset) | Same as reset |
| Label-set change | New label key or missing expected label | Invalidate the interval; require operator ack in `report.md` |
| HA role change | HA state metric changed | Do not merge counters across the role change; classify the transition as its own timeline event |
| Missing sample | SSH failure or poll timeout | Two consecutive misses → invalidate the interval; three misses → abort the run as `ABORTED` |
| Delayed `.prom` update | `.prom` file mtime older than poll interval × 2 | Invalidate the affected samples |
| Non-atomic snapshot | Two counters obviously inconsistent (e.g. `accepted > offered`) | Invalidate the interval |
| Export-interval skew between HA nodes | Different `.prom` write intervals | Recorded; per-node analysis, no attempt to sum across |

**TrapNinja prerequisites (REQUIRED — must land in TrapNinja before R2 collector work begins):**

These three additions are small, well-scoped, and each has a specific correctness role. TrapDojo cannot ship R2 without them because the alternatives all silently corrupt delivery-obligation accounting.

| Requirement | Purpose | Failure mode if absent |
|---|---|---|
| **P1. `trapninja_process_start_tai_ns` gauge** — exported in `.prom` and `trapninja metrics show --json`, value = process start time in `CLOCK_TAI` nanoseconds. Set once at daemon startup. | Lets the orchestrator detect a TrapNinja process restart between two polls atomically and reset the delta baseline exactly at that boundary. | A restart between polls looks like a counter reset; the entire straddling interval is invalidated instead of just the restart boundary, and epochs that were actually healthy become `INVALID`. |
| **P2. `trapninja_metrics_snapshot_id` counter** — increments by 1 on every `.prom` export write (and every `metrics show --json` call). | Lets the orchestrator detect torn reads: a `.prom` file read while it is being rewritten produces an inconsistent counter set; the snapshot id lets the reader retry until it sees a stable id. | Non-atomic snapshots occasionally produce impossible relationships between counters (e.g. `accepted > offered`), which the uncertainty rules classify as `INVALID` — legitimate runs are marked `INVALID` for a rig-side reading problem. |
| **P3. `trapninja config show --json --canonical`** — deterministic canonical JSON of forwarding, filter, redirection, destinations, and SNMPv3 credentials-by-name (never material). Sorted keys, no whitespace ambiguity, integer-vs-string encoding pinned. | Lets TrapDojo hash the frozen forwarding config (`fwd_config_sha256`, `filter_config_sha256`, `destinations_config_sha256` in the manifest) and derive the expected delivery-obligation set reproducibly. | Non-canonical output produces different hashes for identical configs; comparison reports either misfire or force TrapDojo to reimplement TrapNinja's config semantics itself — a maintenance liability we will not accept. |

Additional invariants (already required by TrapNinja's own rules, restated here so the R2 collector can rely on them):

- `.prom` writes are atomic (`.tmp` + `os.rename`).
- Counter names/labels do not change within a running process; a label-set change implies a code deploy and a process restart, which P1 will disambiguate.
- Every counter exported in `.prom` is also available in `trapninja metrics show --json` under the same name and labels.

Pre-run and post-drain snapshots of every SUT counter are always taken and included verbatim in the manifest.

---

## Reproducibility Evidence

Manifest `environment.<host>` block for every host:

```jsonc
{
  "os": { "distro": "rhel", "version": "8.10", "kernel": "4.18.0-…" },
  "runtime": {
    "type": "container",
    "container_engine": "docker",
    "container_engine_version": "25.0.3",
    "image_ref": "trapdojo:0.2.0",
    "image_digest": "sha256:…",
    "network_mode": "host",
    "cap_add": ["NET_RAW", "NET_ADMIN"],
    "seccomp_profile": "default",
    "apparmor_profile": "docker-default",
    "cpuset_cpus": "0-7"
  },
  "cpu": {
    "model": "…",
    "logical_cpus": 32,
    "allocated_cpus": [0,1,2,3,4,5,6,7],
    "governor": "performance"
  },
  "nic": {
    "iface": "eth1",
    "model": "Mellanox …",
    "speed_gbps": 25,
    "mtu_bytes": 1500,
    "offloads": { "tx_checksum_ipv4": "off", "tso": "off", "gso": "off", "gro": "on" }
  },
  "irq": { "rps_cpus": "0-7", "rfs_entries": 32768, "affinity_hint": "…" },
  "socket_buffers": { "net_core_rmem_max_bytes": 268435456, "net_core_wmem_max_bytes": 268435456 },
  "link_counters_start": { "rx_dropped": 0, "tx_dropped": 0, "rx_errors": 0, "tx_errors": 0 },
  "link_counters_end":   { "rx_dropped": 0, "tx_dropped": 0, "rx_errors": 0, "tx_errors": 0 },
  "resource_start": { "rss_bytes": 68000000, "fd_count": 42 },
  "resource_end":   { "rss_bytes": 71000000, "fd_count": 42 }
}
```

Manifest also records:

- `trapdojo.version` and `trapdojo.git_commit`.
- `trapninja.version`, `trapninja.git_commit` (from `trapninja --version --json`), and `trapninja.package_build_id` where present.
- `scenario_sha256`, `fwd_config_sha256`, `filter_config_sha256`, `destinations_config_sha256`, `oid_mix_sha256`.

Reporter comparison (`--compare`, R3+) validates:

- Same `wire.wire_version`.
- Same or compatible `manifest_schema_version` and `report_schema_version`.
- Same `runtime.type`, `runtime.container_engine`, `runtime.container_engine_version`, `runtime.seccomp_profile`, `runtime.apparmor_profile`.
- Same `nic.model`, `nic.speed_gbps`, `nic.mtu_bytes`.
- Same `cpu.governor`, same `allocated_cpus` count.
- Same effective source mode and pool size (within tolerance).

Any mismatch is rendered as an "INCOMPATIBLE ENVIRONMENTS" banner in the comparison report and no headline throughput is compared numerically.

---

## Observability of the Rig Itself

- Generator writes `ledger.jsonl` continuously and a summary on SIGTERM.
- Sink writes `partial.jsonl` every 5 s and `final.json` on stop, plus a per-epoch checkpoint file.
- Orchestrator writes `timeline.jsonl` for every state transition, every SSH invocation, every action.
- Both hot-path components accept `--stats-port <int>` optional HTTP endpoint for live curl-based inspection.
- Structured stderr logs; systemd + journald handle rotation.

---

## Testing Strategy

`dev/tests/` mirrors TrapNinja layout. Tests are grouped by phase gate.

### Unit (offline, no sockets)

- `test_wire.py` — pack/unpack v2 identity; round-trip; malformed inputs rejected.
- `test_ledger.py` — accepted/abandoned interval merging; adjacency; finalise.
- `test_gap_tracker.py` — insert/dup/finalise against a ledger; property tests via `hypothesis` if bundled offline.
- `test_reconcile_input.py` — input equation over synthetic manifest + generator/SUT files.
- `test_reconcile_delivery.py` — obligation set derivation over filter/redirection/fan-out configs; classification correctness.
- `test_confidence.py` — mapping table; asserts `temporally_correlated` never becomes `proven`.
- `test_rate.py` — deadline pacer produces correct grants and lateness metrics under a fake clock; no cumulative drift over 10⁶ steps.
- `test_scenario.py` — schema validation; unit-suffix enforcement; acknowledgement gates; safety allowlist checks.
- `test_extractor.py` — magic collision, wrong run token, unknown stream, short datagram, `MSG_TRUNC`, stale buffer, malformed BER, valid-identity-bad-PDU.
- `test_partial_sendmmsg.py` — worker retries unsent tail with same seq; abandoned range recorded.
- `test_reordering.py` — sink handles arbitrary permutations of a stream without corrupting duplicate/missing counts.
- `test_duplicate_missing.py` — one missing + one unrelated duplicate produces FAIL.
- `test_fanout.py` — one obligation to two destinations; loss on one destination only produces per-destination FAIL, not aggregate FAIL.
- `test_redirection.py` — redirection removes obligation from destination A, adds to destination B; verdicts respect this.
- `test_filter.py` — filter removes obligation entirely; delivery accounting reflects `not_expected_filtered`.
- `test_dest_forward_failure.py` — TrapNinja records N forward failures in an epoch; reporter attributes at `temporally_correlated` confidence, never `proven`.
- `test_delayed_drain.py` — obligations satisfied post-dwell but pre-settlement produce PASS.
- `test_epoch_boundary.py` — sequences from epoch 1 and epoch 2 do not cross-contaminate counters.
- `test_counter_reset.py` — reset detected via `process_start_tai_ns` change → interval invalidated.
- `test_missing_metrics.py` — two consecutive missing polls → INVALID; three → ABORTED.
- `test_listener_restart.py` — simulated listener crash triggers supervisor restart; epoch marked INVALID.
- `test_sink_kernel_drops.py` — non-zero `/proc/net/udp` delta → INVALID.
- `test_negative_delta.py` — negative counter delta → invalidate; never resolves to negative loss.
- `test_gen_underachievement.py` — requested 50k tps but achieved 30k tps → INVALID, verdict_scope = "rig".
- `test_clock_invalid.py` — pre/post clock offset above threshold → latency INVALID; delivery still evaluable.
- `test_source_mode_no_fallback.py` — spoof probe fails and `allow_source_mode_fallback: false` → ABORTED.
- `test_termination.py` — SIGTERM mid-run produces ABORTED with partial evidence; SIGKILL of a worker produces ABORTED.

### Integration (localhost loopback)

- `test_loopback_baseline.py` — 1k tps × 10 s, verdict PASS, unexplained_count = 0.
- `test_loopback_ramp.py` — 1k → 10k, monotonic ledger, no false gaps at epoch transitions.
- `test_loopback_rcvbuf_undersized.py` — undersized `SO_RCVBUF`; verdict INVALID, scope = "rig".
- `test_loopback_dry_run.py` — every shipped scenario passes `--dry-run`.
- `test_loopback_pcap_valid.py` — generator egress pcap parses and all packets round-trip.
- `test_container_bare_metal_parity.py` — same loopback baseline in the container image and bare-metal on the same host; asserts ≤ 1% delta on achieved offered rate, pacing lateness p99, sink received rate, and RSS growth. Delta value recorded in the R1 exit artefact regardless of pass/fail.

### Property-based tests (if `hypothesis` bundleable)

- Interval math (accepted/received/abandoned): union, intersection, gap computation over random inputs.
- Reconciliation: for any generator ledger and any sink observation, the invariant

  ```
  obligations_total == satisfied + missing + not_expected + duplicates_beyond_first
  ```

  holds; a duplicate never reduces `missing`.

### Not tested in R1

- Real SSH, real SUT, real Redis, real HA. Move to R2+ with a lab.

---

## Performance Budgets & Validation

Budgets validated by `trapdojo selfcheck` on lab hardware before any SUT conclusion is trusted:

| Component | Metric | Target |
|---|---|---|
| Generator | Per-worker successfully-offered rate (loopback, 128-batch sendmmsg, 200-byte packets) | ≥ 30,000 tps |
| Generator | Aggregate successfully-offered rate, 8 workers | ≥ 100,000 tps |
| Generator | Ledger accepted rate matches wire pcap count | equal within tolerance ≤ 0.01 fraction |
| Generator | Steady-state allocations after warm-up | measured & reported (target: near zero) |
| Generator | Pacing lateness p99 at target rate | ≤ 1 ms |
| Sink | Single-listener received rate (loopback recvmmsg, 128-batch) | ≥ 120,000 tps; **qualified ceiling written into manifest** |
| Sink | `unexplained` in loopback baseline | 0 |
| Sink | Kernel drops in loopback baseline at 100k tps | 0 |
| Orchestrator | SUT poll overhead per poll (multiplexed SSH + parse) | ≤ 100 ms |
| Clock | Estimated max offset across all hosts, pre/post | ≤ 500 µs (default; scenario-adjustable) |
| Runtime parity | Container vs bare-metal delta on achieved offered rate, pacing lateness p99, sink received rate, RSS growth | ≤ 1% of ceiling on all four (or two ceilings published) |

Selfcheck must PASS on lab hardware **before** the R2 exit criterion is claimed.

---

## Build Phases & Gates

### R0 — Accounting and Protocol Proof (new gate)

Deliverables:
- Final wire format (this document's v2) with byte-exact spec.
- `core/ledger.py`, `core/obligation.py`, `core/wire.py`, `core/template.py` (v2c encoder).
- `reporting/reconcile_input.py`, `reporting/reconcile_delivery.py`, `reporting/confidence.py`.
- Synthetic reconciliation tests (all unit tests listed above under [Testing Strategy](#testing-strategy)).
- Partial-send and epoch-boundary tests.

Exit criterion: every synthetic edge case produces an unambiguous correct verdict.

### R1 — v2c Generator and Single-Process Sink

Deliverables:
- `generator/` (all modules).
- `sink/` (single-process listener; extractor; gap tracker against ledger; drop monitor).
- `cli/generate.py`, `cli/sink.py`, `cli/selfcheck.py`.
- Loopback integration tests.
- Two-host self-check with pcap validation.

Exit criterion: rig sustains its qualified ceiling with zero unexplained input loss and zero rig-side drops, verified by pcap.

### R2 — Orchestration and SUT Metrics

Deliverables:
- `orchestrator/` (all modules), `reporting/report_json.py`, `reporting/report_md.py`.
- Lifecycle state machine with settlement barriers.
- SUT counter uncertainty rules.
- `cli/orchestrate.py`, `cli/report.py`.
- Single-destination baseline and ramp scenarios.

Exit criterion: `ramp-to-failure` produces a defensible, reproducible breaking point with confidence-labelled attribution and correct PASS/FAIL/INVALID classification.

### R3 — Scale and Complex Delivery

- Multi-source spoofing at scale, malformed classes, multi-destination routing (fan-out + redirection), burst profiles, SNMPv1 implementation.
- Sink multi-listener via offline-union option.

### R4 — HA and Dependency Disruption

- Action injector for destructive scenarios (with all safety controls proven in R2).
- Failover, Redis outage, split-brain.

### R5 — SNMPv3 and Comparison Reporting

- v3 contract signed off before any code.
- `--compare` regression reports with incompatible-environment refusal.

---

## Open Design Questions

Only genuinely unresolved decisions remain. Four items previously in this list (identity OID, TrapNinja metrics prerequisites, canonical-config CLI, `chronyd`-based clock discipline) were resolved by product review on 2026-08-11 and are now normative in the sections above.

1. **`hypothesis` in offline dependency bundle.** Property-based tests are strongly desired for interval math (ledger vs received-set vs obligation-set) and reconciliation invariants. Decide inclusion in `dev/scripts/download-packages.sh` before R0 test bring-up. Concrete example tests are drafted in the R0 test plan to inform the decision.
2. **v3 contract (R5).** Full USM/engine/salt/authentication policy — deferred but tracked. See [SNMP Version Handling](#snmp-version-handling) for the required contract content.

### Resolved (2026-08-11)

| # | Question | Resolution |
|---|---|---|
| 1 | Enterprise OID arc | Use `.1.3.6.1.3.5850.1.1` under the IANA-reserved experimental subtree `1.3.6.1.3` (RFC 1155). Baked into templates; documented in [Wire Format](#wire-format-byte-exact-v2). |
| 3 | `CLOCK_TAI` in the lab | `chronyd` confirmed running on every host. `chronyc tracking` / `chronyc sources -v` are the sync-health source. Manifest records `tai_offset_applied` per host; degradation to `CLOCK_REALTIME` is explicit, never silent. See [Clock Model](#clock-model). |
| 4 | TrapNinja metrics prerequisites | Elevated to **REQUIRED** in [SUT Counter Uncertainty Handling](#sut-counter-uncertainty-handling): `trapninja_process_start_tai_ns` (P1) and `trapninja_metrics_snapshot_id` (P2). Must land before R2. |
| 5 | Canonical-config CLI prerequisite | Elevated to **REQUIRED** in [SUT Counter Uncertainty Handling](#sut-counter-uncertainty-handling): `trapninja config show --json --canonical` (P3). Must land before R2. |

---

*Next step: decide on Q1 (`hypothesis` bundle), then produce the R0 implementation prompt for `core/` + `reporting/reconcile_*` + the synthetic-test harness.*
