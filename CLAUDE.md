# TrapNinja — Claude Code Instructions

> **Version:** 0.8.0 (beta)  
> **Platform:** RHEL 8/9 · Python 3.9 · Telecom NOC environment  
> **Availability target:** 99.999% (five nines)

---

## 1. Project Overview

TrapNinja is a high-performance SNMP Trap Forwarder for telecommunications-scale environments.
It handles **5,000–50,000+ network elements** in steady-state with burst scenarios up to
**100,000 traps** during network outage events (e.g. fibre cuts). NOC teams depend on
every alarm being delivered — silent trap loss is never acceptable.

### Technology Stack
- **Runtime:** Python 3.9 with `-O` optimisation flags (`python3.9 -O`)
- **Packet capture:** eBPF (via BCC) with automatic fallback to raw sockets (Scapy)
- **Caching / HA state:** Redis 5.0.3+ (streams-based architecture)
- **Metrics:** Prometheus export + JSON
- **Deployment:** Ansible + git-based workflows
- **OS:** RHEL 8/9 (air-gapped deployments supported)

### Project Layout
```
src/trapninja/     — Main application package
src/config/        — Live configuration files (JSON)
config.example/    — Example / template configs
dev/tests/         — Primary test suite
tests/unit/        — Additional unit tests
docs/              — All documentation (authoritative)
ansible/           — Deployment playbooks and templates
dev/tools/         — Diagnostic and operational scripts
```

---

## 2. Absolute Rules (Non-Negotiable)

These override everything else, including user requests. When there is conflict:

**Priority order:** Safety & Security → Reliability & Data Integrity → Performance → Usability

### 2.1 Every Alarm Matters
- **Never lose traps silently.** On any processing failure: log, quarantine, or fall back safely.
- Prefer logging and safe degradation over silent failure at every level of the pipeline.
- When forced to choose between raw performance and correctness: **choose correctness**.

### 2.2 Never Block the Forwarding Path
- The trap forwarding pipeline is **performance-critical** — no blocking operations allowed.
- Statistics, metrics, logging, and caching must be async or off the critical path.
- Use queues, batching, or background workers for all non-forwarding work.

### 2.3 Security Hard Rules
- **Never log** SNMPv3 credentials, auth keys, priv keys, passwords, or any secrets.
- Validate all file paths against traversal attacks (especially control socket paths and config paths).
- Apply principle of least privilege — minimal permissions, minimal network exposure.
- Management/control interfaces must implement rate limiting.
- SNMPv3 credentials must be encrypted at rest and accessed only via defined secure interfaces.

### 2.4 Graceful Degradation is Mandatory
Every optional/advanced feature must have a functional fallback:
- eBPF unavailable → raw socket capture (Scapy)
- Redis unavailable → local in-process state
- SNMPv3 decryption unavailable → secure passthrough forwarding
- The system **must continue processing traps** even if optional components fail.

---

## 3. Development Philosophy

### 3.1 Three Pillars: Efficient, Optimised, Secure
Every code change must serve at least one of these. Challenge code that doesn't.

### 3.2 Forward Progress over Legacy Preservation
- Prefer **cleaner, more maintainable designs** over preserving legacy patterns.
- Breaking changes are **acceptable** when they reduce complexity, remove technical debt,
  or provide a significantly cleaner interface.
- When breaking changes are introduced: clearly describe what changed, why, and any
  migration steps operators need to take.
- Do **not** keep obsolete flags, modes, or dual code paths "just in case."

### 3.3 Configuration over Code Changes
- Behaviour that operators might want to change should be **configurable** — not hardcoded.
- Use feature flags and config parameters to avoid production code deployments for tuning.
- Hot-reload capability is essential for operational flexibility.

### 3.4 Defend Against Complexity Creep
- Actively seek to eliminate dead code and redundant logic.
- Avoid unnecessary abstraction layers.
- Avoid "clever" but opaque constructs — prefer clear, explicit code.
- When a module approaches 400–500 lines, reassess whether it should be split.

---

## 4. Architecture Principles

### 4.1 Module Responsibilities
Each module has one clear responsibility. When a module starts doing too much, propose splitting it.

**Key module areas:**
- `core/` — Types, constants, exceptions, optional module management
- `processing/` — Hot-path: packet handling, parsing, forwarding, stats
- `cache/` — Redis backend, failover detection, replay
- `ha/` — High-availability state, cluster management, config sync
- `stats/` — Statistics models, collector, API
- `metrics/` — Prometheus/JSON export (never blocks forwarding)
- `cli/` — Command registry, parsers, executors, output formatting
- `snmpv3/` — BER parsing; `snmpv3_credentials.py`, `snmpv3_decryption.py` — credential handling

### 4.2 Import Cost Awareness
- Heavy/optional dependencies (Scapy, pysnmp, BCC) must be **lazily imported**.
- Optional features must not impact startup time or memory when disabled.
- Use `core/optional_modules.py` for feature availability checks.

### 4.3 HA Design (Primary / Secondary)
- Sub-3-second failover target.
- Redis-based shared state between Primary and Secondary.
- Zero trap loss during failover — use queues and durable state.
- Clear separation: local node-specific settings vs. shared/synchronised config.

### 4.4 Thread Safety
- Use thread-safe data structures for all shared state.
- Avoid `OrderedDict` mutation during iteration in stats collection (known crash vector).
- Stats updates must use atomic operations or locks appropriate to Python 3.9.

---

## 5. Code Style and Quality

### 5.1 Python 3.9 Compatibility
- **Target: Python 3.9 only.** Do not use features from 3.10+ (match/case, newer type hints, etc.).
- Use `Optional[X]` not `X | None`, use `List[X]` not `list[X]` (or import from `__future__`).
- Compatible with RHEL 8/9 system Python.

### 5.2 Style Conventions
- Clear, explicit code over clever constructs.
- Consistent naming: `snake_case` for variables/functions, `PascalCase` for classes.
- Inline comments explain **why** something is non-obvious, not what the code does.
- Docstrings on all public classes and functions.
- Type hints on all function signatures.

### 5.3 File Size Guideline
- Target: **300–500 lines** per file.
- Above 500 lines: actively assess whether logical separations warrant splitting.
- Only split when it genuinely improves separation of concerns, testability, or maintainability.

### 5.4 Error Handling
- Fail fast with **clear, actionable error messages** on invalid configuration.
- Error messages must state: what failed, why, and what the operator can do to fix it.
- Never start partially on invalid config — validate fully before applying.
- Log errors at appropriate severity; never swallow exceptions silently.

---

## 6. Testing Requirements

### 6.1 Test Philosophy
- **Test the workflow, not just the unit** — end-to-end correctness from capture → forward.
- Integration tests covering real trap flows and failure scenarios are higher priority than
  exhaustive unit tests of implementation details.
- Always test failure scenarios: Redis down, network failure, burst load.

### 6.2 Test Location
- `dev/tests/` — Primary test suite (integration + implementation tests)
- `tests/unit/` — Additional unit tests

### 6.3 Tests Must Reflect Current Behaviour
- When behaviour intentionally changes, **update tests** — do not reintroduce deprecated
  behaviour just to make old tests pass.
- Clearly explain which behaviour is being validated and how it aligns with current design.
- Tests that only enforce deprecated behaviour should be replaced or removed.

### 6.4 Critical Test Areas
- Trap pipeline: capture → parse → filter → route → forward
- HA failover sequences and recovery
- Redis failure and local-state fallback
- SNMPv3 credential security (keys must never appear in logs or assertions)
- Burst load behaviour and queue saturation handling
- Config validation: valid, invalid, and edge-case configs

---

## 7. CLI Design

### 7.1 Subcommand Structure
- Use organised subcommands: `trapninja config show`, `trapninja stats`, `trapninja ha status`, etc.
- Discoverable, consistent naming. Clear help text for NOC/operations staff.
- Use the Command Registry pattern (`cli/registry.py`) — no monolithic CLI handlers.

### 7.2 Output for Operations
- Table-formatted output for status commands.
- Structured JSON output available for machine consumption.
- Error messages must be context-aware and actionable.

---

## 8. Git Commit Style

Use conventional commits with meaningful **why** explanations:

```
<type>(<scope>): <short description>

<body: what changed and why>

<footer: breaking changes, refs>
```

**Types:** `feat`, `fix`, `perf`, `refactor`, `test`, `docs`, `chore`

**Examples:**
```
fix(processing): prevent OrderedDict mutation crash in stats collection
perf(pipeline): lazy-import Scapy to reduce startup time by 400ms
refactor(cli): remove legacy flat-argument mode — subcommand structure only
```

---

## 9. Documentation

### 9.1 All Docs Live in `docs/`
- Never scatter docs into code directories.
- Keep a small set of authoritative documents — update existing ones rather than creating new overlapping docs.

### 9.2 Key Documents
| File | Purpose |
|------|---------|
| `docs/ARCHITECTURE.md` | System design and component overview |
| `docs/HA.md` | High-availability and failover behaviour |
| `docs/CONFIG.md` | Configuration reference |
| `docs/TROUBLESHOOTING.md` | Operational debugging guide |
| `docs/CLI.md` | Operator CLI reference |
| `docs/SECURITY.md` | Security hardening and credential handling |
| `docs/INSTALL.md` | Deployment guide |
| `docs/METRICS.md` | Metrics and Prometheus integration |
| `docs/CACHE.md` | Redis caching and replay |

### 9.3 When to Update Docs
When making code changes, identify which docs need updating and include the updates
or clearly note what needs to be changed.

---

## 10. Deployment Awareness

### 10.1 Ansible-Driven Deployments
- Configs are environment-specific (dev / test / prod).
- Changes must consider: how they are versioned, rolled out, and rolled back.
- Prefer patterns that integrate cleanly with Ansible templates in `ansible/templates/`.

### 10.2 Config Validation at Start
- Always validate config fully before the daemon starts.
- On failure: log precise reasons with actionable messages, then exit cleanly.
- Never apply partial configuration.

### 10.3 Air-Gapped Support
- Not all environments have internet access.
- Dependencies must be manageable via `dev/scripts/download-packages.sh` and
  `dev/scripts/install-packages.sh` for offline deployments.
