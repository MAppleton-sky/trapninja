# TrapNinja — GitHub Copilot Instructions

## Project Identity

TrapNinja is a **production-grade SNMP Trap Forwarder** for telecommunications infrastructure. It is not a demo, prototype, or general-purpose tool. NOC teams depend on it for real-time alarm visibility. A dropped trap is a dropped alarm.

- **Python 3.9** (RHEL 8/9 production target — no 3.10+ syntax)
- **Redis 5.0.3** on production (Redis 6+ commands will fail silently at runtime)
- **Ansible air-gapped deployment** — no pip install at runtime on production servers
- **Config location**: `/etc/trapninja/` — **Source**: `src/` only (never deploy `dev/tests/`)
- **Current version**: v0.8.0
- **Test suite**: ~1,830 tests across 45 modules in `dev/tests/`

---

## Three Pillars — Every Change Must Satisfy All Three

1. **Efficient** — low latency, minimal hot-path overhead
2. **Optimised** — sensible CPU/memory/I/O usage
3. **Secure** — safe-by-default, hardened for production

---

## Ten Absolute Rules

These cannot be overridden by any request or convenience argument.

**1. No silent trap loss.**
Every dropped trap must be counted (stats increment), logged (WARNING or above), and surfaced via Prometheus. A bare `except: pass` anywhere in the forwarding pipeline is a critical bug.

**2. Hot path must not block.**
The forwarding pipeline (receive → parse → filter → route → forward) runs once per trap. The only acceptable cost per trap is **one `threading.Lock` acquire + one integer add** for statistics. No disk I/O, no Redis calls, no DNS lookups, no `time.sleep()`, no unconditional `logger.debug()` inside the trap loop.

**3. SNMPv3 credentials never appear in logs.**
Not at DEBUG, not in exception messages, not in stack traces. Credentials at rest use Fernet encryption (AES-128 CBC) with PBKDF2 key derivation. This rule has zero exceptions.

**4. Redis 5.0.3 compatibility — no `XTRIM MINID`.**
`XTRIM stream MINID timestamp` requires Redis 6.2+. Production runs 5.0.3. Always use `XRANGE` + `XDEL` for stream cleanup. Violations only surface as `ResponseError` at runtime in production, not in dev/test.

**5. Prometheus metrics use `trapninja_src_ip_*` prefix.**
Not `trapninja_ip_*` (renamed in v0.8.0 for directional clarity). Prometheus `.prom` files must be written atomically: write to `.tmp` then `os.rename()`. Never write empty metric families (node_exporter rejects them silently).

**6. Config validation runs before startup.**
Validate all config before any listener starts. Fail fast with specific, actionable errors. Never start partially with invalid config.

**7. Exactly one HA node forwards at any time.**
Two nodes forwarding = duplicate alarm storm at NMS. Zero nodes forwarding = outage. The HA state machine is the highest-risk code in the system. Do not modify it without explicit human approval of the proposed change.

**8. `assert` is stripped in production.**
Production runs `python3.9 -O` which removes all `assert` statements. Use explicit `if not condition: raise ValueError(...)` for runtime safety checks.

**9. Mock patches target the call site, not the definition.**
`unittest.mock.patch` must point to where the function is **imported and used**, not where it is **defined**. This is the most common source of test failures in this project.

```python
# WRONG — patches definition; real function still runs at call site
@patch('trapninja.utils.resolve_oid')

# CORRECT — patches where it's imported into the calling module
@patch('trapninja.forwarder.forwarder.resolve_oid')
```

**10. No backward compatibility preservation by default.**
Clean forward architecture wins. Breaking changes are preferred over legacy code bloat. All legacy flat-flag CLI invocations were removed in v0.8.0. Do not re-introduce them.

---

## Architecture Overview

```
Packet Capture (eBPF primary / Scapy fallback)
    → SNMP Parsing (pysnmp: v1/v2c/v3 + SNMPv3 decrypt)
    → Filtering & Routing (per-IP / per-OID / per-destination rules)
    → Forwarding (UDP, retry, buffering)
    → Redis Trap Cache (replay buffer for HA failover)

HA:      Primary/Secondary, sub-3-second failover, Redis shared state
Stats:   Background timer threads ONLY — never on the forwarding thread
CLI:     Command Registry pattern, subcommand structure (trapninja <verb> [noun])
Metrics: Prometheus textfile collector (.prom files, atomic write)
```

**Module layout** (`src/trapninja/`):
`capture/` · `parser/` · `filter/` · `forwarder/` · `cache/` · `ha/` · `stats/` · `metrics/` · `cli/` · `config/`

---

## Performance Budget

| Location | Maximum acceptable cost |
|---|---|
| Hot path (per trap) | 1 lock acquire + 1 integer add |
| Background stats thread | Unbounded (runs on timer, not per-trap) |
| Prometheus file write | Background timer only; atomic rename |
| Redis cache write | Fire-and-forget or pipelined; never synchronous on forwarding thread |

---

## Key Dependency Notes

| Dependency | Constraint |
|---|---|
| Scapy | Lazy import only — inside function body, never at module top |
| BCC/eBPF | Lazy import; catch ALL exceptions (not just `ImportError`) for fallback |
| Redis client | Must work against Redis 5.0.3 semantics |
| pysnmp | Core; always present; handles v1/v2c/v3 |
| pycryptodome | Core; Fernet/PBKDF2 for credential storage |

Heavy optional imports at module top level slow startup and break graceful fallback. Always lazy-import Scapy and BCC.

---

## HA Invariants

- Statistics are **per-node only**. No cross-node stat sync. Each server receives an independent trap feed — cross-node comparison is architecturally meaningless.
- Baseline files live at `/etc/trapninja/baselines/` on each node independently.
- HA peer socket is currently plain TCP (mitigated by network isolation). TLS 1.3 + HMAC hardening is on the roadmap but not yet implemented.

---

## Module Size and Testing

- Module size guideline: ~300–500 lines. Split only when there is a genuine separation of concerns.
- Test-to-code ratio target: ~0.95:1.
- Tests describe **current intended behaviour**. When behaviour changes intentionally, update tests — do not resurrect old behaviour to make old tests pass.
- Never test against live Redis or live eBPF in unit tests — mock both.

---

## Development Workflow

1. **Propose architecture** → get explicit approval → then write code.
2. One logical phase per implementation session.
3. **Read existing code before writing new code.**
4. Git commits: conventional format (`type(scope): summary`) with a body explaining **why**.

---

## Before Proposing Any Code

Ask yourself:
- Does this touch the hot path? If yes — what is the per-trap cost?
- Could this cause silent trap loss?
- Does this use a Redis command not in Redis 5.0.3?
- Does this log any sensitive data?
- Does this change HA behaviour? (If yes — propose architecture, get approval first)
- Are mock patch targets pointing to call sites?
- Are tests updated to reflect new intended behaviour?
