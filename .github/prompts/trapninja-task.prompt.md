---
description: "TrapNinja implementation task template — fills in all required context for a new phase of work"
mode: "agent"
---

I need to implement a new feature or phase for TrapNinja. Help me structure the task correctly before writing any code.

Ask me the following questions one at a time, then produce a complete filled-in task specification:

1. What is the feature or change being implemented? (one sentence)
2. Which phase is this? (e.g. "Phase 2 of 4")
3. Which source files or modules are affected? (e.g. `src/trapninja/stats/sliding_window.py`)
4. Has the architecture been reviewed and approved? If yes, paste it. If no, stop here — architecture must be approved before implementation.
5. What is the exact scope of THIS phase? (list what should be implemented now, and what is deferred)
6. Does any new code execute on the forwarding thread (hot path)? If yes, what is the per-trap cost?
7. Does this change affect HA state, Redis streams, or the heartbeat mechanism?
8. What tests are needed?

Once I've answered, produce a task specification in this format:

---

## Task: [feature name] — [phase]

### Modules affected
[list]

### Architecture (approved)
[paste or summarise]

### Scope — this phase only
[numbered list of what to implement]

**Deferred to later phases:**
[list]

### Constraints (always apply)
- Python 3.9 only
- Redis 5.0.3: use XRANGE/XDEL, never XTRIM MINID
- No blocking operations on the forwarding thread
- No SNMPv3 credential logging at any level
- Prometheus metrics: trapninja_src_ip_* prefix; atomic .prom writes; no empty families
- assert is stripped in production — use explicit raises
- Scapy and BCC: lazy imports inside function body only
- Mock patch targets: call site, not definition site

### Hot-path impact
[what runs on the forwarding thread and what is its cost]

### HA implications
[any shared state, failover, or heartbeat effects]

### Testing requirements
[specific tests needed; note mock patch targets]

### Validation checklist
- [ ] Full test suite passes: `python -m pytest dev/tests/ -v`
- [ ] No new blocking operations on forwarding thread
- [ ] Prometheus .prom file valid (no empty families, atomic write)
- [ ] Redis commands compatible with 5.0.3
- [ ] No credentials in any log output

### Output expected
Full replacement files (not diffs), plus test file additions.
