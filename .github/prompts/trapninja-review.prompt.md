---
description: "TrapNinja code review — runs the 13-category safety checklist against selected or pasted code"
mode: "agent"
tools: ["search/codebase"]
---

Review the following code against TrapNinja's production safety requirements. Work through each category below. For each item, give a clear PASS, FAIL, or N/A with a one-line explanation. If any BLOCK condition is met, stop and flag it prominently before continuing.

---

## Code to review

${selection}

---

## Review Categories

### 1. Hot Path Performance
- Is any new code on the forwarding thread (capture → parse → filter → route → forward)?
- If yes: is the per-trap cost limited to one lock acquire + one integer add?
- **BLOCK**: Any disk I/O, Redis call, `time.sleep()`, or unconditional `logger.debug()` on the forwarding thread.

### 2. Silent Trap Loss
- Is there any code path where a trap can be discarded without a counter increment AND a log entry?
- **BLOCK**: Any bare `except: pass` or `except Exception: pass` in the forwarding pipeline.

### 3. Redis 5.0.3 Compatibility
- Does any Redis code use `XTRIM MINID`?
- **BLOCK**: `XTRIM MINID` is Redis 6.2+ only. Production runs 5.0.3. Use XRANGE + XDEL.

### 4. Security — Credentials
- Does any log statement, exception message, or output include SNMPv3 auth keys, priv keys, or community strings?
- **BLOCK**: Credentials in any log output at any level.

### 5. HA Correctness
- Could this code cause both nodes to be in ACTIVE state simultaneously?
- Could this code cause neither node to forward in a non-failure scenario?
- **BLOCK**: Either condition.

### 6. Prometheus Metrics
- Are `.prom` file writes atomic (write to `.tmp` then `os.rename()`)?
- Are empty metric families filtered out before writing?
- Do per-IP metrics use `trapninja_src_ip_*` prefix (not `trapninja_ip_*`)?
- **BLOCK**: Non-atomic write or empty families emitted.

### 7. Thread Safety
- Is all shared mutable state protected by a `threading.Lock`?
- Are locks released before any I/O operation?
- Are there any unbounded data structures that grow with traffic volume?
- **BLOCK**: Unbounded growth or unprotected shared state.

### 8. `assert` Usage
- Is `assert` used for any runtime safety check?
- **BLOCK**: `assert` is stripped by `python3.9 -O` in production. Use explicit raises.

### 9. Import Discipline
- Are Scapy and BCC imported at module top level?
- Are any Python 3.10+ language features used (match statements, X|Y unions, ParamSpec)?
- **BLOCK**: Either condition.

### 10. Test Mock Targets
- Do `unittest.mock.patch` decorators target the call site (where imported), not the definition site?
- **BLOCK**: Definition-site patching — the mock will have no effect.

### 11. Test Evolution
- Do any new or modified tests enforce deprecated behaviour that was intentionally removed?
- **BLOCK**: Tests must describe current intended behaviour, not historical behaviour.

### 12. Error Handling
- Are error messages specific (what failed, why, what to do)?
- Are exception types specific (not bare `except Exception` without re-raise or logging)?

### 13. Deployment Safety
- Does this require config file changes? (Document them)
- Is this rollback-safe?
- Does this change the Redis stream key schema? (Breaks HA replay during rolling upgrades)

---

## Summary

List all FAILs and BLOCKs. Then give an overall decision:

**ACCEPT** / **REVISE** / **BLOCK**

If REVISE or BLOCK: list the specific changes required before this can be merged.
