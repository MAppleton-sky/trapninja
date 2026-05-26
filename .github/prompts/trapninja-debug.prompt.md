---
description: "TrapNinja structured debugging — root cause analysis before any fix is proposed"
mode: "agent"
tools: ["search/codebase", "read"]
---

I need to debug a TrapNinja issue. Walk through the diagnostic sequence below. Do NOT propose a fix until root cause is confirmed.

---

## Symptom

${input:symptom:Describe the observed problem — what is wrong, when does it happen, what is the impact on trap forwarding?}

## Evidence available

Paste any of the following that are available (leave blank if not):

**Log excerpt** (with timestamps):


**Stack trace**:


**What I've already ruled out**:


**Module or file suspected**:


---

## Diagnostic sequence

Work through these in order. Stop when root cause is found.

### Step 1 — Classify the failure type

Which category does this fall into?
- A) Trap not received (capture layer issue)
- B) Trap received but not forwarded (parsing, filtering, or forwarding issue)
- C) Trap forwarded but not visible at NMS (network or NMS issue)
- D) Prometheus metrics wrong or missing (metrics/stats issue)
- E) Test failing unexpectedly (mock or test design issue)
- F) HA / failover misbehaviour
- G) Redis error
- H) Startup / config error

### Step 2 — Check the most common causes for that category

**For E (test failing):** Check mock patch target first — is it patching the call site or the definition site? This is the most common cause.

**For D (Prometheus):** Inspect the `.prom` file directly with `cat -A`. Look for: empty `# HELP`/`# TYPE` blocks with no samples, missing `\n\n` separator between families, partial file (non-atomic write).

**For G (Redis error):** Check if the command is `XTRIM MINID` — this fails on Redis 5.0.3. Use `XRANGE` + `XDEL` instead.

**For F (HA):** Check whether both nodes are in the same state. Check heartbeat logs for timing. Check whether the forwarding thread was blocked before the heartbeat missed.

### Step 3 — Trace the call chain

Identify the entry point for this failure and trace through the module call chain to the failure point. Use `search/codebase` to find the relevant code. State each step explicitly — do not assume.

### Step 4 — Confirm root cause

State the root cause in one sentence: "The failure occurs because [specific code path] does [specific thing] when [specific condition]."

Do not proceed to Step 5 until this is confirmed.

### Step 5 — Propose a fix

Now propose the minimal fix that addresses the root cause. The fix must:
- Not introduce any new blocking operation on the forwarding thread
- Not cause silent trap loss
- Not use Redis commands unavailable in 5.0.3
- Not log any sensitive credential data
- Include a test that would have caught this bug

State what changed, why, and what tests need updating.
