---
applyTo: "src/trapninja/capture/**,src/trapninja/forwarder/**,src/trapninja/parser/**,src/trapninja/filter/**"
---

# Hot Path — Performance Rules

This code executes **once per SNMP trap**. At 100,000 traps/burst, every microsecond of added latency matters. These rules are absolute for any code in `capture/`, `forwarder/`, `parser/`, and `filter/`.

## What Is Allowed on the Hot Path

- One `threading.Lock` acquire + one integer add (statistics counter update)
- SNMP parsing via pysnmp (unavoidable)
- In-memory dict/set lookups (O(1) or O(log n))
- UDP socket send (async dispatch to worker pool)

## What Is Forbidden on the Hot Path

| Operation | Reason |
|---|---|
| `logger.debug()` unconditionally | Saturates disk I/O at burst rate |
| Any `time.sleep()` or blocking wait | Directly introduces forwarding latency |
| Synchronous Redis call | Redis RTT (1–5ms) × 100,000 traps = pipeline backup |
| Disk I/O (log write, file open) | Same as Redis — blocks the forwarding thread |
| DNS lookup or hostname resolution | Unpredictable latency |
| Lock held across any I/O | Blocks all other forwarding threads |
| `assert` for safety checks | Stripped by `python3.9 -O` in production |

## Statistics on the Hot Path

The ONLY acceptable stats pattern on the forwarding thread:

```python
with self._lock:
    self._counters[source_ip] += 1
```

Everything else — aggregation, rolling windows, file writes, Redis updates — belongs on a **background timer thread**.

## Graceful Degradation

- If eBPF fails to attach: fall through to Scapy automatically. Catch **all** exceptions from the eBPF attach sequence (not just `ImportError` — BCC can raise `OSError`, `RuntimeError`, or `Exception`).
- If Scapy capture interrupts: restart automatically with a WARNING log.
- If a trap fails to parse: log at WARNING (without sensitive data), increment failed counter, do NOT silently discard.

## Import Rule

Scapy and BCC must be **lazy imports** — inside the function body, never at module top:

```python
# CORRECT
def _start_scapy_capture(self):
    from scapy.all import sniff  # only loaded when actually needed
    ...

# WRONG — kills startup if Scapy has issues, prevents eBPF-first approach
from scapy.all import sniff
```
