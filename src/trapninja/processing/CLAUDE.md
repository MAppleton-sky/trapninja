# Processing Pipeline — Scoped Rules

> Read `../../CLAUDE.md` for project-wide rules. This file adds **pipeline-specific constraints**.

## Critical Path Rules

This directory (`src/trapninja/processing/`) contains the **hot path** — the innermost
trap forwarding loop. Any regression here directly impacts trap loss and latency.

### Absolute Constraints
1. **No blocking I/O in the forwarding path.** No synchronous Redis calls, no file reads,
   no DNS lookups, no locks that could block under load.
2. **No unnecessary object allocation in the per-packet path.** Pre-allocate buffers and
   reuse them where possible.
3. **Stats must be written asynchronously.** `stats.py` increments must never block
   `packet_handler.py` or `forwarder.py`.
4. **Config cache reads must be lock-free or use read-write locks with minimal contention.**
   `config_cache.py` is read on every packet — it must be fast.

### Performance Targets
- SNMPv2c fast-path: target < 1ms per trap at steady-state load
- Worker thread saturation: alert at > 80% queue depth, never drop without logging
- Burst handling: queue must absorb 10,000+ trap spikes without loss

### Thread Safety Requirements
- `stats.py`: Use thread-safe counters — never mutate `OrderedDict` or `dict` while
  another thread may be iterating it. Use `threading.Lock` with minimal critical sections.
- `worker.py`: Worker pool must handle shutdown signals gracefully — drain the queue
  before exiting, do not discard in-flight traps.
- `forwarder.py`: Socket operations must handle `EAGAIN`/`EWOULDBLOCK` with retry logic,
  not silent failure.

### Fallback Behaviour
- If forwarding to a destination fails: log with destination details, increment error counter,
  retry with backoff, then quarantine after max retries — **never silently drop**.
- If `config_cache.py` returns stale/missing data: use last-known-good config and log a warning.

### Module Responsibilities
| File | Responsibility |
|------|---------------|
| `packet_handler.py` | Raw packet receipt, BPF filtering, hand-off to worker queue |
| `parser.py` | SNMP PDU parsing (SNMPv2c fast-path + SNMPv3 pipeline) |
| `forwarder.py` | UDP forwarding to destinations with retry logic |
| `worker.py` | Thread pool management, queue draining, shutdown |
| `config_cache.py` | In-memory config snapshot — read by every packet, must be fast |
| `stats.py` | Non-blocking stats increments, background flush |

### Testing Requirements for This Package
- Benchmark tests for per-packet latency under load
- Queue saturation tests (what happens at 100,000 traps/min input?)
- Forwarder retry and quarantine behaviour under simulated destination failure
- Config cache invalidation and hot-reload correctness
