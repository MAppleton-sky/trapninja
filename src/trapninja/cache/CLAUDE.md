# Cache Module — Scoped Rules

> Read `../../CLAUDE.md` for project-wide rules. This file adds **cache-specific constraints**.

## Cache Design Requirements

The `cache/` package provides Redis-backed trap buffering for replay during failover.
It is **optional but critical** for zero-trap-loss HA operations.

### Core Invariants
- Redis unavailability must **never** stop trap forwarding — degrade to local state silently
  after logging a single warning (not one per trap).
- The replay mechanism must be **idempotent** — replaying the same trap twice must not
  cause duplicate forwarding to destinations.
- Cache TTL is **2 hours** — traps older than this are considered expired and should not
  be replayed.
- Trap storage uses Redis Streams (`XADD`/`XREAD`) for ordered, replayable access.

### Failover Detector (`failover/detector.py`)
- Must detect Primary failure within the sub-3-second target window.
- Use Redis heartbeat key with TTL — not periodic polling with long intervals.
- On detection: notify `failover/manager.py` immediately via callback, not queue.

### Failover Manager (`failover/manager.py`)
- Coordinates cache replay when Secondary promotes.
- Must handle partial replay: if replay is interrupted, resume from last confirmed position.
- Track replay progress in Redis so it survives a Secondary restart during replay.

### Redis Backend (`redis_backend.py`)
- All Redis operations must have explicit timeouts — no indefinite blocking.
- Use connection pooling — do not create a new connection per trap.
- On connection error: log once, return failure to caller, let caller decide on fallback.
- Never expose raw Redis exceptions to calling code — wrap in TrapNinja cache exceptions.

### Secondary Server Cache Writes
- Secondary must write to cache in real-time (not just Primary).
- This enables Secondary-sourced replay if Primary never recovers.
- Verify that both Primary and Secondary cache writes are tested.

### Module Responsibilities
| File | Responsibility |
|------|---------------|
| `redis_backend.py` | Low-level Redis operations with timeout and pooling |
| `replay.py` | Trap replay from cache to destinations on failover |
| `failover/detector.py` | Primary failure detection via heartbeat |
| `failover/manager.py` | Failover sequence orchestration |
| `failover/tracker.py` | Replay position tracking in Redis |
