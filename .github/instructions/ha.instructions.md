---
applyTo: "src/trapninja/ha/**"
---

# HA State Machine — High-Risk Rules

The HA subsystem is the **highest-risk code in TrapNinja**. Bugs here have two catastrophic failure modes:

- **Both nodes ACTIVE** → duplicate trap forwarding → alarm storm at NMS
- **Both nodes STANDBY** → zero forwarding → complete alarm blackout for NOC

## Do Not Modify Without Explicit Approval

Do not change HA state transitions without proposing the change in writing and receiving explicit human confirmation. The sub-3-second failover target is a hard requirement, not a guideline.

## State Machine Rules

```
STANDBY → (heartbeat lost) → PROMOTING → ACTIVE
ACTIVE  → (heartbeat restored / manual demotion) → STANDBY
```

- Transitions must be **atomic and logged** at INFO level.
- A node must pass through STOPPING before the peer can promote. Never skip transition states.
- Heartbeat miss threshold must account for the full transition window to avoid spurious failover.

## Forwarding Exclusivity

At all times, **exactly one node** is in ACTIVE state and forwarding. Enforce this:
- Secondary must detect Primary alive before starting any forwarding.
- On promotion, Secondary must confirm no heartbeat for the full timeout period — not just one missed beat.
- Primary must stop forwarding before Secondary promotes (use the Redis cache as the handoff mechanism).

## Redis Cache as HA Handoff

- Traps are written to the Redis cache **before** forwarding confirmation.
- On failover, Secondary reads unforwarded entries from the cache and replays them.
- The cache write uses Redis Streams. **Never use `XTRIM MINID`** — production Redis is 5.0.3. Use `XRANGE` + `XDEL`.
- Cache write failure (Redis unavailable): continue forwarding without cache write. Log a WARNING. Do not stop.

## Statistics Are Per-Node Only

Never attempt to sync statistics between Primary and Secondary via Redis or any other mechanism. Each node receives an independent trap feed — cross-node stat comparison is architecturally meaningless.

Baseline files are stored at `/etc/trapninja/baselines/` on each node independently. This was an explicit design decision, not an oversight.

## Peer Socket Security

The HA peer socket is currently plain TCP, mitigated by network isolation (management VLAN). Architecture for TLS 1.3 + HMAC-SHA256 with sequence numbers is designed but not yet implemented. Do not implement partial hardening — implement the full sequence or leave as-is.
