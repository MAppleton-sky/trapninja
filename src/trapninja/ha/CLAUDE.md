# High-Availability Module — Scoped Rules

> Read `../../CLAUDE.md` for project-wide rules. This file adds **HA-specific constraints**.

## HA Design Requirements

The `ha/` package manages Primary/Secondary cluster state, failover coordination, and
configuration synchronisation. Errors here can cause split-brain conditions, duplicate
trap forwarding, or missed traps during failover — all critical failures.

### Failover Requirements
- **Sub-3-second failover** from Primary failure to Secondary taking over.
- **Zero trap loss** during failover — in-flight traps must be buffered and replayed.
- Failover must be **deterministic and observable** — log every state transition with timestamp.
- Failover state machine must handle: Primary unreachable, Primary graceful shutdown,
  network partition (split-brain avoidance).

### Split-Brain Protection
- Never have two active Primary nodes simultaneously.
- Use Redis-based distributed lock or heartbeat with TTL to arbitrate.
- When in doubt about peer state: **stay Secondary** rather than risk duplicate forwarding.
- Log split-brain detection events at CRITICAL severity.

### State Synchronisation (`ha/sync/`)
- Config sync must be idempotent — applying the same config bundle twice must be safe.
- Use versioned config bundles — always reject older versions.
- Sync failures must not prevent local operation — log and continue with local config.

### API Surface (`ha/api.py`)
- The HA API is called by CLI commands and potentially by monitoring systems.
- All API methods must be safe to call from any node role (Primary or Secondary).
- Rate-limit control operations to prevent rapid state oscillation.

### Module Responsibilities
| File | Responsibility |
|------|---------------|
| `api.py` | External HA API — CLI and monitoring integration |
| `cluster.py` | Cluster membership, peer discovery, heartbeat |
| `config.py` | HA-specific configuration loading and validation |
| `messages.py` | Inter-node message types and serialisation |
| `state.py` | Node role state machine (Primary / Secondary / Unknown) |
| `sync/manager.py` | Config synchronisation orchestration |
| `sync/config_bundle.py` | Versioned config bundle packaging |

### Testing Requirements
- State machine transitions: all valid and invalid transitions
- Failover sequence: Primary → unreachable → Secondary promotes → Primary recovers
- Split-brain scenario: both nodes think they are Primary
- Config sync: version conflict, partial sync failure, idempotent re-apply
- Redis unavailable: HA degrades gracefully, local operation continues
