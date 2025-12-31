# TrapNinja Architecture

**Version:** 0.7.13 (Beta)  
**Last Updated:** December 31, 2025

## Overview

TrapNinja is a high-performance SNMP trap forwarder designed for telecommunications environments requiring 99.999% availability. The system handles SNMP traps from multi-vendor network equipment and forwards them to specialized NOCs with support for extreme traffic scenarios including alarm floods during fiber cuts (10,000-100,000+ trap bursts).

## Directory Structure

```
trapninja/
├── trapninja.py              # Main entry point
├── VERSION                   # Version file (single source of truth)
├── trapninja/                # Core package
│   ├── __init__.py           # Package initialization and exports
│   ├── __version__.py        # Version reading and feature flags
│   ├── main.py               # CLI entry point
│   ├── config.py             # Configuration management
│   ├── daemon.py             # Daemon control (start/stop/status)
│   ├── service.py            # Main service with HA integration
│   ├── network.py            # Network capture and packet queue
│   ├── snmp.py               # SNMP packet parsing
│   ├── metrics.py            # Prometheus-compatible metrics
│   ├── logger.py             # Logging configuration
│   ├── redirection.py        # IP/OID redirection logic
│   ├── control.py            # Control socket for CLI
│   ├── diagnostics.py        # System diagnostics
│   ├── ebpf.py               # eBPF kernel-space acceleration
│   ├── shadow.py             # Shadow/mirror mode for testing
│   ├── snmpv3_credentials.py # SNMPv3 credential store
│   ├── snmpv3_decryption.py  # SNMPv3 decryption engine
│   │
│   ├── cache/                # Redis-based trap caching
│   │   ├── __init__.py       # Package exports
│   │   ├── redis_backend.py  # TrapCache, RetentionManager
│   │   ├── replay.py         # ReplayEngine for trap replay
│   │   └── failover/         # HA failover replay
│   │       ├── __init__.py
│   │       ├── detector.py   # GapDetector for outage detection
│   │       ├── manager.py    # FailoverReplayManager
│   │       └── tracker.py    # FailoverTracker state tracking
│   │
│   ├── cli/                  # Command-line interface
│   │   ├── __init__.py       # Package exports
│   │   ├── parser.py         # Argument parsing configuration
│   │   ├── validation.py     # Input validation and security
│   │   ├── executor.py       # Command routing and execution
│   │   ├── output.py         # Output formatting utilities
│   │   ├── daemon_commands.py    # Service lifecycle commands
│   │   ├── filtering_commands.py # IP/OID block/unblock
│   │   ├── ha_commands.py        # HA status/promote/demote
│   │   ├── cache_commands.py     # Cache query/replay/clear
│   │   ├── stats_commands.py     # Statistics display commands
│   │   ├── stats.py              # Statistics CLI helpers
│   │   ├── shadow_commands.py    # Shadow mode commands
│   │   ├── snmpv3_commands.py    # SNMPv3 credential management
│   │   ├── sync_commands.py      # Config sync commands
│   │   └── failover_commands.py  # Failover replay commands
│   │
│   ├── core/                 # Core types and constants
│   │   ├── __init__.py       # Package exports
│   │   ├── constants.py      # FORWARD_SOURCE_PORT, ASN1 tags, etc.
│   │   ├── exceptions.py     # TrapNinjaError, ConfigurationError, etc.
│   │   └── types.py          # PacketData, Destination, ForwardingResult
│   │
│   ├── ha/                   # High Availability package
│   │   ├── __init__.py       # Package exports
│   │   ├── api.py            # Public HA API functions
│   │   ├── cluster.py        # HACluster implementation
│   │   ├── config.py         # HAConfig dataclass
│   │   ├── messages.py       # HAMessage, HAMessageType
│   │   ├── state.py          # HAState enum and transitions
│   │   └── sync/             # Configuration synchronization
│   │       ├── __init__.py
│   │       ├── config_bundle.py  # SharedConfig types
│   │       └── manager.py        # ConfigSyncManager
│   │
│   ├── processing/           # Packet processing pipeline
│   │   ├── __init__.py       # Package exports
│   │   ├── parser.py         # Fast SNMP parsing
│   │   ├── forwarder.py      # SocketPool, raw socket forwarding
│   │   ├── worker.py         # PacketWorker, batch processing
│   │   └── stats.py          # ProcessingStats, lock-free counters
│   │
│   └── stats/                # Granular statistics
│       ├── __init__.py       # Package exports
│       ├── collector.py      # GranularStatsCollector
│       ├── models.py         # IPStats, OIDStats, RateTracker
│       └── api.py            # Query functions for CLI/API
│
└── config/                   # Configuration files
    ├── destinations.json
    ├── blocked_ips.json
    ├── blocked_traps.json
    ├── redirected_ips.json
    ├── redirected_oids.json
    ├── redirected_destinations.json
    ├── ha_config.json
    ├── cache_config.json
    ├── stats_config.json
    └── listen_ports.json
```

## Module Responsibilities

### Core Modules

| Module | Responsibility |
|--------|---------------|
| `config.py` | Load/save configuration, define paths and constants |
| `daemon.py` | Process daemonization, PID management, subprocess spawning |
| `service.py` | Main service loop, component initialization, capture mode selection |
| `network.py` | UDP listeners, packet queue (200K capacity), Scapy capture integration |
| `snmp.py` | SNMP packet parsing, OID extraction, filtering logic |
| `metrics.py` | Prometheus metrics collection and HTTP export |
| `ebpf.py` | eBPF kernel-space packet acceleration |
| `shadow.py` | Shadow/mirror mode for parallel testing without forwarding |
| `redirection.py` | IP and OID-based trap routing to alternate destinations |
| `control.py` | Unix socket server for CLI communication |
| `diagnostics.py` | System health checks and diagnostic commands |

### Sub-Packages

#### `cache/` - Trap Caching System

Redis-based trap storage with rolling retention for replay during monitoring outages.

| Module | Purpose |
|--------|---------|
| `redis_backend.py` | TrapCache class, Redis Streams operations, RetentionManager |
| `replay.py` | ReplayEngine with rate limiting and filtering |
| `failover/detector.py` | GapDetector for identifying outage windows |
| `failover/manager.py` | FailoverReplayManager for automatic gap replay |
| `failover/tracker.py` | FailoverTracker for state persistence |

**Key Classes:**
- `TrapCache` - Store and retrieve traps by destination
- `ReplayEngine` - Time-windowed replay with rate control
- `FailoverReplayManager` - Automatic replay when becoming PRIMARY

#### `cli/` - Command Line Interface

Modular CLI with security-focused input validation.

| Module | Purpose |
|--------|---------|
| `parser.py` | ArgumentParser configuration, all CLI arguments |
| `validation.py` | InputValidator with security patterns, sanitization |
| `executor.py` | Command dispatch based on parsed arguments |
| `output.py` | Formatted output helpers, table generation |
| `daemon_commands.py` | --start, --stop, --restart, --status |
| `filtering_commands.py` | --block-ip, --unblock-ip, --block-oid, --unblock-oid |
| `ha_commands.py` | --ha-status, --promote, --demote, --force-failover |
| `cache_commands.py` | --cache-status, --cache-query, --cache-replay |
| `stats_commands.py` | --stats-summary, --stats-top-ips, --stats-top-oids |
| `shadow_commands.py` | --shadow-mode, --mirror-mode |
| `snmpv3_commands.py` | --snmpv3-add-user, --snmpv3-list-users |
| `sync_commands.py` | --ha-sync, config synchronization |
| `failover_commands.py` | --failover-status, --failover-replay |

#### `core/` - Core Definitions

Shared types, constants, and exceptions used across all modules.

| Module | Purpose |
|--------|---------|
| `constants.py` | `FORWARD_SOURCE_PORT` (10162), ASN.1 tags, queue sizes |
| `exceptions.py` | `TrapNinjaError`, `ConfigurationError`, `HAError`, etc. |
| `types.py` | `PacketData`, `Destination`, `ForwardingResult` dataclasses |

#### `ha/` - High Availability

Primary/Secondary clustering with automatic failover.

| Module | Purpose |
|--------|---------|
| `api.py` | Public functions: `initialize_ha()`, `shutdown_ha()`, `is_forwarding_enabled()` |
| `cluster.py` | `HACluster` class with heartbeat, election, state management |
| `config.py` | `HAConfig` dataclass, `load_ha_config()`, `save_ha_config()` |
| `messages.py` | `HAMessage`, `HAMessageType` for inter-node communication |
| `state.py` | `HAState` enum (PRIMARY, SECONDARY, STANDALONE, etc.) |
| `sync/manager.py` | `ConfigSyncManager` for config replication between nodes |
| `sync/config_bundle.py` | `SharedConfig` types, shared vs local config definitions |

#### `processing/` - Packet Processing

High-performance packet handling pipeline.

| Module | Purpose |
|--------|---------|
| `parser.py` | Fast SNMP parsing with direct byte scanning |
| `forwarder.py` | `SocketPool` for connection reuse, raw socket forwarding |
| `worker.py` | `PacketWorker` threads, batch processing |
| `stats.py` | `ProcessingStats` with lock-free atomic counters |

**Key Features:**
- Fast-path optimization for SNMPv2c (5-10x faster)
- Socket pooling reduces connection overhead
- Lock-free statistics using Python GIL guarantees

#### `stats/` - Granular Statistics

Per-IP, per-OID, and per-destination statistics collection.

| Module | Purpose |
|--------|---------|
| `collector.py` | `GranularStatsCollector`, periodic export, LRU bounds |
| `models.py` | `IPStats`, `OIDStats`, `DestinationStats`, `RateTracker` |
| `api.py` | Query functions for CLI and REST API integration |

**Key Features:**
- Per-source IP: trap counts, rates, top OIDs, peak rates
- Per-OID: trap counts, rates, unique source count
- Per-destination: forward counts, failure rates
- Memory-bounded with LRU eviction
- Prometheus and JSON export

## Data Flow

```
┌───────────────────────────────────────────────────────────────────────────┐
│                              CAPTURE LAYER                                 │
│   ┌─────────┐    ┌─────────┐    ┌─────────┐                               │
│   │ eBPF    │    │ Socket  │    │ Scapy   │                               │
│   │ Capture │    │ Capture │    │ Sniff   │                               │
│   └────┬────┘    └────┬────┘    └────┬────┘                               │
│        └──────────────┼──────────────┘                                    │
│               (Only ONE method active)                                     │
└───────────────────────┼───────────────────────────────────────────────────┘
                        │
                        ▼
┌───────────────────────────────────────────────────────────────────────────┐
│                         PACKET QUEUE (200K capacity)                       │
└───────────────────────────────────────────────────────────────────────────┘
                        │
                        ▼
┌───────────────────────────────────────────────────────────────────────────┐
│                      PROCESSING WORKERS (2x CPU cores)                     │
│                                                                            │
│   ┌─────────────────────────────────────────────────────────────────┐     │
│   │  1. HA Check (is_forwarding_enabled)                            │     │
│   │     └─► If SECONDARY: cache trap, increment ha_blocked, SKIP    │     │
│   │                                                                  │     │
│   │  2. IP Block Check                                               │     │
│   │     └─► If blocked_ip: DROP or redirect to blocked_dest         │     │
│   │                                                                  │     │
│   │  3. SNMP Parse (fast path first, slow path fallback)            │     │
│   │                                                                  │     │
│   │  4. OID Block/Redirect Check                                     │     │
│   │     └─► Apply redirection rules if matched                       │     │
│   │                                                                  │     │
│   │  5. Determine Destinations                                       │     │
│   │                                                                  │     │
│   │  6. Update Granular Statistics (per-IP, per-OID)                │     │
│   └─────────────────────────────────────────────────────────────────┘     │
└───────────────────────────────────────────────────────────────────────────┘
                        │
          ┌─────────────┼─────────────┐
          ▼             ▼             ▼
┌──────────────┐ ┌──────────────┐ ┌──────────────┐
│ Redis Cache  │ │  Forwarding  │ │  Statistics  │
│ (if enabled) │ │    Layer     │ │   Export     │
└──────────────┘ └──────┬───────┘ └──────────────┘
                        │
                        ▼
┌───────────────────────────────────────────────────────────────────────────┐
│                          FORWARDING LAYER                                  │
│                                                                            │
│   forward_packet() - Single forwarding function                            │
│   Source Port: FORWARD_SOURCE_PORT (10162) - prevents re-capture          │
│                                                                            │
│   ┌──────────────┐  ┌──────────────┐  ┌──────────────┐                    │
│   │ Destination 1│  │ Destination 2│  │ Destination N│                    │
│   │  Raw Socket  │  │  Raw Socket  │  │  Raw Socket  │                    │
│   └──────────────┘  └──────────────┘  └──────────────┘                    │
└───────────────────────────────────────────────────────────────────────────┘
```

## HA Architecture

```
   Primary Node                    Secondary Node
   ┌─────────────────┐            ┌─────────────────┐
   │    TrapNinja    │◄──────────►│    TrapNinja    │
   │    (ACTIVE)     │  Heartbeat │    (STANDBY)    │
   │                 │  (TCP/UDP) │                 │
   │  is_forwarding  │            │  is_forwarding  │
   │     = True      │            │     = False     │
   │                 │            │                 │
   │  Config Sync ──────────────────► Pull configs  │
   │  (push changes) │            │  on startup     │
   └────────┬────────┘            └────────┬────────┘
            │                              │
            ▼                              ▼
      Forwards Traps               Caches Traps
     to Destinations              (for failover replay)
```

### HA States

| State | `is_forwarding_enabled()` | Behavior |
|-------|--------------------------|----------|
| PRIMARY | True | Forwards all traps, pushes config changes |
| SECONDARY | False | Caches traps, pulls configs, monitors primary |
| STANDALONE | True | No HA, forwards all traps |
| INITIALIZING | False | Starting up, no forwarding |
| FAILOVER | True (transitioning) | Becoming PRIMARY |
| SPLIT_BRAIN | False | Both nodes detected as primary |
| ERROR | False | Error state, no forwarding |

### Config Synchronization

**Shared configs** (synced between nodes):
- `destinations.json`
- `blocked_ips.json`
- `blocked_traps.json`
- `redirected_*.json`

**Local configs** (not synced):
- `ha_config.json`
- `cache_config.json`
- `stats_config.json`
- `listen_ports.json`

## Capture Mode Selection

TrapNinja supports three capture modes, tried in order:

1. **eBPF** (highest performance): Kernel-space filtering
   - Requires: root, BCC library, kernel 4.4+
   - Performance: 30k+ traps/sec, ~20% CPU

2. **Socket** (standard): UDP socket listeners
   - Requires: port binding capability
   - Performance: 10k+ traps/sec, ~40% CPU

3. **Sniff** (fallback): Scapy packet capture
   - Requires: raw socket capability (usually root)
   - Performance: 5k+ traps/sec, ~60% CPU

### Critical: Single Capture Method

Only ONE capture method runs at a time. Running multiple methods simultaneously causes packet duplication.

```python
# In service.py - capture mode selection
if capture_mode == "ebpf" and ebpf_available():
    start_ebpf_capture()  # ONLY eBPF
elif capture_mode == "socket":
    start_all_udp_listeners()  # ONLY socket
elif capture_mode == "sniff":
    cleanup_udp_sockets()  # Ensure no sockets running
    start_sniff()  # ONLY sniff
```

## Key Design Decisions

### 1. Single Source of Truth for Forwarding

All packet forwarding uses functions from `processing/forwarder.py` with:
- Centralized destination management
- Consistent source port (`FORWARD_SOURCE_PORT = 10162`)
- BPF filter exclusion to prevent re-capture loops

### 2. HA Check at Processing Time

HA state is checked when processing packets, not when queuing:
- Handles all capture modes consistently
- Eliminates race conditions during state changes
- SECONDARY nodes cache traps for potential failover replay

### 3. Lock-Free Statistics

Uses Python GIL guarantees for atomic counter operations:
- No mutex overhead in hot paths
- Thread-safe increment operations
- Minimal latency impact

### 4. Raw Socket Forwarding

Primary forwarding uses raw sockets (6-10x faster than Scapy):
- Direct kernel interface
- Minimal packet construction overhead
- Falls back to Scapy when raw sockets unavailable

### 5. Queue-Based Processing

Decouples capture from processing:
- Handles burst traffic (alarm floods)
- Queue capacity: 200,000 packets
- Non-blocking capture threads

### 6. Modular Package Structure

Each major feature is a self-contained package:
- `cache/` - Redis caching with failover replay
- `cli/` - Command-line interface
- `core/` - Shared types and constants
- `ha/` - High availability with config sync
- `processing/` - Packet processing pipeline
- `stats/` - Granular statistics collection

## Performance Targets

| Metric | Target | Notes |
|--------|--------|-------|
| Throughput | 10,000+ traps/sec | Sustained, with eBPF: 30k+ |
| Queue Capacity | 200,000 packets | Handles alarm floods |
| Failover Time | &lt;3 seconds | Typical: 1-2 seconds |
| Memory | &lt;500MB | Typical operation |
| CPU (with eBPF) | &lt;30% | At 10k traps/sec |
| Drop Rate | &lt;0.1% | Target: zero drops |

## Constants Reference

Key constants in `core/constants.py`:

```python
FORWARD_SOURCE_PORT = 10162  # Distinct from trap port 162
DEFAULT_TRAP_PORT = 162
DEFAULT_QUEUE_SIZE = 200000
WORKER_COUNT = cpu_count() * 2

# ASN.1 tags for SNMP parsing
ASN1_SEQUENCE = 0x30
ASN1_INTEGER = 0x02
ASN1_OCTET_STRING = 0x04
ASN1_OID = 0x06
```

## File Naming Conventions

| Pattern | Purpose |
|---------|---------|
| `*_commands.py` | CLI command implementations |
| `*_backend.py` | Backend implementations (e.g., Redis) |
| `*.json` | Configuration files |
| `*.bak` | Backup files (temporary, to be removed) |

## Related Documentation

| Document | Contents |
|----------|----------|
| [DIRECTORY_STRUCTURE.md](DIRECTORY_STRUCTURE.md) | Repository layout and deployment |
| [CLI.md](CLI.md) | Full CLI reference |
| [CLI_MODULE.md](CLI_MODULE.md) | CLI module architecture |
| [HA.md](HA.md) | High Availability configuration |
| [CACHE.md](CACHE.md) | Redis cache setup |
| [FAILOVER_REPLAY.md](FAILOVER_REPLAY.md) | Failover replay system |
| [GRANULAR_STATS.md](GRANULAR_STATS.md) | Statistics system |
| [METRICS.md](METRICS.md) | Prometheus metrics |
