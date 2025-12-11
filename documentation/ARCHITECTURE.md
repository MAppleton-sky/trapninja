# TrapNinja Architecture

## Overview

TrapNinja is a high-performance SNMP trap forwarder designed for telecommunications environments requiring 99.999% availability. The system handles SNMP traps from multi-vendor network equipment and forwards them to specialized NOCs with support for extreme traffic scenarios including alarm floods during fiber cuts (10,000-100,000+ trap bursts).

## Directory Structure

```
trapninja/
├── trapninja.py              # Main entry point
├── trapninja/                # Core package
│   ├── __init__.py           # Package initialization
│   ├── __version__.py        # Version (single source of truth)
│   ├── main.py               # CLI entry point
│   ├── config.py             # Configuration management
│   ├── daemon.py             # Daemon control (start/stop/status)
│   ├── service.py            # Main service with HA integration
│   ├── network.py            # Network capture and forwarding
│   ├── packet_processor.py   # High-performance packet processing
│   ├── snmp.py               # SNMP packet parsing
│   ├── metrics.py            # Prometheus-compatible metrics
│   ├── logger.py             # Logging configuration
│   ├── redirection.py        # IP/OID redirection logic
│   ├── control.py            # Control socket for CLI
│   ├── diagnostics.py        # System diagnostics
│   ├── ebpf.py               # eBPF acceleration
│   ├── snmpv3_credentials.py # SNMPv3 credential store
│   ├── snmpv3_decryption.py  # SNMPv3 decryption
│   │
│   ├── cli/                  # Command-line interface
│   │   ├── __init__.py
│   │   ├── parser.py         # Argument parsing
│   │   ├── validation.py     # Input validation
│   │   ├── executor.py       # Command execution
│   │   ├── daemon_commands.py
│   │   ├── filtering_commands.py
│   │   ├── ha_commands.py
│   │   └── snmpv3_commands.py
│   │
│   ├── core/                 # Core types and constants
│   │   ├── __init__.py
│   │   ├── constants.py      # Global constants (FORWARD_SOURCE_PORT, etc.)
│   │   ├── exceptions.py     # Custom exceptions
│   │   └── types.py          # Type definitions
│   │
│   ├── ha/                   # High Availability package
│   │   ├── __init__.py
│   │   ├── api.py            # Public HA API
│   │   ├── cluster.py        # HACluster implementation
│   │   ├── config.py         # HA configuration model
│   │   ├── messages.py       # HA message types
│   │   └── state.py          # State machine
│   │
│   └── processing/           # Packet processing package
│       ├── __init__.py
│       ├── parser.py         # SNMP parsing
│       ├── forwarder.py      # Packet forwarding
│       ├── worker.py         # Processing workers
│       └── stats.py          # Processing statistics
│
├── config/                   # Configuration files
├── documentation/            # All documentation
└── tests/                    # Test files
```

## Module Responsibilities

### Core Modules

| Module | Responsibility |
|--------|---------------|
| `config.py` | Load/save configuration, define paths and constants |
| `daemon.py` | Process daemonization, PID management |
| `service.py` | Main service loop, component initialization, capture mode selection |
| `network.py` | UDP listeners, packet queue, Scapy capture |
| `packet_processor.py` | High-performance packet processing pipeline |
| `snmp.py` | SNMP packet parsing and filtering logic |
| `metrics.py` | Prometheus metrics collection and export |
| `ebpf.py` | eBPF kernel-space acceleration |

### Sub-Packages

#### `cli/` - Command Line Interface
- `parser.py` - Argument definitions
- `validation.py` - Input sanitization with security patterns
- `executor.py` - Command routing
- `*_commands.py` - Specific command implementations

#### `ha/` - High Availability
- `api.py` - Public functions for HA control
- `cluster.py` - HACluster class implementation
- `state.py` - State machine (PRIMARY/SECONDARY/STANDALONE/etc.)
- `messages.py` - Inter-node communication
- `config.py` - HA configuration model

#### `processing/` - Packet Processing
Alternative modular processing pipeline (fallback):
- `parser.py` - Fast SNMP parsing
- `forwarder.py` - Raw socket forwarding
- `worker.py` - Processing workers
- `stats.py` - Lock-free statistics

#### `core/` - Core Definitions
- `constants.py` - Global constants including `FORWARD_SOURCE_PORT`
- `exceptions.py` - Custom exceptions
- `types.py` - Type definitions

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
│   │     └─► If SECONDARY: increment ha_blocked counter, DROP packet │     │
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
│   └─────────────────────────────────────────────────────────────────┘     │
└───────────────────────────────────────────────────────────────────────────┘
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
   │                 │   (UDP)    │                 │
   │  is_forwarding  │            │  is_forwarding  │
   │     = True      │            │     = False     │
   └────────┬────────┘            └────────┬────────┘
            │                              │
            ▼                              ▼
      Forwards Traps                 Drops Traps
     to Destinations              (ha_blocked++)
```

### HA States

| State | `is_forwarding_enabled()` | Behavior |
|-------|--------------------------|----------|
| PRIMARY | True | Forwards all traps |
| SECONDARY | False | Drops traps, monitors primary |
| STANDALONE | True | No HA, forwards all traps |
| INITIALIZING | False | Starting up, no forwarding |
| FAILOVER | False | Transitioning states |
| SPLIT_BRAIN | False | Both nodes detected as primary |
| ERROR | False | Error state, no forwarding |

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

All packet forwarding uses a single `forward_packet()` function with:
- Centralized destination management
- Consistent source port (`FORWARD_SOURCE_PORT = 10162`)
- BPF filter exclusion to prevent re-capture loops

### 2. HA Check at Processing Time

HA state is checked when processing packets, not when queuing:
- Handles all capture modes consistently
- Eliminates race conditions during state changes
- Packets dropped immediately on SECONDARY nodes

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

## Performance Targets

| Metric | Target | Notes |
|--------|--------|-------|
| Throughput | 10,000+ traps/sec | Sustained, with eBPF: 30k+ |
| Queue Capacity | 200,000 packets | Handles alarm floods |
| Failover Time | <3 seconds | Typical: 1-2 seconds |
| Memory | <500MB | Typical operation |
| CPU (with eBPF) | <30% | At 10k traps/sec |

## Constants Reference

Key constants in `core/constants.py`:

```python
FORWARD_SOURCE_PORT = 10162  # Distinct from trap port 162
DEFAULT_TRAP_PORT = 162
QUEUE_CAPACITY = 200000
WORKER_COUNT = cpu_count() * 2
```

## File Naming Conventions

| Pattern | Purpose |
|---------|---------|
| `*_commands.py` | CLI command implementations |
| `*_test*.py` | Test files |
| `*.json` | Configuration files |

---

**Version**: 0.5.2 (Beta)  
**Last Updated**: 2025-01-10
