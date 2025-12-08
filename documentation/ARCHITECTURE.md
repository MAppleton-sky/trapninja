# TrapNinja Code Architecture

## Overview

TrapNinja is a high-performance SNMP trap forwarder designed for telecommunications environments requiring 99.999% availability. The codebase is organized into modular components for maintainability and ease of development.

## Directory Structure

```
trapninja/
├── trapninja.py              # Main entry point with startup logic
├── trapninja/                 # Core package
│   ├── __init__.py           # Package initialization, exports version info
│   ├── __version__.py        # Version information (single source of truth)
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
│   ├── control.py            # Control socket for CLI communication
│   ├── diagnostics.py        # System diagnostics
│   ├── ebpf.py               # eBPF acceleration
│   ├── snmpv3_credentials.py # SNMPv3 credential store
│   ├── snmpv3_decryption.py  # SNMPv3 decryption
│   │
│   ├── cli/                  # Command-line interface module
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
│   │   ├── constants.py
│   │   ├── exceptions.py
│   │   └── types.py
│   │
│   ├── ha/                   # High Availability package
│   │   ├── __init__.py
│   │   ├── api.py            # Public HA API
│   │   ├── cluster.py        # Cluster management
│   │   ├── config.py         # HA configuration
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
│   ├── destinations.json
│   ├── blocked_ips.json
│   ├── blocked_traps.json
│   ├── ha_config.json
│   ├── listen_ports.json
│   ├── redirected_ips.json
│   ├── redirected_oids.json
│   └── redirected_destinations.json
│
├── documentation/            # All documentation
│   ├── CLI.md
│   └── HA_FORWARDING_FIX.md
│
├── tests/                    # Test files
│   ├── config-tests.py
│   ├── metrics-test.py
│   ├── network-tests.py
│   ├── snmp-parser-tests.py
│   └── trapninja-tests.py
│
├── VERSION                   # Version file
├── CHANGELOG.md              # Change history
└── .gitignore
```

## Module Responsibilities

### Core Modules

| Module | Responsibility |
|--------|---------------|
| `config.py` | Load/save configuration, define paths and constants |
| `daemon.py` | Process daemonization, PID management |
| `service.py` | Main service loop, component initialization |
| `network.py` | UDP listeners, packet queue, Scapy capture |
| `packet_processor.py` | High-performance packet processing pipeline |
| `snmp.py` | SNMP packet parsing and filtering logic |
| `metrics.py` | Prometheus metrics collection and export |

### Sub-Packages

#### `cli/` - Command Line Interface
Modular CLI with separation of concerns:
- `parser.py` - Argument definitions
- `validation.py` - Input sanitization  
- `executor.py` - Command routing
- `*_commands.py` - Specific command implementations

#### `ha/` - High Availability
Complete HA clustering solution:
- `api.py` - Public functions for HA control
- `cluster.py` - HACluster class implementation
- `state.py` - State machine (PRIMARY/SECONDARY/etc.)
- `messages.py` - Inter-node communication
- `config.py` - HA configuration model

#### `processing/` - Packet Processing
Alternative modular processing pipeline:
- `parser.py` - Fast SNMP parsing
- `forwarder.py` - Raw socket forwarding
- `worker.py` - Processing workers
- `stats.py` - Lock-free statistics

#### `core/` - Core Definitions
Shared types and constants:
- `constants.py` - Global constants
- `exceptions.py` - Custom exceptions
- `types.py` - Type definitions

## Data Flow

```
Packet Capture (eBPF/UDP Socket/Scapy)
            │
            ▼
      Packet Queue (200K capacity)
            │
            ▼
   Processing Workers (2x CPU cores)
            │
            ├──► Blocked? → blocked_dest or drop
            │
            ├──► Redirected? → redirected_destinations
            │
            └──► Normal → destinations
```

## HA Architecture

```
   Primary Node                Secondary Node
   ┌─────────────┐            ┌─────────────┐
   │  TrapNinja  │◄─Heartbeat─►│  TrapNinja  │
   │  (Active)   │             │  (Standby)  │
   └─────────────┘            └─────────────┘
         │                           │
         ▼                           ▼
    Forwards Traps               Drops Traps
```

## Key Design Decisions

1. **Modular HA Package**: HA functionality is split into focused modules for easier testing and maintenance

2. **Dual Processing Paths**: `packet_processor.py` is the primary high-performance processor; `processing/` package provides modular alternative

3. **Lock-free Statistics**: Uses Python GIL guarantees for atomic counter operations

4. **Raw Socket Forwarding**: 6-10x faster than Scapy for packet forwarding

5. **Queue-based Processing**: Decouples capture from processing for burst handling

## Performance Targets

- **Throughput**: 10,000+ traps/second sustained
- **Queue Capacity**: 200,000 packets (handles alarm floods)
- **Failover Time**: <3 seconds
- **Memory**: <500MB typical operation

## File Naming Conventions

- `*_commands.py` - CLI command implementations
- `*_test*.py` - Test files  
- `*.json` - Configuration files
- Lowercase with underscores for Python modules

---

**Version**: 0.5.0 (Beta)  
**Target**: 1.0.0 (Q2 2025)
