# Changelog

All notable changes to TrapNinja will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## About Version Numbers

**TrapNinja is currently in BETA (0.x.x versions)**

- **0.x.x versions** indicate pre-release/beta software
- **Breaking changes can occur** between minor versions during beta
- **Version 1.0.0** will be released when the software is production-ready with a stable API
- See the "Road to 1.0.0" section below for our stability goals

---

## [0.7.0] - 2025-12-12

### Added

#### Granular Statistics System - Service Integration
- **Enabled granular statistics collection in service** - The stats module was fully
  implemented but never initialized. Now properly integrated into service startup.
- **Per-IP statistics**: Track trap volume, rates, and breakdowns per source IP
- **Per-OID statistics**: Track trap volume, rates, and source IP distribution per OID
- **Per-destination statistics**: Track forwards, success rates, and source breakdown
- **REST API server** for web frontend integration (optional, enable via env var)
  - `GET /api/stats/summary` - Overall statistics summary
  - `GET /api/stats/dashboard` - Full dashboard data for visualization
  - `GET /api/stats/ips/top` - Top source IPs by volume or rate
  - `GET /api/stats/oids/top` - Top OIDs by volume or rate
  - `GET /api/stats/ip/<ip>` - Detailed stats for specific IP
  - `GET /api/stats/oid/<oid>` - Detailed stats for specific OID
  - `GET /api/stats/matrix` - IP/OID matrix for heatmap visualization
  - `GET /api/health` - Health check endpoint
- **LRU-bounded storage** prevents unbounded memory growth
- **Automatic stale entry cleanup** removes idle entries
- **Prometheus export** with dimensional labels (per-IP, per-OID)
- **JSON export** for custom integrations

#### CLI Commands for Granular Statistics
- `stats summary` - Show statistics overview
- `stats top-ips [-n N] [-s sort]` - View top source IPs
- `stats top-oids [-n N] [-s sort]` - View top OIDs
- `stats ip <ip>` - Detailed stats for specific IP
- `stats oid <oid>` - Detailed stats for specific OID
- `stats destinations` - Destination statistics
- `stats dashboard` - Export full dashboard data
- `stats api [--host HOST] [--port PORT]` - Start standalone API server
- `stats export [-f format] [-o file]` - Export stats to file
- `stats reset` - Reset all statistics

#### Configuration
- New `config/stats_config.json` for granular statistics settings
- Environment variables for API server:
  - `TRAPNINJA_STATS_API_PORT` - Enable API server on specified port
  - `TRAPNINJA_STATS_API_HOST` - API server bind host (default: 0.0.0.0)

### Fixed

#### Critical: Granular Statistics Not Collecting
- **Root Cause**: The `trapninja/stats/` module was fully implemented with
  collector, models, API, and HTTP server, but `initialize_stats()` was never
  called in `service.py`. The packet processor imported `get_stats_collector()`
  but it always returned `None`.
- **Solution**: Added proper initialization of granular statistics system in
  service startup, with configuration from `CollectorConfig`.
- **Impact**: Per-IP/OID statistics now actually collect and can be queried
  via CLI commands or REST API.

### Documentation
- Added `documentation/GRANULAR_STATS.md` with comprehensive guide
- API endpoint reference with example responses
- Web frontend integration guide
- Prometheus/Grafana integration examples

---

## [0.6.0] - 2025-06-15

### Added

#### Redis-Based Trap Caching System
- **New cache module** (`trapninja/cache/`) for trap buffering and replay
  - `redis_backend.py`: Redis Streams-based cache with rolling retention
  - `replay.py`: Time-window based trap replay with rate limiting
  - Automatic retention trimming (configurable, default 2 hours)
  - Non-blocking cache operations - failures don't affect forwarding

#### Cache CLI Commands
- `--cache-status`: View cache statistics and per-destination info
- `--cache-query`: Preview cached traps for a time window
- `--cache-replay`: Replay cached traps with rate limiting
- `--cache-clear`: Clear cached entries (per-destination or all)
- `--cache-help`: Comprehensive cache system help

#### Cache Features
- Per-destination streams for isolated replay
- Flexible time formats: relative (`-2h`, `-30m`), time-only (`14:30`), full datetime
- OID and source IP filtering during replay
- Dry-run mode for replay preview
- Progress tracking during replay operations
- Automatic integration with existing forwarding pipeline

### Configuration
- New `cache_config.json` configuration file
- Configurable retention period, Redis connection, trim intervals
- Optional password authentication for Redis

### Documentation
- Added `documentation/CACHE.md` with comprehensive cache system guide
- Memory sizing guide for Redis capacity planning
- Integration guide for HA deployments

### Technical Details
- Cache writes are fire-and-forget (non-blocking)
- Traps cached after successful forwarding
- Background retention trimmer thread
- Statistics tracking: cached, cache_failures in processor stats

### Fixed

#### Critical: Metrics All Showing Zero Values
- **Root Cause**: The `metrics.py` module had its own counters that were never
  incremented by the packet processing code. The `packet_processor.py` used
  separate `AtomicStats` that weren't synced to the Prometheus exporter.
- **Solution**: Unified metrics system that collects from all sources:
  - `packet_processor.py` → AtomicStats (core processing metrics)
  - `network.py` → QueueStats (queue depth and utilization)
  - `ha.py` → HA cluster status (if enabled)
  - `cache.py` → Cache availability (if enabled)
- **New metrics added**:
  - `trapninja_fast_path_hits_total` - Packets using optimized path
  - `trapninja_slow_path_hits_total` - Packets requiring full parsing
  - `trapninja_fast_path_ratio` - Performance efficiency percentage
  - `trapninja_processing_rate` - Current packets/second
- **Documentation**: Added `documentation/METRICS.md` with full metrics reference
- **Testing**: Updated `tests/metrics-test.py` with integration tests

---

## [0.5.2] - 2025-01-09

### Fixed

#### Critical: Socket + Sniff Capture Duplication (2x Multiplication)
- **Disabled auto-start of UDP socket listeners** during config load
  - Old: `load_config(restart_udp_listeners)` started listeners before capture mode was determined
  - New: `load_config(None)` - listeners only start explicitly in socket mode
- **Added explicit socket cleanup** before sniff mode starts
- **Root cause**: UDP socket listeners were running simultaneously with Scapy sniff(),
  causing every packet to be captured twice (once by each method)
- Socket listeners now ONLY start in socket capture mode

#### Defense-in-Depth: Application-Level Duplicate Check
- Added safety check in `network.py`'s `forward_trap()` to reject packets with
  our source port (FORWARD_SOURCE_PORT) even if BPF filter fails

### Changed
- Capture mode selection now strictly enforces single capture method
- Improved logging for capture mode initialization

---

## [0.5.1] - 2025-01-09

### Fixed

#### Critical: Packet Re-Capture Loop (10x Multiplication)
- **Fixed BPF filter in sniff mode** - Changed to exclude our own forwarded packets:
  - Old: `udp port 162` (matched both incoming AND our outgoing)
  - New: `udp dst port 162 and not udp src port 10162`
- **Centralized FORWARD_SOURCE_PORT constant** (10162) in `core/constants.py`
- **Updated all forwarding modules** to use distinct source port:
  - `packet_processor.py` - Uses FORWARD_SOURCE_PORT for raw socket forwarding
  - `snmp.py` - Uses FORWARD_SOURCE_PORT for fallback forwarding
  - `network.py` - Uses FORWARD_SOURCE_PORT in Scapy fallback
  - `processing/forwarder.py` - Uses FORWARD_SOURCE_PORT for socket pool
- **Root cause**: Forwarded packets have dport=162 (standard trap port), so even
  changing source port alone wasn't enough - BPF filter must explicitly exclude
  packets from our forward source port
- **Documentation**: See `documentation/fixes/PACKET_RECAPTURE_LOOP_FIX.md`

### Changed
- BPF filter now explicitly excludes packets from FORWARD_SOURCE_PORT (10162)
- Forward source port changed from 162 to 10162 to enable packet identification

### Planned for Future Releases
- Additional EMS integrations
- Web UI for management and monitoring
- Advanced analytics and reporting
- Multi-tenant support
- Cloud deployment templates

---

## [0.5.0] - 2025-01-15

**Beta Release: High Availability, SNMPv3, and CLI Refactoring**

This is a major feature release combining HA capabilities, SNMPv3 decryption,
and a complete CLI architecture refactoring. Still in beta - API may change.

### Added

#### High Availability (HA)
- **Primary/Secondary coordination** with automatic role negotiation
- **Automatic failover** with configurable timeouts and delays
- **Heartbeat monitoring** with peer health detection
- **Split-brain detection** and resolution with priority-based election
- **Priority-based PRIMARY election** for controlled failover
- **Shared secret authentication** for HA communication (configurable)
- **Manual failover commands** for maintenance scenarios
- **Manual promotion/demotion** (`--promote`, `--demote`)
- **Persistent state tracking** across restarts
- **Prometheus metrics** for HA monitoring
- **HA help command** (`--ha-help`) with examples and scenarios

#### SNMPv3 Decryption
- **Transparent SNMPv3 to SNMPv2c conversion** for legacy system compatibility
- **Secure credential storage** using Fernet encryption
- **Support for all security levels**: authPriv, authNoPriv, noAuthNoPriv
- **Multiple authentication protocols**: MD5, SHA, SHA-224, SHA-256, SHA-384, SHA-512
- **Multiple privacy protocols**: DES, 3DES, AES-128, AES-192, AES-256
- **CLI commands** for credential management
- **Password-based credential protection** with Fernet key derivation
- **Automatic decryption** of incoming SNMPv3 traps
- **Transparent forwarding** as SNMPv2c to destinations

#### CLI Architecture
- **Modular CLI structure** with separated command modules:
  - `cli/parser.py` - Argument parsing configuration
  - `cli/validation.py` - Input validation and sanitization  
  - `cli/daemon_commands.py` - Service lifecycle commands
  - `cli/filtering_commands.py` - IP and OID filtering
  - `cli/ha_commands.py` - High Availability management
  - `cli/snmpv3_commands.py` - SNMPv3 credential management
  - `cli/executor.py` - Command orchestration
- **Thread-safe configuration management** with atomic file operations
- **Comprehensive input validation** with security-focused patterns
- **LRU caching** for validation functions
- **Interactive confirmation prompts** for destructive operations

#### Security
- **Command injection detection** in input validation
- **Path traversal prevention** 
- **XSS-pattern detection** in user inputs
- **Control character removal** from all user input
- **Input length limits** enforcement
- **Reserved name checking**

#### Configuration
- **HA configuration file** (`config/ha_config.json`)
- **SNMPv3 credential storage** (encrypted)
- **Per-file locking** prevents race conditions
- **Configuration caching** reduces file I/O

### Changed

#### Architecture
- **CLI module completely refactored** for separation of concerns
- **Command handling separated** into focused, testable modules
- **Configuration operations now atomic** with write-to-temp-then-rename
- **Enhanced error handling** throughout CLI layer
- **Improved daemon** for HA coordination
- **Better signal handling** for graceful restart

#### HA System
- **Improved peer discovery** with multi-attempt logic (3 attempts × 3s timeout)
- **Better state coordination** with manual override support
- **Enhanced split-brain handling** with configurable behavior
- **Graceful failback** mechanism with optional auto-failback
- **More informative status display** with actionable suggestions

#### Network Handling  
- **Multi-instance support** with proper port management
- **Enhanced listener** with HA state awareness
- **Forwarding control** based on HA state (PRIMARY forwards, SECONDARY doesn't)
- **Better error handling** in network operations

#### Metrics
- **Expanded Prometheus metrics** with HA-specific metrics
- **Per-destination metrics** for HA forwarding
- **State change tracking** for debugging

### Fixed
- **Race conditions** in configuration file access
- **Input validation edge cases** that could bypass security checks
- **Command argument parsing issues** in complex scenarios
- **Thread synchronization** in configuration reload
- **Split-brain scenarios** during startup
- **State persistence** across restarts
- **Network listener** port binding conflicts in multi-instance setup
- **Configuration reload** handling in HA scenarios
- **Memory leaks** in HA message handling

### Performance
- **Configuration caching** reduces file I/O by ~70%
- **LRU-cached validation** improves response time for repeated inputs
- **Precompiled regex patterns** eliminate runtime compilation overhead
- **Atomic operations** reduce lock contention
- **Minimal overhead** for HA heartbeats (~100 bytes/second)
- **Fast failover** (<5 seconds typical)

### Documentation
- **CLI module README** with comprehensive usage examples
- **HA deployment guide** with setup instructions
- **HA testing guide** with comprehensive test scenarios
- **SNMPv3 configuration guide** with examples
- **Extension guidelines** for adding new commands
- **Security best practices** documentation
- **Troubleshooting guides** for HA and SNMPv3 issues

### Notes
This release combines major features that would typically be spread across
multiple major versions. Since we're in beta (0.x.x), we're grouping related
functionality together. Breaking changes may occur in future 0.x.x releases.

---

## [0.4.0] - 2024-12-15

**Beta Release: eBPF Acceleration**

This release introduces optional eBPF (Extended Berkeley Packet Filter) acceleration
for significantly improved performance and reduced CPU usage.

### Added

#### eBPF Support
- **eBPF kernel-space packet filtering** for high performance
- **Reduced CPU usage** (up to 70% reduction in high-traffic scenarios)
- **Improved packet processing** throughput (2-3x improvement)
- **Graceful fallback** to raw socket capture when eBPF unavailable
- **eBPF support detection** at startup
- **Status reporting** for eBPF availability
- **Compatibility checking**:
  - Root privilege check
  - BCC library availability check
  - Kernel version check (4.4+ required)
- **Performance benchmarking** utilities

#### Startup Enhancements
- **Enhanced startup checks** with detailed status reporting
- **Feature detection** and reporting
- **Improved error messages** for missing dependencies
- **Installation guidance** for eBPF dependencies

### Changed

#### Packet Processing
- **Optimized packet processing pipeline** with eBPF path
- **Enhanced threading model** for better concurrency
- **Improved memory management** with packet buffer pooling
- **Better queue management** for packet handling

#### Performance
- **Reduced system call overhead** via eBPF
- **Lower context switching** with kernel-space filtering
- **Better cache utilization** with optimized data structures
- **Improved scalability** for high packet rates

### Fixed
- **Packet loss** during high traffic scenarios (100k+ traps/minute)
- **Memory leaks** in packet processing loop
- **Thread synchronization issues** in packet queuing
- **CPU spikes** during traffic bursts

### Performance Benchmarks
- **Without eBPF**: ~10k traps/sec, ~60% CPU
- **With eBPF**: ~30k traps/sec, ~20% CPU
- **Latency**: <1ms average with eBPF vs <5ms without

### Documentation
- **eBPF installation guide** (`install_ebpf_deps.sh`)
- **Performance tuning guide** with recommendations
- **Troubleshooting guide** for eBPF issues
- **Benchmark results** documentation

---

## [0.3.0] - 2024-11-01

**Beta Release: Enhanced Filtering and Metrics**

### Added

#### Filtering
- **OID-based filtering** with regex pattern support
- **IP-based filtering** with CIDR notation support
- **Trap blocking** by OID pattern
- **Redirection rules**:
  - By source IP
  - By OID pattern
  - By destination group
- **Dynamic configuration reload** without restart

#### Metrics
- **Prometheus metrics endpoint** (default: port 8080)
- **Key metrics**:
  - `trapninja_traps_received_total` - Total traps received
  - `trapninja_traps_forwarded_total` - Total traps forwarded
  - `trapninja_traps_dropped_total` - Total traps dropped
  - `trapninja_traps_processing_seconds` - Processing time histogram
  - `trapninja_active_connections` - Active network connections
- **Per-destination metrics** for detailed monitoring
- **Per-port metrics** for multi-listener scenarios

#### Configuration
- **Blocked IPs configuration** (`config/blocked_ips.json`)
- **Blocked OIDs configuration** (`config/blocked_traps.json`)
- **Redirection configurations**:
  - `config/redirected_ips.json` - IP-based redirection
  - `config/redirected_oids.json` - OID-based redirection
  - `config/redirected_destinations.json` - Destination redirection

### Changed

#### Filtering Engine
- **Enhanced filtering** with compiled regex for performance
- **Improved OID matching** with prefix matching support
- **Better CIDR handling** for IP filtering
- **Configuration caching** for faster lookups

#### Logging
- **Enhanced logging** with structured format
- **Per-filter logging** for debugging
- **Configurable log levels** per component
- **Log rotation** support

### Fixed
- **SNMP parsing** edge cases with malformed traps
- **Configuration validation** with better error messages
- **Memory usage** in long-running instances
- **Filter matching** corner cases

### Performance
- **Filter caching** reduces lookup time by 90%
- **Compiled regex** improves pattern matching
- **Reduced allocations** in hot paths

---

## [0.2.0] - 2024-09-15

**Beta Release: Multi-Port and Destinations**

### Added

#### Multi-Port Support
- **Multiple UDP ports** for trap reception
- **Port-specific configurations** via `config/listen_ports.json`
- **Independent listeners** per port
- **Port-based routing** to destinations

#### Destination Management
- **Destination groups** with tagging
- **Multiple destinations** per group
- **Load balancing** across group members (round-robin)
- **Destination health checking** (basic)
- **Configuration file** `config/destinations.json`

#### Redirection
- **Basic redirection rules** for trap routing
- **Tag-based routing** to destination groups
- **Conditional forwarding** based on source

#### Daemon Mode
- **Daemon mode** with proper daemonization
- **PID file** management
- **Signal handling** for graceful shutdown
- **Service management** compatibility

### Changed

#### SNMP Handling
- **Improved trap parsing** with better error handling
- **Enhanced network handling** with timeout management
- **Better socket management** for reliability
- **Improved exception handling** in packet processing

#### Configuration
- **Better configuration structure** with separate files
- **Configuration validation** on load
- **Default configurations** for common scenarios
- **Environment variable support** for overrides

### Fixed
- **UDP socket handling** issues with high load
- **Trap forwarding** reliability under packet loss
- **Memory leaks** in destination management
- **Signal handling** during shutdown

---

## [0.1.0] - 2024-08-01

**Initial Beta Release**

### Added

#### Core Functionality
- **SNMP trap reception** on single UDP port
- **Basic trap parsing** with SNMPv2c support
- **Simple trap forwarding** to single destination
- **Basic filtering** by source IP
- **Configuration file** support (JSON)

#### Features
- **Command-line interface** with basic options
- **Logging** to file and console
- **Configuration examples** included
- **Basic error handling** and recovery

#### Documentation
- **README** with installation instructions
- **Configuration examples** for common scenarios
- **Basic usage guide**

### Known Limitations
- Single listening port only
- No eBPF support
- No HA support
- No SNMPv3 support
- Basic filtering only
- No metrics/monitoring

---

## Road to 1.0.0

**Version 1.0.0 Requirements (Production-Ready)**

Before releasing 1.0.0, we need:

### Stability Goals
- [ ] API stability - no breaking changes for 6 months
- [ ] Extensive field testing in production-like environments
- [ ] Performance benchmarks under real NOC conditions
- [ ] Security audit completed
- [ ] Comprehensive test coverage (>80%)

### Feature Completeness
- [ ] Complete documentation suite
- [ ] Migration guides from 0.x to 1.0
- [ ] All critical bugs resolved
- [ ] Automated testing in CI/CD
- [ ] Production deployment guides

### Community Feedback
- [ ] Beta testing feedback incorporated
- [ ] At least 3 production deployments
- [ ] User feedback on API design
- [ ] Documentation validated by users

**Current Status: Beta (0.5.0)**
- ✅ Core features implemented
- ✅ HA and SNMPv3 working
- ✅ Performance optimized with eBPF
- ⏳ Field testing in progress
- ⏳ Documentation being refined
- ⏳ Security audit planned

**Target 1.0.0 Release: Q2 2025**

---

## Version History Summary

| Version | Date | Type | Key Features | Status |
|---------|------|------|--------------|--------|
| **0.5.0** | 2025-01-15 | Minor | HA, SNMPv3, CLI refactoring | **Current** |
| 0.4.0 | 2024-12-15 | Minor | eBPF acceleration | Beta |
| 0.3.0 | 2024-11-01 | Minor | Enhanced filtering, Metrics | Beta |
| 0.2.0 | 2024-09-15 | Minor | Multi-port, Destinations | Beta |
| 0.1.0 | 2024-08-01 | Initial | Basic forwarding | Beta |

---

## Semantic Versioning During Beta (0.x.x)

While in beta, we follow these guidelines:

- **0.MINOR.PATCH** format indicates pre-release software
- **MINOR** version bumps may include breaking changes
- **PATCH** version bumps for bug fixes only
- **Major features** increment MINOR version
- **Breaking changes** are documented clearly in release notes
- **Migration guides** provided for breaking changes

Once we reach **1.0.0**:
- **MAJOR** version for breaking changes
- **MINOR** version for new features (backward compatible)
- **PATCH** version for bug fixes only

---

## Upgrade Notes

### Upgrading to 0.5.0 from 0.4.x
- **Add HA configuration** if using HA features (optional)
- **SNMPv3 credentials** need to be added via CLI (optional)
- **New configuration files** - examples provided
- **CLI structure changed** - imports may need updates if using programmatically
- **Test failover** before production deployment (if using HA)
- **Review security settings** - new input validation may affect custom scripts

### Upgrading to 0.4.0 from 0.3.x
- **Install eBPF** dependencies for best performance (optional)
- **Run as root** if using eBPF
- **Works without eBPF** - graceful fallback

### Upgrading to 0.3.0 from 0.2.x
- **New configuration files** for filtering and metrics
- **Metrics endpoint** enabled by default on port 8080
- **OID filtering** may affect existing trap flows - test thoroughly

### Upgrading to 0.2.0 from 0.1.x
- **Configuration format changed** - use separate JSON files
- **Port configuration** moved to `listen_ports.json`
- **Destinations** now in `destinations.json`

---

## Development Process

### Versioning Policy (Beta)
We follow [Semantic Versioning](https://semver.org/) with beta adaptations:
- **0.MINOR.x**: New features, may include breaking changes
- **0.x.PATCH**: Bug fixes, backward compatible
- **1.0.0**: Stable release when production-ready

### Release Process
1. Update `VERSION` file
2. Update this `CHANGELOG.md`
3. Run verification tests: `python tests/test_versioning.py`
4. Commit: `git commit -m "Release v0.x.0"`
5. Tag: `git tag -a v0.x.0 -m "Release 0.x.0: Description"`
6. Push: `git push origin main && git push origin v0.x.0`

### Contributing
When contributing, please:
- Add changes to `[Unreleased]` section
- Follow the existing format
- Group changes by type (Added, Changed, Fixed, etc.)
- Reference issue numbers where applicable
- Note if changes are breaking

---

[Unreleased]: https://github.com/yourusername/trapninja/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/yourusername/trapninja/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/yourusername/trapninja/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/yourusername/trapninja/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/yourusername/trapninja/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/yourusername/trapninja/releases/tag/v0.1.0
