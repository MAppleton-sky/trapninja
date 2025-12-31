# TrapNinja Directory Structure

**Version:** 0.7.13  
**Last Updated:** December 31, 2025

This document describes the repository layout and deployment architecture.

## Repository Layout

```
trapninja/
├── src/                          # ← DEPLOYABLE CODE
│   ├── trapninja.py              # Main entry point
│   ├── VERSION                   # Version file (read by code)
│   ├── trapninja/                # Python package
│   │   ├── __init__.py           # Package exports
│   │   ├── __version__.py        # Reads VERSION file
│   │   ├── main.py               # CLI argument handling
│   │   ├── service.py            # Main service orchestration
│   │   ├── config.py             # Configuration loading
│   │   ├── daemon.py             # Daemon management
│   │   ├── network.py            # Network/UDP listener logic
│   │   ├── snmp.py               # SNMP processing logic
│   │   ├── ebpf.py               # eBPF acceleration module
│   │   ├── shadow.py             # Shadow/mirror mode logic
│   │   ├── control.py            # Unix socket control interface
│   │   ├── metrics.py            # Prometheus metrics export
│   │   ├── logger.py             # Logging configuration
│   │   ├── redirection.py        # IP/OID redirection
│   │   ├── diagnostics.py        # System diagnostics
│   │   ├── snmpv3_decryption.py  # SNMPv3 decryption engine
│   │   ├── snmpv3_credentials.py # SNMPv3 credential management
│   │   │
│   │   ├── cache/                # Redis caching module
│   │   │   ├── __init__.py
│   │   │   ├── redis_backend.py  # TrapCache, RetentionManager
│   │   │   ├── replay.py         # ReplayEngine
│   │   │   └── failover/         # Failover replay
│   │   │       ├── __init__.py
│   │   │       ├── detector.py   # GapDetector
│   │   │       ├── manager.py    # FailoverReplayManager
│   │   │       └── tracker.py    # FailoverTracker
│   │   │
│   │   ├── cli/                  # CLI command modules
│   │   │   ├── __init__.py
│   │   │   ├── parser.py         # Argument parsing
│   │   │   ├── validation.py     # Input validation
│   │   │   ├── executor.py       # Command dispatch
│   │   │   ├── output.py         # Output formatting
│   │   │   ├── daemon_commands.py
│   │   │   ├── filtering_commands.py
│   │   │   ├── ha_commands.py
│   │   │   ├── cache_commands.py
│   │   │   ├── stats_commands.py
│   │   │   ├── stats.py
│   │   │   ├── shadow_commands.py
│   │   │   ├── snmpv3_commands.py
│   │   │   ├── sync_commands.py
│   │   │   └── failover_commands.py
│   │   │
│   │   ├── core/                 # Types, constants, exceptions
│   │   │   ├── __init__.py
│   │   │   ├── constants.py      # FORWARD_SOURCE_PORT, etc.
│   │   │   ├── exceptions.py     # TrapNinjaError, etc.
│   │   │   └── types.py          # PacketData, Destination, etc.
│   │   │
│   │   ├── ha/                   # High Availability module
│   │   │   ├── __init__.py
│   │   │   ├── api.py            # Public HA API
│   │   │   ├── cluster.py        # HACluster implementation
│   │   │   ├── config.py         # HAConfig dataclass
│   │   │   ├── messages.py       # HAMessage types
│   │   │   ├── state.py          # HAState enum
│   │   │   └── sync/             # Config synchronization
│   │   │       ├── __init__.py
│   │   │       ├── config_bundle.py
│   │   │       └── manager.py
│   │   │
│   │   ├── processing/           # Packet processing
│   │   │   ├── __init__.py
│   │   │   ├── parser.py         # SNMP parsing
│   │   │   ├── forwarder.py      # Packet forwarding
│   │   │   ├── worker.py         # Processing workers
│   │   │   └── stats.py          # Processing statistics
│   │   │
│   │   └── stats/                # Statistics collection
│   │       ├── __init__.py
│   │       ├── collector.py      # GranularStatsCollector
│   │       ├── models.py         # IPStats, OIDStats, etc.
│   │       └── api.py            # Query API
│   │
│   └── config/                   # Default configuration files
│       ├── destinations.json
│       ├── blocked_ips.json
│       ├── blocked_traps.json
│       ├── redirected_ips.json
│       ├── redirected_oids.json
│       ├── redirected_destinations.json
│       ├── ha_config.json
│       ├── cache_config.json
│       ├── stats_config.json
│       └── listen_ports.json
│
├── dev/                          # ← DEVELOPMENT FILES (not deployed)
│   ├── CHANGELOG.md              # Version history
│   ├── requirements.txt          # Full Python dependencies
│   ├── requirements-minimal.txt  # Minimal dependencies
│   ├── scripts/                  # Development scripts
│   │   ├── download-packages.sh
│   │   └── install-packages.sh
│   ├── tests/                    # Test files
│   │   ├── trapninja-tests.py
│   │   ├── network-tests.py
│   │   ├── snmp-parser-tests.py
│   │   ├── config-tests.py
│   │   ├── granular-stats-test.py
│   │   └── metrics-test.py
│   └── tools/                    # Development tools
│       ├── cleanup.sh
│       └── snmp_trap_tracker.sh
│
├── docs/                         # ← DOCUMENTATION (not deployed)
│   ├── ARCHITECTURE.md           # System architecture
│   ├── USER_GUIDE.md             # Operations guide
│   ├── INSTALL.md                # Installation instructions
│   ├── CLI.md                    # CLI reference
│   ├── CLI_MODULE.md             # CLI module architecture
│   ├── HA.md                     # High Availability guide
│   ├── CACHE.md                  # Redis cache setup
│   ├── FAILOVER_REPLAY.md        # Failover replay system
│   ├── CONFIG.md                 # Configuration reference
│   ├── CONFIG_SYNC.md            # Config sync between HA nodes
│   ├── METRICS.md                # Prometheus metrics
│   ├── GRANULAR_STATS.md         # Statistics system
│   ├── SHADOW_MODE.md            # Shadow/mirror mode
│   ├── SNMPV3_CREDENTIALS.md     # SNMPv3 setup
│   ├── TROUBLESHOOTING.md        # Problem diagnosis
│   ├── CODE_REVIEW.md            # Code review notes
│   ├── DIRECTORY_STRUCTURE.md    # This file
│   └── refactoring/              # Refactoring documentation
│       ├── REFACTORING_PLAN.md
│       └── CLEANUP_SUMMARY.md
│
├── ansible/                      # ← DEPLOYMENT AUTOMATION
│   ├── deploy.yml                # Main deployment playbook
│   └── templates/                # Jinja2 templates
│       ├── trapninja.service.j2
│       ├── destinations.json.j2
│       ├── ha_config.json.j2
│       └── cache_config.json.j2
│
├── README.md                     # Repository documentation
└── .gitignore               
```

## Package Summary

| Package | Files | Purpose |
|---------|-------|---------|
| `cache/` | 6 | Redis-based trap caching with failover replay |
| `cli/` | 15 | Command-line interface modules |
| `core/` | 4 | Shared constants, types, exceptions |
| `ha/` | 9 | High availability with config sync |
| `processing/` | 5 | High-performance packet processing |
| `stats/` | 4 | Granular per-IP/OID statistics |

## Deployment Model

### What Gets Deployed

Only the contents of `src/` are deployed to the target system:

```
/opt/trapninja/               # trapninja_dest
├── trapninja.py              # Entry point
├── VERSION                   # Version file
├── trapninja/                # Python package
│   ├── cache/                # Caching module
│   ├── cli/                  # CLI module
│   ├── core/                 # Core module
│   ├── ha/                   # HA module
│   ├── processing/           # Processing module
│   ├── stats/                # Statistics module
│   └── *.py                  # Core modules
└── config/                   # Default configs (copied to /etc/)
```

### Configuration Directory

Site-specific configurations are stored separately:

```
/etc/trapninja/               # trapninja_config_dest
├── destinations.json         # Forward destinations
├── blocked_ips.json          # Blocked source IPs
├── blocked_traps.json        # Blocked OIDs
├── redirected_ips.json       # IP redirection rules
├── redirected_oids.json      # OID redirection rules
├── redirected_destinations.json  # Redirect targets
├── ha_config.json            # HA settings
├── cache_config.json         # Redis cache settings
├── stats_config.json         # Statistics settings
└── listen_ports.json         # UDP ports to listen on
```

## Ansible Deployment

### Simple Deployment

The ansible playbook syncs only `src/`:

```yaml
# From ansible/deploy.yml
- name: Sync TrapNinja application files
  synchronize:
    src: "{{ trapninja_src }}/src/"     # Only deploy src/
    dest: "{{ trapninja_dest }}/"
    delete: yes
    rsync_opts:
      - "--exclude=__pycache__/"
      - "--exclude=*.pyc"
      - "--exclude=*.pyo"
      - "--exclude=.DS_Store"
      - "--exclude=*.bak"
```

### Manual Deployment

```bash
# Sync source files to target
rsync -avz --delete \
    --exclude='__pycache__/' \
    --exclude='*.pyc' \
    --exclude='*.bak' \
    src/ root@target:/opt/trapninja/

# Copy default configs (first time only)
scp -r src/config/* root@target:/etc/trapninja/
```

## Development Workflow

### Running Locally

```bash
# Install dependencies
pip3.9 install --break-system-packages -r dev/requirements.txt

# Run from src directory
cd src
sudo python3.9 -O trapninja.py

# Run tests
cd src
python3.9 ../dev/tests/trapninja-tests.py
```

### Running in Production

```bash
# Via systemd service
sudo systemctl start trapninja

# Direct execution
cd /opt/trapninja
sudo python3.9 -O trapninja.py
```

## Directory Purposes

| Directory | Purpose | Deployed? |
|-----------|---------|-----------|
| `src/` | Production code | ✅ Yes |
| `src/trapninja/` | Python package | ✅ Yes |
| `src/config/` | Default configs | ✅ Yes (copied to /etc/) |
| `dev/` | Development files | ❌ No |
| `docs/` | Documentation | ❌ No |
| `ansible/` | Deployment automation | ❌ No |

## Version Management

The version is stored in a single location:

```
src/VERSION          # Contains version string e.g., "0.7.13"
```

This is read by `src/trapninja/__version__.py` which provides:
- `__version__` - Version string
- `VERSION_INFO` - Version tuple for comparisons
- `FEATURES` - Feature flags based on version
- Helper functions for version display

## Air-Gapped Deployment

For systems without internet access:

1. **On build machine**: Download packages using `dev/scripts/download-packages.sh`
2. **Transfer**: Copy packages and `src/` directory to target
3. **On target**: Install packages using `dev/scripts/install-packages.sh`
4. **Deploy**: Copy `src/` contents to `/opt/trapninja/`

## Related Documentation

- [INSTALL.md](INSTALL.md) - Detailed installation instructions
- [USER_GUIDE.md](USER_GUIDE.md) - Operations guide
- [ARCHITECTURE.md](ARCHITECTURE.md) - System design
- [CLI.md](CLI.md) - CLI reference
