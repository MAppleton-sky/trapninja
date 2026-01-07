# TrapNinja CLI Reference

## Overview

TrapNinja provides a modern, organized command-line interface using **subcommands** for better discoverability and clearer error messages. Legacy flat-style arguments remain supported for backward compatibility.

## Quick Start

```bash
# Get help on all commands
trapninja --help

# Get help for a specific category
trapninja daemon --help
trapninja filter --help

# Common operations
trapninja daemon start              # Start the service
trapninja daemon status             # Check service status
trapninja filter block-ip 10.0.0.1  # Block an IP address
trapninja ha status                 # Check HA status
trapninja stats summary             # View statistics
```

## Command Categories

| Category  | Description |
|-----------|-------------|
| `daemon`  | Service control (start, stop, restart, status) |
| `filter`  | IP and OID blocking/redirection |
| `ha`      | High Availability configuration |
| `snmpv3`  | SNMPv3 credential management |
| `cache`   | Trap caching and replay |
| `stats`   | Granular statistics and monitoring |
| `metrics` | Prometheus metrics configuration |
| `shadow`  | Shadow/mirror mode for testing |
| `failover`| Failover gap detection and replay |
| `sync`    | Configuration synchronization (HA) |

## Module Structure

```
trapninja/cli/
├── __init__.py              # Public API exports
├── parser.py                # Subcommand-based argument parsing
├── executor.py              # Command routing and execution
├── validation.py            # Input validation and sanitization
├── output.py                # Unified output formatting
├── daemon_commands.py       # Daemon control commands
├── filtering_commands.py    # IP/OID filtering commands
├── ha_commands.py           # High Availability commands
├── snmpv3_commands.py       # SNMPv3 credential management
├── cache_commands.py        # Trap caching operations
├── stats_commands.py        # Statistics commands
├── metrics_commands.py      # Prometheus metrics config
├── shadow_commands.py       # Shadow mode commands
├── failover_commands.py     # Failover replay commands
└── sync_commands.py         # Config sync commands
```

---

## Daemon Commands

Control the TrapNinja daemon service.

```bash
trapninja daemon --help
```

### Start/Stop/Restart

```bash
# Start as background daemon
trapninja daemon start

# Start with custom interface and ports
trapninja daemon start --interface eth0 --ports 162,1162

# Stop daemon
trapninja daemon stop

# Restart daemon
trapninja daemon restart

# Check daemon status
trapninja daemon status
```

### Foreground Mode

Run in foreground for testing and debugging:

```bash
# Basic foreground mode
trapninja daemon foreground

# With debug logging
trapninja daemon foreground --debug

# Shadow mode (observe only, no forwarding)
trapninja daemon foreground --shadow-mode

# Mirror mode (parallel capture)
trapninja daemon foreground --mirror-mode

# Log observed traps to file
trapninja daemon foreground --shadow-mode --log-traps /tmp/traps.log

# Force specific capture mode
trapninja daemon foreground --capture-mode sniff
```

### Configuration

```bash
# Show current configuration
trapninja daemon config

# Show configuration as JSON
trapninja daemon config --json

# Validate configuration without starting
trapninja daemon config --validate

# Show queue statistics
trapninja daemon queue-stats
```

### Logging Options

Available on `start`, `restart`, and `foreground` commands:

```bash
trapninja daemon start --log-level DEBUG
trapninja daemon start --log-max-size 10M --log-backup-count 5
trapninja daemon start --log-compress
```

---

## Filter Commands

Manage trap filtering and redirection rules.

```bash
trapninja filter --help
```

### IP Blocking

```bash
# Block an IP address
trapninja filter block-ip 10.0.1.50

# Unblock an IP address
trapninja filter unblock-ip 10.0.1.50

# List all blocked IPs
trapninja filter list-blocked-ips
```

### OID Blocking

```bash
# Block an OID pattern
trapninja filter block-oid 1.3.6.1.4.1.8072.2.3.0.1

# Unblock an OID pattern
trapninja filter unblock-oid 1.3.6.1.4.1.8072.2.3.0.1

# List all blocked OIDs
trapninja filter list-blocked-oids
```

### IP Redirection

```bash
# Redirect traps from IP to destination group
trapninja filter redirect-ip 10.0.0.1 --tag security

# Remove IP redirection
trapninja filter unredirect-ip 10.0.0.1

# List all IP redirections
trapninja filter list-redirected-ips
```

### OID Redirection

```bash
# Redirect traps with OID to destination group
trapninja filter redirect-oid 1.3.6.1.4.1.9.9.41.2.0.1 --tag security

# Remove OID redirection
trapninja filter unredirect-oid 1.3.6.1.4.1.9.9.41.2.0.1

# List all OID redirections
trapninja filter list-redirected-oids
```

### Redirect Destinations

```bash
# Add redirect destination
trapninja filter add-redirect-dest --tag security --ip 10.1.1.100 --port 162

# Remove redirect destination
trapninja filter remove-redirect-dest --tag security --ip 10.1.1.100 --port 162

# List all redirect destinations
trapninja filter list-redirect-dests

# Show comprehensive redirection help
trapninja filter help
```

---

## HA Commands

Configure and manage High Availability clustering.

```bash
trapninja ha --help
```

### Configuration

```bash
# Configure as primary node
trapninja ha configure --mode primary --peer 192.168.1.102 --priority 150

# Configure as secondary node
trapninja ha configure --mode secondary --peer 192.168.1.101 --priority 100

# Configure with custom ports
trapninja ha configure --mode primary --peer 192.168.1.102 \
    --peer-port 8162 --listen-port 8162
```

### Status and Control

```bash
# Show HA status
trapninja ha status

# Promote to PRIMARY
trapninja ha promote

# Force promotion without peer coordination
trapninja ha promote --force

# Demote to SECONDARY
trapninja ha demote

# Force failover (for maintenance)
trapninja ha force-failover

# Disable HA
trapninja ha disable

# Show comprehensive HA help
trapninja ha help
```

---

## SNMPv3 Commands

Manage SNMPv3 user credentials for trap decryption.

```bash
trapninja snmpv3 --help
```

### User Management

```bash
# Add SNMPv3 user (interactive - prompts for passwords)
trapninja snmpv3 add-user \
    --username myuser \
    --engine-id 80001f888056565656565656 \
    --auth-protocol SHA \
    --priv-protocol AES128

# Add with inline passwords (for scripting)
trapninja snmpv3 add-user \
    --username myuser \
    --engine-id 80001f888056565656565656 \
    --auth-protocol SHA \
    --auth-passphrase "MyAuthPassword123" \
    --priv-protocol AES128 \
    --priv-passphrase "MyPrivPassword456"

# Remove SNMPv3 user
trapninja snmpv3 remove-user --username myuser --engine-id 80001f88...

# List all SNMPv3 users
trapninja snmpv3 list-users

# Show user details
trapninja snmpv3 show-user --username myuser --engine-id 80001f88...

# Check SNMPv3 status
trapninja snmpv3 status
```

### Testing

```bash
# Test decryption with captured trap
trapninja snmpv3 test-decrypt --trap-file /tmp/trap.bin

# Test and convert to SNMPv2c
trapninja snmpv3 test-decrypt --trap-file /tmp/trap.bin --convert

# Write output to file
trapninja snmpv3 test-decrypt --trap-file /tmp/trap.bin --output /tmp/decrypted.bin
```

See [SNMPV3_CREDENTIALS.md](SNMPV3_CREDENTIALS.md) for complete documentation.

---

## Cache Commands

Manage the Redis-based trap cache for backfill operations.

```bash
trapninja cache --help
```

### Status and Query

```bash
# Show cache status
trapninja cache status

# Query cached traps
trapninja cache query --destination default --from "-2h" --to now

# Query with limit
trapninja cache query --destination voice_noc --from "14:30" --to "15:45" --limit 50
```

### Replay

```bash
# Replay cached traps to original destination
trapninja cache replay --destination voice_noc --from "14:30" --to "15:45"

# Replay with rate limiting
trapninja cache replay --destination default --from "-1h" --to now --rate-limit 1000

# Preview without sending (dry run)
trapninja cache replay --destination default --from "-1h" --to now --dry-run

# Replay to custom destination
trapninja cache replay --destination default --from "-1h" --to now --replay-to 10.1.1.100:162

# Filter by OID prefix
trapninja cache replay --destination default --from "-1h" --to now --oid-filter 1.3.6.1.4.1.9

# Filter by source IP
trapninja cache replay --destination default --from "-1h" --to now --source-filter 10.0.0.

# Exclude specific OID
trapninja cache replay --destination default --from "-1h" --to now --exclude-oid 1.3.6.1.4.1.9.9.41
```

### Maintenance

```bash
# Clear cached entries for destination
trapninja cache clear --destination default

# Clear all cached entries
trapninja cache clear

# Manually trigger retention trim
trapninja cache trim

# Show comprehensive cache help
trapninja cache help
```

See [CACHE.md](CACHE.md) for complete documentation.

---

## Stats Commands

View and export detailed trap statistics.

```bash
trapninja stats --help
```

### Overview

```bash
# Show statistics summary
trapninja stats summary
```

### Top Sources

```bash
# Show top source IPs
trapninja stats top-ips

# Top 20 by different metrics
trapninja stats top-ips -n 20 -s rate      # By current rate
trapninja stats top-ips -n 20 -s peak      # By peak rate
trapninja stats top-ips -n 20 -s blocked   # By blocked count
trapninja stats top-ips -n 20 -s recent    # Most recent
```

### Top OIDs

```bash
# Show top OIDs
trapninja stats top-oids

# Top 20 by rate
trapninja stats top-oids -n 20 -s rate
```

### Detailed Views

```bash
# Details for specific IP
trapninja stats ip --ip 10.0.0.1

# Details with more OIDs
trapninja stats ip --ip 10.0.0.1 --oids 20

# Details for specific OID
trapninja stats oid --oid 1.3.6.1.4.1.9.9.41.2.0.1

# Details with more sources
trapninja stats oid --oid 1.3.6.1.4.1.9.9.41.2.0.1 --sources 20

# Destination statistics
trapninja stats destinations
```

### Export

```bash
# Export full dashboard data
trapninja stats dashboard

# Export to JSON file
trapninja stats export -f json -o /tmp/stats.json

# Export in Prometheus format
trapninja stats export -f prometheus -o /tmp/stats.prom
```

### Maintenance

```bash
# Reset all statistics
trapninja stats reset

# Show diagnostic info
trapninja stats debug

# Show comprehensive stats help
trapninja stats help
```

See [GRANULAR_STATS.md](GRANULAR_STATS.md) for complete documentation.

---

## Metrics Commands

Configure Prometheus metrics export.

```bash
trapninja metrics --help
```

```bash
# Show current metrics configuration
trapninja metrics config

# Set output directory
trapninja metrics set-dir /opt/prometheus/textfiles

# Add global label
trapninja metrics add-label --name region --value us-west
trapninja metrics add-label --name environment --value production

# Remove global label
trapninja metrics remove-label region

# Set export interval (seconds)
trapninja metrics set-interval 30

# Show comprehensive metrics help
trapninja metrics help
```

---

## Shadow Commands

Shadow mode for observation and parallel testing.

```bash
trapninja shadow --help
```

```bash
# Show shadow mode statistics
trapninja shadow status

# Export statistics to JSON
trapninja shadow export
```

To run in shadow mode, use the daemon foreground command:

```bash
trapninja daemon foreground --shadow-mode
trapninja daemon foreground --mirror-mode
```

See [SHADOW_MODE.md](SHADOW_MODE.md) for complete documentation.

---

## Failover Commands

Manage failover gap detection and replay.

```bash
trapninja failover --help
```

```bash
# Show failover status and tracking info
trapninja failover status

# Detect forwarding gaps
trapninja failover detect

# Auto-detect and replay gaps
trapninja failover replay

# Manual replay with specific time range
trapninja failover replay --destination default --from "-5m" --to now

# Preview without sending
trapninja failover replay --dry-run

# Show comprehensive failover help
trapninja failover help
```

---

## Sync Commands

Configuration synchronization between HA nodes.

```bash
trapninja sync --help
```

```bash
# Sync configs with peer now
trapninja sync now

# Force sync even if versions match
trapninja sync now --force

# Show sync status
trapninja sync status

# Show comprehensive sync help
trapninja sync help
```

See [CONFIG_SYNC.md](CONFIG_SYNC.md) for complete documentation.

---

## Global Options

Available on all commands:

| Option | Description |
|--------|-------------|
| `--config-dir PATH` | Configuration directory path |
| `--log-file PATH` | Log file path |
| `--pid-file PATH` | PID file path |
| `--debug` | Enable debug mode with verbose logging |
| `--json` | Output in JSON format |
| `--yes`, `-y` | Skip confirmation prompts |
| `--verbose` | Verbose output |

Example:

```bash
trapninja --config-dir /etc/trapninja daemon start --debug
trapninja --json stats summary
trapninja -y cache clear --destination default
```

---

## Legacy Commands (Backward Compatibility)

The original flat-style arguments are still supported for backward compatibility with existing scripts:

```bash
# Legacy style (still works)
trapninja --start
trapninja --stop
trapninja --status
trapninja --block-ip 10.0.0.1
trapninja --ha-status

# Modern subcommand style (recommended)
trapninja daemon start
trapninja daemon stop
trapninja daemon status
trapninja filter block-ip 10.0.0.1
trapninja ha status
```

### Migration Guide

| Legacy Command | Subcommand Equivalent |
|----------------|----------------------|
| `--start` | `daemon start` |
| `--stop` | `daemon stop` |
| `--restart` | `daemon restart` |
| `--status` | `daemon status` |
| `--foreground` | `daemon foreground` |
| `--show-config` | `daemon config` |
| `--validate-config` | `daemon config --validate` |
| `--queue-stats` | `daemon queue-stats` |
| `--block-ip IP` | `filter block-ip IP` |
| `--unblock-ip IP` | `filter unblock-ip IP` |
| `--list-blocked-ips` | `filter list-blocked-ips` |
| `--block-oid OID` | `filter block-oid OID` |
| `--redirect-ip IP --tag TAG` | `filter redirect-ip IP --tag TAG` |
| `--configure-ha` | `ha configure` |
| `--ha-status` | `ha status` |
| `--promote` | `ha promote` |
| `--demote` | `ha demote` |
| `--disable-ha` | `ha disable` |
| `--snmpv3-add-user` | `snmpv3 add-user` |
| `--snmpv3-list-users` | `snmpv3 list-users` |
| `--snmpv3-status` | `snmpv3 status` |
| `--cache-status` | `cache status` |
| `--cache-query` | `cache query` |
| `--cache-replay` | `cache replay` |
| `--stats-summary` | `stats summary` |
| `--stats-top-ips` | `stats top-ips` |
| `--failover-status` | `failover status` |
| `--ha-sync` | `sync now` |
| `--sync-status` | `sync status` |

---

## Programmatic Usage

### Argument Parsing

```python
from trapninja.cli.parser import create_argument_parser

parser = create_argument_parser()
args = parser.parse_args()
```

### Command Execution

```python
from trapninja.cli import create_argument_parser, execute_command

parser = create_argument_parser()
args = parser.parse_args()
exit_code = execute_command(args)
```

### Input Validation

```python
from trapninja.cli.validation import InputValidator

# Validate IP address
valid_ip = InputValidator.validate_ip("192.168.1.100")

# Validate OID
valid_oid = InputValidator.validate_oid("1.3.6.1.4.1.8072.2.3.0.1")

# Validate port
valid_port = InputValidator.validate_port(162)

# Sanitize string input
safe_str = InputValidator.sanitize_string(user_input)

# Parse size string
bytes_val = InputValidator.parse_size("10M")  # Returns 10485760
```

### Direct Command Calls

```python
from trapninja.cli import daemon_commands, filtering_commands, ha_commands

# Daemon operations
daemon_commands.start()
daemon_commands.stop()
daemon_commands.status()

# Filtering operations
filtering_commands.block_ip("10.0.1.50")
filtering_commands.unblock_ip("10.0.1.50")
filtering_commands.list_blocked_ips()

# HA operations
ha_commands.configure_ha("primary", "192.168.1.102", priority=150)
ha_commands.show_ha_status()
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error |
| 2 | Invalid arguments |
| 3 | Configuration error |
| 4 | Permission denied |
| 5 | Service not running |

---

## Security Notes

### Input Validation

All user input is validated before use. The `InputValidator` class checks for:

| Check | Description |
|-------|-------------|
| Command injection | Patterns like `; rm`, `\| cat`, backticks |
| Path traversal | Patterns like `../`, `/etc/` |
| XSS patterns | Script tags, javascript: URLs |
| Control characters | Non-printable characters |
| Length limits | Prevents buffer overflow attempts |
| Reserved names | System reserved file/path names |

### Best Practices

```python
# CORRECT - validate before use
from trapninja.cli.validation import InputValidator

validated_ip = InputValidator.validate_ip(user_input)
if validated_ip:
    filtering_commands.block_ip(validated_ip)
else:
    print("Invalid IP address")

# INCORRECT - never use raw input
filtering_commands.block_ip(user_input)  # UNSAFE!
```

---

## Troubleshooting

### Import Errors

Ensure you're running from the correct directory:

```bash
# From project root
python -m trapninja.main daemon status

# Or with full path
python /opt/trapninja/trapninja/main.py daemon status
```

### Command Not Found

If a subcommand isn't recognized:

```bash
# Check available commands
trapninja --help
trapninja daemon --help
```

### Cache Issues

Force configuration cache invalidation:

```python
from trapninja.cli.filtering_commands import config_manager
config_manager.invalidate_cache()
```

---

**Module Version**: 3.0.0  
**Python Compatibility**: 3.6+  
**Last Updated**: 2026-01-07
