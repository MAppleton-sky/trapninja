# TrapNinja CLI Module

**Version:** 3.0.0  
**Last Updated:** February 2026

## Overview

The CLI module provides a clean, modular command-line interface for TrapNinja using a **subcommand-based structure** for better discoverability. The code is organized by functional concern for maintainability, testability, and extensibility.

## Architecture

### Module Structure

```
trapninja/cli/
├── __init__.py              # Public API exports
├── parser.py                # Compatibility shim → re-exports from cli/parsers/
├── validation.py            # Input validation and sanitization
├── executor.py              # Command orchestration and execution
├── output.py                # Output formatting utilities
├── daemon_commands.py       # Daemon control commands
├── filtering_commands.py    # IP/OID filtering commands
├── ha_commands.py           # High Availability commands
├── cache_commands.py        # Redis cache commands
├── stats_commands.py        # Statistics display commands
├── stats.py                 # Statistics CLI helpers
├── shadow_commands.py       # Shadow/mirror mode commands
├── snmpv3_commands.py       # SNMPv3 credential management
├── sync_commands.py         # Config sync commands
├── failover_commands.py     # Failover replay commands
├── metrics_commands.py      # Prometheus metrics configuration
└── parsers/                 # Argument parser definitions (sub-package)
    ├── __init__.py           # Re-exports create_argument_parser()
    ├── base.py               # Shared parser utilities and global options
    ├── daemon_parser.py      # Daemon subcommand argument definitions
    ├── config_parser.py      # Config subcommand argument definitions
    ├── filter_parser.py      # Filter subcommand argument definitions
    ├── ha_parser.py          # HA subcommand argument definitions
    ├── snmpv3_parser.py      # SNMPv3 subcommand argument definitions
    ├── cache_parser.py       # Cache subcommand argument definitions
    ├── stats_parser.py       # Stats subcommand argument definitions
    ├── metrics_parser.py     # Metrics subcommand argument definitions
    ├── shadow_parser.py      # Shadow subcommand argument definitions
    ├── failover_parser.py    # Failover subcommand argument definitions
    ├── sync_parser.py        # Sync subcommand argument definitions
    ├── legacy_parser.py      # Legacy flat-flag definitions (hidden)
    └── legacy_compat.py      # Legacy flag → subcommand translation
```

### Design Principles

1. **Single Responsibility**: Each module handles one specific concern
2. **Separation of Concerns**: Parsing, validation, and execution are separate
3. **Testability**: Each module can be tested independently
4. **Security**: All user input is validated before processing
5. **Maintainability**: Clear structure makes code easy to navigate and modify

## Module Descriptions

### `parser.py`
**Purpose**: Compatibility shim — re-exports `create_argument_parser()` from `cli/parsers/`

This file exists to preserve backward-compatible imports. All argument parser
definitions live in the `cli/parsers/` sub-package.

**Example**:
```python
# Both imports work; prefer the parsers/ sub-package for new code
from trapninja.cli.parser import create_argument_parser       # shim
from trapninja.cli.parsers import create_argument_parser      # canonical

parser = create_argument_parser()
args = parser.parse_args()
```

### `parsers/` sub-package
**Purpose**: All argument parser definitions, split by command category

| Module | Defines parsers for |
|--------|--------------------|
| `base.py` | Global options (`--config-dir`, `--debug`, `--json`, etc.) |
| `daemon_parser.py` | `daemon` subcommands |
| `config_parser.py` | `config` subcommands |
| `filter_parser.py` | `filter` subcommands |
| `ha_parser.py` | `ha` subcommands |
| `snmpv3_parser.py` | `snmpv3` subcommands |
| `cache_parser.py` | `cache` subcommands |
| `stats_parser.py` | `stats` subcommands |
| `metrics_parser.py` | `metrics` subcommands |
| `shadow_parser.py` | `shadow` subcommands |
| `failover_parser.py` | `failover` subcommands |
| `sync_parser.py` | `sync` subcommands |
| `legacy_parser.py` | Hidden legacy flat-flags (argparse.SUPPRESS) |
| `legacy_compat.py` | Translates legacy flags to subcommand equivalents |

### `validation.py`
**Purpose**: Validate and sanitize all user input

**Key Classes**:
- `InputValidator`: Comprehensive validation with caching
- `SecurityError`: Raised when validation fails for security reasons

**Key Functions**:
- `validate_ip()`: Validate IP addresses
- `validate_oid()`: Validate SNMP OIDs
- `validate_port()`: Validate port numbers
- `validate_tag()`: Validate destination group tags
- `sanitize_string()`: Remove dangerous characters
- `parse_size()`: Parse size strings (e.g., "10M", "1G")

**Security Features**:
- Pattern matching for command injection attempts
- Path traversal detection
- XSS-like pattern detection
- Input length limits
- Control character removal
- Reserved name checking

**Example**:
```python
from trapninja.cli.validation import InputValidator

# Validate and sanitize an IP address
valid_ip = InputValidator.validate_ip("192.168.1.100")
if valid_ip:
    # Use the validated IP
    pass

# Validate an OID
valid_oid = InputValidator.validate_oid("1.3.6.1.4.1.8072.2.3.0.1")
if valid_oid:
    # Use the validated OID
    pass
```

### `executor.py`
**Purpose**: Orchestrate command execution based on parsed arguments

**Key Functions**:
- `execute_command()`: Main dispatcher that routes to appropriate handler
- `update_global_config()`: Apply command-line config overrides

**Features**:
- Centralized command routing
- Global configuration updates
- Error handling and exit code management
- Support for foreground daemon mode

### `output.py`
**Purpose**: Consistent output formatting across CLI commands

**Key Functions**:
- `format_table()`: Generate formatted ASCII tables
- `format_json()`: JSON output with optional pretty printing
- `print_error()`: Standardized error output
- `print_success()`: Standardized success messages

### `daemon_commands.py`
**Purpose**: Handle daemon lifecycle operations

**Key Functions**:
- `start()`: Start TrapNinja as daemon
- `stop()`: Stop running daemon
- `restart()`: Restart daemon
- `status()`: Check daemon status
- `run_foreground()`: Run in foreground with optional debug mode

**CLI Commands**:
```bash
trapninja daemon start              # Start as daemon
trapninja daemon stop               # Stop daemon
trapninja daemon restart            # Restart daemon
trapninja daemon status             # Show status
trapninja daemon foreground         # Run in foreground
trapninja daemon foreground --debug # Run with debug logging
trapninja daemon config             # Show configuration
```

### `filtering_commands.py`
**Purpose**: Manage IP and OID filtering rules

**Key Classes**:
- `ConfigManager`: Thread-safe configuration file management with caching

**Key Functions**:
- `block_ip()`: Add IP to blocked list
- `unblock_ip()`: Remove IP from blocked list
- `list_blocked_ips()`: Display all blocked IPs
- `block_oid()`: Add OID to blocked list
- `unblock_oid()`: Remove OID from blocked list
- `list_blocked_oids()`: Display all blocked OIDs

**CLI Commands**:
```bash
trapninja filter block-ip 10.0.1.50      # Block an IP
trapninja filter unblock-ip 10.0.1.50    # Unblock an IP
trapninja filter list-blocked-ips        # List blocked IPs
trapninja filter block-oid 1.3.6.1...    # Block an OID
trapninja filter unblock-oid 1.3.6.1...  # Unblock an OID
trapninja filter list-blocked-oids       # List blocked OIDs
```

**Features**:
- Atomic file operations (write to temp, then rename)
- Thread-safe with per-file locking
- Configuration caching for performance
- Automatic validation of all inputs

### `ha_commands.py`
**Purpose**: Configure and manage High Availability

**Key Functions**:
- `configure_ha()`: Configure HA mode, peer, and priority
- `disable_ha()`: Disable HA functionality
- `show_ha_status()`: Display detailed HA status
- `force_failover()`: Manually trigger failover (maintenance)
- `promote_to_primary()`: Promote to PRIMARY
- `demote_to_secondary()`: Demote to SECONDARY

**CLI Commands**:
```bash
trapninja ha status                      # Show HA status
trapninja ha help                        # Show HA help
trapninja ha promote                     # Promote to PRIMARY
trapninja ha promote --force             # Force promote
trapninja ha demote                      # Demote to SECONDARY
trapninja ha force-failover              # Force failover
trapninja ha configure --mode primary --peer 192.168.1.102 --priority 150
trapninja ha disable                     # Disable HA
```

### `cache_commands.py`
**Purpose**: Redis cache operations

**Key Functions**:
- `cache_status()`: Show cache connection and statistics
- `cache_query()`: Preview cached traps for time window
- `cache_replay()`: Replay cached traps with rate limiting
- `cache_clear()`: Clear cached entries

**CLI Commands**:
```bash
trapninja cache status                   # Show cache status
trapninja cache help                     # Show cache help
trapninja cache query --destination voice_noc --from "-2h" --to "-1h"
trapninja cache replay --destination voice_noc --from "14:30" --to "15:45"
trapninja cache replay --destination default --dry-run
trapninja cache clear --destination voice_noc
```

### `stats_commands.py`
**Purpose**: Display granular statistics

**Key Functions**:
- `stats_summary()`: Overall statistics summary
- `stats_top_ips()`: Top source IPs by volume/rate
- `stats_top_oids()`: Top OIDs by volume/rate
- `stats_ip()`: Detailed stats for specific IP
- `stats_oid()`: Detailed stats for specific OID
- `stats_destinations()`: Per-destination statistics
- `stats_export()`: Export statistics to file

**CLI Commands**:
```bash
trapninja stats summary                  # Statistics summary
trapninja stats help                     # Statistics help
trapninja stats top-ips                  # Top source IPs
trapninja stats top-ips -n 20 -s rate    # Top 20 by rate
trapninja stats top-oids                 # Top OIDs
trapninja stats ip --ip 10.0.0.1         # IP details
trapninja stats oid --oid 1.3.6.1...     # OID details
trapninja stats destinations             # Destination stats
trapninja stats export -f json -o /tmp/stats.json
```

### `stats.py`
**Purpose**: Statistics CLI helper functions

**Key Functions**:
- `format_rate()`: Format rate values with units
- `format_duration()`: Human-readable duration strings
- `format_timestamp()`: Format timestamps consistently
- `calculate_percentages()`: Calculate percentage values

### `shadow_commands.py`
**Purpose**: Shadow and mirror mode operations

**Key Functions**:
- `enable_shadow_mode()`: Enable shadow mode (receive only, no forward)
- `enable_mirror_mode()`: Enable mirror mode (copy to secondary destination)
- `disable_shadow_mode()`: Disable shadow/mirror modes
- `show_shadow_status()`: Display current mode status

**CLI Commands**:
```bash
trapninja shadow status                  # Show shadow status
trapninja shadow export                  # Export shadow stats
trapninja daemon start --shadow-mode     # Start in shadow mode
trapninja daemon start --mirror-mode     # Start in mirror mode
```

### `snmpv3_commands.py`
**Purpose**: SNMPv3 credential management

**Key Functions**:
- `add_user()`: Add SNMPv3 user credentials
- `remove_user()`: Remove SNMPv3 user
- `list_users()`: List configured users
- `show_status()`: Show SNMPv3 decryption status

**CLI Commands**:
```bash
trapninja snmpv3 status                  # Show SNMPv3 status
trapninja snmpv3 add-user --username USER --engine-id ID --auth-protocol SHA
trapninja snmpv3 remove-user --username USER --engine-id ID
trapninja snmpv3 list-users              # List configured users
trapninja snmpv3 test-decrypt --trap-file /tmp/trap.bin
```

### `sync_commands.py`
**Purpose**: Configuration synchronization between HA nodes

**Key Functions**:
- `sync_now()`: Manually trigger config sync
- `sync_status()`: Show sync status

**CLI Commands**:
```bash
trapninja sync status                    # Show sync status
trapninja sync now                       # Trigger sync
trapninja sync now --force               # Force sync
trapninja sync help                      # Show sync help
```

### `failover_commands.py`
**Purpose**: Failover replay operations

**Key Functions**:
- `failover_status()`: Show failover replay status
- `failover_replay()`: Manually trigger failover replay
- `failover_detect()`: Show detected gaps

**CLI Commands**:
```bash
trapninja failover status                # Show failover status
trapninja failover detect                # Detect gaps
trapninja failover replay                # Replay gaps
trapninja failover replay --dry-run      # Preview replay
trapninja failover help                  # Show failover help
```

### `metrics_commands.py`
**Purpose**: Configure Prometheus metrics export

**CLI Commands**:
```bash
trapninja metrics config                 # Show metrics config
trapninja metrics set-dir /opt/metrics   # Set output directory
trapninja metrics add-label --name env --value prod
trapninja metrics remove-label env
trapninja metrics set-interval 30        # Set export interval
trapninja metrics help                   # Show metrics help
```

## Usage Examples

### From Command Line

```bash
# Start daemon
trapninja daemon start

# Configure High Availability
trapninja ha configure --mode primary --peer 192.168.1.102 --priority 150

# Block an IP
trapninja filter block-ip 10.0.1.50

# View statistics
trapninja stats summary
trapninja stats top-ips -n 20 -s rate

# Cache operations
trapninja cache status
trapninja cache replay --destination default --from "-2h" --to "-1h"

# Run in foreground with debug
trapninja daemon foreground --debug
```

### Programmatic Usage

```python
from trapninja.cli import (
    daemon_commands,
    filtering_commands,
    ha_commands,
    cache_commands,
    stats_commands,
    InputValidator
)

# Validate input before using
ip = "192.168.1.100"
if InputValidator.validate_ip(ip):
    # Block the validated IP
    filtering_commands.block_ip(ip)

# Configure HA programmatically
ha_commands.configure_ha(
    mode="secondary",
    peer_host="192.168.1.101",
    priority=100
)

# Check cache status
cache_commands.cache_status()

# Get statistics
stats_commands.stats_summary()

# Start daemon
daemon_commands.start()
```

## Testing

Each module can be tested independently:

```python
# Test validation
def test_ip_validation():
    from trapninja.cli.validation import InputValidator
    
    assert InputValidator.validate_ip("192.168.1.1") == "192.168.1.1"
    assert InputValidator.validate_ip("invalid") is None
    assert InputValidator.validate_ip("256.1.1.1") is None

# Test filtering commands
def test_block_ip(monkeypatch):
    from trapninja.cli import filtering_commands
    
    # Mock the config manager
    # ... test implementation
```

## Configuration Management

The CLI module uses `ConfigManager` for thread-safe configuration file operations:

**Features**:
- **Atomic writes**: Write to temp file, then rename
- **Caching**: Reduces file I/O for frequently accessed configs
- **Thread-safe**: Per-file locking prevents race conditions
- **Cache invalidation**: Automatic when files are updated

## Security Considerations

### Input Validation

All user input goes through `InputValidator` which:
- Removes control characters
- Detects command injection patterns
- Prevents path traversal
- Enforces length limits
- Uses LRU caching for performance

### Secure Patterns

**DO**:
```python
# Always validate before use
validated_ip = InputValidator.validate_ip(user_input)
if validated_ip:
    # Use validated_ip
```

**DON'T**:
```python
# Never use raw user input
block_ip(user_input)  # UNSAFE!
```

## Extension Guidelines

### Adding New Commands

1. **Create command function in appropriate module**:
   ```python
   # In filtering_commands.py
   def block_subnet(subnet: str) -> bool:
       """Block entire subnet"""
       # Implementation
   ```

2. **Add subcommand to parser**:
   ```python
   # In cli/parsers/filter_parser.py - add to filter subparser
   filter_parser.add_parser('block-subnet', help='Block entire subnet')
   ```

3. **Add validation if needed**:
   ```python
   # In validation.py
   @classmethod
   def validate_subnet(cls, subnet_str: str) -> Optional[str]:
       # Validation logic
   ```

4. **Route command in executor**:
   ```python
   # In executor.py
   elif args.command == 'block-subnet':
       return 0 if filtering_commands.block_subnet(args.subnet) else 1
   ```

### Adding New Command Categories

For entirely new command categories:

1. Create new module: `trapninja/cli/your_category_commands.py`
2. Import in `__init__.py`
3. Add subparser in parser.py
4. Route in executor

## Command Reference Summary

| Category | Commands |
|----------|----------|
| **daemon** | `start`, `stop`, `restart`, `status`, `foreground`, `config` |
| **filter** | `block-ip`, `unblock-ip`, `block-oid`, `unblock-oid`, `redirect-ip`, `list-*` |
| **ha** | `status`, `promote`, `demote`, `force-failover`, `configure`, `disable`, `help` |
| **cache** | `status`, `query`, `replay`, `clear`, `help` |
| **stats** | `summary`, `top-ips`, `top-oids`, `ip`, `oid`, `destinations`, `export`, `reset` |
| **snmpv3** | `status`, `add-user`, `remove-user`, `list-users`, `test-decrypt` |
| **shadow** | `status`, `export` |
| **failover** | `status`, `detect`, `replay`, `help` |
| **sync** | `status`, `now`, `help` |
| **metrics** | `config`, `set-dir`, `add-label`, `remove-label`, `set-interval`, `help` |

## Legacy Command Support

For backward compatibility, flat-style arguments are still supported:

```bash
# Legacy (still works)
trapninja --start
trapninja --ha-status
trapninja --block-ip 10.0.0.1

# Modern subcommand style (recommended)
trapninja daemon start
trapninja ha status
trapninja filter block-ip 10.0.0.1
```

## Performance Considerations

- **LRU Caching**: Validation functions use `@lru_cache` for performance
- **Precompiled Patterns**: Regex patterns compiled once at module load
- **Configuration Caching**: Reduces file I/O for frequently accessed configs
- **Atomic Operations**: Write operations are fast due to temp file strategy

## Related Documentation

| Document | Contents |
|----------|----------|
| [CLI.md](CLI.md) | Full CLI reference with all options |
| [USER_GUIDE.md](USER_GUIDE.md) | User-friendly operations guide |
| [ARCHITECTURE.md](ARCHITECTURE.md) | System architecture overview |
