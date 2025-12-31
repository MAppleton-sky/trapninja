# TrapNinja CLI Module

**Version:** 2.1.0  
**Last Updated:** December 31, 2025

## Overview

The CLI module provides a clean, modular command-line interface for TrapNinja. The code is organized by functional concern for better maintainability, testability, and extensibility.

## Architecture

### Module Structure

```
trapninja/cli/
├── __init__.py              # Public API exports
├── parser.py                # Argument parsing configuration
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
└── failover_commands.py     # Failover replay commands
```

### Design Principles

1. **Single Responsibility**: Each module handles one specific concern
2. **Separation of Concerns**: Parsing, validation, and execution are separate
3. **Testability**: Each module can be tested independently
4. **Security**: All user input is validated before processing
5. **Maintainability**: Clear structure makes code easy to navigate and modify

## Module Descriptions

### `parser.py`
**Purpose**: Configure all command-line arguments and options

**Key Functions**:
- `create_argument_parser()`: Returns configured ArgumentParser instance

**Features**:
- Comprehensive argument definitions with help text
- Built-in type validation using custom validators
- Mutually exclusive command groups
- Hidden internal arguments

**Example**:
```python
from trapninja.cli.parser import create_argument_parser

parser = create_argument_parser()
args = parser.parse_args()
```

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

**CLI Options**:
- `--start`: Start as daemon
- `--stop`: Stop daemon
- `--restart`: Restart daemon
- `--status`: Show status
- `--foreground`: Run in foreground
- `--debug`: Enable debug logging

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

**CLI Options**:
- `--block-ip IP`: Block an IP address
- `--unblock-ip IP`: Unblock an IP address
- `--list-blocked-ips`: List all blocked IPs
- `--block-oid OID`: Block a trap OID
- `--unblock-oid OID`: Unblock a trap OID
- `--list-blocked-oids`: List all blocked OIDs

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
- `promote()`: Promote to PRIMARY
- `demote()`: Demote to SECONDARY

**CLI Options**:
- `--ha-status`: Show HA status
- `--ha-help`: Show HA help
- `--promote`: Promote to PRIMARY
- `--demote`: Demote to SECONDARY
- `--force-failover`: Force immediate failover
- `--configure-ha`: Configure HA settings
- `--ha-mode MODE`: Set HA mode (primary/secondary)
- `--ha-peer-host HOST`: Set peer hostname/IP
- `--ha-priority N`: Set election priority

### `cache_commands.py`
**Purpose**: Redis cache operations

**Key Functions**:
- `cache_status()`: Show cache connection and statistics
- `cache_query()`: Preview cached traps for time window
- `cache_replay()`: Replay cached traps with rate limiting
- `cache_clear()`: Clear cached entries

**CLI Options**:
- `--cache-status`: Show cache status
- `--cache-help`: Show cache help
- `--cache-query`: Query cached traps
- `--cache-replay`: Replay cached traps
- `--cache-clear`: Clear cache
- `--destination DEST`: Target destination for cache operations
- `--from TIME`: Start time for query/replay
- `--to TIME`: End time for query/replay
- `--rate-limit N`: Rate limit for replay (traps/sec)
- `--dry-run`: Preview without executing

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

**CLI Options**:
- `--stats-summary`: Show statistics summary
- `--stats-help`: Show statistics help
- `--stats-top-ips`: Show top source IPs
- `--stats-top-oids`: Show top OIDs
- `--stats-ip`: Show stats for specific IP
- `--stats-oid`: Show stats for specific OID
- `--stats-destinations`: Show destination stats
- `--stats-export`: Export statistics
- `-n, --count N`: Number of items to show
- `-s, --sort FIELD`: Sort by field (total, rate, blocked, peak)
- `-f, --format FMT`: Export format (json, prometheus)

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

**CLI Options**:
- `--shadow-mode`: Enable shadow mode
- `--mirror-mode`: Enable mirror mode
- `--parallel`: Run shadow in parallel

### `snmpv3_commands.py`
**Purpose**: SNMPv3 credential management

**Key Functions**:
- `add_user()`: Add SNMPv3 user credentials
- `remove_user()`: Remove SNMPv3 user
- `list_users()`: List configured users
- `show_status()`: Show SNMPv3 decryption status

**CLI Options**:
- `--snmpv3-status`: Show SNMPv3 status
- `--snmpv3-add-user`: Add SNMPv3 user
- `--snmpv3-remove-user`: Remove SNMPv3 user
- `--snmpv3-list-users`: List configured users
- `--username USER`: Username for operations
- `--engine-id ID`: SNMPv3 engine ID
- `--auth-protocol PROTO`: Authentication protocol
- `--auth-passphrase PASS`: Auth passphrase
- `--priv-protocol PROTO`: Privacy protocol
- `--priv-passphrase PASS`: Privacy passphrase

### `sync_commands.py`
**Purpose**: Configuration synchronization between HA nodes

**Key Functions**:
- `sync_configs()`: Manually trigger config sync
- `sync_status()`: Show sync status

**CLI Options**:
- `--ha-sync`: Trigger config synchronization
- `--sync-status`: Show synchronization status

### `failover_commands.py`
**Purpose**: Failover replay operations

**Key Functions**:
- `failover_status()`: Show failover replay status
- `failover_replay()`: Manually trigger failover replay
- `failover_gaps()`: Show detected gaps

**CLI Options**:
- `--failover-status`: Show failover replay status
- `--failover-replay`: Trigger failover replay
- `--failover-gaps`: Show detected outage gaps

## Usage Examples

### From Command Line

```bash
# Start daemon
python -m trapninja.main --start

# Configure High Availability
python -m trapninja.main --configure-ha \
    --ha-mode primary \
    --ha-peer-host 192.168.1.102 \
    --ha-priority 150

# Block an IP
python -m trapninja.main --block-ip 10.0.1.50

# View statistics
python -m trapninja.main --stats-summary
python -m trapninja.main --stats-top-ips -n 20 -s rate

# Cache operations
python -m trapninja.main --cache-status
python -m trapninja.main --cache-replay --destination default --from "-2h" --to "-1h"

# Run in foreground with debug
python -m trapninja.main --foreground --debug
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

2. **Add argument to parser**:
   ```python
   # In parser.py
   group.add_argument('--block-subnet', type=validated_subnet,
                     help='Block entire subnet')
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
   elif args.block_subnet:
       return 0 if filtering_commands.block_subnet(args.block_subnet) else 1
   ```

### Adding New Command Categories

For entirely new command categories:

1. Create new module: `trapninja/cli/your_category_commands.py`
2. Import in `__init__.py`
3. Add commands to parser
4. Route in executor

## Command Reference Summary

| Category | Commands |
|----------|----------|
| **Daemon** | `--start`, `--stop`, `--restart`, `--status`, `--foreground` |
| **Filtering** | `--block-ip`, `--unblock-ip`, `--block-oid`, `--unblock-oid`, `--list-blocked-*` |
| **HA** | `--ha-status`, `--promote`, `--demote`, `--force-failover`, `--ha-sync` |
| **Cache** | `--cache-status`, `--cache-query`, `--cache-replay`, `--cache-clear` |
| **Statistics** | `--stats-summary`, `--stats-top-ips`, `--stats-top-oids`, `--stats-ip`, `--stats-oid` |
| **SNMPv3** | `--snmpv3-status`, `--snmpv3-add-user`, `--snmpv3-remove-user`, `--snmpv3-list-users` |
| **Shadow** | `--shadow-mode`, `--mirror-mode` |
| **Failover** | `--failover-status`, `--failover-replay`, `--failover-gaps` |
| **Help** | `--help`, `--ha-help`, `--cache-help`, `--stats-help` |

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
