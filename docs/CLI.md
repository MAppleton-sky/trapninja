# TrapNinja CLI Reference

## Overview

The CLI module provides a modular command-line interface for TrapNinja, organized by functional concern for maintainability, testability, and extensibility.

## Module Structure

```
trapninja/cli/
├── __init__.py              # Public API exports
├── parser.py                # Argument parsing configuration
├── validation.py            # Input validation and sanitization
├── daemon_commands.py       # Daemon control commands
├── filtering_commands.py    # IP/OID filtering commands
├── ha_commands.py           # High Availability commands
├── snmpv3_commands.py       # SNMPv3 credential management
└── executor.py              # Command orchestration and execution
```

## Command Reference

### Daemon Control

```bash
# Start as daemon
python trapninja.py --start

# Stop daemon
python trapninja.py --stop

# Restart daemon
python trapninja.py --restart

# Check status
python trapninja.py --status

# Run in foreground (for testing/debugging)
python trapninja.py --foreground

# Run with debug logging
python trapninja.py --foreground --debug
```

### IP Filtering

```bash
# Block an IP address
python trapninja.py --block-ip 10.0.1.50

# Unblock an IP address
python trapninja.py --unblock-ip 10.0.1.50

# List all blocked IPs
python trapninja.py --list-blocked-ips
```

### OID Filtering

```bash
# Block an OID pattern
python trapninja.py --block-oid 1.3.6.1.4.1.8072.2.3.0.1

# Unblock an OID pattern
python trapninja.py --unblock-oid 1.3.6.1.4.1.8072.2.3.0.1

# List all blocked OIDs
python trapninja.py --list-blocked-oids
```

### High Availability

```bash
# Configure as primary node
python trapninja.py --configure-ha \
    --ha-mode primary \
    --ha-peer-host 192.168.1.102 \
    --ha-priority 150

# Configure as secondary node
python trapninja.py --configure-ha \
    --ha-mode secondary \
    --ha-peer-host 192.168.1.101 \
    --ha-priority 100

# Show HA status
python trapninja.py --ha-status

# Manual promotion to primary
python trapninja.py --promote

# Manual demotion to secondary
python trapninja.py --demote

# Force failover (maintenance)
python trapninja.py --force-failover

# Disable HA
python trapninja.py --disable-ha

# Show HA help
python trapninja.py --ha-help
```

### SNMPv3 Credentials

```bash
# Add SNMPv3 user
python trapninja.py --snmpv3-add-user \
    --username myuser \
    --engine-id 80001f888056565656565656 \
    --auth-protocol SHA \
    --priv-protocol AES128

# Remove SNMPv3 user
python trapninja.py --snmpv3-remove-user myuser

# List SNMPv3 users
python trapninja.py --snmpv3-list-users

# Show SNMPv3 user details
python trapninja.py --snmpv3-show-user myuser

# Check SNMPv3 status
python trapninja.py --snmpv3-status
```

### Configuration Options

```bash
# Override config directory
python trapninja.py --config-dir /etc/trapninja

# Override log file
python trapninja.py --log-file /var/log/trapninja.log

# Set log level
python trapninja.py --log-level DEBUG

# Override metrics port
python trapninja.py --metrics-port 9090
```

## Module Details

### `parser.py`

Configures all command-line arguments and options.

```python
from trapninja.cli.parser import create_argument_parser

parser = create_argument_parser()
args = parser.parse_args()
```

Features:
- Comprehensive argument definitions with help text
- Built-in type validation using custom validators
- Mutually exclusive command groups
- Hidden internal arguments

### `validation.py`

Validates and sanitizes all user input.

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

Security Features:
- Command injection detection
- Path traversal prevention
- XSS-pattern detection
- Input length limits
- Control character removal
- Reserved name checking

### `daemon_commands.py`

Handles daemon lifecycle operations.

```python
from trapninja.cli import daemon_commands

# Start daemon
exit_code = daemon_commands.start()

# Stop daemon
exit_code = daemon_commands.stop()

# Check status
exit_code = daemon_commands.status()

# Run in foreground
exit_code = daemon_commands.run_foreground(debug=True)
```

### `filtering_commands.py`

Manages IP and OID filtering rules with thread-safe configuration.

```python
from trapninja.cli import filtering_commands

# Block operations
success = filtering_commands.block_ip("10.0.1.50")
success = filtering_commands.block_oid("1.3.6.1.4.1.8072")

# Unblock operations
success = filtering_commands.unblock_ip("10.0.1.50")
success = filtering_commands.unblock_oid("1.3.6.1.4.1.8072")

# List operations
filtering_commands.list_blocked_ips()
filtering_commands.list_blocked_oids()
```

Features:
- Atomic file operations (write to temp, then rename)
- Thread-safe with per-file locking
- Configuration caching for performance

### `ha_commands.py`

Configures and manages High Availability.

```python
from trapninja.cli import ha_commands

# Configure HA
success = ha_commands.configure_ha(
    mode="primary",
    peer_host="192.168.1.102",
    priority=150
)

# Show status
ha_commands.show_ha_status()

# Manual operations
ha_commands.promote_to_primary()
ha_commands.demote_to_secondary()
ha_commands.force_failover()

# Disable HA
ha_commands.disable_ha()
```

### `snmpv3_commands.py`

Manages SNMPv3 credentials.

```python
from trapninja.cli import snmpv3_commands

# Add user
snmpv3_commands.handle_snmpv3_add_user(args)

# Remove user
snmpv3_commands.handle_snmpv3_remove_user(username)

# List users
snmpv3_commands.handle_snmpv3_list_users()

# Show user
snmpv3_commands.handle_snmpv3_show_user(username)

# Check status
snmpv3_commands.handle_snmpv3_status()
```

### `executor.py`

Orchestrates command execution based on parsed arguments.

```python
from trapninja.cli import create_argument_parser, execute_command

parser = create_argument_parser()
args = parser.parse_args()
exit_code = execute_command(args)
```

## Configuration Management

The CLI uses `ConfigManager` for thread-safe configuration operations:

```python
from trapninja.cli.filtering_commands import config_manager

# Load configuration with caching
config = config_manager.load_json("/path/to/config.json", default=[])

# Save with atomic write
success = config_manager.save_json("/path/to/config.json", data)

# Invalidate cache
config_manager.invalidate_cache("/path/to/config.json")
```

Features:
- **Atomic writes**: Write to temp file, then rename
- **Caching**: Reduces file I/O for frequently accessed configs
- **Thread-safe**: Per-file locking prevents race conditions
- **Cache invalidation**: Automatic when files are updated

## Security Patterns

### Always Validate Input

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

### Input Validation Details

The `InputValidator` class checks for:

| Check | Description |
|-------|-------------|
| Command injection | Patterns like `; rm`, `| cat`, backticks |
| Path traversal | Patterns like `../`, `/etc/` |
| XSS patterns | Script tags, javascript: URLs |
| Control characters | Non-printable characters |
| Length limits | Prevents buffer overflow attempts |
| Reserved names | System reserved file/path names |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error |
| 2 | Invalid arguments |
| 3 | Configuration error |
| 4 | Permission denied |
| 5 | Service not running |

## Extending the CLI

### Adding a New Command

1. **Add command function** in the appropriate module:

```python
# In filtering_commands.py
def block_subnet(subnet: str) -> bool:
    """Block an entire subnet."""
    validated = InputValidator.validate_subnet(subnet)
    if not validated:
        print(f"Invalid subnet: {subnet}")
        return False
    # Implementation...
    return True
```

2. **Add argument** in `parser.py`:

```python
group.add_argument('--block-subnet',
    type=str,
    metavar='SUBNET',
    help='Block entire subnet (CIDR notation)')
```

3. **Add validation** in `validation.py` (if needed):

```python
@classmethod
def validate_subnet(cls, subnet_str: str) -> Optional[str]:
    """Validate CIDR subnet notation."""
    try:
        import ipaddress
        network = ipaddress.ip_network(subnet_str, strict=False)
        return str(network)
    except ValueError:
        return None
```

4. **Route command** in `executor.py`:

```python
elif args.block_subnet:
    return 0 if filtering_commands.block_subnet(args.block_subnet) else 1
```

### Adding a New Command Category

1. Create new module: `trapninja/cli/your_category_commands.py`
2. Add exports to `__init__.py`
3. Add arguments to `parser.py`
4. Add routing to `executor.py`

## Troubleshooting

### Import Errors

Ensure you're running from the correct directory:

```bash
# From project root
python -m trapninja.main --status

# Or with full path
python /opt/trapninja/trapninja/main.py --status
```

### Validation Failures

Test specific validators:

```python
from trapninja.cli.validation import InputValidator

result = InputValidator.validate_ip("192.168.1.1")
print(f"Validation result: {result}")  # Should print the IP or None
```

### Cache Issues

Force cache invalidation:

```python
from trapninja.cli.filtering_commands import config_manager
config_manager.invalidate_cache()
```

## Performance Notes

- **LRU Caching**: Validation functions use `@lru_cache` for performance
- **Precompiled Patterns**: Regex patterns compiled once at module load
- **Configuration Caching**: Reduces file I/O for frequently accessed configs
- **Atomic Operations**: Write operations are fast due to temp file strategy

---

**Module Version**: 2.0.0  
**Python Compatibility**: 3.6+  
**Last Updated**: 2025-01-10
