# TrapNinja CLI Module

## Overview

The CLI module provides a clean, modular command-line interface for TrapNinja. The code is organized by functional concern for better maintainability, testability, and extensibility.

## Architecture

### Module Structure

```
trapninja/cli/
├── __init__.py              # Public API exports
├── parser.py                # Argument parsing configuration
├── validation.py            # Input validation and sanitization
├── daemon_commands.py       # Daemon control commands
├── filtering_commands.py    # IP/OID filtering commands
├── ha_commands.py          # High Availability commands
└── executor.py             # Command orchestration and execution
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

### `daemon_commands.py`
**Purpose**: Handle daemon lifecycle operations

**Key Functions**:
- `start()`: Start TrapNinja as daemon
- `stop()`: Stop running daemon
- `restart()`: Restart daemon
- `status()`: Check daemon status
- `run_foreground()`: Run in foreground with optional debug mode

**Example**:
```python
from trapninja.cli import daemon_commands

# Start the daemon
exit_code = daemon_commands.start()

# Check status
exit_code = daemon_commands.status()
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

**Features**:
- Atomic file operations (write to temp, then rename)
- Thread-safe with per-file locking
- Configuration caching for performance
- Automatic validation of all inputs

**Example**:
```python
from trapninja.cli import filtering_commands

# Block an IP address
success = filtering_commands.block_ip("10.0.1.50")

# List blocked OIDs
filtering_commands.list_blocked_oids()
```

### `ha_commands.py`
**Purpose**: Configure and manage High Availability

**Key Functions**:
- `configure_ha()`: Configure HA mode, peer, and priority
- `disable_ha()`: Disable HA functionality
- `show_ha_status()`: Display detailed HA status
- `force_failover()`: Manually trigger failover (maintenance)

**Example**:
```python
from trapninja.cli import ha_commands

# Configure as primary
success = ha_commands.configure_ha(
    mode="primary",
    peer_host="192.168.1.102",
    priority=150
)

# Check HA status
ha_commands.show_ha_status()
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

**Example**:
```python
from trapninja.cli import create_argument_parser, execute_command

parser = create_argument_parser()
args = parser.parse_args()
exit_code = execute_command(args)
```

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

# Run in foreground with debug
python -m trapninja.main --foreground --debug
```

### Programmatic Usage

```python
from trapninja.cli import (
    daemon_commands,
    filtering_commands,
    ha_commands,
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

**Example**:
```python
from trapninja.cli.filtering_commands import config_manager

# Load configuration with caching
config = config_manager.load_json("/path/to/config.json", default=[])

# Save with atomic write
success = config_manager.save_json("/path/to/config.json", data)

# Invalidate cache when external changes occur
config_manager.invalidate_cache("/path/to/config.json")
```

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

## Migration from Old main.py

The new structure is backward compatible. To migrate:

1. **Backup old main.py**:
   ```bash
   cp trapninja/main.py trapninja/main_backup.py
   ```

2. **Replace with new version**:
   ```bash
   cp trapninja/main_refactored.py trapninja/main.py
   ```

3. **Test all commands**:
   ```bash
   python -m trapninja.main --status
   python -m trapninja.main --list-blocked-ips
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

## Benefits of This Structure

1. **Maintainability**: Clear organization makes code easy to find and modify
2. **Testability**: Each module can be unit tested independently
3. **Extensibility**: Adding new commands is straightforward
4. **Security**: Centralized validation prevents injection attacks
5. **Performance**: Caching and LRU decorators optimize repeated operations
6. **Professionalism**: Industry-standard modular architecture

## Troubleshooting

### Import Errors

If you get import errors, ensure you're running from the correct directory:

```bash
# Run from project root
python -m trapninja.main --status

# Or with full path
python /opt/trapninja/trapninja/main.py --status
```

### Validation Failures

If validation consistently fails for valid input:

```python
# Check validation logic
from trapninja.cli.validation import InputValidator

# Test specific validator
result = InputValidator.validate_ip("192.168.1.1")
print(f"Validation result: {result}")
```

### Cache Issues

If configuration changes aren't being picked up:

```python
from trapninja.cli.filtering_commands import config_manager

# Force cache invalidation
config_manager.invalidate_cache()
```

## Performance Considerations

- **LRU Caching**: Validation functions use `@lru_cache` for performance
- **Precompiled Patterns**: Regex patterns compiled once at module load
- **Configuration Caching**: Reduces file I/O for frequently accessed configs
- **Atomic Operations**: Write operations are fast due to temp file strategy

## Future Enhancements

Potential improvements to consider:

1. **Async Operations**: Support async/await for concurrent operations
2. **Plugin System**: Allow third-party command extensions
3. **Shell Completion**: Add bash/zsh completion support
4. **Interactive Mode**: REPL-style interface for multiple commands
5. **Configuration Validation**: Schema validation with Pydantic
6. **Audit Logging**: Track all configuration changes

---

**Last Updated**: 2025-01-15  
**Module Version**: 2.0.0  
**Python Compatibility**: 3.6+
