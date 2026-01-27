# TrapNinja Security Documentation

This document describes the security measures implemented in TrapNinja to address common vulnerability patterns identified by static security analysis.

## Overview

TrapNinja has been updated to address the following Common Weakness Enumerations (CWEs):

| CWE | Description | Status |
|-----|-------------|--------|
| CWE-284 | Improper Access Control (Bind Address) | Fixed |
| CWE-327 | Use of Broken or Risky Cryptographic Algorithm | Mitigated with warnings |
| CWE-23 | Relative Path Traversal | Fixed |
| CWE-916 | Use of Password Hash With Insufficient Computational Effort | Fixed |

## CWE-284: Improper Access Control (Bind Address)

### Background

Binding network listeners to `0.0.0.0` (all interfaces) can expose services to unintended networks, increasing attack surface.

### TrapNinja's Situation

TrapNinja has two network listeners:
1. **SNMP Trap Listener** (UDP) - Receives traps from network devices
2. **HA Cluster Listener** (TCP) - Receives heartbeats and commands from HA peer

Previously, both bound to `0.0.0.0` by default.

### Remediation Applied

1. **Configurable Bind Address**: Both listeners now support explicit bind address configuration
2. **Auto-Detection**: If not explicitly configured, the bind address is auto-detected from the configured interface
3. **Fallback Warning**: If auto-detection fails, `0.0.0.0` is used with a warning logged

**Files Modified:**
- `config.py` - Added `BIND_ADDRESS` with auto-detection from interface
- `network.py` - Uses `BIND_ADDRESS` instead of hardcoded `0.0.0.0`
- `ha/config.py` - Added `listen_address` field to `HAConfig`
- `ha/cluster.py` - Uses `config.listen_address` for HA listener

### Configuration

**SNMP Trap Listener** (`trapninja.json`):
```json
{
  "interface": "eth0",
  "bind_address": "10.1.2.3"
}
```

If `bind_address` is not set, TrapNinja will:
1. Try to get the IP address of the configured `interface`
2. Fall back to `0.0.0.0` with a warning if detection fails

**HA Cluster Listener** (`ha_config.json`):
```json
{
  "listen_address": "10.1.2.100",
  "listen_port": 60006
}
```

### Recommendations

1. **Always set explicit bind addresses** in production environments
2. **Use management VLAN IPs** for HA communication
3. **Firewall rules** should still be applied as defense-in-depth

## CWE-327: Cryptographic Algorithm Security

### Background

Security scanners flag the use of MD5, SHA-1, and DES algorithms as these are cryptographically weak by modern standards.

### TrapNinja's Situation

TrapNinja implements **SNMPv3 protocol support**, which is governed by RFC 3414 (User-based Security Model for SNMPv3). This RFC mandates support for:

- **Authentication**: MD5 (MD5-96 HMAC) and SHA-1 (SHA-96 HMAC)
- **Privacy**: DES (DES-CBC)

These algorithms cannot be removed without breaking protocol compatibility with network devices.

### Remediation Applied

1. **Documentation**: Added security notes to affected files explaining RFC 3414 requirements
2. **Warnings**: Implemented runtime warnings when legacy algorithms are used
3. **Recommendations**: Log messages recommend stronger alternatives where device support exists
4. **Non-SNMP Code**: Updated all non-SNMP cryptographic operations to use SHA-256

**Files Modified:**
- `snmpv3_decryption.py` - Added CWE-327 documentation and runtime warnings
- `ha/sync/config_bundle.py` - Changed from MD5 to SHA-256 for checksums
- `security.py` (new) - Security utilities with algorithm validation

### Example Log Output

When legacy SNMPv3 algorithms are used:
```
INFO: SNMPv3 key localization: Using MD5 (RFC 3414 required). Consider SHA-256 where device supports it. [CWE-327 acknowledged]
INFO: SNMPv3 encryption: Using DES (RFC 3414 required). Consider AES-128+ where device supports it. [CWE-327 acknowledged]
```

### Recommendations for Operators

1. **Prefer Modern Algorithms**: When configuring SNMPv3 on network devices, use:
   - Authentication: SHA-256, SHA-384, or SHA-512
   - Privacy: AES-128, AES-192, or AES-256

2. **Legacy Device Support**: MD5/DES support is maintained for compatibility with older devices that don't support modern algorithms

3. **Security Audit**: Review logs for legacy algorithm warnings and upgrade devices where possible

## CWE-23: Path Traversal Prevention

### Background

Path traversal vulnerabilities allow attackers to access files outside the intended directory by using sequences like `../` in file paths.

### Remediation Applied

1. **Allowlist Validation**: Configuration file loading now validates against an explicit allowlist of filenames
2. **Path Canonicalization**: All paths are resolved to absolute paths before validation
3. **Directory Containment**: Paths must remain within the configuration directory
4. **Pattern Detection**: Input is checked for path traversal sequences

**Files Modified:**
- `config.py` - Added `_validate_config_path()` function and `ALLOWED_CONFIG_FILES` allowlist
- `cli/validation.py` - Already had traversal pattern detection (confirmed adequate)
- `security.py` (new) - `SecurePath` class for secure path operations

### Design Note: Hardcoded Paths

TrapNinja's config loading uses **hardcoded file paths** defined as constants (e.g., `DESTINATIONS_FILE`, `BLOCKED_TRAPS_FILE`). These paths are constructed from `CONFIG_DIR` + a fixed filename, so path traversal is not possible through normal operation.

The `_validate_config_path()` function is available for use in any code that handles user-provided paths (such as CLI commands or API endpoints), but is not called automatically in `safe_load_json()` since that function only receives the hardcoded constants.

### Allowed Configuration Files

Only these filenames are permitted:
```python
ALLOWED_CONFIG_FILES = frozenset([
    'trapninja.json',
    'destinations.json',
    'blocked_traps.json',
    'listen_ports.json',
    'blocked_ips.json',
    'redirected_ips.json',
    'redirected_oids.json',
    'redirected_destinations.json',
    'cache_config.json',
    'snmpv3_credentials.json',
    'ha_config.json',
])
```

### Using SecurePath

The `security.py` module provides a `SecurePath` class for secure file operations:

```python
from trapninja.security import SecurePath, PathTraversalError

secure = SecurePath('/etc/trapninja')

# Safe file operations
try:
    path = secure.safe_join('config.json')  # Returns validated path
    content = secure.safe_open('config.json', 'r').read()
except PathTraversalError as e:
    logger.error(f"Path traversal attempt: {e}")
```

## CWE-916: Password Hashing Strength

### Background

Insufficient computational effort in password hashing allows brute-force attacks to succeed more quickly.

### Remediation Applied

1. **PBKDF2 Iterations**: Increased from 100,000 to 600,000 (OWASP 2023 recommendation)
2. **Algorithm**: Using PBKDF2-SHA256 (already compliant)
3. **Documentation**: Added security notes explaining iteration count choices

**Files Modified:**
- `snmpv3_credentials.py` - Increased PBKDF2 iterations to 600,000

### Implementation Details

```python
# Key derivation with OWASP 2023 recommended iterations
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=600000,  # OWASP 2023 recommendation
    backend=default_backend()
)
```

### Migration Note

Existing encrypted credentials will need to be re-encrypted after updating, as the new iteration count is incompatible with the old one. This is by design - the old credentials used weaker protection.

To re-encrypt credentials:
```bash
# Export existing credentials
trapninja --list-v3-users > credentials_backup.txt

# Remove old credentials
rm /etc/trapninja/snmpv3_credentials.json

# Re-add credentials (will use new iteration count)
trapninja --add-v3-user ... 
```

## Security Module Reference

The new `security.py` module provides utilities for security-sensitive operations:

### Path Security

```python
from trapninja.security import SecurePath, PathTraversalError, validate_config_path

# Create secure path handler
secure = SecurePath('/etc/trapninja')

# Validate and join paths safely
safe_path = secure.safe_join('config.json')

# Check if file exists safely
exists = secure.exists('config.json')

# Open file safely
with secure.safe_open('config.json', 'r') as f:
    data = f.read()
```

### Cryptographic Validation

```python
from trapninja.security import (
    check_algorithm_security,
    validate_snmpv3_algorithm,
    log_snmpv3_security_assessment,
    secure_checksum
)

# Check algorithm security
is_ok, warning = check_algorithm_security('SHA256', 'hashing')

# Validate SNMP algorithm
is_valid, warning = validate_snmpv3_algorithm('AES128', 'priv')

# Log security assessment
log_snmpv3_security_assessment(auth_protocol='SHA256', priv_protocol='AES128')

# Calculate secure checksum (uses SHA-256)
checksum = secure_checksum(data)
```

### Key Derivation Validation

```python
from trapninja.security import validate_kdf_parameters

is_secure, warning = validate_kdf_parameters(
    iterations=600000,
    salt_length=32,
    algorithm='SHA256'
)
```

## Security Testing

After applying these fixes, run the security scanner again. Expected results:

| Finding | Expected Status |
|---------|-----------------|
| CWE-284 (Bind to 0.0.0.0) | Fixed - Configurable bind address |
| CWE-327 (MD5/SHA1/DES in SNMP) | Acknowledged - RFC 3414 requirement |
| CWE-327 (MD5 in checksums) | Fixed - Now uses SHA-256 |
| CWE-23 (Path traversal) | Fixed - Path validation added |
| CWE-916 (PBKDF2 iterations) | Fixed - Increased to 600,000 |

## Future Recommendations

1. **Argon2**: Consider migrating to Argon2id for credential encryption when library support is available on target platforms
2. **SNMPv3 Deprecation**: As devices are upgraded, phase out MD5/DES usage by tracking which devices still require legacy support
3. **Regular Audits**: Schedule periodic security scans and review the logs for legacy algorithm warnings

## References

- [RFC 3414 - User-based Security Model for SNMPv3](https://tools.ietf.org/html/rfc3414)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [CWE-284: Improper Access Control](https://cwe.mitre.org/data/definitions/284.html)
- [CWE-327: Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)
- [CWE-23: Relative Path Traversal](https://cwe.mitre.org/data/definitions/23.html)
- [CWE-916: Use of Password Hash With Insufficient Computational Effort](https://cwe.mitre.org/data/definitions/916.html)
