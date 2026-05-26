---
applyTo: "src/trapninja/parser/**"
---

# Parser — SNMPv3 Security Rules

## Credential Handling — Absolute Rules

SNMPv3 credentials (auth keys, priv keys, community strings) must **never** appear in:
- Log messages at any level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
- Exception messages or stack traces
- Stdout or stderr output
- Any serialised state (Redis, baseline files, stats output)

These rules have zero exceptions. If an error message would naturally include a key or password to be helpful, rewrite it to include only a safe identifier (e.g. username, engine ID) instead.

## Credential Storage

- Credentials at rest: encrypted using **Fernet** (AES-128 CBC + HMAC-SHA256)
- Key derivation: **PBKDF2** from a site-specific master secret provisioned by Ansible
- The master secret is never stored in the codebase
- Access credentials only via the defined secure credential loader — never read the encrypted file directly in parser code

## Parse Failure Handling

A trap that fails to parse must **never** be silently dropped:

```python
# CORRECT
try:
    trap = parse_snmp_packet(data)
except SNMPParseError as e:
    self._stats.increment_failed(source_ip)
    logger.warning("Parse failed: src=%s err=%s", source_ip, e)
    # quarantine or forward raw depending on config
    return

# WRONG — silent loss
try:
    trap = parse_snmp_packet(data)
except Exception:
    pass
```

## SNMPv3 Decryption Flow

1. Authenticate the trap (HMAC against configured auth key for that USM user)
2. Decrypt the payload (AES or DES using priv key)
3. Parse the decrypted OID and varbind data
4. Re-encode as SNMPv2c for downstream forwarding

**Note**: TrapNinja does NOT re-encrypt as SNMPv3 on forward. All downstream NMS systems are assumed to accept v2c. This is a known accepted limitation.

## pysnmp API

Use the pysnmp API version consistent with what exists in the current codebase. pysnmp has had breaking API changes between versions — do not introduce a different API style without reviewing all existing parser code first.
