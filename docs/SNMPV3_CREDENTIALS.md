# TrapNinja SNMPv3 Credentials Guide

**Version 0.7.0 (Beta)**

Complete guide to managing SNMPv3 user credentials for trap decryption.

---

## Overview

TrapNinja can receive encrypted SNMPv3 traps, decrypt them using stored credentials, and forward the contents as SNMPv2c traps. This enables integration with monitoring systems that don't support SNMPv3 while maintaining security on the network element side.

The SNMPv3 security model uses three key elements:

1. **Engine ID** - Unique identifier for the SNMP agent (network element)
2. **Authentication** - Verifies message integrity (MD5, SHA family)
3. **Privacy** - Encrypts message contents (DES, AES family)

---

## Prerequisites

SNMPv3 functionality requires several Python packages:

```bash
# Required for credential storage (encrypted at rest)
pip3 install --break-system-packages cryptography

# Required for trap decryption
pip3 install --break-system-packages pysnmp pyasn1

# Required for AES/DES decryption of encrypted payloads
pip3 install --break-system-packages pycryptodome
```

Or install all at once:

```bash
pip3 install --break-system-packages cryptography pysnmp pyasn1 pycryptodome
```

Verify dependencies are installed:

```bash
python3.9 -O trapninja.py --snmpv3-status
```

If dependencies are missing, you'll see:

```
✗ Error: SNMPv3 credential module not available
  Details: No module named 'cryptography'
```

---

## Credential Storage Security

TrapNinja encrypts SNMPv3 credentials at rest using Fernet symmetric encryption. The encryption key is derived from the Engine ID using PBKDF2 with 100,000 iterations, meaning credentials can only be decrypted when the correct Engine ID is known.

Credentials are stored in `config/snmpv3_credentials.json` with restrictive file permissions (0600 - owner read/write only). Passphrases are never stored in plaintext.

---

## Adding SNMPv3 Users

### Interactive Mode (Recommended)

The safest method prompts for passphrases without echoing them to the terminal:

```bash
python3.9 -O trapninja.py --snmpv3-add-user \
    --username myuser \
    --engine-id 80001f888056565656565656 \
    --auth-protocol SHA \
    --priv-protocol AES128
```

You will be prompted:

```
Authentication passphrase for myuser: 
Confirm authentication passphrase: 
Privacy passphrase for myuser: 
Confirm privacy passphrase: 
✓ Added user myuser for engine 80001f888056565656565656
```

Passphrases must be at least 8 characters and will not be displayed as you type.

### Command-Line Mode

For scripted deployments, passphrases can be provided directly. **Use with caution** - passphrases may be visible in process listings and shell history.

```bash
python3.9 -O trapninja.py --snmpv3-add-user \
    --username myuser \
    --engine-id 80001f888056565656565656 \
    --auth-protocol SHA \
    --auth-passphrase "MyAuthPassword123" \
    --priv-protocol AES128 \
    --priv-passphrase "MyPrivPassword456"
```

Clear shell history after use:

```bash
history -c
```

### From Environment Variables

For automation without exposing secrets:

```bash
export SNMPV3_AUTH_PASS="MyAuthPassword123"
export SNMPV3_PRIV_PASS="MyPrivPassword456"

python3.9 -O trapninja.py --snmpv3-add-user \
    --username myuser \
    --engine-id 80001f888056565656565656 \
    --auth-protocol SHA \
    --auth-passphrase "$SNMPV3_AUTH_PASS" \
    --priv-protocol AES128 \
    --priv-passphrase "$SNMPV3_PRIV_PASS"

unset SNMPV3_AUTH_PASS SNMPV3_PRIV_PASS
```

---

## Supported Protocols

### Authentication Protocols

| Protocol | Description | Recommendation |
|----------|-------------|----------------|
| `NONE` | No authentication | Not recommended |
| `MD5` | HMAC-MD5-96 | Legacy, avoid if possible |
| `SHA` | HMAC-SHA-96 | Widely supported |
| `SHA224` | HMAC-SHA-224 | Better security |
| `SHA256` | HMAC-SHA-256 | Recommended |
| `SHA384` | HMAC-SHA-384 | High security |
| `SHA512` | HMAC-SHA-512 | Highest security |

### Privacy (Encryption) Protocols

| Protocol | Description | Recommendation |
|----------|-------------|----------------|
| `NONE` | No encryption | Not recommended |
| `DES` | DES-CBC | Legacy, avoid |
| `3DES` | 3DES-EDE | Legacy, avoid |
| `AES128` | AES-128-CFB | Recommended |
| `AES192` | AES-192-CFB | High security |
| `AES256` | AES-256-CFB | Highest security |

### Security Levels

SNMPv3 supports three security levels:

1. **noAuthNoPriv** - No authentication, no encryption (auth/priv both NONE)
2. **authNoPriv** - Authentication only, no encryption (auth set, priv NONE)
3. **authPriv** - Both authentication and encryption (both set)

Example for authNoPriv (authentication only):

```bash
python3.9 -O trapninja.py --snmpv3-add-user \
    --username authonly_user \
    --engine-id 80001f888056565656565656 \
    --auth-protocol SHA256 \
    --priv-protocol NONE
```

---

## Engine ID Format

The Engine ID is a hexadecimal string that uniquely identifies the SNMP agent. Common formats:

### Standard Format (RFC 3411)

Format: `80` + `enterprise_number (8 hex)` + `format_type (2 hex)` + `unique_data`

Examples:

```
80001f888056565656565656  (Cisco format)
8000000001020304          (Simple format)
800000c20300001234        (Nokia format)
```

### Finding Engine IDs

**From Cisco devices:**

```
show snmp engineID
```

**From Nokia 7750/7950:**

```
show system snmp engine-id
```

**From snmpwalk:**

```bash
snmpwalk -v 3 -u username -l authPriv -a SHA -A "authpass" \
    -x AES -X "privpass" device_ip 1.3.6.1.6.3.10.2.1.1.0
```

**From captured traffic:**

Use Wireshark to capture an SNMPv3 trap, then examine the `msgAuthoritativeEngineID` field.

---

## Managing Users

### List All Users

```bash
python3.9 -O trapninja.py --snmpv3-list-users
```

Output:

```
Configured SNMPv3 Users (2 total):

Engine ID                                Username             Auth       Priv      
-------------------------------------------------------------------------------------
80001f888056565656565656                 cisco_user           SHA        AES128    
800000c20300001234                       nokia_user           SHA256     AES256    
```

### Show User Details

```bash
python3.9 -O trapninja.py --snmpv3-show-user \
    --engine-id 80001f888056565656565656 \
    --username cisco_user
```

Output:

```
SNMPv3 User Details:

  Engine ID:          80001f888056565656565656
  Username:           cisco_user
  Auth Protocol:      SHA
  Auth Passphrase:    ***
  Privacy Protocol:   AES128
  Privacy Passphrase: ***
```

### Update User Credentials

To update credentials, add the user again with the same engine-id and username:

```bash
python3.9 -O trapninja.py --snmpv3-add-user \
    --username cisco_user \
    --engine-id 80001f888056565656565656 \
    --auth-protocol SHA256 \
    --priv-protocol AES256
```

You'll be prompted for new passphrases. Output shows "Updated" instead of "Added":

```
Authentication passphrase for cisco_user: 
Confirm authentication passphrase: 
Privacy passphrase for cisco_user: 
Confirm privacy passphrase: 
✓ Updated user cisco_user for engine 80001f888056565656565656
```

### Remove User

```bash
python3.9 -O trapninja.py --snmpv3-remove-user \
    --engine-id 80001f888056565656565656 \
    --username cisco_user
```

Confirmation prompt:

```
Remove user 'cisco_user' for engine '80001f888056565656565656'? (yes/no): yes
✓ Removed user cisco_user for engine 80001f888056565656565656
```

Skip confirmation with `-y`:

```bash
python3.9 -O trapninja.py --snmpv3-remove-user \
    --engine-id 80001f888056565656565656 \
    --username cisco_user \
    -y
```

---

## SNMPv3 Status

Check the overall SNMPv3 subsystem status:

```bash
python3.9 -O trapninja.py --snmpv3-status
```

Output:

```
SNMPv3 Subsystem Status:

  Configured Engine IDs: 2
  Configured Users:      3

  Engine IDs:
    - 80001f888056565656565656 (2 users)
    - 800000c20300001234 (1 users)
```

---

## Testing Decryption

Test that credentials work with a captured SNMPv3 trap:

```bash
# Basic test
python3.9 -O trapninja.py --snmpv3-test-decrypt \
    --trap-file /tmp/captured_trap.bin \
    --engine-id 80001f888056565656565656

# Verbose output showing varbinds
python3.9 -O trapninja.py --snmpv3-test-decrypt \
    --trap-file /tmp/captured_trap.bin \
    --engine-id 80001f888056565656565656 \
    --verbose

# Test conversion to SNMPv2c
python3.9 -O trapninja.py --snmpv3-test-decrypt \
    --trap-file /tmp/captured_trap.bin \
    --convert \
    --community public \
    --output /tmp/snmpv2c_trap.bin
```

### Capturing Test Traps

**Using tcpdump:**

```bash
# Capture SNMPv3 traps to file
tcpdump -i any udp port 162 -w /tmp/snmpv3_traps.pcap

# Extract individual trap payloads with tshark
tshark -r /tmp/snmpv3_traps.pcap -T fields -e snmp.data > /tmp/trap_hex.txt
```

**Using netcat:**

```bash
# Listen for one trap
nc -u -l 162 > /tmp/trap.bin
```

---

## Common Configurations

### Cisco ASR/NCS Routers

```bash
# Typical Cisco SNMPv3 configuration
python3.9 -O trapninja.py --snmpv3-add-user \
    --username trap_user \
    --engine-id 80001f888056565656565656 \
    --auth-protocol SHA \
    --priv-protocol AES128
```

Corresponding Cisco configuration:

```
snmp-server user trap_user TRAPGROUP v3 auth sha MyAuthPassword123 priv aes 128 MyPrivPassword456
snmp-server host 10.234.83.133 traps version 3 priv trap_user
```

### Nokia 7750SR/7950XRS

```bash
# Nokia typically uses SHA256/AES256
python3.9 -O trapninja.py --snmpv3-add-user \
    --username nokia_trap \
    --engine-id 800000c20300001234 \
    --auth-protocol SHA256 \
    --priv-protocol AES256
```

Corresponding Nokia configuration:

```
configure system security snmp user-name "nokia_trap"
    auth-protocol sha256 auth-password "MyAuthPassword123"
    privacy-protocol aes256 privacy-password "MyPrivPassword456"
```

### Multiple Users Per Engine

Some deployments use different users for different trap types:

```bash
# Critical alarms user
python3.9 -O trapninja.py --snmpv3-add-user \
    --username critical_traps \
    --engine-id 80001f888056565656565656 \
    --auth-protocol SHA256 \
    --priv-protocol AES256

# Info/debug user
python3.9 -O trapninja.py --snmpv3-add-user \
    --username debug_traps \
    --engine-id 80001f888056565656565656 \
    --auth-protocol SHA \
    --priv-protocol AES128
```

---

## Troubleshooting

### "No credentials configured for Engine ID"

The trap's Engine ID doesn't match any configured user.

1. Verify the Engine ID from the network element
2. Check configured Engine IDs: `--snmpv3-list-users`
3. Engine IDs are case-insensitive but stored lowercase

### "Failed to decrypt SNMPv3 trap"

Authentication or privacy credentials don't match.

1. Verify username matches exactly (case-sensitive)
2. Confirm authentication protocol matches device configuration
3. Confirm privacy protocol matches device configuration
4. Re-enter credentials if passwords may have changed

### Decryption Works in Test But Not in Production

1. Ensure TrapNinja is running as a user with access to the credentials file
2. Check file permissions: `ls -la config/snmpv3_credentials.json`
3. Verify pysnmp is installed for the Python instance running TrapNinja

### Engine ID Mismatch

Different Engine IDs may be seen when:

- Device is configured for proxy forwarding
- Trap originated from a sub-agent
- Device was re-provisioned

Use verbose logging to see actual Engine IDs:

```bash
python3.9 -O trapninja.py --foreground --debug 2>&1 | grep "Engine ID"
```

### Password Policy Issues

SNMPv3 passphrases must be at least 8 characters. If your network element requires longer or more complex passwords, ensure you meet those requirements when adding users to TrapNinja.

---

## Security Best Practices

1. **Use strong passphrases** - Minimum 12 characters with mixed case, numbers, and symbols

2. **Prefer interactive mode** - Avoid exposing passphrases in shell history

3. **Restrict file access** - The credentials file should be readable only by the TrapNinja service account

4. **Use SHA256+ and AES128+** - Avoid legacy protocols (MD5, DES) when possible

5. **Rotate credentials periodically** - Update passphrases when personnel change or annually

6. **Monitor credential usage** - Check logs for decryption failures that may indicate credential issues

7. **Backup credentials securely** - The encrypted credentials file can be backed up but the Engine IDs must also be preserved for decryption

---

## CLI Reference

| Command | Description |
|---------|-------------|
| `--snmpv3-status` | Show SNMPv3 subsystem status |
| `--snmpv3-add-user` | Add or update user credentials |
| `--snmpv3-remove-user` | Remove user credentials |
| `--snmpv3-list-users` | List all configured users |
| `--snmpv3-show-user` | Show details for specific user |
| `--snmpv3-test-decrypt` | Test decryption with captured trap |

### Add User Options

| Option | Required | Description |
|--------|----------|-------------|
| `--username` | Yes | SNMP username (1-32 characters) |
| `--engine-id` | Yes | Engine ID (hex string) |
| `--auth-protocol` | Yes | Authentication protocol |
| `--auth-passphrase` | No | Auth password (prompted if not given) |
| `--priv-protocol` | Yes | Privacy protocol |
| `--priv-passphrase` | No | Privacy password (prompted if not given) |

### Remove User Options

| Option | Required | Description |
|--------|----------|-------------|
| `--username` | Yes | SNMP username |
| `--engine-id` | Yes | Engine ID |
| `-y`, `--yes` | No | Skip confirmation prompt |

### Test Decrypt Options

| Option | Required | Description |
|--------|----------|-------------|
| `--trap-file` | Yes | Path to captured trap file |
| `--engine-id` | No | Engine ID (extracted from trap if not given) |
| `--verbose` | No | Show detailed varbind information |
| `--convert` | No | Also test conversion to SNMPv2c |
| `--community` | No | Community string for conversion (default: public) |
| `--output` | No | Save converted trap to file |

---

## Related Documentation

- [USER_GUIDE.md](USER_GUIDE.md) - General TrapNinja usage
- [ARCHITECTURE.md](ARCHITECTURE.md) - System architecture including SNMPv3 processing flow
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md) - General troubleshooting

---

*TrapNinja v0.7.0 (Beta)*
