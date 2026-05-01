# Security-Critical Code — Scoped Rules

> Read `../../CLAUDE.md` for project-wide rules. This file adds **security-specific constraints**
> for the SNMPv3 credential and decryption modules.

## Security Constraints — Enforced Without Exception

The files in this directory and the adjacent `snmpv3_credentials.py` and `snmpv3_decryption.py`
handle **SNMPv3 authentication and privacy credentials**. These are among the most
security-sensitive components in the entire system.

### Hard Rules

1. **Credentials must never appear in logs, error messages, exceptions, or tracebacks.**
   - No auth keys, priv keys, passphrases, or community strings — not even partially.
   - When logging credential operations, log only: engine ID, security name, and operation result.
   - Use `repr()` guards or redaction wrappers if there is any risk of credential leakage.

2. **Credentials must be stored encrypted at rest.**
   - Never store raw credentials in config files, JSON state files, or Redis keys.
   - Access credentials only through the defined secure interface in `snmpv3_credentials.py`.

3. **Decryption failures must be handled securely.**
   - On decryption failure: log the failure reason (NOT the credential), forward the raw
     encrypted trap to the destination (passthrough mode), increment error counter.
   - Never discard a trap solely because decryption failed — passthrough is the fallback.

4. **BER parsing (`ber.py`) must be hardened against malformed input.**
   - All length fields must be validated before use.
   - Reject inputs exceeding expected size bounds.
   - Never follow unbounded pointers or allocate based on untrusted length values.
   - All parsing functions must handle malformed data without raising unhandled exceptions.

5. **No credential material in test fixtures or assertions.**
   - Test SNMPv3 flows with synthetic/throwaway credentials only.
   - Never commit real credentials to the repository — even in test files.

### Acceptable Degradation
- If SNMPv3 decryption is unavailable (pysnmp not installed, key not found):
  → Forward the trap in encrypted form (passthrough) and log a warning.
  → This is correct and safe behaviour — do not treat it as an error condition.

### Module Responsibilities
| File | Responsibility |
|------|---------------|
| `snmpv3/ber.py` | Low-level BER/DER ASN.1 parsing — security-hardened |
| `snmpv3/__init__.py` | SNMPv3 message framing and version detection |
| `snmpv3_credentials.py` | Secure credential store — encrypted at rest, controlled access |
| `snmpv3_decryption.py` | Decryption pipeline — passthrough fallback on failure |
