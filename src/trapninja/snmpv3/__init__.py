#!/usr/bin/env python3
"""
TrapNinja SNMPv3 Decryption Package

Handles decryption of SNMPv3 traps and conversion to SNMPv2c format.
Integrates with the credential management system for authentication.

Supports both pysnmp 4.x and 7.x API versions.

Package Structure:
    ber.py       - BER/ASN.1 encoding and decoding utilities
    crypto.py    - Key localization, encryption/decryption operations
    parser.py    - SNMPv3 message structure parsing (USM, ScopedPDU)
    converter.py - SNMPv2c message construction from decoded trap data
    decryptor.py - Main SNMPv3Decryptor orchestrator class

Security Notes (CWE-327):
    - MD5 and SHA-1 usage is REQUIRED by RFC 3414 (SNMPv3 USM) for protocol
      compatibility with network devices. These cannot be removed.
    - DES usage is REQUIRED by RFC 3414 for legacy device support.
    - Prefer SHA-256+ and AES-128+ when devices support them.
    - Security warnings are logged when legacy algorithms are used.

Refactored from monolithic snmpv3_decryption.py (1317 lines) into
focused modules for maintainability and testability.
"""

from .decryptor import (
    SNMPv3Decryptor,
    get_snmpv3_decryptor,
    initialize_snmpv3_decryptor,
    decrypt_and_convert_trap,
)

from .parser import (
    extract_engine_id_from_bytes,
    extract_username_from_bytes,
)

from .ber import (
    PYSNMP_AVAILABLE,
    PYSNMP_VERSION,
    CRYPTO_AVAILABLE,
)

__all__ = [
    # Main decryptor
    'SNMPv3Decryptor',
    'get_snmpv3_decryptor',
    'initialize_snmpv3_decryptor',
    'decrypt_and_convert_trap',
    # Parsing utilities
    'extract_engine_id_from_bytes',
    'extract_username_from_bytes',
    # Availability flags
    'PYSNMP_AVAILABLE',
    'PYSNMP_VERSION',
    'CRYPTO_AVAILABLE',
]
