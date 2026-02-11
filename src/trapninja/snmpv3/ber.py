#!/usr/bin/env python3
"""
TrapNinja SNMPv3 BER Encoding/Decoding Utilities

Handles BER (Basic Encoding Rules) / ASN.1 encoding and decoding for
SNMP message construction and parsing.

Also manages detection of optional dependencies (pysnmp, pycryptodome).
"""
import logging
from typing import Any, Tuple

logger = logging.getLogger("trapninja")


# ============================================================================
# DEPENDENCY DETECTION
# ============================================================================

PYSNMP_AVAILABLE = False
PYSNMP_VERSION = None

try:
    import pysnmp
    PYSNMP_VERSION = getattr(pysnmp, '__version__', '0.0.0')
    major_version = int(PYSNMP_VERSION.split('.')[0])

    if major_version >= 7:
        from pyasn1.codec.ber import decoder, encoder  # noqa: F401
        from pyasn1.type import univ  # noqa: F401
        PYSNMP_AVAILABLE = True
        logger.info(f"Using pysnmp {PYSNMP_VERSION} (v7.x API)")
    else:
        from pyasn1.codec.ber import decoder, encoder  # noqa: F401
        from pyasn1.type import univ  # noqa: F401
        PYSNMP_AVAILABLE = True
        logger.info(f"Using pysnmp {PYSNMP_VERSION} (v4.x API)")

except ImportError as e:
    logger.warning(f"pysnmp not available: {e}")
    logger.warning("SNMPv3 decryption will not be available")
    logger.warning("Install with: pip3 install --break-system-packages pysnmp pyasn1")

CRYPTO_AVAILABLE = False
try:
    from Crypto.Cipher import AES, DES  # noqa: F401
    CRYPTO_AVAILABLE = True
except ImportError:
    logger.warning("pycryptodome not available - encrypted SNMPv3 traps cannot be decrypted")
    logger.warning("Install with: pip3 install --break-system-packages pycryptodome")


# ============================================================================
# BER LENGTH PARSING
# ============================================================================

def parse_ber_length(data: bytes, idx: int) -> Tuple[int, int]:
    """
    Parse BER length encoding.

    Args:
        data: Raw bytes
        idx: Index of the length byte(s)

    Returns:
        Tuple of (length, new_idx past the length bytes)
    """
    if data[idx] & 0x80:
        len_bytes = data[idx] & 0x7f
        length = int.from_bytes(data[idx + 1:idx + 1 + len_bytes], 'big')
        return length, idx + 1 + len_bytes
    else:
        return data[idx], idx + 1


# ============================================================================
# BER ENCODING
# ============================================================================

def encode_length(length: int) -> bytes:
    """Encode an integer as BER length bytes."""
    if length < 128:
        return bytes([length])
    elif length < 256:
        return bytes([0x81, length])
    elif length < 65536:
        return bytes([0x82, (length >> 8) & 0xff, length & 0xff])
    else:
        return bytes([0x83, (length >> 16) & 0xff, (length >> 8) & 0xff, length & 0xff])


def encode_integer(value: int) -> bytes:
    """Encode an integer as BER INTEGER (tag 0x02)."""
    if value == 0:
        return bytes([0x02, 0x01, 0x00])

    if value < 0:
        byte_len = (value.bit_length() + 8) // 8
        value_bytes = value.to_bytes(byte_len, 'big', signed=True)
    else:
        byte_len = (value.bit_length() + 7) // 8
        value_bytes = value.to_bytes(byte_len, 'big')
        if value_bytes[0] & 0x80:
            value_bytes = bytes([0x00]) + value_bytes

    return bytes([0x02]) + encode_length(len(value_bytes)) + value_bytes


def encode_oid(oid_str: str) -> bytes:
    """Encode an OID string (e.g. '1.3.6.1.2') as BER OBJECT IDENTIFIER."""
    components = [int(c) for c in oid_str.split('.') if c]

    if len(components) < 2:
        return bytes([0x06, 0x00])

    result = bytes([components[0] * 40 + components[1]])

    for comp in components[2:]:
        if comp < 128:
            result += bytes([comp])
        else:
            enc = []
            while comp > 0:
                enc.insert(0, (comp & 0x7f) | 0x80)
                comp >>= 7
            enc[-1] &= 0x7f
            result += bytes(enc)

    return bytes([0x06]) + encode_length(len(result)) + result


def encode_value(value: Any, value_type: str) -> bytes:
    """
    Encode a value as BER bytes based on its SNMP type string.

    Args:
        value: The value to encode
        value_type: SNMP type name (Integer, OctetString, ObjectIdentifier, etc.)

    Returns:
        BER-encoded bytes
    """
    if value_type == 'Integer' or 'Integer' in value_type:
        return encode_integer(int(value) if value else 0)

    elif value_type == 'OctetString':
        data = value if isinstance(value, bytes) else str(value).encode('utf-8')
        return bytes([0x04]) + encode_length(len(data)) + data

    elif value_type == 'ObjectIdentifier':
        return encode_oid(str(value))

    elif value_type == 'IpAddress':
        parts = str(value).split('.')
        if len(parts) == 4:
            data = bytes([int(p) for p in parts])
        else:
            data = bytes.fromhex(str(value))
        return bytes([0x40]) + encode_length(len(data)) + data

    elif value_type == 'Counter32':
        val = int(value) if value else 0
        data = val.to_bytes((val.bit_length() + 7) // 8 or 1, 'big')
        return bytes([0x41]) + encode_length(len(data)) + data

    elif value_type == 'Gauge32':
        val = int(value) if value else 0
        data = val.to_bytes((val.bit_length() + 7) // 8 or 1, 'big')
        return bytes([0x42]) + encode_length(len(data)) + data

    elif value_type == 'TimeTicks':
        val = int(value) if value else 0
        data = val.to_bytes((val.bit_length() + 7) // 8 or 1, 'big')
        return bytes([0x43]) + encode_length(len(data)) + data

    elif value_type == 'Counter64':
        val = int(value) if value else 0
        data = val.to_bytes((val.bit_length() + 7) // 8 or 1, 'big')
        return bytes([0x46]) + encode_length(len(data)) + data

    elif value_type == 'Null':
        return bytes([0x05, 0x00])

    else:
        # Default to OctetString
        data = value if isinstance(value, bytes) else str(value).encode('utf-8')
        return bytes([0x04]) + encode_length(len(data)) + data


# ============================================================================
# BER DECODING
# ============================================================================

def decode_oid(oid_bytes: bytes) -> str:
    """
    Decode BER-encoded OID bytes to dotted-decimal string.

    Args:
        oid_bytes: Raw OID bytes (tag and length already stripped)

    Returns:
        Dotted-decimal OID string (e.g. '1.3.6.1.4.1')
    """
    if not oid_bytes:
        return ""

    components = []

    first = oid_bytes[0]
    components.append(str(first // 40))
    components.append(str(first % 40))

    idx = 1
    while idx < len(oid_bytes):
        value = 0
        while idx < len(oid_bytes):
            byte = oid_bytes[idx]
            value = (value << 7) | (byte & 0x7f)
            idx += 1
            if not (byte & 0x80):
                break
        components.append(str(value))

    return '.'.join(components)


def decode_value(tag: int, value_bytes: bytes) -> Tuple[Any, str]:
    """
    Decode a BER value based on its ASN.1 tag.

    Args:
        tag: ASN.1 tag byte
        value_bytes: Raw value bytes (tag and length already stripped)

    Returns:
        Tuple of (decoded_value, type_name_string)
    """
    if tag == 0x02:  # INTEGER
        if not value_bytes:
            return 0, 'Integer'
        return int.from_bytes(value_bytes, 'big', signed=True), 'Integer'

    elif tag == 0x04:  # OCTET STRING
        try:
            return value_bytes.decode('utf-8'), 'OctetString'
        except UnicodeDecodeError:
            return value_bytes.hex(), 'OctetString'

    elif tag == 0x05:  # NULL
        return None, 'Null'

    elif tag == 0x06:  # OBJECT IDENTIFIER
        return decode_oid(value_bytes), 'ObjectIdentifier'

    elif tag == 0x40:  # IpAddress
        if len(value_bytes) == 4:
            return '.'.join(str(b) for b in value_bytes), 'IpAddress'
        return value_bytes.hex(), 'IpAddress'

    elif tag == 0x41:  # Counter32
        return int.from_bytes(value_bytes, 'big'), 'Counter32'

    elif tag == 0x42:  # Gauge32/Unsigned32
        return int.from_bytes(value_bytes, 'big'), 'Gauge32'

    elif tag == 0x43:  # TimeTicks
        return int.from_bytes(value_bytes, 'big'), 'TimeTicks'

    elif tag == 0x44:  # Opaque
        return value_bytes.hex(), 'Opaque'

    elif tag == 0x46:  # Counter64
        return int.from_bytes(value_bytes, 'big'), 'Counter64'

    else:
        return value_bytes.hex(), f'Unknown(0x{tag:02x})'
