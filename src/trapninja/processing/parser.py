#!/usr/bin/env python3
"""
TrapNinja SNMP Parser

High-performance SNMP parsing with optimized fast path for SNMPv2c.

Key optimizations:
- Direct byte scanning for SNMPv2c (avoids full packet parsing)
- Pre-compiled byte patterns
- Minimal memory allocation
- Fast OID decoding

Performance: ~5-10x faster than full Scapy parsing for SNMPv2c

Author: TrapNinja Team
Version: 2.0.0
"""

import logging
from typing import Optional, Tuple, Dict, Any

logger = logging.getLogger("trapninja")


# =============================================================================
# BYTE PATTERNS (Pre-compiled for fast matching)
# =============================================================================

# snmpTrapOID.0 as binary bytes
SNMPTRAPOID_MARKER = b'\x2b\x06\x01\x06\x03\x01\x01\x04\x01\x00'

# ASN.1 tags
ASN1_SEQUENCE = 0x30
ASN1_INTEGER = 0x02
ASN1_OCTET_STRING = 0x04
ASN1_OID = 0x06

# SNMP version values
SNMP_V1 = 0
SNMP_V2C = 1
SNMP_V3 = 3


# =============================================================================
# SNMP VERSION DETECTION
# =============================================================================

def get_snmp_version(payload: bytes) -> Optional[int]:
    """
    Get SNMP version from packet payload.
    
    Fast version detection without full parsing.
    
    Args:
        payload: Raw SNMP packet bytes
        
    Returns:
        SNMP version (0=v1, 1=v2c, 3=v3) or None if invalid
    """
    if len(payload) < 6:
        return None
    
    # Check for SEQUENCE tag
    if payload[0] != ASN1_SEQUENCE:
        return None
    
    # Find version field
    # Skip length byte(s)
    pos = 1
    length = payload[pos]
    
    if length & 0x80:
        # Long form length
        num_octets = length & 0x7F
        pos += num_octets + 1
    else:
        pos += 1
    
    # Should be INTEGER tag for version
    if pos >= len(payload) or payload[pos] != ASN1_INTEGER:
        return None
    
    pos += 1
    if pos >= len(payload):
        return None
    
    # Version length (should be 1)
    version_len = payload[pos]
    pos += 1
    
    if pos >= len(payload) or version_len != 1:
        return None
    
    return payload[pos]


def is_snmpv2c(payload: bytes) -> bool:
    """
    Fast SNMPv2c detection.
    
    Checks for the specific structure of an SNMPv2c message:
    - SEQUENCE tag (0x30)
    - INTEGER tag (0x02) for version
    - Version value 1 (SNMPv2c)
    - OCTET STRING tag (0x04) for community
    
    Handles both short and long form length encoding.
    
    Args:
        payload: Raw SNMP packet bytes
        
    Returns:
        True if packet is SNMPv2c
    """
    if len(payload) < 8:
        return False
    
    # Must start with SEQUENCE
    if payload[0] != ASN1_SEQUENCE:
        return False
    
    # Skip SEQUENCE length (handles both short and long form)
    idx = 1
    if payload[idx] & 0x80:
        # Long form: high bit set, low 7 bits = number of length bytes
        num_len_bytes = payload[idx] & 0x7F
        idx += 1 + num_len_bytes
    else:
        # Short form: length is the byte itself
        idx += 1
    
    if idx + 4 > len(payload):
        return False
    
    # Check for INTEGER tag (version)
    if payload[idx] != ASN1_INTEGER:
        return False
    idx += 1
    
    # Version length should be 1
    if payload[idx] != 0x01:
        return False
    idx += 1
    
    # Version value should be 1 (SNMPv2c)
    if payload[idx] != SNMP_V2C:
        return False
    idx += 1
    
    # Next should be OCTET STRING (community)
    if idx >= len(payload) or payload[idx] != ASN1_OCTET_STRING:
        return False
    
    return True


def is_snmpv1(payload: bytes) -> bool:
    """
    Fast SNMPv1 detection.
    
    Handles both short and long form length encoding.
    
    Args:
        payload: Raw SNMP packet bytes
        
    Returns:
        True if packet is SNMPv1
    """
    if len(payload) < 6:
        return False
    
    # Must start with SEQUENCE
    if payload[0] != ASN1_SEQUENCE:
        return False
    
    # Skip SEQUENCE length (handles both short and long form)
    idx = 1
    if payload[idx] & 0x80:
        num_len_bytes = payload[idx] & 0x7F
        idx += 1 + num_len_bytes
    else:
        idx += 1
    
    if idx + 3 > len(payload):
        return False
    
    # Check for INTEGER tag (version)
    if payload[idx] != ASN1_INTEGER:
        return False
    idx += 1
    
    # Version length should be 1
    if payload[idx] != 0x01:
        return False
    idx += 1
    
    # Version value should be 0 (SNMPv1)
    return payload[idx] == SNMP_V1


def is_snmpv3(payload: bytes) -> bool:
    """
    Fast SNMPv3 detection using byte-level analysis.
    
    SNMPv3 structure:
    - SEQUENCE (0x30)
    - INTEGER version = 3
    - SEQUENCE msgGlobalData (NOT OCTET STRING like v1/v2c community)
    
    Args:
        payload: Raw SNMP packet bytes
        
    Returns:
        True if packet is SNMPv3
    """
    if len(payload) < 10:
        return False
    
    # Must start with SEQUENCE
    if payload[0] != ASN1_SEQUENCE:
        return False
    
    # Skip outer SEQUENCE length
    idx = 1
    if payload[idx] & 0x80:
        # Long form length
        num_octets = payload[idx] & 0x7F
        idx += num_octets + 1
    else:
        idx += 1
    
    if idx >= len(payload):
        return False
    
    # Check for INTEGER tag (version)
    if payload[idx] != ASN1_INTEGER:
        return False
    idx += 1
    
    if idx >= len(payload):
        return False
    
    # Get version length
    version_len = payload[idx]
    idx += 1
    
    if idx + version_len > len(payload):
        return False
    
    # Get version value
    version = 0
    for i in range(version_len):
        version = (version << 8) | payload[idx + i]
    
    # SNMPv3 has version = 3
    if version != 3:
        return False
    
    idx += version_len
    
    # After version, SNMPv3 has SEQUENCE (msgGlobalData)
    # v1/v2c have OCTET STRING (community)
    if idx < len(payload) and payload[idx] == ASN1_SEQUENCE:
        return True
    
    return False


# =============================================================================
# FAST OID EXTRACTION (For SNMPv2c)
# =============================================================================

def extract_trap_oid_fast(payload: bytes) -> Optional[str]:
    """
    Fast OID extraction using direct byte scanning.
    
    Searches for snmpTrapOID.0 marker and extracts the following OID.
    Avoids full packet parsing for common SNMPv2c traps.
    
    Args:
        payload: Raw SNMP packet bytes
        
    Returns:
        Trap OID string or None if not found
    """
    # Find snmpTrapOID.0 marker
    pos = payload.find(SNMPTRAPOID_MARKER)
    if pos == -1:
        return None
    
    pos += len(SNMPTRAPOID_MARKER)
    
    try:
        # Expect OID tag (0x06)
        if pos >= len(payload) or payload[pos] != ASN1_OID:
            return None
        pos += 1
        
        # Get OID length
        if pos >= len(payload):
            return None
        oid_len = payload[pos]
        
        # Handle long form length
        if oid_len & 0x80:
            num_octets = oid_len & 0x7F
            if pos + num_octets + 1 > len(payload):
                return None
            oid_len = 0
            for i in range(num_octets):
                oid_len = (oid_len << 8) | payload[pos + 1 + i]
            pos += num_octets + 1
        else:
            pos += 1
        
        # Extract and decode OID
        if pos + oid_len > len(payload):
            return None
        
        return decode_oid(payload[pos:pos + oid_len])
        
    except Exception:
        return None


def decode_oid(oid_bytes: bytes) -> str:
    """
    Decode OID from ASN.1 binary representation.
    
    ASN.1 OID encoding:
    - First byte encodes first two components: first * 40 + second
    - Subsequent components use 7-bit encoding with continuation bit
    
    Args:
        oid_bytes: Binary OID data
        
    Returns:
        Dotted string OID representation
    """
    if not oid_bytes:
        return ""
    
    # First byte encodes first two components
    first = oid_bytes[0]
    if first < 40:
        parts = [0, first]
    elif first < 80:
        parts = [1, first - 40]
    else:
        parts = [2, first - 80]
    
    # Decode remaining components (7-bit encoding)
    i = 1
    while i < len(oid_bytes):
        num = 0
        while i < len(oid_bytes):
            b = oid_bytes[i]
            num = (num << 7) | (b & 0x7F)
            i += 1
            if not (b & 0x80):  # No continuation bit
                break
        parts.append(num)
    
    return '.'.join(map(str, parts))


def encode_oid(oid_str: str) -> bytes:
    """
    Encode OID string to ASN.1 binary representation.
    
    Args:
        oid_str: Dotted string OID
        
    Returns:
        Binary OID data
    """
    parts = [int(p) for p in oid_str.split('.') if p]
    if len(parts) < 2:
        return b''
    
    result = bytearray()
    
    # First two components
    result.append(parts[0] * 40 + parts[1])
    
    # Remaining components
    for num in parts[2:]:
        if num == 0:
            result.append(0)
        else:
            # 7-bit encoding with continuation bit
            octets = []
            while num:
                octets.append(num & 0x7F)
                num >>= 7
            
            # Set continuation bit on all but last
            for i in range(len(octets) - 1):
                octets[i] |= 0x80
            
            result.extend(reversed(octets))
    
    return bytes(result)


# =============================================================================
# FULL PARSING (Slow path using Scapy)
# =============================================================================

def parse_snmp_packet(payload: bytes) -> Tuple[Optional[Any], Optional[str]]:
    """
    Parse SNMP packet using Scapy (slow path).
    
    Used when fast parsing fails or for non-SNMPv2c packets.
    
    Args:
        payload: Raw SNMP packet bytes
        
    Returns:
        Tuple of (parsed_packet, version_string) or (None, None)
    """
    try:
        from scapy.layers.snmp import SNMP
        
        VERSION_MAP = {0: "v1", 1: "v2c", 2: "v2", 3: "v3"}
        
        snmp = SNMP(payload)
        version = VERSION_MAP.get(snmp.version.val, "unknown")
        return snmp, version
        
    except Exception:
        pass
    
    # Try with offset scanning (for packets with leading bytes)
    try:
        from scapy.layers.snmp import SNMP
        
        for i in range(min(len(payload) - 4, 50)):
            if payload[i] == ASN1_SEQUENCE:
                try:
                    snmp = SNMP(payload[i:])
                    version = VERSION_MAP.get(snmp.version.val, "unknown")
                    return snmp, version
                except Exception:
                    continue
    except Exception:
        pass
    
    return None, None


def get_varbinds(packet) -> Dict[str, Any]:
    """
    Extract varbind dictionary from parsed SNMP packet.
    
    Args:
        packet: Parsed Scapy SNMP packet
        
    Returns:
        Dictionary mapping OID to value
    """
    try:
        if not hasattr(packet["SNMP"].PDU, "varbindlist"):
            return {}
        
        result = {}
        for vb in packet["SNMP"].PDU.varbindlist:
            try:
                oid = str(vb.oid.val)
                result[oid] = _convert_value(vb.value)
            except Exception:
                pass
        
        return result
        
    except Exception:
        return {}


def get_snmptrap_oid(packet) -> Optional[str]:
    """
    Extract snmpTrapOID from parsed packet.
    
    Args:
        packet: Parsed Scapy SNMP packet
        
    Returns:
        Trap OID string or None
    """
    varbinds = get_varbinds(packet)
    return varbinds.get("1.3.6.1.6.3.1.1.4.1.0")


def get_enterprise_oid(packet) -> Optional[str]:
    """
    Extract enterprise-specific OID from SNMPv1 trap.
    
    Args:
        packet: Parsed Scapy SNMP packet
        
    Returns:
        Enterprise OID or None
    """
    try:
        pdu = packet["SNMP"].PDU
        if hasattr(pdu, "enterprise") and hasattr(pdu, "specific_trap"):
            ent = str(pdu.enterprise.val).rstrip('.')
            spec = int(pdu.specific_trap.val)
            return f"{ent}.0.{spec}"
    except Exception:
        pass
    return None


def _convert_value(value) -> Any:
    """
    Convert ASN.1 value to Python type.
    
    Args:
        value: ASN.1 value from Scapy
        
    Returns:
        Python representation
    """
    try:
        name = value.__class__.__name__
        if 'INTEGER' in name:
            return int(value.val)
        elif 'STRING' in name or 'OID' in name:
            return str(value.val)
        elif 'NULL' in name:
            return None
        elif 'TIME' in name:
            return int(value.val)
        else:
            return str(value)
    except Exception:
        return str(value)
