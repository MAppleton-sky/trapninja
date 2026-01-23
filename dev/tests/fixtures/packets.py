#!/usr/bin/env python3
"""
TrapNinja Test Fixtures - SNMP Packet Builders

Functions for building valid SNMP packets for testing.
Includes proper ASN.1 BER encoding for OIDs.

Author: TrapNinja Team
"""

import struct


# =============================================================================
# ASN.1 BER ENCODING HELPERS
# =============================================================================

def encode_oid_component(num: int) -> bytes:
    """
    Encode a single OID component using ASN.1 BER encoding.
    
    ASN.1 BER uses 7-bit groups with continuation bit (0x80) on all 
    bytes EXCEPT the last byte.
    
    Args:
        num: The OID component value to encode
        
    Returns:
        Encoded bytes for this component
        
    Example:
        8072 -> [0xBF, 0x08]
        - 8072 = 63 * 128 + 8
        - First byte: 63 | 0x80 = 0xBF (continuation bit set)
        - Last byte: 8 = 0x08 (no continuation bit)
    """
    if num == 0:
        return bytes([0])
    
    # Build octets from least significant to most significant
    octets = []
    while num:
        octets.append(num & 0x7F)
        num >>= 7
    
    # Set continuation bit on all bytes except the last (which is first in our list)
    # After reversal, continuation bits should be on all but the final byte
    for i in range(1, len(octets)):
        octets[i] |= 0x80
    
    return bytes(reversed(octets))


def encode_oid(oid_string: str) -> bytes:
    """
    Encode an OID string to ASN.1 BER format.
    
    Args:
        oid_string: Dotted decimal OID string (e.g., "1.3.6.1.4.1.8072")
        
    Returns:
        ASN.1 BER encoded OID bytes
    """
    parts = [int(p) for p in oid_string.split('.')]
    
    # First two components are encoded specially
    result = bytearray([parts[0] * 40 + parts[1]])
    
    # Remaining components
    for num in parts[2:]:
        result.extend(encode_oid_component(num))
    
    return bytes(result)


# =============================================================================
# SNMP PACKET BUILDERS
# =============================================================================

def build_snmpv2c_trap(
    community: str = "public",
    trap_oid: str = "1.3.6.1.4.1.8072.2.3.0.1",
    request_id: int = 1,
    uptime: int = 1
) -> bytes:
    """
    Build a valid SNMPv2c trap packet.
    
    Args:
        community: SNMP community string
        trap_oid: The trap OID (snmpTrapOID.0 value)
        request_id: Request ID for the PDU
        uptime: System uptime in timeticks
        
    Returns:
        Complete SNMPv2c trap packet bytes
    """
    # Encode trap OID
    oid_bytes = bytearray(encode_oid(trap_oid))
    
    # snmpTrapOID.0 marker: 1.3.6.1.6.3.1.1.4.1.0
    snmptrapoid_marker = bytes([0x2b, 0x06, 0x01, 0x06, 0x03, 0x01, 0x01, 0x04, 0x01, 0x00])
    
    # VarBind for snmpTrapOID.0
    varbind_oid = bytes([
        0x30, len(snmptrapoid_marker) + 2 + len(oid_bytes) + 2,
        0x06, len(snmptrapoid_marker),
    ]) + snmptrapoid_marker + bytes([
        0x06, len(oid_bytes)
    ]) + bytes(oid_bytes)
    
    # sysUpTime.0 marker: 1.3.6.1.2.1.1.3.0
    sysuptime_oid = bytes([0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x03, 0x00])
    
    # VarBind for sysUpTime.0
    uptime_bytes = struct.pack('>I', uptime)
    varbind_uptime = bytes([
        0x30, len(sysuptime_oid) + 2 + len(uptime_bytes) + 2,
        0x06, len(sysuptime_oid),
    ]) + sysuptime_oid + bytes([
        0x43, len(uptime_bytes)
    ]) + uptime_bytes
    
    # VarBindList
    varbindlist = bytes([0x30, len(varbind_uptime) + len(varbind_oid)]) + varbind_uptime + varbind_oid
    
    # PDU content
    pdu_content = bytes([
        0x02, 0x04,  # INTEGER, length 4
    ]) + struct.pack('>I', request_id) + bytes([
        0x02, 0x01, 0x00,  # error-status = 0
        0x02, 0x01, 0x00,  # error-index = 0
    ]) + varbindlist
    
    # SNMPv2-Trap PDU (0xa7)
    pdu = bytes([0xa7, len(pdu_content)]) + pdu_content
    
    # Community string
    community_bytes = community.encode('ascii')
    community_field = bytes([0x04, len(community_bytes)]) + community_bytes
    
    # Version field (SNMPv2c = 1)
    version_field = bytes([0x02, 0x01, 0x01])
    
    # Complete message
    message_content = version_field + community_field + pdu
    message = bytes([0x30, len(message_content)]) + message_content
    
    return message


def build_snmpv1_trap(
    community: str = "public",
    enterprise_oid: str = "1.3.6.1.4.1.8072.2.3",
    generic_trap: int = 6,
    specific_trap: int = 1,
    agent_addr: str = "192.168.1.1"
) -> bytes:
    """
    Build a valid SNMPv1 trap packet.
    
    Args:
        community: SNMP community string
        enterprise_oid: Enterprise OID
        generic_trap: Generic trap type (0-6, 6=enterprise-specific)
        specific_trap: Specific trap code
        agent_addr: Agent IP address
        
    Returns:
        Complete SNMPv1 trap packet bytes
    """
    # Encode enterprise OID
    enterprise_bytes = encode_oid(enterprise_oid)
    
    # Agent address (4 bytes)
    addr_parts = [int(p) for p in agent_addr.split('.')]
    agent_addr_bytes = bytes(addr_parts)
    
    # VarBindList (empty for simplicity)
    varbindlist = bytes([0x30, 0x00])
    
    # PDU content
    pdu_content = bytes([
        0x06, len(enterprise_bytes)
    ]) + enterprise_bytes + bytes([
        0x40, 0x04  # NetworkAddress
    ]) + agent_addr_bytes + bytes([
        0x02, 0x01, generic_trap,    # generic-trap
        0x02, 0x01, specific_trap,   # specific-trap
        0x43, 0x01, 0x00             # time-stamp
    ]) + varbindlist
    
    # Trap PDU (0xa4)
    pdu = bytes([0xa4, len(pdu_content)]) + pdu_content
    
    # Community string
    community_bytes = community.encode('ascii')
    community_field = bytes([0x04, len(community_bytes)]) + community_bytes
    
    # Version field (SNMPv1 = 0)
    version_field = bytes([0x02, 0x01, 0x00])
    
    # Complete message
    message_content = version_field + community_field + pdu
    message = bytes([0x30, len(message_content)]) + message_content
    
    return message


def build_snmpv3_packet(
    msg_id: int = 1,
    msg_max_size: int = 65507,
    msg_flags: int = 0x04,  # reportableFlag
    security_model: int = 3  # USM
) -> bytes:
    """
    Build a minimal SNMPv3 packet structure.
    
    Note: This creates a minimal structure for version detection tests.
    Full SNMPv3 with encryption requires more complex setup.
    
    Args:
        msg_id: Message ID
        msg_max_size: Maximum message size
        msg_flags: Message flags byte
        security_model: Security model (3 = USM)
        
    Returns:
        Minimal SNMPv3 packet bytes
    """
    # msgGlobalData
    msg_global_data = bytes([
        0x30, 0x0e,
        0x02, 0x04  # msgID
    ]) + struct.pack('>I', msg_id) + bytes([
        0x02, 0x02  # msgMaxSize
    ]) + struct.pack('>H', msg_max_size) + bytes([
        0x04, 0x01, msg_flags,  # msgFlags
        0x02, 0x01, security_model  # msgSecurityModel
    ])
    
    # Minimal security parameters (empty for detection test)
    security_params = bytes([0x04, 0x00])
    
    # Minimal scoped PDU placeholder
    scoped_pdu = bytes([0x30, 0x00])
    
    # Version field (SNMPv3 = 3)
    version_field = bytes([0x02, 0x01, 0x03])
    
    # Complete message
    message_content = version_field + msg_global_data + security_params + scoped_pdu
    message = bytes([0x30, len(message_content)]) + message_content
    
    return message


def build_invalid_snmp_packet() -> bytes:
    """Build an invalid/malformed SNMP packet for error handling tests."""
    return bytes([0x30, 0x05, 0x02, 0x01, 0x99, 0x00, 0x00])


def build_non_snmp_packet() -> bytes:
    """Build a non-SNMP packet for filtering tests."""
    return b"This is not an SNMP packet at all"
