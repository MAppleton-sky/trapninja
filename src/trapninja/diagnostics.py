#!/usr/bin/env python3
"""
TrapNinja Diagnostics Module

Provides detailed packet inspection and diagnostic capabilities for
troubleshooting parsing failures.
"""

import logging
import binascii
import struct
from typing import Optional, Dict, Any
from scapy.all import SNMP

logger = logging.getLogger("trapninja")


def analyze_packet_structure(payload: bytes) -> Dict[str, Any]:
    """
    Perform deep analysis of packet structure to understand parsing failures.
    
    Args:
        payload: Raw packet payload bytes
        
    Returns:
        Dictionary containing diagnostic information
    """
    analysis = {
        'payload_length': len(payload),
        'first_20_bytes_hex': binascii.hexlify(payload[:20]).decode('ascii') if len(payload) >= 20 else binascii.hexlify(payload).decode('ascii'),
        'asn1_structure': None,
        'snmp_detection': {},
        'potential_issues': []
    }
    
    if len(payload) == 0:
        analysis['potential_issues'].append('Empty payload')
        return analysis
    
    # Check first byte for ASN.1 SEQUENCE tag (0x30)
    if payload[0] != 0x30:
        analysis['potential_issues'].append(f'Missing ASN.1 SEQUENCE tag (expected 0x30, got 0x{payload[0]:02x})')
    
    # Try to decode ASN.1 length field
    if len(payload) >= 2:
        length_byte = payload[1]
        if length_byte & 0x80:  # Long form
            num_length_bytes = length_byte & 0x7F
            if num_length_bytes > 0 and len(payload) >= 2 + num_length_bytes:
                try:
                    length_bytes = payload[2:2 + num_length_bytes]
                    declared_length = int.from_bytes(length_bytes, 'big')
                    analysis['asn1_structure'] = {
                        'length_encoding': 'long_form',
                        'declared_length': declared_length,
                        'actual_payload_length': len(payload) - 2 - num_length_bytes
                    }
                    
                    if declared_length != len(payload) - 2 - num_length_bytes:
                        analysis['potential_issues'].append(
                            f'Length mismatch: declared={declared_length}, actual={len(payload) - 2 - num_length_bytes}'
                        )
                except Exception as e:
                    analysis['potential_issues'].append(f'Failed to decode ASN.1 length: {e}')
        else:
            # Short form
            declared_length = length_byte
            analysis['asn1_structure'] = {
                'length_encoding': 'short_form',
                'declared_length': declared_length,
                'actual_payload_length': len(payload) - 2
            }
            
            if declared_length != len(payload) - 2:
                analysis['potential_issues'].append(
                    f'Length mismatch: declared={declared_length}, actual={len(payload) - 2}'
                )
    
    # Check for SNMP version field
    if len(payload) >= 5:
        analysis['snmp_detection']['has_version_field'] = (
            payload[2] == 0x02 and  # INTEGER tag
            payload[3] == 0x01      # Length = 1
        )
        
        if analysis['snmp_detection']['has_version_field']:
            version_byte = payload[4]
            version_map = {0: 'v1', 1: 'v2c', 2: 'v2', 3: 'v3'}
            analysis['snmp_detection']['version'] = version_map.get(version_byte, f'unknown(0x{version_byte:02x})')
        
        # Check for community string (OCTET STRING tag 0x04)
        if len(payload) >= 6:
            analysis['snmp_detection']['has_community_field'] = (payload[5] == 0x04)
            
            if analysis['snmp_detection']['has_community_field'] and len(payload) >= 7:
                community_length = payload[6]
                if len(payload) >= 7 + community_length:
                    try:
                        community = payload[7:7 + community_length].decode('ascii', errors='ignore')
                        analysis['snmp_detection']['community'] = community
                    except Exception:
                        analysis['snmp_detection']['community'] = '<non-ascii>'
    
    # Check for common corruption patterns
    if b'\x00' * 10 in payload:
        analysis['potential_issues'].append('Contains long sequence of null bytes')
    
    # Check for truncation
    if len(payload) < 20:
        analysis['potential_issues'].append('Payload suspiciously short for SNMP packet')
    
    return analysis


def log_parsing_failure(source_ip: str, payload: bytes, snmp_version: Optional[str] = None):
    """
    Log detailed information about a parsing failure.
    
    Args:
        source_ip: Source IP address of the problematic packet
        payload: Raw packet payload
        snmp_version: SNMP version if detectable, None otherwise
    """
    analysis = analyze_packet_structure(payload)
    
    logger.warning(f"=== Parsing Failure Analysis for {source_ip} ===")
    logger.warning(f"Payload Length: {analysis['payload_length']} bytes")
    logger.warning(f"First 20 bytes (hex): {analysis['first_20_bytes_hex']}")
    
    if snmp_version:
        logger.warning(f"Detected SNMP Version: {snmp_version}")
    
    if analysis['asn1_structure']:
        logger.warning(f"ASN.1 Structure: {analysis['asn1_structure']}")
    
    if analysis['snmp_detection']:
        logger.warning(f"SNMP Detection Results: {analysis['snmp_detection']}")
    
    if analysis['potential_issues']:
        logger.warning(f"Potential Issues:")
        for issue in analysis['potential_issues']:
            logger.warning(f"  - {issue}")
    
    logger.warning("==========================================")


def dump_packet_to_file(source_ip: str, payload: bytes, dump_dir: str = "/tmp/trapninja_dumps"):
    """
    Dump problematic packet to file for offline analysis.
    
    Args:
        source_ip: Source IP address
        payload: Raw packet payload
        dump_dir: Directory to save dump files
    """
    import os
    from datetime import datetime
    
    try:
        # Create dump directory if it doesn't exist
        os.makedirs(dump_dir, exist_ok=True)
        
        # Generate filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        filename = f"{dump_dir}/trap_{source_ip.replace('.', '_')}_{timestamp}.bin"
        
        # Write raw payload
        with open(filename, 'wb') as f:
            f.write(payload)
        
        # Write analysis text file
        analysis_filename = filename.replace('.bin', '.txt')
        analysis = analyze_packet_structure(payload)
        
        with open(analysis_filename, 'w') as f:
            f.write(f"Source IP: {source_ip}\n")
            f.write(f"Timestamp: {datetime.now().isoformat()}\n")
            f.write(f"Payload Length: {analysis['payload_length']} bytes\n\n")
            f.write(f"Hex Dump (first 200 bytes):\n")
            hex_dump = binascii.hexlify(payload[:200]).decode('ascii')
            for i in range(0, len(hex_dump), 32):
                f.write(f"  {hex_dump[i:i+32]}\n")
            f.write(f"\nASN.1 Structure: {analysis['asn1_structure']}\n")
            f.write(f"SNMP Detection: {analysis['snmp_detection']}\n")
            if analysis['potential_issues']:
                f.write(f"\nPotential Issues:\n")
                for issue in analysis['potential_issues']:
                    f.write(f"  - {issue}\n")
        
        logger.info(f"Packet dumped to {filename}")
        return filename
        
    except Exception as e:
        logger.error(f"Failed to dump packet: {e}")
        return None


def validate_snmp_basic_structure(payload: bytes) -> tuple[bool, Optional[str]]:
    """
    Perform basic validation of SNMP packet structure.
    
    Args:
        payload: Raw packet payload
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if len(payload) < 8:
        return False, f"Payload too short: {len(payload)} bytes (minimum 8 required)"
    
    # Check SEQUENCE tag
    if payload[0] != 0x30:
        return False, f"Invalid SEQUENCE tag: 0x{payload[0]:02x} (expected 0x30)"
    
    # Check INTEGER tag for version
    if payload[2] != 0x02:
        return False, f"Invalid INTEGER tag at position 2: 0x{payload[2]:02x} (expected 0x02)"
    
    # Check version field length
    if payload[3] != 0x01:
        return False, f"Invalid version field length: {payload[3]} (expected 1)"
    
    # Check version value (0=v1, 1=v2c, 3=v3)
    version = payload[4]
    if version not in [0, 1, 2, 3]:
        return False, f"Invalid SNMP version: {version}"
    
    # For v1 and v2c, check for community string
    if version in [0, 1]:
        if len(payload) < 6:
            return False, "Payload too short for community string"
        
        if payload[5] != 0x04:  # OCTET STRING tag
            return False, f"Invalid community string tag: 0x{payload[5]:02x} (expected 0x04)"
        
        community_length = payload[6]
        if len(payload) < 7 + community_length:
            return False, f"Payload too short for declared community length: {community_length}"
    
    return True, None


def suggest_parser_improvements(payload: bytes) -> list[str]:
    """
    Analyze packet and suggest potential parser improvements.
    
    Args:
        payload: Raw packet payload
        
    Returns:
        List of suggestions for parser improvements
    """
    suggestions = []
    analysis = analyze_packet_structure(payload)
    
    # Check for vendor-specific variations
    if len(payload) >= 10:
        # Check for non-standard OID prefixes
        if b'\x2b\x06\x01\x04\x01' in payload[:50]:  # 1.3.6.1.4.1 (enterprise OID)
            suggestions.append("Packet contains enterprise OID - may be vendor-specific format")
        
        # Check for unusual PDU types
        if b'\xa7' in payload[:30]:  # SNMPv2 Trap PDU
            suggestions.append("SNMPv2 Trap PDU detected - verify trap-specific parsing")
        elif b'\xa4' in payload[:30]:  # SNMPv1 Trap PDU
            suggestions.append("SNMPv1 Trap PDU detected - verify v1 trap parsing")
    
    # Check for encoding issues
    if analysis.get('potential_issues'):
        if any('Length mismatch' in issue for issue in analysis['potential_issues']):
            suggestions.append("ASN.1 length mismatch - may indicate truncation or padding issue")
    
    # Check for SNMPv3 encrypted packets
    if len(payload) >= 5 and payload[4] == 3:
        suggestions.append("SNMPv3 packet detected - may require decryption")
    
    return suggestions
