#!/usr/bin/env python3
"""
TrapNinja SNMP Module - HA Enhanced Version

Handles SNMP packet processing with HA integration to ensure only
the active instance forwards traps.
"""
import logging
import functools
import time
import struct
import binascii
from scapy.all import IP, UDP, Raw
from scapy.layers.snmp import SNMP, SNMPtrapv2
import sys

from .config import LISTEN_PORTS
from .network import forward_packet
from .redirection import check_for_redirection
from .metrics import (
    increment_trap_received, increment_trap_forwarded,
    increment_blocked_ip, increment_blocked_oid,
    increment_redirected_ip, increment_redirected_oid
)

# Import HA functions
try:
    from .ha import is_forwarding_enabled, notify_trap_processed
except ImportError:
    # Fallback if HA module not available
    def is_forwarding_enabled():
        return True


    def notify_trap_processed():
        pass

# Get logger instance
logger = logging.getLogger("trapninja")

# SNMP version mapping
SNMP_VERSION_MAP = {
    0: "v1",
    1: "v2c",
    2: "v2",
    3: "v3"
}

# Cache for expensive operations
_varbind_cache = {}
_varbind_cache_expiry = {}
_varbind_cache_ttl = 300  # 5 minutes


def timed_cache(seconds=60):
    """
    Cache decorator with time-based expiration

    Args:
        seconds (int): Cache lifetime in seconds

    Returns:
        function: Decorated function with caching
    """

    def decorator(func):
        cache = {}
        timestamps = {}

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            key = str(args) + str(kwargs)

            # Check if key exists and is not expired
            now = time.time()
            if key in cache and now - timestamps[key] < seconds:
                return cache[key]

            # Execute function and cache result
            result = func(*args, **kwargs)
            cache[key] = result
            timestamps[key] = now

            # Clean old entries (basic garbage collection)
            expired_keys = [k for k, t in timestamps.items() if now - t > seconds]
            for k in expired_keys:
                if k in cache:
                    del cache[k]
                if k in timestamps:
                    del timestamps[k]

            return result

        # Add method to clear the cache
        wrapper.clear_cache = lambda: cache.clear() and timestamps.clear()

        return wrapper

    return decorator


def convert_asn1_value(value):
    """
    Convert ASN.1 value to a Python native type
    Optimized with type lookup table instead of if/elif chain

    Args:
        value: ASN.1 value to convert

    Returns:
        The converted Python native value
    """
    # Use a dictionary for faster lookup instead of if/elif chain
    try:
        class_name = value.__class__.__name__

        # Type conversion mapping
        type_converters = {
            'ASN1_INTEGER': lambda v: int(v.val),
            'ASN1_STRING': lambda v: str(v.val),
            'ASN1_PRINTABLE_STRING': lambda v: str(v.val),
            'ASN1_OCTET_STRING': lambda v: str(v.val),
            'ASN1_OID': lambda v: str(v.val),
            'ASN1_TIME_TICKS': lambda v: int(v.val),
            'ASN1_IP_ADDRESS': lambda v: str(v.val),
            'ASN1_NULL': lambda v: None
        }

        # Get converter or use default
        converter = type_converters.get(class_name, lambda v: str(v))

        return converter(value)
    except Exception:
        # Fallback to string representation
        return str(value)


def get_varbind_dict(packet):
    """
    Extract varbind dictionary from SNMP packet with proper type handling
    Optimized with caching and early bailout

    Args:
        packet: SNMP packet to extract varbinds from

    Returns:
        dict: Dictionary mapping OIDs to their values
    """
    # Use packet id as cache key
    packet_id = id(packet)

    # Check cache expiry
    now = time.time()
    expired_keys = [k for k, t in _varbind_cache_expiry.items()
                    if now - t > _varbind_cache_ttl]
    for k in expired_keys:
        if k in _varbind_cache:
            del _varbind_cache[k]
        if k in _varbind_cache_expiry:
            del _varbind_cache_expiry[k]

    # Check cache
    if packet_id in _varbind_cache:
        return _varbind_cache[packet_id]

    try:
        if not hasattr(packet["SNMP"].PDU, "varbindlist"):
            return {}

        varbinds = packet["SNMP"].PDU.varbindlist
        result = {}

        # Process varbinds efficiently
        for vb in varbinds:
            try:
                # Convert OID to string
                oid = str(vb.oid.val)

                # Convert value based on type using optimized function
                value = convert_asn1_value(vb.value)

                # Store in result dictionary
                result[oid] = value
            except Exception:
                # Single exception handler for entire loop iteration
                pass

        # Cache the result
        _varbind_cache[packet_id] = result
        _varbind_cache_expiry[packet_id] = now

        return result
    except Exception:
        # Global exception handler
        return {}


def get_snmp_enterprise_specific(packet):
    """
    Extract enterprise-specific OID from SNMPv1 trap
    Optimized with better error handling

    Args:
        packet: SNMPv1 trap packet

    Returns:
        str: Consolidated SNMPv2c-style trap OID or None if not found
    """
    try:
        pdu = packet["SNMP"].PDU

        if hasattr(pdu, "enterprise") and hasattr(pdu, "specific_trap"):
            # Extract raw values
            enterprise_oid = str(pdu.enterprise.val).rstrip('.')
            specific_trap = int(pdu.specific_trap.val)

            # Convert to SNMPv2c-style trap OID
            v2c_oid = f"{enterprise_oid}.0.{specific_trap}"

            logger.debug(f"SNMPv1 Enterprise: {enterprise_oid}, Specific: {specific_trap}")
            logger.debug(f"SNMPv2c Trap OID: {v2c_oid}")

            return v2c_oid
    except Exception as e:
        logger.debug(f"Failed to extract SNMPv1 trap info: {e}")

    return None


def get_snmptrap_oid(packet):
    """
    Extract snmpTrapOID from SNMPv2c trap
    Optimized to use varbind cache

    Args:
        packet: SNMPv2c trap packet

    Returns:
        str: The snmpTrapOID or None if not found
    """
    try:
        vb_map = get_varbind_dict(packet)
        trap_oid = vb_map.get("1.3.6.1.6.3.1.1.4.1.0")  # snmpTrapOID.0
        if trap_oid:
            return trap_oid
    except Exception as e:
        logger.debug(f"Failed to extract snmpTrapOID: {e}")

    return None


def manual_snmpv3_decode(payload):
    """
    Manually decode the initial part of an SNMPv3 message to extract key fields

    Args:
        payload (bytes): Raw packet payload data

    Returns:
        dict: SNMPv3 header information or None if parsing fails
    """
    try:
        # First byte of an SNMP message is always 0x30 (SEQUENCE)
        if not payload or payload[0] != 0x30:
            return None

        # Skip over the SEQUENCE header
        pos = 2  # Skip SEQUENCE tag and length byte

        # If length has long form, adjust position
        if payload[1] & 0x80:
            length_octets = payload[1] & 0x7F
            pos = 2 + length_octets

        # Parse version (INTEGER)
        if payload[pos] != 0x02:  # INTEGER tag
            return None

        pos += 1
        length = payload[pos]
        pos += 1

        if pos + length > len(payload):
            return None

        # Extract version number (should be 3 for SNMPv3)
        version = int.from_bytes(payload[pos:pos + length], byteorder='big')
        if version != 3:
            return None

        logger.debug(f"Manual SNMPv3 parsing: Found version {version}")

        # Skip to the msgSecurityModel field (fourth field in SNMPv3 header)
        pos += length  # Skip version

        # Skip HeaderData SEQUENCE
        if payload[pos] != 0x30:  # SEQUENCE tag
            return None

        pos += 1
        length = payload[pos]
        pos += 1 + length  # Skip HeaderData

        # Parse msgSecurityParameters (OCTET STRING)
        if pos >= len(payload) or payload[pos] != 0x04:  # OCTET STRING tag
            return None

        pos += 1
        length = payload[pos]
        pos += 1

        if pos + length > len(payload):
            return None

        # Extract security parameters (byte string)
        security_params = payload[pos:pos + length]

        # Look for user name inside security parameters
        for i in range(len(security_params) - 8):
            if security_params[i] == 0x04:  # OCTET STRING tag
                try:
                    str_len = security_params[i + 1]
                    if i + 2 + str_len <= len(security_params):
                        user_name = security_params[i + 2:i + 2 + str_len].decode('utf-8', errors='ignore')
                        if 3 <= len(user_name) <= 32 and user_name.isprintable():
                            logger.debug(f"Found possible SNMPv3 user name: {user_name}")
                            return {
                                'version': version,
                                'user': user_name,
                                'is_snmpv3': True
                            }
                except Exception:
                    continue

        # If we got here, it's likely SNMPv3 but we couldn't extract user name
        return {
            'version': version,
            'is_snmpv3': True
        }
    except Exception as e:
        logger.debug(f"Manual SNMPv3 parsing failed: {e}")
        return None


def detect_snmp_version(payload):
    """
    Attempt to detect SNMP version from raw payload

    Args:
        payload (bytes): Raw packet payload

    Returns:
        str: SNMP version string or None if not detected
    """
    try:
        # Look for SNMP version field (usually within first 10-20 bytes)
        # SNMP version field is typically at a fixed position: 0x30, len, 0x02, 0x01, version
        if not payload or len(payload) < 5:
            return None

        # Try to find sequence start
        if payload[0] != 0x30:  # SEQUENCE tag
            # Try to find SEQUENCE tag within first few bytes
            for i in range(1, min(10, len(payload))):
                if payload[i] == 0x30:
                    payload = payload[i:]
                    break
            else:
                return None  # No SEQUENCE tag found

        # Skip SEQUENCE header (variable length)
        pos = 2

        # If length has long form, adjust position
        if payload[1] & 0x80:
            length_octets = payload[1] & 0x7F
            pos = 2 + length_octets

        # Check for INTEGER tag
        if pos < len(payload) and payload[pos] == 0x02:
            pos += 1

            # Check length of INTEGER
            if pos < len(payload):
                int_len = payload[pos]
                pos += 1

                # Check if we have enough bytes
                if pos + int_len <= len(payload):
                    # Extract version number
                    version = 0
                    for i in range(int_len):
                        version = (version << 8) | payload[pos + i]

                    # Map to version string
                    if version in SNMP_VERSION_MAP:
                        logger.debug(f"Detected SNMP version: {SNMP_VERSION_MAP[version]}")
                        return SNMP_VERSION_MAP[version]

        # Check for SNMPv3 specifically using manual decoder
        v3_info = manual_snmpv3_decode(payload)
        if v3_info and v3_info.get('is_snmpv3'):
            logger.debug("Detected SNMPv3 using manual decoder")
            return "v3"

        return None
    except Exception as e:
        logger.debug(f"SNMP version detection failed: {e}")
        return None


def process_snmpv3(packet_data):
    """
    Process SNMPv3 packet with HA awareness and decryption support
    Optimized for extracted packet data

    Args:
        packet_data (dict): Dictionary with packet data

    Returns:
        bool: True if successful, False otherwise
    """
    # Check if HA allows forwarding
    if not is_forwarding_enabled():
        logger.debug("SNMPv3 trap captured but forwarding disabled by HA")
        return False

    # Import here to ensure we get the latest values
    from .config import destinations, blocked_ips

    source_ip = packet_data['src_ip']
    payload = packet_data['payload']

    # Check if source IP is blocked
    if source_ip in blocked_ips:
        logger.info(f"SNMPv3 trap from {source_ip} blocked due to IP filtering")
        # Track blocked IP metrics
        increment_blocked_ip(source_ip)
        return False

    logger.info(f"SNMPv3 trap received from {source_ip}")

    # Try to decrypt and convert to SNMPv2c
    try:
        from .snmpv3_decryption import get_snmpv3_decryptor
        
        decryptor = get_snmpv3_decryptor()
        if decryptor:
            logger.debug("Attempting SNMPv3 decryption")
            
            # Try to decrypt the trap
            result = decryptor.decrypt_snmpv3_trap(payload)
            
            if result:
                engine_id, trap_data = result
                logger.info(f"Successfully decrypted SNMPv3 trap from engine {engine_id}")
                
                # Convert to SNMPv2c
                snmpv2c_payload = decryptor.convert_to_snmpv2c(trap_data, community="public")
                
                if snmpv2c_payload:
                    logger.info(f"Converted SNMPv3 trap to SNMPv2c format")
                    
                    # Forward the converted trap
                    logger.debug(f"Forwarding converted trap to destinations: {destinations}")
                    forward_packet(source_ip, snmpv2c_payload, destinations)
                    # Track forwarded trap metrics
                    increment_trap_forwarded()
                    # Notify HA system
                    notify_trap_processed()
                    return True
                else:
                    logger.warning("Failed to convert decrypted trap to SNMPv2c")
            else:
                logger.debug("Could not decrypt SNMPv3 trap - no matching credentials")
        else:
            logger.debug("SNMPv3 decryptor not initialized")
    except Exception as e:
        logger.debug(f"SNMPv3 decryption/conversion error: {e}")

    # If decryption failed or not configured, forward as-is
    logger.info(f"Forwarding SNMPv3 trap without decryption")
    
    try:
        # Forward to all destinations
        logger.debug(f"Forwarding SNMPv3 trap to destinations: {destinations}")
        forward_packet(source_ip, payload, destinations)
        # Track forwarded trap metrics
        increment_trap_forwarded()
        # Notify HA system
        notify_trap_processed()
        return True
    except Exception as e:
        logger.error(f"Error forwarding SNMPv3 trap: {e}")
        return False


def try_parse_snmp(payload):
    """
    Try multiple methods to parse SNMP from payload

    Args:
        payload (bytes): Raw packet payload data

    Returns:
        tuple: (snmp_packet, version_str) or (None, None) if parsing fails
    """
    try:
        # Try direct parsing first
        snmp_packet = SNMP(payload)
        raw_ver = snmp_packet.version.val
        snmp_version = SNMP_VERSION_MAP.get(raw_ver, f"unknown({raw_ver})")
        logger.debug(f"Successfully parsed SNMP packet (version {snmp_version})")
        return snmp_packet, snmp_version
    except Exception as e1:
        logger.debug(f"Direct SNMP parsing failed: {e1}")

        # Log sample of the raw data for debugging
        if payload and len(payload) > 0:
            hex_sample = binascii.hexlify(payload[:min(32, len(payload))]).decode()
            logger.debug(f"Payload sample (hex): {hex_sample}")

        try:
            # Try wrapping in IP/UDP layers to help with parsing
            dummy_packet = IP(src="1.1.1.1", dst="2.2.2.2") / UDP(sport=161, dport=162) / Raw(payload)
            if dummy_packet.haslayer(SNMP):
                snmp_packet = dummy_packet[SNMP]
                raw_ver = snmp_packet.version.val
                snmp_version = SNMP_VERSION_MAP.get(raw_ver, f"unknown({raw_ver})")
                logger.debug(f"Parsed SNMP using dummy packet (version {snmp_version})")
                return snmp_packet, snmp_version
        except Exception as e2:
            logger.debug(f"Dummy packet parsing failed: {e2}")

        try:
            # Try removing potential extra headers (e.g., if from raw socket)
            # Look for SNMP sequence tag (0x30) - common in SNMP packets
            # Skip any irrelevant data before the SNMP packet
            for i in range(min(len(payload) - 4, 100)):  # Only scan first 100 bytes for performance
                # Look for SEQUENCE tag followed by length
                if payload[i] == 0x30:
                    try:
                        # Try parsing from this position
                        snmp_packet = SNMP(payload[i:])
                        raw_ver = snmp_packet.version.val
                        snmp_version = SNMP_VERSION_MAP.get(raw_ver, f"unknown({raw_ver})")
                        logger.debug(f"Parsed SNMP with offset {i} (version {snmp_version})")
                        return snmp_packet, snmp_version
                    except Exception:
                        # Try next position
                        continue
        except Exception as e3:
            logger.debug(f"Offset search parsing failed: {e3}")

        # Try to at least identify the SNMP version, even if we can't fully parse
        snmp_version = detect_snmp_version(payload)
        if snmp_version:
            logger.debug(f"Detected SNMP version {snmp_version} but couldn't fully parse")
            return None, snmp_version

    # All parsing methods failed
    return None, None


def process_captured_packet(packet_data):
    """
    Process a captured packet from the packet queue with HA awareness
    This function is called by the packet processing workers
    Enhanced with better error handling for different capture methods

    Args:
        packet_data (dict): Dictionary with packet data including src_ip, dst_port, and payload
    """
    # Check if HA allows forwarding first (fast check)
    if not is_forwarding_enabled():
        logger.debug("Packet captured but forwarding disabled by HA")
        return

    # Import here to ensure we get the latest values
    from .config import blocked_traps, destinations, blocked_dest, blocked_ips
    from .config import redirected_ips, redirected_oids

    # Track received trap metrics
    increment_trap_received()

    source_ip = packet_data['src_ip']

    # Check if source IP is in the blocked IPs list (quick early check)
    if source_ip in blocked_ips:
        logger.info(f"Packet from {source_ip} blocked due to IP filtering")
        # Track blocked IP metrics
        increment_blocked_ip(source_ip)
        return

    payload = packet_data['payload']

    # Log the packet capture
    logger.debug(f"Processing packet from {source_ip} to port {packet_data.get('dst_port')}, {len(payload)} bytes")

    # Try multiple methods to parse as SNMP
    snmp_packet, snmp_version = try_parse_snmp(payload)

    # Handle the case where we detected SNMPv3 but couldn't fully parse it
    if not snmp_packet and snmp_version == "v3":
        logger.info(f"Detected SNMPv3 trap from {source_ip} (manual detection)")
        process_snmpv3(packet_data)
        return

    if not snmp_packet:
        # If we can't parse as SNMP, forward as-is (if HA allows)
        logger.warning(f"Could not parse packet as SNMP from {source_ip}, forwarding as-is")
        forward_packet(source_ip, payload, destinations)
        # Track forwarded trap metrics
        increment_trap_forwarded()
        # Notify HA system
        notify_trap_processed()
        return

    logger.info(f"Received SNMP {snmp_version} trap from {source_ip}")

    # Special handling for SNMPv3
    if snmp_version == "v3":
        process_snmpv3(packet_data)
        return

    # Process SNMPv1 and SNMPv2c traps
    trap_oid_str = None
    if snmp_version == "v1":
        logger.info("SNMP v1 Trap detected")
        trap_oid_str = get_snmp_enterprise_specific(snmp_packet)
    elif snmp_version == "v2c":
        logger.info("SNMP v2c Trap detected")
        trap_oid_str = get_snmptrap_oid(snmp_packet)

    if not trap_oid_str:
        # Forward anyway as we don't have filtering criteria
        logger.warning(f"Could not determine trap OID from {source_ip}")
        forward_packet(source_ip, payload, destinations)
        # Track forwarded trap metrics
        increment_trap_forwarded()
        # Notify HA system
        notify_trap_processed()
        return

    logger.info(f"Trap OID: {trap_oid_str}")

    # Check for redirection with cached lookup
    is_redirected, redirection_destinations, redirection_tag = check_for_redirection(source_ip, trap_oid_str)

    if is_redirected and redirection_destinations:
        logger.info(f"Redirecting trap to '{redirection_tag}' group")
        forward_packet(source_ip, payload, redirection_destinations)
        # Track redirected trap metrics based on whether it was IP or OID-based
        if source_ip in redirected_ips:
            increment_redirected_ip(source_ip, redirection_tag)
        elif trap_oid_str and trap_oid_str in redirected_oids:
            increment_redirected_oid(trap_oid_str, redirection_tag)
        # Notify HA system
        notify_trap_processed()
        return

    # Check if trap should be blocked (fast lookup with set)
    if trap_oid_str in blocked_traps:
        logger.info(f"Trap from {source_ip} blocked by OID filter: {trap_oid_str}")
        # Track blocked OID metrics
        increment_blocked_oid(trap_oid_str)
        # Forward to blocked destination if configured
        if blocked_dest:
            forward_packet(source_ip, payload, blocked_dest)
        return

    # Default case: forward to normal destinations
    logger.info(f"Forwarding allowed trap from {source_ip} with OID {trap_oid_str}")
    forward_packet(source_ip, payload, destinations)
    # Track forwarded trap metrics
    increment_trap_forwarded()
    # Notify HA system
    notify_trap_processed()


def forward_trap(packet):
    """
    HA-aware queuing function for packet processing from traditional capture
    Captures the packet data and puts it in the processing queue only if HA allows

    Args:
        packet: Scapy packet from sniff function
    """
    from .config import LISTEN_PORTS

    try:
        # Check if HA allows forwarding first
        if not is_forwarding_enabled():
            logger.debug("Packet captured but forwarding disabled by HA")
            return

        # Only queue if we have IP and UDP layers
        if packet.haslayer(IP) and packet.haslayer(UDP):
            # Check if destination port is one we're listening on (quick check)
            if packet[UDP].dport in LISTEN_PORTS:
                # Copy only what we need to reduce memory usage
                packet_data = {
                    'src_ip': packet[IP].src,
                    'dst_port': packet[UDP].dport,
                    'payload': bytes(packet[UDP].payload)
                }

                # Put in queue for processing by worker threads
                from .network import packet_queue
                try:
                    packet_queue.put(packet_data, block=False)
                except Exception:
                    logger.warning("Packet processing queue full, dropping packet")
    except Exception as e:
        logger.error(f"Error queuing packet: {e}")