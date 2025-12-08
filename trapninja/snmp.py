#!/usr/bin/env python3
"""
TrapNinja SNMP Module - High-Performance Version 2.0

Optimized SNMP trap processing with minimal overhead:
- Fast OID extraction for SNMPv2c (direct byte scanning)
- Raw socket forwarding by default
- Minimal logging (summaries only)
- Cached configuration
- Integration with packet_processor module

Performance Target: 10,000+ traps/second
"""

import logging
import time
import struct
import socket
import threading
from typing import Optional, Tuple, List, Dict, Any
from scapy.all import IP, UDP, Raw
from scapy.layers.snmp import SNMP

from .config import LISTEN_PORTS
from .redirection import check_for_redirection
from .metrics import (
    increment_trap_received, increment_trap_forwarded,
    increment_blocked_ip, increment_blocked_oid,
    increment_redirected_ip, increment_redirected_oid
)

# Optional imports
try:
    from .diagnostics import log_parsing_failure, validate_snmp_basic_structure
    DIAGNOSTICS_AVAILABLE = True
except ImportError:
    DIAGNOSTICS_AVAILABLE = False
    def log_parsing_failure(*args, **kwargs): pass
    def validate_snmp_basic_structure(*args, **kwargs): return True, None

try:
    from .ha import is_forwarding_enabled, notify_trap_processed
except ImportError:
    def is_forwarding_enabled(): return True
    def notify_trap_processed(): pass

logger = logging.getLogger("trapninja")

# =============================================================================
# SNMP VERSION CONSTANTS
# =============================================================================

SNMP_VERSION_MAP = {0: "v1", 1: "v2c", 2: "v2", 3: "v3"}

# Pre-compiled byte patterns
_SNMPTRAPOID_MARKER = b'\x2b\x06\x01\x06\x03\x01\x01\x04\x01\x00'


# =============================================================================
# CONFIGURATION CACHE (Reduce import overhead)
# =============================================================================

class ConfigCache:
    """Thread-safe configuration cache with TTL"""
    
    def __init__(self, ttl: float = 30.0):
        self.ttl = ttl
        self._cache: Optional[Dict] = None
        self._cache_time: float = 0
        self._lock = threading.Lock()
    
    def get(self) -> Dict:
        now = time.time()
        
        # Fast path: cache is valid
        if self._cache and (now - self._cache_time) < self.ttl:
            return self._cache
        
        # Slow path: reload config
        with self._lock:
            # Double-check after acquiring lock
            if self._cache and (now - self._cache_time) < self.ttl:
                return self._cache
            
            from .config import (destinations, blocked_traps, blocked_dest, 
                                 blocked_ips, redirected_ips, redirected_oids,
                                 redirected_destinations)
            
            self._cache = {
                'destinations': destinations,
                'blocked_traps': blocked_traps,
                'blocked_dest': blocked_dest,
                'blocked_ips': blocked_ips,
                'redirected_ips': redirected_ips,
                'redirected_oids': redirected_oids,
                'redirected_destinations': redirected_destinations
            }
            self._cache_time = now
        
        return self._cache
    
    def invalidate(self):
        """Force cache reload on next access"""
        self._cache_time = 0


_config_cache = ConfigCache()


# =============================================================================
# PROCESSING STATISTICS (For periodic logging)
# =============================================================================

class ProcessingStats:
    """Lock-free processing statistics"""
    
    def __init__(self):
        self.received = 0
        self.forwarded = 0
        self.blocked = 0
        self.redirected = 0
        self.errors = 0
        self.fast_path_hits = 0
        self.slow_path_hits = 0
        self.last_log_time = time.time()
        self.log_interval = 60.0  # Log summary every 60 seconds
    
    def should_log(self) -> bool:
        now = time.time()
        if now - self.last_log_time >= self.log_interval:
            self.last_log_time = now
            return True
        return False
    
    def log_summary(self):
        if self.received > 0:
            fast_pct = (self.fast_path_hits / self.received) * 100
            logger.info(f"SNMP Stats: received={self.received}, "
                       f"forwarded={self.forwarded}, blocked={self.blocked}, "
                       f"redirected={self.redirected}, fast_path={fast_pct:.1f}%")


_stats = ProcessingStats()


# =============================================================================
# FAST OID EXTRACTION (Optimized for SNMPv2c)
# =============================================================================

def is_snmpv2c(payload: bytes) -> bool:
    """Ultra-fast SNMPv2c detection using byte signature"""
    return (len(payload) >= 8 and 
            payload[0] == 0x30 and  # SEQUENCE
            payload[2] == 0x02 and  # INTEGER (version)
            payload[3] == 0x01 and  # Length 1
            payload[4] == 0x01 and  # Version 1 (SNMPv2c)
            payload[5] == 0x04)     # OCTET STRING (community)


def extract_trap_oid_fast(payload: bytes) -> Optional[str]:
    """
    Fast OID extraction using direct byte scanning.
    
    Avoids full packet parsing for common SNMPv2c traps.
    Falls back to None for complex cases.
    """
    # Find snmpTrapOID.0 marker
    pos = payload.find(_SNMPTRAPOID_MARKER)
    if pos == -1:
        return None
    
    pos += len(_SNMPTRAPOID_MARKER)
    
    try:
        # Expect OID tag (0x06)
        if pos >= len(payload) or payload[pos] != 0x06:
            return None
        pos += 1
        
        # Get OID length
        if pos >= len(payload):
            return None
        oid_len = payload[pos]
        pos += 1
        
        # Extract and decode OID
        if pos + oid_len > len(payload):
            return None
        
        return _decode_oid(payload[pos:pos + oid_len])
        
    except Exception:
        return None


def _decode_oid(oid_bytes: bytes) -> str:
    """Decode OID from ASN.1 binary representation"""
    if not oid_bytes:
        return ""
    
    first = oid_bytes[0]
    parts = [first // 40, first % 40] if first < 80 else [2, first - 80]
    
    i = 1
    while i < len(oid_bytes):
        num = 0
        while i < len(oid_bytes):
            b = oid_bytes[i]
            num = (num << 7) | (b & 0x7F)
            i += 1
            if not (b & 0x80):
                break
        parts.append(num)
    
    return '.'.join(map(str, parts))


# =============================================================================
# RAW SOCKET FORWARDING
# =============================================================================

_raw_socket: Optional[socket.socket] = None
_raw_socket_lock = threading.Lock()
_raw_socket_available: Optional[bool] = None


def _init_raw_socket() -> bool:
    """Initialize raw socket for fast forwarding"""
    global _raw_socket, _raw_socket_available
    
    with _raw_socket_lock:
        if _raw_socket_available is not None:
            return _raw_socket_available
        
        try:
            _raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, 
                                        socket.IPPROTO_UDP)
            _raw_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            _raw_socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4194304)
            _raw_socket_available = True
            logger.info("Raw socket forwarding enabled")
            return True
        except (PermissionError, OSError) as e:
            _raw_socket_available = False
            logger.debug(f"Raw socket unavailable: {e}")
            return False


def _checksum(data: bytes) -> int:
    """Calculate IP header checksum"""
    if len(data) % 2:
        data += b'\x00'
    total = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def _build_packet(src_ip: str, dst_ip: str, src_port: int, 
                  dst_port: int, payload: bytes) -> bytes:
    """Build IP+UDP packet for raw socket"""
    # IP header
    ip_header = struct.pack(
        '!BBHHHBBH4s4s',
        0x45, 0, 20 + 8 + len(payload), 0, 0,
        64, 17, 0,
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip)
    )
    checksum = _checksum(ip_header)
    ip_header = ip_header[:10] + struct.pack('!H', checksum) + ip_header[12:]
    
    # UDP header
    udp_header = struct.pack('!HHHH', src_port, dst_port, 8 + len(payload), 0)
    
    return ip_header + udp_header + payload


def forward_packet(source_ip: str, payload: bytes, 
                   destinations: List[Tuple[str, int]]):
    """
    Forward packet to destinations using fastest available method.
    
    Priority:
    1. Raw socket (6-10x faster)
    2. Scapy (fallback)
    """
    if not destinations:
        return
    
    # Try raw socket first
    if _raw_socket_available != False:
        if _init_raw_socket():
            try:
                for dst_ip, dst_port in destinations:
                    pkt = _build_packet(source_ip, dst_ip, 162, dst_port, payload)
                    _raw_socket.sendto(pkt, (dst_ip, 0))
                return
            except Exception:
                pass
    
    # Fallback to Scapy
    _forward_scapy(source_ip, payload, destinations)


def _forward_scapy(source_ip: str, payload: bytes, 
                   destinations: List[Tuple[str, int]]):
    """Scapy-based forwarding (fallback)"""
    from scapy.all import send, get_if_list
    from .config import INTERFACE
    
    template = IP(src=source_ip) / UDP(sport=162)
    
    for dst_ip, dst_port in destinations:
        try:
            template[IP].dst = dst_ip
            template[UDP].dport = dst_port
            pkt = template / payload
            
            if INTERFACE in get_if_list():
                send(pkt, verbose=False, iface=INTERFACE)
            else:
                send(pkt, verbose=False)
        except Exception as e:
            logger.debug(f"Scapy forward error: {e}")


# =============================================================================
# SLOW PATH PARSING (For non-SNMPv2c or when fast path fails)
# =============================================================================

def try_parse_snmp(payload: bytes) -> Tuple[Optional[Any], Optional[str]]:
    """Parse SNMP packet using Scapy (slow path)"""
    try:
        snmp = SNMP(payload)
        version = SNMP_VERSION_MAP.get(snmp.version.val, "unknown")
        return snmp, version
    except Exception:
        pass
    
    # Try with offset scanning
    for i in range(min(len(payload) - 4, 50)):
        if payload[i] == 0x30:
            try:
                snmp = SNMP(payload[i:])
                version = SNMP_VERSION_MAP.get(snmp.version.val, "unknown")
                return snmp, version
            except Exception:
                continue
    
    return None, None


def get_varbind_dict(packet) -> Dict[str, Any]:
    """Extract varbind dictionary from parsed SNMP packet"""
    try:
        if not hasattr(packet["SNMP"].PDU, "varbindlist"):
            return {}
        
        result = {}
        for vb in packet["SNMP"].PDU.varbindlist:
            try:
                oid = str(vb.oid.val)
                result[oid] = str(vb.value)
            except Exception:
                pass
        return result
    except Exception:
        return {}


def get_snmptrap_oid(packet) -> Optional[str]:
    """Extract snmpTrapOID from parsed packet (slow path)"""
    return get_varbind_dict(packet).get("1.3.6.1.6.3.1.1.4.1.0")


def get_snmp_enterprise_specific(packet) -> Optional[str]:
    """Extract enterprise-specific OID from SNMPv1 trap"""
    try:
        pdu = packet["SNMP"].PDU
        if hasattr(pdu, "enterprise") and hasattr(pdu, "specific_trap"):
            ent = str(pdu.enterprise.val).rstrip('.')
            spec = int(pdu.specific_trap.val)
            return f"{ent}.0.{spec}"
    except Exception:
        pass
    return None


# =============================================================================
# SNMPv3 PROCESSING
# =============================================================================

def process_snmpv3(packet_data: Dict[str, Any]) -> bool:
    """Process SNMPv3 packet"""
    config = _config_cache.get()
    source_ip = packet_data['src_ip']
    payload = packet_data['payload']
    
    if source_ip in config['blocked_ips']:
        increment_blocked_ip(source_ip)
        return False
    
    # Try decryption
    try:
        from .snmpv3_decryption import get_snmpv3_decryptor
        decryptor = get_snmpv3_decryptor()
        if decryptor:
            result = decryptor.decrypt_snmpv3_trap(payload)
            if result:
                _, trap_data = result
                v2c_payload = decryptor.convert_to_snmpv2c(trap_data, "public")
                if v2c_payload:
                    forward_packet(source_ip, v2c_payload, config['destinations'])
                    increment_trap_forwarded()
                    notify_trap_processed()
                    return True
    except Exception:
        pass
    
    # Forward without decryption
    forward_packet(source_ip, payload, config['destinations'])
    increment_trap_forwarded()
    notify_trap_processed()
    return True


# =============================================================================
# MAIN PROCESSING FUNCTION
# =============================================================================

def process_captured_packet(packet_data: Dict[str, Any]):
    """
    Process captured packet with optimized fast/slow path selection.
    
    Fast path (SNMPv2c with direct OID extraction):
    - No full packet parsing
    - Minimal memory allocation
    - ~5-10x faster than slow path
    
    Slow path (all other cases):
    - Full Scapy parsing
    - Complete varbind extraction
    - Handles edge cases
    """
    # HA check
    if not is_forwarding_enabled():
        return
    
    increment_trap_received()
    _stats.received += 1
    
    config = _config_cache.get()
    source_ip = packet_data['src_ip']
    payload = packet_data['payload']
    
    # Quick IP block check (O(1) with set)
    if source_ip in config['blocked_ips']:
        increment_blocked_ip(source_ip)
        _stats.blocked += 1
        logger.debug(f"Blocked by IP: {source_ip}")
        return
    
    # === FAST PATH (SNMPv2c) ===
    trap_oid = None
    if is_snmpv2c(payload):
        trap_oid = extract_trap_oid_fast(payload)
        
        if trap_oid:
            _stats.fast_path_hits += 1
            
            # Check OID blocking
            if trap_oid in config['blocked_traps']:
                increment_blocked_oid(trap_oid)
                _stats.blocked += 1
                if config['blocked_dest']:
                    forward_packet(source_ip, payload, config['blocked_dest'])
                return
            
            # Check redirection
            is_redir, redir_dests, redir_tag = check_for_redirection(source_ip, trap_oid)
            if is_redir and redir_dests:
                forward_packet(source_ip, payload, redir_dests)
                _stats.redirected += 1
                if source_ip in config['redirected_ips']:
                    increment_redirected_ip(source_ip, redir_tag)
                else:
                    increment_redirected_oid(trap_oid, redir_tag)
                notify_trap_processed()
                return
            
            # Forward to normal destinations
            forward_packet(source_ip, payload, config['destinations'])
            increment_trap_forwarded()
            _stats.forwarded += 1
            notify_trap_processed()
            
            # Periodic logging
            if _stats.should_log():
                _stats.log_summary()
            
            return
    
    # === SLOW PATH ===
    _stats.slow_path_hits += 1
    
    snmp_packet, snmp_version = try_parse_snmp(payload)
    
    # Handle SNMPv3
    if snmp_version == "v3":
        process_snmpv3(packet_data)
        return
    
    # Parsing failed - forward anyway
    if not snmp_packet:
        if DIAGNOSTICS_AVAILABLE and logger.isEnabledFor(logging.DEBUG):
            is_valid, error = validate_snmp_basic_structure(payload)
            if not is_valid:
                logger.debug(f"Parse failure ({source_ip}): {error}")
        
        forward_packet(source_ip, payload, config['destinations'])
        increment_trap_forwarded()
        _stats.forwarded += 1
        notify_trap_processed()
        return
    
    # Extract OID using slow method
    if snmp_version == "v1":
        trap_oid = get_snmp_enterprise_specific(snmp_packet)
    else:
        trap_oid = get_snmptrap_oid(snmp_packet)
    
    if not trap_oid:
        forward_packet(source_ip, payload, config['destinations'])
        increment_trap_forwarded()
        _stats.forwarded += 1
        notify_trap_processed()
        return
    
    # Check redirection
    is_redir, redir_dests, redir_tag = check_for_redirection(source_ip, trap_oid)
    if is_redir and redir_dests:
        forward_packet(source_ip, payload, redir_dests)
        _stats.redirected += 1
        if source_ip in config['redirected_ips']:
            increment_redirected_ip(source_ip, redir_tag)
        else:
            increment_redirected_oid(trap_oid, redir_tag)
        notify_trap_processed()
        return
    
    # Check blocking
    if trap_oid in config['blocked_traps']:
        increment_blocked_oid(trap_oid)
        _stats.blocked += 1
        if config['blocked_dest']:
            forward_packet(source_ip, payload, config['blocked_dest'])
        return
    
    # Forward to normal destinations
    forward_packet(source_ip, payload, config['destinations'])
    increment_trap_forwarded()
    _stats.forwarded += 1
    notify_trap_processed()
    
    # Periodic logging
    if _stats.should_log():
        _stats.log_summary()


def forward_trap(packet):
    """Queue packet from Scapy capture for processing"""
    try:
        if not is_forwarding_enabled():
            return
        
        if packet.haslayer(IP) and packet.haslayer(UDP):
            if packet[UDP].dport in LISTEN_PORTS:
                packet_data = {
                    'src_ip': packet[IP].src,
                    'dst_port': packet[UDP].dport,
                    'payload': bytes(packet[UDP].payload)
                }
                
                from .network import packet_queue
                try:
                    packet_queue.put_nowait(packet_data)
                except Exception:
                    logger.debug("Queue full, dropping packet")
    except Exception as e:
        logger.debug(f"Error queuing packet: {e}")


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def convert_asn1_value(value) -> Any:
    """Convert ASN.1 value to Python type"""
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


def get_processing_stats() -> Dict[str, Any]:
    """Get current processing statistics"""
    return {
        'received': _stats.received,
        'forwarded': _stats.forwarded,
        'blocked': _stats.blocked,
        'redirected': _stats.redirected,
        'errors': _stats.errors,
        'fast_path_hits': _stats.fast_path_hits,
        'slow_path_hits': _stats.slow_path_hits,
        'fast_path_ratio': (_stats.fast_path_hits / max(_stats.received, 1)) * 100
    }
