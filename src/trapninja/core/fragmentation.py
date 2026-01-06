#!/usr/bin/env python3
"""
TrapNinja IP Fragment Reassembly Module

Provides IP fragment reassembly for SNMP traps that exceed MTU.
Essential for sniff mode where the kernel doesn't reassemble for us.

Background:
-----------
When an SNMP trap exceeds the network MTU (typically 1500 bytes), IP fragmentation
occurs. The Linux kernel handles reassembly automatically for socket-based capture,
but when using raw packet capture (sniff mode), we see individual fragments:

  Fragment 1: [IP Header (offset=0, MF=1)] [UDP Header] [SNMP data part 1]
  Fragment 2: [IP Header (offset>0)]       [NO UDP HDR] [SNMP data continuation]
  Fragment 3: [IP Header (offset>0, MF=0)] [NO UDP HDR] [SNMP data end]

The standard BPF filter "udp dst port 162" only matches Fragment 1 because
subsequent fragments don't have a UDP header - the protocol information was
only in the first fragment.

Solution:
---------
This module provides:
1. A fragment-aware BPF filter that captures all fragments
2. A reassembly buffer that collects and reassembles fragments
3. Integration with the capture pipeline

Usage:
------
    from trapninja.core.fragmentation import (
        FragmentReassemblyBuffer,
        generate_fragment_aware_filter,
        parse_ip_header,
    )
    
    # Create reassembly buffer
    buffer = FragmentReassemblyBuffer(timeout_seconds=5.0, max_buffer_mb=100)
    
    # Generate BPF filter
    bpf = generate_fragment_aware_filter([162], exclude_sport=10162)
    
    # Process packets
    def packet_handler(packet):
        result = buffer.process_packet(packet)
        if result:
            # Complete packet ready for processing
            process_trap(result)

Author: TrapNinja Team
Version: 1.0.0
"""

import time
import struct
import logging
import threading
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any
from collections import OrderedDict

logger = logging.getLogger("trapninja")


# =============================================================================
# IP FRAGMENT PARSING
# =============================================================================

@dataclass
class IPFragment:
    """Represents a single IP fragment."""
    src_ip: str
    dst_ip: str
    protocol: int
    ip_id: int
    offset: int          # Offset in 8-byte units
    more_fragments: bool # MF flag
    data: bytes          # Fragment payload (after IP header)
    timestamp: float = field(default_factory=time.time)
    
    @property
    def byte_offset(self) -> int:
        """Get offset in bytes (offset field is in 8-byte units)."""
        return self.offset * 8
    
    @property
    def is_first(self) -> bool:
        """Check if this is the first fragment."""
        return self.offset == 0
    
    @property
    def is_last(self) -> bool:
        """Check if this is the last fragment (MF=0)."""
        return not self.more_fragments


def parse_ip_header(raw_bytes: bytes) -> Optional[IPFragment]:
    """
    Parse IP header and extract fragment information.
    
    Args:
        raw_bytes: Raw IP packet bytes (starting with IP header)
        
    Returns:
        IPFragment if valid IP packet, None otherwise
    """
    if len(raw_bytes) < 20:
        return None
    
    try:
        # Version and IHL (Internet Header Length)
        version_ihl = raw_bytes[0]
        version = (version_ihl >> 4) & 0x0F
        ihl = (version_ihl & 0x0F) * 4  # Header length in bytes
        
        if version != 4:
            return None  # Only IPv4 supported
        
        if len(raw_bytes) < ihl:
            return None
        
        # Total length
        total_length = struct.unpack('!H', raw_bytes[2:4])[0]
        
        # Identification
        ip_id = struct.unpack('!H', raw_bytes[4:6])[0]
        
        # Flags and Fragment Offset
        flags_offset = struct.unpack('!H', raw_bytes[6:8])[0]
        
        # Flags: bit 0 = reserved, bit 1 = DF (Don't Fragment), bit 2 = MF (More Fragments)
        # Note: These are in the HIGH 3 bits of the first byte
        df_flag = bool(flags_offset & 0x4000)  # Don't fragment
        mf_flag = bool(flags_offset & 0x2000)  # More fragments
        
        # Fragment offset is in the lower 13 bits (in 8-byte units)
        frag_offset = flags_offset & 0x1FFF
        
        # Protocol
        protocol = raw_bytes[9]
        
        # Source and Destination IP
        src_ip = '.'.join(str(b) for b in raw_bytes[12:16])
        dst_ip = '.'.join(str(b) for b in raw_bytes[16:20])
        
        # Extract payload (everything after IP header)
        # For fragments, we need everything after the IP header
        payload = raw_bytes[ihl:]
        
        return IPFragment(
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=protocol,
            ip_id=ip_id,
            offset=frag_offset,
            more_fragments=mf_flag,
            data=payload,
        )
        
    except Exception as e:
        logger.debug(f"Failed to parse IP header: {e}")
        return None


def is_fragment(raw_bytes: bytes) -> bool:
    """
    Quick check if packet is an IP fragment.
    
    Args:
        raw_bytes: Raw IP packet bytes
        
    Returns:
        True if packet is fragmented (MF=1 or offset>0)
    """
    if len(raw_bytes) < 8:
        return False
    
    try:
        flags_offset = struct.unpack('!H', raw_bytes[6:8])[0]
        mf_flag = bool(flags_offset & 0x2000)
        frag_offset = flags_offset & 0x1FFF
        return mf_flag or frag_offset > 0
    except Exception:
        return False


def is_udp_fragment(raw_bytes: bytes) -> bool:
    """
    Check if packet is a UDP fragment.
    
    Args:
        raw_bytes: Raw IP packet bytes
        
    Returns:
        True if packet is a fragmented UDP packet
    """
    if len(raw_bytes) < 10:
        return False
    
    try:
        protocol = raw_bytes[9]
        return protocol == 17 and is_fragment(raw_bytes)  # 17 = UDP
    except Exception:
        return False


# =============================================================================
# FRAGMENT REASSEMBLY BUFFER
# =============================================================================

@dataclass
class FragmentedDatagram:
    """Tracks fragments for a single datagram being reassembled."""
    key: Tuple[str, str, int, int]  # (src_ip, dst_ip, protocol, ip_id)
    fragments: Dict[int, bytes]      # offset -> data
    total_length: Optional[int]      # Set when last fragment received
    first_seen: float
    last_update: float
    bytes_received: int
    
    def add_fragment(self, fragment: IPFragment):
        """Add a fragment to this datagram."""
        byte_offset = fragment.byte_offset
        self.fragments[byte_offset] = fragment.data
        self.bytes_received += len(fragment.data)
        self.last_update = time.time()
        
        # If this is the last fragment (MF=0), we can calculate total length
        if fragment.is_last:
            self.total_length = byte_offset + len(fragment.data)
    
    def is_complete(self) -> bool:
        """Check if all fragments have been received."""
        if self.total_length is None:
            return False
        
        # Check for contiguous data from 0 to total_length
        current_offset = 0
        for offset in sorted(self.fragments.keys()):
            if offset != current_offset:
                return False  # Gap in fragments
            current_offset += len(self.fragments[offset])
        
        return current_offset == self.total_length
    
    def reassemble(self) -> Optional[bytes]:
        """Reassemble fragments into complete datagram."""
        if not self.is_complete():
            return None
        
        # Concatenate fragments in order
        result = bytearray()
        for offset in sorted(self.fragments.keys()):
            result.extend(self.fragments[offset])
        
        return bytes(result)


class FragmentReassemblyBuffer:
    """
    Thread-safe IP fragment reassembly buffer.
    
    Collects IP fragments and reassembles them into complete datagrams.
    Includes timeout and memory limits to prevent resource exhaustion.
    
    Attributes:
        timeout_seconds: Maximum time to wait for all fragments
        max_buffer_bytes: Maximum total memory for buffered fragments
        max_datagrams: Maximum number of incomplete datagrams to track
    """
    
    def __init__(
        self,
        timeout_seconds: float = 5.0,
        max_buffer_mb: float = 100.0,
        max_datagrams: int = 10000,
        cleanup_interval: float = 1.0,
    ):
        """
        Initialize reassembly buffer.
        
        Args:
            timeout_seconds: Time to wait for all fragments (default: 5s)
            max_buffer_mb: Maximum buffer size in megabytes (default: 100MB)
            max_datagrams: Maximum incomplete datagrams to track (default: 10000)
            cleanup_interval: Interval for cleanup thread (default: 1s)
        """
        self.timeout_seconds = timeout_seconds
        self.max_buffer_bytes = int(max_buffer_mb * 1024 * 1024)
        self.max_datagrams = max_datagrams
        self.cleanup_interval = cleanup_interval
        
        # Use OrderedDict for LRU eviction
        self._datagrams: OrderedDict[Tuple, FragmentedDatagram] = OrderedDict()
        self._lock = threading.RLock()
        self._current_bytes = 0
        
        # Statistics
        self._stats = {
            'fragments_received': 0,
            'datagrams_completed': 0,
            'datagrams_timeout': 0,
            'datagrams_evicted': 0,
            'bytes_reassembled': 0,
            'current_datagrams': 0,
            'current_bytes': 0,
        }
        
        # Cleanup thread
        self._stop_event = threading.Event()
        self._cleanup_thread = threading.Thread(
            target=self._cleanup_loop,
            daemon=True,
            name="FragmentCleanup"
        )
        self._cleanup_thread.start()
    
    def add_fragment(self, fragment: IPFragment) -> Optional[bytes]:
        """
        Add a fragment to the buffer.
        
        Args:
            fragment: Parsed IP fragment
            
        Returns:
            Complete reassembled payload if all fragments received, None otherwise
        """
        key = (fragment.src_ip, fragment.dst_ip, fragment.protocol, fragment.ip_id)
        
        with self._lock:
            self._stats['fragments_received'] += 1
            
            # Check if we have an existing datagram for this key
            if key in self._datagrams:
                datagram = self._datagrams[key]
                # Move to end for LRU
                self._datagrams.move_to_end(key)
            else:
                # Check limits before creating new datagram
                self._enforce_limits()
                
                datagram = FragmentedDatagram(
                    key=key,
                    fragments={},
                    total_length=None,
                    first_seen=time.time(),
                    last_update=time.time(),
                    bytes_received=0,
                )
                self._datagrams[key] = datagram
            
            # Track bytes for memory limit
            old_bytes = datagram.bytes_received
            
            # Add the fragment
            datagram.add_fragment(fragment)
            
            # Update byte count
            self._current_bytes += (datagram.bytes_received - old_bytes)
            self._stats['current_bytes'] = self._current_bytes
            self._stats['current_datagrams'] = len(self._datagrams)
            
            # Check if complete
            if datagram.is_complete():
                result = datagram.reassemble()
                if result:
                    self._stats['datagrams_completed'] += 1
                    self._stats['bytes_reassembled'] += len(result)
                    
                    # Remove from buffer
                    self._current_bytes -= datagram.bytes_received
                    del self._datagrams[key]
                    
                    self._stats['current_bytes'] = self._current_bytes
                    self._stats['current_datagrams'] = len(self._datagrams)
                    
                    return result
        
        return None
    
    def process_packet(self, packet) -> Optional[Dict[str, Any]]:
        """
        Process a Scapy packet, handling fragments if necessary.
        
        Args:
            packet: Scapy packet (may be complete or fragment)
            
        Returns:
            Dict with packet info if ready for processing, None if still waiting
        """
        try:
            from scapy.all import IP, UDP, Raw
            
            if not packet.haslayer(IP):
                return None
            
            ip_layer = packet[IP]
            
            # Check if this is a fragment
            # MF (More Fragments) flag or fragment offset > 0
            is_frag = (ip_layer.flags.MF) or (ip_layer.frag > 0)
            
            if not is_frag:
                # Complete packet - pass through
                if packet.haslayer(UDP):
                    return {
                        'src_ip': ip_layer.src,
                        'dst_port': packet[UDP].dport,
                        'payload': bytes(packet[UDP].payload),
                        'fragmented': False,
                    }
                return None
            
            # This is a fragment - parse and add to buffer
            fragment = IPFragment(
                src_ip=ip_layer.src,
                dst_ip=ip_layer.dst,
                protocol=ip_layer.proto,
                ip_id=ip_layer.id,
                offset=ip_layer.frag,
                more_fragments=bool(ip_layer.flags.MF),
                data=bytes(ip_layer.payload),
            )
            
            # Try to reassemble
            reassembled = self.add_fragment(fragment)
            
            if reassembled:
                # We have the complete payload - extract UDP info
                # The first 8 bytes are the UDP header
                if len(reassembled) >= 8 and fragment.protocol == 17:  # UDP
                    src_port = struct.unpack('!H', reassembled[0:2])[0]
                    dst_port = struct.unpack('!H', reassembled[2:4])[0]
                    udp_payload = reassembled[8:]  # Skip UDP header
                    
                    return {
                        'src_ip': fragment.src_ip,
                        'dst_port': dst_port,
                        'payload': udp_payload,
                        'fragmented': True,
                        'fragment_count': len([k for k in self._datagrams.keys() 
                                               if k[:3] == fragment.key[:3]]) + 1,
                    }
            
            return None
            
        except Exception as e:
            logger.debug(f"Error processing packet for reassembly: {e}")
            return None
    
    def _enforce_limits(self):
        """Enforce memory and count limits by evicting oldest entries."""
        # Evict if too many datagrams
        while len(self._datagrams) >= self.max_datagrams:
            self._evict_oldest()
        
        # Evict if too much memory
        while self._current_bytes > self.max_buffer_bytes and self._datagrams:
            self._evict_oldest()
    
    def _evict_oldest(self):
        """Evict the oldest datagram (LRU)."""
        if not self._datagrams:
            return
        
        # Get oldest (first item in OrderedDict)
        key = next(iter(self._datagrams))
        datagram = self._datagrams.pop(key)
        
        self._current_bytes -= datagram.bytes_received
        self._stats['datagrams_evicted'] += 1
        self._stats['current_bytes'] = self._current_bytes
        self._stats['current_datagrams'] = len(self._datagrams)
        
        logger.debug(f"Evicted fragment buffer for {key} ({datagram.bytes_received} bytes)")
    
    def _cleanup_loop(self):
        """Background thread to clean up timed-out fragments."""
        while not self._stop_event.wait(self.cleanup_interval):
            self._cleanup_expired()
    
    def _cleanup_expired(self):
        """Remove timed-out incomplete datagrams."""
        now = time.time()
        expired_keys = []
        
        with self._lock:
            for key, datagram in self._datagrams.items():
                if now - datagram.first_seen > self.timeout_seconds:
                    expired_keys.append(key)
            
            for key in expired_keys:
                datagram = self._datagrams.pop(key)
                self._current_bytes -= datagram.bytes_received
                self._stats['datagrams_timeout'] += 1
                
                logger.debug(
                    f"Fragment timeout for {key}: received {len(datagram.fragments)} "
                    f"fragments, {datagram.bytes_received} bytes"
                )
            
            if expired_keys:
                self._stats['current_bytes'] = self._current_bytes
                self._stats['current_datagrams'] = len(self._datagrams)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get current statistics."""
        with self._lock:
            return dict(self._stats)
    
    def shutdown(self):
        """Shutdown the reassembly buffer."""
        self._stop_event.set()
        if self._cleanup_thread.is_alive():
            self._cleanup_thread.join(timeout=2.0)
        
        with self._lock:
            # Log final stats
            stats = self.get_stats()
            logger.info(
                f"Fragment reassembly shutdown: "
                f"completed={stats['datagrams_completed']}, "
                f"timeout={stats['datagrams_timeout']}, "
                f"evicted={stats['datagrams_evicted']}"
            )
            self._datagrams.clear()
            self._current_bytes = 0


# =============================================================================
# BPF FILTER GENERATION
# =============================================================================

def generate_fragment_aware_filter(
    listen_ports: List[int],
    exclude_sport: Optional[int] = None,
) -> str:
    """
    Generate a BPF filter that captures both complete packets and fragments.
    
    The filter captures:
    1. Complete UDP packets destined to listen_ports
    2. First fragments (offset=0, MF=1) destined to listen_ports  
    3. Non-first UDP fragments (offset>0) regardless of port
       (port info is only in first fragment)
    
    Args:
        listen_ports: List of UDP ports to capture
        exclude_sport: Source port to exclude (prevents re-capture of forwarded packets)
        
    Returns:
        BPF filter string
    
    Example:
        >>> generate_fragment_aware_filter([162], exclude_sport=10162)
        '((udp dst port 162) and not (udp src port 10162)) or ((ip[6:2] & 0x1fff) != 0 and ip proto 17)'
    """
    # Part 1: Complete packets and first fragments (UDP header visible)
    port_parts = [f"udp dst port {port}" for port in listen_ports]
    port_filter = " or ".join(port_parts)
    if len(listen_ports) > 1:
        port_filter = f"({port_filter})"
    
    # Add source port exclusion if specified
    if exclude_sport:
        complete_filter = f"(({port_filter}) and not (udp src port {exclude_sport}))"
    else:
        complete_filter = f"({port_filter})"
    
    # Part 2: Non-first fragments (offset > 0) for UDP protocol
    # ip[6:2] is the flags/fragment offset field
    # & 0x1fff masks out the flags to get just the offset
    # != 0 means this is NOT the first fragment
    # ip proto 17 ensures it's UDP (we can't see port in non-first fragments)
    fragment_filter = "((ip[6:2] & 0x1fff) != 0 and ip proto 17)"
    
    # Combine: complete packets OR non-first fragments
    return f"{complete_filter} or {fragment_filter}"


def generate_simple_filter(
    listen_ports: List[int],
    exclude_sport: Optional[int] = None,
) -> str:
    """
    Generate a simple BPF filter (no fragment support).
    
    Use this when fragmentation support is disabled.
    
    Args:
        listen_ports: List of UDP ports to capture
        exclude_sport: Source port to exclude
        
    Returns:
        BPF filter string
    """
    port_parts = [f"udp dst port {port}" for port in listen_ports]
    port_filter = " or ".join(port_parts)
    
    if len(listen_ports) > 1:
        port_filter = f"({port_filter})"
    
    if exclude_sport:
        return f"({port_filter}) and not (udp src port {exclude_sport})"
    
    return port_filter


# =============================================================================
# GLOBAL BUFFER INSTANCE
# =============================================================================

_global_buffer: Optional[FragmentReassemblyBuffer] = None
_buffer_lock = threading.Lock()


def get_fragment_buffer() -> Optional[FragmentReassemblyBuffer]:
    """Get the global fragment reassembly buffer."""
    return _global_buffer


def initialize_fragment_buffer(
    timeout_seconds: float = 5.0,
    max_buffer_mb: float = 100.0,
    max_datagrams: int = 10000,
) -> FragmentReassemblyBuffer:
    """
    Initialize the global fragment reassembly buffer.
    
    Args:
        timeout_seconds: Fragment timeout
        max_buffer_mb: Maximum buffer size
        max_datagrams: Maximum tracked datagrams
        
    Returns:
        The initialized buffer
    """
    global _global_buffer
    
    with _buffer_lock:
        if _global_buffer is not None:
            _global_buffer.shutdown()
        
        _global_buffer = FragmentReassemblyBuffer(
            timeout_seconds=timeout_seconds,
            max_buffer_mb=max_buffer_mb,
            max_datagrams=max_datagrams,
        )
        
        logger.info(
            f"Fragment reassembly initialized: timeout={timeout_seconds}s, "
            f"max_buffer={max_buffer_mb}MB, max_datagrams={max_datagrams}"
        )
        
        return _global_buffer


def shutdown_fragment_buffer():
    """Shutdown the global fragment reassembly buffer."""
    global _global_buffer
    
    with _buffer_lock:
        if _global_buffer is not None:
            _global_buffer.shutdown()
            _global_buffer = None


def get_fragment_stats() -> Dict[str, Any]:
    """Get fragment reassembly statistics."""
    buffer = get_fragment_buffer()
    if buffer:
        return buffer.get_stats()
    return {}
