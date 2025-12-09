#!/usr/bin/env python3
"""
TrapNinja Packet Forwarder

High-performance packet forwarding using raw sockets with Scapy fallback.

Key optimizations:
- Pre-initialized socket pool
- Raw socket with IP_HDRINCL for minimal overhead
- Large send buffers
- Batch forwarding capability

Performance: ~6-10x faster than Scapy for raw socket forwarding

Author: TrapNinja Team
Version: 2.0.0
"""

import socket
import struct
import threading
import logging
from typing import Optional, List, Tuple
from collections import deque

try:
    from ..core.constants import FORWARD_SOURCE_PORT
except ImportError:
    # Fallback if running standalone or import fails
    FORWARD_SOURCE_PORT = 10162

logger = logging.getLogger("trapninja")


# =============================================================================
# CONSTANTS
# =============================================================================

DEFAULT_POOL_SIZE = 4
DEFAULT_SEND_BUFFER = 4194304  # 4MB
# Use FORWARD_SOURCE_PORT from core.constants to prevent re-capture loops
# See documentation/fixes/PACKET_RECAPTURE_LOOP_FIX.md
DEFAULT_SOURCE_PORT = FORWARD_SOURCE_PORT


# =============================================================================
# SOCKET POOL
# =============================================================================

class SocketPool:
    """
    Pool of pre-initialized raw sockets for efficient forwarding.
    
    Avoids socket creation overhead on the hot path.
    Falls back to Scapy if raw sockets unavailable.
    
    Attributes:
        pool_size: Number of sockets in pool
        is_raw_available: Whether raw sockets can be used
    """
    
    def __init__(self, pool_size: int = DEFAULT_POOL_SIZE):
        """
        Initialize socket pool.
        
        Args:
            pool_size: Number of sockets to maintain in pool
        """
        self.pool_size = pool_size
        self._sockets: deque = deque()
        self._lock = threading.Lock()
        self._available = threading.Semaphore(0)
        self._raw_available: Optional[bool] = None
        self._initialized = False
    
    def initialize(self) -> bool:
        """
        Initialize the socket pool.
        
        Creates raw sockets if permissions allow.
        
        Returns:
            True if raw sockets available
        """
        if self._initialized:
            return self._raw_available
        
        for _ in range(self.pool_size):
            sock = self._create_socket()
            if sock:
                self._sockets.append(sock)
                self._available.release()
        
        self._initialized = True
        
        if self._raw_available:
            logger.info(f"Socket pool initialized with {len(self._sockets)} raw sockets")
        else:
            logger.info("Raw sockets unavailable, will use Scapy fallback")
        
        return self._raw_available
    
    def _create_socket(self) -> Optional[socket.socket]:
        """Create a raw socket for packet forwarding."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, DEFAULT_SEND_BUFFER)
            sock.setblocking(False)
            self._raw_available = True
            return sock
        except (PermissionError, OSError) as e:
            if self._raw_available is None:
                logger.debug(f"Raw sockets unavailable: {e}")
                self._raw_available = False
            return None
    
    @property
    def is_raw_available(self) -> bool:
        """Check if raw sockets are available."""
        if not self._initialized:
            self.initialize()
        return self._raw_available == True
    
    def acquire(self, timeout: float = 0.1) -> Optional[socket.socket]:
        """
        Acquire a socket from the pool.
        
        Args:
            timeout: Maximum time to wait for available socket
            
        Returns:
            Socket or None if unavailable
        """
        if not self._raw_available:
            return None
        
        if self._available.acquire(timeout=timeout):
            with self._lock:
                if self._sockets:
                    return self._sockets.popleft()
        return None
    
    def release(self, sock: socket.socket):
        """
        Return a socket to the pool.
        
        Args:
            sock: Socket to return
        """
        if sock:
            with self._lock:
                self._sockets.append(sock)
            self._available.release()
    
    def shutdown(self):
        """Close all sockets in the pool."""
        with self._lock:
            while self._sockets:
                sock = self._sockets.popleft()
                try:
                    sock.close()
                except Exception:
                    pass
        self._initialized = False
        logger.info("Socket pool shutdown complete")


# Global socket pool (lazy initialization)
_socket_pool: Optional[SocketPool] = None
_socket_pool_lock = threading.Lock()


def get_socket_pool() -> SocketPool:
    """
    Get or create the global socket pool.
    
    Returns:
        SocketPool instance
    """
    global _socket_pool
    if _socket_pool is None:
        with _socket_pool_lock:
            if _socket_pool is None:
                _socket_pool = SocketPool()
                _socket_pool.initialize()
    return _socket_pool


# =============================================================================
# PACKET BUILDING
# =============================================================================

def _ip_checksum(data: bytes) -> int:
    """
    Calculate IP header checksum.
    
    Args:
        data: IP header bytes
        
    Returns:
        Checksum value
    """
    if len(data) % 2:
        data += b'\x00'
    words = struct.unpack('!%dH' % (len(data) // 2), data)
    total = sum(words)
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def build_packet(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    payload: bytes
) -> bytes:
    """
    Build IP+UDP packet for raw socket sending.
    
    Args:
        src_ip: Source IP address
        dst_ip: Destination IP address
        src_port: Source UDP port
        dst_port: Destination UDP port
        payload: UDP payload
        
    Returns:
        Complete IP packet bytes
    """
    total_len = 20 + 8 + len(payload)
    
    # IP header
    ip_header = struct.pack(
        '!BBHHHBBH4s4s',
        0x45,  # Version (4) + IHL (5)
        0,     # TOS
        total_len,
        0,     # ID
        0,     # Flags + Fragment offset
        64,    # TTL
        17,    # Protocol (UDP)
        0,     # Checksum (placeholder)
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip)
    )
    
    # Calculate IP checksum
    checksum = _ip_checksum(ip_header)
    ip_header = ip_header[:10] + struct.pack('!H', checksum) + ip_header[12:]
    
    # UDP header (checksum optional for IPv4)
    udp_len = 8 + len(payload)
    udp_header = struct.pack('!HHHH', src_port, dst_port, udp_len, 0)
    
    return ip_header + udp_header + payload


# =============================================================================
# FORWARDING FUNCTIONS
# =============================================================================

def forward_packet(
    source_ip: str,
    payload: bytes,
    destinations: List[Tuple[str, int]],
    source_port: int = DEFAULT_SOURCE_PORT
) -> bool:
    """
    Forward packet to destinations using fastest available method.
    
    Priority:
    1. Raw socket (6-10x faster)
    2. Scapy (fallback)
    
    Args:
        source_ip: Source IP to spoof
        payload: UDP payload to forward
        destinations: List of (ip, port) destination tuples
        source_port: Source port for forwarding
        
    Returns:
        True if forwarding succeeded to at least one destination
    """
    if not destinations:
        return False
    
    # Try raw socket first
    pool = get_socket_pool()
    
    if pool.is_raw_available:
        sock = pool.acquire()
        if sock:
            try:
                success = False
                for dst_ip, dst_port in destinations:
                    packet = build_packet(source_ip, dst_ip, source_port, dst_port, payload)
                    try:
                        sock.sendto(packet, (dst_ip, 0))
                        success = True
                    except BlockingIOError:
                        # Socket buffer full, continue with next destination
                        pass
                    except Exception as e:
                        logger.debug(f"Raw forward to {dst_ip}:{dst_port} failed: {e}")
                return success
            except Exception as e:
                logger.debug(f"Raw socket error: {e}")
            finally:
                pool.release(sock)
    
    # Fallback to Scapy
    return _forward_scapy(source_ip, payload, destinations, source_port)


def forward_packet_batch(
    packets: List[Tuple[str, bytes, List[Tuple[str, int]]]]
) -> int:
    """
    Forward multiple packets efficiently.
    
    Reuses socket for all packets in batch.
    
    Args:
        packets: List of (source_ip, payload, destinations) tuples
        
    Returns:
        Number of packets successfully forwarded
    """
    if not packets:
        return 0
    
    pool = get_socket_pool()
    success_count = 0
    
    if pool.is_raw_available:
        sock = pool.acquire(timeout=0.5)
        if sock:
            try:
                for source_ip, payload, destinations in packets:
                    for dst_ip, dst_port in destinations:
                        packet = build_packet(source_ip, dst_ip, DEFAULT_SOURCE_PORT, dst_port, payload)
                        try:
                            sock.sendto(packet, (dst_ip, 0))
                            success_count += 1
                        except BlockingIOError:
                            pass
                        except Exception:
                            pass
            finally:
                pool.release(sock)
            return success_count
    
    # Fallback to individual Scapy forwards
    for source_ip, payload, destinations in packets:
        if _forward_scapy(source_ip, payload, destinations, DEFAULT_SOURCE_PORT):
            success_count += 1
    
    return success_count


def _forward_scapy(
    source_ip: str,
    payload: bytes,
    destinations: List[Tuple[str, int]],
    source_port: int
) -> bool:
    """
    Scapy-based forwarding (fallback).
    
    Args:
        source_ip: Source IP to spoof
        payload: UDP payload
        destinations: List of (ip, port) tuples
        source_port: Source UDP port
        
    Returns:
        True if any destination reached
    """
    try:
        from scapy.all import IP, UDP, send, get_if_list
        
        # Get interface if available
        try:
            from ..config import INTERFACE
            available = get_if_list()
            use_iface = INTERFACE if INTERFACE in available else None
        except ImportError:
            use_iface = None
        
        template = IP(src=source_ip) / UDP(sport=source_port)
        success = False
        
        for dst_ip, dst_port in destinations:
            try:
                template[IP].dst = dst_ip
                template[UDP].dport = dst_port
                packet = template / payload
                
                if use_iface:
                    send(packet, verbose=False, iface=use_iface)
                else:
                    send(packet, verbose=False)
                success = True
            except Exception as e:
                logger.debug(f"Scapy forward to {dst_ip}:{dst_port} failed: {e}")
        
        return success
        
    except Exception as e:
        logger.error(f"Scapy forwarding failed: {e}")
        return False


def shutdown_forwarder():
    """Clean up forwarder resources."""
    global _socket_pool
    if _socket_pool:
        _socket_pool.shutdown()
        _socket_pool = None
