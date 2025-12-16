#!/usr/bin/env python3
"""
TrapNinja High-Performance Packet Processor

Optimized packet processing pipeline designed for telecommunications-scale
SNMP trap forwarding. Addresses queue saturation issues through:

- Efficient batch processing with adaptive batch sizes
- Minimal logging overhead (periodic summaries only)
- Lock-free statistics using atomic operations
- Pre-initialized socket pools for forwarding
- Optimized memory handling with buffer reuse

Performance Target: 10,000+ traps/second sustained throughput

Author: TrapNinja Team
Version: 1.0.0
"""

import logging
import threading
import queue
import time
import socket
import struct
from typing import Optional, List, Tuple, Dict, Any
from collections import deque
from dataclasses import dataclass, field

from .config import stop_event, LISTEN_PORTS
from .core.constants import FORWARD_SOURCE_PORT

# Import HA functions for forwarding control
# CRITICAL: These functions control whether this node should forward traps
try:
    from .ha import is_forwarding_enabled, notify_trap_processed
    HA_AVAILABLE = True
except ImportError as e:
    # Log the import failure - this is critical for HA to work!
    import sys
    print(f"WARNING: Failed to import HA module: {e}", file=sys.stderr)
    print("WARNING: HA forwarding control DISABLED - all nodes will forward!", file=sys.stderr)
    HA_AVAILABLE = False
    
    # Counter to rate-limit warnings
    _ha_warning_count = 0
    
    def is_forwarding_enabled():
        """Fallback when HA module unavailable - ALWAYS returns True (unsafe for HA)"""
        global _ha_warning_count
        _ha_warning_count += 1
        if _ha_warning_count <= 5:  # Only warn first 5 times
            logger.warning("HA module not available - forwarding enabled by default")
        return True
    
    def notify_trap_processed():
        pass

logger = logging.getLogger("trapninja")

# Import cache module with fallback
try:
    from .cache import get_cache
    CACHE_AVAILABLE = True
except ImportError:
    CACHE_AVAILABLE = False
    def get_cache():
        return None

# Import granular statistics module with fallback
try:
    from .stats import get_stats_collector, initialize_stats
    GRANULAR_STATS_AVAILABLE = True
except ImportError:
    GRANULAR_STATS_AVAILABLE = False
    def get_stats_collector():
        return None
    def initialize_stats(config=None):
        return None


def _record_granular_stats(source_ip: str, oid: str = None, 
                           action: str = 'forwarded', destination: str = None):
    """
    Record granular per-IP/OID statistics.
    Non-blocking - failures don't affect packet processing.
    """
    if not GRANULAR_STATS_AVAILABLE:
        return
    
    collector = get_stats_collector()
    if collector:
        try:
            collector.record_trap(
                source_ip=source_ip,
                oid=oid,
                action=action,
                destination=destination
            )
        except Exception:
            pass  # Never block packet processing for stats


# =============================================================================
# LOCK-FREE STATISTICS (Atomic counters for performance)
# =============================================================================

@dataclass
class AtomicStats:
    """
    Lock-free statistics using Python's GIL for atomic int operations.
    
    Tracks all packet processing metrics for Prometheus export.
    """
    # Core packet counts
    packets_processed: int = 0
    packets_forwarded: int = 0
    packets_blocked: int = 0
    packets_redirected: int = 0
    packets_dropped: int = 0
    queue_full_events: int = 0
    processing_errors: int = 0
    
    # HA metrics
    ha_blocked: int = 0  # Packets not forwarded due to HA secondary mode
    
    # Cache metrics
    packets_cached: int = 0  # Packets stored in cache
    cache_failures: int = 0  # Cache store failures
    
    # Performance metrics (fast/slow path tracking)
    fast_path_hits: int = 0  # SNMPv2c packets using optimized path
    slow_path_hits: int = 0  # Packets requiring full parsing
    
    # Timing and queue metrics
    start_time: float = field(default_factory=time.time)
    last_summary_time: float = field(default_factory=time.time)
    max_queue_depth: int = 0
    
    def increment_processed(self):
        self.packets_processed += 1
    
    def increment_forwarded(self):
        self.packets_forwarded += 1
    
    def increment_blocked(self):
        self.packets_blocked += 1
    
    def increment_redirected(self):
        self.packets_redirected += 1
        
    def increment_dropped(self):
        self.packets_dropped += 1
        self.queue_full_events += 1
    
    def increment_error(self):
        self.processing_errors += 1
    
    def increment_ha_blocked(self):
        self.ha_blocked += 1
    
    def increment_cached(self):
        self.packets_cached += 1
    
    def increment_cache_failure(self):
        self.cache_failures += 1
    
    def record_fast_path(self):
        """Record packet processed via fast SNMPv2c path."""
        self.fast_path_hits += 1
    
    def record_slow_path(self):
        """Record packet processed via full parsing path."""
        self.slow_path_hits += 1
    
    def update_max_depth(self, depth: int):
        if depth > self.max_queue_depth:
            self.max_queue_depth = depth
    
    @property
    def uptime(self) -> float:
        """Get seconds since start."""
        return time.time() - self.start_time
    
    @property
    def fast_path_ratio(self) -> float:
        """Calculate fast path ratio as percentage."""
        total = self.fast_path_hits + self.slow_path_hits
        if total == 0:
            return 0.0
        return (self.fast_path_hits / total) * 100
    
    @property
    def processing_rate(self) -> float:
        """Calculate packets per second."""
        elapsed = self.uptime
        if elapsed <= 0:
            return 0.0
        return self.packets_processed / elapsed
    
    def get_summary(self) -> Dict[str, Any]:
        """Get all statistics as a dictionary for metrics export."""
        return {
            # Core counts
            'processed': self.packets_processed,
            'forwarded': self.packets_forwarded,
            'blocked': self.packets_blocked,
            'redirected': self.packets_redirected,
            'dropped': self.packets_dropped,
            'queue_full_events': self.queue_full_events,
            'errors': self.processing_errors,
            
            # HA
            'ha_blocked': self.ha_blocked,
            
            # Cache
            'cached': self.packets_cached,
            'cache_failures': self.cache_failures,
            
            # Performance
            'fast_path_hits': self.fast_path_hits,
            'slow_path_hits': self.slow_path_hits,
            'fast_path_ratio': round(self.fast_path_ratio, 1),
            'processing_rate': round(self.processing_rate, 1),
            
            # Queue
            'max_queue_depth': self.max_queue_depth,
            
            # Timing
            'uptime_seconds': round(self.uptime, 1),
        }
    
    def should_log_summary(self, interval: float = 30.0) -> bool:
        """Check if it's time to log a summary (every interval seconds)"""
        now = time.time()
        if now - self.last_summary_time >= interval:
            self.last_summary_time = now
            return True
        return False


# Global statistics instance
_stats = AtomicStats()


def get_processor_stats() -> Dict[str, Any]:
    """Get current processor statistics"""
    return _stats.get_summary()


def reset_processor_stats():
    """Reset processor statistics"""
    global _stats
    _stats = AtomicStats()


# =============================================================================
# SOCKET POOL FOR EFFICIENT FORWARDING
# =============================================================================

class SocketPool:
    """
    Pool of pre-initialized raw sockets for efficient packet forwarding.
    Avoids socket creation overhead on the hot path.
    """
    
    def __init__(self, pool_size: int = 4):
        self.pool_size = pool_size
        self.sockets: deque = deque()
        self.lock = threading.Lock()
        self.available = threading.Semaphore(0)
        self._raw_available: Optional[bool] = None
        self._init_pool()
    
    def _init_pool(self):
        """Initialize the socket pool"""
        for _ in range(self.pool_size):
            sock = self._create_socket()
            if sock:
                self.sockets.append(sock)
                self.available.release()
    
    def _create_socket(self) -> Optional[socket.socket]:
        """Create a raw socket for packet forwarding"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4194304)  # 4MB buffer
            sock.setblocking(False)
            self._raw_available = True
            return sock
        except (PermissionError, OSError) as e:
            if self._raw_available is None:
                logger.debug(f"Raw sockets unavailable: {e}")
                self._raw_available = False
            return None
    
    def acquire(self, timeout: float = 0.1) -> Optional[socket.socket]:
        """Acquire a socket from the pool"""
        if not self._raw_available:
            return None
        
        if self.available.acquire(timeout=timeout):
            with self.lock:
                if self.sockets:
                    return self.sockets.popleft()
        return None
    
    def release(self, sock: socket.socket):
        """Return a socket to the pool"""
        if sock:
            with self.lock:
                self.sockets.append(sock)
            self.available.release()
    
    def is_raw_available(self) -> bool:
        """Check if raw sockets are available"""
        return self._raw_available == True
    
    def shutdown(self):
        """Close all sockets in the pool"""
        with self.lock:
            while self.sockets:
                sock = self.sockets.popleft()
                try:
                    sock.close()
                except Exception:
                    pass


# Global socket pool (lazy initialization)
_socket_pool: Optional[SocketPool] = None
_socket_pool_lock = threading.Lock()


def get_socket_pool() -> SocketPool:
    """Get or create the global socket pool"""
    global _socket_pool
    if _socket_pool is None:
        with _socket_pool_lock:
            if _socket_pool is None:
                _socket_pool = SocketPool()
    return _socket_pool


# =============================================================================
# HIGH-PERFORMANCE PACKET FORWARDING
# =============================================================================

def _ip_checksum(data: bytes) -> int:
    """Calculate IP header checksum"""
    if len(data) % 2:
        data += b'\x00'
    words = struct.unpack('!%dH' % (len(data) // 2), data)
    total = sum(words)
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def _build_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int, 
                  payload: bytes) -> bytes:
    """Build IP+UDP packet for raw socket sending"""
    # IP header
    version_ihl = 0x45
    tos = 0
    total_len = 20 + 8 + len(payload)
    pkt_id = 0
    flags_frag = 0
    ttl = 64
    protocol = 17  # UDP
    
    src_addr = socket.inet_aton(src_ip)
    dst_addr = socket.inet_aton(dst_ip)
    
    ip_header = struct.pack(
        '!BBHHHBBH4s4s',
        version_ihl, tos, total_len, pkt_id, flags_frag,
        ttl, protocol, 0, src_addr, dst_addr
    )
    
    checksum = _ip_checksum(ip_header)
    ip_header = struct.pack(
        '!BBHHHBBH4s4s',
        version_ihl, tos, total_len, pkt_id, flags_frag,
        ttl, protocol, checksum, src_addr, dst_addr
    )
    
    # UDP header (checksum optional for IPv4)
    udp_len = 8 + len(payload)
    udp_header = struct.pack('!HHHH', src_port, dst_port, udp_len, 0)
    
    return ip_header + udp_header + payload


def forward_fast(source_ip: str, payload: bytes, 
                 destinations: List[Tuple[str, int]]) -> bool:
    """
    High-performance packet forwarding using raw sockets.
    Falls back to Scapy if raw sockets unavailable.
    
    IMPORTANT: Uses FORWARD_SOURCE_PORT (not 162) to prevent forwarded
    packets from being re-captured by sniff() filters matching 'udp port 162'.
    
    Args:
        source_ip: Source IP to spoof
        payload: UDP payload to forward
        destinations: List of (ip, port) destination tuples
    
    Returns:
        True if forwarding succeeded, False otherwise
    """
    if not destinations:
        return False
    
    pool = get_socket_pool()
    
    if pool.is_raw_available():
        sock = pool.acquire()
        if sock:
            try:
                for dst_ip, dst_port in destinations:
                    packet = _build_packet(source_ip, dst_ip, FORWARD_SOURCE_PORT, dst_port, payload)
                    try:
                        sock.sendto(packet, (dst_ip, 0))
                    except BlockingIOError:
                        # Socket buffer full, continue
                        pass
                return True
            except Exception as e:
                logger.debug(f"Raw forward error: {e}")
                return False
            finally:
                pool.release(sock)
    
    # Fallback to Scapy
    return _forward_scapy(source_ip, payload, destinations)


def _forward_scapy(source_ip: str, payload: bytes, 
                   destinations: List[Tuple[str, int]]) -> bool:
    """Fallback forwarding using Scapy"""
    try:
        from scapy.all import IP, UDP, send, get_if_list
        from .config import INTERFACE
        
        # Use FORWARD_SOURCE_PORT to prevent re-capture loops
        template = IP(src=source_ip) / UDP(sport=FORWARD_SOURCE_PORT)
        
        for dst_ip, dst_port in destinations:
            template[IP].dst = dst_ip
            template[UDP].dport = dst_port
            packet = template / payload
            
            try:
                if INTERFACE in get_if_list():
                    send(packet, verbose=False, iface=INTERFACE)
                else:
                    send(packet, verbose=False)
            except Exception:
                send(packet, verbose=False)
        
        return True
    except Exception as e:
        logger.debug(f"Scapy forward error: {e}")
        return False


# =============================================================================
# OPTIMIZED SNMP PROCESSING
# =============================================================================

# Pre-compiled byte patterns for fast detection
_SNMPV2C_SIGNATURE = b'\x30'  # SEQUENCE tag
_SNMPTRAPOID_MARKER = b'\x2b\x06\x01\x06\x03\x01\x01\x04\x01\x00'


def is_snmpv2c_fast(payload: bytes) -> bool:
    """Ultra-fast SNMPv2c detection"""
    return (len(payload) >= 8 and 
            payload[0] == 0x30 and
            payload[2] == 0x02 and
            payload[3] == 0x01 and
            payload[4] == 0x01 and
            payload[5] == 0x04)


def extract_oid_fast(payload: bytes) -> Optional[str]:
    """
    Fast OID extraction for SNMPv2c traps.
    Uses direct byte scanning without full packet parsing.
    """
    pos = payload.find(_SNMPTRAPOID_MARKER)
    if pos == -1:
        return None
    
    pos += len(_SNMPTRAPOID_MARKER)
    
    try:
        if pos >= len(payload) or payload[pos] != 0x06:
            return None
        
        pos += 1
        if pos >= len(payload):
            return None
        
        oid_len = payload[pos]
        pos += 1
        
        if pos + oid_len > len(payload):
            return None
        
        oid_bytes = payload[pos:pos + oid_len]
        return _decode_oid(oid_bytes)
    except Exception:
        return None


def _decode_oid(oid_bytes: bytes) -> str:
    """Decode OID from ASN.1 binary representation"""
    if not oid_bytes:
        return ""
    
    first = oid_bytes[0]
    if first < 40:
        parts = [0, first]
    elif first < 80:
        parts = [1, first - 40]
    else:
        parts = [2, first - 80]
    
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
# CACHE INTEGRATION
# =============================================================================

import base64
from datetime import datetime


def cache_trap(destination: str, source_ip: str, payload: bytes, 
               trap_oid: Optional[str] = None) -> bool:
    """
    Cache a trap for later replay. Non-blocking - failures don't affect forwarding.
    
    Args:
        destination: Destination identifier (e.g., "default", "voice_noc")
        source_ip: Source IP address of the trap
        payload: Raw UDP payload
        trap_oid: Extracted trap OID (optional)
        
    Returns:
        True if cached successfully, False otherwise
    """
    if not CACHE_AVAILABLE:
        return False
    
    cache = get_cache()
    if not cache or not cache.available:
        return False
    
    try:
        # Encode payload as base64
        pdu_base64 = base64.b64encode(payload).decode('ascii')
        
        # Build trap data
        trap_data = {
            'timestamp': datetime.now().isoformat(),
            'source_ip': source_ip,
            'trap_oid': trap_oid or '',
            'pdu_base64': pdu_base64,
        }
        
        # Store in cache (non-blocking)
        entry_id = cache.store(destination, trap_data)
        
        if entry_id:
            _stats.increment_cached()
            return True
        else:
            _stats.increment_cache_failure()
            return False
            
    except Exception as e:
        logger.debug(f"Cache trap failed: {e}")
        _stats.increment_cache_failure()
        return False


# =============================================================================
# BATCH PROCESSOR (Core processing engine)
# =============================================================================

class BatchProcessor:
    """
    High-performance batch packet processor.
    
    Optimizations:
    - Processes packets in configurable batches
    - Minimal per-packet overhead
    - Periodic summary logging (not per-packet)
    - Pre-cached configuration
    """
    
    def __init__(self, worker_id: int = 0):
        self.worker_id = worker_id
        self.packets_since_log = 0
        self.log_interval = 1000  # Log every N packets
        self._config_cache = None
        self._config_cache_time = 0
        self._config_cache_ttl = 30.0  # Refresh config every 30s
    
    def _get_config(self):
        """Get cached configuration"""
        now = time.time()
        if self._config_cache is None or (now - self._config_cache_time) > self._config_cache_ttl:
            from .config import (destinations, blocked_traps, blocked_ips,
                                 redirected_ips, redirected_oids, redirected_destinations)
            self._config_cache = {
                'destinations': destinations,
                'blocked_traps': blocked_traps,
                'blocked_ips': blocked_ips,
                'redirected_ips': redirected_ips,
                'redirected_oids': redirected_oids,
                'redirected_destinations': redirected_destinations
            }
            self._config_cache_time = now
        return self._config_cache
    
    def process_packet(self, packet_data: Dict[str, Any]) -> bool:
        """
        Process a single packet with minimal overhead.
        
        Note: Caching happens regardless of HA state. Only forwarding
        is controlled by HA. This ensures the Secondary has trap history
        if it becomes Primary.
        
        Returns:
            True if packet was processed successfully
        """
        try:
            # Check HA state for forwarding decision (but always cache)
            ha_forwarding_enabled = is_forwarding_enabled()
            
            config = self._get_config()
            source_ip = packet_data['src_ip']
            payload = packet_data['payload']
            
            _stats.increment_processed()
            
            # Quick IP block check
            if source_ip in config['blocked_ips']:
                _stats.increment_blocked()
                _stats.record_fast_path()  # Simple check is fast path
                _record_granular_stats(source_ip, oid=None, action='blocked')
                return True
            
            # Try fast path for SNMPv2c
            trap_oid = None
            used_fast_path = False
            
            if is_snmpv2c_fast(payload):
                trap_oid = extract_oid_fast(payload)
                if trap_oid:
                    used_fast_path = True
                    _stats.record_fast_path()
            
            # If fast path failed, record slow path
            if not used_fast_path:
                _stats.record_slow_path()
            
            if trap_oid:
                # Check OID blocking
                if trap_oid in config['blocked_traps']:
                    _stats.increment_blocked()
                    _record_granular_stats(source_ip, oid=trap_oid, action='blocked')
                    return True
                
                # Check redirection
                if source_ip in config['redirected_ips']:
                    tag = config['redirected_ips'][source_ip]
                    if tag in config['redirected_destinations']:
                        # Always cache, regardless of HA state
                        cache_trap(tag, source_ip, payload, trap_oid)
                        
                        # Only forward if HA allows
                        if ha_forwarding_enabled:
                            forward_fast(source_ip, payload, 
                                        config['redirected_destinations'][tag])
                            _stats.increment_redirected()
                            _record_granular_stats(source_ip, oid=trap_oid, 
                                                   action='redirected', destination=tag)
                            notify_trap_processed()
                        else:
                            _stats.increment_ha_blocked()
                            _record_granular_stats(source_ip, oid=trap_oid, action='dropped')
                        return True
                
                if trap_oid in config['redirected_oids']:
                    tag = config['redirected_oids'][trap_oid]
                    if tag in config['redirected_destinations']:
                        # Always cache, regardless of HA state
                        cache_trap(tag, source_ip, payload, trap_oid)
                        
                        # Only forward if HA allows
                        if ha_forwarding_enabled:
                            forward_fast(source_ip, payload,
                                        config['redirected_destinations'][tag])
                            _stats.increment_redirected()
                            _record_granular_stats(source_ip, oid=trap_oid,
                                                   action='redirected', destination=tag)
                            notify_trap_processed()
                        else:
                            _stats.increment_ha_blocked()
                            _record_granular_stats(source_ip, oid=trap_oid, action='dropped')
                        return True
            
            # Default destination handling
            # Always cache, regardless of HA state
            cache_trap('default', source_ip, payload, trap_oid)
            
            # Only forward if HA allows
            if ha_forwarding_enabled:
                if config['destinations']:
                    forward_fast(source_ip, payload, config['destinations'])
                    _stats.increment_forwarded()
                    _record_granular_stats(source_ip, oid=trap_oid,
                                           action='forwarded', destination='default')
                    notify_trap_processed()
            else:
                _stats.increment_ha_blocked()
                _record_granular_stats(source_ip, oid=trap_oid, action='dropped')
            
            return True
            
        except Exception as e:
            _stats.increment_error()
            logger.debug(f"Worker {self.worker_id} error: {e}")
            return False
    
    def process_batch(self, batch: List[Dict[str, Any]]):
        """Process a batch of packets efficiently"""
        for packet in batch:
            self.process_packet(packet)
        
        self.packets_since_log += len(batch)
        
        # Periodic summary logging (not per-packet!)
        if self.packets_since_log >= self.log_interval:
            stats = _stats.get_summary()
            logger.info(f"Worker {self.worker_id}: processed={stats['processed']}, "
                       f"forwarded={stats['forwarded']}, blocked={stats['blocked']}")
            self.packets_since_log = 0


# =============================================================================
# WORKER THREAD
# =============================================================================

def packet_worker(worker_id: int, packet_queue: queue.Queue,
                  batch_size: int = 50, timeout: float = 0.5):
    """
    Optimized packet processing worker.
    
    Key optimizations:
    - Larger batch sizes (50 vs 10)
    - Longer timeouts (0.5s vs 0.1s) to reduce CPU spinning
    - Batch-level statistics
    - Minimal per-packet logging
    """
    processor = BatchProcessor(worker_id)
    batch = []
    
    logger.info(f"Packet worker {worker_id} started (batch_size={batch_size})")
    
    while not stop_event.is_set():
        try:
            # Collect a batch
            deadline = time.time() + timeout
            
            while len(batch) < batch_size and time.time() < deadline:
                remaining = deadline - time.time()
                if remaining <= 0:
                    break
                
                try:
                    packet = packet_queue.get(timeout=min(remaining, 0.05))
                    batch.append(packet)
                except queue.Empty:
                    break
            
            # Process batch if we have packets
            if batch:
                processor.process_batch(batch)
                
                # Mark tasks done
                for _ in batch:
                    try:
                        packet_queue.task_done()
                    except ValueError:
                        pass
                
                # Update queue depth stats
                _stats.update_max_depth(packet_queue.qsize())
                
                batch.clear()
                
        except Exception as e:
            logger.error(f"Worker {worker_id} error: {e}")
            batch.clear()
    
    logger.info(f"Packet worker {worker_id} stopped")


def start_workers(packet_queue: queue.Queue, num_workers: int = None) -> List[threading.Thread]:
    """
    Start packet processing workers.
    
    Args:
        packet_queue: Queue to process packets from
        num_workers: Number of workers (default: 2x CPU cores, max 32)
    
    Returns:
        List of worker threads
    """
    import multiprocessing
    
    if num_workers is None:
        cpu_count = multiprocessing.cpu_count()
        num_workers = min(cpu_count * 2, 32)
    
    workers = []
    for i in range(num_workers):
        t = threading.Thread(
            target=packet_worker,
            args=(i, packet_queue),
            kwargs={'batch_size': 50, 'timeout': 0.5},
            daemon=True,
            name=f"PacketWorker-{i}"
        )
        t.start()
        workers.append(t)
    
    logger.info(f"Started {num_workers} packet processing workers")
    return workers


# =============================================================================
# MONITORING
# =============================================================================

def stats_monitor(interval: float = 30.0):
    """Background thread for periodic stats logging"""
    logger.info("Stats monitor started")
    
    last_processed = 0
    last_time = time.time()
    
    while not stop_event.is_set():
        try:
            time.sleep(interval)
            
            stats = _stats.get_summary()
            now = time.time()
            elapsed = now - last_time
            
            processed_delta = stats['processed'] - last_processed
            rate = processed_delta / elapsed if elapsed > 0 else 0
            
            logger.info(f"Stats: rate={rate:.1f}/s, total={stats['processed']}, "
                       f"forwarded={stats['forwarded']}, dropped={stats['dropped']}, "
                       f"ha_blocked={stats['ha_blocked']}, errors={stats['errors']}")
            
            last_processed = stats['processed']
            last_time = now
            
        except Exception as e:
            logger.debug(f"Stats monitor error: {e}")
    
    logger.info("Stats monitor stopped")


def start_stats_monitor(interval: float = 30.0) -> threading.Thread:
    """Start the statistics monitoring thread"""
    t = threading.Thread(target=stats_monitor, args=(interval,), daemon=True,
                        name="StatsMonitor")
    t.start()
    return t


# =============================================================================
# CLEANUP
# =============================================================================

def shutdown():
    """Clean up resources"""
    global _socket_pool
    if _socket_pool:
        _socket_pool.shutdown()
        _socket_pool = None
    
    logger.info(f"Packet processor shutdown. Final stats: {_stats.get_summary()}")
