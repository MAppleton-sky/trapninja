#!/usr/bin/env python3
"""
TrapNinja Network Module - High-Performance Version 2.0

Optimized for telecommunications-scale SNMP trap processing.
Addresses queue saturation issues with:

- Larger queue capacity (200K packets)
- Efficient capture with minimal overhead
- Integration with high-performance packet processor
- Adaptive backpressure handling

Performance Target: 10,000+ traps/second sustained
"""

import socket
import logging
import threading
import queue
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from typing import Optional, List, Dict, Any

from scapy.all import IP, UDP, get_if_list

from .config import stop_event, LISTEN_PORTS, INTERFACE, BIND_ADDRESS
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

# =============================================================================
# PACKET QUEUE (Central queue for all capture methods)
# =============================================================================

# Increased queue size for alarm flood scenarios
# Telco networks can generate 100K+ traps during major events
QUEUE_MAX_SIZE = 200000

packet_queue = queue.Queue(maxsize=QUEUE_MAX_SIZE)


# =============================================================================
# QUEUE STATISTICS (Lock-free for performance)
# =============================================================================

class QueueStats:
    """Lock-free queue statistics"""
    
    def __init__(self):
        self.total_queued = 0
        self.total_dropped = 0
        self.full_events = 0
        self.max_depth = 0
        self.last_drop_log_time = 0
        self.drops_since_last_log = 0
    
    def record_queued(self):
        self.total_queued += 1
    
    def record_dropped(self):
        self.total_dropped += 1
        self.drops_since_last_log += 1
        self.full_events += 1
        
        # Rate-limited drop logging (max once per second)
        now = time.time()
        if now - self.last_drop_log_time >= 1.0:
            if self.drops_since_last_log > 0:
                logger.warning(f"Queue full: {self.drops_since_last_log} packets dropped")
                self.drops_since_last_log = 0
            self.last_drop_log_time = now
    
    def update_depth(self, depth: int):
        if depth > self.max_depth:
            self.max_depth = depth
    
    def get_stats(self) -> Dict[str, Any]:
        # Update max depth on every stats check
        current_depth = packet_queue.qsize()
        if current_depth > self.max_depth:
            self.max_depth = current_depth
        
        return {
            'current_depth': current_depth,
            'max_depth': self.max_depth,
            'total_queued': self.total_queued,
            'total_dropped': self.total_dropped,
            'full_events': self.full_events,
            'queue_capacity': QUEUE_MAX_SIZE,
            'utilization': current_depth / QUEUE_MAX_SIZE
        }


_queue_stats = QueueStats()


def get_queue_stats() -> Dict[str, Any]:
    """Get current queue statistics"""
    return _queue_stats.get_stats()


# =============================================================================
# SOCKET DROP MONITOR (kernel-level visibility)
# =============================================================================

class SocketDropMonitor:
    """
    Reads /proc/net/udp to surface kernel-level UDP receive buffer drops.

    These drops happen below this application entirely — the kernel
    discarded a datagram before recvfrom() ever saw it, because the
    socket's receive buffer was full. QueueStats only sees packets that
    made it into packet_queue, so this is a genuine blind spot under burst
    load in socket capture mode.

    Linux-specific (reads /proc/net/udp, standard on RHEL 8/9). Only
    meaningful when CAPTURE_MODE is "socket" — eBPF and sniff modes do not
    bind UDP sockets the same way; their drop visibility (eBPF perf-buffer
    lost samples) is handled separately in ebpf.py (see Part B2).
    """

    PROC_UDP_PATH = "/proc/net/udp"

    def __init__(self):
        self._lock = threading.Lock()
        self._cumulative: Dict[int, int] = {}  # port -> cumulative drops

    def poll(self, ports: List[int]) -> Dict[int, int]:
        """
        Read /proc/net/udp and return cumulative drop counts per port.

        Returns {} (never raises) if /proc/net/udp is unavailable or
        unparseable — this must never affect packet processing. Format:
        each line's local_address field is "HEXADDR:HEXPORT"; the drops
        column is the 13th whitespace-separated field (index 12).
        """
        try:
            wanted_hex_ports = {f"{p:04X}": p for p in ports}
            result: Dict[int, int] = {}

            with open(self.PROC_UDP_PATH, "r") as f:
                next(f)  # skip header line
                for line in f:
                    fields = line.split()
                    if len(fields) < 13:
                        continue
                    local_address = fields[1]
                    try:
                        hex_port = local_address.split(":")[1]
                    except IndexError:
                        continue
                    if hex_port not in wanted_hex_ports:
                        continue
                    port = wanted_hex_ports[hex_port]
                    try:
                        drops = int(fields[12])
                    except (ValueError, IndexError):
                        continue
                    result[port] = result.get(port, 0) + drops

            with self._lock:
                self._cumulative.update(result)
                return dict(self._cumulative)

        except FileNotFoundError:
            logger.debug("/proc/net/udp not available (non-Linux or restricted environment)")
            return {}
        except Exception as e:
            logger.debug(f"Socket drop monitor poll failed: {e}")
            return {}


_socket_drop_monitor: Optional[SocketDropMonitor] = None


def get_socket_drop_monitor() -> SocketDropMonitor:
    """Get or create the global SocketDropMonitor singleton."""
    global _socket_drop_monitor
    if _socket_drop_monitor is None:
        _socket_drop_monitor = SocketDropMonitor()
    return _socket_drop_monitor


def get_socket_drops() -> Dict[int, int]:
    """
    Get current cumulative kernel-level UDP drop counts per listen port.

    Returns {} when eBPF capture mode is active, since this socket-level
    check is not meaningful there.
    """
    if ebpf_mode_active:
        return {}
    return get_socket_drop_monitor().poll(LISTEN_PORTS)


# =============================================================================
# BUFFER POOL (Reduce memory allocation overhead)
# =============================================================================

class BufferPool:
    """Memory pool for packet buffers"""
    
    def __init__(self, max_size: int = 5000, buffer_size: int = 4096):
        self.pool = deque(maxlen=max_size)
        self.buffer_size = buffer_size
        self.lock = threading.Lock()
    
    def get(self) -> bytearray:
        with self.lock:
            if self.pool:
                return self.pool.popleft()
        return bytearray(self.buffer_size)
    
    def put(self, buffer: bytearray):
        with self.lock:
            if len(self.pool) < self.pool.maxlen:
                self.pool.append(buffer)


_buffer_pool = BufferPool()


# =============================================================================
# UDP SOCKET LISTENERS
# =============================================================================

# Socket management
udp_sockets: Dict[int, socket.socket] = {}
udp_threads: Dict[int, Any] = {}  # port -> (future, stop_event)
udp_thread_pool: Optional[ThreadPoolExecutor] = None

# Mode flags
ebpf_mode_active = False


def set_ebpf_mode(active: bool):
    """Set eBPF mode flag"""
    global ebpf_mode_active
    ebpf_mode_active = active
    logger.info(f"eBPF mode: {'active' if active else 'inactive'}")


def _init_thread_pool():
    """Initialize thread pool for UDP listeners"""
    global udp_thread_pool
    if udp_thread_pool is None:
        udp_thread_pool = ThreadPoolExecutor(max_workers=16, 
                                              thread_name_prefix="UDPListener")


def start_udp_listener(port: int) -> bool:
    """
    Start UDP socket listener for a port.
    
    Optimized with:
    - Large receive buffers (64MB)
    - Non-blocking I/O with select
    - Batch enqueueing
    """
    global udp_sockets, udp_threads
    
    if ebpf_mode_active:
        return True
    
    if port in udp_sockets and udp_sockets[port]:
        return True
    
    _init_thread_pool()
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # Large receive buffer for burst handling
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 67108864)  # 64MB
        except Exception:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 16777216)  # 16MB fallback
        
        sock.bind((BIND_ADDRESS, port))
        sock.settimeout(1.0)
        
        udp_sockets[port] = sock
        
        # Per-port stop event for clean shutdown without affecting other ports
        port_stop_event = threading.Event()
        future = udp_thread_pool.submit(_udp_receive_loop, sock, port, port_stop_event)
        udp_threads[port] = (future, port_stop_event)
        
        logger.info(f"UDP listener started on {BIND_ADDRESS}:{port}")
        return True
        
    except socket.error as e:
        logger.warning(f"Could not bind to port {port}: {e}")
        return False
    except Exception as e:
        logger.error(f"Error starting UDP listener on port {port}: {e}")
        return False


def _udp_receive_loop(sock: socket.socket, port: int, port_stop_event: threading.Event):
    """
    Optimized UDP receive loop.
    
    Key optimizations:
    - Uses recvfrom_into() with buffer pool
    - Non-blocking queue insertion
    - Batch statistics updates
    - Minimal per-packet overhead
    
    Args:
        sock: The UDP socket to receive from
        port: The port number (for logging/stats)
        port_stop_event: Per-port stop event for clean shutdown
    """
    logger.info(f"UDP receive loop started for port {port}")
    
    local_queued = 0
    local_dropped = 0
    last_stats_time = time.time()
    
    # Check both global stop_event (service shutdown) and per-port stop event
    while not stop_event.is_set() and not port_stop_event.is_set():
        try:
            buffer = _buffer_pool.get()
            
            try:
                nbytes, addr = sock.recvfrom_into(buffer, len(buffer))
            except socket.timeout:
                _buffer_pool.put(buffer)
                continue
            except Exception as e:
                _buffer_pool.put(buffer)
                if not stop_event.is_set():
                    logger.debug(f"Receive error on port {port}: {e}")
                continue
            
            if nbytes > 0:
                packet_data = {
                    'src_ip': addr[0],
                    'dst_port': port,
                    'payload': bytes(buffer[:nbytes]),
                    '_capture_ts': time.monotonic(),
                }

                try:
                    packet_queue.put_nowait(packet_data)
                    local_queued += 1
                except queue.Full:
                    local_dropped += 1
            
            _buffer_pool.put(buffer)
            
            # Periodic stats update (every 5 seconds)
            now = time.time()
            if now - last_stats_time >= 5.0:
                _queue_stats.total_queued += local_queued
                if local_dropped > 0:
                    for _ in range(local_dropped):
                        _queue_stats.record_dropped()
                _queue_stats.update_depth(packet_queue.qsize())
                
                local_queued = 0
                local_dropped = 0
                last_stats_time = now
                
        except Exception as e:
            if not stop_event.is_set():
                logger.error(f"UDP loop error on port {port}: {e}")
            break
    
    # Final stats update
    _queue_stats.total_queued += local_queued
    for _ in range(local_dropped):
        _queue_stats.record_dropped()
    
    logger.info(f"UDP receive loop stopped for port {port}")


def start_all_udp_listeners() -> bool:
    """Start UDP listeners on all configured ports"""
    if ebpf_mode_active:
        return True
    
    success = True
    for port in LISTEN_PORTS:
        if not start_udp_listener(port):
            success = False
    return success


def restart_udp_listeners() -> bool:
    """Restart all UDP listeners"""
    if ebpf_mode_active:
        try:
            from .ebpf import update_ebpf_config
            update_ebpf_config(LISTEN_PORTS)
        except (ImportError, AttributeError):
            pass
        return True
    
    cleanup_udp_sockets()
    return start_all_udp_listeners()


def cleanup_udp_sockets():
    """Clean up UDP sockets.
    
    Signals all per-port receive loops to stop gracefully, then closes
    sockets and cleans up the thread pool. Uses per-port stop events
    instead of future.cancel() since cancel() only works for tasks that
    haven't started yet.
    """
    global udp_sockets, udp_threads, udp_thread_pool
    
    if ebpf_mode_active:
        return
    
    # Signal all receive loops to stop via their per-port stop events
    for port, entry in list(udp_threads.items()):
        if entry:
            future, port_stop_event = entry
            port_stop_event.set()
    
    # Close sockets to unblock any pending recv calls
    for port, sock in list(udp_sockets.items()):
        if sock:
            try:
                sock.close()
            except Exception:
                pass
    
    udp_sockets.clear()
    udp_threads.clear()
    
    if udp_thread_pool:
        try:
            udp_thread_pool.shutdown(wait=False)
        except Exception:
            pass
        udp_thread_pool = None


# =============================================================================
# PACKET PROCESSING (Integration with packet_processor module)
# =============================================================================

def start_packet_processors(num_workers: int = None) -> List[threading.Thread]:
    """
    Start packet processing workers.
    
    Uses the optimized processing module which provides:
    - Batch processing with adaptive batch sizes
    - Cached configuration (30s TTL)
    - Fast path for SNMPv2c (direct byte scanning)
    - Minimal per-packet logging
    - HA integration with forwarding control
    - Cache integration for trap replay
    - Granular statistics collection
    
    Args:
        num_workers: Number of worker threads (default: 2x CPU cores, max 32)
        
    Returns:
        List of worker threads
        
    Raises:
        ImportError: If processing module is not available
    """
    from .processing import start_workers
    
    # Start workers
    # IMPORTANT: Use keyword argument for num_workers to avoid
    # passing it as stop_event (which is the 2nd positional parameter)
    workers = start_workers(packet_queue, num_workers=num_workers)
    
    return workers


def start_queue_monitor() -> threading.Thread:
    """Start queue monitoring thread"""
    
    def monitor():
        while not stop_event.is_set():
            try:
                stats = get_queue_stats()
                depth = stats['current_depth']
                utilization = stats['utilization']
                
                # Log if queue is getting full
                if utilization > 0.8:
                    logger.warning(f"Queue high utilization: {utilization:.1%} "
                                  f"({depth}/{stats['queue_capacity']})")
                elif utilization > 0.5:
                    logger.info(f"Queue utilization: {utilization:.1%}")
                
                time.sleep(60)
            except Exception as e:
                logger.debug(f"Queue monitor error: {e}")
        
        logger.info("Queue monitor stopped")
    
    t = threading.Thread(target=monitor, daemon=True, name="QueueMonitor")
    t.start()
    return t


# =============================================================================
# PACKET FORWARDING (For Scapy capture integration)
# =============================================================================

def forward_trap(packet):
    """
    Queue packet from Scapy capture for processing.
    Used when sniff() mode is active.
    
    IMPORTANT: This only QUEUES packets - actual forwarding happens in workers.
    """
    try:
        if not (packet.haslayer(IP) and packet.haslayer(UDP)):
            return
        
        # Only process packets destined to our listen ports
        if packet[UDP].dport not in LISTEN_PORTS:
            return
        
        # SAFETY CHECK: Skip packets that came FROM us (shouldn't happen with
        # correct BPF filter, but defense in depth)
        if packet[UDP].sport == FORWARD_SOURCE_PORT:
            logger.debug(f"Skipping packet with our source port {FORWARD_SOURCE_PORT}")
            return
        
        packet_data = {
            'src_ip': packet[IP].src,
            'dst_port': packet[UDP].dport,
            'payload': bytes(packet[UDP].payload),
            '_capture_ts': time.monotonic(),
        }

        try:
            packet_queue.put_nowait(packet_data)
            _queue_stats.record_queued()
        except queue.Full:
            _queue_stats.record_dropped()
            
    except Exception as e:
        logger.debug(f"Error queuing packet: {e}")


def forward_packet(source_ip: str, payload: bytes, destinations: List):
    """
    Forward packet to destinations.
    Uses optimized forwarding from processing module if available.
    
    IMPORTANT: Uses FORWARD_SOURCE_PORT (not 162) to prevent
    forwarded packets from being re-captured.
    """
    try:
        from .processing import forward_packet as forward_packet_raw
        forward_packet_raw(source_ip, payload, destinations)
    except ImportError:
        # Fallback to Scapy-based forwarding
        _forward_packet_scapy(source_ip, payload, destinations)


def _forward_packet_scapy(source_ip: str, payload: bytes, destinations: List):
    """Scapy-based packet forwarding (fallback)"""
    from scapy.all import send
    
    # Use FORWARD_SOURCE_PORT to prevent re-capture loops
    template = IP(src=source_ip) / UDP(sport=FORWARD_SOURCE_PORT)
    
    for dst_ip, dst_port in destinations:
        try:
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
                
        except Exception as e:
            logger.error(f"Forward to {dst_ip}:{dst_port} failed: {e}")
