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

from .config import stop_event, LISTEN_PORTS, INTERFACE
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
        return {
            'current_depth': packet_queue.qsize(),
            'max_depth': self.max_depth,
            'total_queued': self.total_queued,
            'total_dropped': self.total_dropped,
            'full_events': self.full_events,
            'queue_capacity': QUEUE_MAX_SIZE,
            'utilization': packet_queue.qsize() / QUEUE_MAX_SIZE
        }


_queue_stats = QueueStats()


def get_queue_stats() -> Dict[str, Any]:
    """Get current queue statistics"""
    return _queue_stats.get_stats()


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
udp_threads: Dict[int, Any] = {}
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
        
        sock.bind(('0.0.0.0', port))
        sock.settimeout(1.0)
        
        udp_sockets[port] = sock
        
        future = udp_thread_pool.submit(_udp_receive_loop, sock, port)
        udp_threads[port] = future
        
        logger.info(f"UDP listener started on port {port}")
        return True
        
    except socket.error as e:
        logger.warning(f"Could not bind to port {port}: {e}")
        return False
    except Exception as e:
        logger.error(f"Error starting UDP listener on port {port}: {e}")
        return False


def _udp_receive_loop(sock: socket.socket, port: int):
    """
    Optimized UDP receive loop.
    
    Key optimizations:
    - Uses recvfrom_into() with buffer pool
    - Non-blocking queue insertion
    - Batch statistics updates
    - Minimal per-packet overhead
    """
    logger.info(f"UDP receive loop started for port {port}")
    
    local_queued = 0
    local_dropped = 0
    last_stats_time = time.time()
    
    while not stop_event.is_set():
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
                    'payload': bytes(buffer[:nbytes])
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
    """Clean up UDP sockets"""
    global udp_sockets, udp_threads, udp_thread_pool
    
    if ebpf_mode_active:
        return
    
    for port, future in list(udp_threads.items()):
        if future:
            future.cancel()
    
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
    Uses the optimized packet_processor module.
    """
    try:
        from .packet_processor import start_workers, start_stats_monitor
        
        # Start workers
        workers = start_workers(packet_queue, num_workers)
        
        # Start stats monitor
        start_stats_monitor(interval=30.0)
        
        return workers
        
    except ImportError:
        # Fallback to legacy worker implementation
        logger.warning("Using legacy packet processor (packet_processor module not found)")
        return _start_legacy_workers(num_workers or 4)


def _start_legacy_workers(num_workers: int) -> List[threading.Thread]:
    """Legacy worker implementation for backward compatibility"""
    from .snmp import process_captured_packet
    
    def worker(worker_id):
        logger.info(f"Legacy worker {worker_id} started")
        
        while not stop_event.is_set():
            try:
                packet = packet_queue.get(timeout=0.5)
                
                # CRITICAL: Check HA state before processing
                # Only the PRIMARY node should forward traps
                if not is_forwarding_enabled():
                    logger.debug("Packet received but forwarding disabled by HA (secondary mode)")
                    packet_queue.task_done()
                    continue
                
                process_captured_packet(packet)
                notify_trap_processed()  # Notify HA system of activity
                packet_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Worker {worker_id} error: {e}")
        
        logger.info(f"Legacy worker {worker_id} stopped")
    
    workers = []
    for i in range(num_workers):
        t = threading.Thread(target=worker, args=(i,), daemon=True)
        t.start()
        workers.append(t)
    
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
            'payload': bytes(packet[UDP].payload)
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
    Uses optimized forwarding from packet_processor if available.
    
    IMPORTANT: Uses FORWARD_SOURCE_PORT (not 162) to prevent
    forwarded packets from being re-captured.
    """
    try:
        from .packet_processor import forward_fast
        forward_fast(source_ip, payload, destinations)
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
