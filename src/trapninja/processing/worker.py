#!/usr/bin/env python3
"""
TrapNinja Packet Processing Workers

High-performance worker threads for packet processing.

Key optimizations:
- Batch processing with adaptive batch sizes
- Cached configuration (30s TTL)
- Minimal per-packet logging
- Efficient queue draining

Author: TrapNinja Team
Version: 2.0.0
"""

import time
import queue
import threading
import logging
from typing import Optional, List, Dict, Any

from .parser import is_snmpv2c, is_snmpv3, extract_trap_oid_fast, parse_snmp_packet
from .forwarder import forward_packet
from .stats import ProcessingStats, StatsCollector, get_global_stats

# Import HA functions for forwarding control
# CRITICAL: These functions control whether this node should forward traps
try:
    from ..ha import is_forwarding_enabled, notify_trap_processed
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
            import logging
            logging.getLogger("trapninja").warning(
                "HA module not available - forwarding enabled by default"
            )
        return True
    
    def notify_trap_processed():
        pass

logger = logging.getLogger("trapninja")


# =============================================================================
# CONFIGURATION CACHE
# =============================================================================

class ConfigCache:
    """
    Thread-safe configuration cache with TTL.
    
    Reduces import and dict access overhead on hot path.
    """
    
    def __init__(self, ttl: float = 30.0):
        self.ttl = ttl
        self._cache: Optional[Dict] = None
        self._cache_time: float = 0
        self._lock = threading.Lock()
    
    def get(self) -> Dict:
        """Get cached configuration, reloading if stale."""
        now = time.time()
        
        # Fast path: cache is valid
        if self._cache and (now - self._cache_time) < self.ttl:
            return self._cache
        
        # Slow path: reload config
        with self._lock:
            # Double-check after acquiring lock
            if self._cache and (now - self._cache_time) < self.ttl:
                return self._cache
            
            try:
                from ..config import (
                    destinations, blocked_traps, blocked_dest,
                    blocked_ips, redirected_ips, redirected_oids,
                    redirected_destinations
                )
                
                self._cache = {
                    'destinations': destinations,
                    'blocked_traps': blocked_traps,
                    'blocked_dest': blocked_dest,
                    'blocked_ips': blocked_ips,
                    'redirected_ips': redirected_ips,
                    'redirected_oids': redirected_oids,
                    'redirected_destinations': redirected_destinations
                }
            except ImportError:
                # Minimal fallback
                self._cache = {
                    'destinations': [],
                    'blocked_traps': set(),
                    'blocked_dest': [],
                    'blocked_ips': set(),
                    'redirected_ips': {},
                    'redirected_oids': {},
                    'redirected_destinations': {}
                }
            
            self._cache_time = now
        
        return self._cache
    
    def invalidate(self):
        """Force cache reload on next access."""
        self._cache_time = 0


# Global config cache
_config_cache = ConfigCache()


# =============================================================================
# PACKET WORKER
# =============================================================================

class PacketWorker:
    """
    High-performance packet processing worker.
    
    Optimizations:
    - Batch processing (reduces queue overhead)
    - Cached configuration
    - Fast path for SNMPv2c
    - Minimal logging
    """
    
    def __init__(
        self,
        worker_id: int,
        packet_queue: queue.Queue,
        stop_event: threading.Event,
        batch_size: int = 50,
        timeout: float = 0.5
    ):
        """
        Initialize packet worker.
        
        Args:
            worker_id: Unique worker identifier
            packet_queue: Queue to read packets from
            stop_event: Event to signal shutdown
            batch_size: Maximum packets per batch
            timeout: Timeout for queue reads
        """
        self.worker_id = worker_id
        self.packet_queue = packet_queue
        self.stop_event = stop_event
        self.batch_size = batch_size
        self.timeout = timeout
        
        self.stats = StatsCollector()
        self._thread: Optional[threading.Thread] = None
        self._packets_since_log = 0
        self._log_interval = 1000
    
    def start(self) -> threading.Thread:
        """
        Start worker thread.
        
        Returns:
            Worker thread
        """
        self._thread = threading.Thread(
            target=self._run,
            daemon=True,
            name=f"PacketWorker-{self.worker_id}"
        )
        self._thread.start()
        logger.info(f"Packet worker {self.worker_id} started")
        return self._thread
    
    def _run(self):
        """Main worker loop."""
        batch = []
        
        while not self.stop_event.is_set():
            try:
                # Collect a batch
                deadline = time.time() + self.timeout
                
                while len(batch) < self.batch_size:
                    remaining = deadline - time.time()
                    if remaining <= 0:
                        break
                    
                    try:
                        packet = self.packet_queue.get(
                            timeout=min(remaining, 0.05)
                        )
                        batch.append(packet)
                    except queue.Empty:
                        break
                
                # Process batch if we have packets
                if batch:
                    self._process_batch(batch)
                    batch.clear()
                    
            except Exception as e:
                logger.error(f"Worker {self.worker_id} error: {e}")
                batch.clear()
        
        # Final flush
        self.stats.flush()
        logger.info(f"Packet worker {self.worker_id} stopped")
    
    def _process_batch(self, batch: List[Dict[str, Any]]):
        """Process a batch of packets."""
        for packet in batch:
            self._process_packet(packet)
            try:
                self.packet_queue.task_done()
            except ValueError:
                pass
        
        self._packets_since_log += len(batch)
        
        # Periodic logging
        if self._packets_since_log >= self._log_interval:
            stats = get_global_stats()
            if stats.should_log_summary():
                logger.info(
                    f"Processing: rate={stats.processing_rate:.1f}/s, "
                    f"total={stats.packets_processed}, "
                    f"fast_path={stats.fast_path_ratio:.1f}%"
                )
            self._packets_since_log = 0
    
    def _process_packet(self, packet_data: Dict[str, Any]):
        """
        Process a single packet.
        
        Uses fast path for SNMPv2c, slow path for others.
        
        IMPORTANT: HA check happens here at processing time, not at
        capture time. This ensures consistent behavior across all
        capture modes (sniff, socket, eBPF).
        """
        try:
            # CRITICAL: Check HA state FIRST before any processing
            # Only the PRIMARY node should forward traps
            if not is_forwarding_enabled():
                # Track blocked packets for monitoring
                self.stats.increment_ha_blocked()
                
                # Log periodically to help diagnose issues without flooding
                if self.stats.ha_blocked_count % 1000 == 1:  # First and every 1000th
                    logger.info(
                        f"HA: Packets blocked (secondary mode): "
                        f"{self.stats.ha_blocked_count} total"
                    )
                return  # Drop packet - we're in secondary mode
            
            config = _config_cache.get()
            source_ip = packet_data['src_ip']
            payload = packet_data['payload']
            
            self.stats.increment_processed()
            
            # Quick IP block check
            if source_ip in config['blocked_ips']:
                self.stats.increment_blocked()
                return
            
            # Try fast path for SNMPv2c
            trap_oid = None
            if is_snmpv2c(payload):
                trap_oid = extract_trap_oid_fast(payload)
                
                if trap_oid:
                    self.stats.record_fast_path()
                    
                    # Check OID blocking
                    if trap_oid in config['blocked_traps']:
                        self.stats.increment_blocked()
                        if config['blocked_dest']:
                            forward_packet(source_ip, payload, config['blocked_dest'])
                        return
                    
                    # Check IP redirection
                    if source_ip in config['redirected_ips']:
                        tag = config['redirected_ips'][source_ip]
                        if tag in config['redirected_destinations']:
                            forward_packet(
                                source_ip, payload,
                                config['redirected_destinations'][tag]
                            )
                            self.stats.increment_redirected()
                            notify_trap_processed()  # Notify HA system of activity
                            return
                    
                    # Check OID redirection
                    if trap_oid in config['redirected_oids']:
                        tag = config['redirected_oids'][trap_oid]
                        if tag in config['redirected_destinations']:
                            forward_packet(
                                source_ip, payload,
                                config['redirected_destinations'][tag]
                            )
                            self.stats.increment_redirected()
                            notify_trap_processed()  # Notify HA system of activity
                            return
                    
                    # Forward to normal destinations
                    if config['destinations']:
                        forward_packet(source_ip, payload, config['destinations'])
                        self.stats.increment_forwarded()
                        notify_trap_processed()  # Notify HA system of activity
                    
                    return
            
            # Slow path
            self.stats.record_slow_path()
            self._process_slow_path(packet_data, config)
            
        except Exception as e:
            self.stats.increment_error()
            logger.debug(f"Worker {self.worker_id} packet error: {e}")
    
    def _process_slow_path(self, packet_data: Dict[str, Any], config: Dict):
        """Process packet using full parsing (slow path)."""
        source_ip = packet_data['src_ip']
        payload = packet_data['payload']
        
        # CRITICAL: Check for SNMPv3 at byte level FIRST
        # Scapy's SNMP parser cannot handle SNMPv3 - it will fail or return wrong results
        if is_snmpv3(payload):
            logger.debug(f"SNMPv3 packet detected from {source_ip} ({len(payload)} bytes)")
            self._process_snmpv3(packet_data, config)
            return
        
        # Try Scapy parsing for v1/v2c
        snmp_packet, version = parse_snmp_packet(payload)
        
        # Parsing failed - forward anyway
        if not snmp_packet:
            if config['destinations']:
                forward_packet(source_ip, payload, config['destinations'])
                self.stats.increment_forwarded()
                notify_trap_processed()  # Notify HA system of activity
            return
        
        # Extract OID using slow method
        if version == "v1":
            from .parser import get_enterprise_oid
            trap_oid = get_enterprise_oid(snmp_packet)
        else:
            from .parser import get_snmptrap_oid
            trap_oid = get_snmptrap_oid(snmp_packet)
        
        if not trap_oid:
            if config['destinations']:
                forward_packet(source_ip, payload, config['destinations'])
                self.stats.increment_forwarded()
                notify_trap_processed()  # Notify HA system of activity
            return
        
        # Check blocking
        if trap_oid in config['blocked_traps']:
            self.stats.increment_blocked()
            if config['blocked_dest']:
                forward_packet(source_ip, payload, config['blocked_dest'])
            return
        
        # Check redirection
        if source_ip in config['redirected_ips']:
            tag = config['redirected_ips'][source_ip]
            if tag in config['redirected_destinations']:
                forward_packet(
                    source_ip, payload,
                    config['redirected_destinations'][tag]
                )
                self.stats.increment_redirected()
                notify_trap_processed()  # Notify HA system of activity
                return
        
        if trap_oid in config['redirected_oids']:
            tag = config['redirected_oids'][trap_oid]
            if tag in config['redirected_destinations']:
                forward_packet(
                    source_ip, payload,
                    config['redirected_destinations'][tag]
                )
                self.stats.increment_redirected()
                notify_trap_processed()  # Notify HA system of activity
                return
        
        # Forward normally
        if config['destinations']:
            forward_packet(source_ip, payload, config['destinations'])
            self.stats.increment_forwarded()
            notify_trap_processed()  # Notify HA system of activity
    
    def _process_snmpv3(self, packet_data: Dict[str, Any], config: Dict):
        """Process SNMPv3 packet."""
        source_ip = packet_data['src_ip']
        payload = packet_data['payload']
        
        logger.debug(f"Processing SNMPv3 trap from {source_ip} ({len(payload)} bytes)")
        
        # Try to extract engine ID and username for logging
        try:
            from ..snmpv3_decryption import extract_engine_id_from_bytes, extract_username_from_bytes
            engine_id = extract_engine_id_from_bytes(payload)
            username = extract_username_from_bytes(payload)
            logger.debug(f"SNMPv3 trap: engine_id={engine_id}, username={username}")
        except Exception as e:
            logger.debug(f"Could not extract SNMPv3 metadata: {e}")
            engine_id = None
            username = None
        
        # Try decryption
        try:
            from ..snmpv3_decryption import get_snmpv3_decryptor
            decryptor = get_snmpv3_decryptor()
            
            if decryptor:
                logger.debug(f"Attempting SNMPv3 decryption for engine {engine_id}")
                result = decryptor.decrypt_snmpv3_trap(payload)
                
                if result:
                    result_engine_id, trap_data = result
                    logger.info(
                        f"SNMPv3 decrypted from {source_ip}: engine={result_engine_id}, "
                        f"user={trap_data.get('username', 'N/A')}, "
                        f"varbinds={len(trap_data.get('varbinds', []))}"
                    )
                    
                    v2c_payload = decryptor.convert_to_snmpv2c(trap_data, "public")
                    
                    if v2c_payload and len(v2c_payload) > 20:
                        logger.debug(
                            f"SNMPv3->v2c conversion: {len(payload)} -> {len(v2c_payload)} bytes"
                        )
                        if config['destinations']:
                            forward_packet(source_ip, v2c_payload, config['destinations'])
                            self.stats.increment_forwarded()
                            notify_trap_processed()
                        return
                    else:
                        logger.warning(
                            f"SNMPv3->v2c conversion produced invalid payload: "
                            f"{len(v2c_payload) if v2c_payload else 0} bytes"
                        )
                else:
                    logger.warning(
                        f"SNMPv3 decryption failed for {source_ip}: "
                        f"engine={engine_id}, user={username}"
                    )
            else:
                logger.warning("SNMPv3 decryptor not initialized")
                
        except ImportError as e:
            logger.warning(f"SNMPv3 module not available: {e}")
        except Exception as e:
            logger.warning(f"SNMPv3 processing error: {e}")
            import traceback
            logger.debug(traceback.format_exc())
        
        # Forward original packet if decryption failed or not available
        # Note: This forwards encrypted payload which may not be useful
        logger.debug(f"Forwarding original SNMPv3 packet from {source_ip} (no decryption)")
        if config['destinations']:
            forward_packet(source_ip, payload, config['destinations'])
            self.stats.increment_forwarded()
            notify_trap_processed()


# =============================================================================
# WORKER MANAGEMENT
# =============================================================================

_workers: List[PacketWorker] = []


def start_workers(
    packet_queue: queue.Queue,
    stop_event: threading.Event = None,
    num_workers: int = None
) -> List[threading.Thread]:
    """
    Start packet processing workers.
    
    Args:
        packet_queue: Queue to process packets from
        stop_event: Event to signal shutdown
        num_workers: Number of workers (default: 2x CPU cores, max 32)
        
    Returns:
        List of worker threads
    """
    global _workers
    import multiprocessing
    
    if stop_event is None:
        try:
            from ..config import stop_event as config_stop_event
            stop_event = config_stop_event
        except ImportError:
            stop_event = threading.Event()
    
    if num_workers is None:
        cpu_count = multiprocessing.cpu_count()
        num_workers = min(cpu_count * 2, 32)
    
    threads = []
    for i in range(num_workers):
        worker = PacketWorker(i, packet_queue, stop_event)
        _workers.append(worker)
        threads.append(worker.start())
    
    logger.info(f"Started {num_workers} packet processing workers")
    return threads


def get_processor_stats() -> Dict[str, Any]:
    """Get current processor statistics."""
    return get_global_stats().to_dict()


def reset_processor_stats():
    """Reset processor statistics."""
    from .stats import reset_global_stats
    reset_global_stats()
