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

# Import granular statistics collector
try:
    from ..stats import get_stats_collector as get_granular_stats
    GRANULAR_STATS_AVAILABLE = True
except ImportError:
    GRANULAR_STATS_AVAILABLE = False
    def get_granular_stats():
        return None

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
        self._granular_collector = None  # Cached reference to granular stats
    
    def _record_granular_stats(self, source_ip: str, oid: str = None,
                                action: str = 'forwarded', destination: str = None):
        """
        Record trap in granular statistics collector.
        
        Args:
            source_ip: Source IP address
            oid: Trap OID (if extracted)
            action: 'forwarded', 'blocked', 'redirected', 'dropped'
            destination: Destination tag or "ip:port"
        """
        # Lazy initialization of collector reference
        if self._granular_collector is None:
            if GRANULAR_STATS_AVAILABLE:
                self._granular_collector = get_granular_stats()
                if self._granular_collector:
                    logger.debug(f"Worker {self.worker_id}: Got granular stats collector")
                else:
                    logger.warning(f"Worker {self.worker_id}: get_granular_stats() returned None - stats not initialized?")
            else:
                # Log once per worker that granular stats are not available
                if not hasattr(self, '_granular_warning_logged'):
                    logger.warning(f"Worker {self.worker_id}: GRANULAR_STATS_AVAILABLE is False - import failed")
                    self._granular_warning_logged = True
        
        if self._granular_collector:
            try:
                self._granular_collector.record_trap(
                    source_ip=source_ip,
                    oid=oid,
                    action=action,
                    destination=destination
                )
            except Exception as e:
                # Don't let stats recording errors affect packet processing
                logger.debug(f"Error recording granular stats: {e}")
    
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
            source_ip = packet_data['src_ip']
            payload = packet_data['payload']
            
            # Always count packets received (for diagnostics)
            self.stats.increment_processed()
            
            # CRITICAL: Check HA state before forwarding
            # Only the PRIMARY node should forward traps
            # But ALWAYS record stats so we can see what's arriving
            if not is_forwarding_enabled():
                # Track blocked packets for monitoring
                self.stats.increment_ha_blocked()
                
                # Record in granular stats as 'ha_blocked' so it shows up in reports
                self._record_granular_stats(source_ip, None, 'ha_blocked')
                
                # Log periodically to help diagnose issues without flooding
                if self.stats.ha_blocked_count % 1000 == 1:  # First and every 1000th
                    logger.info(
                        f"HA: Packets blocked (secondary mode): "
                        f"{self.stats.ha_blocked_count} total"
                    )
                return  # Drop packet - we're in secondary mode
            
            config = _config_cache.get()
            
            # DEBUG: Log packet info for troubleshooting
            if logger.isEnabledFor(logging.DEBUG):
                # Check SNMP version at byte level
                snmp_ver = "unknown"
                if len(payload) >= 5 and payload[0] == 0x30:
                    # Try to get version
                    idx = 1
                    if payload[idx] & 0x80:
                        idx += (payload[idx] & 0x7f) + 1
                    else:
                        idx += 1
                    if idx < len(payload) and payload[idx] == 0x02:  # INTEGER
                        idx += 1
                        if idx < len(payload):
                            vlen = payload[idx]
                            idx += 1
                            if idx + vlen <= len(payload):
                                ver = int.from_bytes(payload[idx:idx+vlen], 'big')
                                snmp_ver = {0: "v1", 1: "v2c", 3: "v3"}.get(ver, f"v{ver}")
                
                logger.debug(
                    f"Processing packet from {source_ip}: {len(payload)} bytes, "
                    f"SNMP {snmp_ver}, first bytes: {payload[:10].hex()}"
                )
            
            # Quick IP block check
            if source_ip in config['blocked_ips']:
                self.stats.increment_blocked()
                self._record_granular_stats(source_ip, None, 'blocked')
                return
            
            # Check for SNMPv3 FIRST before trying v2c fast path
            # This is critical because is_snmpv2c() might not correctly reject all v3 packets
            if is_snmpv3(payload):
                logger.debug(f"SNMPv3 detected from {source_ip}, routing to v3 handler")
                self.stats.record_slow_path()
                self._process_snmpv3(packet_data, config)
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
                        self._record_granular_stats(source_ip, trap_oid, 'blocked')
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
                            self._record_granular_stats(source_ip, trap_oid, 'redirected', tag)
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
                            self._record_granular_stats(source_ip, trap_oid, 'redirected', tag)
                            notify_trap_processed()  # Notify HA system of activity
                            return
                    
                    # Forward to normal destinations
                    if config['destinations']:
                        forward_packet(source_ip, payload, config['destinations'])
                        self.stats.increment_forwarded()
                        self._record_granular_stats(source_ip, trap_oid, 'forwarded', 'default')
                        notify_trap_processed()  # Notify HA system of activity
                    
                    return
            
            # Slow path for everything else (v1, malformed, etc.)
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
                self._record_granular_stats(source_ip, None, 'forwarded', 'default')
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
                self._record_granular_stats(source_ip, None, 'forwarded', 'default')
                notify_trap_processed()  # Notify HA system of activity
            return
        
        # Check blocking
        if trap_oid in config['blocked_traps']:
            self.stats.increment_blocked()
            self._record_granular_stats(source_ip, trap_oid, 'blocked')
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
                self._record_granular_stats(source_ip, trap_oid, 'redirected', tag)
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
                self._record_granular_stats(source_ip, trap_oid, 'redirected', tag)
                notify_trap_processed()  # Notify HA system of activity
                return
        
        # Forward normally
        if config['destinations']:
            forward_packet(source_ip, payload, config['destinations'])
            self.stats.increment_forwarded()
            self._record_granular_stats(source_ip, trap_oid, 'forwarded', 'default')
            notify_trap_processed()  # Notify HA system of activity
    
    def _process_snmpv3(self, packet_data: Dict[str, Any], config: Dict):
        """
        Process SNMPv3 packet with decryption support.
        
        Flow:
        1. Extract metadata (engine_id, username) for logging/credential lookup
        2. Attempt decryption if credentials are available
        3. If decryption succeeds, convert to v2c and forward
        4. If decryption fails but we have NO credentials, forward original v3
        5. If decryption fails but we HAVE credentials, drop packet (config controls)
        
        The key insight is: if we have credentials configured for an engine but
        decryption/conversion fails, we should NOT forward the encrypted v3 packet
        as it's unlikely to be useful to NOC systems expecting v2c.
        """
        source_ip = packet_data['src_ip']
        payload = packet_data['payload']
        
        logger.debug(f"Processing SNMPv3 trap from {source_ip} ({len(payload)} bytes)")
        
        # Try to extract engine ID and username for logging/credential lookup
        engine_id = None
        username = None
        try:
            from ..snmpv3_decryption import extract_engine_id_from_bytes, extract_username_from_bytes
            engine_id = extract_engine_id_from_bytes(payload)
            username = extract_username_from_bytes(payload)
            logger.debug(f"SNMPv3 trap: engine_id={engine_id}, username={username}")
        except Exception as e:
            logger.debug(f"Could not extract SNMPv3 metadata: {e}")
        
        # Track whether we have credentials for this engine
        # This determines fallback behavior when decryption fails
        have_credentials = False
        decryption_attempted = False
        
        # Try decryption
        try:
            from ..snmpv3_decryption import get_snmpv3_decryptor
            from ..snmpv3_credentials import get_credential_store
            
            decryptor = get_snmpv3_decryptor()
            
            if decryptor:
                # Check if we have credentials for this engine BEFORE attempting decryption
                if engine_id:
                    credential_store = get_credential_store()
                    users = credential_store.get_users_for_engine(engine_id.lower())
                    have_credentials = len(users) > 0
                    if have_credentials:
                        logger.debug(
                            f"Found {len(users)} credential(s) for engine {engine_id}"
                        )
                
                logger.debug(f"Attempting SNMPv3 decryption for engine {engine_id}")
                decryption_attempted = True
                result = decryptor.decrypt_snmpv3_trap(payload)
                
                if result:
                    result_engine_id, trap_data = result
                    # Extract username from USM params if available in trap_data
                    decrypted_username = trap_data.get('username', username or 'N/A')
                    varbind_count = len(trap_data.get('varbinds', []))
                    
                    logger.info(
                        f"SNMPv3 decrypted from {source_ip}: engine={result_engine_id}, "
                        f"user={decrypted_username}, varbinds={varbind_count}"
                    )
                    
                    # Convert to SNMPv2c format
                    v2c_payload = decryptor.convert_to_snmpv2c(trap_data, "public")
                    
                    if v2c_payload and len(v2c_payload) > 20:
                        logger.debug(
                            f"SNMPv3->v2c conversion successful: "
                            f"{len(payload)} -> {len(v2c_payload)} bytes"
                        )
                        # Log first bytes to verify it's valid SNMP
                        logger.debug(
                            f"v2c payload first 20 bytes: {v2c_payload[:20].hex()}"
                        )
                        
                        # Determine destination based on redirection rules
                        # Check IP redirection first (same as v2c path)
                        if source_ip in config['redirected_ips']:
                            tag = config['redirected_ips'][source_ip]
                            if tag in config['redirected_destinations']:
                                dest_list = config['redirected_destinations'][tag]
                                logger.info(
                                    f"Forwarding decrypted v2c trap from {source_ip} "
                                    f"({len(v2c_payload)} bytes) to REDIRECTED destination '{tag}' "
                                    f"({len(dest_list)} hosts)"
                                )
                                forward_packet(source_ip, v2c_payload, dest_list)
                                self.stats.increment_redirected()
                                self._record_granular_stats(
                                    source_ip, None, 'forwarded_v3_decrypted', tag
                                )
                                notify_trap_processed()
                                return
                        
                        # Default destinations
                        if config['destinations']:
                            logger.info(
                                f"Forwarding decrypted v2c trap from {source_ip} "
                                f"({len(v2c_payload)} bytes) to {len(config['destinations'])} destination(s)"
                            )
                            forward_packet(source_ip, v2c_payload, config['destinations'])
                            self.stats.increment_forwarded()
                            self._record_granular_stats(
                                source_ip, None, 'forwarded_v3_decrypted', 'default'
                            )
                            notify_trap_processed()
                        return
                    else:
                        # CRITICAL FIX: Log error and return - do NOT fall through!
                        # The decryption worked but v2c conversion failed.
                        # This is a bug in the conversion code, not missing credentials.
                        logger.error(
                            f"SNMPv3->v2c conversion FAILED for {source_ip}: "
                            f"produced {len(v2c_payload) if v2c_payload else 0} bytes "
                            f"(expected >20). Decrypted data: varbinds={varbind_count}, "
                            f"request_id={trap_data.get('request_id', 'N/A')}. "
                            f"Packet will be DROPPED to avoid forwarding encrypted v3."
                        )
                        # Record as conversion failure
                        self._record_granular_stats(
                            source_ip, None, 'v3_conversion_failed', None
                        )
                        self.stats.increment_error()
                        return  # CRITICAL: Return here to prevent v3 fallback
                else:
                    # Decryption failed - result was None
                    logger.warning(
                        f"SNMPv3 decryption failed for {source_ip}: "
                        f"engine={engine_id}, user={username}"
                    )
                    # If we have credentials but decryption failed, don't forward v3
                    if have_credentials:
                        logger.warning(
                            f"Credentials exist for engine {engine_id} but decryption "
                            f"failed - check auth/priv settings. Packet DROPPED."
                        )
                        self._record_granular_stats(
                            source_ip, None, 'v3_decryption_failed', None
                        )
                        self.stats.increment_error()
                        return  # Don't forward encrypted v3 when we have credentials
            else:
                logger.warning("SNMPv3 decryptor not initialized")
                
        except ImportError as e:
            logger.warning(f"SNMPv3 module not available: {e}")
        except Exception as e:
            logger.warning(f"SNMPv3 processing error: {e}")
            import traceback
            logger.debug(traceback.format_exc())
            # If we have credentials but got an exception, don't forward v3
            if have_credentials:
                logger.warning(
                    f"Exception during decryption with credentials for engine "
                    f"{engine_id} - packet DROPPED"
                )
                self._record_granular_stats(
                    source_ip, None, 'v3_decryption_error', None
                )
                self.stats.increment_error()
                return
        
        # Fallback: Forward original v3 packet ONLY if:
        # 1. No credentials exist for this engine (we can't decrypt anyway)
        # 2. Decryptor wasn't initialized (module issue)
        # 
        # If we have credentials but failed, we already returned above.
        # Forwarding encrypted v3 when we expected to decrypt is usually not useful.
        if have_credentials:
            # This shouldn't happen - we should have returned above
            logger.error(
                f"BUG: Reached v3 fallback with credentials for {source_ip}. "
                f"This indicates a logic error. Packet DROPPED."
            )
            self._record_granular_stats(source_ip, None, 'v3_logic_error', None)
            self.stats.increment_error()
            return
        
        logger.debug(
            f"Forwarding original SNMPv3 packet from {source_ip} "
            f"(no credentials configured for engine {engine_id})"
        )
        if config['destinations']:
            forward_packet(source_ip, payload, config['destinations'])
            self.stats.increment_forwarded()
            self._record_granular_stats(source_ip, None, 'forwarded_v3_passthrough', 'default')
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
