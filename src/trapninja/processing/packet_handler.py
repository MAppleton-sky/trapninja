#!/usr/bin/env python3
"""
TrapNinja Packet Handler

Packet processing pipeline for SNMP trap forwarding. Implements the
complete trap lifecycle: version detection → filtering → redirection →
forwarding → stats → cache.

This module provides the PacketHandler mixin that encapsulates all
packet processing logic, keeping it separate from worker thread
management. The PacketWorker class in worker.py inherits from this
to combine processing with threading.

Processing paths:
    Fast path: SNMPv2c → byte-level OID extraction → forward (no Scapy)
    Slow path: v1/malformed → Scapy parsing → forward
    SNMPv3 path: decrypt → convert to v2c → re-enter pipeline

Author: TrapNinja Team
Version: 2.0.0
"""

import logging
import base64
import functools
import ipaddress
from datetime import datetime
from typing import Optional, Dict, Any

from .parser import is_snmpv2c, is_snmpv3, extract_trap_oid_fast, parse_snmp_packet
from .forwarder import forward_packet
from .config_cache import _config_cache
from .stats import get_global_stats

# Import optional modules registry for lazy loading with automatic fallbacks
from ..core.optional_modules import modules

logger = logging.getLogger("trapninja")


def _is_ip_blocked_by_range(source_ip: str, ranges: list) -> bool:
    """
    Return True if source_ip falls within any network in ranges.

    Fast path: returns False immediately if ranges is empty — no cache
    lookup, no ipaddress parsing, no iteration. This is the common case
    for deployments that have not configured any CIDR ranges.

    Delegates to _is_ip_blocked_by_range_impl (LRU-cached) by converting
    the list to a tuple (hashable) and passing id(ranges) as a cache-bust
    key. When load_config() replaces the list object, the id() changes and
    stale cache entries are naturally bypassed.

    Args:
        source_ip: Source IP string (e.g. "10.0.0.5")
        ranges:    List of ipaddress.IPv4Network / IPv6Network objects

    Returns:
        True if source_ip is contained in any range, False otherwise.
    """
    if not ranges:
        return False
    return _is_ip_blocked_by_range_impl(source_ip, id(ranges), tuple(ranges))


@functools.lru_cache(maxsize=65536)
def _is_ip_blocked_by_range_impl(source_ip: str, ranges_id: int,
                                  ranges: tuple) -> bool:
    """
    Cached implementation of IP-in-range check.

    Args:
        source_ip:  Source IP string
        ranges_id:  id() of the original list (cache-bust on config reload)
        ranges:     Tuple of IPv4Network/IPv6Network objects

    Returns:
        True if source_ip is contained in any range, False otherwise.
    """
    try:
        addr = ipaddress.ip_address(source_ip)
        return any(addr in net for net in ranges)
    except ValueError:
        return False


def _get_redirect_tag_from_ranges(source_ip: str, ip_ranges: list) -> str:
    """
    Return the redirection tag for source_ip from ip_ranges, or "" if none.

    ip_ranges is a list of (IPv4Network|IPv6Network, tag: str) tuples.

    Fast path: returns "" immediately if ip_ranges is empty.

    Uses the same id()-based cache-bust pattern as _is_ip_blocked_by_range.

    Args:
        source_ip:  Source IP string
        ip_ranges:  List of (network, tag) tuples from
                    config['redirected_ip_ranges']

    Returns:
        First matching tag string, or "" if no match.
    """
    if not ip_ranges:
        return ""
    return _get_redirect_tag_from_ranges_impl(source_ip, id(ip_ranges),
                                              tuple(ip_ranges))


@functools.lru_cache(maxsize=65536)
def _get_redirect_tag_from_ranges_impl(source_ip: str, ranges_id: int,
                                       ip_ranges: tuple) -> str:
    """
    Cached implementation of IP-range-to-tag lookup.

    Args:
        source_ip:  Source IP string
        ranges_id:  id() of the original list (cache-bust on config reload)
        ip_ranges:  Tuple of (network, tag) tuples

    Returns:
        First matching tag string, or "" if no match.
    """
    try:
        addr = ipaddress.ip_address(source_ip)
        for net, tag in ip_ranges:
            if addr in net:
                return tag
    except ValueError:
        pass
    return ""


class PacketHandler:
    """
    Mixin providing SNMP trap processing pipeline methods.

    Expects the inheriting class to provide:
        - self.worker_id: int
        - self.stats: StatsCollector instance

    Initialises its own granular stats and cache references lazily
    on first use.
    """

    def _init_handler(self):
        """Initialise packet handler state. Call from subclass __init__."""
        self._granular_collector = None
        self._granular_retries = 0
        self._granular_max_retries = 10
        self._cache = None
        self._cache_checked = False

    # -----------------------------------------------------------------
    # Bookkeeping helpers
    # -----------------------------------------------------------------

    def _record_granular_stats(self, source_ip: str, oid: str = None,
                                action: str = 'forwarded', destination: str = None):
        """
        Record trap in granular statistics collector.

        Uses lazy initialisation with retry logic to handle stats module
        startup timing.

        Args:
            source_ip: Source IP address
            oid: Trap OID (if extracted)
            action: 'forwarded', 'blocked', 'redirected', 'dropped', etc.
            destination: Destination tag or "ip:port"
        """
        # Lazy initialisation of collector reference with retry logic
        if self._granular_collector is None:
            if modules.stats.available:
                self._granular_collector = modules.stats.get_collector()
                if self._granular_collector:
                    if self._granular_retries > 0:
                        logger.debug(
                            f"Worker {self.worker_id}: Got granular stats collector "
                            f"after {self._granular_retries} retries"
                        )
                    else:
                        logger.debug(
                            f"Worker {self.worker_id}: Got granular stats collector"
                        )
                else:
                    self._granular_retries += 1
                    if self._granular_retries == self._granular_max_retries:
                        logger.warning(
                            f"Worker {self.worker_id}: get_collector() still returning "
                            f"None after {self._granular_retries} attempts - stats may "
                            f"not be initialized"
                        )
            else:
                if not hasattr(self, '_granular_warning_logged'):
                    logger.debug(
                        f"Worker {self.worker_id}: stats module not available - "
                        f"granular statistics disabled"
                    )
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

    def _store_trap_in_cache(self, source_ip: str, payload: bytes,
                              trap_oid: str = None, destination: str = 'default'):
        """
        Store trap in Redis cache for replay capability.

        Caching is non-blocking — failures never affect forwarding.

        Args:
            source_ip: Source IP address of the trap
            payload: Raw SNMP PDU bytes
            trap_oid: Extracted trap OID (if available)
            destination: Destination tag/name for stream organisation
        """
        if not modules.cache.available:
            return

        # Lazy initialisation of cache reference
        if not self._cache_checked:
            self._cache = modules.cache.get_cache()
            self._cache_checked = True
            if self._cache and self._cache.available:
                logger.debug(f"Worker {self.worker_id}: Cache connected")
            elif self._cache:
                logger.debug(f"Worker {self.worker_id}: Cache not available")

        if not self._cache or not self._cache.available:
            return

        try:
            trap_data = {
                'timestamp': datetime.now().isoformat(),
                'source_ip': source_ip,
                'trap_oid': trap_oid or '',
                'pdu_base64': base64.b64encode(payload).decode('ascii'),
            }

            entry_id = self._cache.store(destination, trap_data)

            if entry_id:
                logger.debug(
                    f"Cached trap from {source_ip} to stream "
                    f"'{destination}': {entry_id}"
                )
        except Exception as e:
            # Non-blocking — don't let cache errors affect forwarding
            logger.debug(f"Cache store failed: {e}")

    def _complete_forward(
        self,
        source_ip: str,
        payload: bytes,
        destinations: list,
        trap_oid: str = None,
        destination_tag: str = 'default',
        action: str = 'forwarded'
    ):
        """
        Complete a forward operation with all bookkeeping.

        Consolidates: forward, stats increment, granular stats, cache,
        HA notification. Single point of change for adding new
        bookkeeping operations.

        Args:
            source_ip: Source IP address
            payload: Raw SNMP PDU bytes
            destinations: List of (ip, port) tuples to forward to
            trap_oid: Extracted trap OID (if available)
            destination_tag: Tag for stats/cache (e.g., 'default')
            action: Stats action — 'forwarded' or 'redirected'
        """
        # Forward the packet
        forward_packet(source_ip, payload, destinations)

        # Update sliding-window counter for forwarded traps.
        # Redirected has no window counter; total counters are owned by GranularStatsCollector.
        if action == 'forwarded':
            get_global_stats()._window_forwarded.increment()

        # Record granular statistics
        self._record_granular_stats(source_ip, trap_oid, action, destination_tag)

        # Store in cache for replay
        self._store_trap_in_cache(source_ip, payload, trap_oid, destination_tag)

        # Notify HA system of activity
        modules.ha.notify_trap_processed()

    # -----------------------------------------------------------------
    # Main processing entry point
    # -----------------------------------------------------------------

    def _process_packet(self, packet_data: Dict[str, Any]):
        """
        Process a single packet through the appropriate path.

        Uses fast path for SNMPv2c, slow path for v1/malformed, and
        dedicated handler for SNMPv3.

        IMPORTANT: HA check happens here at processing time, not at
        capture time. This ensures consistent behaviour across all
        capture modes (sniff, socket, eBPF).
        """
        try:
            source_ip = packet_data['src_ip']
            payload = packet_data['payload']

            # Increment 60s sliding-window for received traps.
            # Total counters are owned by GranularStatsCollector.
            get_global_stats()._window_received.increment()

            # CRITICAL: Check HA state before forwarding
            # Only the PRIMARY node should forward traps
            # But ALWAYS record stats and cache so we can see what's arriving
            # and replay if we become PRIMARY
            ha_forwarding_enabled = modules.ha.is_forwarding_enabled()

            if not ha_forwarding_enabled:
                self.stats.increment_ha_blocked()
                self._record_granular_stats(source_ip, None, 'ha_blocked')

                # IMPORTANT: Still cache the trap even on secondary
                # This enables gap-fill replay when we become primary
                self._store_trap_in_cache(source_ip, payload, None, 'default')

                # Log periodically to help diagnose without flooding
                if self.stats.ha_blocked_count % 1000 == 1:
                    logger.info(
                        f"HA: Packets blocked (secondary mode): "
                        f"{self.stats.ha_blocked_count} total"
                    )
                return

            config = _config_cache.get()

            # DEBUG: Log packet info for troubleshooting
            if logger.isEnabledFor(logging.DEBUG):
                snmp_ver = _detect_snmp_version(payload)
                logger.debug(
                    f"Processing packet from {source_ip}: {len(payload)} bytes, "
                    f"SNMP {snmp_ver}, first bytes: {payload[:10].hex()}"
                )

            # IP block check — exact first (O(1)), range fallback (O(1) after warmup)
            if (source_ip in config['blocked_ips'] or
                    _is_ip_blocked_by_range(source_ip, config.get('blocked_ip_ranges', []))):
                self._record_granular_stats(source_ip, None, 'blocked')
                return

            # Check for SNMPv3 FIRST before trying v2c fast path
            if is_snmpv3(payload):
                logger.debug(
                    f"SNMPv3 detected from {source_ip}, routing to v3 handler"
                )
                self.stats.record_slow_path()
                self._process_snmpv3(packet_data, config)
                return

            # Try fast path for SNMPv2c
            if is_snmpv2c(payload):
                trap_oid = extract_trap_oid_fast(payload)

                if trap_oid:
                    self.stats.record_fast_path()

                    # Check OID blocking
                    if trap_oid in config['blocked_traps']:
                        self._record_granular_stats(
                            source_ip, trap_oid, 'blocked'
                        )
                        if config['blocked_dest']:
                            forward_packet(
                                source_ip, payload, config['blocked_dest']
                            )
                        return

                    # IP redirect — exact first (O(1)), range fallback (O(1) after warmup)
                    tag = config['redirected_ips'].get(source_ip, '')
                    if not tag:
                        tag = _get_redirect_tag_from_ranges(
                            source_ip, config.get('redirected_ip_ranges', [])
                        )
                    if tag and tag in config['redirected_destinations']:
                        self._complete_forward(
                            source_ip, payload,
                            config['redirected_destinations'][tag],
                            trap_oid, tag, 'redirected'
                        )
                        return

                    # Check OID redirection
                    if trap_oid in config['redirected_oids']:
                        tag = config['redirected_oids'][trap_oid]
                        if tag in config['redirected_destinations']:
                            self._complete_forward(
                                source_ip, payload,
                                config['redirected_destinations'][tag],
                                trap_oid, tag, 'redirected'
                            )
                            return

                    # Forward to normal destinations
                    if config['destinations']:
                        self._complete_forward(
                            source_ip, payload, config['destinations'],
                            trap_oid, 'default', 'forwarded'
                        )

                    return

            # Slow path for everything else (v1, malformed, etc.)
            self.stats.record_slow_path()
            self._process_slow_path(packet_data, config)

        except Exception as e:
            self.stats.increment_error()
            logger.debug(f"Worker {self.worker_id} packet error: {e}")

    # -----------------------------------------------------------------
    # Slow path processing
    # -----------------------------------------------------------------

    def _process_slow_path(self, packet_data: Dict[str, Any], config: Dict):
        """Process packet using full Scapy parsing (slow path)."""
        source_ip = packet_data['src_ip']
        payload = packet_data['payload']

        # CRITICAL: Check for SNMPv3 at byte level FIRST
        # Scapy's SNMP parser cannot handle SNMPv3
        if is_snmpv3(payload):
            logger.debug(
                f"SNMPv3 packet detected from {source_ip} "
                f"({len(payload)} bytes)"
            )
            self._process_snmpv3(packet_data, config)
            return

        # Try Scapy parsing for v1/v2c
        snmp_packet, version = parse_snmp_packet(payload)

        # Parsing failed — forward anyway
        if not snmp_packet:
            if config['destinations']:
                self._complete_forward(
                    source_ip, payload, config['destinations'],
                    None, 'default', 'forwarded'
                )
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
                self._complete_forward(
                    source_ip, payload, config['destinations'],
                    None, 'default', 'forwarded'
                )
            return

        # Check blocking
        if trap_oid in config['blocked_traps']:
            self._record_granular_stats(source_ip, trap_oid, 'blocked')
            if config['blocked_dest']:
                forward_packet(source_ip, payload, config['blocked_dest'])
            return

        # IP redirect — exact first, range fallback
        tag = config['redirected_ips'].get(source_ip, '')
        if not tag:
            tag = _get_redirect_tag_from_ranges(
                source_ip, config.get('redirected_ip_ranges', [])
            )
        if tag and tag in config['redirected_destinations']:
            self._complete_forward(
                source_ip, payload,
                config['redirected_destinations'][tag],
                trap_oid, tag, 'redirected'
            )
            return

        if trap_oid in config['redirected_oids']:
            tag = config['redirected_oids'][trap_oid]
            if tag in config['redirected_destinations']:
                self._complete_forward(
                    source_ip, payload,
                    config['redirected_destinations'][tag],
                    trap_oid, tag, 'redirected'
                )
                return

        # Forward normally
        if config['destinations']:
            self._complete_forward(
                source_ip, payload, config['destinations'],
                trap_oid, 'default', 'forwarded'
            )

    # -----------------------------------------------------------------
    # SNMPv2c payload processing (shared by fast path and v3 decryption)
    # -----------------------------------------------------------------

    def _process_v2c_payload(
        self,
        source_ip: str,
        payload: bytes,
        config: Dict,
        trap_oid: Optional[str] = None,
        is_decrypted_v3: bool = False
    ) -> bool:
        """
        Process an SNMPv2c payload through the standard pipeline.

        Unified processing path for both native v2c traps and decrypted
        SNMPv3 traps (after conversion to v2c format).

        Args:
            source_ip: Source IP address
            payload: SNMPv2c packet bytes
            config: Configuration dict from cache
            trap_oid: Pre-extracted trap OID (optional)
            is_decrypted_v3: True if from SNMPv3 decryption (for logging)

        Returns:
            True if packet was handled, False if processing failed
        """
        if trap_oid is None:
            trap_oid = extract_trap_oid_fast(payload)

        log_prefix = "[v3->v2c] " if is_decrypted_v3 else ""

        # Check OID blocking
        if trap_oid and trap_oid in config['blocked_traps']:
            self._record_granular_stats(source_ip, trap_oid, 'blocked')
            if config['blocked_dest']:
                forward_packet(source_ip, payload, config['blocked_dest'])
            logger.debug(f"{log_prefix}Trap blocked by OID filter: {trap_oid}")
            return True

        # IP redirect — exact first, range fallback
        tag = config['redirected_ips'].get(source_ip, '')
        if not tag:
            tag = _get_redirect_tag_from_ranges(
                source_ip, config.get('redirected_ip_ranges', [])
            )
        if tag and tag in config['redirected_destinations']:
            dest_list = config['redirected_destinations'][tag]
            self._complete_forward(
                source_ip, payload, dest_list,
                trap_oid, tag, 'redirected'
            )
            if is_decrypted_v3:
                logger.info(
                    f"{log_prefix}Forwarded from {source_ip} to '{tag}' "
                    f"({len(dest_list)} hosts)"
                )
            return True

        # Check OID redirection
        if trap_oid and trap_oid in config['redirected_oids']:
            tag = config['redirected_oids'][trap_oid]
            if tag in config['redirected_destinations']:
                dest_list = config['redirected_destinations'][tag]
                self._complete_forward(
                    source_ip, payload, dest_list,
                    trap_oid, tag, 'redirected'
                )
                if is_decrypted_v3:
                    logger.info(
                        f"{log_prefix}OID {trap_oid} redirected to '{tag}' "
                        f"({len(dest_list)} hosts)"
                    )
                return True

        # Forward to default destinations
        if config['destinations']:
            self._complete_forward(
                source_ip, payload, config['destinations'],
                trap_oid, 'default', 'forwarded'
            )
            if is_decrypted_v3:
                logger.info(
                    f"{log_prefix}Forwarded from {source_ip} "
                    f"({len(payload)} bytes) to "
                    f"{len(config['destinations'])} destination(s)"
                )
            return True

        logger.debug(f"{log_prefix}No destinations configured, packet dropped")
        return False

    # -----------------------------------------------------------------
    # SNMPv3 processing with decryption
    # -----------------------------------------------------------------

    def _process_snmpv3(self, packet_data: Dict[str, Any], config: Dict):
        """
        Process SNMPv3 packet with decryption support.

        Flow:
        1. Extract metadata (engine_id, username) for logging/credential lookup
        2. Attempt decryption if credentials are available
        3. If decryption succeeds, convert to v2c and forward
        4. If decryption fails but NO credentials configured, forward original v3
        5. If decryption fails but credentials exist, drop packet

        The key insight: if credentials are configured for an engine but
        decryption/conversion fails, forwarding the encrypted v3 packet
        is unlikely to be useful to NOC systems expecting v2c.
        """
        source_ip = packet_data['src_ip']
        payload = packet_data['payload']

        logger.debug(
            f"Processing SNMPv3 trap from {source_ip} ({len(payload)} bytes)"
        )

        # Try to extract engine ID and username for logging/credential lookup
        engine_id = None
        username = None
        try:
            from ..snmpv3_decryption import (
                extract_engine_id_from_bytes,
                extract_username_from_bytes,
            )
            engine_id = extract_engine_id_from_bytes(payload)
            username = extract_username_from_bytes(payload)
            logger.debug(
                f"SNMPv3 trap: engine_id={engine_id}, username={username}"
            )
        except Exception as e:
            logger.debug(f"Could not extract SNMPv3 metadata: {e}")

        # Track whether we have credentials for this engine
        have_credentials = False

        # Try decryption
        try:
            from ..snmpv3_decryption import get_snmpv3_decryptor
            from ..snmpv3_credentials import get_credential_store

            decryptor = get_snmpv3_decryptor()

            if decryptor:
                # Check credentials BEFORE attempting decryption
                if engine_id:
                    credential_store = get_credential_store()
                    users = credential_store.get_users_for_engine(
                        engine_id.lower()
                    )
                    have_credentials = len(users) > 0
                    if have_credentials:
                        logger.debug(
                            f"Found {len(users)} credential(s) for "
                            f"engine {engine_id}"
                        )

                logger.debug(
                    f"Attempting SNMPv3 decryption for engine {engine_id}"
                )
                result = decryptor.decrypt_snmpv3_trap(payload)

                if result:
                    self._handle_v3_decryption_success(
                        result, source_ip, payload, config, engine_id, username
                    )
                    return
                else:
                    # Decryption failed — result was None
                    logger.warning(
                        f"SNMPv3 decryption failed for {source_ip}: "
                        f"engine={engine_id}, user={username}"
                    )
                    if have_credentials:
                        logger.warning(
                            f"Credentials exist for engine {engine_id} but "
                            f"decryption failed - check auth/priv settings. "
                            f"Packet DROPPED."
                        )
                        self._record_granular_stats(
                            source_ip, None, 'v3_decryption_failed', None
                        )
                        self.stats.increment_error()
                        return
            else:
                logger.warning("SNMPv3 decryptor not initialized")

        except ImportError as e:
            logger.warning(f"SNMPv3 module not available: {e}")
        except Exception as e:
            logger.warning(f"SNMPv3 processing error: {e}")
            import traceback
            logger.debug(traceback.format_exc())
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

        # Fallback: Forward original v3 packet ONLY if no credentials exist
        if have_credentials:
            logger.error(
                f"BUG: Reached v3 fallback with credentials for {source_ip}. "
                f"This indicates a logic error. Packet DROPPED."
            )
            self._record_granular_stats(
                source_ip, None, 'v3_logic_error', None
            )
            self.stats.increment_error()
            return

        logger.debug(
            f"Forwarding original SNMPv3 packet from {source_ip} "
            f"(no credentials configured for engine {engine_id})"
        )
        if config['destinations']:
            self._complete_forward(
                source_ip, payload, config['destinations'],
                None, 'default', 'forwarded'
            )

    def _handle_v3_decryption_success(
        self,
        result,
        source_ip: str,
        original_payload: bytes,
        config: Dict,
        engine_id: str,
        username: str
    ):
        """
        Handle successful SNMPv3 decryption: convert to v2c and forward.

        Args:
            result: (engine_id, trap_data) tuple from decryptor
            source_ip: Source IP address
            original_payload: Original encrypted payload
            config: Configuration dict
            engine_id: Extracted engine ID
            username: Extracted username
        """
        from ..snmpv3_decryption import get_snmpv3_decryptor

        result_engine_id, trap_data = result
        decrypted_username = trap_data.get('username', username or 'N/A')
        varbind_count = len(trap_data.get('varbinds', []))

        logger.info(
            f"SNMPv3 decrypted from {source_ip}: engine={result_engine_id}, "
            f"user={decrypted_username}, varbinds={varbind_count}"
        )

        # Convert to SNMPv2c format
        decryptor = get_snmpv3_decryptor()
        v2c_payload = decryptor.convert_to_snmpv2c(trap_data, "public")

        if v2c_payload and len(v2c_payload) > 20:
            logger.debug(
                f"SNMPv3->v2c conversion successful: "
                f"{len(original_payload)} -> {len(v2c_payload)} bytes"
            )

            # Route through standard v2c processing pipeline
            self._process_v2c_payload(
                source_ip=source_ip,
                payload=v2c_payload,
                config=config,
                trap_oid=None,
                is_decrypted_v3=True
            )
        else:
            logger.error(
                f"SNMPv3->v2c conversion FAILED for {source_ip}: "
                f"produced {len(v2c_payload) if v2c_payload else 0} bytes "
                f"(expected >20). Decrypted data: varbinds={varbind_count}, "
                f"request_id={trap_data.get('request_id', 'N/A')}. "
                f"Packet will be DROPPED to avoid forwarding encrypted v3."
            )
            self._record_granular_stats(
                source_ip, None, 'v3_conversion_failed', None
            )
            self.stats.increment_error()


# =====================================================================
# Module-level helpers
# =====================================================================

def _detect_snmp_version(payload: bytes) -> str:
    """
    Detect SNMP version from raw packet bytes (debug only).

    Performs minimal ASN.1 parsing to extract the version integer.

    Returns:
        Version string: "v1", "v2c", "v3", or "unknown"
    """
    if len(payload) < 5 or payload[0] != 0x30:
        return "unknown"

    try:
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
                    ver = int.from_bytes(payload[idx:idx + vlen], 'big')
                    return {0: "v1", 1: "v2c", 3: "v3"}.get(ver, f"v{ver}")
    except (IndexError, ValueError):
        pass

    return "unknown"
