#!/usr/bin/env python3
"""
TrapNinja Service Module - HA Enhanced Version

Contains the main service functionality with High Availability integration.
Includes Primary/Secondary deployment with heartbeat and failover capabilities.

The heavy lifting of service initialization is delegated to
core.service_init.ServiceInitializer (B1 refactoring). This module
retains:
  - validate_configuration()  — used by CLI --validate and the initializer
  - run_service()             — thin wrapper around ServiceInitializer.run()
  - get_ha_status()           — queried by control socket and CLI
  - get_service_status()      — queried by control socket and CLI
  - ha_aware_forward_trap()   — sniff callback
  - forward_trap_dict()       — fragment reassembly callback
  - trap_forwarder_control()  — HA state callback
"""
import os
import sys
import time
import signal
import logging
from scapy.all import sniff, get_if_list, get_if_addr

from .config import INTERFACE, PID_FILE, LISTEN_PORTS, stop_event, load_config, CONFIG_DIR, LOG_FILE
from .network import start_all_udp_listeners, cleanup_udp_sockets, forward_trap, start_packet_processors, start_queue_monitor
from .redirection import schedule_config_check, load_redirection_config
from .metrics import init_metrics, get_metrics_summary, load_metrics_config
from .ha import (
    load_ha_config, initialize_ha, shutdown_ha, get_ha_cluster,
    notify_trap_processed, is_forwarding_enabled,
    HAState
)

# Import optional modules registry - provides lazy loading with automatic fallbacks
from .core.optional_modules import modules

# Get logger instance
logger = logging.getLogger("trapninja")


class ConfigurationError(Exception):
    """Raised when configuration validation fails."""
    pass


def validate_configuration() -> tuple:
    """
    Validate all configuration before starting the service.
    
    Performs comprehensive checks on:
    - Network interface existence
    - Listen port validity
    - Destination configuration
    - HA configuration (if enabled)
    - Cache configuration (if enabled)
    
    Returns:
        Tuple of (is_valid: bool, errors: list, warnings: list)
    """
    # IMPORTANT: Import the module, not the variables directly!
    # We need to load config first, then access via module reference.
    from . import config as cfg
    
    # Temporarily set stop_event to prevent load_config from starting timer
    cfg.stop_event.set()
    cfg.load_config(None)  # Load configuration from files
    cfg.stop_event.clear()
    
    errors = []
    warnings = []
    
    # =======================================================================
    # Validate Network Interface
    # =======================================================================
    try:
        available_interfaces = get_if_list()
        if cfg.INTERFACE not in available_interfaces:
            errors.append(
                f"Interface '{cfg.INTERFACE}' not found. "
                f"Available interfaces: {', '.join(available_interfaces)}"
            )
    except Exception as e:
        warnings.append(f"Could not verify interface: {e}")
    
    # =======================================================================
    # Validate Listen Ports
    # =======================================================================
    if not cfg.LISTEN_PORTS:
        errors.append("No listen ports configured")
    else:
        for port in cfg.LISTEN_PORTS:
            if not isinstance(port, int):
                errors.append(f"Invalid port type: {port} (must be integer)")
            elif port < 1 or port > 65535:
                errors.append(f"Port {port} out of valid range (1-65535)")
            elif port < 1024:
                warnings.append(f"Port {port} is privileged (requires root)")
    
    # =======================================================================
    # Validate Destinations
    # =======================================================================
    if not cfg.destinations:
        warnings.append(
            "No forwarding destinations configured. "
            "Traps will be received but not forwarded."
        )
    else:
        for dest in cfg.destinations:
            if isinstance(dest, (list, tuple)):
                if len(dest) < 1:
                    errors.append(f"Destination array is empty: {dest}")
                elif len(dest) == 1:
                    warnings.append(f"Destination {dest} has no port, will use 162")
                elif len(dest) >= 2:
                    host, port = dest[0], dest[1]
                    if not isinstance(host, str) or not host:
                        errors.append(f"Destination host must be a non-empty string: {dest}")
                    try:
                        port_num = int(port)
                        if port_num < 1 or port_num > 65535:
                            errors.append(f"Destination port {port_num} out of valid range (1-65535): {dest}")
                    except (ValueError, TypeError):
                        errors.append(f"Destination port must be an integer: {dest}")
            elif isinstance(dest, dict):
                if 'host' not in dest:
                    errors.append(f"Destination missing 'host': {dest}")
                if 'port' not in dest:
                    warnings.append(f"Destination missing 'port', will use 162: {dest}")
            elif isinstance(dest, str):
                if ':' not in dest:
                    warnings.append(f"Destination '{dest}' has no port, will use 162")
            else:
                errors.append(f"Invalid destination format (expected list, dict, or string): {dest}")
    
    # =======================================================================
    # Validate HA Configuration (if enabled)
    # =======================================================================
    try:
        ha_config = load_ha_config()
        if ha_config.enabled:
            if not ha_config.peer_host:
                errors.append("HA enabled but peer_host not configured")
            
            if ha_config.peer_port < 1 or ha_config.peer_port > 65535:
                errors.append(f"HA peer_port {ha_config.peer_port} out of valid range")
            
            if ha_config.listen_port < 1 or ha_config.listen_port > 65535:
                errors.append(f"HA listen_port {ha_config.listen_port} out of valid range")
            
            if ha_config.heartbeat_interval <= 0:
                errors.append("HA heartbeat_interval must be positive")
            
            if ha_config.heartbeat_timeout <= ha_config.heartbeat_interval:
                warnings.append(
                    "HA heartbeat_timeout should be greater than heartbeat_interval"
                )
            
            if not ha_config.shared_secret:
                warnings.append(
                    "HA shared_secret not configured - using weaker authentication. "
                    "Consider adding a shared_secret for HMAC-SHA256 authentication."
                )
    except Exception as e:
        warnings.append(f"Could not validate HA configuration: {e}")
    
    # =======================================================================
    # Validate Cache Configuration (if enabled)
    # =======================================================================
    if modules.cache.available:
        try:
            cache_config_path = os.path.join(cfg.CONFIG_DIR, 'cache_config.json')
            if os.path.exists(cache_config_path):
                import json as _json
                with open(cache_config_path) as f:
                    cache_data = _json.load(f)
                from .cache import CacheConfig
                cache_cfg = CacheConfig.from_dict(cache_data)
                if cache_cfg.enabled:
                    if not cache_cfg.host:
                        errors.append("Cache enabled but Redis host not configured")
                    if cache_cfg.port < 1 or cache_cfg.port > 65535:
                        errors.append(f"Cache port {cache_cfg.port} out of valid range")
        except Exception as e:
            warnings.append(f"Could not validate cache configuration: {e}")
    
    # =======================================================================
    # Check for blocking/redirection rules
    # =======================================================================
    if cfg.blocked_ips:
        logger.debug(f"Loaded {len(cfg.blocked_ips)} blocked IP rules")
    if cfg.blocked_traps:
        logger.debug(f"Loaded {len(cfg.blocked_traps)} blocked OID rules")
    if cfg.redirected_ips:
        logger.debug(f"Loaded {len(cfg.redirected_ips)} IP redirection rules")
    if cfg.redirected_oids:
        logger.debug(f"Loaded {len(cfg.redirected_oids)} OID redirection rules")
    
    is_valid = len(errors) == 0
    return is_valid, errors, warnings


# =========================================================================
# GLOBAL STATE
# =========================================================================
# These globals are read by get_service_status() and other modules.
# The ServiceInitializer updates them via _sync_globals_from_initializer().

capture_instance = None
use_ebpf = False
ha_forwarding_enabled = True
start_time = None

# Reference to the active ServiceInitializer (for signal handler access)
_active_initializer = None


def trap_forwarder_control(enabled: bool):
    """
    Control trap forwarding based on HA state.

    Args:
        enabled: Whether to enable or disable trap forwarding
    """
    global ha_forwarding_enabled
    ha_forwarding_enabled = enabled

    if enabled:
        logger.info("HA: Trap forwarding enabled - this instance is active")
    else:
        logger.info("HA: Trap forwarding disabled - this instance is standby")


def handle_signal(signum, frame):
    """
    Signal handler for graceful shutdown with HA coordination.

    If a ServiceInitializer is active, delegates to its signal handler.
    Otherwise falls back to direct shutdown.

    Args:
        signum (int): Signal number
        frame: Current stack frame
    """
    global _active_initializer
    
    if _active_initializer is not None:
        _active_initializer._handle_signal(signum, frame)
        return

    # Fallback: direct shutdown (e.g., if called before initializer is set up)
    logger.info(f"Received signal {signum}, shutting down...")
    stop_event.set()

    try:
        if modules.control.available:
            modules.control.shutdown()
    except Exception as e:
        logger.error(f"Error shutting down control socket: {e}")

    shutdown_ha()

    if modules.stats.available:
        try:
            modules.stats.shutdown()
        except Exception as e:
            logger.error(f"Error shutting down granular stats: {e}")

    try:
        logger.info("Final metrics before shutdown:")
        metrics_summary = get_metrics_summary()
        logger.info(f"Total traps received: {metrics_summary['total_traps_received']}")
        logger.info(f"Total traps forwarded: {metrics_summary['total_traps_forwarded']}")
        logger.info(f"Total traps blocked: {metrics_summary['total_traps_blocked']}")
        logger.info(f"Total traps redirected: {metrics_summary['total_traps_redirected']}")
    except Exception as e:
        logger.error(f"Error logging final metrics: {e}")

    if capture_instance:
        capture_instance.stop()

    cleanup_udp_sockets()
    sys.exit(0)


def _sync_globals_from_initializer(initializer):
    """
    Sync module-level globals from a ServiceInitializer instance.
    
    Called after initialization completes so that get_service_status()
    and other consumers see consistent state.
    
    Args:
        initializer: The active ServiceInitializer instance
    """
    global capture_instance, use_ebpf, start_time, _active_initializer
    
    capture_instance = initializer.handles.capture_instance
    use_ebpf = initializer.handles.use_ebpf
    start_time = initializer.start_time
    _active_initializer = initializer


def run_service(debug=False, shadow_mode=False, mirror_mode=False,
                parallel=False, capture_mode=None, log_traps=None):
    """
    Main service function with HA integration.
    
    Delegates to ServiceInitializer for modular, testable initialization.

    Args:
        debug (bool): Whether to run in debug mode with more verbose logging
        shadow_mode (bool): Observe only mode (no forwarding)
        mirror_mode (bool): Parallel capture and forward mode
        parallel (bool): Enable sniff capture for coexistence
        capture_mode (str): Force capture mode (auto, sniff, socket)
        log_traps (str): Log all traps to this file

    Returns:
        int: Exit code
    """
    from .core.service_init import RuntimeConfig, ServiceInitializer
    
    config = RuntimeConfig(
        debug=debug,
        shadow_mode=shadow_mode,
        mirror_mode=mirror_mode,
        parallel=parallel,
        capture_mode=capture_mode,
        log_traps=log_traps,
    )
    
    initializer = ServiceInitializer(config)
    _sync_globals_from_initializer(initializer)
    
    return initializer.run()


def ha_aware_forward_trap(packet):
    """
    Packet capture callback that queues packets for processing.
    
    Note: HA state is checked in the packet processor, not here.
    This ensures packets are always queued for processing (filtering, caching)
    even on Secondary nodes. The processor will skip forwarding if HA
    indicates this node is Secondary.

    Args:
        packet: Scapy packet from sniff function
    """
    try:
        forward_trap(packet)
    except Exception as e:
        logger.error(f"Error in packet capture callback: {e}")


def forward_trap_dict(packet_info: dict):
    """
    Queue a packet for processing from a dict (used by fragment reassembly).
    
    This function handles packets that have been reassembled from fragments,
    which are passed as dicts rather than Scapy packets.
    
    Args:
        packet_info: Dict with 'src_ip', 'dst_port', 'payload' keys
    """
    from .network import packet_queue, _queue_stats
    import queue
    
    try:
        packet_data = {
            'src_ip': packet_info.get('src_ip', ''),
            'dst_port': packet_info.get('dst_port', 162),
            'payload': packet_info.get('payload', b''),
        }
        
        if packet_info.get('fragmented', False):
            logger.debug(
                f"Reassembled fragmented trap from {packet_data['src_ip']}, "
                f"payload size: {len(packet_data['payload'])} bytes"
            )
        
        try:
            packet_queue.put_nowait(packet_data)
            _queue_stats.record_queued()
        except queue.Full:
            _queue_stats.record_dropped()
            
    except Exception as e:
        logger.error(f"Error queuing reassembled packet: {e}")


def get_ha_status():
    """
    Get HA status from the cluster instance.
    
    Returns:
        dict: HA status information
    """
    try:
        ha_cluster = get_ha_cluster()
        if ha_cluster:
            return ha_cluster.get_status()
        return {"enabled": False, "state": "disabled"}
    except Exception as e:
        logger.error(f"Error getting HA status: {e}")
        return {"enabled": False, "state": "disabled"}


def get_service_status():
    """
    Get comprehensive service status including HA information.

    Returns:
        dict: Service status information including uptime, configuration,
              HA state, and metrics
    """
    from .config import destinations, blocked_traps, blocked_ips

    # Calculate uptime
    uptime = time.time() - start_time if start_time else 0

    status = {
        "pid": os.getpid(),
        "uptime": uptime,
        "destinations": len(destinations),
        "blocked_traps": len(blocked_traps),
        "blocked_ips": len(blocked_ips),
        "listen_ports": LISTEN_PORTS,
        "interface": INTERFACE,
        "ebpf_enabled": use_ebpf
    }

    # Add HA status
    ha_status = get_ha_status()
    status["ha"] = ha_status

    # Add metrics
    try:
        metrics = get_metrics_summary()
        status["metrics"] = metrics
    except Exception:
        status["metrics"] = {}
    
    # Add fragment reassembly stats if available
    if modules.fragmentation.available:
        try:
            frag_stats = modules.fragmentation.get_stats()
            if frag_stats:
                status["fragment_reassembly"] = frag_stats
        except Exception:
            pass

    return status
