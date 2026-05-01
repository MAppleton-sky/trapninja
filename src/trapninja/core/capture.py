#!/usr/bin/env python3
"""
TrapNinja Capture Manager

Handles all packet capture modes: eBPF accelerated, Scapy sniff, and
raw UDP socket. Extracted from ServiceInitializer Phase 13 to keep
service_init.py focused on orchestration.

Capture modes:
  - eBPF:   Highest performance, kernel-level filtering (requires BCC)
  - Sniff:  Scapy-based capture, supports parallel/shadow/mirror modes
  - Socket: UDP socket listeners for direct port binding

Also handles:
  - IP fragment reassembly initialization and configuration
  - BPF filter generation (simple and fragment-aware)
  - Packet handler selection (standard vs fragment-aware)
  - Main event loops for each capture mode

Author: TrapNinja Team
"""

import json
import logging
import os
import time
from typing import Any, Callable, Optional, TYPE_CHECKING

from scapy.all import get_if_addr, sniff

from ..config import INTERFACE, LISTEN_PORTS, CONFIG_DIR, stop_event
from ..network import (
    cleanup_udp_sockets,
    packet_queue,
    start_all_udp_listeners,
)
from .optional_modules import modules

if TYPE_CHECKING:
    from .service_init import SubsystemHandles

logger = logging.getLogger("trapninja")


# =============================================================================
# FRAGMENT REASSEMBLY
# =============================================================================

def initialize_fragment_reassembly(handles: 'SubsystemHandles') -> None:
    """
    Initialize IP fragment reassembly if configured and available.

    Reads capture_config.json for fragment_reassembly settings and
    initializes the fragment buffer if enabled.

    Args:
        handles: SubsystemHandles to update with fragment state
    """
    if not modules.fragmentation.available:
        logger.debug("Fragmentation module not available")
        return

    try:
        capture_config_file = os.path.join(CONFIG_DIR, "capture_config.json")
        if not os.path.exists(capture_config_file):
            logger.debug(
                "No capture_config.json found, fragment reassembly disabled"
            )
            return

        with open(capture_config_file, "r") as f:
            capture_cfg = json.load(f)

        frag_cfg = capture_cfg.get("fragment_reassembly", {})
        if not frag_cfg.get("enabled", False):
            return

        timeout_seconds = frag_cfg.get("timeout_seconds", 5.0)
        max_buffer_mb = frag_cfg.get("max_buffer_mb", 100.0)
        max_datagrams = frag_cfg.get("max_datagrams", 10000)

        fragment_buffer = modules.fragmentation.initialize(
            timeout_seconds=timeout_seconds,
            max_buffer_mb=max_buffer_mb,
            max_datagrams=max_datagrams,
        )

        if fragment_buffer:
            handles.fragment_buffer = fragment_buffer
            handles.fragment_reassembly_enabled = True
            logger.info("Fragment reassembly ENABLED")
            logger.info(
                f"  Timeout: {timeout_seconds}s, "
                f"Buffer: {max_buffer_mb}MB, "
                f"Max datagrams: {max_datagrams}"
            )

    except Exception as e:
        logger.warning(f"Could not load fragment reassembly config: {e}")
        logger.info("Fragment reassembly disabled")


# =============================================================================
# BPF FILTER GENERATION
# =============================================================================

def build_bpf_filter(handles: 'SubsystemHandles') -> str:
    """
    Build the BPF filter string for sniff capture.

    Handles local IP filtering for parallel modes and fragment-aware
    filter generation.

    Args:
        handles: SubsystemHandles with capture mode state

    Returns:
        BPF filter string
    """
    from ..core.constants import FORWARD_SOURCE_PORT

    # Get local IP for parallel mode filtering
    local_ip = None
    if handles.force_sniff_mode:
        try:
            local_ip = get_if_addr(INTERFACE)
            if local_ip and local_ip != "0.0.0.0":
                logger.info(
                    f"Parallel mode: filtering to local IP {local_ip}"
                )
            else:
                logger.warning(
                    f"Could not determine local IP for {INTERFACE}, "
                    f"may capture other processes' forwarded packets"
                )
                local_ip = None
        except Exception as e:
            logger.warning(
                f"Failed to get local IP for {INTERFACE}: {e}"
            )
            local_ip = None

    if handles.fragment_reassembly_enabled:
        bpf_filter = modules.fragmentation.generate_fragment_aware_filter(
            LISTEN_PORTS,
            exclude_sport=FORWARD_SOURCE_PORT,
            local_ip=local_ip,
        )
        logger.info("Using fragment-aware BPF filter")
    else:
        bpf_filter = modules.fragmentation.generate_simple_filter(
            LISTEN_PORTS,
            exclude_sport=FORWARD_SOURCE_PORT,
            local_ip=local_ip,
        )

    return bpf_filter


# =============================================================================
# PACKET HANDLER SELECTION
# =============================================================================

def get_packet_handler(handles: 'SubsystemHandles') -> Callable:
    """
    Select the appropriate packet handler based on configuration.

    Returns fragment-aware handler if fragment reassembly is enabled,
    otherwise returns the standard HA-aware handler.

    Args:
        handles: SubsystemHandles with fragment reassembly state

    Returns:
        Packet handler callable
    """
    if handles.fragment_reassembly_enabled and handles.fragment_buffer:
        fragment_buffer = handles.fragment_buffer

        def fragment_aware_trap_handler(packet):
            """Handle packets with fragment reassembly support."""
            try:
                result = fragment_buffer.process_packet(packet)
                if result:
                    from ..service import forward_trap_dict
                    forward_trap_dict(result)
            except Exception as e:
                logger.error(f"Error in fragment-aware handler: {e}")

        logger.info("Using fragment-aware packet handler")
        return fragment_aware_trap_handler
    else:
        from ..service import ha_aware_forward_trap
        return ha_aware_forward_trap


# =============================================================================
# CAPTURE MODES
# =============================================================================

def try_ebpf_capture(handles: 'SubsystemHandles') -> bool:
    """
    Attempt to start eBPF-accelerated packet capture.
    Initialises fragment reassembly (if configured) before starting capture
    so that fragmented SNMP traps are handled the same way as in sniff mode.

    Args:
        handles: SubsystemHandles to update with capture instance

    Returns:
        True if eBPF capture started successfully
    """
    logger.info("Checking for eBPF support...")

    if not (modules.ebpf.is_supported() and modules.ebpf.check_dependencies()):
        logger.warning(
            "eBPF not supported on this system, using standard capture"
        )
        return False

    logger.info("eBPF support available - creating capture instance")

    # Initialise fragment reassembly from capture_config.json (same config path
    # as sniff mode).  Must happen before create_capture so we can hand the
    # buffer to the capture instance.
    initialize_fragment_reassembly(handles)
    if handles.fragment_reassembly_enabled:
        logger.info(
            "eBPF capture: fragment reassembly enabled "
            "(fragmented SNMP traps will be reassembled)"
        )
    else:
        logger.debug(
            "eBPF capture: fragment reassembly not enabled "
            "(large traps >1472 bytes will be logged as warnings if fragmented)"
        )

    try:
        capture_instance = modules.ebpf.create_capture(
            interface=INTERFACE,
            listen_ports=LISTEN_PORTS,
            queue_ref=packet_queue,
            stop_event_ref=stop_event,
            fragment_buffer=handles.fragment_buffer,
        )

        if capture_instance.start():
            handles.capture_instance = capture_instance
            handles.use_ebpf = True
            logger.info(
                "Packet capture started successfully with eBPF acceleration"
            )
            logger.info(">>> CAPTURE ACTIVE - Now receiving packets <<<")
            return True
        else:
            logger.warning(
                "Failed to start eBPF capture, will try standard capture"
            )
            return False

    except Exception as e:
        logger.error(f"Error initializing eBPF capture: {e}")
        logger.warning("Will try standard capture method")
        return False


def run_socket_capture() -> int:
    """
    Run socket-based UDP capture mode.

    Returns:
        Exit code (0 for clean shutdown)
    """
    logger.info("Starting UDP socket listeners (socket mode)")
    logger.info(
        f"Listening on interface '{INTERFACE}', UDP ports {LISTEN_PORTS}"
    )

    if not start_all_udp_listeners():
        logger.warning("Some UDP listeners failed to start")
        logger.warning(
            "This may cause packet loss if ports are in use by other services"
        )

    try:
        logger.info(
            "Socket mode active - packet capture running in background threads"
        )
        while not stop_event.is_set():
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("TrapNinja service stopped by keyboard interrupt")

    return 0


def run_sniff_capture(handles: 'SubsystemHandles') -> int:
    """
    Run Scapy sniff-based capture mode with optional fragment reassembly.

    Args:
        handles: SubsystemHandles with capture mode state

    Returns:
        Exit code (0 for clean shutdown)
    """
    logger.info(
        "Starting packet capture with Scapy sniff (sniff mode)"
    )
    logger.info(
        f"Listening on interface '{INTERFACE}', UDP ports {LISTEN_PORTS}"
    )
    logger.info(
        "NOTE: UDP socket listeners are DISABLED in sniff mode "
        "to prevent duplication"
    )

    # Ensure no UDP socket listeners are running
    cleanup_udp_sockets()
    logger.debug("Cleaned up any existing UDP socket listeners")

    # Initialize fragment reassembly if available
    initialize_fragment_reassembly(handles)

    try:
        bpf_filter = build_bpf_filter(handles)
        logger.info(f"BPF filter: {bpf_filter}")

        packet_handler = get_packet_handler(handles)

        sniff(
            iface=INTERFACE,
            filter=bpf_filter,
            prn=packet_handler,
            store=0,
            stop_filter=lambda x: stop_event.is_set(),
        )
    except KeyboardInterrupt:
        logger.info("TrapNinja service stopped by keyboard interrupt")
    except Exception as e:
        logger.error(f"Error in packet capture: {e}", exc_info=True)
        logger.info(
            "Waiting for configuration update or manual restart..."
        )
        while not stop_event.is_set():
            time.sleep(5)

    return 0


def run_standard_capture(handles: 'SubsystemHandles') -> int:
    """
    Run standard capture mode (socket or sniff).

    Determines mode from config and dispatches to the appropriate
    capture implementation.

    Args:
        handles: SubsystemHandles with capture mode state

    Returns:
        Exit code (0 for clean shutdown)
    """
    from ..config import CAPTURE_MODE
    from ..network import set_ebpf_mode

    set_ebpf_mode(False)

    capture_mode = CAPTURE_MODE.lower()
    if capture_mode not in ["auto", "sniff", "socket"]:
        logger.warning(
            f"Invalid CAPTURE_MODE '{CAPTURE_MODE}', defaulting to 'auto'"
        )
        capture_mode = "auto"

    if capture_mode == "auto":
        capture_mode = "sniff"
        logger.info("Auto mode selected: using 'sniff' capture method")

    logger.info(f"Capture mode: {capture_mode.upper()}")

    if capture_mode == "socket":
        return run_socket_capture()
    else:
        return run_sniff_capture(handles)


def run_ebpf_main_loop() -> int:
    """
    Main loop when eBPF capture is active.

    Periodically logs HA status while waiting for shutdown signal.

    Returns:
        Exit code (0 for clean shutdown)
    """
    logger.info("TrapNinja service running with packet capture active")

    try:
        last_status_log = 0
        while not stop_event.is_set():
            current_time = time.time()

            if current_time - last_status_log > 60:
                from ..service import get_ha_status
                ha_status = get_ha_status()
                if ha_status.get("enabled", False):
                    logger.info(
                        f"HA Status: {ha_status['state']}, "
                        f"Forwarding: {ha_status['is_forwarding']}, "
                        f"Peer Connected: "
                        f"{ha_status.get('peer_connected', False)}"
                    )
                last_status_log = current_time

            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("TrapNinja service stopped by keyboard interrupt")
        stop_event.set()

    return 0
