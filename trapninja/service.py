#!/usr/bin/env python3
"""
TrapNinja Service Module - HA Enhanced Version - FIXED

Contains the main service functionality with High Availability integration.
Includes Primary/Secondary deployment with heartbeat and failover capabilities.

FIXED: Separated get_ha_status() and get_service_status() functions that were merged.
"""
import os
import sys
import time
import signal
import logging
from scapy.all import sniff, get_if_list

from .config import INTERFACE, PID_FILE, LISTEN_PORTS, stop_event, load_config, CONFIG_DIR, LOG_FILE
from .network import start_all_udp_listeners, cleanup_udp_sockets, forward_trap, start_packet_processors, start_queue_monitor
from .redirection import schedule_config_check, load_redirection_config
from .metrics import init_metrics, get_metrics_summary
from .ha import (
    load_ha_config, initialize_ha, shutdown_ha, get_ha_cluster,
    notify_trap_processed, is_forwarding_enabled,
    HAState
)

# Import control socket module with fallback if not available
try:
    from .control import initialize_control_socket, shutdown_control_socket
    CONTROL_SOCKET_AVAILABLE = True
except ImportError:
    CONTROL_SOCKET_AVAILABLE = False
    def initialize_control_socket():
        return False
    def shutdown_control_socket():
        pass

# Import eBPF module with fallback if not available
try:
    from .ebpf import is_ebpf_supported, check_ebpf_dependencies, create_capture

    EBPF_AVAILABLE = True
except ImportError:
    EBPF_AVAILABLE = False

# Get logger instance
logger = logging.getLogger("trapninja")

# Global variables
capture_instance = None
use_ebpf = False
ha_forwarding_enabled = True
start_time = None  # Initialize service start time


def trap_forwarder_control(enabled: bool):
    """
    Control trap forwarding based on HA state

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
    Signal handler for graceful shutdown with HA coordination

    Args:
        signum (int): Signal number
        frame: Current stack frame
    """
    logger.info(f"Received signal {signum}, shutting down...")

    # Signal all components to stop
    stop_event.set()

    # Shutdown control socket
    try:
        if CONTROL_SOCKET_AVAILABLE:
            shutdown_control_socket()
    except Exception as e:
        logger.error(f"Error shutting down control socket: {e}")

    # Shutdown HA cluster first to coordinate with peer
    shutdown_ha()

    # Log final metrics before shutdown
    try:
        logger.info("Final metrics before shutdown:")
        metrics_summary = get_metrics_summary()
        logger.info(f"Total traps received: {metrics_summary['total_traps_received']}")
        logger.info(f"Total traps forwarded: {metrics_summary['total_traps_forwarded']}")
        logger.info(f"Total traps blocked: {metrics_summary['total_traps_blocked']}")
        logger.info(f"Total traps redirected: {metrics_summary['total_traps_redirected']}")
    except Exception as e:
        logger.error(f"Error logging final metrics: {e}")

    # Stop capture if active
    global capture_instance
    if capture_instance:
        capture_instance.stop()

    # Clean up network resources
    cleanup_udp_sockets()

    sys.exit(0)


def run_service(debug=False):
    """
    Main service function with HA integration

    Args:
        debug (bool): Whether to run in debug mode with more verbose logging

    Returns:
        int: Exit code
    """
    global capture_instance, use_ebpf, ha_forwarding_enabled, start_time
    
    # Record service start time
    start_time = time.time()

    if debug:
        # Set logger to DEBUG level for more detailed information
        logger.setLevel(logging.DEBUG)
        # Add a console handler for immediate feedback
        ch = logging.StreamHandler()
        ch.setLevel(logging.DEBUG)
        formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] %(message)s')
        ch.setFormatter(formatter)
        logger.addHandler(ch)
        logger.debug("Debug mode enabled - verbose logging activated")

    logger.info(f"Starting TrapNinja service with HA support (PID: {os.getpid()})...")
    logger.info(f"Python version: {sys.version}")
    logger.info(f"Running as user: {os.getenv('USER', 'unknown')}")

    # Write PID to file to ensure it's correct
    try:
        with open(PID_FILE, 'w') as f:
            f.write(str(os.getpid()))
        logger.info(f"PID file updated with current PID: {os.getpid()}")
    except Exception as e:
        logger.error(f"Failed to write PID file: {e}")

    # Register signal handlers
    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    # =======================================================================
    # Initialize Control Socket (for CLI communication)
    # =======================================================================
    if CONTROL_SOCKET_AVAILABLE:
        logger.info("Initializing control socket for CLI communication...")
        try:
            if not initialize_control_socket():
                logger.warning("Failed to initialize control socket - CLI commands may not work")
                logger.warning("Service will continue without control socket support")
            else:
                logger.info("Control socket initialized successfully")
        except Exception as e:
            logger.error(f"Error initializing control socket: {e}")
            logger.error("Service will continue without control socket support")
            import traceback
            logger.debug(traceback.format_exc())
    else:
        logger.warning("Control socket module not available - CLI commands will not work")
        logger.warning("This is expected if running older code without control.py")
        logger.warning("Service will continue in compatibility mode")

    # =======================================================================
    # Initialize High Availability
    # =======================================================================
    logger.info("Initializing High Availability system...")

    try:
        ha_config = load_ha_config()

        if ha_config.enabled:
            logger.info(f"HA enabled - Mode: {ha_config.mode}, Priority: {ha_config.priority}")
            logger.info(f"Peer: {ha_config.peer_host}:{ha_config.peer_port}")

            # Initialize HA cluster
            if not initialize_ha(ha_config, trap_forwarder_control):
                logger.error("Failed to initialize HA cluster")
                return 1

            # Wait for initial HA state to stabilize
            time.sleep(2.0)

            # Log initial HA status
            ha_status = get_ha_status()
            logger.info(f"HA Status: {ha_status['state']}, Forwarding: {ha_status['is_forwarding']}")

        else:
            logger.info("HA disabled - running in standalone mode")

    except Exception as e:
        logger.error(f"Error initializing HA: {e}")
        return 1

    # Load configuration files initially
    from .network import restart_udp_listeners, packet_queue
    from .config import destinations, blocked_traps, blocked_dest, blocked_ips
    from .config import redirected_ips, redirected_oids, redirected_destinations

    # Initialize metrics module
    metrics_dir = os.path.join(os.path.dirname(LOG_FILE), "metrics")
    init_metrics(metrics_directory=metrics_dir, export_interval=60)
    logger.info(f"Metrics collection initialized with output to {metrics_dir}")

    # First load the configuration
    # NOTE: Do NOT pass restart_udp_listeners here - we'll start listeners
    # only in socket mode to prevent duplication with sniff mode
    config_changed = load_config(None)  # No callback - don't auto-start listeners
    logger.info(f"Initial configuration loaded (changed: {config_changed})")

    # Initialize redirection configuration
    try:
        # Schedule periodic checks for redirection config updates
        schedule_config_check(interval=60)  # Check every 60 seconds

        # Log redirection configuration
        logger.info(f"Redirection configuration loaded:")
        logger.info(f"  - IP redirections: {len(redirected_ips)}")
        logger.info(f"  - OID redirections: {len(redirected_oids)}")
        logger.info(f"  - Destination groups: {len(redirected_destinations)}")

    except Exception as e:
        logger.error(f"Error initializing redirection configuration: {e}")

    # Initialize SNMPv3 decryption subsystem
    try:
        logger.info("Initializing SNMPv3 decryption subsystem...")
        from .snmpv3_decryption import initialize_snmpv3_decryptor, PYSNMP_AVAILABLE
        from .snmpv3_credentials import get_credential_store
        
        if not PYSNMP_AVAILABLE:
            logger.info("SNMPv3 decryption dependencies not installed")
            logger.info("  SNMPv3 traps will be forwarded without decryption")
            logger.info("  To enable decryption, install: pip3 install --break-system-packages pysnmp pyasn1 cryptography")
        else:
            # Initialize credential store
            credential_store = get_credential_store()
            
            # Initialize decryptor
            decryptor = initialize_snmpv3_decryptor()
            
            if decryptor:
                # Log SNMPv3 status
                engine_ids = credential_store.get_engine_ids()
                if engine_ids:
                    logger.info(f"SNMPv3 decryption enabled with {len(engine_ids)} configured engine(s)")
                    for engine_id in engine_ids:
                        users = credential_store.get_users_for_engine(engine_id)
                        logger.info(f"  - Engine {engine_id}: {len(users)} user(s)")
                else:
                    logger.info("SNMPv3 decryption initialized but no credentials configured")
                    logger.info("  Use --snmpv3-add-user to add SNMPv3 credentials")
            else:
                logger.warning("SNMPv3 decryptor initialization failed")
                logger.info("  SNMPv3 traps will be forwarded without decryption")
    except ImportError as e:
        logger.info(f"SNMPv3 decryption not available: {e}")
        logger.info("  SNMPv3 traps will be forwarded without decryption")
        logger.info("  To enable decryption, install: pip3 install --break-system-packages pysnmp pyasn1 cryptography")
    except Exception as e:
        logger.warning(f"Failed to initialize SNMPv3 decryption: {e}")
        logger.warning("SNMPv3 traps will be forwarded without decryption")

    # Verify that destinations are loaded
    if not destinations:
        logger.warning("No destinations loaded from configuration! Traps will not be forwarded.")
        logger.warning(f"Please check the destinations file: {CONFIG_DIR}/destinations.json")
        logger.warning("Example content: [[\"192.168.1.100\", 162], [\"127.0.0.1\", 1162]]")
    else:
        logger.info(f"Current destinations: {destinations}")

    # Enhanced logging for blocked OIDs
    logger.info(f"Number of blocked trap OIDs: {len(blocked_traps)}")
    if blocked_traps:
        # Display the blocked OIDs in the log for easier troubleshooting
        oid_list = list(blocked_traps)
        if len(oid_list) <= 5:
            # If there are only a few OIDs, show all of them
            logger.info(f"Blocked trap OIDs: {sorted(oid_list)}")
        else:
            # If there are many OIDs, show the first 5 and indicate total count
            logger.info(f"First 5 blocked trap OIDs (of {len(oid_list)} total): {sorted(oid_list)[:5]}")

    # IP filtering info
    logger.info(f"Number of blocked IP addresses: {len(blocked_ips)}")
    if blocked_ips:
        if len(blocked_ips) <= 10:
            logger.info(f"Blocked IP addresses: {sorted(blocked_ips)}")
        else:
            logger.info(
                f"First 10 blocked IP addresses (of {len(blocked_ips)} total): {sorted(list(blocked_ips))[:10]}")

    # Check interfaces and validate configuration
    available_interfaces = get_if_list()
    logger.info(f"Available interfaces: {available_interfaces}")

    if INTERFACE not in available_interfaces:
        logger.warning(f"Configured interface '{INTERFACE}' not found! Available interfaces: {available_interfaces}")
        logger.warning("Please update the configuration with a valid interface name.")
        logger.info(f"Will attempt to use interface: {INTERFACE} anyway")
    else:
        logger.info(f"Using interface: {INTERFACE}")

    # Determine number of worker threads based on CPU cores
    # OPTIMIZED: Use 2x CPU cores (up to 32) for high-throughput processing
    import multiprocessing
    cpu_count = multiprocessing.cpu_count()
    worker_count = min(cpu_count * 2, 32)
    
    # Start queue monitor for utilization tracking
    start_queue_monitor()
    
    # Start optimized packet processing workers
    # Uses larger batch sizes and longer timeouts to reduce CPU spinning
    workers = start_packet_processors(num_workers=worker_count)
    logger.info(f"Started {len(workers)} packet processing workers (optimized)")
    logger.info(f"Queue capacity: {packet_queue.maxsize} packets")

    # =======================================================================
    # Initialize packet capture (either eBPF or traditional)
    # =======================================================================
    capture_started = False

    # Try eBPF if available
    if EBPF_AVAILABLE:
        logger.info("Checking for eBPF support...")

        # Check if eBPF is supported
        if is_ebpf_supported() and check_ebpf_dependencies():
            logger.info("eBPF support available - creating capture instance")

            try:
                # Create capture instance
                capture_instance = create_capture(
                    interface=INTERFACE,
                    listen_ports=LISTEN_PORTS,
                    queue_ref=packet_queue,
                    stop_event_ref=stop_event
                )

                # Start eBPF capture
                if capture_instance.start():
                    use_ebpf = True
                    capture_started = True
                    logger.info("Packet capture started successfully with eBPF acceleration")
                else:
                    logger.warning("Failed to start eBPF capture, will try standard capture")
            except Exception as e:
                logger.error(f"Error initializing eBPF capture: {e}")
                logger.warning("Will try standard capture method")
        else:
            logger.warning("eBPF not supported on this system, using standard capture")
    else:
        logger.warning("eBPF module not available, using standard capture")

    # If eBPF didn't work, use standard capture based on CAPTURE_MODE
    if not capture_started:
        from .network import set_ebpf_mode
        from .config import CAPTURE_MODE
        
        set_ebpf_mode(False)
        
        # Determine which capture mode to use
        capture_mode = CAPTURE_MODE.lower()
        
        if capture_mode not in ["auto", "sniff", "socket"]:
            logger.warning(f"Invalid CAPTURE_MODE '{CAPTURE_MODE}', defaulting to 'auto'")
            capture_mode = "auto"
        
        # For "auto" mode without eBPF, default to "sniff" (more reliable)
        if capture_mode == "auto":
            capture_mode = "sniff"
            logger.info("Auto mode selected: using 'sniff' capture method")
        
        logger.info(f"Capture mode: {capture_mode.upper()}")
        
        # =======================================================================
        # SOCKET MODE: Use UDP socket listeners only
        # =======================================================================
        if capture_mode == "socket":
            logger.info("Starting UDP socket listeners (socket mode)")
            logger.info(f"Listening on interface '{INTERFACE}', UDP ports {LISTEN_PORTS}")
            
            # Start UDP listeners - they will queue packets for processing
            if not start_all_udp_listeners():
                logger.warning("Some UDP listeners failed to start")
                logger.warning("This may cause packet loss if ports are in use by other services")
            
            # In socket mode, we just wait for stop signal
            # The UDP listeners run in their own threads and queue packets
            try:
                logger.info("Socket mode active - packet capture running in background threads")
                while not stop_event.is_set():
                    time.sleep(1)
            except KeyboardInterrupt:
                logger.info("TrapNinja service stopped by keyboard interrupt")
        
        # =======================================================================
        # SNIFF MODE: Use Scapy sniff() with libpcap
        # =======================================================================
        elif capture_mode == "sniff":
            logger.info("Starting packet capture with Scapy sniff (sniff mode)")
            logger.info(f"Listening on interface '{INTERFACE}', UDP ports {LISTEN_PORTS}")
            logger.info("NOTE: UDP socket listeners are DISABLED in sniff mode to prevent duplication")
            
            # CRITICAL: Ensure no UDP socket listeners are running!
            # Having both socket listeners AND sniff() causes 2x packet duplication
            cleanup_udp_sockets()
            logger.debug("Cleaned up any existing UDP socket listeners")
            
            try:
                # Construct BPF filter for incoming traps only
                # CRITICAL: Must exclude our own forwarded packets to prevent re-capture loop
                # - "udp dst port 162" captures packets destined to port 162
                # - "not udp src port 10162" excludes packets WE are sending (FORWARD_SOURCE_PORT)
                # Without the exclusion, forwarded packets (sport=10162, dport=162) would be re-captured
                from .core.constants import FORWARD_SOURCE_PORT
                port_filter = " or ".join(
                    [f"(udp dst port {port} and not udp src port {FORWARD_SOURCE_PORT})" 
                     for port in LISTEN_PORTS]
                )
                logger.info(f"BPF filter: {port_filter}")
                
                # Use prn callback to queue packets instead of processing them directly
                sniff(
                    iface=INTERFACE,
                    filter=port_filter,
                    prn=ha_aware_forward_trap,  # Use HA-aware packet handler
                    store=0,  # Don't store packets in memory
                    stop_filter=lambda x: stop_event.is_set()
                )
            except KeyboardInterrupt:
                logger.info("TrapNinja service stopped by keyboard interrupt")
            except Exception as e:
                logger.error(f"Error in packet capture: {e}", exc_info=True)
                # Keep running to check for configuration changes or corrections
                logger.info("Waiting for configuration update or manual restart...")
                
                # Instead of exiting, stay running until explicitly stopped
                while not stop_event.is_set():
                    time.sleep(5)
    else:
        # eBPF capture is running, just wait for termination
        logger.info("TrapNinja service running with packet capture active")
        try:
            # Main thread just waits for stop signal with periodic HA status logging
            last_status_log = 0
            while not stop_event.is_set():
                current_time = time.time()

                # Log HA status every 60 seconds
                if current_time - last_status_log > 60:
                    ha_status = get_ha_status()
                    if ha_status.get('enabled', False):
                        logger.info(f"HA Status: {ha_status['state']}, "
                                    f"Forwarding: {ha_status['is_forwarding']}, "
                                    f"Peer Connected: {ha_status.get('peer_connected', False)}")
                    last_status_log = current_time

                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("TrapNinja service stopped by keyboard interrupt")
            stop_event.set()

    # =======================================================================
    # SHUTDOWN: Clean up resources
    # =======================================================================

    # Signal workers to stop
    stop_event.set()
    logger.info("Stopping packet processing workers...")

    # Shutdown packet processor (socket pool, stats)
    try:
        from .packet_processor import shutdown as shutdown_processor
        shutdown_processor()
    except ImportError:
        pass

    # Shutdown control socket
    try:
        if CONTROL_SOCKET_AVAILABLE:
            shutdown_control_socket()
    except Exception as e:
        logger.error(f"Error shutting down control socket: {e}")

    # Shutdown HA cluster
    shutdown_ha()

    # Stop capture if active
    if capture_instance:
        capture_instance.stop()

    # Wait for queue to empty (with progress logging)
    shutdown_start_time = time.time()
    max_wait_time = 10  # Extended wait time for large queues

    try:
        last_size = packet_queue.qsize()
        while not packet_queue.empty() and time.time() - shutdown_start_time < max_wait_time:
            current_size = packet_queue.qsize()
            if current_size != last_size:
                logger.info(f"Draining queue: {current_size} packets remaining...")
                last_size = current_size
            time.sleep(0.5)
    except Exception:
        pass

    # Clean up UDP sockets
    cleanup_udp_sockets()

    # Final metrics export before shutdown
    try:
        metrics_summary = get_metrics_summary()
        logger.info("Final metrics summary:")
        logger.info(f"Total traps received: {metrics_summary['total_traps_received']}")
        logger.info(f"Total traps forwarded: {metrics_summary['total_traps_forwarded']}")
        logger.info(f"Total traps blocked: {metrics_summary['total_traps_blocked']}")
        logger.info(f"Total traps redirected: {metrics_summary['total_traps_redirected']}")
    except Exception as e:
        logger.error(f"Error exporting final metrics: {e}")

    logger.info("TrapNinja service shutting down")
    return 0


def ha_aware_forward_trap(packet):
    """
    HA-aware packet capture function that only forwards when this instance is active

    Args:
        packet: Scapy packet from sniff function
    """
    try:
        # Check if HA allows forwarding
        if not is_forwarding_enabled():
            logger.debug("Packet captured but forwarding disabled by HA")
            return

        # Use the original forward_trap function
        forward_trap(packet)

        # Notify HA system that we processed a trap
        notify_trap_processed()

    except Exception as e:
        logger.error(f"Error in HA-aware packet forwarding: {e}")


def get_ha_status():
    """
    Get HA status from the cluster instance
    
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
    Get comprehensive service status including HA information

    Returns:
        dict: Service status information including uptime, configuration, HA state, and metrics
    """
    from .config import destinations, blocked_traps, blocked_ips

    # Calculate uptime
    uptime = time.time() - start_time if start_time else 0

    # Get basic service info
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

    return status
