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
# This eliminates 100+ lines of try/except boilerplate while providing the same functionality
from .core.optional_modules import modules

# Import cache config loader (always available from config module)
try:
    from .config import load_cache_config, CACHE_CONFIG_FILE
except ImportError:
    CACHE_CONFIG_FILE = None
    def load_cache_config():
        return None

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
            # Check destination format - supports multiple formats:
            # 1. List/tuple: ["host", port] or ("host", port)
            # 2. Dict: {"host": "...", "port": 162}
            # 3. String: "host:port" or "host"
            if isinstance(dest, (list, tuple)):
                # Array format: ["host", port]
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
                # Dict format: {"host": "...", "port": 162}
                if 'host' not in dest:
                    errors.append(f"Destination missing 'host': {dest}")
                if 'port' not in dest:
                    warnings.append(f"Destination missing 'port', will use 162: {dest}")
            elif isinstance(dest, str):
                # String format "host:port" or "host"
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
            # Check peer host
            if not ha_config.peer_host:
                errors.append("HA enabled but peer_host not configured")
            
            # Check peer port
            if ha_config.peer_port < 1 or ha_config.peer_port > 65535:
                errors.append(f"HA peer_port {ha_config.peer_port} out of valid range")
            
            # Check listen port
            if ha_config.listen_port < 1 or ha_config.listen_port > 65535:
                errors.append(f"HA listen_port {ha_config.listen_port} out of valid range")
            
            # Check heartbeat settings
            if ha_config.heartbeat_interval <= 0:
                errors.append("HA heartbeat_interval must be positive")
            
            if ha_config.heartbeat_timeout <= ha_config.heartbeat_interval:
                warnings.append(
                    "HA heartbeat_timeout should be greater than heartbeat_interval"
                )
            
            # Warn if no shared secret (weaker authentication)
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
            cache_config = load_cache_config()
            if cache_config and cache_config.enabled:
                if not cache_config.host:
                    errors.append("Cache enabled but Redis host not configured")
                if cache_config.port < 1 or cache_config.port > 65535:
                    errors.append(f"Cache port {cache_config.port} out of valid range")
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
        if modules.control.available:
            modules.control.shutdown()
    except Exception as e:
        logger.error(f"Error shutting down control socket: {e}")

    # Shutdown HA cluster first to coordinate with peer
    shutdown_ha()

    # Shutdown granular statistics
    if modules.stats.available:
        try:
            modules.stats.shutdown()
        except Exception as e:
            logger.error(f"Error shutting down granular stats: {e}")

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


def run_service(debug=False, shadow_mode=False, mirror_mode=False,
                parallel=False, capture_mode=None, log_traps=None):
    """
    Main service function with HA integration

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
    global capture_instance, use_ebpf, ha_forwarding_enabled, start_time
    
    # Record service start time
    start_time = time.time()
    
    # =======================================================================
    # Validate Configuration Before Starting
    # =======================================================================
    logger.info("Validating configuration...")
    is_valid, errors, warnings = validate_configuration()
    
    # Log warnings
    for warning in warnings:
        logger.warning(f"Configuration warning: {warning}")
    
    # If there are errors, fail fast
    if not is_valid:
        for error in errors:
            logger.error(f"Configuration error: {error}")
        logger.error("Configuration validation failed. Please fix the errors above.")
        return 1
    
    logger.info("Configuration validation passed")
    
    # =======================================================================
    # Initialize Shadow/Parallel Mode
    # =======================================================================
    observe_only = False
    force_sniff_mode = False
    
    if shadow_mode or mirror_mode or parallel:
        # Shadow/mirror/parallel modes require sniff capture for coexistence
        force_sniff_mode = True
        
        if shadow_mode:
            observe_only = True
            logger.info("="*60)
            logger.info("SHADOW MODE ENABLED")
            logger.info("  - Using sniff capture (can run alongside other receivers)")
            logger.info("  - Forwarding DISABLED - observe only")
            logger.info("  - All traps will be counted but NOT forwarded")
            logger.info("="*60)
        elif mirror_mode:
            logger.info("="*60)
            logger.info("MIRROR MODE ENABLED")
            logger.info("  - Using sniff capture (can run alongside other receivers)")
            logger.info("  - Forwarding ENABLED - parallel operation")
            logger.info("  - Both TrapNinja and existing receivers will forward traps")
            logger.info("="*60)
        else:
            logger.info("="*60)
            logger.info("PARALLEL CAPTURE ENABLED")
            logger.info("  - Using sniff capture (can run alongside other receivers)")
            logger.info("="*60)
        
        # Initialize shadow mode if available
        if modules.shadow.available:
            shadow_config = modules.shadow.ShadowConfig(
                enabled=shadow_mode,
                observe_only=observe_only,
                log_all_traps=bool(log_traps),
                log_file=log_traps
            )
            capture_config = modules.shadow.CaptureConfig(
                mode="sniff" if force_sniff_mode else (capture_mode or "auto"),
                allow_parallel=force_sniff_mode
            )
            modules.shadow.initialize(shadow_config, capture_config)
    
    # Override capture mode if specified via CLI
    if capture_mode:
        from . import config
        config.CAPTURE_MODE = capture_mode
        logger.info(f"Capture mode overridden via CLI: {capture_mode}")
    elif force_sniff_mode:
        from . import config
        config.CAPTURE_MODE = "sniff"
        logger.info("Capture mode forced to SNIFF for parallel operation")

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
    logger.info(f"Configuration directory: {CONFIG_DIR}")

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
    if modules.control.available:
        logger.info("Initializing control socket for CLI communication...")
        try:
            if not modules.control.initialize():
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

            # Initialize HA cluster with config_dir for config sync
            if not initialize_ha(ha_config, trap_forwarder_control, config_dir=CONFIG_DIR):
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
    # Load metrics configuration (supports custom directory and global labels)
    metrics_dir = os.path.join(os.path.dirname(LOG_FILE), "metrics")  # Default
    metrics_config = None  # Initialize for later use in granular stats
    try:
        metrics_config = load_metrics_config()
        if metrics_config:
            init_metrics(config=metrics_config)
            metrics_dir = metrics_config.directory  # Use configured directory
            logger.info(f"Metrics collection initialized:")
            logger.info(f"  Output directory: {metrics_config.directory}")
            logger.info(f"  Export interval: {metrics_config.export_interval_seconds}s")
            if metrics_config.global_labels:
                labels_str = ", ".join(
                    f"{k}={v}" for k, v in metrics_config.global_labels.items()
                )
                logger.info(f"  Global labels: {labels_str}")
        else:
            # Fall back to default location
            init_metrics(metrics_directory=metrics_dir, export_interval=60)
            logger.info(f"Metrics collection initialized with defaults: {metrics_dir}")
    except Exception as e:
        logger.warning(f"Error loading metrics config: {e}")
        init_metrics(metrics_directory=metrics_dir, export_interval=60)
        logger.info(f"Metrics collection initialized with fallback: {metrics_dir}")

    # =======================================================================
    # Initialize Cache System (Redis-based trap buffering)
    # =======================================================================
    if modules.cache.available:
        logger.info("Initializing cache system...")
        try:
            cache_config = load_cache_config()
            if cache_config and cache_config.enabled:
                # Pass config file path for hot-reload support
                cache = modules.cache.initialize(cache_config, CACHE_CONFIG_FILE)
                if cache and cache.available:
                    logger.info(f"Cache enabled: Redis at {cache_config.host}:{cache_config.port}")
                    logger.info(f"Cache retention: {cache_config.retention_hours} hours")
                else:
                    logger.warning("Cache configured but failed to connect to Redis")
                    logger.info("Traps will be forwarded but not cached")
                    logger.info("To enable caching, ensure Redis is running and accessible")
            else:
                logger.info("Cache not enabled - traps will not be buffered")
                logger.info("To enable caching, create config/cache_config.json with enabled=true")
        except Exception as e:
            logger.warning(f"Failed to initialize cache: {e}")
            logger.info("Traps will be forwarded without caching")
    else:
        logger.debug("Cache module not available")

    # =======================================================================
    # Initialize Granular Statistics System
    # =======================================================================
    if modules.stats.available:
        logger.info("Initializing granular statistics system...")
        try:
            # Get global labels from metrics config (if available)
            global_labels = {}
            if metrics_config and metrics_config.global_labels:
                global_labels = metrics_config.global_labels
            
            # Configure the collector
            stats_config = modules.stats.CollectorConfig(
                max_ips=10000,      # Track up to 10,000 unique source IPs
                max_oids=5000,      # Track up to 5,000 unique OIDs
                max_destinations=100,
                cleanup_interval=300,  # Cleanup stale entries every 5 minutes
                stale_threshold=3600,  # Remove entries idle for 1 hour
                rate_window=60,        # 1 minute rate calculation window
                export_interval=60,    # Export to files every minute
                metrics_dir=metrics_dir,  # Same directory as other metrics
                global_labels=global_labels,  # Apply same labels as main metrics
            )
            
            # Initialize the collector
            collector = modules.stats.initialize(stats_config)
            
            if collector:
                logger.info("Granular statistics collector initialized successfully")
                logger.info(f"  Max tracked IPs: {stats_config.max_ips:,}")
                logger.info(f"  Max tracked OIDs: {stats_config.max_oids:,}")
                logger.info(f"  Export interval: {stats_config.export_interval}s")
                if global_labels:
                    labels_str = ", ".join(f"{k}={v}" for k, v in global_labels.items())
                    logger.info(f"  Global labels: {labels_str}")
            else:
                logger.warning("Failed to initialize granular statistics collector")
        except Exception as e:
            logger.warning(f"Error initializing granular statistics: {e}")
            logger.info("Service will continue without granular statistics")
    else:
        logger.debug("Granular statistics module not available")

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
    
    # CRITICAL: Allow workers to fully initialize before starting capture
    # Without this delay, packets arrive before workers are ready to process them,
    # causing drops during the first few seconds of startup
    worker_warmup_delay = 0.5  # 500ms for thread initialization
    logger.info(f"Waiting {worker_warmup_delay}s for workers to initialize...")
    time.sleep(worker_warmup_delay)

    # =======================================================================
    # Initialize packet capture (either eBPF or traditional)
    # =======================================================================
    capture_started = False

    # Try eBPF if available
    # IMPORTANT: Skip eBPF in parallel/shadow/mirror modes - eBPF binds exclusively
    # and cannot coexist with other trap receivers. These modes require sniff capture.
    if force_sniff_mode:
        logger.info("Skipping eBPF - parallel/shadow/mirror mode requires sniff capture")
    elif modules.ebpf.available:
        logger.info("Checking for eBPF support...")

        # Check if eBPF is supported
        if modules.ebpf.is_supported() and modules.ebpf.check_dependencies():
            logger.info("eBPF support available - creating capture instance")

            try:
                # Create capture instance
                capture_instance = modules.ebpf.create_capture(
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
                    logger.info(">>> CAPTURE ACTIVE - Now receiving packets <<<")
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
            
            # =======================================================================
            # Initialize Fragment Reassembly (for traps exceeding MTU)
            # =======================================================================
            fragment_reassembly_enabled = False
            fragment_buffer = None
            
            if modules.fragmentation.available:
                # Load capture config to check if fragmentation is enabled
                try:
                    import json
                    capture_config_file = os.path.join(CONFIG_DIR, 'capture_config.json')
                    if os.path.exists(capture_config_file):
                        with open(capture_config_file, 'r') as f:
                            capture_cfg = json.load(f)
                        
                        frag_cfg = capture_cfg.get('fragment_reassembly', {})
                        fragment_reassembly_enabled = frag_cfg.get('enabled', False)
                        
                        if fragment_reassembly_enabled:
                            timeout_seconds = frag_cfg.get('timeout_seconds', 5.0)
                            max_buffer_mb = frag_cfg.get('max_buffer_mb', 100.0)
                            max_datagrams = frag_cfg.get('max_datagrams', 10000)
                            
                            fragment_buffer = modules.fragmentation.initialize(
                                timeout_seconds=timeout_seconds,
                                max_buffer_mb=max_buffer_mb,
                                max_datagrams=max_datagrams,
                            )
                            logger.info("Fragment reassembly ENABLED")
                            logger.info(f"  Timeout: {timeout_seconds}s, Buffer: {max_buffer_mb}MB, Max datagrams: {max_datagrams}")
                    else:
                        logger.debug("No capture_config.json found, fragment reassembly disabled")
                except Exception as e:
                    logger.warning(f"Could not load fragment reassembly config: {e}")
                    logger.info("Fragment reassembly disabled")
            else:
                logger.debug("Fragmentation module not available")
            
            try:
                # Construct BPF filter for incoming traps
                # CRITICAL: Must exclude our own forwarded packets to prevent re-capture loop
                from .core.constants import FORWARD_SOURCE_PORT
                
                # Get local IP for the interface - CRITICAL for parallel/sniff mode
                # Without this, we capture packets forwarded by other processes to
                # other destinations, causing duplication
                local_ip = None
                if force_sniff_mode:  # parallel, shadow, or mirror mode
                    try:
                        local_ip = get_if_addr(INTERFACE)
                        if local_ip and local_ip != '0.0.0.0':
                            logger.info(f"Parallel mode: filtering to local IP {local_ip}")
                        else:
                            logger.warning(
                                f"Could not determine local IP for {INTERFACE}, "
                                f"may capture other processes' forwarded packets"
                            )
                            local_ip = None
                    except Exception as e:
                        logger.warning(f"Failed to get local IP for {INTERFACE}: {e}")
                        local_ip = None
                
                if fragment_reassembly_enabled:
                    # Fragment-aware filter captures:
                    # 1. Complete UDP packets destined to our ports
                    # 2. Non-first IP fragments (which don't have UDP header visible)
                    port_filter = modules.fragmentation.generate_fragment_aware_filter(
                        LISTEN_PORTS, 
                        exclude_sport=FORWARD_SOURCE_PORT,
                        local_ip=local_ip
                    )
                    logger.info("Using fragment-aware BPF filter")
                else:
                    # Standard filter only captures complete packets
                    port_filter = modules.fragmentation.generate_simple_filter(
                        LISTEN_PORTS,
                        exclude_sport=FORWARD_SOURCE_PORT,
                        local_ip=local_ip
                    )
                
                logger.info(f"BPF filter: {port_filter}")
                
                # Create the appropriate packet handler
                if fragment_reassembly_enabled and fragment_buffer:
                    # Use fragment-aware handler
                    def fragment_aware_trap_handler(packet):
                        """Handle packets with fragment reassembly support."""
                        try:
                            result = fragment_buffer.process_packet(packet)
                            if result:
                                # Got a complete packet (either non-fragmented or reassembled)
                                forward_trap_dict(result)
                        except Exception as e:
                            logger.error(f"Error in fragment-aware handler: {e}")
                    
                    packet_handler = fragment_aware_trap_handler
                    logger.info("Using fragment-aware packet handler")
                else:
                    # Use standard handler
                    packet_handler = ha_aware_forward_trap
                
                # Use prn callback to queue packets instead of processing them directly
                sniff(
                    iface=INTERFACE,
                    filter=port_filter,
                    prn=packet_handler,
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

    # Shutdown shadow mode
    if modules.shadow.available:
        try:
            modules.shadow.shutdown()
        except Exception as e:
            logger.error(f"Error shutting down shadow mode: {e}")

    # Shutdown fragment reassembly buffer
    if modules.fragmentation.available:
        try:
            frag_stats = modules.fragmentation.get_stats()
            if frag_stats:
                logger.info(
                    f"Fragment stats: completed={frag_stats.get('datagrams_completed', 0)}, "
                    f"timeout={frag_stats.get('datagrams_timeout', 0)}, "
                    f"evicted={frag_stats.get('datagrams_evicted', 0)}"
                )
            modules.fragmentation.shutdown()
        except Exception as e:
            logger.debug(f"Error shutting down fragment buffer: {e}")

    # Shutdown packet processor (socket pool)
    try:
        from .processing import shutdown_forwarder
        shutdown_forwarder()
        logger.info("Packet processing resources released")
    except ImportError:
        pass

    # Shutdown cache
    if modules.cache.available:
        try:
            modules.cache.shutdown()
        except Exception as e:
            logger.error(f"Error shutting down cache: {e}")

    # Shutdown granular statistics
    if modules.stats.available:
        try:
            logger.info("Shutting down granular statistics...")
            modules.stats.shutdown()
        except Exception as e:
            logger.error(f"Error shutting down granular stats: {e}")

    # Shutdown control socket
    try:
        if modules.control.available:
            modules.control.shutdown()
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
    Packet capture callback that queues packets for processing.
    
    Note: HA state is checked in the packet processor, not here.
    This ensures packets are always queued for processing (filtering, caching)
    even on Secondary nodes. The processor will skip forwarding if HA
    indicates this node is Secondary.

    Args:
        packet: Scapy packet from sniff function
    """
    try:
        # Always queue the packet for processing
        # The packet processor will handle HA state for forwarding decisions
        # but will always cache the trap regardless of HA state
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
        
        # Log if this was a reassembled fragment
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
    
    # Add fragment reassembly stats if available
    if modules.fragmentation.available:
        try:
            frag_stats = modules.fragmentation.get_stats()
            if frag_stats:
                status["fragment_reassembly"] = frag_stats
        except Exception:
            pass

    return status
