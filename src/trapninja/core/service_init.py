#!/usr/bin/env python3
"""
TrapNinja Service Initializer

Breaks the monolithic run_service() into distinct, testable initialization
phases. Each phase can be independently tested and has clear dependencies.

The ServiceInitializer orchestrates the full service lifecycle:
  1. Configuration validation
  2. Capture mode determination
  3. Debug/logging setup
  4. PID file + signal handlers
  5. Control socket initialization
  6. HA cluster initialization
  7. Metrics initialization
  8. Cache initialization
  9. Granular statistics initialization
  10. Configuration loading (destinations, filters, redirections)
  11. SNMPv3 decryption initialization
  12. Worker thread startup
  13. Packet capture startup (eBPF / sniff / socket)
  14. Main loop
  15. Ordered shutdown

Refactoring: Category B1 from CODE-REVIEW-REFACTORING-ANALYSIS.md
Previously ~850 lines in a single function, now modular and testable.

Author: TrapNinja Team
"""

import logging
import multiprocessing
import os
import queue
import signal
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from scapy.all import get_if_list

from ..config import (
    CONFIG_DIR,
    INTERFACE,
    LISTEN_PORTS,
    LOG_FILE,
    PID_FILE,
    load_config,
    stop_event,
)
from ..ha import (
    HAState,
    get_ha_cluster,
    initialize_ha,
    load_ha_config,
    shutdown_ha,
)
from ..metrics import get_metrics_summary, init_metrics, load_metrics_config
from ..network import (
    cleanup_udp_sockets,
    forward_trap,
    packet_queue,
    start_all_udp_listeners,
    start_packet_processors,
    start_queue_monitor,
)
from ..redirection import load_redirection_config, schedule_config_check
from .optional_modules import modules
from .capture import (
    try_ebpf_capture,
    run_standard_capture,
    run_ebpf_main_loop,
)

# Import cache config loader (always available from config module)
try:
    from ..config import CACHE_CONFIG_FILE, load_cache_config
except ImportError:
    CACHE_CONFIG_FILE = None

    def load_cache_config():
        return None


logger = logging.getLogger("trapninja")


# =============================================================================
# CONFIGURATION DATACLASSES
# =============================================================================


@dataclass
class RuntimeConfig:
    """
    Runtime configuration for a service invocation.

    Maps directly to the CLI arguments passed to run_service().
    Immutable after creation to prevent accidental mid-run changes.
    """

    debug: bool = False
    shadow_mode: bool = False
    mirror_mode: bool = False
    parallel: bool = False
    capture_mode: Optional[str] = None
    log_traps: Optional[str] = None


@dataclass
class SubsystemHandles:
    """
    Tracks handles to all initialized subsystems for ordered shutdown.

    Each field is populated during initialization and consulted during
    shutdown to ensure proper cleanup in reverse dependency order.
    """

    control_initialized: bool = False
    ha_initialized: bool = False
    ha_enabled: bool = False
    cache_initialized: bool = False
    stats_initialized: bool = False
    shadow_initialized: bool = False
    metrics_config: Optional[Any] = None
    metrics_dir: str = ""
    capture_instance: Optional[Any] = None
    use_ebpf: bool = False
    fragment_buffer: Optional[Any] = None
    fragment_reassembly_enabled: bool = False
    workers: list = field(default_factory=list)
    worker_count: int = 0
    observe_only: bool = False
    force_sniff_mode: bool = False


# =============================================================================
# SERVICE INITIALIZER
# =============================================================================


class ServiceInitializer:
    """
    Orchestrates TrapNinja service lifecycle in distinct, testable phases.

    Each initialization method is independent and returns a success/failure
    indication. The run() method orchestrates all phases in dependency order
    with proper error handling and cleanup.

    Usage:
        config = RuntimeConfig(debug=True, shadow_mode=False)
        initializer = ServiceInitializer(config)
        exit_code = initializer.run()
    """

    def __init__(self, config: RuntimeConfig):
        self.config = config
        self.handles = SubsystemHandles()
        self.start_time: Optional[float] = None
        self._forwarding_enabled = True

    # =========================================================================
    # PHASE 1: Configuration Validation
    # =========================================================================

    def validate_configuration(self) -> Tuple[bool, List[str], List[str]]:
        """
        Validate all configuration before starting the service.

        Delegates to the module-level validate_configuration() which performs
        comprehensive checks on network interface, ports, destinations,
        HA config, and cache config.

        Returns:
            Tuple of (is_valid, errors, warnings)
        """
        # Import here to use the existing thorough validation
        from ..service import validate_configuration as _validate

        return _validate()

    # =========================================================================
    # PHASE 2: Capture Mode Determination
    # =========================================================================

    def setup_capture_mode(self) -> None:
        """
        Determine capture mode based on shadow/mirror/parallel flags.

        Sets force_sniff_mode and observe_only on SubsystemHandles,
        and initializes shadow mode module if appropriate.
        """
        cfg = self.config
        handles = self.handles

        if not (cfg.shadow_mode or cfg.mirror_mode or cfg.parallel):
            # Standard mode - apply any CLI override
            if cfg.capture_mode:
                from .. import config as config_mod

                config_mod.CAPTURE_MODE = cfg.capture_mode
                logger.info(f"Capture mode overridden via CLI: {cfg.capture_mode}")
            return

        # Shadow/mirror/parallel modes require sniff capture for coexistence
        handles.force_sniff_mode = True

        if cfg.shadow_mode:
            handles.observe_only = True
            logger.info("=" * 60)
            logger.info("SHADOW MODE ENABLED")
            logger.info("  - Using sniff capture (can run alongside other receivers)")
            logger.info("  - Forwarding DISABLED - observe only")
            logger.info("  - All traps will be counted but NOT forwarded")
            logger.info("=" * 60)
        elif cfg.mirror_mode:
            logger.info("=" * 60)
            logger.info("MIRROR MODE ENABLED")
            logger.info("  - Using sniff capture (can run alongside other receivers)")
            logger.info("  - Forwarding ENABLED - parallel operation")
            logger.info("  - Both TrapNinja and existing receivers will forward traps")
            logger.info("=" * 60)
        else:
            logger.info("=" * 60)
            logger.info("PARALLEL CAPTURE ENABLED")
            logger.info("  - Using sniff capture (can run alongside other receivers)")
            logger.info("=" * 60)

        # Initialize shadow mode module if available
        if modules.shadow.available:
            shadow_config = modules.shadow.ShadowConfig(
                enabled=cfg.shadow_mode,
                observe_only=handles.observe_only,
                log_all_traps=bool(cfg.log_traps),
                log_file=cfg.log_traps,
            )
            capture_config = modules.shadow.CaptureConfig(
                mode="sniff"
                if handles.force_sniff_mode
                else (cfg.capture_mode or "auto"),
                allow_parallel=handles.force_sniff_mode,
            )
            modules.shadow.initialize(shadow_config, capture_config)
            handles.shadow_initialized = True

        # Override capture mode for parallel operation
        if cfg.capture_mode:
            from .. import config as config_mod

            config_mod.CAPTURE_MODE = cfg.capture_mode
            logger.info(f"Capture mode overridden via CLI: {cfg.capture_mode}")
        elif handles.force_sniff_mode:
            from .. import config as config_mod

            config_mod.CAPTURE_MODE = "sniff"
            logger.info("Capture mode forced to SNIFF for parallel operation")

    # =========================================================================
    # PHASE 3: Debug & Logging Setup
    # =========================================================================

    def setup_logging(self) -> None:
        """Configure debug logging if requested."""
        if not self.config.debug:
            return

        logger.setLevel(logging.DEBUG)
        ch = logging.StreamHandler()
        ch.setLevel(logging.DEBUG)
        formatter = logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s")
        ch.setFormatter(formatter)
        logger.addHandler(ch)
        logger.debug("Debug mode enabled - verbose logging activated")

    # =========================================================================
    # PHASE 4: PID File & Signal Handlers
    # =========================================================================

    def setup_process(self) -> None:
        """Write PID file and register signal handlers."""
        self.start_time = time.time()

        logger.info(
            f"Starting TrapNinja service with HA support (PID: {os.getpid()})..."
        )
        logger.info(f"Python version: {sys.version}")
        logger.info(f"Running as user: {os.getenv('USER', 'unknown')}")
        logger.info(f"Configuration directory: {CONFIG_DIR}")

        # Write PID file
        try:
            with open(PID_FILE, "w") as f:
                f.write(str(os.getpid()))
            logger.info(f"PID file updated with current PID: {os.getpid()}")
        except Exception as e:
            logger.error(f"Failed to write PID file: {e}")

        # Register signal handlers
        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT, self._handle_signal)

    def _handle_signal(self, signum: int, frame: Any) -> None:
        """
        Signal handler for graceful shutdown with HA coordination.

        Args:
            signum: Signal number
            frame: Current stack frame
        """
        logger.info(f"Received signal {signum}, shutting down...")
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
            logger.info(
                f"Total traps received: {metrics_summary['total_traps_received']}"
            )
            logger.info(
                f"Total traps forwarded: {metrics_summary['total_traps_forwarded']}"
            )
            logger.info(
                f"Total traps blocked: {metrics_summary['total_traps_blocked']}"
            )
            logger.info(
                f"Total traps redirected: {metrics_summary['total_traps_redirected']}"
            )
        except Exception as e:
            logger.error(f"Error logging final metrics: {e}")

        # Stop capture if active
        if self.handles.capture_instance:
            self.handles.capture_instance.stop()

        # Clean up network resources
        cleanup_udp_sockets()

        sys.exit(0)

    # =========================================================================
    # PHASE 5: Control Socket
    # =========================================================================

    def initialize_control_socket(self) -> bool:
        """
        Initialize Unix control socket for CLI communication.

        Returns:
            True if initialized successfully or module unavailable (non-fatal)
        """
        if not modules.control.available:
            logger.warning(
                "Control socket module not available - CLI commands will not work"
            )
            logger.warning("This is expected if running older code without control.py")
            logger.warning("Service will continue in compatibility mode")
            return True

        logger.info("Initializing control socket for CLI communication...")
        try:
            if not modules.control.initialize():
                logger.warning(
                    "Failed to initialize control socket - CLI commands may not work"
                )
                logger.warning("Service will continue without control socket support")
            else:
                self.handles.control_initialized = True
                logger.info("Control socket initialized successfully")
        except Exception as e:
            logger.error(f"Error initializing control socket: {e}")
            logger.error("Service will continue without control socket support")
            import traceback

            logger.debug(traceback.format_exc())

        return True

    # =========================================================================
    # PHASE 6: High Availability
    # =========================================================================

    def _trap_forwarder_control(self, enabled: bool) -> None:
        """
        Callback for HA state changes to control trap forwarding.

        Args:
            enabled: Whether to enable or disable trap forwarding
        """
        self._forwarding_enabled = enabled
        if enabled:
            logger.info("HA: Trap forwarding enabled - this instance is active")
        else:
            logger.info("HA: Trap forwarding disabled - this instance is standby")

    def initialize_ha(self) -> bool:
        """
        Initialize High Availability cluster if configured.

        Returns:
            True if HA initialized or disabled. False on fatal error.
        """
        logger.info("Initializing High Availability system...")

        try:
            ha_config = load_ha_config()

            if not ha_config.enabled:
                logger.info("HA disabled - running in standalone mode")
                return True

            logger.info(
                f"HA enabled - Mode: {ha_config.mode}, Priority: {ha_config.priority}"
            )
            logger.info(f"Peer: {ha_config.peer_host}:{ha_config.peer_port}")

            # Initialize HA cluster with config_dir for config sync
            if not initialize_ha(
                ha_config, self._trap_forwarder_control, config_dir=CONFIG_DIR
            ):
                logger.error("Failed to initialize HA cluster")
                return False

            self.handles.ha_initialized = True
            self.handles.ha_enabled = True

            # Wait for initial HA state to stabilize
            time.sleep(2.0)

            # Log initial HA status
            from ..service import get_ha_status

            ha_status = get_ha_status()
            logger.info(
                f"HA Status: {ha_status['state']}, "
                f"Forwarding: {ha_status['is_forwarding']}"
            )

            return True

        except Exception as e:
            logger.error(f"Error initializing HA: {e}")
            return False

    # =========================================================================
    # PHASE 7: Metrics
    # =========================================================================

    def initialize_metrics(self) -> bool:
        """
        Initialize Prometheus metrics collection.

        Returns:
            True always (metrics failure is non-fatal)
        """
        metrics_dir = os.path.join(os.path.dirname(LOG_FILE), "metrics")
        metrics_config = None

        try:
            metrics_config = load_metrics_config()
            if metrics_config:
                init_metrics(config=metrics_config)
                metrics_dir = metrics_config.directory
                logger.info("Metrics collection initialized:")
                logger.info(f"  Output directory: {metrics_config.directory}")
                logger.info(
                    f"  Export interval: {metrics_config.export_interval_seconds}s"
                )
                if metrics_config.global_labels:
                    labels_str = ", ".join(
                        f"{k}={v}" for k, v in metrics_config.global_labels.items()
                    )
                    logger.info(f"  Global labels: {labels_str}")
            else:
                init_metrics(metrics_directory=metrics_dir, export_interval=60)
                logger.info(
                    f"Metrics collection initialized with defaults: {metrics_dir}"
                )
        except Exception as e:
            logger.warning(f"Error loading metrics config: {e}")
            init_metrics(metrics_directory=metrics_dir, export_interval=60)
            logger.info(
                f"Metrics collection initialized with fallback: {metrics_dir}"
            )

        self.handles.metrics_config = metrics_config
        self.handles.metrics_dir = metrics_dir
        return True

    # =========================================================================
    # PHASE 8: Cache
    # =========================================================================

    def initialize_cache(self) -> bool:
        """
        Initialize Redis-based trap caching if configured.

        Returns:
            True always (cache failure is non-fatal)
        """
        if not modules.cache.available:
            logger.debug("Cache module not available")
            return True

        logger.info("Initializing cache system...")
        try:
            cache_config = load_cache_config()
            if cache_config and cache_config.enabled:
                cache = modules.cache.initialize(cache_config, CACHE_CONFIG_FILE)
                if cache and cache.available:
                    self.handles.cache_initialized = True
                    logger.info(
                        f"Cache enabled: Redis at "
                        f"{cache_config.host}:{cache_config.port}"
                    )
                    logger.info(
                        f"Cache retention: {cache_config.retention_hours} hours"
                    )
                else:
                    logger.warning(
                        "Cache configured but failed to connect to Redis"
                    )
                    logger.info("Traps will be forwarded but not cached")
                    logger.info(
                        "To enable caching, ensure Redis is running and accessible"
                    )
            else:
                logger.info("Cache not enabled - traps will not be buffered")
                logger.info(
                    "To enable caching, create config/cache_config.json "
                    "with enabled=true"
                )
        except Exception as e:
            logger.warning(f"Failed to initialize cache: {e}")
            logger.info("Traps will be forwarded without caching")

        return True

    # =========================================================================
    # PHASE 9: Granular Statistics
    # =========================================================================

    def initialize_stats(self) -> bool:
        """
        Initialize granular statistics collection system.

        Returns:
            True always (stats failure is non-fatal)
        """
        if not modules.stats.available:
            logger.debug("Granular statistics module not available")
            return True

        logger.info("Initializing granular statistics system...")
        try:
            # Get global labels from metrics config (if available)
            global_labels = {}
            mc = self.handles.metrics_config
            if mc and mc.global_labels:
                global_labels = mc.global_labels

            stats_config = modules.stats.CollectorConfig(
                max_ips=10000,
                max_oids=5000,
                max_destinations=100,
                cleanup_interval=300,
                stale_threshold=3600,
                rate_window=60,
                export_interval=60,
                metrics_dir=self.handles.metrics_dir,
                global_labels=global_labels,
            )

            collector = modules.stats.initialize(stats_config)

            if collector:
                self.handles.stats_initialized = True
                logger.info(
                    "Granular statistics collector initialized successfully"
                )
                logger.info(f"  Max tracked IPs: {stats_config.max_ips:,}")
                logger.info(f"  Max tracked OIDs: {stats_config.max_oids:,}")
                logger.info(
                    f"  Export interval: {stats_config.export_interval}s"
                )
                if global_labels:
                    labels_str = ", ".join(
                        f"{k}={v}" for k, v in global_labels.items()
                    )
                    logger.info(f"  Global labels: {labels_str}")
            else:
                logger.warning(
                    "Failed to initialize granular statistics collector"
                )
        except Exception as e:
            logger.warning(f"Error initializing granular statistics: {e}")
            logger.info("Service will continue without granular statistics")

        return True

    # =========================================================================
    # PHASE 10: Load Runtime Configuration
    # =========================================================================

    def load_runtime_configuration(self) -> bool:
        """
        Load destinations, filters, redirections, and log status.

        Returns:
            True always (missing config produces warnings, not errors)
        """
        from ..config import (
            blocked_ips,
            blocked_traps,
            destinations,
            redirected_destinations,
            redirected_ips,
            redirected_oids,
        )

        # Load configuration (no callback - listeners started separately)
        config_changed = load_config(None)
        logger.info(f"Initial configuration loaded (changed: {config_changed})")

        # Initialize redirection configuration
        try:
            schedule_config_check(interval=60)
            logger.info("Redirection configuration loaded:")
            logger.info(f"  - IP redirections: {len(redirected_ips)}")
            logger.info(f"  - OID redirections: {len(redirected_oids)}")
            logger.info(f"  - Destination groups: {len(redirected_destinations)}")
        except Exception as e:
            logger.error(f"Error initializing redirection configuration: {e}")

        # Log destinations
        if not destinations:
            logger.warning(
                "No destinations loaded from configuration! "
                "Traps will not be forwarded."
            )
            logger.warning(
                f"Please check the destinations file: {CONFIG_DIR}/destinations.json"
            )
            logger.warning(
                'Example content: [["192.168.1.100", 162], ["127.0.0.1", 1162]]'
            )
        else:
            logger.info(f"Current destinations: {destinations}")

        # Log blocked OIDs
        logger.info(f"Number of blocked trap OIDs: {len(blocked_traps)}")
        if blocked_traps:
            oid_list = list(blocked_traps)
            if len(oid_list) <= 5:
                logger.info(f"Blocked trap OIDs: {sorted(oid_list)}")
            else:
                logger.info(
                    f"First 5 blocked trap OIDs (of {len(oid_list)} total): "
                    f"{sorted(oid_list)[:5]}"
                )

        # Log blocked IPs
        logger.info(f"Number of blocked IP addresses: {len(blocked_ips)}")
        if blocked_ips:
            if len(blocked_ips) <= 10:
                logger.info(f"Blocked IP addresses: {sorted(blocked_ips)}")
            else:
                logger.info(
                    f"First 10 blocked IP addresses "
                    f"(of {len(blocked_ips)} total): "
                    f"{sorted(list(blocked_ips))[:10]}"
                )

        # Log interface status
        available_interfaces = get_if_list()
        logger.info(f"Available interfaces: {available_interfaces}")

        if INTERFACE not in available_interfaces:
            logger.warning(
                f"Configured interface '{INTERFACE}' not found! "
                f"Available interfaces: {available_interfaces}"
            )
            logger.warning(
                "Please update the configuration with a valid interface name."
            )
            logger.info(f"Will attempt to use interface: {INTERFACE} anyway")
        else:
            logger.info(f"Using interface: {INTERFACE}")

        return True

    # =========================================================================
    # PHASE 11: SNMPv3 Decryption
    # =========================================================================

    def initialize_snmpv3(self) -> bool:
        """
        Initialize SNMPv3 decryption subsystem if dependencies are available.

        Returns:
            True always (SNMPv3 failure is non-fatal)
        """
        try:
            logger.info("Initializing SNMPv3 decryption subsystem...")
            from ..snmpv3_credentials import get_credential_store
            from ..snmpv3_decryption import (
                PYSNMP_AVAILABLE,
                initialize_snmpv3_decryptor,
            )

            if not PYSNMP_AVAILABLE:
                logger.info("SNMPv3 decryption dependencies not installed")
                logger.info(
                    "  SNMPv3 traps will be forwarded without decryption"
                )
                logger.info(
                    "  To enable decryption, install: "
                    "pip3 install --break-system-packages pysnmp pyasn1 cryptography"
                )
                return True

            # Initialize credential store and decryptor
            credential_store = get_credential_store()
            decryptor = initialize_snmpv3_decryptor()

            if decryptor:
                engine_ids = credential_store.get_engine_ids()
                if engine_ids:
                    logger.info(
                        f"SNMPv3 decryption enabled with "
                        f"{len(engine_ids)} configured engine(s)"
                    )
                    for engine_id in engine_ids:
                        users = credential_store.get_users_for_engine(engine_id)
                        logger.info(
                            f"  - Engine {engine_id}: {len(users)} user(s)"
                        )
                else:
                    logger.info(
                        "SNMPv3 decryption initialized but no credentials "
                        "configured"
                    )
                    logger.info(
                        "  Use --snmpv3-add-user to add SNMPv3 credentials"
                    )
            else:
                logger.warning("SNMPv3 decryptor initialization failed")
                logger.info(
                    "  SNMPv3 traps will be forwarded without decryption"
                )

        except ImportError as e:
            logger.info(f"SNMPv3 decryption not available: {e}")
            logger.info(
                "  SNMPv3 traps will be forwarded without decryption"
            )
            logger.info(
                "  To enable decryption, install: "
                "pip3 install --break-system-packages pysnmp pyasn1 cryptography"
            )
        except Exception as e:
            logger.warning(f"Failed to initialize SNMPv3 decryption: {e}")
            logger.warning(
                "SNMPv3 traps will be forwarded without decryption"
            )

        return True

    # =========================================================================
    # PHASE 12: Worker Threads
    # =========================================================================

    def start_workers(self) -> bool:
        """
        Start packet processing worker threads.

        Determines optimal worker count based on CPU cores and starts
        the packet processing pipeline.

        Returns:
            True if workers started successfully
        """
        cpu_count = multiprocessing.cpu_count()
        worker_count = min(cpu_count * 2, 32)

        # Start queue monitor for utilization tracking
        start_queue_monitor()

        # Start optimized packet processing workers
        workers = start_packet_processors(num_workers=worker_count)
        self.handles.workers = workers
        self.handles.worker_count = len(workers)

        logger.info(
            f"Started {len(workers)} packet processing workers (optimized)"
        )
        logger.info(f"Queue capacity: {packet_queue.maxsize} packets")

        # Allow workers to fully initialize before starting capture
        worker_warmup_delay = 0.5
        logger.info(
            f"Waiting {worker_warmup_delay}s for workers to initialize..."
        )
        time.sleep(worker_warmup_delay)

        return True

    # =========================================================================
    # PHASE 13: Packet Capture (delegated to core.capture)
    # =========================================================================

    def start_capture(self) -> int:
        """
        Start packet capture and run the main service loop.

        Attempts capture in order: eBPF → standard (socket/sniff).
        Contains the main blocking loop that keeps the service alive.
        Heavy lifting delegated to core.capture module.

        Returns:
            Exit code (0 for clean shutdown)
        """
        capture_started = False

        # Try eBPF if available and not in parallel mode
        if self.handles.force_sniff_mode:
            logger.info(
                "Skipping eBPF - parallel/shadow/mirror mode requires "
                "sniff capture"
            )
        elif modules.ebpf.available:
            capture_started = try_ebpf_capture(self.handles)

        # Standard capture (socket or sniff)
        if not capture_started:
            return run_standard_capture(self.handles)

        # eBPF capture running - enter main loop
        return run_ebpf_main_loop()

    # =========================================================================
    # PHASE 14: Shutdown
    # =========================================================================

    def shutdown(self) -> None:
        """
        Orderly shutdown of all subsystems in reverse dependency order.

        Safe to call multiple times. Each subsystem is only shut down
        if it was successfully initialized.
        """
        stop_event.set()
        logger.info("Stopping packet processing workers...")

        # Shadow mode
        if self.handles.shadow_initialized and modules.shadow.available:
            try:
                modules.shadow.shutdown()
            except Exception as e:
                logger.error(f"Error shutting down shadow mode: {e}")

        # Fragment reassembly
        if modules.fragmentation.available:
            try:
                frag_stats = modules.fragmentation.get_stats()
                if frag_stats:
                    logger.info(
                        f"Fragment stats: "
                        f"completed={frag_stats.get('datagrams_completed', 0)}, "
                        f"timeout={frag_stats.get('datagrams_timeout', 0)}, "
                        f"evicted={frag_stats.get('datagrams_evicted', 0)}"
                    )
                modules.fragmentation.shutdown()
            except Exception as e:
                logger.debug(f"Error shutting down fragment buffer: {e}")

        # Packet processor (socket pool)
        try:
            from ..processing import shutdown_forwarder

            shutdown_forwarder()
            logger.info("Packet processing resources released")
        except ImportError:
            pass

        # Cache
        if self.handles.cache_initialized and modules.cache.available:
            try:
                modules.cache.shutdown()
            except Exception as e:
                logger.error(f"Error shutting down cache: {e}")

        # Granular statistics
        if self.handles.stats_initialized and modules.stats.available:
            try:
                logger.info("Shutting down granular statistics...")
                modules.stats.shutdown()
            except Exception as e:
                logger.error(f"Error shutting down granular stats: {e}")

        # Control socket
        if self.handles.control_initialized:
            try:
                if modules.control.available:
                    modules.control.shutdown()
            except Exception as e:
                logger.error(f"Error shutting down control socket: {e}")

        # HA cluster
        if self.handles.ha_initialized:
            shutdown_ha()

        # Capture instance
        if self.handles.capture_instance:
            self.handles.capture_instance.stop()

        # Drain packet queue
        self._drain_queue()

        # Clean up UDP sockets
        cleanup_udp_sockets()

        # Final metrics
        self._log_final_metrics()

        logger.info("TrapNinja service shutting down")

    def _drain_queue(self, max_wait: float = 10.0) -> None:
        """
        Wait for packet queue to drain with progress logging.

        Args:
            max_wait: Maximum seconds to wait for queue drain
        """
        shutdown_start = time.time()

        try:
            last_size = packet_queue.qsize()
            while (
                not packet_queue.empty()
                and time.time() - shutdown_start < max_wait
            ):
                current_size = packet_queue.qsize()
                if current_size != last_size:
                    logger.info(
                        f"Draining queue: {current_size} packets remaining..."
                    )
                    last_size = current_size
                time.sleep(0.5)
        except Exception:
            pass

    def _log_final_metrics(self) -> None:
        """Log final metrics summary before shutdown."""
        try:
            metrics_summary = get_metrics_summary()
            logger.info("Final metrics summary:")
            logger.info(
                f"Total traps received: "
                f"{metrics_summary['total_traps_received']}"
            )
            logger.info(
                f"Total traps forwarded: "
                f"{metrics_summary['total_traps_forwarded']}"
            )
            logger.info(
                f"Total traps blocked: "
                f"{metrics_summary['total_traps_blocked']}"
            )
            logger.info(
                f"Total traps redirected: "
                f"{metrics_summary['total_traps_redirected']}"
            )
        except Exception as e:
            logger.error(f"Error exporting final metrics: {e}")

    # =========================================================================
    # ORCHESTRATION
    # =========================================================================

    def run(self) -> int:
        """
        Full service lifecycle - orchestrates all initialization phases.

        Phases execute in dependency order. Fatal failures in critical
        phases cause early exit. Non-fatal failures log warnings and
        continue. Shutdown is always executed via finally block.

        Returns:
            Exit code (0 = success, 1 = configuration error)
        """
        try:
            # Phase 1: Validate configuration
            logger.info("Validating configuration...")
            is_valid, errors, warnings = self.validate_configuration()

            for warning in warnings:
                logger.warning(f"Configuration warning: {warning}")

            if not is_valid:
                for error in errors:
                    logger.error(f"Configuration error: {error}")
                logger.error(
                    "Configuration validation failed. "
                    "Please fix the errors above."
                )
                return 1

            logger.info("Configuration validation passed")

            # Phase 2: Determine capture mode
            self.setup_capture_mode()

            # Phase 3: Debug/logging
            self.setup_logging()

            # Phase 4: PID + signals
            self.setup_process()

            # Phase 5: Control socket (non-fatal)
            self.initialize_control_socket()

            # Phase 6: HA (fatal on error)
            if not self.initialize_ha():
                return 1

            # Phase 7: Metrics (non-fatal)
            self.initialize_metrics()

            # Phase 8: Cache (non-fatal)
            self.initialize_cache()

            # Phase 9: Granular stats (non-fatal)
            self.initialize_stats()

            # Phase 10: Load runtime config
            self.load_runtime_configuration()

            # Phase 11: SNMPv3 (non-fatal)
            self.initialize_snmpv3()

            # Phase 12: Start workers
            self.start_workers()

            # Phase 13+14: Capture + main loop (blocking)
            return self.start_capture()

        finally:
            # Phase 15: Always shutdown cleanly
            self.shutdown()
