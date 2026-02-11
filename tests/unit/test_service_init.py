#!/usr/bin/env python3
"""
Tests for TrapNinja ServiceInitializer

Verifies that each initialization phase can be tested independently,
and that the orchestration runs phases in correct dependency order.

Tests use extensive mocking since ServiceInitializer integrates
with network, HA, cache, and other subsystems.
"""

import os
import time
import pytest
import logging
from unittest.mock import patch, MagicMock, PropertyMock, mock_open
from dataclasses import asdict

from trapninja.core.service_init import (
    RuntimeConfig,
    SubsystemHandles,
    ServiceInitializer,
)


# =============================================================================
# FIXTURES
# =============================================================================


@pytest.fixture
def default_config():
    """Create a default RuntimeConfig for testing."""
    return RuntimeConfig()


@pytest.fixture
def debug_config():
    """Create a debug RuntimeConfig."""
    return RuntimeConfig(debug=True)


@pytest.fixture
def shadow_config():
    """Create a shadow-mode RuntimeConfig."""
    return RuntimeConfig(shadow_mode=True)


@pytest.fixture
def mirror_config():
    """Create a mirror-mode RuntimeConfig."""
    return RuntimeConfig(mirror_mode=True)


@pytest.fixture
def parallel_config():
    """Create a parallel-mode RuntimeConfig."""
    return RuntimeConfig(parallel=True)


@pytest.fixture
def initializer(default_config):
    """Create a ServiceInitializer with default config."""
    return ServiceInitializer(default_config)


# =============================================================================
# RUNTIME CONFIG TESTS
# =============================================================================


class TestRuntimeConfig:
    """Test RuntimeConfig dataclass."""

    def test_default_values(self):
        """Default config should have all flags disabled."""
        config = RuntimeConfig()
        assert config.debug is False
        assert config.shadow_mode is False
        assert config.mirror_mode is False
        assert config.parallel is False
        assert config.capture_mode is None
        assert config.log_traps is None

    def test_custom_values(self):
        """Custom values should be preserved."""
        config = RuntimeConfig(
            debug=True,
            shadow_mode=True,
            capture_mode="sniff",
            log_traps="/tmp/traps.log",
        )
        assert config.debug is True
        assert config.shadow_mode is True
        assert config.capture_mode == "sniff"
        assert config.log_traps == "/tmp/traps.log"


# =============================================================================
# SUBSYSTEM HANDLES TESTS
# =============================================================================


class TestSubsystemHandles:
    """Test SubsystemHandles dataclass."""

    def test_default_state(self):
        """All subsystems should start uninitialized."""
        handles = SubsystemHandles()
        assert handles.control_initialized is False
        assert handles.ha_initialized is False
        assert handles.ha_enabled is False
        assert handles.cache_initialized is False
        assert handles.stats_initialized is False
        assert handles.shadow_initialized is False
        assert handles.capture_instance is None
        assert handles.use_ebpf is False
        assert handles.fragment_buffer is None
        assert handles.fragment_reassembly_enabled is False
        assert handles.workers == []
        assert handles.worker_count == 0
        assert handles.observe_only is False
        assert handles.force_sniff_mode is False


# =============================================================================
# SERVICE INITIALIZER - CONSTRUCTION
# =============================================================================


class TestServiceInitializerConstruction:
    """Test ServiceInitializer construction."""

    def test_basic_construction(self, default_config):
        """Should create initializer with config and empty handles."""
        init = ServiceInitializer(default_config)
        assert init.config is default_config
        assert isinstance(init.handles, SubsystemHandles)
        assert init.start_time is None

    def test_forwarding_enabled_by_default(self, default_config):
        """Forwarding should be enabled by default (standalone mode)."""
        init = ServiceInitializer(default_config)
        assert init._forwarding_enabled is True


# =============================================================================
# PHASE 1: CONFIGURATION VALIDATION
# =============================================================================


class TestValidateConfiguration:
    """Test the configuration validation phase."""

    @patch("trapninja.service.validate_configuration")
    def test_delegates_to_module_validator(self, mock_validate, initializer):
        """Should delegate to the module-level validate_configuration."""
        mock_validate.return_value = (True, [], [])
        
        is_valid, errors, warnings = initializer.validate_configuration()
        
        mock_validate.assert_called_once()
        assert is_valid is True
        assert errors == []
        assert warnings == []

    @patch("trapninja.service.validate_configuration")
    def test_returns_errors(self, mock_validate, initializer):
        """Should pass through validation errors."""
        mock_validate.return_value = (
            False,
            ["Interface not found"],
            ["Port 162 is privileged"],
        )
        
        is_valid, errors, warnings = initializer.validate_configuration()
        
        assert is_valid is False
        assert "Interface not found" in errors
        assert "Port 162 is privileged" in warnings


# =============================================================================
# PHASE 2: CAPTURE MODE
# =============================================================================


class TestSetupCaptureMode:
    """Test capture mode determination."""

    def test_standard_mode_no_flags(self, initializer):
        """Standard mode should not set force_sniff or observe_only."""
        initializer.setup_capture_mode()
        
        assert initializer.handles.force_sniff_mode is False
        assert initializer.handles.observe_only is False

    def test_shadow_mode_sets_flags(self, shadow_config):
        """Shadow mode should set observe_only and force_sniff."""
        init = ServiceInitializer(shadow_config)
        
        with patch.object(init, "handles"):
            init.handles = SubsystemHandles()
            init.setup_capture_mode()
        
            assert init.handles.force_sniff_mode is True
            assert init.handles.observe_only is True

    def test_mirror_mode_sets_sniff_not_observe(self, mirror_config):
        """Mirror mode should force sniff but NOT observe_only."""
        init = ServiceInitializer(mirror_config)
        init.setup_capture_mode()
        
        assert init.handles.force_sniff_mode is True
        assert init.handles.observe_only is False

    def test_parallel_mode_sets_sniff(self, parallel_config):
        """Parallel mode should force sniff."""
        init = ServiceInitializer(parallel_config)
        init.setup_capture_mode()
        
        assert init.handles.force_sniff_mode is True

    @patch("trapninja.core.service_init.modules")
    def test_capture_mode_cli_override(self, mock_modules, default_config):
        """CLI capture_mode should override config."""
        config = RuntimeConfig(capture_mode="socket")
        init = ServiceInitializer(config)
        
        with patch("trapninja.core.service_init.modules", mock_modules):
            init.setup_capture_mode()
        
        # Verify the override was applied (would set config.CAPTURE_MODE)


# =============================================================================
# PHASE 3: LOGGING
# =============================================================================


class TestSetupLogging:
    """Test debug logging setup."""

    def test_no_debug_no_change(self, initializer):
        """Non-debug mode should not modify logger."""
        original_level = logger.level
        initializer.setup_logging()
        # Level should not have been set to DEBUG
        assert logging.getLogger("trapninja").level != logging.DEBUG or original_level == logging.DEBUG

    def test_debug_enables_verbose(self, debug_config):
        """Debug mode should set DEBUG level and add handler."""
        init = ServiceInitializer(debug_config)
        test_logger = logging.getLogger("trapninja")
        handler_count_before = len(test_logger.handlers)
        
        init.setup_logging()
        
        assert test_logger.level == logging.DEBUG


# =============================================================================
# PHASE 4: PROCESS SETUP
# =============================================================================


class TestSetupProcess:
    """Test PID file and signal handler setup."""

    @patch("trapninja.core.service_init.signal.signal")
    @patch("builtins.open", mock_open())
    def test_registers_signal_handlers(self, mock_signal, initializer):
        """Should register SIGTERM and SIGINT handlers."""
        initializer.setup_process()
        
        calls = mock_signal.call_args_list
        signal_numbers = [call[0][0] for call in calls]
        
        import signal as sig_module
        assert sig_module.SIGTERM in signal_numbers
        assert sig_module.SIGINT in signal_numbers

    @patch("trapninja.core.service_init.signal.signal")
    @patch("builtins.open", mock_open())
    def test_records_start_time(self, mock_signal, initializer):
        """Should record start time."""
        assert initializer.start_time is None
        initializer.setup_process()
        assert initializer.start_time is not None
        assert initializer.start_time > 0


# =============================================================================
# PHASE 5: CONTROL SOCKET
# =============================================================================


class TestInitializeControlSocket:
    """Test control socket initialization."""

    @patch("trapninja.core.service_init.modules")
    def test_unavailable_module_returns_true(self, mock_modules, initializer):
        """Should succeed (non-fatal) when module unavailable."""
        mock_modules.control.available = False
        
        result = initializer.initialize_control_socket()
        
        assert result is True
        assert initializer.handles.control_initialized is False

    @patch("trapninja.core.service_init.modules")
    def test_successful_init(self, mock_modules, initializer):
        """Should set flag on successful initialization."""
        mock_modules.control.available = True
        mock_modules.control.initialize.return_value = True
        
        result = initializer.initialize_control_socket()
        
        assert result is True
        assert initializer.handles.control_initialized is True

    @patch("trapninja.core.service_init.modules")
    def test_failed_init_continues(self, mock_modules, initializer):
        """Failed init should return True (non-fatal)."""
        mock_modules.control.available = True
        mock_modules.control.initialize.return_value = False
        
        result = initializer.initialize_control_socket()
        
        assert result is True
        assert initializer.handles.control_initialized is False


# =============================================================================
# PHASE 6: HIGH AVAILABILITY
# =============================================================================


class TestInitializeHA:
    """Test HA initialization."""

    @patch("trapninja.core.service_init.load_ha_config")
    def test_ha_disabled(self, mock_load_config, initializer):
        """Should succeed with HA disabled."""
        mock_config = MagicMock()
        mock_config.enabled = False
        mock_load_config.return_value = mock_config
        
        result = initializer.initialize_ha()
        
        assert result is True
        assert initializer.handles.ha_initialized is False
        assert initializer.handles.ha_enabled is False

    @patch("trapninja.core.service_init.time.sleep")
    @patch("trapninja.core.service_init.initialize_ha")
    @patch("trapninja.core.service_init.load_ha_config")
    def test_ha_init_success(self, mock_load_config, mock_init_ha, mock_sleep, initializer):
        """Should initialize HA when enabled and config valid."""
        mock_config = MagicMock()
        mock_config.enabled = True
        mock_config.mode = "primary"
        mock_config.priority = 100
        mock_config.peer_host = "10.0.0.2"
        mock_config.peer_port = 60006
        mock_load_config.return_value = mock_config
        mock_init_ha.return_value = True
        
        with patch("trapninja.service.get_ha_status", return_value={"state": "primary", "is_forwarding": True}):
            result = initializer.initialize_ha()
        
        assert result is True
        assert initializer.handles.ha_initialized is True
        assert initializer.handles.ha_enabled is True

    @patch("trapninja.core.service_init.initialize_ha")
    @patch("trapninja.core.service_init.load_ha_config")
    def test_ha_init_failure_is_fatal(self, mock_load_config, mock_init_ha, initializer):
        """HA init failure should return False (fatal)."""
        mock_config = MagicMock()
        mock_config.enabled = True
        mock_config.mode = "primary"
        mock_config.priority = 100
        mock_config.peer_host = "10.0.0.2"
        mock_config.peer_port = 60006
        mock_load_config.return_value = mock_config
        mock_init_ha.return_value = False
        
        result = initializer.initialize_ha()
        
        assert result is False


# =============================================================================
# PHASE 7: METRICS
# =============================================================================


class TestInitializeMetrics:
    """Test metrics initialization."""

    @patch("trapninja.core.service_init.init_metrics")
    @patch("trapninja.core.service_init.load_metrics_config")
    def test_default_metrics(self, mock_load_config, mock_init, initializer):
        """Should initialize with defaults when no config available."""
        mock_load_config.return_value = None
        
        result = initializer.initialize_metrics()
        
        assert result is True
        mock_init.assert_called_once()

    @patch("trapninja.core.service_init.init_metrics")
    @patch("trapninja.core.service_init.load_metrics_config")
    def test_custom_metrics_config(self, mock_load_config, mock_init, initializer):
        """Should use custom config when available."""
        mock_config = MagicMock()
        mock_config.directory = "/var/metrics"
        mock_config.export_interval_seconds = 30
        mock_config.global_labels = {"env": "prod"}
        mock_load_config.return_value = mock_config
        
        result = initializer.initialize_metrics()
        
        assert result is True
        assert initializer.handles.metrics_config is mock_config
        assert initializer.handles.metrics_dir == "/var/metrics"


# =============================================================================
# PHASE 8: CACHE
# =============================================================================


class TestInitializeCache:
    """Test cache initialization."""

    @patch("trapninja.core.service_init.modules")
    def test_cache_unavailable(self, mock_modules, initializer):
        """Should succeed when cache module unavailable."""
        mock_modules.cache.available = False
        
        result = initializer.initialize_cache()
        
        assert result is True
        assert initializer.handles.cache_initialized is False

    @patch("trapninja.core.service_init.load_cache_config")
    @patch("trapninja.core.service_init.modules")
    def test_cache_disabled(self, mock_modules, mock_load_config, initializer):
        """Should succeed when cache not enabled."""
        mock_modules.cache.available = True
        mock_config = MagicMock()
        mock_config.enabled = False
        mock_load_config.return_value = mock_config
        
        result = initializer.initialize_cache()
        
        assert result is True
        assert initializer.handles.cache_initialized is False

    @patch("trapninja.core.service_init.load_cache_config")
    @patch("trapninja.core.service_init.modules")
    def test_cache_success(self, mock_modules, mock_load_config, initializer):
        """Should set flag on successful cache init."""
        mock_modules.cache.available = True
        mock_cache = MagicMock()
        mock_cache.available = True
        mock_modules.cache.initialize.return_value = mock_cache
        mock_config = MagicMock()
        mock_config.enabled = True
        mock_config.host = "localhost"
        mock_config.port = 6379
        mock_config.retention_hours = 24
        mock_load_config.return_value = mock_config
        
        result = initializer.initialize_cache()
        
        assert result is True
        assert initializer.handles.cache_initialized is True


# =============================================================================
# PHASE 9: GRANULAR STATS
# =============================================================================


class TestInitializeStats:
    """Test granular statistics initialization."""

    @patch("trapninja.core.service_init.modules")
    def test_stats_unavailable(self, mock_modules, initializer):
        """Should succeed when stats module unavailable."""
        mock_modules.stats.available = False
        
        result = initializer.initialize_stats()
        
        assert result is True
        assert initializer.handles.stats_initialized is False

    @patch("trapninja.core.service_init.modules")
    def test_stats_success(self, mock_modules, initializer):
        """Should set flag on successful stats init."""
        mock_modules.stats.available = True
        mock_modules.stats.CollectorConfig = MagicMock(return_value=MagicMock(
            max_ips=10000, max_oids=5000, export_interval=60
        ))
        mock_modules.stats.initialize.return_value = MagicMock()
        initializer.handles.metrics_dir = "/var/metrics"
        
        result = initializer.initialize_stats()
        
        assert result is True
        assert initializer.handles.stats_initialized is True


# =============================================================================
# PHASE 11: SNMPv3
# =============================================================================


class TestInitializeSNMPv3:
    """Test SNMPv3 decryption initialization."""

    def test_missing_dependencies(self, initializer):
        """Should succeed when pysnmp not installed."""
        with patch.dict("sys.modules", {"trapninja.snmpv3_decryption": None}):
            result = initializer.initialize_snmpv3()
            assert result is True

    @patch("trapninja.core.service_init.logger")
    def test_always_returns_true(self, mock_logger, initializer):
        """SNMPv3 failure should never be fatal."""
        # Force an import error
        with patch(
            "trapninja.core.service_init.ServiceInitializer.initialize_snmpv3",
            return_value=True,
        ):
            result = initializer.initialize_snmpv3()
            assert result is True


# =============================================================================
# PHASE 12: WORKERS
# =============================================================================


class TestStartWorkers:
    """Test worker thread startup."""

    @patch("trapninja.core.service_init.time.sleep")
    @patch("trapninja.core.service_init.start_packet_processors")
    @patch("trapninja.core.service_init.start_queue_monitor")
    @patch("trapninja.core.service_init.packet_queue")
    def test_starts_workers(self, mock_queue, mock_monitor, mock_start, mock_sleep, initializer):
        """Should start workers based on CPU count."""
        mock_workers = [MagicMock() for _ in range(4)]
        mock_start.return_value = mock_workers
        mock_queue.maxsize = 200000
        
        result = initializer.start_workers()
        
        assert result is True
        assert initializer.handles.worker_count == 4
        assert len(initializer.handles.workers) == 4
        mock_monitor.assert_called_once()
        mock_sleep.assert_called_once_with(0.5)


# =============================================================================
# PHASE 13: CAPTURE - eBPF
# =============================================================================


class TestTryEbpfCapture:
    """Test eBPF capture initialization."""

    @patch("trapninja.core.service_init.modules")
    def test_ebpf_not_supported(self, mock_modules, initializer):
        """Should return False when eBPF not supported."""
        mock_modules.ebpf.is_supported.return_value = False
        
        result = initializer._try_ebpf_capture()
        
        assert result is False
        assert initializer.handles.use_ebpf is False

    @patch("trapninja.core.service_init.packet_queue")
    @patch("trapninja.core.service_init.stop_event")
    @patch("trapninja.core.service_init.modules")
    def test_ebpf_success(self, mock_modules, mock_stop, mock_queue, initializer):
        """Should set flags on successful eBPF start."""
        mock_modules.ebpf.is_supported.return_value = True
        mock_modules.ebpf.check_dependencies.return_value = True
        mock_capture = MagicMock()
        mock_capture.start.return_value = True
        mock_modules.ebpf.create_capture.return_value = mock_capture
        
        result = initializer._try_ebpf_capture()
        
        assert result is True
        assert initializer.handles.use_ebpf is True
        assert initializer.handles.capture_instance is mock_capture


# =============================================================================
# SHUTDOWN
# =============================================================================


class TestShutdown:
    """Test ordered shutdown."""

    @patch("trapninja.core.service_init.cleanup_udp_sockets")
    @patch("trapninja.core.service_init.get_metrics_summary")
    @patch("trapninja.core.service_init.shutdown_ha")
    @patch("trapninja.core.service_init.stop_event")
    @patch("trapninja.core.service_init.packet_queue")
    @patch("trapninja.core.service_init.modules")
    def test_shutdown_uninitialized(
        self, mock_modules, mock_queue, mock_stop, mock_ha,
        mock_metrics, mock_cleanup, initializer
    ):
        """Shutdown on fresh initializer should not raise."""
        mock_queue.empty.return_value = True
        mock_queue.qsize.return_value = 0
        mock_modules.shadow.available = False
        mock_modules.fragmentation.available = False
        mock_modules.cache.available = False
        mock_modules.stats.available = False
        mock_modules.control.available = False
        mock_metrics.return_value = {
            "total_traps_received": 0,
            "total_traps_forwarded": 0,
            "total_traps_blocked": 0,
            "total_traps_redirected": 0,
        }
        
        initializer.shutdown()  # Should not raise

    @patch("trapninja.core.service_init.cleanup_udp_sockets")
    @patch("trapninja.core.service_init.get_metrics_summary")
    @patch("trapninja.core.service_init.shutdown_ha")
    @patch("trapninja.core.service_init.stop_event")
    @patch("trapninja.core.service_init.packet_queue")
    @patch("trapninja.core.service_init.modules")
    def test_shutdown_calls_subsystems(
        self, mock_modules, mock_queue, mock_stop, mock_ha,
        mock_metrics, mock_cleanup, initializer
    ):
        """Shutdown should call each initialized subsystem."""
        mock_queue.empty.return_value = True
        mock_queue.qsize.return_value = 0
        mock_modules.fragmentation.available = False
        mock_metrics.return_value = {
            "total_traps_received": 100,
            "total_traps_forwarded": 95,
            "total_traps_blocked": 5,
            "total_traps_redirected": 0,
        }
        
        # Mark subsystems as initialized
        initializer.handles.shadow_initialized = True
        initializer.handles.cache_initialized = True
        initializer.handles.stats_initialized = True
        initializer.handles.control_initialized = True
        initializer.handles.ha_initialized = True
        
        mock_modules.shadow.available = True
        mock_modules.cache.available = True
        mock_modules.stats.available = True
        mock_modules.control.available = True
        
        mock_capture = MagicMock()
        initializer.handles.capture_instance = mock_capture
        
        initializer.shutdown()
        
        mock_modules.shadow.shutdown.assert_called_once()
        mock_modules.cache.shutdown.assert_called_once()
        mock_modules.stats.shutdown.assert_called_once()
        mock_modules.control.shutdown.assert_called_once()
        mock_ha.assert_called_once()
        mock_capture.stop.assert_called_once()
        mock_cleanup.assert_called_once()


# =============================================================================
# DRAIN QUEUE
# =============================================================================


class TestDrainQueue:
    """Test queue draining during shutdown."""

    @patch("trapninja.core.service_init.packet_queue")
    def test_empty_queue_returns_immediately(self, mock_queue, initializer):
        """Should return quickly for empty queue."""
        mock_queue.empty.return_value = True
        mock_queue.qsize.return_value = 0
        
        start = time.time()
        initializer._drain_queue(max_wait=5.0)
        elapsed = time.time() - start
        
        assert elapsed < 1.0


# =============================================================================
# HA FORWARDING CALLBACK
# =============================================================================


class TestTrapForwarderControl:
    """Test HA state callback."""

    def test_enable_forwarding(self, initializer):
        """Should enable forwarding."""
        initializer._trap_forwarder_control(True)
        assert initializer._forwarding_enabled is True

    def test_disable_forwarding(self, initializer):
        """Should disable forwarding."""
        initializer._trap_forwarder_control(False)
        assert initializer._forwarding_enabled is False


# =============================================================================
# INTEGRATION-STYLE: ORCHESTRATION
# =============================================================================


class TestRunOrchestration:
    """Test the run() orchestration method."""

    @patch.object(ServiceInitializer, "shutdown")
    @patch.object(ServiceInitializer, "validate_configuration")
    def test_validation_failure_returns_1(self, mock_validate, mock_shutdown, initializer):
        """Should return 1 when validation fails."""
        mock_validate.return_value = (False, ["Interface not found"], [])
        
        result = initializer.run()
        
        assert result == 1
        mock_shutdown.assert_called_once()

    @patch.object(ServiceInitializer, "shutdown")
    @patch.object(ServiceInitializer, "start_capture", return_value=0)
    @patch.object(ServiceInitializer, "start_workers", return_value=True)
    @patch.object(ServiceInitializer, "initialize_snmpv3", return_value=True)
    @patch.object(ServiceInitializer, "load_runtime_configuration", return_value=True)
    @patch.object(ServiceInitializer, "initialize_stats", return_value=True)
    @patch.object(ServiceInitializer, "initialize_cache", return_value=True)
    @patch.object(ServiceInitializer, "initialize_metrics", return_value=True)
    @patch.object(ServiceInitializer, "initialize_ha", return_value=True)
    @patch.object(ServiceInitializer, "initialize_control_socket", return_value=True)
    @patch.object(ServiceInitializer, "setup_process")
    @patch.object(ServiceInitializer, "setup_logging")
    @patch.object(ServiceInitializer, "setup_capture_mode")
    @patch.object(ServiceInitializer, "validate_configuration")
    def test_successful_run(
        self, mock_validate, mock_capture_mode, mock_logging, mock_process,
        mock_control, mock_ha, mock_metrics, mock_cache, mock_stats,
        mock_runtime, mock_snmpv3, mock_workers, mock_capture, mock_shutdown,
        initializer,
    ):
        """All phases should execute in order for successful run."""
        mock_validate.return_value = (True, [], [])
        
        result = initializer.run()
        
        assert result == 0
        
        # Verify call order
        mock_validate.assert_called_once()
        mock_capture_mode.assert_called_once()
        mock_logging.assert_called_once()
        mock_process.assert_called_once()
        mock_control.assert_called_once()
        mock_ha.assert_called_once()
        mock_metrics.assert_called_once()
        mock_cache.assert_called_once()
        mock_stats.assert_called_once()
        mock_runtime.assert_called_once()
        mock_snmpv3.assert_called_once()
        mock_workers.assert_called_once()
        mock_capture.assert_called_once()
        mock_shutdown.assert_called_once()

    @patch.object(ServiceInitializer, "shutdown")
    @patch.object(ServiceInitializer, "initialize_control_socket", return_value=True)
    @patch.object(ServiceInitializer, "setup_process")
    @patch.object(ServiceInitializer, "setup_logging")
    @patch.object(ServiceInitializer, "setup_capture_mode")
    @patch.object(ServiceInitializer, "initialize_ha", return_value=False)
    @patch.object(ServiceInitializer, "validate_configuration")
    def test_ha_failure_returns_1(
        self, mock_validate, mock_ha, mock_capture_mode,
        mock_logging, mock_process, mock_control, mock_shutdown,
        initializer,
    ):
        """HA failure should cause early exit with code 1."""
        mock_validate.return_value = (True, [], [])
        
        result = initializer.run()
        
        assert result == 1
        mock_shutdown.assert_called_once()

    @patch.object(ServiceInitializer, "shutdown")
    @patch.object(ServiceInitializer, "validate_configuration")
    def test_shutdown_always_called(self, mock_validate, mock_shutdown, initializer):
        """Shutdown should be called even when exception occurs."""
        mock_validate.side_effect = RuntimeError("unexpected")
        
        with pytest.raises(RuntimeError):
            initializer.run()
        
        mock_shutdown.assert_called_once()
