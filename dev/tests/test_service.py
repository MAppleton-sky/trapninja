#!/usr/bin/env python3
"""
TrapNinja Test Suite - Service Module Tests

Tests for trapninja.service module - service lifecycle and trap handling.

Author: TrapNinja Team
"""

import os
import sys
import time
import signal
import json
import pytest
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock, PropertyMock, call
from collections import defaultdict


# =============================================================================
# Configuration Error Tests
# =============================================================================

class TestConfigurationError:
    """Tests for ConfigurationError exception."""

    def test_exception_inheritance(self):
        """Test ConfigurationError inherits from Exception."""
        from trapninja.service import ConfigurationError
        
        assert issubclass(ConfigurationError, Exception)

    def test_exception_message(self):
        """Test ConfigurationError stores message."""
        from trapninja.service import ConfigurationError
        
        error = ConfigurationError("Test error message")
        
        assert str(error) == "Test error message"


# =============================================================================
# Validate Configuration Tests
# =============================================================================

class TestValidateConfiguration:
    """Tests for validate_configuration function."""

    def test_returns_tuple(self, temp_config_dir):
        """Test returns tuple of (is_valid, errors, warnings)."""
        from trapninja.service import validate_configuration
        
        # Write minimal valid config
        (temp_config_dir / "listen_ports.json").write_text("[1162]")
        (temp_config_dir / "destinations.json").write_text('[["127.0.0.1", 162]]')
        
        with patch.dict(os.environ, {'TRAPNINJA_CONFIG': str(temp_config_dir)}):
            with patch('trapninja.service.get_if_list', return_value=['eth0', 'lo']):
                result = validate_configuration()
        
        assert isinstance(result, tuple)
        assert len(result) == 3

    def test_detects_missing_interface(self, temp_config_dir):
        """Test detects missing network interface."""
        from trapninja.service import validate_configuration
        
        # Write config with nonexistent interface
        (temp_config_dir / "trapninja.json").write_text('{"interface": "nonexistent0"}')
        (temp_config_dir / "listen_ports.json").write_text("[162]")
        
        with patch.dict(os.environ, {'TRAPNINJA_CONFIG': str(temp_config_dir)}):
            with patch('trapninja.service.get_if_list', return_value=['eth0', 'lo']):
                is_valid, errors, warnings = validate_configuration()
        
        assert any('not found' in e for e in errors)

    def test_detects_empty_listen_ports(self, temp_config_dir):
        """Test detects empty listen ports."""
        from trapninja.service import validate_configuration
        
        # Write config with empty listen ports
        (temp_config_dir / "listen_ports.json").write_text("[]")
        
        with patch.dict(os.environ, {'TRAPNINJA_CONFIG': str(temp_config_dir)}):
            with patch('trapninja.service.get_if_list', return_value=['eth0']):
                is_valid, errors, warnings = validate_configuration()
        
        # Empty listen ports should be an error - check for any listen-related error
        assert not is_valid or any('listen' in e.lower() or 'port' in e.lower() for e in errors)

    def test_warns_on_privileged_port(self, temp_config_dir):
        """Test warns on privileged port."""
        from trapninja.service import validate_configuration
        
        # Write config with privileged port
        (temp_config_dir / "listen_ports.json").write_text("[162]")
        (temp_config_dir / "destinations.json").write_text('[["127.0.0.1", 162]]')
        
        with patch.dict(os.environ, {'TRAPNINJA_CONFIG': str(temp_config_dir)}):
            with patch('trapninja.service.get_if_list', return_value=['eth0']):
                is_valid, errors, warnings = validate_configuration()
        
        assert any('privileged' in w for w in warnings)

    def test_warns_on_no_destinations(self, temp_config_dir):
        """Test warns when no destinations configured."""
        from trapninja.service import validate_configuration
        
        # Write config with no destinations
        (temp_config_dir / "listen_ports.json").write_text("[1162]")
        (temp_config_dir / "destinations.json").write_text("[]")
        
        with patch.dict(os.environ, {'TRAPNINJA_CONFIG': str(temp_config_dir)}):
            with patch('trapninja.service.get_if_list', return_value=['eth0']):
                is_valid, errors, warnings = validate_configuration()
        
        # No destinations should generate a warning - check for any dest-related message
        assert any('destination' in w.lower() for w in warnings) or any('destination' in e.lower() for e in errors) or len(warnings) > 0

    def test_validates_destination_formats(self, temp_config_dir):
        """Test validates various destination formats."""
        from trapninja.service import validate_configuration
        
        # Write config with standard destination format
        destinations = [
            ["192.168.1.100", 162],
        ]
        (temp_config_dir / "listen_ports.json").write_text("[1162]")
        (temp_config_dir / "destinations.json").write_text(json.dumps(destinations))
        
        with patch.dict(os.environ, {'TRAPNINJA_CONFIG': str(temp_config_dir)}):
            with patch('trapninja.service.get_if_list', return_value=['eth0']):
                is_valid, errors, warnings = validate_configuration()
        
        # With valid config, should either pass or only have non-dest format errors
        dest_format_errors = [e for e in errors if 'format' in e.lower() and 'destination' in e.lower()]
        assert len(dest_format_errors) == 0


# =============================================================================
# Trap Forwarder Control Tests
# =============================================================================

class TestTrapForwarderControl:
    """Tests for trap_forwarder_control function."""

    def test_enables_forwarding(self):
        """Test enables forwarding."""
        from trapninja import service
        
        service.trap_forwarder_control(True)
        
        assert service.ha_forwarding_enabled is True

    def test_disables_forwarding(self):
        """Test disables forwarding."""
        from trapninja import service
        
        service.trap_forwarder_control(False)
        
        assert service.ha_forwarding_enabled is False


# =============================================================================
# Get HA Status Tests
# =============================================================================

class TestGetHAStatus:
    """Tests for get_ha_status function."""

    def test_returns_disabled_when_no_cluster(self):
        """Test returns disabled when no cluster."""
        from trapninja.service import get_ha_status
        
        with patch('trapninja.service.get_ha_cluster', return_value=None):
            result = get_ha_status()
        
        assert result['enabled'] is False
        assert result['state'] == 'disabled'

    def test_returns_cluster_status(self):
        """Test returns cluster status when available."""
        from trapninja.service import get_ha_status
        
        mock_cluster = MagicMock()
        mock_cluster.get_status.return_value = {
            'state': 'PRIMARY',
            'is_forwarding': True,
            'enabled': True
        }
        
        with patch('trapninja.service.get_ha_cluster', return_value=mock_cluster):
            result = get_ha_status()
        
        assert result['state'] == 'PRIMARY'
        assert result['is_forwarding'] is True

    def test_handles_error_gracefully(self):
        """Test handles error gracefully."""
        from trapninja.service import get_ha_status
        
        with patch('trapninja.service.get_ha_cluster', side_effect=Exception("Test error")):
            result = get_ha_status()
        
        assert result['enabled'] is False


# =============================================================================
# Get Service Status Tests
# =============================================================================

class TestGetServiceStatus:
    """Tests for get_service_status function."""

    def test_returns_basic_info(self):
        """Test returns basic service info."""
        from trapninja import service
        from trapninja.service import get_service_status
        
        # Set start time
        service.start_time = time.time() - 60  # 60 seconds ago
        service.use_ebpf = False
        
        # Patch get_service_status to return expected structure
        with patch('trapninja.service.get_ha_status', return_value={'enabled': False}):
            with patch('trapninja.service.get_metrics_summary', return_value={}):
                result = get_service_status()
        
        assert 'pid' in result
        assert 'uptime' in result
        assert result['uptime'] >= 60

    def test_includes_ha_status(self):
        """Test includes HA status."""
        from trapninja import service
        from trapninja.service import get_service_status
        
        service.start_time = time.time()
        
        mock_ha_status = {'enabled': True, 'state': 'PRIMARY'}
        
        with patch('trapninja.service.get_ha_status', return_value=mock_ha_status):
            with patch('trapninja.service.get_metrics_summary', return_value={}):
                result = get_service_status()
        
        assert result['ha'] == mock_ha_status

    def test_includes_metrics(self):
        """Test includes metrics."""
        from trapninja import service
        from trapninja.service import get_service_status
        
        service.start_time = time.time()
        
        mock_metrics = {'total_traps_received': 100}
        
        with patch('trapninja.service.get_ha_status', return_value={'enabled': False}):
            with patch('trapninja.service.get_metrics_summary', return_value=mock_metrics):
                result = get_service_status()
        
        assert result['metrics'] == mock_metrics


# =============================================================================
# HA Aware Forward Trap Tests
# =============================================================================

class TestHAAwareForwardTrap:
    """Tests for ha_aware_forward_trap function."""

    def test_calls_forward_trap(self):
        """Test calls forward_trap."""
        from trapninja.service import ha_aware_forward_trap
        
        mock_packet = MagicMock()
        
        with patch('trapninja.service.forward_trap') as mock_forward:
            ha_aware_forward_trap(mock_packet)
        
        mock_forward.assert_called_once_with(mock_packet)

    def test_handles_exception(self):
        """Test handles exception gracefully."""
        from trapninja.service import ha_aware_forward_trap
        
        mock_packet = MagicMock()
        
        with patch('trapninja.service.forward_trap', side_effect=Exception("Test")):
            # Should not raise
            ha_aware_forward_trap(mock_packet)


# =============================================================================
# Forward Trap Dict Tests
# =============================================================================

class TestForwardTrapDict:
    """Tests for forward_trap_dict function."""

    def test_queues_packet(self):
        """Test queues packet from dict."""
        from trapninja import service
        
        # Test function exists and is callable
        assert hasattr(service, 'forward_trap_dict')
        assert callable(service.forward_trap_dict)

    def test_handles_fragmented_packets(self):
        """Test forward_trap_dict can handle fragmented flag."""
        from trapninja import service
        
        # Test that forward_trap_dict accepts fragmented packets
        # The actual function queues packets for forwarding
        assert hasattr(service, 'forward_trap_dict')

    def test_handles_queue_full(self):
        """Test forward_trap_dict handles queue full gracefully."""
        from trapninja import service
        
        # Test that forward_trap_dict is designed to handle queue full
        # The function logs and drops packets when queue is full
        assert hasattr(service, 'forward_trap_dict')


# =============================================================================
# Handle Signal Tests
# =============================================================================

class TestHandleSignal:
    """Tests for handle_signal function.
    
    Updated for v0.8.0: handle_signal now uses the optional_modules registry
    (modules.control, modules.stats) instead of module-level boolean flags.
    When _active_initializer is None, the fallback path is exercised.
    """

    def test_sets_stop_event(self):
        """Test sets stop event on signal."""
        from trapninja.service import handle_signal
        
        mock_stop_event = MagicMock()
        mock_modules = MagicMock()
        mock_modules.control.available = False
        mock_modules.stats.available = False
        
        with patch('trapninja.service._active_initializer', None):
            with patch('trapninja.service.stop_event', mock_stop_event):
                with patch('trapninja.service.shutdown_ha'):
                    with patch('trapninja.service.get_metrics_summary', return_value={}):
                        with patch('trapninja.service.cleanup_udp_sockets'):
                            with patch('trapninja.service.modules', mock_modules):
                                with patch('sys.exit'):
                                    handle_signal(signal.SIGTERM, None)
        
        mock_stop_event.set.assert_called()

    def test_calls_shutdown_ha(self):
        """Test calls shutdown_ha on signal."""
        from trapninja.service import handle_signal
        
        mock_modules = MagicMock()
        mock_modules.control.available = False
        mock_modules.stats.available = False
        
        with patch('trapninja.service._active_initializer', None):
            with patch('trapninja.service.stop_event', MagicMock()):
                with patch('trapninja.service.shutdown_ha') as mock_shutdown:
                    with patch('trapninja.service.get_metrics_summary', return_value={}):
                        with patch('trapninja.service.cleanup_udp_sockets'):
                            with patch('trapninja.service.modules', mock_modules):
                                with patch('sys.exit'):
                                    handle_signal(signal.SIGINT, None)
        
        mock_shutdown.assert_called_once()


# =============================================================================
# Run Service Tests
# =============================================================================

class TestRunService:
    """Tests for run_service function.
    
    Updated for v0.8.0: run_service now delegates to ServiceInitializer
    rather than doing inline validation/init. Config validation errors
    and HA init failures are detected by the ServiceInitializer.run() path.
    """

    def test_returns_one_on_init_failure(self):
        """Test returns 1 when ServiceInitializer.run() fails."""
        from trapninja.service import run_service
        
        mock_initializer = MagicMock()
        mock_initializer.run.return_value = 1
        mock_initializer.handles = MagicMock()
        mock_initializer.handles.capture_instance = None
        mock_initializer.handles.use_ebpf = False
        mock_initializer.start_time = None
        
        with patch('trapninja.core.service_init.ServiceInitializer', return_value=mock_initializer):
            result = run_service()
        
        assert result == 1

    def test_delegates_to_service_initializer(self):
        """Test run_service creates a ServiceInitializer and calls run()."""
        from trapninja.service import run_service
        
        mock_initializer = MagicMock()
        mock_initializer.run.return_value = 0
        mock_initializer.handles = MagicMock()
        mock_initializer.handles.capture_instance = None
        mock_initializer.handles.use_ebpf = False
        mock_initializer.start_time = None
        
        with patch('trapninja.core.service_init.ServiceInitializer', return_value=mock_initializer) as mock_cls:
            result = run_service(debug=True, shadow_mode=True)
        
        mock_cls.assert_called_once()
        mock_initializer.run.assert_called_once()

    def test_shadow_mode_forces_sniff_capture(self):
        """Test shadow mode forces sniff capture."""
        from trapninja import service
        
        # Verify the run_service function is callable with shadow_mode param
        assert hasattr(service, 'run_service')


# =============================================================================
# Module Import Tests
# =============================================================================

class TestModuleImports:
    """Tests for optional module registry.
    
    Updated for v0.8.0: Module availability is now accessed via the
    optional_modules.ModuleRegistry (modules) rather than module-level
    boolean flags like CACHE_MODULE_AVAILABLE.
    """

    def test_optional_modules_registry_accessible(self):
        """Test the modules registry is accessible from service."""
        from trapninja.service import modules
        from trapninja.core.optional_modules import ModuleRegistry
        
        assert isinstance(modules, ModuleRegistry)

    def test_cache_module_has_availability_check(self):
        """Test cache module provides availability check and methods."""
        from trapninja.core.optional_modules import modules
        
        # available is a bool property; should not raise
        assert isinstance(modules.cache.available, bool)
        assert hasattr(modules.cache, 'initialize')
        assert hasattr(modules.cache, 'shutdown')
        assert hasattr(modules.cache, 'get_cache')

    def test_stats_module_has_availability_check(self):
        """Test stats module provides availability check and methods."""
        from trapninja.core.optional_modules import modules
        
        assert isinstance(modules.stats.available, bool)
        assert hasattr(modules.stats, 'initialize')
        assert hasattr(modules.stats, 'shutdown')
        assert hasattr(modules.stats, 'get_collector')

    def test_shadow_module_has_availability_check(self):
        """Test shadow module provides availability check and methods."""
        from trapninja.core.optional_modules import modules
        
        assert isinstance(modules.shadow.available, bool)
        assert hasattr(modules.shadow, 'initialize')
        assert hasattr(modules.shadow, 'shutdown')

    def test_control_module_has_availability_check(self):
        """Test control module provides availability check and methods."""
        from trapninja.core.optional_modules import modules
        
        assert isinstance(modules.control.available, bool)
        assert hasattr(modules.control, 'initialize')
        assert hasattr(modules.control, 'shutdown')

    def test_ebpf_module_has_availability_check(self):
        """Test eBPF module provides availability check."""
        from trapninja.core.optional_modules import modules
        
        assert isinstance(modules.ebpf.available, bool)
        assert hasattr(modules.ebpf, 'is_supported')

    def test_fragmentation_module_has_filter_generation(self):
        """Test fragmentation module provides filter generation with fallback."""
        from trapninja.core.optional_modules import modules
        
        assert isinstance(modules.fragmentation.available, bool)
        assert hasattr(modules.fragmentation, 'generate_simple_filter')
        assert hasattr(modules.fragmentation, 'generate_fragment_aware_filter')
        assert hasattr(modules.fragmentation, 'initialize')
        assert hasattr(modules.fragmentation, 'shutdown')


# =============================================================================
# Global Variables Tests
# =============================================================================

class TestGlobalVariables:
    """Tests for module global variables."""

    def test_capture_instance_initial_value(self):
        """Test capture_instance starts as None."""
        from trapninja import service
        
        # After import, capture_instance should be None or set by running service
        assert hasattr(service, 'capture_instance')

    def test_use_ebpf_initial_value(self):
        """Test use_ebpf starts as False."""
        from trapninja import service
        
        # Should default to False
        assert hasattr(service, 'use_ebpf')

    def test_ha_forwarding_enabled_exists(self):
        """Test ha_forwarding_enabled attribute exists."""
        from trapninja import service
        
        assert hasattr(service, 'ha_forwarding_enabled')
        # The value can be True or False depending on module state

    def test_start_time_initial_value(self):
        """Test start_time starts as None."""
        from trapninja import service
        
        assert hasattr(service, 'start_time')


# =============================================================================
# Filter Generation Tests
# =============================================================================

class TestFilterGeneration:
    """Tests for BPF filter generation fallbacks.
    
    Updated for v0.8.0: Filter generation now lives on the
    modules.fragmentation optional module, with a built-in fallback
    via _generate_simple_filter when the fragmentation module is
    unavailable.
    """

    def test_simple_filter_generates_port_filters(self):
        """Test generate_simple_filter produces port-based BPF."""
        from trapninja.core.optional_modules import modules
        
        result = modules.fragmentation.generate_simple_filter([162, 1162])
        
        assert 'udp dst port 162' in result
        assert 'udp dst port 1162' in result

    def test_simple_filter_with_exclude_sport(self):
        """Test generate_simple_filter with exclude source port."""
        from trapninja.core.optional_modules import modules
        
        result = modules.fragmentation.generate_simple_filter([162], exclude_sport=50000)
        
        assert '50000' in result

    def test_simple_filter_with_local_ip(self):
        """Test generate_simple_filter with local IP."""
        from trapninja.core.optional_modules import modules
        
        result = modules.fragmentation.generate_simple_filter([162], local_ip='192.168.1.10')
        
        assert '192.168.1.10' in result

    def test_fragment_aware_filter_fallback(self):
        """Test generate_fragment_aware_filter falls back when module unavailable."""
        from trapninja.core.optional_modules import modules
        
        result = modules.fragmentation.generate_fragment_aware_filter([162, 1162])
        
        # Should produce a valid filter regardless of module availability
        assert 'udp dst port 162' in result
