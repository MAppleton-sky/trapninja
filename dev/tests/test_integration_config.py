#!/usr/bin/env python3
"""
TrapNinja Test Suite - Integration Tests: Configuration

End-to-end tests for configuration loading and hot reload.
Tests the complete configuration flow including runtime updates.

Author: TrapNinja Team
"""

import os
import sys
import time
import json
import threading
import pytest
import tempfile
import importlib
from pathlib import Path
from unittest.mock import patch, MagicMock


# =============================================================================
# Configuration Loading Integration Tests
# =============================================================================

class TestConfigurationLoadingIntegration:
    """Integration tests for configuration loading."""

    def test_config_module_has_expected_attributes(self):
        """Test config module has expected attributes."""
        from trapninja import config
        
        assert hasattr(config, 'INTERFACE')
        assert hasattr(config, 'LISTEN_PORTS')
        assert hasattr(config, 'destinations')
        assert hasattr(config, 'blocked_ips')
        assert hasattr(config, 'blocked_traps')
        assert hasattr(config, 'load_config')

    def test_config_types_are_correct(self):
        """Test configuration values have correct types."""
        from trapninja import config
        
        assert isinstance(config.INTERFACE, str)
        assert isinstance(config.LISTEN_PORTS, (list, tuple))
        assert isinstance(config.destinations, list)
        assert isinstance(config.blocked_ips, set)
        assert isinstance(config.blocked_traps, set)

    def test_config_dir_attribute_exists(self):
        """Test CONFIG_DIR attribute exists."""
        from trapninja import config
        
        assert hasattr(config, 'CONFIG_DIR')
        assert isinstance(config.CONFIG_DIR, str)

    def test_load_config_function_is_callable(self):
        """Test load_config is callable."""
        from trapninja.config import load_config
        
        assert callable(load_config)


# =============================================================================
# Hot Reload Integration Tests
# =============================================================================

class TestHotReloadIntegration:
    """Integration tests for configuration hot reload."""

    def test_blocked_ips_can_be_modified_at_runtime(self):
        """Test blocked IPs can be modified at runtime."""
        from trapninja import config
        
        original_blocked = config.blocked_ips.copy()
        
        try:
            config.blocked_ips.add('10.99.99.99')
            assert '10.99.99.99' in config.blocked_ips
            
            config.blocked_ips.discard('10.99.99.99')
            assert '10.99.99.99' not in config.blocked_ips
        finally:
            config.blocked_ips.clear()
            config.blocked_ips.update(original_blocked)

    def test_blocked_oids_can_be_modified_at_runtime(self):
        """Test blocked OIDs can be modified at runtime."""
        from trapninja import config
        
        original_blocked = config.blocked_traps.copy()
        
        try:
            config.blocked_traps.add('1.3.6.1.4.1.99999.1')
            assert '1.3.6.1.4.1.99999.1' in config.blocked_traps
            
            config.blocked_traps.discard('1.3.6.1.4.1.99999.1')
            assert '1.3.6.1.4.1.99999.1' not in config.blocked_traps
        finally:
            config.blocked_traps.clear()
            config.blocked_traps.update(original_blocked)

    def test_destinations_is_mutable_list(self):
        """Test destinations is a mutable list."""
        from trapninja import config
        
        assert isinstance(config.destinations, list)
        
        original_len = len(config.destinations)
        assert isinstance(original_len, int)


# =============================================================================
# Configuration File Watching Integration Tests
# =============================================================================

class TestConfigFileWatchingIntegration:
    """Integration tests for config file watching."""

    def test_redirection_module_has_schedule_check(self):
        """Test redirection module has schedule_config_check."""
        from trapninja.redirection import schedule_config_check
        
        assert callable(schedule_config_check)

    def test_detects_file_modification(self, temp_config_dir):
        """Test detection of config file changes via mtime."""
        test_file = temp_config_dir / 'test.json'
        test_file.write_text('[162]')
        
        initial_mtime = os.path.getmtime(test_file)
        
        time.sleep(0.1)
        test_file.write_text('[162, 1162]')
        
        new_mtime = os.path.getmtime(test_file)
        
        assert new_mtime > initial_mtime


# =============================================================================
# Configuration Validation Integration Tests
# =============================================================================

class TestConfigurationValidationIntegration:
    """Integration tests for configuration validation."""

    def test_validate_configuration_function_exists(self):
        """Test validate_configuration function exists."""
        from trapninja.service import validate_configuration
        
        assert callable(validate_configuration)

    def test_validate_configuration_returns_tuple(self):
        """Test validate_configuration returns tuple."""
        from trapninja.service import validate_configuration
        
        with patch('trapninja.service.get_if_list', return_value=['eth0', 'lo']):
            result = validate_configuration()
        
        assert isinstance(result, tuple)
        assert len(result) == 3

    def test_validation_tuple_structure(self):
        """Test validation result has correct structure."""
        from trapninja.service import validate_configuration
        
        with patch('trapninja.service.get_if_list', return_value=['eth0', 'lo']):
            is_valid, errors, warnings = validate_configuration()
        
        assert isinstance(is_valid, bool)
        assert isinstance(errors, list)
        assert isinstance(warnings, list)


# =============================================================================
# Configuration Persistence Integration Tests
# =============================================================================

class TestConfigurationPersistenceIntegration:
    """Integration tests for configuration persistence."""

    def test_can_save_blocked_ips_to_file(self, temp_config_dir):
        """Test can save blocked IPs to file."""
        blocked_ips = ['10.0.0.1', '10.0.0.2']
        
        blocked_file = temp_config_dir / 'blocked_ips.json'
        blocked_file.write_text(json.dumps(blocked_ips))
        
        saved = json.loads(blocked_file.read_text())
        assert '10.0.0.1' in saved
        assert '10.0.0.2' in saved

    def test_can_save_destinations_to_file(self, temp_config_dir):
        """Test can save destinations to file."""
        destinations = [
            ['192.168.1.100', 162],
            ['192.168.1.101', 1162]
        ]
        
        dest_file = temp_config_dir / 'destinations.json'
        dest_file.write_text(json.dumps(destinations))
        
        saved = json.loads(dest_file.read_text())
        assert len(saved) == 2


# =============================================================================
# HA Configuration Integration Tests
# =============================================================================

class TestHAConfigurationIntegration:
    """Integration tests for HA configuration."""

    def test_ha_config_class_exists(self):
        """Test HAConfig class exists."""
        from trapninja.ha.config import HAConfig
        
        assert HAConfig is not None

    def test_load_ha_config_function_exists(self):
        """Test load_ha_config function exists."""
        from trapninja.ha import load_ha_config
        
        assert callable(load_ha_config)

    def test_ha_config_has_expected_attributes(self):
        """Test HAConfig has expected attributes."""
        from trapninja.ha.config import HAConfig
        
        default_config = HAConfig()
        
        assert hasattr(default_config, 'enabled')
        assert hasattr(default_config, 'priority')
        assert hasattr(default_config, 'peer_host')
        assert hasattr(default_config, 'mode')

    def test_can_create_enabled_ha_config(self):
        """Test can create enabled HA config."""
        from trapninja.ha.config import HAConfig
        
        config = HAConfig(
            enabled=True,
            mode='primary',
            priority=150,
            peer_host='192.168.1.101',
            peer_port=60006,
            listen_port=60006
        )
        
        assert config.enabled is True
        assert config.priority == 150


# =============================================================================
# Cache Configuration Integration Tests
# =============================================================================

class TestCacheConfigurationIntegration:
    """Integration tests for cache configuration."""

    def test_cache_module_importable(self):
        """Test cache module is importable."""
        try:
            from trapninja import cache
            assert cache is not None
        except ImportError:
            # Cache module may be optional
            pytest.skip("Cache module not available")


# =============================================================================
# Metrics Configuration Integration Tests
# =============================================================================

class TestMetricsConfigurationIntegration:
    """Integration tests for metrics configuration."""

    def test_metrics_module_exists(self):
        """Test metrics module exists."""
        from trapninja import metrics
        
        assert metrics is not None

    def test_load_metrics_config_exists(self):
        """Test load_metrics_config function exists."""
        from trapninja.metrics import load_metrics_config
        
        assert callable(load_metrics_config)

    def test_init_metrics_exists(self):
        """Test init_metrics function exists."""
        from trapninja.metrics import init_metrics
        
        assert callable(init_metrics)

    def test_get_metrics_summary_exists(self):
        """Test get_metrics_summary function exists."""
        from trapninja.metrics import get_metrics_summary
        
        assert callable(get_metrics_summary)


# =============================================================================
# Configuration Error Handling Integration Tests
# =============================================================================

class TestConfigurationErrorHandlingIntegration:
    """Integration tests for configuration error handling."""

    def test_handles_malformed_json_file(self, temp_config_dir):
        """Test can detect malformed JSON."""
        bad_file = temp_config_dir / 'bad.json'
        bad_file.write_text('[162')
        
        with pytest.raises(json.JSONDecodeError):
            json.loads(bad_file.read_text())

    def test_handles_missing_file_gracefully(self, temp_config_dir):
        """Test handles missing file."""
        missing_file = temp_config_dir / 'nonexistent.json'
        
        with pytest.raises(FileNotFoundError):
            missing_file.read_text()

    def test_can_check_file_exists(self, temp_config_dir):
        """Test can check if file exists."""
        existing_file = temp_config_dir / 'test.json'
        existing_file.write_text('[]')
        
        assert existing_file.exists()
        assert not (temp_config_dir / 'missing.json').exists()


# =============================================================================
# Environment Configuration Integration Tests
# =============================================================================

class TestEnvironmentConfigurationIntegration:
    """Integration tests for environment-based configuration."""

    def test_config_dir_is_string(self):
        """Test CONFIG_DIR is a string path."""
        from trapninja import config
        
        assert isinstance(config.CONFIG_DIR, str)
        assert len(config.CONFIG_DIR) > 0


# =============================================================================
# Configuration Format Integration Tests
# =============================================================================

class TestConfigurationFormatIntegration:
    """Integration tests for configuration file formats."""

    def test_destinations_json_format(self, temp_config_dir):
        """Test destinations JSON format."""
        formats = [
            [['192.168.1.100', 162]],
        ]
        
        for fmt in formats:
            dest_file = temp_config_dir / 'destinations.json'
            dest_file.write_text(json.dumps(fmt))
            
            loaded = json.loads(dest_file.read_text())
            assert len(loaded) == 1

    def test_listen_ports_json_format(self, temp_config_dir):
        """Test listen_ports JSON format."""
        ports = [162, 1162, 2162]
        
        ports_file = temp_config_dir / 'listen_ports.json'
        ports_file.write_text(json.dumps(ports))
        
        loaded = json.loads(ports_file.read_text())
        assert len(loaded) == 3
        assert all(isinstance(p, int) for p in loaded)

    def test_blocked_ips_json_format(self, temp_config_dir):
        """Test blocked_ips JSON format."""
        ips = ['10.0.0.1', '192.168.1.0/24']
        
        ips_file = temp_config_dir / 'blocked_ips.json'
        ips_file.write_text(json.dumps(ips))
        
        loaded = json.loads(ips_file.read_text())
        assert len(loaded) == 2
        assert all(isinstance(ip, str) for ip in loaded)

    def test_blocked_traps_json_format(self, temp_config_dir):
        """Test blocked_traps JSON format."""
        oids = ['1.3.6.1.4.1.9999', '1.3.6.1.4.1.8888.*']
        
        oids_file = temp_config_dir / 'blocked_traps.json'
        oids_file.write_text(json.dumps(oids))
        
        loaded = json.loads(oids_file.read_text())
        assert len(loaded) == 2
        assert all(isinstance(oid, str) for oid in loaded)
