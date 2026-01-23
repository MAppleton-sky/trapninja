#!/usr/bin/env python3
"""
TrapNinja Test Suite - Metrics Configuration Tests

Tests for trapninja.metrics.config module - metrics configuration management.

Author: TrapNinja Team
"""

import os
import json
import pytest
from unittest.mock import patch, MagicMock


class TestMetricsConfigDefaults:
    """Tests for default configuration values."""

    def test_default_metrics_dir(self):
        """Test default metrics directory."""
        from trapninja.metrics.config import DEFAULT_METRICS_DIR
        
        assert DEFAULT_METRICS_DIR == "/var/log/trapninja/metrics"

    def test_default_export_interval(self):
        """Test default export interval."""
        from trapninja.metrics.config import DEFAULT_EXPORT_INTERVAL
        
        assert DEFAULT_EXPORT_INTERVAL == 60

    def test_default_prometheus_file(self):
        """Test default Prometheus filename."""
        from trapninja.metrics.config import DEFAULT_PROMETHEUS_FILE
        
        assert DEFAULT_PROMETHEUS_FILE == "trapninja_metrics.prom"

    def test_default_json_file(self):
        """Test default JSON filename."""
        from trapninja.metrics.config import DEFAULT_JSON_FILE
        
        assert DEFAULT_JSON_FILE == "trapninja_metrics.json"


class TestMetricsConfigDataclass:
    """Tests for MetricsConfig dataclass."""

    def test_default_initialization(self):
        """Test MetricsConfig with default values."""
        from trapninja.metrics.config import MetricsConfig
        
        config = MetricsConfig()
        
        assert config.enabled is True
        assert config.export_interval_seconds == 60
        assert config.json_enabled is True
        assert config.global_labels == {}

    def test_custom_initialization(self):
        """Test MetricsConfig with custom values."""
        from trapninja.metrics.config import MetricsConfig
        
        config = MetricsConfig(
            enabled=False,
            directory="/custom/path",
            export_interval_seconds=120,
            global_labels={"env": "test"}
        )
        
        assert config.enabled is False
        assert config.directory == "/custom/path"
        assert config.export_interval_seconds == 120
        assert config.global_labels == {"env": "test"}

    def test_relative_path_made_absolute(self):
        """Test relative directory path is converted to absolute."""
        from trapninja.metrics.config import MetricsConfig
        
        config = MetricsConfig(directory="relative/path")
        
        assert os.path.isabs(config.directory)

    def test_invalid_export_interval_corrected(self):
        """Test invalid export interval is corrected to default."""
        from trapninja.metrics.config import MetricsConfig, DEFAULT_EXPORT_INTERVAL
        
        config = MetricsConfig(export_interval_seconds=0)
        
        assert config.export_interval_seconds == DEFAULT_EXPORT_INTERVAL

    def test_negative_export_interval_corrected(self):
        """Test negative export interval is corrected."""
        from trapninja.metrics.config import MetricsConfig, DEFAULT_EXPORT_INTERVAL
        
        config = MetricsConfig(export_interval_seconds=-10)
        
        assert config.export_interval_seconds == DEFAULT_EXPORT_INTERVAL


class TestLabelSanitization:
    """Tests for Prometheus label name sanitization."""

    def test_sanitize_valid_label(self):
        """Test valid label name passes through."""
        from trapninja.metrics.config import MetricsConfig
        
        result = MetricsConfig._sanitize_label_name("valid_label")
        
        assert result == "valid_label"

    def test_sanitize_label_starting_with_number(self):
        """Test label starting with number is prefixed."""
        from trapninja.metrics.config import MetricsConfig
        
        result = MetricsConfig._sanitize_label_name("1invalid")
        
        assert result[0] == '_' or result[0].isalpha()

    def test_sanitize_label_with_hyphen(self):
        """Test label with hyphen is sanitized."""
        from trapninja.metrics.config import MetricsConfig
        
        result = MetricsConfig._sanitize_label_name("my-label")
        
        assert '-' not in result
        assert result == "my_label"

    def test_sanitize_label_with_spaces(self):
        """Test label with spaces is sanitized."""
        from trapninja.metrics.config import MetricsConfig
        
        result = MetricsConfig._sanitize_label_name("my label")
        
        assert ' ' not in result

    def test_sanitize_empty_label(self):
        """Test empty label returns unnamed."""
        from trapninja.metrics.config import MetricsConfig
        
        result = MetricsConfig._sanitize_label_name("")
        
        assert result == "_unnamed"

    def test_labels_sanitized_on_init(self):
        """Test global labels are sanitized during initialization."""
        from trapninja.metrics.config import MetricsConfig
        
        config = MetricsConfig(global_labels={
            "my-label": "value1",
            "1numeric": "value2"
        })
        
        assert "my_label" in config.global_labels
        assert "my-label" not in config.global_labels


class TestMetricsConfigFromDict:
    """Tests for MetricsConfig.from_dict class method."""

    def test_from_dict_with_all_fields(self):
        """Test creating config from complete dictionary."""
        from trapninja.metrics.config import MetricsConfig
        
        data = {
            'enabled': False,
            'directory': '/opt/metrics',
            'export_interval_seconds': 30,
            'prometheus_file': 'custom.prom',
            'json_file': 'custom.json',
            'json_enabled': False,
            'global_labels': {'env': 'prod'}
        }
        
        config = MetricsConfig.from_dict(data)
        
        assert config.enabled is False
        assert config.directory == '/opt/metrics'
        assert config.export_interval_seconds == 30
        assert config.prometheus_file == 'custom.prom'
        assert config.json_enabled is False

    def test_from_dict_with_missing_fields(self):
        """Test creating config from partial dictionary."""
        from trapninja.metrics.config import MetricsConfig
        
        data = {'enabled': True}
        
        config = MetricsConfig.from_dict(data)
        
        assert config.enabled is True
        assert config.export_interval_seconds == 60  # Default

    def test_from_dict_empty(self):
        """Test creating config from empty dictionary."""
        from trapninja.metrics.config import MetricsConfig
        
        config = MetricsConfig.from_dict({})
        
        assert config.enabled is True  # Default


class TestMetricsConfigToDict:
    """Tests for MetricsConfig.to_dict method."""

    def test_to_dict_contains_all_fields(self):
        """Test to_dict includes all configuration fields."""
        from trapninja.metrics.config import MetricsConfig
        
        config = MetricsConfig()
        result = config.to_dict()
        
        assert 'enabled' in result
        assert 'directory' in result
        assert 'export_interval_seconds' in result
        assert 'prometheus_file' in result
        assert 'json_file' in result
        assert 'json_enabled' in result
        assert 'global_labels' in result

    def test_to_dict_roundtrip(self):
        """Test from_dict(to_dict()) produces equivalent config."""
        from trapninja.metrics.config import MetricsConfig
        
        original = MetricsConfig(
            enabled=False,
            export_interval_seconds=120,
            global_labels={'test': 'value'}
        )
        
        data = original.to_dict()
        restored = MetricsConfig.from_dict(data)
        
        assert restored.enabled == original.enabled
        assert restored.export_interval_seconds == original.export_interval_seconds
        assert restored.global_labels == original.global_labels


class TestMetricsConfigPaths:
    """Tests for path properties."""

    def test_prometheus_path(self):
        """Test prometheus_path property."""
        from trapninja.metrics.config import MetricsConfig
        
        config = MetricsConfig(
            directory='/opt/metrics',
            prometheus_file='test.prom'
        )
        
        assert config.prometheus_path == '/opt/metrics/test.prom'

    def test_json_path(self):
        """Test json_path property."""
        from trapninja.metrics.config import MetricsConfig
        
        config = MetricsConfig(
            directory='/opt/metrics',
            json_file='test.json'
        )
        
        assert config.json_path == '/opt/metrics/test.json'


class TestLoadMetricsConfig:
    """Tests for load_metrics_config function."""

    def test_load_from_existing_file(self, tmp_path):
        """Test loading config from existing file."""
        from trapninja.metrics.config import load_metrics_config
        
        config_file = tmp_path / "metrics_config.json"
        config_data = {
            'enabled': True,
            'directory': '/custom/metrics',
            'export_interval_seconds': 90,
            'global_labels': {'test': 'value'}
        }
        config_file.write_text(json.dumps(config_data))
        
        result = load_metrics_config(str(config_file))
        
        assert result.directory == '/custom/metrics'
        assert result.export_interval_seconds == 90
        assert result.global_labels == {'test': 'value'}

    def test_load_from_missing_file(self, tmp_path):
        """Test loading config from non-existent file returns defaults."""
        from trapninja.metrics.config import load_metrics_config
        
        config_file = tmp_path / "nonexistent.json"
        
        result = load_metrics_config(str(config_file))
        
        assert result.enabled is True
        assert result.export_interval_seconds == 60

    def test_load_from_invalid_json(self, tmp_path):
        """Test loading config from invalid JSON returns defaults."""
        from trapninja.metrics.config import load_metrics_config
        
        config_file = tmp_path / "invalid.json"
        config_file.write_text("{ not valid json }")
        
        result = load_metrics_config(str(config_file))
        
        assert result.enabled is True  # Defaults


class TestSaveMetricsConfig:
    """Tests for save_metrics_config function."""

    def test_save_creates_file(self, tmp_path):
        """Test saving config creates file."""
        from trapninja.metrics.config import MetricsConfig, save_metrics_config
        
        config = MetricsConfig(
            enabled=True,
            export_interval_seconds=45
        )
        config_file = tmp_path / "saved_config.json"
        
        result = save_metrics_config(config, str(config_file))
        
        assert result is True
        assert config_file.exists()

    def test_save_creates_directory(self, tmp_path):
        """Test saving config creates parent directory."""
        from trapninja.metrics.config import MetricsConfig, save_metrics_config
        
        config = MetricsConfig()
        config_file = tmp_path / "subdir" / "config.json"
        
        result = save_metrics_config(config, str(config_file))
        
        assert result is True
        assert config_file.exists()

    def test_save_content_valid_json(self, tmp_path):
        """Test saved content is valid JSON."""
        from trapninja.metrics.config import MetricsConfig, save_metrics_config
        
        config = MetricsConfig(global_labels={'env': 'test'})
        config_file = tmp_path / "config.json"
        
        save_metrics_config(config, str(config_file))
        
        # Should parse without error
        data = json.loads(config_file.read_text())
        assert data['global_labels'] == {'env': 'test'}


class TestGetMetricsConfig:
    """Tests for get_metrics_config function."""

    def test_get_returns_config(self):
        """Test get_metrics_config returns MetricsConfig."""
        from trapninja.metrics.config import get_metrics_config, MetricsConfig
        
        result = get_metrics_config()
        
        assert isinstance(result, MetricsConfig)

    def test_get_caches_config(self):
        """Test get_metrics_config caches the config."""
        from trapninja.metrics import config as config_module
        
        # Clear cached config
        config_module._metrics_config = None
        
        result1 = config_module.get_metrics_config()
        result2 = config_module.get_metrics_config()
        
        # Should return same instance
        assert result1 is result2


class TestGetConfigFilePath:
    """Tests for get_config_file_path function."""

    def test_returns_path_string(self):
        """Test get_config_file_path returns a string path."""
        from trapninja.metrics.config import get_config_file_path
        
        result = get_config_file_path()
        
        assert isinstance(result, str)
        assert result.endswith('metrics_config.json')


class TestCreateExampleConfig:
    """Tests for create_example_config function."""

    def test_returns_dict(self):
        """Test create_example_config returns dictionary."""
        from trapninja.metrics.config import create_example_config
        
        result = create_example_config()
        
        assert isinstance(result, dict)

    def test_contains_required_fields(self):
        """Test example config has required fields."""
        from trapninja.metrics.config import create_example_config
        
        result = create_example_config()
        
        assert 'enabled' in result
        assert 'directory' in result
        assert 'export_interval_seconds' in result
        assert 'global_labels' in result

    def test_contains_example_labels(self):
        """Test example config has example global labels."""
        from trapninja.metrics.config import create_example_config
        
        result = create_example_config()
        
        assert 'global_labels' in result
        assert isinstance(result['global_labels'], dict)
        assert len(result['global_labels']) > 0
