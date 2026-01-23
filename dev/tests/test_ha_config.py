#!/usr/bin/env python3
"""
TrapNinja Test Suite - HA Configuration Tests

Tests for trapninja.ha.config module - HA configuration management.

Author: TrapNinja Team
"""

import json
import pytest
from unittest.mock import patch, MagicMock


class TestHAConfigDefaults:
    """Tests for HAConfig default values."""

    def test_default_values(self):
        """Test HAConfig default values."""
        from trapninja.ha.config import HAConfig
        
        config = HAConfig()
        
        assert config.enabled is False
        assert config.mode == "primary"
        assert config.peer_host == "127.0.0.1"
        assert config.peer_port == 60006
        assert config.listen_port == 60006
        assert config.heartbeat_interval == 1.0
        assert config.heartbeat_timeout == 3.0
        assert config.failover_delay == 2.0
        assert config.priority == 100

    def test_str_representation(self):
        """Test string representation."""
        from trapninja.ha.config import HAConfig
        
        config = HAConfig(enabled=True, mode="primary")
        
        result = str(config)
        
        assert "enabled=True" in result
        assert "mode=primary" in result


class TestHAConfigValidation:
    """Tests for HAConfig validation."""

    def test_valid_primary_mode(self):
        """Test valid primary mode."""
        from trapninja.ha.config import HAConfig
        
        config = HAConfig(mode="primary")
        
        assert config.mode == "primary"

    def test_valid_secondary_mode(self):
        """Test valid secondary mode."""
        from trapninja.ha.config import HAConfig
        
        config = HAConfig(mode="secondary")
        
        assert config.mode == "secondary"

    def test_invalid_mode_raises(self):
        """Test invalid mode raises ValueError."""
        from trapninja.ha.config import HAConfig
        
        with pytest.raises(ValueError, match="Invalid mode"):
            HAConfig(mode="invalid")

    def test_invalid_peer_port_raises(self):
        """Test invalid peer_port raises ValueError."""
        from trapninja.ha.config import HAConfig
        
        with pytest.raises(ValueError, match="Invalid peer_port"):
            HAConfig(peer_port=0)
        
        with pytest.raises(ValueError, match="Invalid peer_port"):
            HAConfig(peer_port=70000)

    def test_invalid_listen_port_raises(self):
        """Test invalid listen_port raises ValueError."""
        from trapninja.ha.config import HAConfig
        
        with pytest.raises(ValueError, match="Invalid listen_port"):
            HAConfig(listen_port=-1)

    def test_invalid_heartbeat_interval_raises(self):
        """Test invalid heartbeat_interval raises ValueError."""
        from trapninja.ha.config import HAConfig
        
        with pytest.raises(ValueError, match="heartbeat_interval must be positive"):
            HAConfig(heartbeat_interval=0)

    def test_invalid_heartbeat_timeout_raises(self):
        """Test invalid heartbeat_timeout raises ValueError."""
        from trapninja.ha.config import HAConfig
        
        with pytest.raises(ValueError, match="heartbeat_timeout must be positive"):
            HAConfig(heartbeat_timeout=0)

    def test_invalid_priority_raises(self):
        """Test invalid priority raises ValueError."""
        from trapninja.ha.config import HAConfig
        
        with pytest.raises(ValueError, match="Invalid priority"):
            HAConfig(priority=-1)
        
        with pytest.raises(ValueError, match="Invalid priority"):
            HAConfig(priority=256)


class TestHAConfigSerialization:
    """Tests for HAConfig serialization."""

    def test_to_dict(self):
        """Test to_dict returns all fields."""
        from trapninja.ha.config import HAConfig
        
        config = HAConfig(
            enabled=True,
            mode="secondary",
            peer_host="10.0.0.1",
            priority=150
        )
        
        result = config.to_dict()
        
        assert result['enabled'] is True
        assert result['mode'] == "secondary"
        assert result['peer_host'] == "10.0.0.1"
        assert result['priority'] == 150

    def test_from_dict(self):
        """Test from_dict creates config."""
        from trapninja.ha.config import HAConfig
        
        data = {
            'enabled': True,
            'mode': 'primary',
            'peer_host': '192.168.1.1',
            'peer_port': 60007,
            'priority': 200
        }
        
        config = HAConfig.from_dict(data)
        
        assert config.enabled is True
        assert config.peer_host == '192.168.1.1'
        assert config.peer_port == 60007
        assert config.priority == 200

    def test_from_dict_ignores_unknown_fields(self):
        """Test from_dict ignores unknown fields."""
        from trapninja.ha.config import HAConfig
        
        data = {
            'enabled': True,
            'unknown_field': 'ignored',
            'another_unknown': 123
        }
        
        # Should not raise
        config = HAConfig.from_dict(data)
        
        assert config.enabled is True

    def test_roundtrip(self):
        """Test from_dict(to_dict()) produces equivalent config."""
        from trapninja.ha.config import HAConfig
        
        original = HAConfig(
            enabled=True,
            mode="secondary",
            peer_host="10.0.0.1",
            peer_port=60008,
            priority=75
        )
        
        data = original.to_dict()
        restored = HAConfig.from_dict(data)
        
        assert restored.enabled == original.enabled
        assert restored.mode == original.mode
        assert restored.peer_host == original.peer_host
        assert restored.peer_port == original.peer_port
        assert restored.priority == original.priority


class TestLoadHAConfig:
    """Tests for load_ha_config function."""

    def test_load_from_file(self, tmp_path):
        """Test loading config from file."""
        from trapninja.ha.config import load_ha_config
        
        config_file = tmp_path / "ha_config.json"
        config_file.write_text(json.dumps({
            'enabled': True,
            'mode': 'primary',
            'peer_host': '10.0.0.1'
        }))
        
        config = load_ha_config(str(config_file))
        
        assert config.enabled is True
        assert config.mode == 'primary'
        assert config.peer_host == '10.0.0.1'

    def test_load_nonexistent_returns_defaults(self, tmp_path):
        """Test loading nonexistent file returns defaults."""
        from trapninja.ha.config import load_ha_config
        
        config = load_ha_config(str(tmp_path / "nonexistent.json"))
        
        assert config.enabled is False  # Default
        assert config.mode == "primary"  # Default

    def test_load_invalid_json_returns_defaults(self, tmp_path):
        """Test loading invalid JSON returns defaults."""
        from trapninja.ha.config import load_ha_config
        
        config_file = tmp_path / "invalid.json"
        config_file.write_text("not valid json")
        
        config = load_ha_config(str(config_file))
        
        assert config.enabled is False

    def test_load_invalid_values_returns_defaults(self, tmp_path):
        """Test loading invalid values returns defaults."""
        from trapninja.ha.config import load_ha_config
        
        config_file = tmp_path / "bad_values.json"
        config_file.write_text(json.dumps({
            'enabled': True,
            'mode': 'invalid_mode'  # Invalid
        }))
        
        config = load_ha_config(str(config_file))
        
        assert config.enabled is False  # Falls back to default


class TestSaveHAConfig:
    """Tests for save_ha_config function."""

    def test_save_creates_file(self, tmp_path):
        """Test saving creates config file."""
        from trapninja.ha.config import HAConfig, save_ha_config
        
        config_file = tmp_path / "ha_config.json"
        config = HAConfig(enabled=True, mode="primary")
        
        result = save_ha_config(config, str(config_file))
        
        assert result is True
        assert config_file.exists()

    def test_save_creates_directory(self, tmp_path):
        """Test saving creates parent directory."""
        from trapninja.ha.config import HAConfig, save_ha_config
        
        config_file = tmp_path / "subdir" / "ha_config.json"
        config = HAConfig()
        
        result = save_ha_config(config, str(config_file))
        
        assert result is True
        assert config_file.exists()

    def test_save_content_valid_json(self, tmp_path):
        """Test saved content is valid JSON."""
        from trapninja.ha.config import HAConfig, save_ha_config
        
        config_file = tmp_path / "ha_config.json"
        config = HAConfig(enabled=True, priority=150)
        
        save_ha_config(config, str(config_file))
        
        data = json.loads(config_file.read_text())
        assert data['enabled'] is True
        assert data['priority'] == 150


class TestHelperFunctions:
    """Tests for helper configuration functions."""

    def test_create_primary_config(self):
        """Test create_primary_config creates primary config."""
        from trapninja.ha.config import create_primary_config
        
        config = create_primary_config(
            peer_host="10.0.0.2",
            peer_port=60006,
            priority=150
        )
        
        assert config.enabled is True
        assert config.mode == "primary"
        assert config.peer_host == "10.0.0.2"
        assert config.priority == 150

    def test_create_secondary_config(self):
        """Test create_secondary_config creates secondary config."""
        from trapninja.ha.config import create_secondary_config
        
        config = create_secondary_config(
            peer_host="10.0.0.1",
            peer_port=60006,
            priority=100
        )
        
        assert config.enabled is True
        assert config.mode == "secondary"
        assert config.peer_host == "10.0.0.1"
        assert config.priority == 100

    def test_create_configs_with_kwargs(self):
        """Test helper functions pass through kwargs."""
        from trapninja.ha.config import create_primary_config
        
        config = create_primary_config(
            peer_host="10.0.0.2",
            heartbeat_interval=2.0,
            failover_delay=5.0
        )
        
        assert config.heartbeat_interval == 2.0
        assert config.failover_delay == 5.0
