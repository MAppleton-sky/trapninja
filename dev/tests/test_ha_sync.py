#!/usr/bin/env python3
"""
TrapNinja Test Suite - HA Sync Tests

Tests for trapninja.ha.sync module - configuration synchronization.

Author: TrapNinja Team
"""

import json
import time
import os
import pytest
from unittest.mock import patch, MagicMock


class TestSharedConfigFiles:
    """Tests for SHARED_CONFIG_FILES constant."""

    def test_shared_configs_defined(self):
        """Test SHARED_CONFIG_FILES is defined."""
        from trapninja.ha.sync.manager import SHARED_CONFIG_FILES
        
        assert isinstance(SHARED_CONFIG_FILES, list)
        assert len(SHARED_CONFIG_FILES) > 0

    def test_shared_configs_contains_expected_files(self):
        """Test SHARED_CONFIG_FILES contains expected files."""
        from trapninja.ha.sync.manager import SHARED_CONFIG_FILES
        
        assert "destinations.json" in SHARED_CONFIG_FILES
        assert "blocked_ips.json" in SHARED_CONFIG_FILES
        assert "blocked_traps.json" in SHARED_CONFIG_FILES
        assert "redirected_ips.json" in SHARED_CONFIG_FILES


class TestLocalOnlyConfigs:
    """Tests for LOCAL_ONLY_CONFIGS constant."""

    def test_local_only_configs_is_frozenset(self):
        """Test LOCAL_ONLY_CONFIGS is frozenset."""
        from trapninja.ha.sync.manager import LOCAL_ONLY_CONFIGS
        
        assert isinstance(LOCAL_ONLY_CONFIGS, frozenset)

    def test_ha_config_is_local_only(self):
        """Test ha_config.json is in LOCAL_ONLY_CONFIGS."""
        from trapninja.ha.sync.manager import LOCAL_ONLY_CONFIGS
        
        assert "ha_config.json" in LOCAL_ONLY_CONFIGS

    def test_cache_config_is_local_only(self):
        """Test cache_config.json is in LOCAL_ONLY_CONFIGS."""
        from trapninja.ha.sync.manager import LOCAL_ONLY_CONFIGS
        
        assert "cache_config.json" in LOCAL_ONLY_CONFIGS


class TestConfigBundleCreation:
    """Tests for ConfigBundle creation."""

    def test_empty_bundle(self):
        """Test creating empty ConfigBundle."""
        from trapninja.ha.sync.manager import ConfigBundle
        
        bundle = ConfigBundle()
        
        assert bundle.configs == {}
        assert bundle.timestamp > 0

    def test_bundle_with_configs(self):
        """Test creating ConfigBundle with configs."""
        from trapninja.ha.sync.manager import ConfigBundle
        
        configs = {
            "destinations.json": {"dest1": [["10.0.0.1", 162]]},
            "blocked_ips.json": ["192.168.1.1"]
        }
        
        bundle = ConfigBundle(configs=configs, source_instance="test-123")
        
        assert bundle.configs == configs
        assert bundle.source_instance == "test-123"

    def test_bundle_auto_calculates_checksum(self):
        """Test ConfigBundle auto-calculates checksum."""
        from trapninja.ha.sync.manager import ConfigBundle
        
        configs = {"test.json": {"key": "value"}}
        
        bundle = ConfigBundle(configs=configs)
        
        assert bundle.checksum != ""
        assert len(bundle.checksum) == 32  # MD5 hex length


class TestConfigBundleSerialization:
    """Tests for ConfigBundle serialization."""

    def test_to_dict(self):
        """Test ConfigBundle to_dict."""
        from trapninja.ha.sync.manager import ConfigBundle
        
        bundle = ConfigBundle(
            configs={"test.json": {}},
            source_instance="test-id"
        )
        
        result = bundle.to_dict()
        
        assert 'configs' in result
        assert 'checksum' in result
        assert 'timestamp' in result
        assert 'source_instance' in result

    def test_from_dict(self):
        """Test ConfigBundle from_dict."""
        from trapninja.ha.sync.manager import ConfigBundle
        
        data = {
            'configs': {"test.json": {"key": "value"}},
            'checksum': 'abc123',
            'timestamp': 1000.0,
            'source_instance': 'test-id'
        }
        
        bundle = ConfigBundle.from_dict(data)
        
        assert bundle.configs == {"test.json": {"key": "value"}}
        assert bundle.checksum == 'abc123'
        assert bundle.source_instance == 'test-id'

    def test_to_bytes(self):
        """Test ConfigBundle to_bytes."""
        from trapninja.ha.sync.manager import ConfigBundle
        
        bundle = ConfigBundle(configs={"test.json": {}})
        
        result = bundle.to_bytes()
        
        assert isinstance(result, bytes)

    def test_from_bytes(self):
        """Test ConfigBundle from_bytes."""
        from trapninja.ha.sync.manager import ConfigBundle
        
        original = ConfigBundle(
            configs={"test.json": {"key": "value"}},
            source_instance="original"
        )
        
        restored = ConfigBundle.from_bytes(original.to_bytes())
        
        assert restored.configs == original.configs
        assert restored.source_instance == original.source_instance

    def test_roundtrip(self):
        """Test ConfigBundle roundtrip serialization."""
        from trapninja.ha.sync.manager import ConfigBundle
        
        original = ConfigBundle(
            configs={
                "destinations.json": {"d1": [["10.0.0.1", 162]]},
                "blocked_ips.json": ["1.2.3.4"]
            },
            source_instance="test-instance"
        )
        
        data = original.to_dict()
        restored = ConfigBundle.from_dict(data)
        
        assert restored.configs == original.configs


class TestConfigSyncManagerInit:
    """Tests for ConfigSyncManager initialization."""

    def test_initialization(self, tmp_path):
        """Test ConfigSyncManager initialization."""
        from trapninja.ha.sync.manager import ConfigSyncManager
        
        manager = ConfigSyncManager(
            config_dir=str(tmp_path),
            instance_id="test-instance-123",
            peer_host="10.0.0.2",
            peer_port=60006
        )
        
        assert manager.config_dir == str(tmp_path)
        assert manager.instance_id == "test-instance-123"
        assert manager.peer_host == "10.0.0.2"
        assert manager.peer_port == 60006

    def test_initialization_calculates_checksum(self, tmp_path):
        """Test initialization calculates local checksum."""
        from trapninja.ha.sync.manager import ConfigSyncManager
        
        manager = ConfigSyncManager(
            config_dir=str(tmp_path),
            instance_id="test",
            peer_host="localhost",
            peer_port=60006
        )
        
        assert manager._local_checksum is not None

    def test_initialization_with_callback(self, tmp_path):
        """Test initialization with on_config_changed callback."""
        from trapninja.ha.sync.manager import ConfigSyncManager
        
        callback = MagicMock()
        
        manager = ConfigSyncManager(
            config_dir=str(tmp_path),
            instance_id="test",
            peer_host="localhost",
            peer_port=60006,
            on_config_changed=callback
        )
        
        assert manager.on_config_changed == callback


class TestConfigSyncManagerChecksum:
    """Tests for ConfigSyncManager checksum operations."""

    def test_get_local_checksum(self, tmp_path):
        """Test get_local_checksum returns checksum."""
        from trapninja.ha.sync.manager import ConfigSyncManager
        
        manager = ConfigSyncManager(
            config_dir=str(tmp_path),
            instance_id="test",
            peer_host="localhost",
            peer_port=60006
        )
        
        checksum = manager.get_local_checksum()
        
        assert isinstance(checksum, str)
        assert len(checksum) == 32

    def test_checksum_changes_with_files(self, tmp_path):
        """Test checksum changes when files change."""
        from trapninja.ha.sync.manager import ConfigSyncManager
        
        manager = ConfigSyncManager(
            config_dir=str(tmp_path),
            instance_id="test",
            peer_host="localhost",
            peer_port=60006
        )
        
        checksum1 = manager.get_local_checksum()
        
        # Create a config file
        dest_file = tmp_path / "destinations.json"
        dest_file.write_text(json.dumps({"d1": [["10.0.0.1", 162]]}))
        
        # Force recalculation
        manager._local_checksum = None
        checksum2 = manager.get_local_checksum()
        
        assert checksum1 != checksum2

    def test_update_remote_checksum(self, tmp_path):
        """Test update_remote_checksum stores checksum."""
        from trapninja.ha.sync.manager import ConfigSyncManager
        
        manager = ConfigSyncManager(
            config_dir=str(tmp_path),
            instance_id="test",
            peer_host="localhost",
            peer_port=60006
        )
        
        manager.update_remote_checksum("abc123def456")
        
        assert manager._remote_checksum == "abc123def456"


class TestConfigSyncManagerPrimary:
    """Tests for ConfigSyncManager primary/secondary operations."""

    def test_set_primary_true(self, tmp_path):
        """Test set_primary(True) sets flag."""
        from trapninja.ha.sync.manager import ConfigSyncManager
        
        manager = ConfigSyncManager(
            config_dir=str(tmp_path),
            instance_id="test",
            peer_host="localhost",
            peer_port=60006
        )
        
        manager.set_primary(True)
        
        assert manager._is_primary is True

    def test_set_primary_false(self, tmp_path):
        """Test set_primary(False) sets flag."""
        from trapninja.ha.sync.manager import ConfigSyncManager
        
        manager = ConfigSyncManager(
            config_dir=str(tmp_path),
            instance_id="test",
            peer_host="localhost",
            peer_port=60006
        )
        
        manager._is_primary = True
        manager.set_primary(False)
        
        assert manager._is_primary is False


class TestConfigSyncManagerBundle:
    """Tests for ConfigSyncManager bundle operations."""

    def test_create_bundle(self, tmp_path):
        """Test _create_bundle creates bundle from files."""
        from trapninja.ha.sync.manager import ConfigSyncManager, SHARED_CONFIG_FILES
        
        # Create some config files
        for filename in SHARED_CONFIG_FILES[:2]:
            filepath = tmp_path / filename
            filepath.write_text(json.dumps({"test": "data"}))
        
        manager = ConfigSyncManager(
            config_dir=str(tmp_path),
            instance_id="test-instance",
            peer_host="localhost",
            peer_port=60006
        )
        
        bundle = manager._create_bundle()
        
        assert bundle.source_instance == "test-instance"
        assert len(bundle.configs) >= 2

    def test_create_bundle_missing_files(self, tmp_path):
        """Test _create_bundle handles missing files."""
        from trapninja.ha.sync.manager import ConfigSyncManager
        
        manager = ConfigSyncManager(
            config_dir=str(tmp_path),
            instance_id="test",
            peer_host="localhost",
            peer_port=60006
        )
        
        # No files exist - should use defaults
        bundle = manager._create_bundle()
        
        assert bundle is not None
        # Missing files should have empty defaults
        for filename, content in bundle.configs.items():
            assert content is not None


class TestConfigSyncManagerApplyBundle:
    """Tests for ConfigSyncManager _apply_bundle method."""

    def test_apply_bundle_creates_files(self, tmp_path):
        """Test _apply_bundle creates config files."""
        from trapninja.ha.sync.manager import ConfigSyncManager, ConfigBundle
        
        manager = ConfigSyncManager(
            config_dir=str(tmp_path),
            instance_id="test",
            peer_host="localhost",
            peer_port=60006
        )
        
        bundle = ConfigBundle(
            configs={
                "destinations.json": {"dest1": [["10.0.0.1", 162]]},
                "blocked_ips.json": ["1.2.3.4"]
            },
            source_instance="primary"
        )
        
        result = manager._apply_bundle(bundle)
        
        assert result is True
        assert (tmp_path / "destinations.json").exists()
        assert (tmp_path / "blocked_ips.json").exists()

    def test_apply_bundle_refuses_local_only(self, tmp_path):
        """Test _apply_bundle refuses to write LOCAL_ONLY_CONFIGS."""
        from trapninja.ha.sync.manager import ConfigSyncManager, ConfigBundle
        
        manager = ConfigSyncManager(
            config_dir=str(tmp_path),
            instance_id="test",
            peer_host="localhost",
            peer_port=60006
        )
        
        bundle = ConfigBundle(
            configs={
                "ha_config.json": {"mode": "primary"},  # Should be refused
                "destinations.json": {"d1": []}
            },
            source_instance="primary"
        )
        
        manager._apply_bundle(bundle)
        
        # ha_config.json should NOT be created
        assert not (tmp_path / "ha_config.json").exists()
        # destinations.json should be created
        assert (tmp_path / "destinations.json").exists()

    def test_apply_bundle_calls_callback(self, tmp_path):
        """Test _apply_bundle calls on_config_changed callback."""
        from trapninja.ha.sync.manager import ConfigSyncManager, ConfigBundle
        
        callback = MagicMock()
        
        manager = ConfigSyncManager(
            config_dir=str(tmp_path),
            instance_id="test",
            peer_host="localhost",
            peer_port=60006,
            on_config_changed=callback
        )
        
        bundle = ConfigBundle(
            configs={"destinations.json": {}},
            source_instance="primary"
        )
        
        manager._apply_bundle(bundle)
        
        callback.assert_called_once()


class TestConfigSyncManagerHandlers:
    """Tests for ConfigSyncManager request handlers."""

    def test_handle_config_request_not_primary(self, tmp_path):
        """Test handle_config_request returns None when not primary."""
        from trapninja.ha.sync.manager import ConfigSyncManager
        
        manager = ConfigSyncManager(
            config_dir=str(tmp_path),
            instance_id="test",
            peer_host="localhost",
            peer_port=60006
        )
        
        manager._is_primary = False
        
        result = manager.handle_config_request()
        
        assert result is None

    def test_handle_config_request_as_primary(self, tmp_path):
        """Test handle_config_request returns bundle when primary."""
        from trapninja.ha.sync.manager import ConfigSyncManager
        
        manager = ConfigSyncManager(
            config_dir=str(tmp_path),
            instance_id="test",
            peer_host="localhost",
            peer_port=60006
        )
        
        manager._is_primary = True
        
        result = manager.handle_config_request()
        
        assert result is not None

    def test_handle_config_push_as_primary(self, tmp_path):
        """Test handle_config_push rejects when primary."""
        from trapninja.ha.sync.manager import ConfigSyncManager, ConfigBundle
        
        manager = ConfigSyncManager(
            config_dir=str(tmp_path),
            instance_id="test",
            peer_host="localhost",
            peer_port=60006
        )
        
        manager._is_primary = True
        
        bundle = ConfigBundle(configs={})
        success, msg = manager.handle_config_push(bundle.to_bytes())
        
        assert success is False
        assert "PRIMARY" in msg

    def test_handle_config_push_as_secondary(self, tmp_path):
        """Test handle_config_push applies bundle when secondary."""
        from trapninja.ha.sync.manager import ConfigSyncManager, ConfigBundle
        
        manager = ConfigSyncManager(
            config_dir=str(tmp_path),
            instance_id="test",
            peer_host="localhost",
            peer_port=60006
        )
        
        manager._is_primary = False
        
        bundle = ConfigBundle(
            configs={"destinations.json": {"d1": []}},
            source_instance="primary"
        )
        
        success, msg = manager.handle_config_push(bundle.to_bytes())
        
        assert success is True


class TestConfigSyncManagerStatus:
    """Tests for ConfigSyncManager get_status method."""

    def test_get_status_returns_dict(self, tmp_path):
        """Test get_status returns dictionary."""
        from trapninja.ha.sync.manager import ConfigSyncManager
        
        manager = ConfigSyncManager(
            config_dir=str(tmp_path),
            instance_id="test",
            peer_host="10.0.0.2",
            peer_port=60006
        )
        
        status = manager.get_status()
        
        assert isinstance(status, dict)

    def test_get_status_contains_expected_fields(self, tmp_path):
        """Test get_status contains expected fields."""
        from trapninja.ha.sync.manager import ConfigSyncManager
        
        manager = ConfigSyncManager(
            config_dir=str(tmp_path),
            instance_id="test",
            peer_host="10.0.0.2",
            peer_port=60006
        )
        
        status = manager.get_status()
        
        assert 'is_primary' in status
        assert 'local_checksum' in status
        assert 'config_dir' in status
        assert 'peer' in status
        assert 'stats' in status

    def test_get_status_peer_format(self, tmp_path):
        """Test get_status formats peer correctly."""
        from trapninja.ha.sync.manager import ConfigSyncManager
        
        manager = ConfigSyncManager(
            config_dir=str(tmp_path),
            instance_id="test",
            peer_host="10.0.0.2",
            peer_port=60007
        )
        
        status = manager.get_status()
        
        assert status['peer'] == "10.0.0.2:60007"


class TestConfigSyncManagerStats:
    """Tests for ConfigSyncManager statistics tracking."""

    def test_initial_stats(self, tmp_path):
        """Test initial stats are zero."""
        from trapninja.ha.sync.manager import ConfigSyncManager
        
        manager = ConfigSyncManager(
            config_dir=str(tmp_path),
            instance_id="test",
            peer_host="localhost",
            peer_port=60006
        )
        
        assert manager._stats['pulls_completed'] == 0
        assert manager._stats['pushes_completed'] == 0
        assert manager._stats['pull_failures'] == 0
        assert manager._stats['push_failures'] == 0


class TestConfigSyncManagerStartStop:
    """Tests for ConfigSyncManager start/stop."""

    def test_start_as_primary(self, tmp_path):
        """Test start as primary sets flag."""
        from trapninja.ha.sync.manager import ConfigSyncManager
        
        manager = ConfigSyncManager(
            config_dir=str(tmp_path),
            instance_id="test",
            peer_host="localhost",
            peer_port=60006
        )
        
        # Mock pull_configs to avoid network call
        with patch.object(manager, 'pull_configs', return_value=True):
            manager.start(is_primary=True)
        
        assert manager._is_primary is True
        
        manager.stop()

    def test_stop_sets_event(self, tmp_path):
        """Test stop sets stop event."""
        from trapninja.ha.sync.manager import ConfigSyncManager
        
        manager = ConfigSyncManager(
            config_dir=str(tmp_path),
            instance_id="test",
            peer_host="localhost",
            peer_port=60006
        )
        
        with patch.object(manager, 'pull_configs', return_value=True):
            manager.start(is_primary=True)
        
        manager.stop()
        
        assert manager._stop_event.is_set()
