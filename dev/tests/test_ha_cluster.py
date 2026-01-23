#!/usr/bin/env python3
"""
TrapNinja Test Suite - HA Cluster Tests

Tests for trapninja.ha.cluster module - main HA cluster implementation.

Author: TrapNinja Team
"""

import time
import socket
import threading
import pytest
from unittest.mock import patch, MagicMock, PropertyMock


class TestHAClusterInit:
    """Tests for HACluster initialization."""

    def test_initialization(self):
        """Test HACluster initialization."""
        from trapninja.ha.cluster import HACluster
        from trapninja.ha.config import HAConfig
        from trapninja.ha.state import HAState
        
        config = HAConfig(enabled=True, mode="primary", priority=150)
        callback = MagicMock()
        
        cluster = HACluster(config, callback)
        
        assert cluster.config == config
        assert cluster.instance_id is not None
        assert len(cluster.instance_id) == 36  # UUID format
        assert cluster.current_state == HAState.INITIALIZING
        assert cluster.is_forwarding is False

    def test_initialization_with_config_dir(self):
        """Test initialization with config_dir enables sync."""
        from trapninja.ha.cluster import HACluster, CONFIG_SYNC_AVAILABLE
        from trapninja.ha.config import HAConfig
        
        config = HAConfig(enabled=True)
        callback = MagicMock()
        
        cluster = HACluster(config, callback, config_dir="/tmp/test")
        
        # Config sync may or may not be available depending on imports
        if CONFIG_SYNC_AVAILABLE:
            assert cluster.config_sync is not None
        else:
            assert cluster.config_sync is None

    def test_current_state_property(self):
        """Test current_state property."""
        from trapninja.ha.cluster import HACluster
        from trapninja.ha.config import HAConfig
        from trapninja.ha.state import HAState
        
        config = HAConfig()
        callback = MagicMock()
        
        cluster = HACluster(config, callback)
        
        assert cluster.current_state == HAState.INITIALIZING


class TestHAClusterStandalone:
    """Tests for HACluster standalone mode."""

    def test_start_disabled_goes_standalone(self):
        """Test starting with HA disabled goes to STANDALONE."""
        from trapninja.ha.cluster import HACluster
        from trapninja.ha.config import HAConfig
        from trapninja.ha.state import HAState
        
        config = HAConfig(enabled=False)
        callback = MagicMock()
        
        cluster = HACluster(config, callback)
        result = cluster.start()
        
        assert result is True
        assert cluster.current_state == HAState.STANDALONE
        assert cluster.is_forwarding is True
        
        cluster.stop()

    def test_standalone_enables_forwarding(self):
        """Test STANDALONE mode enables forwarding."""
        from trapninja.ha.cluster import HACluster
        from trapninja.ha.config import HAConfig
        
        config = HAConfig(enabled=False)
        callback = MagicMock()
        
        cluster = HACluster(config, callback)
        cluster.start()
        
        assert cluster.is_forwarding is True
        callback.assert_called_with(True)
        
        cluster.stop()


class TestHAClusterStatus:
    """Tests for HACluster get_status method."""

    def test_get_status_returns_dict(self):
        """Test get_status returns dictionary."""
        from trapninja.ha.cluster import HACluster
        from trapninja.ha.config import HAConfig
        
        config = HAConfig(enabled=False)
        callback = MagicMock()
        
        cluster = HACluster(config, callback)
        
        status = cluster.get_status()
        
        assert isinstance(status, dict)
        assert 'instance_id' in status
        assert 'state' in status
        assert 'is_forwarding' in status

    def test_get_status_contains_peer_info(self):
        """Test get_status contains peer information."""
        from trapninja.ha.cluster import HACluster
        from trapninja.ha.config import HAConfig
        
        config = HAConfig(enabled=True)
        callback = MagicMock()
        
        cluster = HACluster(config, callback)
        
        status = cluster.get_status()
        
        assert 'peer_connected' in status
        assert 'peer_state' in status
        assert 'peer_priority' in status

    def test_get_status_contains_config_info(self):
        """Test get_status contains config information."""
        from trapninja.ha.cluster import HACluster
        from trapninja.ha.config import HAConfig
        
        config = HAConfig(enabled=True, priority=150)
        callback = MagicMock()
        
        cluster = HACluster(config, callback)
        
        status = cluster.get_status()
        
        assert status['priority'] == 150
        assert 'enabled' in status


class TestHAClusterNotifyTrap:
    """Tests for HACluster notify_trap_processed method."""

    def test_notify_trap_updates_time(self):
        """Test notify_trap_processed updates last_trap_time."""
        from trapninja.ha.cluster import HACluster
        from trapninja.ha.config import HAConfig
        
        config = HAConfig()
        callback = MagicMock()
        
        cluster = HACluster(config, callback)
        
        assert cluster.last_trap_time is None
        
        cluster.notify_trap_processed()
        
        assert cluster.last_trap_time is not None
        assert time.time() - cluster.last_trap_time < 1.0


class TestHAClusterPromotion:
    """Tests for HACluster promotion and demotion."""

    def test_promote_when_already_primary(self):
        """Test promote returns True when already PRIMARY."""
        from trapninja.ha.cluster import HACluster
        from trapninja.ha.config import HAConfig
        from trapninja.ha.state import HAState
        
        config = HAConfig(enabled=False)
        callback = MagicMock()
        
        cluster = HACluster(config, callback)
        cluster.start()  # Goes STANDALONE
        cluster.state_manager.transition_to(HAState.PRIMARY, force=True)
        
        result = cluster.promote_to_primary()
        
        assert result is True
        
        cluster.stop()

    def test_promote_sets_manual_override(self):
        """Test promote sets manual_override flag."""
        from trapninja.ha.cluster import HACluster
        from trapninja.ha.config import HAConfig
        from trapninja.ha.state import HAState
        
        config = HAConfig(enabled=False)
        callback = MagicMock()
        
        cluster = HACluster(config, callback)
        cluster.state_manager.transition_to(HAState.SECONDARY, force=True)
        
        cluster.promote_to_primary()
        
        assert cluster.manual_override is True
        
        cluster.stop()

    def test_demote_when_already_secondary(self):
        """Test demote returns True when already SECONDARY."""
        from trapninja.ha.cluster import HACluster
        from trapninja.ha.config import HAConfig
        from trapninja.ha.state import HAState
        
        config = HAConfig()
        callback = MagicMock()
        
        cluster = HACluster(config, callback)
        cluster.state_manager.transition_to(HAState.SECONDARY, force=True)
        
        result = cluster.demote_to_secondary()
        
        assert result is True

    def test_demote_from_primary(self):
        """Test demote from PRIMARY goes to SECONDARY."""
        from trapninja.ha.cluster import HACluster
        from trapninja.ha.config import HAConfig
        from trapninja.ha.state import HAState
        
        config = HAConfig(enabled=False)
        callback = MagicMock()
        
        cluster = HACluster(config, callback)
        cluster.start()
        cluster.state_manager.transition_to(HAState.PRIMARY, force=True)
        cluster.is_forwarding = True
        
        result = cluster.demote_to_secondary()
        
        assert result is True
        assert cluster.current_state == HAState.SECONDARY
        
        cluster.stop()


class TestHAClusterStateTransitions:
    """Tests for HACluster state transitions."""

    def test_set_state_enables_forwarding_for_primary(self):
        """Test transitioning to PRIMARY enables forwarding."""
        from trapninja.ha.cluster import HACluster
        from trapninja.ha.config import HAConfig
        from trapninja.ha.state import HAState
        
        config = HAConfig()
        callback = MagicMock()
        
        cluster = HACluster(config, callback)
        cluster._set_state(HAState.PRIMARY)
        
        assert cluster.is_forwarding is True
        callback.assert_called_with(True)

    def test_set_state_disables_forwarding_for_secondary(self):
        """Test transitioning to SECONDARY disables forwarding."""
        from trapninja.ha.cluster import HACluster
        from trapninja.ha.config import HAConfig
        from trapninja.ha.state import HAState
        
        config = HAConfig()
        callback = MagicMock()
        
        cluster = HACluster(config, callback)
        cluster.is_forwarding = True
        cluster._set_state(HAState.SECONDARY)
        
        assert cluster.is_forwarding is False
        callback.assert_called_with(False)


class TestHAClusterPeerTracking:
    """Tests for HACluster peer tracking."""

    def test_update_peer_info(self):
        """Test _update_peer_info updates peer state."""
        from trapninja.ha.cluster import HACluster
        from trapninja.ha.config import HAConfig
        from trapninja.ha.state import HAState
        from trapninja.ha.messages import HAMessage, HAMessageType
        
        config = HAConfig()
        callback = MagicMock()
        
        cluster = HACluster(config, callback)
        
        msg = HAMessage(
            msg_type=HAMessageType.HEARTBEAT,
            sender_id="peer-123",
            timestamp=time.time(),
            sequence=1,
            state=HAState.PRIMARY,
            priority=200,
            uptime=1000.0
        )
        
        cluster._update_peer_info(msg)
        
        assert cluster.peer_state == HAState.PRIMARY
        assert cluster.peer_priority == 200
        assert cluster.peer_uptime == 1000.0
        assert cluster.peer_last_seen is not None


class TestHAClusterStop:
    """Tests for HACluster stop method."""

    def test_stop_sets_event(self):
        """Test stop sets stop_event."""
        from trapninja.ha.cluster import HACluster
        from trapninja.ha.config import HAConfig
        
        config = HAConfig(enabled=False)
        callback = MagicMock()
        
        cluster = HACluster(config, callback)
        cluster.start()
        
        cluster.stop()
        
        assert cluster.stop_event.is_set()

    def test_stop_disables_forwarding(self):
        """Test stop disables forwarding."""
        from trapninja.ha.cluster import HACluster
        from trapninja.ha.config import HAConfig
        
        config = HAConfig(enabled=False)
        callback = MagicMock()
        
        cluster = HACluster(config, callback)
        cluster.start()
        
        assert cluster.is_forwarding is True
        
        cluster.stop()
        
        assert cluster.is_forwarding is False


class TestHAClusterConfigSync:
    """Tests for HACluster config sync integration."""

    def test_sync_config_not_available(self):
        """Test sync_config when config_sync is None."""
        from trapninja.ha.cluster import HACluster
        from trapninja.ha.config import HAConfig
        
        config = HAConfig()
        callback = MagicMock()
        
        cluster = HACluster(config, callback)
        cluster.config_sync = None
        
        result = cluster.sync_config()
        
        assert result['success'] is False
        assert 'not available' in result['message']

    def test_sync_config_as_primary_pushes(self):
        """Test sync_config as PRIMARY pushes configs."""
        from trapninja.ha.cluster import HACluster
        from trapninja.ha.config import HAConfig
        from trapninja.ha.state import HAState
        
        config = HAConfig()
        callback = MagicMock()
        
        cluster = HACluster(config, callback)
        cluster.state_manager.transition_to(HAState.PRIMARY, force=True)
        
        mock_sync = MagicMock()
        mock_sync.push_configs.return_value = True
        cluster.config_sync = mock_sync
        
        result = cluster.sync_config()
        
        mock_sync.push_configs.assert_called_once()
        assert result['direction'] == 'push'

    def test_sync_config_as_secondary_pulls(self):
        """Test sync_config as SECONDARY pulls configs."""
        from trapninja.ha.cluster import HACluster
        from trapninja.ha.config import HAConfig
        from trapninja.ha.state import HAState
        
        config = HAConfig()
        callback = MagicMock()
        
        cluster = HACluster(config, callback)
        cluster.state_manager.transition_to(HAState.SECONDARY, force=True)
        
        mock_sync = MagicMock()
        mock_sync.pull_configs.return_value = True
        cluster.config_sync = mock_sync
        
        result = cluster.sync_config()
        
        mock_sync.pull_configs.assert_called_once()
        assert result['direction'] == 'pull'


class TestHAClusterMessageFactory:
    """Tests for HACluster message factory."""

    def test_message_factory_created(self):
        """Test message factory is created with correct params."""
        from trapninja.ha.cluster import HACluster
        from trapninja.ha.config import HAConfig
        
        config = HAConfig(priority=175)
        callback = MagicMock()
        
        cluster = HACluster(config, callback)
        
        assert cluster.msg_factory is not None
        assert cluster.msg_factory.instance_id == cluster.instance_id
        assert cluster.msg_factory.priority == 175


class TestHAClusterFailoverReplay:
    """Tests for HACluster failover replay tracking."""

    def test_failover_gap_start_initially_none(self):
        """Test failover gap start is initially None."""
        from trapninja.ha.cluster import HACluster
        from trapninja.ha.config import HAConfig
        
        config = HAConfig()
        callback = MagicMock()
        
        cluster = HACluster(config, callback)
        
        assert cluster._failover_gap_start is None

    def test_status_includes_failover_gap_pending(self):
        """Test get_status includes failover_gap_pending."""
        from trapninja.ha.cluster import HACluster
        from trapninja.ha.config import HAConfig
        
        config = HAConfig()
        callback = MagicMock()
        
        cluster = HACluster(config, callback)
        
        status = cluster.get_status()
        
        assert 'failover_gap_pending' in status
        assert status['failover_gap_pending'] is False
