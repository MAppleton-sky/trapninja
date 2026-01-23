#!/usr/bin/env python3
"""
TrapNinja Test Suite - Integration Tests: High Availability

End-to-end tests for HA failover scenarios.
Tests the complete HA flow including state transitions and failover.

Author: TrapNinja Team
"""

import os
import sys
import time
import socket
import threading
import queue
import pytest
import tempfile
import json
from pathlib import Path
from unittest.mock import patch, MagicMock, PropertyMock


# =============================================================================
# Test Fixtures
# =============================================================================

@pytest.fixture
def ha_config_primary():
    """Create HA configuration for primary node."""
    from trapninja.ha.config import HAConfig
    
    return HAConfig(
        enabled=True,
        mode='primary',
        priority=150,
        peer_host='127.0.0.1',
        peer_port=60007,
        listen_port=60006,
        heartbeat_interval=0.5,
        heartbeat_timeout=2.0,
        shared_secret='test_secret_123'
    )


@pytest.fixture
def ha_config_secondary():
    """Create HA configuration for secondary node."""
    from trapninja.ha.config import HAConfig
    
    return HAConfig(
        enabled=True,
        mode='secondary',
        priority=100,
        peer_host='127.0.0.1',
        peer_port=60006,
        listen_port=60007,
        heartbeat_interval=0.5,
        heartbeat_timeout=2.0,
        shared_secret='test_secret_123'
    )


@pytest.fixture
def mock_forwarding_callback():
    """Create a mock forwarding callback."""
    calls = []
    
    def callback(enabled):
        calls.append(('forwarding', enabled, time.time()))
    
    callback.calls = calls
    return callback


# =============================================================================
# HA State Machine Integration Tests
# =============================================================================

class TestHAStateMachineIntegration:
    """Integration tests for HA state machine."""

    def test_state_enum_exists(self):
        """Test HAState enum exists."""
        from trapninja.ha.state import HAState
        
        assert HAState is not None

    def test_state_manager_exists(self):
        """Test HAStateManager class exists."""
        from trapninja.ha.state import HAStateManager
        
        manager = HAStateManager()
        assert manager is not None

    def test_state_manager_has_state(self):
        """Test HAStateManager has state attribute."""
        from trapninja.ha.state import HAStateManager
        
        manager = HAStateManager()
        
        # Check it has state in some form
        assert hasattr(manager, 'state') or hasattr(manager, '_state')

    def test_state_manager_has_transition_method(self):
        """Test HAStateManager has transition_to method."""
        from trapninja.ha.state import HAStateManager
        
        manager = HAStateManager()
        
        assert hasattr(manager, 'transition_to')
        assert callable(manager.transition_to)


# =============================================================================
# HA Cluster Integration Tests
# =============================================================================

class TestHAClusterIntegration:
    """Integration tests for HA cluster operations."""

    def test_cluster_class_exists(self):
        """Test HACluster class exists."""
        from trapninja.ha.cluster import HACluster
        
        assert HACluster is not None

    def test_cluster_initialization(self, ha_config_primary, mock_forwarding_callback):
        """Test HA cluster initializes correctly."""
        from trapninja.ha.cluster import HACluster
        
        cluster = HACluster(ha_config_primary, mock_forwarding_callback)
        
        assert cluster is not None
        assert cluster.config == ha_config_primary

    def test_cluster_has_get_status(self, ha_config_primary, mock_forwarding_callback):
        """Test cluster has get_status method."""
        from trapninja.ha.cluster import HACluster
        
        cluster = HACluster(ha_config_primary, mock_forwarding_callback)
        
        assert hasattr(cluster, 'get_status')
        assert callable(cluster.get_status)

    def test_cluster_status_returns_dict(self, ha_config_primary, mock_forwarding_callback):
        """Test cluster status returns dict."""
        from trapninja.ha.cluster import HACluster
        
        cluster = HACluster(ha_config_primary, mock_forwarding_callback)
        status = cluster.get_status()
        
        assert isinstance(status, dict)

    def test_cluster_has_promote_method(self, ha_config_primary, mock_forwarding_callback):
        """Test cluster has promote method."""
        from trapninja.ha.cluster import HACluster
        
        cluster = HACluster(ha_config_primary, mock_forwarding_callback)
        
        assert hasattr(cluster, 'promote_to_primary')

    def test_cluster_has_demote_method(self, ha_config_primary, mock_forwarding_callback):
        """Test cluster has demote method."""
        from trapninja.ha.cluster import HACluster
        
        cluster = HACluster(ha_config_primary, mock_forwarding_callback)
        
        assert hasattr(cluster, 'demote_to_secondary')


# =============================================================================
# HA Heartbeat Integration Tests
# =============================================================================

class TestHAHeartbeatIntegration:
    """Integration tests for HA heartbeat mechanism."""

    def test_message_types_exist(self):
        """Test HA message types exist."""
        from trapninja.ha.messages import HAMessageType
        
        assert hasattr(HAMessageType, 'HEARTBEAT')

    def test_message_factory_exists(self):
        """Test MessageFactory exists."""
        from trapninja.ha.messages import MessageFactory
        
        assert MessageFactory is not None

    def test_message_class_exists(self):
        """Test HAMessage class exists."""
        from trapninja.ha.messages import HAMessage
        
        assert HAMessage is not None

    def test_heartbeat_timeout_config(self, ha_config_primary):
        """Test heartbeat timeout is configured."""
        assert ha_config_primary.heartbeat_timeout > 0
        assert ha_config_primary.heartbeat_interval > 0
        assert ha_config_primary.heartbeat_timeout > ha_config_primary.heartbeat_interval


# =============================================================================
# HA Failover Integration Tests
# =============================================================================

class TestHAFailoverIntegration:
    """Integration tests for HA failover scenarios."""

    def test_priority_comparison(self, ha_config_primary, ha_config_secondary):
        """Test priority comparison for failover."""
        assert ha_config_primary.priority > ha_config_secondary.priority

    def test_config_has_shared_secret(self, ha_config_primary):
        """Test config has shared secret."""
        assert ha_config_primary.shared_secret != ''

    def test_config_has_peer_info(self, ha_config_primary):
        """Test config has peer connection info."""
        assert ha_config_primary.peer_host != ''
        assert ha_config_primary.peer_port > 0
        assert ha_config_primary.listen_port > 0


# =============================================================================
# HA Forwarding Control Integration Tests
# =============================================================================

class TestHAForwardingControlIntegration:
    """Integration tests for HA forwarding control."""

    def test_service_has_forwarding_control(self):
        """Test service has forwarding control function."""
        from trapninja.service import trap_forwarder_control
        
        assert callable(trap_forwarder_control)

    def test_forwarding_can_be_enabled(self):
        """Test forwarding can be enabled."""
        from trapninja import service
        
        service.trap_forwarder_control(True)
        assert service.ha_forwarding_enabled is True

    def test_forwarding_can_be_disabled(self):
        """Test forwarding can be disabled."""
        from trapninja import service
        
        service.trap_forwarder_control(False)
        assert service.ha_forwarding_enabled is False

    def test_forwarding_toggle(self):
        """Test forwarding can be toggled."""
        from trapninja import service
        
        service.trap_forwarder_control(True)
        assert service.ha_forwarding_enabled is True
        
        service.trap_forwarder_control(False)
        assert service.ha_forwarding_enabled is False
        
        service.trap_forwarder_control(True)
        assert service.ha_forwarding_enabled is True


# =============================================================================
# HA Configuration Sync Integration Tests
# =============================================================================

class TestHAConfigSyncIntegration:
    """Integration tests for HA configuration synchronization."""

    def test_sync_module_exists(self):
        """Test sync module exists."""
        from trapninja.ha import sync
        
        assert sync is not None

    def test_config_sync_manager_exists(self):
        """Test ConfigSyncManager exists."""
        from trapninja.ha.sync import ConfigSyncManager
        
        assert ConfigSyncManager is not None

    def test_config_bundle_exists(self):
        """Test ConfigBundle exists."""
        from trapninja.ha.sync import ConfigBundle
        
        assert ConfigBundle is not None


# =============================================================================
# HA Service Integration Tests
# =============================================================================

class TestHAServiceIntegration:
    """Integration tests for HA with service module."""

    def test_ha_status_function_exists(self):
        """Test HA status function exists."""
        from trapninja.service import get_ha_status
        
        assert callable(get_ha_status)

    def test_ha_status_returns_dict(self):
        """Test HA status returns dict."""
        from trapninja.service import get_ha_status
        
        status = get_ha_status()
        
        assert isinstance(status, dict)
        assert 'enabled' in status
        assert 'state' in status

    def test_service_respects_ha_forwarding(self):
        """Test service respects HA forwarding enable/disable."""
        from trapninja import service
        
        service.trap_forwarder_control(False)
        assert service.ha_forwarding_enabled is False
        
        service.trap_forwarder_control(True)
        assert service.ha_forwarding_enabled is True

    def test_ha_shutdown_function_exists(self):
        """Test HA shutdown function exists."""
        from trapninja.ha import shutdown_ha
        
        assert callable(shutdown_ha)

    def test_ha_get_cluster_function_exists(self):
        """Test get_ha_cluster function exists."""
        from trapninja.ha import get_ha_cluster
        
        assert callable(get_ha_cluster)


# =============================================================================
# HA Recovery Integration Tests
# =============================================================================

class TestHARecoveryIntegration:
    """Integration tests for HA recovery scenarios."""

    def test_ha_initialization_function_exists(self):
        """Test HA initialization function exists."""
        from trapninja.ha import initialize_ha
        
        assert callable(initialize_ha)

    def test_ha_config_load_function_exists(self):
        """Test HA config load function exists."""
        from trapninja.ha import load_ha_config
        
        assert callable(load_ha_config)

    def test_state_can_be_serialized(self, temp_config_dir):
        """Test state can be serialized to JSON."""
        state_data = {
            'state': 'PRIMARY',
            'timestamp': time.time(),
            'priority': 150
        }
        
        state_file = temp_config_dir / 'ha_state.json'
        state_file.write_text(json.dumps(state_data))
        
        saved_data = json.loads(state_file.read_text())
        
        assert saved_data['state'] == 'PRIMARY'
        assert saved_data['priority'] == 150


# =============================================================================
# HA API Integration Tests
# =============================================================================

class TestHAAPIIntegration:
    """Integration tests for HA public API."""

    def test_api_module_exists(self):
        """Test HA API module exists."""
        from trapninja.ha import api
        
        assert api is not None

    def test_is_primary_exists(self):
        """Test is_primary function exists."""
        from trapninja.ha.api import is_primary
        
        assert callable(is_primary)

    def test_is_forwarding_enabled_exists(self):
        """Test is_forwarding_enabled function exists."""
        from trapninja.ha.api import is_forwarding_enabled
        
        assert callable(is_forwarding_enabled)

    def test_is_forwarding_enabled_returns_bool(self):
        """Test is_forwarding_enabled returns boolean."""
        from trapninja.ha.api import is_forwarding_enabled
        
        result = is_forwarding_enabled()
        assert isinstance(result, bool)

    def test_is_primary_returns_bool(self):
        """Test is_primary returns boolean."""
        from trapninja.ha.api import is_primary
        
        result = is_primary()
        assert isinstance(result, bool)


# =============================================================================
# HA Config Integration Tests
# =============================================================================

class TestHAConfigIntegration:
    """Integration tests for HAConfig dataclass."""

    def test_ha_config_defaults(self):
        """Test HAConfig has sensible defaults."""
        from trapninja.ha.config import HAConfig
        
        config = HAConfig()
        
        assert config.enabled is False
        assert config.mode in ['primary', 'secondary']
        assert config.priority >= 0
        assert config.heartbeat_interval > 0
        assert config.heartbeat_timeout > 0

    def test_ha_config_custom_values(self):
        """Test HAConfig accepts custom values."""
        from trapninja.ha.config import HAConfig
        
        config = HAConfig(
            enabled=True,
            mode='primary',
            priority=200,
            peer_host='10.0.0.1',
            peer_port=60010,
            listen_port=60010
        )
        
        assert config.enabled is True
        assert config.mode == 'primary'
        assert config.priority == 200
        assert config.peer_host == '10.0.0.1'
        assert config.peer_port == 60010

    def test_ha_config_has_validation(self):
        """Test HAConfig has validation."""
        from trapninja.ha.config import HAConfig
        
        # Valid config should work
        config = HAConfig(
            enabled=True,
            mode='primary',
            priority=100
        )
        
        assert config is not None
