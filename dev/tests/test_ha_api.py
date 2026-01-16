#!/usr/bin/env python3
"""
TrapNinja Test Suite - HA API Tests

Tests for trapninja.ha.api module - HA public API functions.

Author: TrapNinja Team
"""

import pytest
from unittest.mock import patch, MagicMock, PropertyMock


class TestGetHACluster:
    """Tests for get_ha_cluster function."""

    def test_returns_none_before_init(self):
        """Test returns None before initialization."""
        from trapninja.ha import api as ha_api
        
        # Save original
        original = ha_api._ha_cluster
        ha_api._ha_cluster = None
        
        try:
            result = ha_api.get_ha_cluster()
            assert result is None
        finally:
            ha_api._ha_cluster = original

    def test_returns_cluster_after_init(self):
        """Test returns cluster after initialization."""
        from trapninja.ha import api as ha_api
        
        # Save original
        original = ha_api._ha_cluster
        mock_cluster = MagicMock()
        ha_api._ha_cluster = mock_cluster
        
        try:
            result = ha_api.get_ha_cluster()
            assert result is mock_cluster
        finally:
            ha_api._ha_cluster = original


class TestGetHAStatus:
    """Tests for get_ha_status function."""

    def test_returns_disabled_when_no_cluster(self):
        """Test returns disabled status when no cluster."""
        from trapninja.ha import api as ha_api
        
        original = ha_api._ha_cluster
        ha_api._ha_cluster = None
        
        try:
            result = ha_api.get_ha_status()
            assert result['enabled'] is False
            assert result['state'] == 'disabled'
        finally:
            ha_api._ha_cluster = original

    def test_returns_cluster_status(self):
        """Test returns cluster status when initialized."""
        from trapninja.ha import api as ha_api
        
        original = ha_api._ha_cluster
        mock_cluster = MagicMock()
        mock_cluster.get_status.return_value = {
            'state': 'primary',
            'is_forwarding': True
        }
        ha_api._ha_cluster = mock_cluster
        
        try:
            result = ha_api.get_ha_status()
            assert result['state'] == 'primary'
            assert result['is_forwarding'] is True
        finally:
            ha_api._ha_cluster = original


class TestIsForwardingEnabled:
    """Tests for is_forwarding_enabled function."""

    def test_returns_true_when_no_cluster(self):
        """Test returns True when no cluster (standalone mode)."""
        from trapninja.ha import api as ha_api
        
        original = ha_api._ha_cluster
        ha_api._ha_cluster = None
        
        try:
            result = ha_api.is_forwarding_enabled()
            assert result is True
        finally:
            ha_api._ha_cluster = original

    def test_returns_cluster_forwarding_state(self):
        """Test returns cluster is_forwarding state."""
        from trapninja.ha import api as ha_api
        from trapninja.ha.state import HAState
        
        original = ha_api._ha_cluster
        mock_cluster = MagicMock()
        mock_cluster.is_forwarding = True
        mock_cluster.current_state = HAState.PRIMARY
        ha_api._ha_cluster = mock_cluster
        
        try:
            result = ha_api.is_forwarding_enabled()
            assert result is True
        finally:
            ha_api._ha_cluster = original

    def test_returns_false_when_secondary(self):
        """Test returns False when cluster is secondary."""
        from trapninja.ha import api as ha_api
        from trapninja.ha.state import HAState
        
        original = ha_api._ha_cluster
        mock_cluster = MagicMock()
        mock_cluster.is_forwarding = False
        mock_cluster.current_state = HAState.SECONDARY
        ha_api._ha_cluster = mock_cluster
        
        try:
            result = ha_api.is_forwarding_enabled()
            assert result is False
        finally:
            ha_api._ha_cluster = original


class TestNotifyTrapProcessed:
    """Tests for notify_trap_processed function."""

    def test_does_nothing_when_no_cluster(self):
        """Test does nothing when no cluster."""
        from trapninja.ha import api as ha_api
        
        original = ha_api._ha_cluster
        ha_api._ha_cluster = None
        
        try:
            # Should not raise
            ha_api.notify_trap_processed()
        finally:
            ha_api._ha_cluster = original

    def test_notifies_cluster(self):
        """Test notifies cluster when initialized."""
        from trapninja.ha import api as ha_api
        
        original = ha_api._ha_cluster
        mock_cluster = MagicMock()
        ha_api._ha_cluster = mock_cluster
        
        try:
            ha_api.notify_trap_processed()
            mock_cluster.notify_trap_processed.assert_called_once()
        finally:
            ha_api._ha_cluster = original


class TestPromoteToPrimary:
    """Tests for promote_to_primary function."""

    def test_returns_false_when_no_cluster(self):
        """Test returns False when no cluster."""
        from trapninja.ha import api as ha_api
        
        original = ha_api._ha_cluster
        ha_api._ha_cluster = None
        
        try:
            result = ha_api.promote_to_primary()
            assert result is False
        finally:
            ha_api._ha_cluster = original

    def test_calls_cluster_promote(self):
        """Test calls cluster promote_to_primary."""
        from trapninja.ha import api as ha_api
        
        original = ha_api._ha_cluster
        mock_cluster = MagicMock()
        mock_cluster.promote_to_primary.return_value = True
        ha_api._ha_cluster = mock_cluster
        
        try:
            result = ha_api.promote_to_primary(force=True)
            mock_cluster.promote_to_primary.assert_called_once_with(force=True)
            assert result is True
        finally:
            ha_api._ha_cluster = original


class TestDemoteToSecondary:
    """Tests for demote_to_secondary function."""

    def test_returns_false_when_no_cluster(self):
        """Test returns False when no cluster."""
        from trapninja.ha import api as ha_api
        
        original = ha_api._ha_cluster
        ha_api._ha_cluster = None
        
        try:
            result = ha_api.demote_to_secondary()
            assert result is False
        finally:
            ha_api._ha_cluster = original

    def test_calls_cluster_demote(self):
        """Test calls cluster demote_to_secondary."""
        from trapninja.ha import api as ha_api
        
        original = ha_api._ha_cluster
        mock_cluster = MagicMock()
        mock_cluster.demote_to_secondary.return_value = True
        ha_api._ha_cluster = mock_cluster
        
        try:
            result = ha_api.demote_to_secondary()
            mock_cluster.demote_to_secondary.assert_called_once()
            assert result is True
        finally:
            ha_api._ha_cluster = original


class TestIsHAEnabled:
    """Tests for is_ha_enabled function."""

    def test_returns_false_when_no_cluster(self):
        """Test returns False when no cluster."""
        from trapninja.ha import api as ha_api
        
        original = ha_api._ha_cluster
        ha_api._ha_cluster = None
        
        try:
            result = ha_api.is_ha_enabled()
            assert result is False
        finally:
            ha_api._ha_cluster = original

    def test_returns_config_enabled(self):
        """Test returns config.enabled value."""
        from trapninja.ha import api as ha_api
        
        original = ha_api._ha_cluster
        mock_cluster = MagicMock()
        mock_cluster.config.enabled = True
        ha_api._ha_cluster = mock_cluster
        
        try:
            result = ha_api.is_ha_enabled()
            assert result is True
        finally:
            ha_api._ha_cluster = original


class TestGetHAState:
    """Tests for get_ha_state function."""

    def test_returns_none_when_no_cluster(self):
        """Test returns None when no cluster."""
        from trapninja.ha import api as ha_api
        
        original = ha_api._ha_cluster
        ha_api._ha_cluster = None
        
        try:
            result = ha_api.get_ha_state()
            assert result is None
        finally:
            ha_api._ha_cluster = original

    def test_returns_current_state(self):
        """Test returns current state."""
        from trapninja.ha import api as ha_api
        from trapninja.ha.state import HAState
        
        original = ha_api._ha_cluster
        mock_cluster = MagicMock()
        mock_cluster.current_state = HAState.PRIMARY
        ha_api._ha_cluster = mock_cluster
        
        try:
            result = ha_api.get_ha_state()
            assert result == HAState.PRIMARY
        finally:
            ha_api._ha_cluster = original


class TestIsPrimary:
    """Tests for is_primary function."""

    def test_returns_true_when_no_cluster(self):
        """Test returns True when no cluster (standalone)."""
        from trapninja.ha import api as ha_api
        
        original = ha_api._ha_cluster
        ha_api._ha_cluster = None
        
        try:
            result = ha_api.is_primary()
            assert result is True
        finally:
            ha_api._ha_cluster = original

    def test_returns_true_when_primary(self):
        """Test returns True when state is PRIMARY."""
        from trapninja.ha import api as ha_api
        from trapninja.ha.state import HAState
        
        original = ha_api._ha_cluster
        mock_cluster = MagicMock()
        mock_cluster.current_state = HAState.PRIMARY
        ha_api._ha_cluster = mock_cluster
        
        try:
            result = ha_api.is_primary()
            assert result is True
        finally:
            ha_api._ha_cluster = original

    def test_returns_false_when_secondary(self):
        """Test returns False when state is SECONDARY."""
        from trapninja.ha import api as ha_api
        from trapninja.ha.state import HAState
        
        original = ha_api._ha_cluster
        mock_cluster = MagicMock()
        mock_cluster.current_state = HAState.SECONDARY
        ha_api._ha_cluster = mock_cluster
        
        try:
            result = ha_api.is_primary()
            assert result is False
        finally:
            ha_api._ha_cluster = original


class TestIsSecondary:
    """Tests for is_secondary function."""

    def test_returns_false_when_no_cluster(self):
        """Test returns False when no cluster (standalone)."""
        from trapninja.ha import api as ha_api
        
        original = ha_api._ha_cluster
        ha_api._ha_cluster = None
        
        try:
            result = ha_api.is_secondary()
            assert result is False
        finally:
            ha_api._ha_cluster = original

    def test_returns_true_when_secondary(self):
        """Test returns True when state is SECONDARY."""
        from trapninja.ha import api as ha_api
        from trapninja.ha.state import HAState
        
        original = ha_api._ha_cluster
        mock_cluster = MagicMock()
        mock_cluster.current_state = HAState.SECONDARY
        ha_api._ha_cluster = mock_cluster
        
        try:
            result = ha_api.is_secondary()
            assert result is True
        finally:
            ha_api._ha_cluster = original


class TestForceFailover:
    """Tests for force_failover function."""

    def test_calls_demote_to_secondary(self):
        """Test force_failover calls demote_to_secondary."""
        from trapninja.ha import api as ha_api
        
        original = ha_api._ha_cluster
        mock_cluster = MagicMock()
        mock_cluster.demote_to_secondary.return_value = True
        ha_api._ha_cluster = mock_cluster
        
        try:
            result = ha_api.force_failover()
            mock_cluster.demote_to_secondary.assert_called_once()
            assert result is True
        finally:
            ha_api._ha_cluster = original


class TestInitializeHA:
    """Tests for initialize_ha function."""

    def test_creates_cluster(self):
        """Test initialize_ha creates cluster."""
        from trapninja.ha import api as ha_api
        from trapninja.ha.config import HAConfig
        
        original = ha_api._ha_cluster
        ha_api._ha_cluster = None
        
        config = HAConfig(enabled=False)  # Disabled for unit test
        callback = MagicMock()
        
        try:
            with patch.object(ha_api, 'HACluster') as mock_cluster_class:
                mock_instance = MagicMock()
                mock_instance.start.return_value = True
                mock_cluster_class.return_value = mock_instance
                
                result = ha_api.initialize_ha(config, callback)
                
                assert result is True
                mock_cluster_class.assert_called()
        finally:
            ha_api._ha_cluster = original

    def test_handles_exception(self):
        """Test handles exception during initialization."""
        from trapninja.ha import api as ha_api
        from trapninja.ha.config import HAConfig
        
        original = ha_api._ha_cluster
        ha_api._ha_cluster = None
        
        config = HAConfig()
        callback = MagicMock()
        
        try:
            with patch.object(ha_api, 'HACluster', side_effect=Exception("Test error")):
                result = ha_api.initialize_ha(config, callback)
                
                assert result is False
        finally:
            ha_api._ha_cluster = original


class TestShutdownHA:
    """Tests for shutdown_ha function."""

    def test_does_nothing_when_no_cluster(self):
        """Test does nothing when no cluster."""
        from trapninja.ha import api as ha_api
        
        original = ha_api._ha_cluster
        ha_api._ha_cluster = None
        
        try:
            # Should not raise
            ha_api.shutdown_ha()
        finally:
            ha_api._ha_cluster = original

    def test_stops_cluster(self):
        """Test stops cluster when initialized."""
        from trapninja.ha import api as ha_api
        
        original = ha_api._ha_cluster
        mock_cluster = MagicMock()
        ha_api._ha_cluster = mock_cluster
        
        try:
            ha_api.shutdown_ha()
            
            mock_cluster.stop.assert_called_once()
            assert ha_api._ha_cluster is None
        finally:
            ha_api._ha_cluster = original
