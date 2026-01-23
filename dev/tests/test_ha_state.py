#!/usr/bin/env python3
"""
TrapNinja Test Suite - HA State Tests

Tests for trapninja.ha.state module - HA state machine.

Author: TrapNinja Team
"""

import pytest
from unittest.mock import MagicMock


class TestHAStateEnum:
    """Tests for HAState enum."""

    def test_all_states_exist(self):
        """Test all expected states exist."""
        from trapninja.ha.state import HAState
        
        assert HAState.INITIALIZING
        assert HAState.PRIMARY
        assert HAState.SECONDARY
        assert HAState.STANDALONE
        assert HAState.FAILOVER
        assert HAState.SPLIT_BRAIN
        assert HAState.ERROR

    def test_state_values(self):
        """Test state string values."""
        from trapninja.ha.state import HAState
        
        assert HAState.INITIALIZING.value == "initializing"
        assert HAState.PRIMARY.value == "primary"
        assert HAState.SECONDARY.value == "secondary"
        assert HAState.STANDALONE.value == "standalone"
        assert HAState.FAILOVER.value == "failover"
        assert HAState.SPLIT_BRAIN.value == "split_brain"
        assert HAState.ERROR.value == "error"

    def test_str_representation(self):
        """Test string representation."""
        from trapninja.ha.state import HAState
        
        assert str(HAState.PRIMARY) == "primary"
        assert str(HAState.SECONDARY) == "secondary"


class TestHAStateProperties:
    """Tests for HAState properties."""

    def test_is_active_primary(self):
        """Test is_active is True for PRIMARY."""
        from trapninja.ha.state import HAState
        
        assert HAState.PRIMARY.is_active is True

    def test_is_active_standalone(self):
        """Test is_active is True for STANDALONE."""
        from trapninja.ha.state import HAState
        
        assert HAState.STANDALONE.is_active is True

    def test_is_active_secondary(self):
        """Test is_active is False for SECONDARY."""
        from trapninja.ha.state import HAState
        
        assert HAState.SECONDARY.is_active is False

    def test_is_active_other_states(self):
        """Test is_active is False for other states."""
        from trapninja.ha.state import HAState
        
        assert HAState.INITIALIZING.is_active is False
        assert HAState.FAILOVER.is_active is False
        assert HAState.SPLIT_BRAIN.is_active is False
        assert HAState.ERROR.is_active is False

    def test_is_healthy_primary(self):
        """Test is_healthy is True for PRIMARY."""
        from trapninja.ha.state import HAState
        
        assert HAState.PRIMARY.is_healthy is True

    def test_is_healthy_secondary(self):
        """Test is_healthy is True for SECONDARY."""
        from trapninja.ha.state import HAState
        
        assert HAState.SECONDARY.is_healthy is True

    def test_is_healthy_standalone(self):
        """Test is_healthy is True for STANDALONE."""
        from trapninja.ha.state import HAState
        
        assert HAState.STANDALONE.is_healthy is True

    def test_is_healthy_error_states(self):
        """Test is_healthy is False for error states."""
        from trapninja.ha.state import HAState
        
        assert HAState.SPLIT_BRAIN.is_healthy is False
        assert HAState.ERROR.is_healthy is False

    def test_is_transitional_initializing(self):
        """Test is_transitional is True for INITIALIZING."""
        from trapninja.ha.state import HAState
        
        assert HAState.INITIALIZING.is_transitional is True

    def test_is_transitional_failover(self):
        """Test is_transitional is True for FAILOVER."""
        from trapninja.ha.state import HAState
        
        assert HAState.FAILOVER.is_transitional is True

    def test_is_transitional_primary(self):
        """Test is_transitional is False for PRIMARY."""
        from trapninja.ha.state import HAState
        
        assert HAState.PRIMARY.is_transitional is False

    def test_is_error_split_brain(self):
        """Test is_error is True for SPLIT_BRAIN."""
        from trapninja.ha.state import HAState
        
        assert HAState.SPLIT_BRAIN.is_error is True

    def test_is_error_error(self):
        """Test is_error is True for ERROR."""
        from trapninja.ha.state import HAState
        
        assert HAState.ERROR.is_error is True

    def test_is_error_primary(self):
        """Test is_error is False for PRIMARY."""
        from trapninja.ha.state import HAState
        
        assert HAState.PRIMARY.is_error is False


class TestValidTransitions:
    """Tests for state transition validation."""

    def test_same_state_always_valid(self):
        """Test transition to same state is always valid."""
        from trapninja.ha.state import HAState, is_valid_transition
        
        for state in HAState:
            assert is_valid_transition(state, state) is True

    def test_initializing_to_primary(self):
        """Test INITIALIZING -> PRIMARY is valid."""
        from trapninja.ha.state import HAState, is_valid_transition
        
        assert is_valid_transition(HAState.INITIALIZING, HAState.PRIMARY) is True

    def test_initializing_to_secondary(self):
        """Test INITIALIZING -> SECONDARY is valid."""
        from trapninja.ha.state import HAState, is_valid_transition
        
        assert is_valid_transition(HAState.INITIALIZING, HAState.SECONDARY) is True

    def test_initializing_to_standalone(self):
        """Test INITIALIZING -> STANDALONE is valid."""
        from trapninja.ha.state import HAState, is_valid_transition
        
        assert is_valid_transition(HAState.INITIALIZING, HAState.STANDALONE) is True

    def test_secondary_to_failover(self):
        """Test SECONDARY -> FAILOVER is valid."""
        from trapninja.ha.state import HAState, is_valid_transition
        
        assert is_valid_transition(HAState.SECONDARY, HAState.FAILOVER) is True

    def test_secondary_to_primary(self):
        """Test SECONDARY -> PRIMARY is valid."""
        from trapninja.ha.state import HAState, is_valid_transition
        
        assert is_valid_transition(HAState.SECONDARY, HAState.PRIMARY) is True

    def test_failover_to_primary(self):
        """Test FAILOVER -> PRIMARY is valid."""
        from trapninja.ha.state import HAState, is_valid_transition
        
        assert is_valid_transition(HAState.FAILOVER, HAState.PRIMARY) is True

    def test_primary_to_secondary(self):
        """Test PRIMARY -> SECONDARY is valid."""
        from trapninja.ha.state import HAState, is_valid_transition
        
        assert is_valid_transition(HAState.PRIMARY, HAState.SECONDARY) is True

    def test_primary_to_split_brain(self):
        """Test PRIMARY -> SPLIT_BRAIN is valid."""
        from trapninja.ha.state import HAState, is_valid_transition
        
        assert is_valid_transition(HAState.PRIMARY, HAState.SPLIT_BRAIN) is True

    def test_error_to_initializing(self):
        """Test ERROR -> INITIALIZING is valid (recovery)."""
        from trapninja.ha.state import HAState, is_valid_transition
        
        assert is_valid_transition(HAState.ERROR, HAState.INITIALIZING) is True

    def test_secondary_to_initializing_invalid(self):
        """Test SECONDARY -> INITIALIZING is invalid."""
        from trapninja.ha.state import HAState, is_valid_transition
        
        assert is_valid_transition(HAState.SECONDARY, HAState.INITIALIZING) is False

    def test_primary_to_initializing_invalid(self):
        """Test PRIMARY -> INITIALIZING is invalid."""
        from trapninja.ha.state import HAState, is_valid_transition
        
        assert is_valid_transition(HAState.PRIMARY, HAState.INITIALIZING) is False


class TestGetValidTransitions:
    """Tests for get_valid_transitions function."""

    def test_returns_list(self):
        """Test returns a list."""
        from trapninja.ha.state import HAState, get_valid_transitions
        
        result = get_valid_transitions(HAState.INITIALIZING)
        
        assert isinstance(result, list)

    def test_initializing_transitions(self):
        """Test valid transitions from INITIALIZING."""
        from trapninja.ha.state import HAState, get_valid_transitions
        
        result = get_valid_transitions(HAState.INITIALIZING)
        
        assert HAState.PRIMARY in result
        assert HAState.SECONDARY in result
        assert HAState.STANDALONE in result

    def test_secondary_transitions(self):
        """Test valid transitions from SECONDARY."""
        from trapninja.ha.state import HAState, get_valid_transitions
        
        result = get_valid_transitions(HAState.SECONDARY)
        
        assert HAState.PRIMARY in result
        assert HAState.FAILOVER in result

    def test_error_transitions(self):
        """Test valid transitions from ERROR."""
        from trapninja.ha.state import HAState, get_valid_transitions
        
        result = get_valid_transitions(HAState.ERROR)
        
        assert HAState.INITIALIZING in result
        assert HAState.STANDALONE in result


class TestHAStateManagerInit:
    """Tests for HAStateManager initialization."""

    def test_default_initial_state(self):
        """Test default initial state is INITIALIZING."""
        from trapninja.ha.state import HAState, HAStateManager
        
        manager = HAStateManager()
        
        assert manager.state == HAState.INITIALIZING

    def test_custom_initial_state(self):
        """Test custom initial state."""
        from trapninja.ha.state import HAState, HAStateManager
        
        manager = HAStateManager(HAState.STANDALONE)
        
        assert manager.state == HAState.STANDALONE

    def test_state_property(self):
        """Test state property returns current state."""
        from trapninja.ha.state import HAState, HAStateManager
        
        manager = HAStateManager(HAState.PRIMARY)
        
        assert manager.state == HAState.PRIMARY


class TestHAStateManagerProperties:
    """Tests for HAStateManager properties."""

    def test_is_active_when_primary(self):
        """Test is_active returns True when PRIMARY."""
        from trapninja.ha.state import HAState, HAStateManager
        
        manager = HAStateManager(HAState.PRIMARY)
        
        assert manager.is_active is True

    def test_is_active_when_secondary(self):
        """Test is_active returns False when SECONDARY."""
        from trapninja.ha.state import HAState, HAStateManager
        
        manager = HAStateManager(HAState.SECONDARY)
        
        assert manager.is_active is False

    def test_is_healthy_when_primary(self):
        """Test is_healthy returns True when PRIMARY."""
        from trapninja.ha.state import HAState, HAStateManager
        
        manager = HAStateManager(HAState.PRIMARY)
        
        assert manager.is_healthy is True

    def test_is_healthy_when_error(self):
        """Test is_healthy returns False when ERROR."""
        from trapninja.ha.state import HAState, HAStateManager
        
        manager = HAStateManager(HAState.ERROR)
        
        assert manager.is_healthy is False


class TestHAStateManagerTransitions:
    """Tests for HAStateManager transition_to method."""

    def test_valid_transition_succeeds(self):
        """Test valid transition succeeds."""
        from trapninja.ha.state import HAState, HAStateManager
        
        manager = HAStateManager(HAState.INITIALIZING)
        
        result = manager.transition_to(HAState.PRIMARY)
        
        assert result is True
        assert manager.state == HAState.PRIMARY

    def test_invalid_transition_fails(self):
        """Test invalid transition fails."""
        from trapninja.ha.state import HAState, HAStateManager
        
        manager = HAStateManager(HAState.SECONDARY)
        
        result = manager.transition_to(HAState.INITIALIZING)
        
        assert result is False
        assert manager.state == HAState.SECONDARY  # Unchanged

    def test_force_transition_bypasses_validation(self):
        """Test force=True bypasses validation."""
        from trapninja.ha.state import HAState, HAStateManager
        
        manager = HAStateManager(HAState.SECONDARY)
        
        result = manager.transition_to(HAState.INITIALIZING, force=True)
        
        assert result is True
        assert manager.state == HAState.INITIALIZING

    def test_same_state_transition_succeeds(self):
        """Test transition to same state succeeds."""
        from trapninja.ha.state import HAState, HAStateManager
        
        manager = HAStateManager(HAState.PRIMARY)
        
        result = manager.transition_to(HAState.PRIMARY)
        
        assert result is True

    def test_transition_increments_count(self):
        """Test transition increments transition count."""
        from trapninja.ha.state import HAState, HAStateManager
        
        manager = HAStateManager(HAState.INITIALIZING)
        
        manager.transition_to(HAState.PRIMARY)
        manager.transition_to(HAState.SECONDARY)
        
        assert manager._transition_count == 2


class TestHAStateManagerCallbacks:
    """Tests for HAStateManager callbacks."""

    def test_add_callback(self):
        """Test add_callback adds callback."""
        from trapninja.ha.state import HAState, HAStateManager
        
        manager = HAStateManager()
        callback = MagicMock()
        
        manager.add_callback(callback)
        
        assert callback in manager._callbacks

    def test_remove_callback(self):
        """Test remove_callback removes callback."""
        from trapninja.ha.state import HAState, HAStateManager
        
        manager = HAStateManager()
        callback = MagicMock()
        manager.add_callback(callback)
        
        manager.remove_callback(callback)
        
        assert callback not in manager._callbacks

    def test_callback_called_on_transition(self):
        """Test callback is called on state transition."""
        from trapninja.ha.state import HAState, HAStateManager
        
        manager = HAStateManager(HAState.INITIALIZING)
        callback = MagicMock()
        manager.add_callback(callback)
        
        manager.transition_to(HAState.PRIMARY)
        
        callback.assert_called_once_with(HAState.INITIALIZING, HAState.PRIMARY)

    def test_callback_not_called_same_state(self):
        """Test callback not called for same state transition."""
        from trapninja.ha.state import HAState, HAStateManager
        
        manager = HAStateManager(HAState.PRIMARY)
        callback = MagicMock()
        manager.add_callback(callback)
        
        manager.transition_to(HAState.PRIMARY)
        
        callback.assert_not_called()

    def test_callback_exception_handled(self):
        """Test callback exception is handled gracefully."""
        from trapninja.ha.state import HAState, HAStateManager
        
        manager = HAStateManager(HAState.INITIALIZING)
        callback = MagicMock(side_effect=Exception("Callback error"))
        manager.add_callback(callback)
        
        # Should not raise
        result = manager.transition_to(HAState.PRIMARY)
        
        assert result is True
        assert manager.state == HAState.PRIMARY


class TestHAStateManagerStats:
    """Tests for HAStateManager get_stats method."""

    def test_get_stats_returns_dict(self):
        """Test get_stats returns dictionary."""
        from trapninja.ha.state import HAState, HAStateManager
        
        manager = HAStateManager(HAState.PRIMARY)
        
        stats = manager.get_stats()
        
        assert isinstance(stats, dict)

    def test_get_stats_contains_current_state(self):
        """Test get_stats contains current_state."""
        from trapninja.ha.state import HAState, HAStateManager
        
        manager = HAStateManager(HAState.SECONDARY)
        
        stats = manager.get_stats()
        
        assert stats['current_state'] == "secondary"

    def test_get_stats_contains_is_active(self):
        """Test get_stats contains is_active."""
        from trapninja.ha.state import HAState, HAStateManager
        
        manager = HAStateManager(HAState.PRIMARY)
        
        stats = manager.get_stats()
        
        assert stats['is_active'] is True

    def test_get_stats_contains_is_healthy(self):
        """Test get_stats contains is_healthy."""
        from trapninja.ha.state import HAState, HAStateManager
        
        manager = HAStateManager(HAState.PRIMARY)
        
        stats = manager.get_stats()
        
        assert stats['is_healthy'] is True

    def test_get_stats_contains_transition_count(self):
        """Test get_stats contains transition_count."""
        from trapninja.ha.state import HAState, HAStateManager
        
        manager = HAStateManager(HAState.INITIALIZING)
        manager.transition_to(HAState.PRIMARY)
        
        stats = manager.get_stats()
        
        assert stats['transition_count'] == 1

    def test_get_stats_contains_valid_transitions(self):
        """Test get_stats contains valid_transitions."""
        from trapninja.ha.state import HAState, HAStateManager
        
        manager = HAStateManager(HAState.SECONDARY)
        
        stats = manager.get_stats()
        
        assert 'valid_transitions' in stats
        assert isinstance(stats['valid_transitions'], list)
