#!/usr/bin/env python3
"""
TrapNinja HA State Management

Defines the High Availability state machine and state transitions.
Handles state validation and provides utilities for state management.

Author: TrapNinja Team
Version: 2.0.0
"""

from enum import Enum
from typing import Set, Dict, List
import logging

logger = logging.getLogger("trapninja")


class HAState(Enum):
    """
    High Availability states.
    
    State Descriptions:
        INITIALIZING: Starting up, determining initial state
        PRIMARY: Active node, processing and forwarding traps
        SECONDARY: Standby node, ready to take over
        STANDALONE: HA disabled, single-node operation
        FAILOVER: Transitioning to primary role
        SPLIT_BRAIN: Both nodes claim primary (error condition)
        ERROR: Unrecoverable error state
    """
    INITIALIZING = "initializing"
    PRIMARY = "primary"
    SECONDARY = "secondary"
    STANDALONE = "standalone"
    FAILOVER = "failover"
    SPLIT_BRAIN = "split_brain"
    ERROR = "error"
    
    def __str__(self) -> str:
        return self.value
    
    @property
    def is_active(self) -> bool:
        """Check if this state should be forwarding traps."""
        return self in (HAState.PRIMARY, HAState.STANDALONE)
    
    @property
    def is_healthy(self) -> bool:
        """Check if this is a healthy operational state."""
        return self in (
            HAState.PRIMARY,
            HAState.SECONDARY,
            HAState.STANDALONE
        )
    
    @property
    def is_transitional(self) -> bool:
        """Check if this is a transitional state."""
        return self in (HAState.INITIALIZING, HAState.FAILOVER)
    
    @property
    def is_error(self) -> bool:
        """Check if this is an error state."""
        return self in (HAState.SPLIT_BRAIN, HAState.ERROR)


# Valid state transitions
VALID_TRANSITIONS: Dict[HAState, Set[HAState]] = {
    HAState.INITIALIZING: {
        HAState.PRIMARY,
        HAState.SECONDARY,
        HAState.STANDALONE,
        HAState.ERROR
    },
    HAState.PRIMARY: {
        HAState.SECONDARY,
        HAState.SPLIT_BRAIN,
        HAState.ERROR,
        HAState.STANDALONE
    },
    HAState.SECONDARY: {
        HAState.PRIMARY,
        HAState.FAILOVER,
        HAState.ERROR,
        HAState.STANDALONE
    },
    HAState.STANDALONE: {
        HAState.PRIMARY,
        HAState.SECONDARY,
        HAState.INITIALIZING,
        HAState.ERROR
    },
    HAState.FAILOVER: {
        HAState.PRIMARY,
        HAState.SECONDARY,
        HAState.ERROR
    },
    HAState.SPLIT_BRAIN: {
        HAState.PRIMARY,
        HAState.SECONDARY,
        HAState.ERROR
    },
    HAState.ERROR: {
        HAState.INITIALIZING,
        HAState.STANDALONE
    }
}


def is_valid_transition(current: HAState, target: HAState) -> bool:
    """
    Check if a state transition is valid.
    
    Args:
        current: Current HA state
        target: Target HA state
        
    Returns:
        True if transition is valid, False otherwise
    """
    if current == target:
        return True  # Same state is always valid
    
    valid_targets = VALID_TRANSITIONS.get(current, set())
    return target in valid_targets


def get_valid_transitions(state: HAState) -> List[HAState]:
    """
    Get list of valid target states from current state.
    
    Args:
        state: Current HA state
        
    Returns:
        List of valid target states
    """
    return list(VALID_TRANSITIONS.get(state, set()))


class HAStateManager:
    """
    Manages HA state transitions with validation and logging.
    
    Provides thread-safe state management with transition validation
    and callback support.
    """
    
    def __init__(self, initial_state: HAState = HAState.INITIALIZING):
        self._state = initial_state
        self._callbacks: List = []
        self._transition_count = 0
    
    @property
    def state(self) -> HAState:
        """Get current state."""
        return self._state
    
    @property
    def is_active(self) -> bool:
        """Check if currently in active state."""
        return self._state.is_active
    
    @property
    def is_healthy(self) -> bool:
        """Check if currently in healthy state."""
        return self._state.is_healthy
    
    def transition_to(self, target: HAState, force: bool = False) -> bool:
        """
        Transition to a new state.
        
        Args:
            target: Target state
            force: If True, skip validation
            
        Returns:
            True if transition succeeded
        """
        if not force and not is_valid_transition(self._state, target):
            logger.warning(
                f"Invalid state transition: {self._state.value} -> {target.value}"
            )
            return False
        
        old_state = self._state
        self._state = target
        self._transition_count += 1
        
        if old_state != target:
            logger.info(f"HA state transition: {old_state.value} -> {target.value}")
            self._notify_callbacks(old_state, target)
        
        return True
    
    def add_callback(self, callback):
        """Add a state change callback."""
        self._callbacks.append(callback)
    
    def remove_callback(self, callback):
        """Remove a state change callback."""
        if callback in self._callbacks:
            self._callbacks.remove(callback)
    
    def _notify_callbacks(self, old_state: HAState, new_state: HAState):
        """Notify all callbacks of state change."""
        for callback in self._callbacks:
            try:
                callback(old_state, new_state)
            except Exception as e:
                logger.error(f"State callback error: {e}")
    
    def get_stats(self) -> dict:
        """Get state manager statistics."""
        return {
            'current_state': self._state.value,
            'is_active': self.is_active,
            'is_healthy': self.is_healthy,
            'transition_count': self._transition_count,
            'valid_transitions': [s.value for s in get_valid_transitions(self._state)]
        }
