#!/usr/bin/env python3
"""
TrapNinja High Availability Package

Provides High Availability clustering capabilities with:
- Active/Passive failover
- Heartbeat monitoring
- Split-brain detection and resolution
- Manual promotion/demotion controls

Package Structure:
- state.py: HA state machine and state definitions
- messages.py: HA message types and serialization
- config.py: HA configuration management
- cluster.py: Main HACluster implementation
- api.py: Public API functions

Usage:
    from trapninja.ha import (
        initialize_ha, shutdown_ha, get_ha_status,
        promote_to_primary, demote_to_secondary,
        HAConfig, HAState
    )

Author: TrapNinja Team
Version: 2.0.0
"""

# Import state definitions
from .state import HAState

# Import message types
from .messages import HAMessage, HAMessageType

# Import configuration
from .config import HAConfig, load_ha_config, save_ha_config

# Import cluster
from .cluster import HACluster

# Import public API
from .api import (
    initialize_ha,
    shutdown_ha,
    get_ha_cluster,
    get_ha_status,
    is_forwarding_enabled,
    notify_trap_processed,
    promote_to_primary,
    demote_to_secondary,
)

__all__ = [
    # State
    'HAState',
    # Messages
    'HAMessage',
    'HAMessageType',
    # Configuration
    'HAConfig',
    'load_ha_config',
    'save_ha_config',
    # Cluster
    'HACluster',
    # API functions
    'initialize_ha',
    'shutdown_ha',
    'get_ha_cluster',
    'get_ha_status',
    'is_forwarding_enabled',
    'notify_trap_processed',
    'promote_to_primary',
    'demote_to_secondary',
]

__version__ = '2.0.0'
