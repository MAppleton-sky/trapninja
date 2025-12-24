#!/usr/bin/env python3
"""
TrapNinja High Availability Package

Provides High Availability clustering capabilities with:
- Active/Passive failover
- Heartbeat monitoring
- Split-brain detection and resolution
- Manual promotion/demotion controls
- Configuration synchronization between nodes

Package Structure:
- state.py: HA state machine and state definitions
- messages.py: HA message types and serialization
- config.py: HA configuration management
- cluster.py: Main HACluster implementation
- api.py: Public API functions
- sync/: Configuration synchronization module

Usage:
    from trapninja.ha import (
        initialize_ha, shutdown_ha, get_ha_status,
        promote_to_primary, demote_to_secondary,
        HAConfig, HAState
    )
    
    # Config sync (if enabled)
    from trapninja.ha.sync import (
        ConfigSyncManager, ConfigSyncConfig, SyncedConfigType
    )

Author: TrapNinja Team
Version: 2.1.0
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

# Import config sync
try:
    from .sync import (
        ConfigSyncManager,
        ConfigSyncConfig,
        SyncedConfigType,
        ConfigSyncMessageType,
    )
    from .sync.manager import (
        load_sync_config,
        save_sync_config,
        LOCAL_ONLY_CONFIGS,
    )
    CONFIG_SYNC_AVAILABLE = True
except ImportError as e:
    CONFIG_SYNC_AVAILABLE = False
    # Define stubs for when sync is not available
    ConfigSyncManager = None
    ConfigSyncConfig = None
    SyncedConfigType = None
    ConfigSyncMessageType = None
    load_sync_config = None
    save_sync_config = None
    LOCAL_ONLY_CONFIGS = frozenset()

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
    # Config sync
    'CONFIG_SYNC_AVAILABLE',
    'ConfigSyncManager',
    'ConfigSyncConfig',
    'SyncedConfigType',
    'ConfigSyncMessageType',
    'load_sync_config',
    'save_sync_config',
    'LOCAL_ONLY_CONFIGS',
]

__version__ = '2.1.0'
