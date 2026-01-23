#!/usr/bin/env python3
"""
TrapNinja HA Config Synchronization Module

Provides configuration synchronization between HA cluster nodes.

Keeps shared configurations (destinations, blocks, redirections) in sync
while leaving server-specific configurations (ha_config, node identity) local.

Usage:
    from trapninja.ha.sync import ConfigSyncManager, ConfigBundle
    
    # Create sync manager (called automatically by HACluster)
    sync_mgr = ConfigSyncManager(
        config_dir="/opt/trapninja/config",
        instance_id="node-1",
        peer_host="192.168.1.102",
        peer_port=60006,
    )
    
    # Start sync as secondary (pulls from primary)
    sync_mgr.start(is_primary=False)
    
    # Manual operations
    sync_mgr.pull_configs()   # As SECONDARY
    sync_mgr.push_configs()   # As PRIMARY

Author: TrapNinja Team
Version: 2.0.0
"""

__all__ = [
    'ConfigSyncManager',
    'ConfigBundle',
    'SHARED_CONFIG_FILES',
    'LOCAL_ONLY_CONFIGS',
]

from .manager import (
    ConfigSyncManager,
    ConfigBundle,
    SHARED_CONFIG_FILES,
    LOCAL_ONLY_CONFIGS,
)

# Also export from config_bundle for backward compatibility
try:
    from .config_bundle import SharedConfig, SHARED_CONFIG_FILES as BUNDLE_SHARED_FILES
    __all__.extend(['SharedConfig'])
except ImportError:
    pass
