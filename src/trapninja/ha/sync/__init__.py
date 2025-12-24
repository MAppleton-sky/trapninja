#!/usr/bin/env python3
"""
TrapNinja HA Config Synchronization Module

Provides configuration synchronization between HA cluster nodes using
the existing HA TCP socket communication mechanism.

Keeps shared configurations (destinations, blocks, redirections) in sync
while leaving server-specific configurations (ha_config, node identity) local.

Architecture:
    - Extends existing HA message protocol for config sync
    - Primary pushes config changes to Secondary
    - Version checksums in heartbeats detect drift
    - No additional dependencies (uses existing HA infrastructure)

Usage:
    from trapninja.ha.sync import (
        ConfigSyncManager, ConfigSyncConfig, SyncedConfigType
    )
    
    # Create sync manager
    sync_mgr = ConfigSyncManager(
        config=ConfigSyncConfig(enabled=True),
        config_dir="/opt/trapninja/config",
        instance_id="node-1",
        get_ha_state=lambda: "primary",
        get_peer_info=lambda: ("192.168.1.102", 60006),
    )
    
    # Start sync
    sync_mgr.start()
    
    # Manual sync
    sync_mgr.push_all_configs()  # As PRIMARY
    sync_mgr.pull_all_configs()  # As SECONDARY

Author: TrapNinja Team
Version: 1.0.0
"""

__all__ = [
    'ConfigSyncManager',
    'ConfigSyncConfig',
    'SyncedConfigType',
    'ConfigSyncMessageType',
    'ConfigVersionInfo',
    'SyncStats',
    'LOCAL_ONLY_CONFIGS',
    'load_sync_config',
    'save_sync_config',
]

from .manager import (
    ConfigSyncManager,
    ConfigSyncConfig,
    SyncedConfigType,
    ConfigSyncMessageType,
    ConfigVersionInfo,
    SyncStats,
    LOCAL_ONLY_CONFIGS,
    load_sync_config,
    save_sync_config,
)
