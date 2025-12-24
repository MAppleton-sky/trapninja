#!/usr/bin/env python3
"""
TrapNinja Config Sync CLI Commands

CLI commands for managing HA configuration synchronization.

Author: TrapNinja Team
Version: 1.0.0
"""

import json
import os
from typing import Optional

from .validation import InputValidator


def configure_sync(
    enabled: bool = True,
    sync_on_startup: bool = True,
    sync_on_promotion: bool = True,
    push_on_file_change: bool = True,
    version_check_interval: int = 30,
    primary_authority: bool = True,
    sync_timeout: float = 10.0
) -> bool:
    """
    Configure HA config synchronization settings.
    
    Args:
        enabled: Enable config sync
        sync_on_startup: Sync configs when service starts
        sync_on_promotion: Push configs when becoming PRIMARY
        push_on_file_change: Auto-push when local configs change
        version_check_interval: Seconds between version checks (SECONDARY)
        primary_authority: Only PRIMARY can push changes
        sync_timeout: Timeout for sync operations in seconds
        
    Returns:
        True if successful
    """
    from ..ha.sync import ConfigSyncConfig
    from ..ha.sync.manager import save_sync_config
    
    try:
        config = ConfigSyncConfig(
            enabled=enabled,
            sync_on_startup=sync_on_startup,
            sync_on_promotion=sync_on_promotion,
            push_on_file_change=push_on_file_change,
            version_check_interval=version_check_interval,
            primary_authority=primary_authority,
            sync_timeout=sync_timeout,
        )
        
        if save_sync_config(config):
            print("Config sync settings saved:")
            print(f"  Enabled: {enabled}")
            print(f"  Sync on startup: {sync_on_startup}")
            print(f"  Sync on promotion: {sync_on_promotion}")
            print(f"  Push on file change: {push_on_file_change}")
            print(f"  Version check interval: {version_check_interval}s")
            print(f"  Primary authority: {primary_authority}")
            print(f"  Sync timeout: {sync_timeout}s")
            return True
        else:
            print("Failed to save config sync settings")
            return False
            
    except Exception as e:
        print(f"Error configuring sync: {e}")
        return False


def enable_sync() -> bool:
    """Enable config synchronization."""
    from ..ha.sync.manager import load_sync_config, save_sync_config
    
    try:
        config = load_sync_config()
        config.enabled = True
        
        if save_sync_config(config):
            print("Config sync ENABLED")
            print("Restart the service for changes to take effect")
            return True
        else:
            print("Failed to enable config sync")
            return False
            
    except Exception as e:
        print(f"Error enabling sync: {e}")
        return False


def disable_sync() -> bool:
    """Disable config synchronization."""
    from ..ha.sync.manager import load_sync_config, save_sync_config
    
    try:
        config = load_sync_config()
        config.enabled = False
        
        if save_sync_config(config):
            print("Config sync DISABLED")
            print("Restart the service for changes to take effect")
            return True
        else:
            print("Failed to disable config sync")
            return False
            
    except Exception as e:
        print(f"Error disabling sync: {e}")
        return False


def show_sync_status() -> bool:
    """
    Show config sync status.
    
    Returns:
        True if successful
    """
    from ..control import ControlSocket
    from ..ha.sync.manager import load_sync_config, LOCAL_ONLY_CONFIGS
    from ..ha.sync import SyncedConfigType
    
    try:
        # Load static config
        config = load_sync_config()
        
        print("=" * 70)
        print("Config Sync Status")
        print("=" * 70)
        
        print(f"\nConfiguration:")
        print(f"  Enabled: {config.enabled}")
        print(f"  Sync on startup: {config.sync_on_startup}")
        print(f"  Sync on promotion: {config.sync_on_promotion}")
        print(f"  Push on file change: {config.push_on_file_change}")
        print(f"  Version check interval: {config.version_check_interval}s")
        print(f"  Primary authority: {config.primary_authority}")
        
        # Try to get live status from daemon
        try:
            response = ControlSocket.send_command('sync_status')
            if response.get('status') == ControlSocket.SUCCESS:
                sync_status = response.get('data', {})
                
                print(f"\nRuntime Status:")
                print(f"  HA State: {sync_status.get('ha_state', 'unknown')}")
                print(f"  Instance: {sync_status.get('instance_id', 'unknown')}")
                
                stats = sync_status.get('stats', {})
                print(f"\nStatistics:")
                print(f"  Pushes sent: {stats.get('pushes_sent', 0)}")
                print(f"  Pushes received: {stats.get('pushes_received', 0)}")
                print(f"  Sync requests: {stats.get('sync_requests', 0)}")
                print(f"  Sync responses: {stats.get('sync_responses', 0)}")
                print(f"  Conflicts: {stats.get('conflicts_detected', 0)}")
                print(f"  Errors: {stats.get('errors', 0)}")
                
                if stats.get('last_sync_time'):
                    import time
                    elapsed = time.time() - stats['last_sync_time']
                    print(f"  Last sync: {elapsed:.1f}s ago")
                
                if stats.get('last_error'):
                    print(f"  Last error: {stats['last_error']}")
                
                # Version info
                local_versions = sync_status.get('local_versions', {})
                peer_versions = sync_status.get('peer_versions', {})
                
                if local_versions or peer_versions:
                    print(f"\nConfig Versions:")
                    print(f"  {'Config':<30} {'Local':<12} {'Peer':<12} {'Status'}")
                    print(f"  {'-'*30} {'-'*12} {'-'*12} {'-'*10}")
                    
                    for ct in SyncedConfigType.all_types():
                        local = local_versions.get(ct.value, {})
                        peer = peer_versions.get(ct.value, {})
                        
                        local_cs = local.get('checksum', '')[:8] if local else '-'
                        peer_cs = peer.get('checksum', '')[:8] if peer else '-'
                        
                        if local and peer:
                            if local.get('checksum') == peer.get('checksum'):
                                status = "✓ In sync"
                            else:
                                status = "⚠ Mismatch"
                        elif local:
                            status = "Local only"
                        elif peer:
                            status = "Peer only"
                        else:
                            status = "-"
                        
                        print(f"  {ct.value:<30} {local_cs:<12} {peer_cs:<12} {status}")
                        
        except ConnectionRefusedError:
            print(f"\n⚠️  Daemon not running - showing static config only")
        except Exception as e:
            print(f"\n⚠️  Could not get runtime status: {e}")
        
        print(f"\nSynced Config Types:")
        for ct in SyncedConfigType.all_types():
            print(f"  • {ct.filename}")
        
        print(f"\nLocal-Only Configs (NOT synced):")
        for cfg in sorted(LOCAL_ONLY_CONFIGS):
            print(f"  • {cfg}")
        
        print("=" * 70)
        return True
        
    except Exception as e:
        print(f"Error showing sync status: {e}")
        return False


def sync_push(config_type: Optional[str] = None, force: bool = False) -> bool:
    """
    Push config(s) to peer.
    
    Args:
        config_type: Specific config to push, or None for all
        force: Push even if not PRIMARY
        
    Returns:
        True if successful
    """
    from ..control import ControlSocket
    
    try:
        try:
            cmd_data = {'force': force}
            if config_type:
                cmd_data['config_type'] = config_type
            
            response = ControlSocket.send_command('sync_push', cmd_data)
            
            if response.get('status') == ControlSocket.SUCCESS:
                results = response.get('data', {})
                print("Config push results:")
                for cfg, success in results.items():
                    status = "✓" if success else "✗"
                    print(f"  {status} {cfg}")
                return all(results.values()) if results else True
            else:
                print(f"Push failed: {response.get('error')}")
                return False
                
        except ConnectionRefusedError:
            print("❌ Daemon not running")
            return False
            
    except Exception as e:
        print(f"Error pushing config: {e}")
        return False


def sync_pull(config_type: Optional[str] = None, force: bool = False) -> bool:
    """
    Pull config(s) from peer.
    
    Args:
        config_type: Specific config to pull, or None for all
        force: Pull even if PRIMARY
        
    Returns:
        True if successful
    """
    from ..control import ControlSocket
    
    try:
        try:
            cmd_data = {'force': force}
            if config_type:
                cmd_data['config_type'] = config_type
            
            response = ControlSocket.send_command('sync_pull', cmd_data)
            
            if response.get('status') == ControlSocket.SUCCESS:
                print("Config pull successful")
                return True
            else:
                print(f"Pull failed: {response.get('error')}")
                return False
                
        except ConnectionRefusedError:
            print("❌ Daemon not running")
            return False
            
    except Exception as e:
        print(f"Error pulling config: {e}")
        return False


def sync_diff() -> bool:
    """
    Show differences between local and peer configs.
    
    Returns:
        True if successful
    """
    from ..control import ControlSocket
    from ..ha.sync import SyncedConfigType
    
    try:
        try:
            response = ControlSocket.send_command('sync_status')
            
            if response.get('status') != ControlSocket.SUCCESS:
                print(f"Failed to get sync status: {response.get('error')}")
                return False
            
            sync_status = response.get('data', {})
            local_versions = sync_status.get('local_versions', {})
            peer_versions = sync_status.get('peer_versions', {})
            
            print("=" * 70)
            print("Config Sync Differences")
            print("=" * 70)
            
            differences = []
            in_sync = []
            local_only = []
            peer_only = []
            
            for ct in SyncedConfigType.all_types():
                local = local_versions.get(ct.value, {})
                peer = peer_versions.get(ct.value, {})
                
                if local and peer:
                    if local.get('checksum') != peer.get('checksum'):
                        differences.append(ct.value)
                    else:
                        in_sync.append(ct.value)
                elif local:
                    local_only.append(ct.value)
                elif peer:
                    peer_only.append(ct.value)
            
            if differences:
                print(f"\n⚠️  Configs with DIFFERENCES (need sync):")
                for cfg in differences:
                    local_cs = local_versions.get(cfg, {}).get('checksum', '')[:8]
                    peer_cs = peer_versions.get(cfg, {}).get('checksum', '')[:8]
                    print(f"  • {cfg}")
                    print(f"      Local:  {local_cs}...")
                    print(f"      Peer:   {peer_cs}...")
            
            if in_sync:
                print(f"\n✓ Configs IN SYNC:")
                for cfg in in_sync:
                    print(f"  • {cfg}")
            
            if local_only:
                print(f"\n📁 LOCAL ONLY (not on peer):")
                for cfg in local_only:
                    print(f"  • {cfg}")
            
            if peer_only:
                print(f"\n📥 PEER ONLY (not local):")
                for cfg in peer_only:
                    print(f"  • {cfg}")
            
            if not any([differences, in_sync, local_only, peer_only]):
                print("\n  No version information available")
                print("  Run sync or wait for version check")
            
            print("=" * 70)
            
            if differences:
                ha_state = sync_status.get('ha_state', 'unknown')
                print(f"\nCurrent HA state: {ha_state}")
                if ha_state == 'primary':
                    print("To sync: python trapninja.py --sync-push")
                else:
                    print("To sync: python trapninja.py --sync-pull")
            
            return True
            
        except ConnectionRefusedError:
            print("❌ Daemon not running")
            return False
            
    except Exception as e:
        print(f"Error showing diff: {e}")
        return False


def show_sync_help() -> bool:
    """Show config sync help information."""
    from ..ha.sync import SyncedConfigType, LOCAL_ONLY_CONFIGS
    
    print("""
╔════════════════════════════════════════════════════════════════════╗
║           TrapNinja Config Synchronization Commands                ║
╚════════════════════════════════════════════════════════════════════╝

OVERVIEW:
─────────

Config sync keeps shared configurations synchronized between HA nodes.
The PRIMARY node is the source of truth and pushes changes to SECONDARY.

SETUP:
──────

  Enable config sync:
    python trapninja.py --enable-sync
    
  Configure sync settings:
    python trapninja.py --configure-sync \\
      --sync-on-startup \\
      --push-on-file-change \\
      --version-check-interval 30
    
  Disable config sync:
    python trapninja.py --disable-sync


STATUS & MONITORING:
────────────────────

  Show sync status:
    python trapninja.py --sync-status
    
  Show config differences:
    python trapninja.py --sync-diff


MANUAL SYNC OPERATIONS:
───────────────────────

  Push all configs to peer (PRIMARY only):
    python trapninja.py --sync-push
    
  Push specific config:
    python trapninja.py --sync-push --config destinations
    
  Pull all configs from peer (SECONDARY):
    python trapninja.py --sync-pull
    
  Force push (even if not PRIMARY):
    python trapninja.py --sync-push --force


SYNCED CONFIGURATIONS:
──────────────────────
""")
    for ct in SyncedConfigType.all_types():
        print(f"  • {ct.filename:<35} ← Synced")
    
    print("""

LOCAL-ONLY CONFIGURATIONS (NOT synced):
───────────────────────────────────────
""")
    for cfg in sorted(LOCAL_ONLY_CONFIGS):
        print(f"  • {cfg:<35} ← Local only")
    
    print("""

HOW IT WORKS:
─────────────

  1. PRIMARY monitors local config files for changes
  2. When a synced config changes, PRIMARY pushes to SECONDARY
  3. SECONDARY periodically checks versions with PRIMARY
  4. If versions differ, SECONDARY pulls updated configs
  5. On failover, new PRIMARY pushes its configs

CONFLICT RESOLUTION:
────────────────────

  • PRIMARY is always authoritative (when primary_authority=true)
  • SECONDARY cannot push to PRIMARY
  • On split-brain, sync is paused until resolved
  • Manual --force flag overrides authority check

BEST PRACTICES:
───────────────

  ✓ Always make config changes on PRIMARY node
  ✓ Use --sync-status to verify sync state
  ✓ After failover, check configs are in sync
  ✓ Keep ha_config.json different per node (not synced)

═══════════════════════════════════════════════════════════════════════
""")
    return True
