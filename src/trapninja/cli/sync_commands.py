#!/usr/bin/env python3
"""
TrapNinja Config Sync CLI Commands

CLI commands for managing HA configuration synchronization.

Author: TrapNinja Team
Version: 2.0.0
"""

import json
import os
from typing import Optional

from .validation import InputValidator


# Shared config files that get synchronized
SHARED_CONFIG_FILES = [
    "destinations.json",
    "blocked_ips.json",
    "blocked_traps.json",
    "redirected_ips.json",
    "redirected_oids.json",
    "redirected_destinations.json",
]

# Local-only configs that should NEVER be synced
LOCAL_ONLY_CONFIGS = [
    "ha_config.json",
    "cache_config.json",
    "listen_ports.json",
    "capture_config.json",
    "shadow_config.json",
    "stats_config.json",
    "sync_config.json",
]


def show_sync_status() -> bool:
    """
    Show config sync status.
    
    Returns:
        True if successful
    """
    from ..control import ControlSocket
    
    try:
        print("=" * 70)
        print("Config Sync Status")
        print("=" * 70)
        
        # Try to get live status from daemon
        try:
            response = ControlSocket.send_command('ha_status')
            if response.get('status') == ControlSocket.SUCCESS:
                ha_status = response.get('data', {})
                sync_status = ha_status.get('config_sync', {})
                
                if not sync_status:
                    print("\n⚠️  Config sync not available")
                    print("   HA may not be enabled or config_dir not set")
                else:
                    print(f"\nRuntime Status:")
                    print(f"  Is Primary: {sync_status.get('is_primary', 'unknown')}")
                    print(f"  Config Dir: {sync_status.get('config_dir', 'unknown')}")
                    print(f"  Peer: {sync_status.get('peer', 'unknown')}")
                    
                    local_cs = sync_status.get('local_checksum', '-')
                    remote_cs = sync_status.get('remote_checksum', '-')
                    checksums_match = sync_status.get('checksums_match')
                    
                    print(f"\nChecksums:")
                    print(f"  Local:  {local_cs}")
                    print(f"  Remote: {remote_cs}")
                    if checksums_match is True:
                        print(f"  Status: ✓ In sync")
                    elif checksums_match is False:
                        print(f"  Status: ⚠ Mismatch - sync needed")
                    else:
                        print(f"  Status: Unknown (peer not connected?)")
                    
                    stats = sync_status.get('stats', {})
                    if stats:
                        print(f"\nStatistics:")
                        print(f"  Pulls completed: {stats.get('pulls_completed', 0)}")
                        print(f"  Pushes completed: {stats.get('pushes_completed', 0)}")
                        print(f"  Pull failures: {stats.get('pull_failures', 0)}")
                        print(f"  Push failures: {stats.get('push_failures', 0)}")
                        
                        if stats.get('last_sync_time'):
                            import time
                            elapsed = time.time() - stats['last_sync_time']
                            print(f"  Last sync: {elapsed:.1f}s ago")
                        
                        if stats.get('last_error'):
                            print(f"  Last error: {stats['last_error']}")
                
                # Show HA state
                print(f"\nHA Status:")
                print(f"  State: {ha_status.get('state', 'unknown')}")
                print(f"  Forwarding: {ha_status.get('is_forwarding', 'unknown')}")
                print(f"  Peer Connected: {ha_status.get('peer_connected', 'unknown')}")
                        
        except ConnectionRefusedError:
            print(f"\n⚠️  Daemon not running")
            print("   Start TrapNinja to see runtime sync status")
        except Exception as e:
            print(f"\n⚠️  Could not get runtime status: {e}")
        
        print(f"\nSynced Config Types:")
        for cfg in SHARED_CONFIG_FILES:
            print(f"  • {cfg}")
        
        print(f"\nLocal-Only Configs (NOT synced):")
        for cfg in LOCAL_ONLY_CONFIGS:
            print(f"  • {cfg}")
        
        print("=" * 70)
        return True
        
    except Exception as e:
        print(f"Error showing sync status: {e}")
        return False


def sync_now(force: bool = False) -> bool:
    """
    Trigger immediate config sync based on HA role.
    
    PRIMARY nodes push to SECONDARY.
    SECONDARY nodes pull from PRIMARY.
    
    Args:
        force: Force sync even if checksums match
        
    Returns:
        True if successful
    """
    from ..control import ControlSocket
    
    try:
        try:
            response = ControlSocket.send_command('config_sync', {'force': force})
            
            if response.get('status') == ControlSocket.SUCCESS:
                result = response.get('data', {})
                success = result.get('success', False)
                message = result.get('message', '')
                direction = result.get('direction', '')
                
                if success:
                    print(f"✓ Config sync {direction} successful")
                    print(f"  {message}")
                else:
                    print(f"✗ Config sync failed")
                    print(f"  {message}")
                return success
            else:
                error = response.get('error', 'Unknown error')
                print(f"✗ Config sync failed: {error}")
                return False
                
        except ConnectionRefusedError:
            print("❌ Daemon not running")
            print("   Start TrapNinja first: python trapninja.py --start")
            return False
            
    except Exception as e:
        print(f"Error triggering sync: {e}")
        return False


def sync_push(force: bool = False) -> bool:
    """
    Push configs to peer (PRIMARY only).
    
    Args:
        force: Force push even if not PRIMARY
        
    Returns:
        True if successful
    """
    from ..control import ControlSocket
    
    try:
        try:
            response = ControlSocket.send_command('config_sync_push', {'force': force})
            
            if response.get('status') == ControlSocket.SUCCESS:
                result = response.get('data', {})
                if result.get('success'):
                    print("✓ Config push successful")
                    return True
                else:
                    print(f"✗ Config push failed: {result.get('message', 'Unknown error')}")
                    return False
            else:
                print(f"✗ Push failed: {response.get('error')}")
                return False
                
        except ConnectionRefusedError:
            print("❌ Daemon not running")
            return False
            
    except Exception as e:
        print(f"Error pushing config: {e}")
        return False


def sync_pull(force: bool = False) -> bool:
    """
    Pull configs from peer (SECONDARY only).
    
    Args:
        force: Force pull even if PRIMARY
        
    Returns:
        True if successful
    """
    from ..control import ControlSocket
    
    try:
        try:
            response = ControlSocket.send_command('config_sync_pull', {'force': force})
            
            if response.get('status') == ControlSocket.SUCCESS:
                result = response.get('data', {})
                if result.get('success'):
                    print("✓ Config pull successful")
                    return True
                else:
                    print(f"✗ Config pull failed: {result.get('message', 'Unknown error')}")
                    return False
            else:
                print(f"✗ Pull failed: {response.get('error')}")
                return False
                
        except ConnectionRefusedError:
            print("❌ Daemon not running")
            return False
            
    except Exception as e:
        print(f"Error pulling config: {e}")
        return False


def show_sync_help() -> bool:
    """Show config sync help information."""
    
    print("""
╔════════════════════════════════════════════════════════════════════╗
║           TrapNinja Config Synchronization Commands                ║
╚════════════════════════════════════════════════════════════════════╝

OVERVIEW:
─────────

Config sync keeps shared configurations synchronized between HA nodes.
The PRIMARY node is the source of truth and pushes changes to SECONDARY.

Config sync is AUTOMATIC when HA is enabled:
  • Secondary pulls configs from Primary on startup
  • Primary pushes changes to Secondary when files change
  • Checksums in heartbeats detect drift and trigger sync


STATUS & MONITORING:
────────────────────

  Show sync status:
    python trapninja.py --sync-status
    

MANUAL SYNC OPERATIONS:
───────────────────────

  Sync based on role (push if PRIMARY, pull if SECONDARY):
    python trapninja.py --ha-sync
    
  Force sync:
    python trapninja.py --ha-sync --force


SYNCED CONFIGURATIONS:
──────────────────────
""")
    for cfg in SHARED_CONFIG_FILES:
        print(f"  • {cfg:<40} ← Synced")
    
    print("""

LOCAL-ONLY CONFIGURATIONS (NOT synced):
───────────────────────────────────────
""")
    for cfg in LOCAL_ONLY_CONFIGS:
        print(f"  • {cfg:<40} ← Local only")
    
    print("""

HOW IT WORKS:
─────────────

  1. SECONDARY pulls all configs from PRIMARY on startup
  2. PRIMARY monitors local config files for changes (every 10s)
  3. When a synced config changes, PRIMARY pushes to SECONDARY
  4. Heartbeats include config checksums to detect drift
  5. If checksums differ 3+ times, SECONDARY pulls from PRIMARY
  6. On state change (becoming SECONDARY), pull is triggered

BEST PRACTICES:
───────────────

  ✓ Always make config changes on PRIMARY node
  ✓ Use --sync-status to verify sync state
  ✓ After failover, verify configs are in sync
  ✓ Keep ha_config.json different per node (it's not synced)

═══════════════════════════════════════════════════════════════════════
""")
    return True
