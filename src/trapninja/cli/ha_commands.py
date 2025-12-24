#!/usr/bin/env python3
"""
TrapNinja High Availability Commands Module - IMPROVED VERSION

New commands:
- promote: Manually promote to PRIMARY
- demote: Manually demote to SECONDARY  
- status: Enhanced status display
"""

from typing import Optional
from .validation import InputValidator


def configure_ha(mode: str, peer_host: str, priority: int = 100, 
                 peer_port: int = 8162, listen_port: int = 8162,
                 auto_failback: bool = False) -> bool:
    """
    Configure High Availability settings

    Args:
        mode: "primary" or "secondary"
        peer_host: IP address of peer server
        priority: Priority value (higher = preferred as primary)
        peer_port: Port to connect to peer
        listen_port: Port to listen for peer connections
        auto_failback: Enable automatic failback when Primary recovers

    Returns:
        True if successful, False otherwise
    """
    from ..ha import load_ha_config, save_ha_config

    try:
        if mode not in ["primary", "secondary"]:
            print("Mode must be 'primary' or 'secondary'")
            return False

        valid_peer_host = InputValidator.validate_ip(peer_host)
        if not valid_peer_host:
            print(f"Invalid peer host IP: {peer_host}")
            return False

        valid_peer_port = InputValidator.validate_port(peer_port)
        valid_listen_port = InputValidator.validate_port(listen_port)

        if not valid_peer_port or not valid_listen_port:
            print("Invalid port numbers")
            return False

        if not (1 <= priority <= 1000):
            print("Priority must be between 1 and 1000")
            return False

        ha_config = load_ha_config()

        ha_config.enabled = True
        ha_config.mode = mode
        ha_config.peer_host = valid_peer_host
        ha_config.peer_port = valid_peer_port
        ha_config.listen_port = valid_listen_port
        ha_config.priority = priority
        ha_config.auto_failback = auto_failback

        if save_ha_config(ha_config):
            print(f"HA configured: {mode} mode, peer {valid_peer_host}:{valid_peer_port}")
            print(f"  Priority: {priority}")
            print(f"  Auto-failback: {auto_failback}")
            return True
        else:
            print("Failed to save HA configuration")
            return False

    except Exception as e:
        print(f"Error configuring HA: {e}")
        return False


def disable_ha() -> bool:
    """
    Disable High Availability

    Returns:
        True if successful, False otherwise
    """
    from ..ha import load_ha_config, save_ha_config

    try:
        ha_config = load_ha_config()
        ha_config.enabled = False

        if save_ha_config(ha_config):
            print("HA disabled")
            return True
        else:
            print("Failed to save HA configuration")
            return False

    except Exception as e:
        print(f"Error disabling HA: {e}")
        return False


def show_ha_status() -> bool:
    """
    Show detailed HA status with enhanced information

    Returns:
        True if successful, False otherwise
    """
    from ..ha import load_ha_config
    from ..control import ControlSocket

    try:
        ha_config = load_ha_config()
        
        # Try to get status from running daemon via control socket
        ha_status = {"enabled": False}
        daemon_running = False
        daemon_error_msg = None
        
        try:
            response = ControlSocket.send_command('ha_status')
            if response.get('status') == ControlSocket.SUCCESS:
                ha_status = response.get('data', {"enabled": False})
                daemon_running = True
        except ConnectionRefusedError:
            # Daemon not running OR running old code without control socket
            daemon_error_msg = "Control socket not found - daemon may need restart with updated code"
        except Exception as e:
            daemon_error_msg = f"Could not connect to daemon: {e}"

        print("=" * 70)
        print("High Availability Status")
        print("=" * 70)
        print(f"  Enabled: {ha_config.enabled}")

        if ha_config.enabled:
            print(f"\nConfiguration:")
            print(f"  Configured Mode: {ha_config.mode.upper()}")
            print(f"  Peer: {ha_config.peer_host}:{ha_config.peer_port}")
            print(f"  Listen Port: {ha_config.listen_port}")
            print(f"  Priority: {ha_config.priority}")
            print(f"  Auto-failback: {ha_config.auto_failback}")
            print(f"  Heartbeat Interval: {ha_config.heartbeat_interval}s")
            print(f"  Heartbeat Timeout: {ha_config.heartbeat_timeout}s")
            print(f"  Failover Delay: {ha_config.failover_delay}s")

            if daemon_running and ha_status.get('enabled', False):
                print(f"\nCurrent Status:")
                
                # Get state and forwarding status
                state = ha_status.get('state', 'unknown')
                is_forwarding = ha_status.get('is_forwarding', False)
                
                # Determine acting role based on actual state
                if state == "primary":
                    acting_role = "PRIMARY"
                elif state == "secondary":
                    acting_role = "SECONDARY"
                elif state == "failover":
                    acting_role = "FAILOVER (→ PRIMARY)"
                elif state == "split_brain":
                    acting_role = "SPLIT-BRAIN"
                elif state == "standalone":
                    acting_role = "STANDALONE"
                else:
                    acting_role = state.upper()
                
                configured_mode = ha_config.mode.upper()
                
                # Check if there's a mismatch (failover/demotion scenario)
                role_mismatch = False
                if state in ["primary", "secondary"]:
                    role_mismatch = (configured_mode != acting_role)
                
                # Choose appropriate status icon
                if state == "primary" and is_forwarding:
                    status_icon = "🟢"  # Green - active primary
                elif state == "secondary":
                    status_icon = "🔴"  # Red - standby secondary
                elif state == "failover":
                    status_icon = "🟡"  # Yellow - transitioning
                elif state == "split_brain":
                    status_icon = "⚠️ "  # Warning - split brain
                else:
                    status_icon = "🟡"  # Yellow - other states
                
                # Display configured mode vs acting role
                print(f"  Configured Mode: {configured_mode}")
                
                if role_mismatch:
                    # Highlight the mismatch
                    print(f"  {status_icon} Acting As: {acting_role} ⚠️  (Role Mismatch)")
                else:
                    print(f"  {status_icon} Acting As: {acting_role}")
                
                print(f"  Forwarding: {'ENABLED' if is_forwarding else 'DISABLED'}")
                print(f"  Uptime: {ha_status.get('uptime', 0):.1f}s")
                
                # Show explanation for role mismatch
                if role_mismatch:
                    print(f"\n  ℹ️  Role Mismatch Explanation:")
                    if configured_mode == "PRIMARY" and acting_role == "SECONDARY":
                        print(f"     Configured as PRIMARY but acting as SECONDARY")
                        print(f"     Possible reasons: Manual demotion, peer took over, or automatic failover")
                        print(f"     Action: Use --promote to reclaim PRIMARY role")
                    elif configured_mode == "SECONDARY" and acting_role == "PRIMARY":
                        print(f"     Configured as SECONDARY but acting as PRIMARY")
                        print(f"     Possible reasons: Peer failure triggered automatic failover")
                        print(f"     Action: This is normal - wait for peer recovery or use --demote")
                
                if ha_status.get('manual_override'):
                    print(f"  ⚠️  Manual Override Active")

                print(f"\nPeer Status:")
                peer_connected = ha_status.get('peer_connected', False)
                print(f"  Connected: {peer_connected}")

                if peer_connected:
                    print(f"  State: {ha_status.get('peer_state', 'unknown')}")
                    print(f"  Priority: {ha_status.get('peer_priority', 0)}")
                    print(f"  Uptime: {ha_status.get('peer_uptime', 0):.1f}s")
                    
                    # Calculate time since last seen
                    last_seen = ha_status.get('peer_last_seen')
                    if last_seen:
                        import time
                        seconds_ago = time.time() - last_seen
                        print(f"  Last Seen: {seconds_ago:.1f}s ago")
                else:
                    print(f"  ⚠️  Peer not responding")

                if ha_status.get('split_brain_detected'):
                    print(f"\n❌ SPLIT-BRAIN DETECTED!")
                    print(f"   Both instances think they are PRIMARY")
                    print(f"   Configured Mode: {configured_mode}, Acting As: {acting_role}")
                    print(f"   This will auto-resolve based on priority ({ha_config.priority})")
                    print(f"   Lower priority node should automatically yield to higher priority")
                    
                # Suggest actions
                print(f"\nAvailable Actions:")
                if state == "secondary":
                    print(f"  • To promote to PRIMARY: python trapninja.py --promote")
                    print(f"  • To force promotion:    python trapninja.py --promote --force")
                elif state == "primary":
                    print(f"  • To demote to SECONDARY: python trapninja.py --demote")
                    print(f"  • To force failover:      python trapninja.py --force-failover")
            elif not daemon_running:
                # Daemon not providing live status
                print(f"\n⚠️  LIVE STATUS UNAVAILABLE")
                print(f"  The daemon is not providing runtime status information.")
                print(f"  ")
                if daemon_error_msg:
                    print(f"  Reason: {daemon_error_msg}")
                print(f"  ")
                print(f"  This usually means:")
                print(f"    1. The daemon is not running, OR")
                print(f"    2. The daemon is running OLD code (before control socket was added)")
                print(f"  ")
                print(f"  To fix:")
                print(f"    • Check if daemon is running: python trapninja.py --status")
                print(f"    • If running, restart with new code: sudo python3.9 -O trapninja.py --restart")
                print(f"    • Check control socket exists: ls -la /tmp/trapninja_control.sock")
                print(f"  ")
                print(f"  Without live status, you'll only see static configuration above.")
                print(f"  The enhanced 'Acting As' display requires the daemon to be running with updated code.")
        else:
            print("\nHA is disabled - running in standalone mode")
            print("To enable HA: python trapninja.py --configure-ha --ha-mode primary --ha-peer-host <ip>")

        print("=" * 70)
        return True

    except Exception as e:
        print(f"Error showing HA status: {e}")
        return False


def force_failover() -> bool:
    """
    Force failover for maintenance purposes

    Returns:
        True if successful, False otherwise
    """
    from ..control import ControlSocket

    try:
        try:
            response = ControlSocket.send_command('ha_force_failover')
        except ConnectionRefusedError:
            print("❌ HA cluster not running")
            return False
        except Exception as e:
            print(f"❌ Error communicating with daemon: {e}")
            return False
        
        if response.get('status') == ControlSocket.SUCCESS:
            print("Failover initiated - yielding PRIMARY role")
            print("This instance will become SECONDARY")
            print("The peer should detect this and become PRIMARY")
            return True
        else:
            print(f"❌ Error forcing failover: {response.get('error')}")
            return False
    except Exception as e:
        print(f"Error forcing failover: {e}")
        return False


# ============================================================================
# NEW: Manual promotion/demotion commands
# ============================================================================

def promote_to_primary(force: bool = False) -> bool:
    """
    Manually promote this instance to PRIMARY
    
    Args:
        force: If True, become PRIMARY immediately without peer coordination
        
    Returns:
        True if successful, False otherwise
    """
    from ..control import ControlSocket
    
    try:
        # Use control socket to communicate with running daemon
        try:
            response = ControlSocket.send_command('ha_status')
        except ConnectionRefusedError:
            print("❌ HA cluster not running")
            print("   Start the service first: python trapninja.py --start")
            return False
        except Exception as e:
            print(f"❌ Error communicating with daemon: {e}")
            return False
        
        if response.get('status') != ControlSocket.SUCCESS:
            print("❌ Error getting HA status:", response.get('error'))
            return False
        
        ha_status = response.get('data', {})
        if not ha_status:
            print("❌ HA not initialized in daemon")
            return False
        
        current_state = ha_status.get('state', 'unknown')
        
        print("=" * 70)
        print("Manual Promotion to PRIMARY")
        print("=" * 70)
        
        if current_state == "primary":
            print("✓ Already PRIMARY - no action needed")
            print(f"  Forwarding: {'ENABLED' if ha_status.get('is_forwarding') else 'DISABLED'}")
            return True
        
        if force:
            print("⚠️  FORCE MODE - will become PRIMARY immediately")
            print("   This may cause brief split-brain until peer yields")
            
            # Confirm force operation
            response = input("\n   Continue with FORCE promotion? (yes/no): ")
            if response.lower() != 'yes':
                print("   Promotion cancelled")
                return False
        else:
            print("Graceful promotion - will coordinate with peer")
            print("This will:")
            print("  1. Send CLAIM_PRIMARY message to peer")
            print("  2. Wait for failover delay (2s)")
            print("  3. Become PRIMARY if peer yields")
        
        # Send promote command via control socket
        try:
            promote_response = ControlSocket.send_command('ha_promote', {'force': force})
        except Exception as e:
            print(f"❌ Error sending promote command: {e}")
            return False
        
        success = promote_response.get('status') == ControlSocket.SUCCESS
        
        if success:
            print("\n✓ Promotion initiated successfully")
            print("  Check status: python trapninja.py --ha-status")
        else:
            print("\n❌ Promotion failed")
            
        print("=" * 70)
        return success
        
    except Exception as e:
        print(f"❌ Error promoting to PRIMARY: {e}")
        return False


def demote_to_secondary() -> bool:
    """
    Manually demote this instance to SECONDARY
    
    Returns:
        True if successful, False otherwise
    """
    from ..control import ControlSocket
    
    try:
        # Use control socket to communicate with running daemon
        try:
            response = ControlSocket.send_command('ha_status')
        except ConnectionRefusedError:
            print("❌ HA cluster not running")
            print("   Start the service first: python trapninja.py --start")
            return False
        except Exception as e:
            print(f"❌ Error communicating with daemon: {e}")
            return False
        
        if response.get('status') != ControlSocket.SUCCESS:
            print("❌ Error getting HA status:", response.get('error'))
            return False
        
        ha_status = response.get('data', {})
        if not ha_status:
            print("❌ HA not initialized in daemon")
            return False
        
        current_state = ha_status.get('state', 'unknown')
        
        print("=" * 70)
        print("Manual Demotion to SECONDARY")
        print("=" * 70)
        
        if current_state == "secondary":
            print("✓ Already SECONDARY - no action needed")
            print(f"  Forwarding: DISABLED (as expected)")
            return True
        
        if current_state == "primary":
            print("Will demote from PRIMARY to SECONDARY")
            print("This will:")
            print("  1. Send YIELD_PRIMARY message to peer")
            print("  2. Disable trap forwarding")
            print("  3. Become SECONDARY")
            print("  4. Peer should become PRIMARY")
            
            # Confirm demotion
            response = input("\n   Continue with demotion? (yes/no): ")
            if response.lower() != 'yes':
                print("   Demotion cancelled")
                return False
        
        # Send demote command via control socket
        try:
            demote_response = ControlSocket.send_command('ha_demote')
        except Exception as e:
            print(f"❌ Error sending demote command: {e}")
            return False
        
        success = demote_response.get('status') == ControlSocket.SUCCESS
        
        if success:
            print("\n✓ Demotion successful")
            print("  This instance is now SECONDARY")
            print("  Trap forwarding is DISABLED")
            print("  Check peer status: python trapninja.py --ha-status")
        else:
            print(f"\n❌ Demotion failed - current state: {current_state}")
            
        print("=" * 70)
        return success
        
    except Exception as e:
        print(f"❌ Error demoting to SECONDARY: {e}")
        return False


def show_ha_help() -> bool:
    """
    Show comprehensive HA help information
    
    Returns:
        True always
    """
    print("""
╔════════════════════════════════════════════════════════════════════╗
║              TrapNinja High Availability Commands                  ║
╚════════════════════════════════════════════════════════════════════╝

SETUP COMMANDS:
───────────────

  Configure Primary Server:
    python trapninja.py --configure-ha \\
      --ha-mode primary \\
      --ha-peer-host 192.168.1.101 \\
      --ha-priority 150

  Configure Secondary Server:
    python trapninja.py --configure-ha \\
      --ha-mode secondary \\
      --ha-peer-host 192.168.1.100 \\
      --ha-priority 100

  Disable HA:
    python trapninja.py --disable-ha


STATUS COMMANDS:
────────────────

  Check HA Status:
    python trapninja.py --ha-status

  Check Service Status:
    python trapninja.py --status


MANUAL CONTROL COMMANDS (NEW!):
────────────────────────────────

  Promote to PRIMARY (graceful):
    python trapninja.py --promote
    
    • Coordinates with peer
    • Waits for failover delay
    • Safe for production
    
  Promote to PRIMARY (forced):
    python trapninja.py --promote --force
    
    • Immediate promotion
    • May cause brief split-brain
    • Use only when peer is down
    
  Demote to SECONDARY:
    python trapninja.py --demote
    
    • Yields PRIMARY role
    • Disables forwarding
    • Peer should become PRIMARY
    
  Force Failover:
    python trapninja.py --force-failover
    
    • Same as demote
    • For maintenance/testing


COMMON SCENARIOS:
─────────────────

  1. Initial Setup:
     • Configure both servers
     • Start both services
     • Primary should be forwarding
     • Secondary should be standby

  2. Primary Fails:
     • Secondary auto-promotes (3s timeout)
     • Secondary becomes PRIMARY
     • Secondary starts forwarding

  3. Primary Recovers (AUTO):
     • Primary restarts
     • Detects Secondary is PRIMARY
     • Becomes SECONDARY automatically
     • No split-brain!

  4. Primary Recovers (MANUAL FAILBACK):
     • Primary restarts as SECONDARY
     • Admin runs: python trapninja.py --promote
     • Primary reclaims PRIMARY role
     • Secondary becomes SECONDARY

  5. Split-Brain Detected:
     • Auto-resolves by priority
     • Higher priority wins
     • Lower priority yields

  6. Forced Takeover:
     On Secondary:
     python trapninja.py --promote --force
     
     Use when:
     • Primary is definitely down
     • Need immediate failover
     • Split-brain can be tolerated

  7. Planned Maintenance:
     On Primary:
     python trapninja.py --demote
     
     Then stop service safely


TROUBLESHOOTING:
────────────────

  Check both nodes are running:
    ssh primary "python trapninja.py --status"
    ssh secondary "python trapninja.py --status"

  Check connectivity:
    nc -zv <peer_ip> 8162

  View logs:
    tail -f /var/log/trapninja/trapninja.log | grep HA

  Force state reset (if stuck):
    python trapninja.py --stop
    python trapninja.py --start


BEST PRACTICES:
───────────────

  ✓ Use different priorities (Primary: 150, Secondary: 100)
  ✓ Test failover before production
  ✓ Monitor both nodes
  ✓ Use firewall rules to restrict HA port
  ✓ Keep auto_failback=False for manual control
  ✓ Document your failover procedures

  ✗ Don't use same priority on both nodes
  ✗ Don't promote both nodes simultaneously
  ✗ Don't disable split-brain detection
  ✗ Don't forget to test recovery scenarios


CONFIGURATION SYNCHRONIZATION (NEW!):
─────────────────────────────────────

  The HA cluster can automatically synchronize shared configuration
  between Primary and Secondary nodes without requiring Redis.
  
  Synchronized configs:
    • destinations.json
    • blocked_ips.json
    • blocked_traps.json
    • redirected_ips.json
    • redirected_oids.json
    • redirected_destinations.json
  
  NOT synchronized (server-specific):
    • ha_config.json
    • listen_ports.json
    • cache_config.json
  
  Commands:
    python trapninja.py --config-sync-status   # Show sync status
    python trapninja.py --config-sync          # Trigger manual sync
    python trapninja.py --config-sync --force  # Force sync (ignore checksums)
  
  How it works:
    • Primary is authoritative for shared config
    • Changes on Primary are automatically pushed to Secondary
    • Config checksums are included in heartbeats
    • Mismatch triggers automatic sync after 3 heartbeats
    • Manual sync available via CLI

═══════════════════════════════════════════════════════════════════════

For more information:
  • Full docs: /opt/trapninja/config/HA_README.md
  • Architecture: /opt/trapninja/HA_ARCHITECTURE.md
""")
    return True


# ============================================================================
# NEW: Configuration Synchronization Commands
# ============================================================================

def show_config_sync_status() -> bool:
    """
    Show configuration synchronization status.
    
    Returns:
        True if successful, False otherwise
    """
    from ..control import ControlSocket
    
    try:
        # Get HA status which includes config sync status
        try:
            response = ControlSocket.send_command('ha_status')
        except ConnectionRefusedError:
            print("❌ HA cluster not running")
            return False
        except Exception as e:
            print(f"❌ Error communicating with daemon: {e}")
            return False
        
        if response.get('status') != ControlSocket.SUCCESS:
            print("❌ Error getting status:", response.get('error'))
            return False
        
        ha_status = response.get('data', {})
        config_sync = ha_status.get('config_sync')
        
        print("=" * 70)
        print("Configuration Synchronization Status")
        print("=" * 70)
        
        if not config_sync:
            print("\n  Config sync is not enabled.")
            print("  To enable, restart with config_dir parameter.")
            return True
        
        enabled = config_sync.get('enabled', False)
        is_primary = config_sync.get('is_primary', False)
        local_checksum = config_sync.get('local_checksum', 'N/A')
        remote_checksum = config_sync.get('remote_checksum', 'N/A')
        checksums_match = config_sync.get('checksums_match', False)
        
        print(f"\n  Enabled: {enabled}")
        print(f"  Role: {'PRIMARY (authoritative)' if is_primary else 'SECONDARY (receiver)'}")
        
        print(f"\n  Checksums:")
        print(f"    Local:  {local_checksum[:16]}..." if local_checksum != 'N/A' else "    Local:  N/A")
        print(f"    Remote: {remote_checksum[:16]}..." if remote_checksum and remote_checksum != 'N/A' else "    Remote: N/A")
        
        if checksums_match:
            print(f"\n  ✓ Configurations are IN SYNC")
        else:
            print(f"\n  ⚠️  Configuration MISMATCH detected")
            print(f"      Run 'python trapninja.py --config-sync' to synchronize")
        
        mismatch_count = config_sync.get('mismatch_count', 0)
        if mismatch_count > 0:
            print(f"\n  Mismatch count: {mismatch_count}")
            print(f"  (Auto-sync triggers at 3 mismatches)")
        
        last_sync = config_sync.get('last_sync_time')
        if last_sync:
            import time
            seconds_ago = time.time() - last_sync
            if seconds_ago < 60:
                print(f"\n  Last sync: {seconds_ago:.1f}s ago")
            elif seconds_ago < 3600:
                print(f"\n  Last sync: {seconds_ago/60:.1f} minutes ago")
            else:
                print(f"\n  Last sync: {seconds_ago/3600:.1f} hours ago")
        
        last_result = config_sync.get('last_sync_result')
        if last_result:
            print(f"\n  Last sync result:")
            print(f"    Success: {last_result.get('success', False)}")
            print(f"    Mode: {last_result.get('mode', 'unknown')}")
            print(f"    Message: {last_result.get('message', 'N/A')}")
            files = last_result.get('files_synced', [])
            if files:
                print(f"    Files synced: {len(files)}")
        
        print(f"\n  Tracked configuration files:")
        for f in config_sync.get('files_tracked', []):
            print(f"    • {f}")
        
        print("=" * 70)
        return True
        
    except Exception as e:
        print(f"❌ Error showing config sync status: {e}")
        return False


def trigger_config_sync(force: bool = False) -> bool:
    """
    Manually trigger configuration synchronization.
    
    Args:
        force: If True, force sync regardless of checksums
    
    Returns:
        True if successful, False otherwise
    """
    from ..control import ControlSocket
    
    try:
        print("=" * 70)
        print("Configuration Synchronization")
        print("=" * 70)
        
        # Get current status first
        try:
            response = ControlSocket.send_command('ha_status')
        except ConnectionRefusedError:
            print("\n❌ HA cluster not running")
            return False
        except Exception as e:
            print(f"\n❌ Error communicating with daemon: {e}")
            return False
        
        if response.get('status') != ControlSocket.SUCCESS:
            print("\n❌ Error getting status:", response.get('error'))
            return False
        
        ha_status = response.get('data', {})
        config_sync_status = ha_status.get('config_sync')
        
        if not config_sync_status:
            print("\n❌ Config sync is not available")
            return False
        
        is_primary = config_sync_status.get('is_primary', False)
        
        print(f"\n  Role: {'PRIMARY' if is_primary else 'SECONDARY'}")
        print(f"  Mode: {'PUSH to peer' if is_primary else 'PULL from peer'}")
        print(f"  Force: {force}")
        
        if force:
            print("\n  ⚠️  FORCE mode - will sync regardless of checksums")
        
        # Trigger sync via control socket
        try:
            sync_response = ControlSocket.send_command(
                'config_sync',
                {'force': force}
            )
        except Exception as e:
            print(f"\n❌ Error triggering sync: {e}")
            return False
        
        if sync_response.get('status') == ControlSocket.SUCCESS:
            result = sync_response.get('data', {})
            success = result.get('success', False)
            message = result.get('message', 'Unknown')
            files = result.get('files_synced', [])
            
            if success:
                print(f"\n  ✓ Sync completed successfully")
                print(f"    {message}")
                if files:
                    print(f"\n    Files synchronized:")
                    for f in files:
                        print(f"      • {f}")
            else:
                print(f"\n  ⚠️  Sync completed with issues")
                print(f"    {message}")
            
            print("\n  Run '--config-sync-status' to verify synchronization")
            print("=" * 70)
            return success
        else:
            print(f"\n❌ Sync failed: {sync_response.get('error', 'Unknown error')}")
            print("=" * 70)
            return False
        
    except Exception as e:
        print(f"❌ Error during config sync: {e}")
        return False
