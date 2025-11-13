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
    from ..ha import load_ha_config, get_ha_cluster

    try:
        ha_config = load_ha_config()
        ha_cluster = get_ha_cluster()
        ha_status = ha_cluster.get_status() if ha_cluster else {"enabled": False}

        print("=" * 70)
        print("High Availability Status")
        print("=" * 70)
        print(f"  Enabled: {ha_config.enabled}")

        if ha_config.enabled:
            print(f"\nConfiguration:")
            print(f"  Mode: {ha_config.mode}")
            print(f"  Peer: {ha_config.peer_host}:{ha_config.peer_port}")
            print(f"  Listen Port: {ha_config.listen_port}")
            print(f"  Priority: {ha_config.priority}")
            print(f"  Auto-failback: {ha_config.auto_failback}")
            print(f"  Heartbeat Interval: {ha_config.heartbeat_interval}s")
            print(f"  Heartbeat Timeout: {ha_config.heartbeat_timeout}s")
            print(f"  Failover Delay: {ha_config.failover_delay}s")

            if ha_status.get('enabled', False):
                print(f"\nCurrent Status:")
                
                # Format state with color indicator
                state = ha_status.get('state', 'unknown')
                is_forwarding = ha_status.get('is_forwarding', False)
                
                status_icon = "🟢" if state == "primary" and is_forwarding else "🔴" if state == "secondary" else "🟡"
                print(f"  {status_icon} State: {state.upper()}")
                print(f"  Forwarding: {'ENABLED' if is_forwarding else 'DISABLED'}")
                print(f"  Uptime: {ha_status.get('uptime', 0):.1f}s")
                
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
                    print(f"   This will auto-resolve based on priority")
                    
                # Suggest actions
                print(f"\nAvailable Actions:")
                if state == "secondary":
                    print(f"  • To promote to PRIMARY: python trapninja.py --promote")
                    print(f"  • To force promotion:    python trapninja.py --promote --force")
                elif state == "primary":
                    print(f"  • To demote to SECONDARY: python trapninja.py --demote")
                    print(f"  • To force failover:      python trapninja.py --force-failover")
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
    from ..ha import get_ha_cluster

    try:
        ha_cluster = get_ha_cluster()
        if ha_cluster:
            ha_cluster.force_failover()
            print("Failover initiated - yielding PRIMARY role")
            print("This instance will become SECONDARY")
            print("The peer should detect this and become PRIMARY")
            return True
        else:
            print("HA cluster not running")
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
    from ..ha import get_ha_cluster
    
    try:
        ha_cluster = get_ha_cluster()
        if not ha_cluster:
            print("❌ HA cluster not running")
            print("   Start the service first: python trapninja.py --start")
            return False
        
        status = ha_cluster.get_status()
        current_state = status.get('state', 'unknown')
        
        print("=" * 70)
        print("Manual Promotion to PRIMARY")
        print("=" * 70)
        
        if current_state == "primary":
            print("✓ Already PRIMARY - no action needed")
            print(f"  Forwarding: {'ENABLED' if status.get('is_forwarding') else 'DISABLED'}")
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
        
        success = ha_cluster.promote_to_primary(force=force)
        
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
    from ..ha import get_ha_cluster
    
    try:
        ha_cluster = get_ha_cluster()
        if not ha_cluster:
            print("❌ HA cluster not running")
            print("   Start the service first: python trapninja.py --start")
            return False
        
        status = ha_cluster.get_status()
        current_state = status.get('state', 'unknown')
        
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
        
        success = ha_cluster.demote_to_secondary()
        
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

═══════════════════════════════════════════════════════════════════════

For more information:
  • Full docs: /opt/trapninja/config/HA_README.md
  • Architecture: /opt/trapninja/HA_ARCHITECTURE.md
""")
    return True
