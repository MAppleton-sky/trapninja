#!/usr/bin/env python3
"""
TrapNinja Shadow Mode CLI Commands

Commands for managing shadow/mirror mode operation for parallel testing
alongside existing SNMP trap receivers.
"""

import json
import sys
from argparse import Namespace

from ..shadow import (
    get_shadow_summary,
    get_shadow_stats,
    is_shadow_mode,
    ShadowConfig,
    CaptureConfig,
    load_shadow_config,
    load_capture_config,
    save_capture_config,
    SHADOW_CONFIG_FILE,
    CAPTURE_CONFIG_FILE
)


def show_shadow_status(verbose: bool = False) -> bool:
    """
    Show shadow mode status and statistics.
    
    Args:
        verbose: Show detailed statistics
        
    Returns:
        True if successful
    """
    try:
        # Try to get live status from running daemon via control socket
        try:
            from ..control import send_control_command
            response = send_control_command({'command': 'shadow_status'})
            if response and response.get('status') == 'success':
                data = response.get('data', {})
                _print_shadow_status(data, verbose)
                return True
        except Exception:
            pass
        
        # Fall back to showing config-based status
        print("Shadow Mode Configuration")
        print("=" * 50)
        
        shadow_config = load_shadow_config()
        capture_config = load_capture_config()
        
        print(f"\nShadow Mode: {'ENABLED' if shadow_config.enabled else 'DISABLED'}")
        if shadow_config.enabled:
            print(f"  Observe Only: {shadow_config.observe_only}")
            print(f"  Log All Traps: {shadow_config.log_all_traps}")
            if shadow_config.log_file:
                print(f"  Log File: {shadow_config.log_file}")
        
        print(f"\nCapture Mode: {capture_config.mode}")
        print(f"  Allow Parallel: {capture_config.allow_parallel}")
        print(f"  Effective Mode: {capture_config.get_effective_mode()}")
        
        print(f"\nConfig Files:")
        print(f"  Shadow: {SHADOW_CONFIG_FILE}")
        print(f"  Capture: {CAPTURE_CONFIG_FILE}")
        
        print("\nNote: Daemon not running - showing configuration only")
        print("Start daemon to see live statistics")
        
        return True
        
    except Exception as e:
        print(f"Error getting shadow status: {e}")
        return False


def _print_shadow_status(data: dict, verbose: bool = False):
    """Print shadow status in formatted output"""
    print("Shadow Mode Status")
    print("=" * 50)
    
    enabled = data.get('enabled', False)
    print(f"\nMode: {'ENABLED' if enabled else 'DISABLED'}")
    
    if enabled:
        print(f"Observe Only: {data.get('observe_only', True)}")
        print(f"\nStatistics:")
        print(f"  Total Observed: {data.get('total_observed', 0):,}")
        print(f"  Would Forward: {data.get('total_forwarded', 0):,}")
        print(f"  Would Block: {data.get('total_blocked', 0):,}")
        print(f"  Would Redirect: {data.get('total_redirected', 0):,}")
        print(f"  Unique Sources: {data.get('unique_sources', 0):,}")
        print(f"  Unique OIDs: {data.get('unique_oids', 0):,}")
        print(f"  Current Rate: {data.get('current_rate_1m', 0):.1f} traps/sec")
        
        uptime = data.get('uptime_seconds', 0)
        if uptime > 0:
            hours = int(uptime // 3600)
            minutes = int((uptime % 3600) // 60)
            seconds = int(uptime % 60)
            print(f"  Uptime: {hours:02d}:{minutes:02d}:{seconds:02d}")


def export_shadow_stats(output_file: str = None) -> bool:
    """
    Export shadow mode statistics to JSON.
    
    Args:
        output_file: Output file path (stdout if None)
        
    Returns:
        True if successful
    """
    try:
        # Try to get stats from running daemon
        try:
            from ..control import send_control_command
            response = send_control_command({'command': 'shadow_export'})
            if response and response.get('status') == 'success':
                data = response.get('data', {})
            else:
                print("Shadow mode not active or daemon not running")
                return False
        except Exception as e:
            print(f"Failed to get shadow stats from daemon: {e}")
            return False
        
        json_output = json.dumps(data, indent=2)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(json_output)
            print(f"Shadow statistics exported to: {output_file}")
        else:
            print(json_output)
        
        return True
        
    except Exception as e:
        print(f"Error exporting shadow stats: {e}")
        return False


def show_shadow_help() -> bool:
    """Show comprehensive shadow mode help"""
    help_text = """
TrapNinja Shadow Mode
=====================

Shadow mode allows TrapNinja to run alongside an existing SNMP trap receiver
for testing and comparison purposes without affecting production traffic.

MODES
-----

1. Shadow Mode (Observe Only)
   - Captures traps using packet sniffing (no port binding)
   - Processes and counts traps without forwarding
   - Perfect for testing routing rules before deployment
   
   Usage:
     python trapninja.py --foreground --shadow-mode
     
2. Mirror Mode (Parallel Operation)  
   - Captures traps using packet sniffing
   - Forwards traps in parallel with existing receiver
   - Use for comparison testing
   
   Usage:
     python trapninja.py --foreground --mirror-mode

3. Parallel Capture Mode
   - Uses sniff mode instead of socket binding
   - Can be combined with normal operation
   
   Usage:
     python trapninja.py --foreground --parallel

HOW IT WORKS
------------

Traditional SNMP trap receivers bind to UDP port 162, which prevents other
applications from receiving traps on the same port. TrapNinja's shadow mode
uses libpcap-based packet capture to "see" all packets without binding to
the port.

Technical details:
- Uses Scapy's sniff() function with libpcap
- Captures packets at the network layer
- Does not interfere with existing socket-based receivers
- Requires root/admin privileges for raw packet capture

CAPTURE MODES
-------------

Configuration in /opt/trapninja/config/capture_config.json:

{
    "mode": "sniff",        // "auto", "sniff", "socket"
    "allow_parallel": true, // Force sniff mode
    "buffer_size_mb": 64
}

- "auto":   Try eBPF first, fall back to sniff (default)
- "sniff":  Always use libpcap sniffing (parallel-safe)  
- "socket": Use UDP socket binding (exclusive access)

CLI COMMANDS
------------

Start in shadow mode:
  python trapninja.py --foreground --shadow-mode

Start in mirror mode:
  python trapninja.py --foreground --mirror-mode

Enable parallel capture:
  python trapninja.py --foreground --parallel

Log all observed traps:
  python trapninja.py --foreground --shadow-mode --log-traps /tmp/traps.log

Show shadow statistics:
  python trapninja.py --shadow-status

Export statistics as JSON:
  python trapninja.py --shadow-export

Set capture mode:
  python trapninja.py --foreground --capture-mode sniff

EXAMPLES
--------

Test TrapNinja alongside existing Net-SNMP snmptrapd:

  # Existing snmptrapd is running on port 162
  # Start TrapNinja in shadow mode
  sudo python trapninja.py --foreground --shadow-mode --debug
  
  # Watch the output to verify routing decisions
  # No traps are actually forwarded

Compare forwarding behavior:

  # Start TrapNinja in mirror mode
  sudo python trapninja.py --foreground --mirror-mode
  
  # Both systems receive and forward traps
  # Compare destinations and timing

CONFIGURATION FILES
-------------------

Shadow config: /opt/trapninja/config/shadow_config.json
{
    "enabled": true,
    "observe_only": true,
    "log_all_traps": false,
    "log_file": "/var/log/trapninja/shadow_traps.log"
}

Capture config: /opt/trapninja/config/capture_config.json
{
    "mode": "sniff",
    "allow_parallel": true,
    "buffer_size_mb": 64
}

NOTES
-----

1. Shadow/mirror modes require root privileges for raw packet capture
2. Statistics are collected in-memory and reset on restart
3. Use --shadow-export to save statistics before stopping
4. The existing receiver will continue working normally
"""
    print(help_text)
    return True


def handle_shadow_status(args: Namespace) -> int:
    """Handle --shadow-status command"""
    verbose = getattr(args, 'verbose', False)
    return 0 if show_shadow_status(verbose=verbose) else 1


def handle_shadow_export(args: Namespace) -> int:
    """Handle --shadow-export command"""
    output = getattr(args, 'output', None)
    return 0 if export_shadow_stats(output_file=output) else 1


def handle_shadow_help(args: Namespace) -> int:
    """Handle --shadow-help command (if added)"""
    return 0 if show_shadow_help() else 1
