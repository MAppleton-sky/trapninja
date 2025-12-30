#!/usr/bin/env python3
"""
TrapNinja Daemon Commands Module

Handles daemon control operations (start, stop, restart, status) via command-line interface.
"""

import json
import sys
from typing import Optional

from ..daemon import start_daemon, stop_daemon, restart_daemon, status_daemon, run_foreground_daemon


def start() -> int:
    """
    Start the TrapNinja daemon

    Returns:
        Exit code (0 for success, non-zero for failure)
    """
    print("Starting TrapNinja daemon with HA support...")
    return start_daemon()


def stop() -> int:
    """
    Stop the TrapNinja daemon

    Returns:
        Exit code (0 for success, non-zero for failure)
    """
    return stop_daemon()


def restart() -> int:
    """
    Restart the TrapNinja daemon

    Returns:
        Exit code (0 for success, non-zero for failure)
    """
    print("Restarting TrapNinja daemon with HA support...")
    return restart_daemon()


def status() -> int:
    """
    Check TrapNinja daemon status

    Returns:
        Exit code (0 for success, non-zero for failure)
    """
    return status_daemon()


def run_foreground(debug: bool = False, shadow_mode: bool = False, 
                   mirror_mode: bool = False, parallel: bool = False,
                   capture_mode: str = None, log_traps: str = None) -> int:
    """
    Run TrapNinja in foreground mode

    Args:
        debug: Enable debug logging
        shadow_mode: Run in shadow mode (observe only, no forwarding)
        mirror_mode: Run in mirror mode (parallel capture and forward)
        parallel: Enable parallel operation (sniff capture)
        capture_mode: Force capture mode (auto, sniff, socket)
        log_traps: Log all observed traps to file

    Returns:
        Exit code (0 for success, non-zero for failure)
    """
    print("Running TrapNinja in foreground with HA support...")
    
    if shadow_mode:
        print("Shadow mode: ENABLED (observe only, no forwarding)")
        print("Using sniff capture to run alongside existing trap receivers")
    elif mirror_mode:
        print("Mirror mode: ENABLED (parallel capture and forward)")
        print("Using sniff capture to run alongside existing trap receivers")
    elif parallel:
        print("Parallel mode: ENABLED (sniff capture for coexistence)")
    
    if capture_mode:
        print(f"Capture mode: {capture_mode.upper()}")
    
    if log_traps:
        print(f"Logging all traps to: {log_traps}")
    
    if debug:
        print("Debug mode enabled")
    
    return run_foreground_daemon(
        debug=debug, 
        shadow_mode=shadow_mode,
        mirror_mode=mirror_mode,
        parallel=parallel,
        capture_mode=capture_mode,
        log_traps=log_traps
    )


def show_config(json_output: bool = False) -> int:
    """
    Show current effective configuration.
    
    Queries the running daemon for its configuration, or reads from
    config files if daemon is not running.

    Args:
        json_output: If True, output as JSON

    Returns:
        Exit code (0 for success, non-zero for failure)
    """
    from ..control import ControlSocket
    
    config_data = None
    from_daemon = False
    
    # Try to get config from running daemon first
    try:
        response = ControlSocket.send_command('show_config', timeout=5.0)
        if response.get('status') == ControlSocket.SUCCESS:
            config_data = response.get('data', {})
            from_daemon = True
    except ConnectionRefusedError:
        # Daemon not running, read from files
        pass
    except Exception as e:
        print(f"Warning: Could not connect to daemon: {e}", file=sys.stderr)
    
    # If daemon not running, read config files directly
    if config_data is None:
        config_data = _read_config_files()
        from_daemon = False
    
    # Output the configuration
    if json_output:
        print(json.dumps(config_data, indent=2, default=str))
    else:
        _print_config(config_data, from_daemon)
    
    return 0


def _read_config_files() -> dict:
    """Read configuration from files when daemon is not running."""
    # IMPORTANT: Import the module, not the variables directly!
    # We need to call load_config() first to populate the variables,
    # then access them via the module reference to get current values.
    from .. import config as cfg
    from ..ha import load_ha_config
    
    # Set stop_event to prevent load_config() from scheduling periodic timer
    # (we only want a one-time load for CLI display)
    cfg.stop_event.set()
    
    # Load configuration from files to populate module variables
    cfg.load_config(None)
    
    # Clear stop_event in case other code checks it
    cfg.stop_event.clear()
    
    config = {
        'source': 'files',
        'config_directory': cfg.CONFIG_DIR,
        'interface': cfg.INTERFACE,
        'listen_ports': list(cfg.LISTEN_PORTS) if cfg.LISTEN_PORTS else [],
        'forwarding': {
            'destinations': cfg.destinations if cfg.destinations else [],
            'destination_count': len(cfg.destinations) if cfg.destinations else 0
        },
        'filtering': {
            'blocked_ips_count': len(cfg.blocked_ips) if cfg.blocked_ips else 0,
            'blocked_oids_count': len(cfg.blocked_traps) if cfg.blocked_traps else 0,
            'ip_redirections_count': len(cfg.redirected_ips) if cfg.redirected_ips else 0,
            'oid_redirections_count': len(cfg.redirected_oids) if cfg.redirected_oids else 0,
            'redirect_destinations_count': len(cfg.redirected_destinations) if cfg.redirected_destinations else 0
        }
    }
    
    # Add HA configuration
    try:
        ha_config = load_ha_config()
        config['high_availability'] = {
            'enabled': ha_config.enabled,
            'mode': ha_config.mode,
            'priority': ha_config.priority,
            'peer_host': ha_config.peer_host if ha_config.enabled else None,
            'peer_port': ha_config.peer_port if ha_config.enabled else None,
            'heartbeat_interval': ha_config.heartbeat_interval,
            'failover_delay': ha_config.failover_delay
        }
    except Exception:
        config['high_availability'] = {'enabled': False}
    
    # Add cache configuration
    try:
        from ..config import load_cache_config
        cache_config = load_cache_config()
        if cache_config:
            config['cache'] = {
                'enabled': cache_config.enabled,
                'host': cache_config.host if cache_config.enabled else None,
                'port': cache_config.port if cache_config.enabled else None,
                'retention_hours': cache_config.retention_hours
            }
    except Exception:
        config['cache'] = {'enabled': False}
    
    return config


def _print_config(config: dict, from_daemon: bool):
    """Pretty print configuration."""
    source = "running daemon" if from_daemon else "configuration files"
    print(f"\nTrapNinja Configuration (from {source})")
    print("=" * 50)
    
    # Basic settings
    print(f"\nConfig Directory: {config.get('config_directory', 'N/A')}")
    print(f"Interface: {config.get('interface', 'N/A')}")
    
    ports = config.get('listen_ports', [])
    print(f"Listen Ports: {', '.join(map(str, ports)) if ports else 'None'}")
    
    # Forwarding
    print("\n--- Forwarding ---")
    fwd = config.get('forwarding', {})
    dest_count = fwd.get('destination_count', 0)
    print(f"Destinations: {dest_count}")
    
    destinations = fwd.get('destinations', [])
    if destinations:
        for i, dest in enumerate(destinations[:5], 1):  # Show first 5
            if isinstance(dest, dict):
                print(f"  {i}. {dest.get('host', '?')}:{dest.get('port', 162)}")
            else:
                print(f"  {i}. {dest}")
        if len(destinations) > 5:
            print(f"  ... and {len(destinations) - 5} more")
    
    # Filtering
    print("\n--- Filtering Rules ---")
    filt = config.get('filtering', {})
    print(f"Blocked IPs: {filt.get('blocked_ips_count', 0)}")
    print(f"Blocked OIDs: {filt.get('blocked_oids_count', 0)}")
    print(f"IP Redirections: {filt.get('ip_redirections_count', 0)}")
    print(f"OID Redirections: {filt.get('oid_redirections_count', 0)}")
    print(f"Redirect Destinations: {filt.get('redirect_destinations_count', 0)}")
    
    # High Availability
    print("\n--- High Availability ---")
    ha = config.get('high_availability', {})
    if ha.get('enabled'):
        print(f"Enabled: Yes")
        print(f"Mode: {ha.get('mode', 'N/A')}")
        print(f"Priority: {ha.get('priority', 'N/A')}")
        print(f"Peer: {ha.get('peer_host', 'N/A')}:{ha.get('peer_port', 'N/A')}")
        print(f"Heartbeat Interval: {ha.get('heartbeat_interval', 'N/A')}s")
        print(f"Failover Delay: {ha.get('failover_delay', 'N/A')}s")
    else:
        print("Enabled: No (standalone mode)")
    
    # Cache
    print("\n--- Redis Cache ---")
    cache = config.get('cache', {})
    if cache.get('enabled'):
        print(f"Enabled: Yes")
        print(f"Redis Host: {cache.get('host', 'N/A')}:{cache.get('port', 'N/A')}")
        print(f"Retention: {cache.get('retention_hours', 'N/A')} hours")
    else:
        print("Enabled: No")
    
    print()


def queue_stats(json_output: bool = False) -> int:
    """
    Show packet queue statistics.
    
    Displays current queue depth, maximum depth, drop count, and utilization.
    Useful for diagnosing packet drops during burst traffic.

    Args:
        json_output: If True, output as JSON

    Returns:
        Exit code (0 for success, non-zero for failure)
    """
    from ..control import ControlSocket
    import os
    
    queue_data = None
    from_daemon = False
    
    # Try to get stats from running daemon first
    try:
        response = ControlSocket.send_command('queue_stats', timeout=5.0)
        if response.get('status') == ControlSocket.SUCCESS:
            queue_data = response.get('data', {})
            from_daemon = True
    except ConnectionRefusedError:
        pass
    except Exception as e:
        print(f"Warning: Could not connect to daemon: {e}", file=sys.stderr)
    
    # If daemon not running, try to read from network module globals or metrics file
    if queue_data is None:
        try:
            # Try to read from metrics file
            metrics_path = "/var/log/trapninja/metrics/trapninja_granular.json"
            if os.path.exists(metrics_path):
                with open(metrics_path) as f:
                    import json as json_mod
                    data = json_mod.load(f)
                    queue_data = data.get('queue', {})
        except Exception:
            pass
    
    if queue_data is None:
        # Return default/empty stats
        queue_data = {
            'current_depth': 0,
            'max_depth': 0,
            'total_queued': 0,
            'total_dropped': 0,
            'full_events': 0,
            'queue_capacity': 200000,
            'utilization': 0.0
        }
        from_daemon = False
    
    if json_output:
        print(json.dumps(queue_data, indent=2))
    else:
        _print_queue_stats(queue_data, from_daemon)
    
    return 0


def _print_queue_stats(stats: dict, from_daemon: bool):
    """Pretty print queue statistics."""
    source = "running daemon" if from_daemon else "last known stats"
    
    print(f"\nTrapNinja Queue Statistics (from {source})")
    print("=" * 50)
    
    current = stats.get('current_depth', 0)
    capacity = stats.get('queue_capacity', 200000)
    utilization = (current / capacity * 100) if capacity > 0 else 0
    
    print(f"\nCurrent Queue Depth:  {current:>12,}")
    print(f"Queue Capacity:       {capacity:>12,}")
    print(f"Utilization:          {utilization:>11.1f}%")
    
    print(f"\nMaximum Depth Seen:   {stats.get('max_depth', 0):>12,}")
    print(f"Total Packets Queued: {stats.get('total_queued', 0):>12,}")
    print(f"Total Packets Dropped:{stats.get('total_dropped', 0):>12,}")
    print(f"Queue Full Events:    {stats.get('full_events', 0):>12,}")
    
    # Calculate drop rate
    total_queued = stats.get('total_queued', 0)
    total_dropped = stats.get('total_dropped', 0)
    total_received = total_queued + total_dropped
    
    if total_received > 0:
        drop_rate = (total_dropped / total_received) * 100
        print(f"\nDrop Rate:            {drop_rate:>11.4f}%")
        
        # Assessment
        if drop_rate < 0.01:
            assessment = "Excellent - no action needed"
        elif drop_rate < 0.1:
            assessment = "Good - acceptable for most environments"
        elif drop_rate < 1.0:
            assessment = "Monitor - may indicate capacity issues"
        else:
            assessment = "Investigate - likely needs optimization"
        print(f"Assessment:           {assessment}")
    
    print()
    
    # Tips if drops detected
    if total_dropped > 0:
        print("TIP: To investigate drops, check:")
        print("  1. grep 'Queue full' /var/log/trapninja.log")
        print("  2. python trapninja.py --stats-top-ips --sort peak")
        print("  3. python trapninja.py --stats-top-oids --sort peak")
        print()


def validate_config() -> int:
    """
    Validate configuration without starting the daemon.
    
    Useful for checking configuration before deployment.

    Returns:
        Exit code (0 if valid, 1 if errors found)
    """
    from ..service import validate_configuration
    
    print("Validating TrapNinja configuration...")
    print()
    
    is_valid, errors, warnings = validate_configuration()
    
    # Print warnings
    if warnings:
        print("Warnings:")
        for warning in warnings:
            print(f"  ⚠ {warning}")
        print()
    
    # Print errors
    if errors:
        print("Errors:")
        for error in errors:
            print(f"  ✗ {error}")
        print()
    
    # Summary
    if is_valid:
        print("✓ Configuration is valid")
        if warnings:
            print(f"  ({len(warnings)} warning(s) - review recommended)")
        return 0
    else:
        print(f"✗ Configuration has {len(errors)} error(s)")
        print("  Please fix the errors above before starting the daemon.")
        return 1
