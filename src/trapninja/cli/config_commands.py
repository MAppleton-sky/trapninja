#!/usr/bin/env python3
"""
TrapNinja Config Commands Module

Provides read-only configuration display commands that show the current
running state of all config files — destinations, blocked IPs/OIDs,
redirection rules, listen ports, HA settings, cache settings, etc.

These commands complement the 'filter' category (which modifies rules)
by providing a unified view of all configuration state.
"""

import json
import os
import sys
from typing import Optional


def show_config(json_output: bool = False, brief: bool = False) -> int:
    """
    Show complete configuration overview with actual rule data.

    Args:
        json_output: Output as JSON
        brief: Show counts only (no rule detail)

    Returns:
        Exit code (0 for success)
    """
    config_data = _gather_full_config(include_detail=not brief)

    if json_output:
        print(json.dumps(config_data, indent=2, default=str))
    else:
        _print_full_config(config_data, brief=brief)

    return 0


def show_destinations(json_output: bool = False) -> int:
    """Show forwarding destinations."""
    from ..config import DESTINATIONS_FILE
    from .command_base import config_io

    data = config_io.load(DESTINATIONS_FILE, [])

    if json_output:
        print(json.dumps(data, indent=2))
    else:
        print("\nForwarding Destinations")
        print("=" * 50)
        if not data:
            print("  No destinations configured")
        else:
            for i, dest in enumerate(data, 1):
                if isinstance(dest, (list, tuple)) and len(dest) >= 2:
                    print(f"  {i}. {dest[0]}:{dest[1]}")
                elif isinstance(dest, dict):
                    print(f"  {i}. {dest.get('host', '?')}:{dest.get('port', 162)}")
                else:
                    print(f"  {i}. {dest}")
            print(f"\nTotal: {len(data)} destination(s)")
        print()

    return 0


def show_blocked_ips(json_output: bool = False) -> int:
    """Show blocked IP addresses."""
    from ..config import BLOCKED_IPS_FILE
    from .command_base import config_io

    data = config_io.load(BLOCKED_IPS_FILE, [])

    if json_output:
        print(json.dumps(data, indent=2))
    else:
        print("\nBlocked IP Addresses")
        print("=" * 50)
        if not data:
            print("  No IPs blocked")
        else:
            for ip in sorted(data):
                print(f"  • {ip}")
            print(f"\nTotal: {len(data)} blocked IP(s)")
        print()

    return 0


def show_blocked_oids(json_output: bool = False) -> int:
    """Show blocked OIDs."""
    from ..config import BLOCKED_TRAPS_FILE
    from .command_base import config_io

    data = config_io.load(BLOCKED_TRAPS_FILE, [])

    if json_output:
        print(json.dumps(data, indent=2))
    else:
        print("\nBlocked OIDs")
        print("=" * 50)
        if not data:
            print("  No OIDs blocked")
        else:
            for oid in sorted(data):
                print(f"  • {oid}")
            print(f"\nTotal: {len(data)} blocked OID(s)")
        print()

    return 0


def show_redirected_ips(json_output: bool = False) -> int:
    """Show IP redirection rules."""
    from ..config import REDIRECTED_IPS_FILE
    from .command_base import config_io

    data = config_io.load(REDIRECTED_IPS_FILE, {})

    if json_output:
        print(json.dumps(data, indent=2))
    else:
        print("\nIP Redirection Rules")
        print("=" * 50)
        if not data:
            print("  No IP redirections configured")
        else:
            # data is typically {ip: tag} or {ip: {tag: ...}}
            for ip, tag in sorted(data.items()):
                if isinstance(tag, dict):
                    tag_str = tag.get('tag', str(tag))
                else:
                    tag_str = str(tag)
                print(f"  {ip:>20s}  →  {tag_str}")
            print(f"\nTotal: {len(data)} IP redirection(s)")
        print()

    return 0


def show_redirected_oids(json_output: bool = False) -> int:
    """Show OID redirection rules."""
    from ..config import REDIRECTED_OIDS_FILE
    from .command_base import config_io

    data = config_io.load(REDIRECTED_OIDS_FILE, {})

    if json_output:
        print(json.dumps(data, indent=2))
    else:
        print("\nOID Redirection Rules")
        print("=" * 50)
        if not data:
            print("  No OID redirections configured")
        else:
            for oid, tag in sorted(data.items()):
                if isinstance(tag, dict):
                    tag_str = tag.get('tag', str(tag))
                else:
                    tag_str = str(tag)
                print(f"  {oid}  →  {tag_str}")
            print(f"\nTotal: {len(data)} OID redirection(s)")
        print()

    return 0


def show_redirect_dests(json_output: bool = False) -> int:
    """Show redirect destination groups."""
    from ..config import REDIRECTED_DESTINATIONS_FILE
    from .command_base import config_io

    data = config_io.load(REDIRECTED_DESTINATIONS_FILE, {})

    if json_output:
        print(json.dumps(data, indent=2))
    else:
        print("\nRedirect Destination Groups")
        print("=" * 50)
        if not data:
            print("  No redirect destination groups configured")
        else:
            for tag, dests in sorted(data.items()):
                print(f"\n  [{tag}]")
                if isinstance(dests, list):
                    for dest in dests:
                        if isinstance(dest, (list, tuple)) and len(dest) >= 2:
                            print(f"    → {dest[0]}:{dest[1]}")
                        elif isinstance(dest, dict):
                            print(f"    → {dest.get('ip', '?')}:{dest.get('port', 162)}")
                        else:
                            print(f"    → {dest}")
                else:
                    print(f"    → {dests}")
            total_dests = sum(
                len(d) if isinstance(d, list) else 1 for d in data.values()
            )
            print(f"\nTotal: {len(data)} group(s), {total_dests} destination(s)")
        print()

    return 0


def show_listen_ports(json_output: bool = False) -> int:
    """Show configured listen ports."""
    from ..config import LISTEN_PORTS_FILE
    from .command_base import config_io

    data = config_io.load(LISTEN_PORTS_FILE, [162])

    if json_output:
        print(json.dumps(data, indent=2))
    else:
        print("\nListen Ports")
        print("=" * 50)
        if not data:
            print("  Default: 162")
        else:
            for port in sorted(data):
                print(f"  • UDP/{port}")
            print(f"\nTotal: {len(data)} port(s)")
        print()

    return 0


def validate_config() -> int:
    """Validate configuration without starting the daemon."""
    from .daemon_commands import validate_config as _validate
    return _validate()


# =============================================================================
# INTERNAL HELPERS
# =============================================================================

def _gather_full_config(include_detail: bool = True) -> dict:
    """
    Gather complete configuration state from all config files.

    Args:
        include_detail: If True, include actual rule lists; if False, counts only.

    Returns:
        Dict containing all configuration state.
    """
    from .. import config as cfg
    from .command_base import config_io

    # Ensure config is loaded
    try:
        cfg.stop_event.set()
        cfg.load_config(None)
        cfg.stop_event.clear()
    except Exception:
        pass

    result = {
        'config_directory': cfg.CONFIG_DIR,
        'interface': cfg.INTERFACE,
        'capture_mode': cfg.CAPTURE_MODE,
    }

    # Listen ports
    try:
        ports = config_io.load(cfg.LISTEN_PORTS_FILE, [162])
        result['listen_ports'] = ports
    except Exception:
        result['listen_ports'] = [162]

    # Destinations
    try:
        dests = config_io.load(cfg.DESTINATIONS_FILE, [])
        result['destinations'] = dests if include_detail else []
        result['destination_count'] = len(dests)
    except Exception:
        result['destinations'] = []
        result['destination_count'] = 0

    # Blocked IPs
    try:
        blocked_ips = config_io.load(cfg.BLOCKED_IPS_FILE, [])
        result['blocked_ips'] = sorted(blocked_ips) if include_detail else []
        result['blocked_ips_count'] = len(blocked_ips)
    except Exception:
        result['blocked_ips'] = []
        result['blocked_ips_count'] = 0

    # Blocked OIDs
    try:
        blocked_oids = config_io.load(cfg.BLOCKED_TRAPS_FILE, [])
        result['blocked_oids'] = sorted(blocked_oids) if include_detail else []
        result['blocked_oids_count'] = len(blocked_oids)
    except Exception:
        result['blocked_oids'] = []
        result['blocked_oids_count'] = 0

    # Redirected IPs
    try:
        redir_ips = config_io.load(cfg.REDIRECTED_IPS_FILE, {})
        result['redirected_ips'] = redir_ips if include_detail else {}
        result['redirected_ips_count'] = len(redir_ips)
    except Exception:
        result['redirected_ips'] = {}
        result['redirected_ips_count'] = 0

    # Redirected OIDs
    try:
        redir_oids = config_io.load(cfg.REDIRECTED_OIDS_FILE, {})
        result['redirected_oids'] = redir_oids if include_detail else {}
        result['redirected_oids_count'] = len(redir_oids)
    except Exception:
        result['redirected_oids'] = {}
        result['redirected_oids_count'] = 0

    # Redirect destinations
    try:
        redir_dests = config_io.load(cfg.REDIRECTED_DESTINATIONS_FILE, {})
        result['redirect_destinations'] = redir_dests if include_detail else {}
        result['redirect_destinations_count'] = len(redir_dests)
    except Exception:
        result['redirect_destinations'] = {}
        result['redirect_destinations_count'] = 0

    # HA configuration
    try:
        from ..ha import load_ha_config
        ha_cfg = load_ha_config()
        result['high_availability'] = {
            'enabled': ha_cfg.enabled,
            'mode': ha_cfg.mode,
            'priority': ha_cfg.priority,
            'peer_host': ha_cfg.peer_host if ha_cfg.enabled else None,
            'peer_port': ha_cfg.peer_port if ha_cfg.enabled else None,
            'heartbeat_interval': ha_cfg.heartbeat_interval,
            'failover_delay': ha_cfg.failover_delay,
        }
    except Exception:
        result['high_availability'] = {'enabled': False}

    # Cache configuration
    try:
        from ..config import load_cache_config
        cache_cfg = load_cache_config()
        if cache_cfg:
            result['cache'] = {
                'enabled': cache_cfg.enabled,
                'host': cache_cfg.host if cache_cfg.enabled else None,
                'port': cache_cfg.port if cache_cfg.enabled else None,
                'retention_hours': cache_cfg.retention_hours,
            }
        else:
            result['cache'] = {'enabled': False}
    except Exception:
        result['cache'] = {'enabled': False}

    return result


def _print_full_config(config: dict, brief: bool = False):
    """Pretty-print the full configuration."""
    from ..__version__ import __version__

    print(f"\nTrapNinja v{__version__} — Configuration Overview")
    print("=" * 60)

    # Basic settings
    print(f"\nConfig Directory:  {config.get('config_directory', 'N/A')}")
    print(f"Interface:         {config.get('interface', 'N/A')}")
    print(f"Capture Mode:      {config.get('capture_mode', 'auto')}")

    ports = config.get('listen_ports', [])
    print(f"Listen Ports:      {', '.join(str(p) for p in ports) if ports else '162 (default)'}")

    # Destinations
    dests = config.get('destinations', [])
    dest_count = config.get('destination_count', len(dests))
    print(f"\n--- Forwarding Destinations ({dest_count}) ---")
    if dests and not brief:
        for i, d in enumerate(dests, 1):
            if isinstance(d, (list, tuple)) and len(d) >= 2:
                print(f"  {i}. {d[0]}:{d[1]}")
            elif isinstance(d, dict):
                print(f"  {i}. {d.get('host', '?')}:{d.get('port', 162)}")
            else:
                print(f"  {i}. {d}")
    elif dest_count == 0:
        print("  None configured")

    # Blocked IPs
    blocked_ips = config.get('blocked_ips', [])
    bip_count = config.get('blocked_ips_count', len(blocked_ips))
    print(f"\n--- Blocked IPs ({bip_count}) ---")
    if blocked_ips and not brief:
        for ip in blocked_ips:
            print(f"  • {ip}")
    elif bip_count == 0:
        print("  None")

    # Blocked OIDs
    blocked_oids = config.get('blocked_oids', [])
    boid_count = config.get('blocked_oids_count', len(blocked_oids))
    print(f"\n--- Blocked OIDs ({boid_count}) ---")
    if blocked_oids and not brief:
        for oid in blocked_oids:
            print(f"  • {oid}")
    elif boid_count == 0:
        print("  None")

    # IP Redirections
    redir_ips = config.get('redirected_ips', {})
    rip_count = config.get('redirected_ips_count', len(redir_ips))
    print(f"\n--- IP Redirections ({rip_count}) ---")
    if redir_ips and not brief:
        for ip, tag in sorted(redir_ips.items()):
            tag_str = tag.get('tag', str(tag)) if isinstance(tag, dict) else str(tag)
            print(f"  {ip:>20s}  →  {tag_str}")
    elif rip_count == 0:
        print("  None")

    # OID Redirections
    redir_oids = config.get('redirected_oids', {})
    roid_count = config.get('redirected_oids_count', len(redir_oids))
    print(f"\n--- OID Redirections ({roid_count}) ---")
    if redir_oids and not brief:
        for oid, tag in sorted(redir_oids.items()):
            tag_str = tag.get('tag', str(tag)) if isinstance(tag, dict) else str(tag)
            print(f"  {oid}  →  {tag_str}")
    elif roid_count == 0:
        print("  None")

    # Redirect Destination Groups
    redir_dests = config.get('redirect_destinations', {})
    rd_count = config.get('redirect_destinations_count', len(redir_dests))
    print(f"\n--- Redirect Destination Groups ({rd_count}) ---")
    if redir_dests and not brief:
        for tag, group_dests in sorted(redir_dests.items()):
            print(f"  [{tag}]")
            if isinstance(group_dests, list):
                for d in group_dests:
                    if isinstance(d, (list, tuple)) and len(d) >= 2:
                        print(f"    → {d[0]}:{d[1]}")
                    elif isinstance(d, dict):
                        print(f"    → {d.get('ip', '?')}:{d.get('port', 162)}")
                    else:
                        print(f"    → {d}")
            else:
                print(f"    → {group_dests}")
    elif rd_count == 0:
        print("  None")

    # HA
    ha = config.get('high_availability', {})
    print(f"\n--- High Availability ---")
    if ha.get('enabled'):
        print(f"  Enabled:    Yes")
        print(f"  Mode:       {ha.get('mode', 'N/A')}")
        print(f"  Priority:   {ha.get('priority', 'N/A')}")
        print(f"  Peer:       {ha.get('peer_host', 'N/A')}:{ha.get('peer_port', 'N/A')}")
        print(f"  Heartbeat:  {ha.get('heartbeat_interval', 'N/A')}s")
        print(f"  Failover:   {ha.get('failover_delay', 'N/A')}s delay")
    else:
        print("  Disabled (standalone mode)")

    # Cache
    cache = config.get('cache', {})
    print(f"\n--- Redis Cache ---")
    if cache.get('enabled'):
        print(f"  Enabled:    Yes")
        print(f"  Host:       {cache.get('host', 'N/A')}:{cache.get('port', 'N/A')}")
        print(f"  Retention:  {cache.get('retention_hours', 'N/A')} hours")
    else:
        print("  Disabled")

    print()
