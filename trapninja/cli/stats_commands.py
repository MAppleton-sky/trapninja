#!/usr/bin/env python3
"""
TrapNinja CLI - Granular Statistics Command Handlers

Handles all granular statistics CLI commands including:
- Summary display
- Top IPs/OIDs queries
- Detailed IP/OID views
- Destination statistics
- Export and API functions

Author: TrapNinja Team
Version: 1.0.0
"""

import os
import sys
import json
import socket
from datetime import datetime
from typing import Optional, Dict, Any, List
from argparse import Namespace


def _get_stats_from_file() -> Optional[Dict]:
    """Read statistics from the exported JSON file."""
    json_path = "/var/log/trapninja/metrics/trapninja_granular.json"
    
    if not os.path.exists(json_path):
        return None
    
    try:
        with open(json_path) as f:
            return json.load(f)
    except Exception as e:
        print(f"Error reading stats file: {e}")
        return None


def _query_daemon_stats(query: Dict) -> Optional[Dict]:
    """Query the running daemon for statistics via Unix socket."""
    socket_path = "/var/run/trapninja/control.sock"
    
    if not os.path.exists(socket_path):
        return None
    
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        sock.connect(socket_path)
        
        # Add stats command prefix
        query['command'] = 'stats'
        
        sock.sendall((json.dumps(query) + '\n').encode())
        
        response = b''
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
            if b'\n' in chunk:
                break
        
        sock.close()
        return json.loads(response.decode().strip())
        
    except Exception:
        return None


def _output_json(data: Any, pretty: bool = False):
    """Output data as JSON."""
    if pretty:
        print(json.dumps(data, indent=2, default=str))
    else:
        print(json.dumps(data, default=str))


def _format_timestamp(ts: str) -> str:
    """Format ISO timestamp for display."""
    if not ts or 'T' not in ts:
        return ts or 'N/A'
    try:
        dt = datetime.fromisoformat(ts.replace('Z', '+00:00'))
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except:
        return ts


# =============================================================================
# COMMAND HANDLERS
# =============================================================================

def handle_stats_summary(args: Namespace) -> int:
    """Handle --stats-summary command."""
    use_json = getattr(args, 'json', False)
    pretty = getattr(args, 'pretty', False)
    
    # Try daemon first
    data = _query_daemon_stats({'action': 'summary'})
    
    # Fall back to file
    if not data:
        data = _get_stats_from_file()
    
    if not data:
        print("Error: Could not retrieve statistics.")
        print("Make sure TrapNinja is running or check metrics files at:")
        print("  /var/log/trapninja/metrics/trapninja_granular.json")
        return 1
    
    if use_json:
        _output_json(data, pretty)
        return 0
    
    # Display formatted summary
    print("\n" + "=" * 60)
    print("  TrapNinja Granular Statistics Summary")
    print("=" * 60 + "\n")
    
    # Handle different data structures
    summary = data.get('summary', data)
    totals = summary.get('totals', summary)
    counts = summary.get('counts', {})
    rates = summary.get('rates', {})
    
    print("TOTALS:")
    print(f"  Total Traps:       {totals.get('traps', totals.get('total_traps', 0)):>12,}")
    print(f"  Forwarded:         {totals.get('forwarded', totals.get('total_forwarded', 0)):>12,}")
    print(f"  Blocked:           {totals.get('blocked', totals.get('total_blocked', 0)):>12,}")
    print(f"  Redirected:        {totals.get('redirected', totals.get('total_redirected', 0)):>12,}")
    print(f"  Dropped:           {totals.get('dropped', totals.get('total_dropped', 0)):>12,}")
    
    if counts:
        print("\nCOUNTS:")
        print(f"  Unique IPs:        {counts.get('unique_ips', 0):>12,}")
        print(f"  Unique OIDs:       {counts.get('unique_oids', 0):>12,}")
        print(f"  Destinations:      {counts.get('destinations', 0):>12}")
    
    if rates:
        print("\nRATES:")
        print(f"  Per Second:        {rates.get('per_second', 0):>12.2f}")
        print(f"  Per Minute:        {rates.get('per_minute', 0):>12.2f}")
        print(f"  Per Hour:          {rates.get('per_hour', 0):>12.2f}")
    
    limits = data.get('limits', {})
    if limits:
        print("\nMEMORY USAGE:")
        print(f"  IP Tracking:       {limits.get('ip_usage', 'N/A'):>12}")
        print(f"  OID Tracking:      {limits.get('oid_usage', 'N/A'):>12}")
    
    ts = data.get('timestamp', summary.get('timestamp'))
    if ts:
        print(f"\nLast Updated: {_format_timestamp(ts)}")
    
    print()
    return 0


def handle_stats_top_ips(args: Namespace) -> int:
    """Handle --stats-top-ips command."""
    count = getattr(args, 'count', 10)
    sort_by = getattr(args, 'sort', 'total')
    use_json = getattr(args, 'json', False)
    pretty = getattr(args, 'pretty', False)
    
    # Try daemon first
    data = _query_daemon_stats({
        'action': 'top_ips',
        'count': count,
        'sort_by': sort_by
    })
    
    # Fall back to file
    if not data:
        file_data = _get_stats_from_file()
        if file_data:
            data = {'data': file_data.get('top_ips', [])}
    
    if not data:
        print("Error: Could not retrieve IP statistics.")
        return 1
    
    ips = data.get('data', data.get('top_ips', []))[:count]
    
    if use_json:
        _output_json(ips, pretty)
        return 0
    
    print("\n" + "=" * 90)
    print(f"  Top {count} Source IPs (sorted by {sort_by})")
    print("=" * 90 + "\n")
    
    if not ips:
        print("No IP statistics available yet.")
        return 0
    
    # Header
    print(f"{'#':>3}  {'IP Address':<20} {'Total':>10} {'Fwd':>8} {'Blk':>8} {'Rate/min':>10} {'Last Seen':<20}")
    print("-" * 90)
    
    for i, ip in enumerate(ips, 1):
        last_seen = _format_timestamp(ip.get('last_seen', ''))
        print(f"{i:>3}  "
              f"{ip.get('ip_address', 'N/A'):<20} "
              f"{ip.get('total_traps', 0):>10,} "
              f"{ip.get('forwarded', 0):>8,} "
              f"{ip.get('blocked', 0):>8,} "
              f"{ip.get('rate_per_minute', 0):>10.2f} "
              f"{last_seen:<20}")
    
    print()
    return 0


def handle_stats_top_oids(args: Namespace) -> int:
    """Handle --stats-top-oids command."""
    count = getattr(args, 'count', 10)
    sort_by = getattr(args, 'sort', 'total')
    use_json = getattr(args, 'json', False)
    pretty = getattr(args, 'pretty', False)
    
    # Try daemon first
    data = _query_daemon_stats({
        'action': 'top_oids',
        'count': count,
        'sort_by': sort_by
    })
    
    # Fall back to file
    if not data:
        file_data = _get_stats_from_file()
        if file_data:
            data = {'data': file_data.get('top_oids', [])}
    
    if not data:
        print("Error: Could not retrieve OID statistics.")
        return 1
    
    oids = data.get('data', data.get('top_oids', []))[:count]
    
    if use_json:
        _output_json(oids, pretty)
        return 0
    
    print("\n" + "=" * 95)
    print(f"  Top {count} OIDs (sorted by {sort_by})")
    print("=" * 95 + "\n")
    
    if not oids:
        print("No OID statistics available yet.")
        return 0
    
    # Header
    print(f"{'#':>3}  {'OID':<50} {'Total':>10} {'Rate/min':>10} {'Sources':>8}")
    print("-" * 95)
    
    for i, oid in enumerate(oids, 1):
        oid_str = oid.get('oid', 'N/A')
        # Truncate long OIDs
        if len(oid_str) > 48:
            oid_str = oid_str[:45] + '...'
        
        print(f"{i:>3}  "
              f"{oid_str:<50} "
              f"{oid.get('total_traps', 0):>10,} "
              f"{oid.get('rate_per_minute', 0):>10.2f} "
              f"{oid.get('unique_sources', 0):>8}")
    
    print()
    return 0


def handle_stats_ip_detail(args: Namespace) -> int:
    """Handle --stats-ip command."""
    ip_address = args.ip
    use_json = getattr(args, 'json', False)
    pretty = getattr(args, 'pretty', False)
    
    # Query daemon for real-time data
    data = _query_daemon_stats({
        'action': 'ip_detail',
        'ip_address': ip_address
    })
    
    if not data or data.get('status') == 'error':
        print(f"Error: IP address '{ip_address}' not found in statistics.")
        print("Note: Only IPs that have sent traps since last restart are tracked.")
        return 1
    
    ip_data = data.get('data', data)
    
    if use_json:
        _output_json(ip_data, pretty)
        return 0
    
    print("\n" + "=" * 60)
    print(f"  Statistics for IP: {ip_address}")
    print("=" * 60 + "\n")
    
    print("COUNTS:")
    print(f"  Total Traps:     {ip_data.get('total_traps', 0):>12,}")
    print(f"  Forwarded:       {ip_data.get('forwarded', 0):>12,}")
    print(f"  Blocked:         {ip_data.get('blocked', 0):>12,}")
    print(f"  Redirected:      {ip_data.get('redirected', 0):>12,}")
    print(f"  Dropped:         {ip_data.get('dropped', 0):>12,}")
    
    print("\nTIMING:")
    print(f"  First Seen:      {_format_timestamp(ip_data.get('first_seen', ''))}")
    print(f"  Last Seen:       {_format_timestamp(ip_data.get('last_seen', ''))}")
    print(f"  Age:             {ip_data.get('age_seconds', 0):.0f} seconds")
    print(f"  Idle:            {ip_data.get('idle_seconds', 0):.0f} seconds")
    
    print("\nRATES:")
    print(f"  Per Second:      {ip_data.get('rate_per_second', 0):>12.4f}")
    print(f"  Per Minute:      {ip_data.get('rate_per_minute', 0):>12.2f}")
    
    top_oids = ip_data.get('top_oids', [])
    if top_oids:
        print(f"\nTOP OIDs ({ip_data.get('unique_oids', len(top_oids))} unique):")
        for i, oid_info in enumerate(top_oids[:10], 1):
            oid = oid_info.get('oid', 'N/A')
            count = oid_info.get('count', 0)
            # Truncate long OIDs
            if len(oid) > 50:
                oid = oid[:47] + '...'
            print(f"  {i:2}. {oid} ({count:,})")
    
    destinations = ip_data.get('destinations', {})
    if destinations:
        print("\nDESTINATIONS:")
        for dest, count in destinations.items():
            print(f"  {dest}: {count:,}")
    
    print()
    return 0


def handle_stats_oid_detail(args: Namespace) -> int:
    """Handle --stats-oid command."""
    oid = args.oid
    use_json = getattr(args, 'json', False)
    pretty = getattr(args, 'pretty', False)
    
    # Query daemon for real-time data
    data = _query_daemon_stats({
        'action': 'oid_detail',
        'oid': oid
    })
    
    if not data or data.get('status') == 'error':
        print(f"Error: OID '{oid}' not found in statistics.")
        print("Note: Only OIDs that have been seen since last restart are tracked.")
        return 1
    
    oid_data = data.get('data', data)
    
    if use_json:
        _output_json(oid_data, pretty)
        return 0
    
    print("\n" + "=" * 60)
    print(f"  Statistics for OID")
    print("=" * 60)
    print(f"OID: {oid}\n")
    
    print("COUNTS:")
    print(f"  Total Traps:     {oid_data.get('total_traps', 0):>12,}")
    print(f"  Forwarded:       {oid_data.get('forwarded', 0):>12,}")
    print(f"  Blocked:         {oid_data.get('blocked', 0):>12,}")
    print(f"  Redirected:      {oid_data.get('redirected', 0):>12,}")
    print(f"  Dropped:         {oid_data.get('dropped', 0):>12,}")
    
    print("\nTIMING:")
    print(f"  First Seen:      {_format_timestamp(oid_data.get('first_seen', ''))}")
    print(f"  Last Seen:       {_format_timestamp(oid_data.get('last_seen', ''))}")
    
    print("\nRATES:")
    print(f"  Per Second:      {oid_data.get('rate_per_second', 0):>12.4f}")
    print(f"  Per Minute:      {oid_data.get('rate_per_minute', 0):>12.2f}")
    
    top_ips = oid_data.get('top_source_ips', [])
    if top_ips:
        print(f"\nTOP SOURCE IPs ({oid_data.get('unique_sources', len(top_ips))} unique):")
        for i, ip_info in enumerate(top_ips[:10], 1):
            ip = ip_info.get('ip', 'N/A')
            count = ip_info.get('count', 0)
            print(f"  {i:2}. {ip} ({count:,})")
    
    print()
    return 0


def handle_stats_destinations(args: Namespace) -> int:
    """Handle --stats-destinations command."""
    use_json = getattr(args, 'json', False)
    pretty = getattr(args, 'pretty', False)
    
    # Try daemon first
    data = _query_daemon_stats({'action': 'destinations'})
    
    # Fall back to file
    if not data:
        file_data = _get_stats_from_file()
        if file_data:
            data = {'data': file_data.get('top_destinations', [])}
    
    if not data:
        print("Error: Could not retrieve destination statistics.")
        return 1
    
    dests = data.get('data', data.get('top_destinations', []))
    
    if use_json:
        _output_json(dests, pretty)
        return 0
    
    print("\n" + "=" * 60)
    print("  Destination Statistics")
    print("=" * 60 + "\n")
    
    if not dests:
        print("No destination statistics available yet.")
        return 0
    
    for dest in dests:
        print(f"Destination: {dest.get('destination', 'Unknown')}")
        print(f"  Total Forwards:  {dest.get('total_forwarded', 0):>10,}")
        print(f"  Successful:      {dest.get('successful', 0):>10,}")
        print(f"  Failed:          {dest.get('failed', 0):>10,}")
        print(f"  Success Rate:    {dest.get('success_rate', 100):>9.1f}%")
        print(f"  Rate/Minute:     {dest.get('rate_per_minute', 0):>10.2f}")
        
        # Show top sources if available
        top_sources = dest.get('top_sources', [])
        if top_sources:
            print(f"  Top Sources:")
            for src in top_sources[:5]:
                print(f"    - {src.get('ip', 'N/A')}: {src.get('count', 0):,}")
        
        print()
    
    return 0


def handle_stats_dashboard(args: Namespace) -> int:
    """Handle --stats-dashboard command - export full dashboard data."""
    pretty = getattr(args, 'pretty', False)
    
    # Try to get comprehensive dashboard data from daemon
    data = _query_daemon_stats({'action': 'dashboard'})
    
    # Fall back to file
    if not data:
        data = _get_stats_from_file()
    
    if not data:
        print("Error: Could not retrieve dashboard data.")
        return 1
    
    _output_json(data, pretty=True)  # Dashboard always pretty-printed
    return 0


def handle_stats_export(args: Namespace) -> int:
    """Handle --stats-export command."""
    output = getattr(args, 'output', None)
    fmt = getattr(args, 'format', 'json')
    
    # Get data
    if fmt == 'json':
        data = _query_daemon_stats({'action': 'export', 'format': 'json'})
        if not data:
            data = _get_stats_from_file()
        
        if not data:
            print("Error: Could not retrieve statistics for export.")
            return 1
        
        content = json.dumps(data, indent=2, default=str)
    
    elif fmt == 'prometheus':
        # Read Prometheus file directly
        prom_path = "/var/log/trapninja/metrics/trapninja_granular.prom"
        if os.path.exists(prom_path):
            with open(prom_path) as f:
                content = f.read()
        else:
            print("Error: Prometheus metrics file not found.")
            return 1
    
    else:
        print(f"Error: Unknown format '{fmt}'")
        return 1
    
    if output:
        with open(output, 'w') as f:
            f.write(content)
        print(f"Statistics exported to: {output}")
    else:
        print(content)
    
    return 0


def handle_stats_reset(args: Namespace) -> int:
    """Handle --stats-reset command."""
    confirm = getattr(args, 'yes', False)
    
    if not confirm:
        print("WARNING: This will reset ALL granular statistics.")
        print("Statistics will be lost and cannot be recovered.")
        response = input("Type 'yes' to confirm: ")
        if response.lower() != 'yes':
            print("Aborted.")
            return 1
    
    # Send reset command to daemon
    data = _query_daemon_stats({'action': 'reset'})
    
    if data and data.get('status') == 'ok':
        print("Granular statistics have been reset.")
        return 0
    else:
        print("Error: Could not reset statistics.")
        print("Make sure TrapNinja daemon is running.")
        return 1


def handle_stats_help(args: Namespace) -> int:
    """Handle --stats-help command."""
    help_text = """
================================================================================
                    TrapNinja Granular Statistics Help
================================================================================

OVERVIEW
--------
TrapNinja tracks detailed per-IP and per-OID statistics for visualization
and analysis. Statistics are collected in real-time and exported periodically
to JSON and Prometheus formats.

COMMANDS
--------

  --stats-summary           Show overall statistics summary
  --stats-top-ips           Show top source IPs by volume or rate
  --stats-top-oids          Show top OIDs by volume or rate
  --stats-ip --ip <IP>      Show detailed stats for specific IP
  --stats-oid --oid <OID>   Show detailed stats for specific OID
  --stats-destinations      Show destination forward statistics
  --stats-dashboard         Export full dashboard data as JSON
  --stats-export            Export statistics to file
  --stats-reset             Reset all statistics (requires --yes)

OPTIONS
-------

  -n, --count <N>           Number of items to show (default: 10)
  -s, --sort <FIELD>        Sort by: total, rate, blocked, recent
  --json                    Output as JSON
  --pretty                  Pretty-print JSON output
  -f, --format <FMT>        Export format: json, prometheus
  -o, --output <FILE>       Output file for export

EXAMPLES
--------

# Show top 20 source IPs sorted by rate
trapninja --stats-top-ips -n 20 --sort rate

# Get details for a specific IP
trapninja --stats-ip --ip 10.0.0.1

# Export statistics in JSON format
trapninja --stats-export --format json -o /tmp/stats.json

# Get dashboard data for visualization
trapninja --stats-dashboard --pretty

METRICS FILES
-------------

Statistics are exported to:
  - JSON:       /var/log/trapninja/metrics/trapninja_granular.json
  - Prometheus: /var/log/trapninja/metrics/trapninja_granular.prom

Files are updated every 60 seconds.

MEMORY LIMITS
-------------

To prevent unbounded memory growth, statistics are bounded:
  - Max IPs tracked:  10,000 (LRU eviction)
  - Max OIDs tracked:  5,000 (LRU eviction)
  - Stale entries removed after 1 hour of inactivity

================================================================================
"""
    print(help_text)
    return 0
