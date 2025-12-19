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
    # Match the socket path used by control.py
    socket_path = "/tmp/trapninja_control.sock"
    
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
            # Response is complete when we get valid JSON
            try:
                json.loads(response.decode())
                break
            except json.JSONDecodeError:
                continue
        
        sock.close()
        
        result = json.loads(response.decode().strip())
        
        # Check if request was successful
        if result.get('status') == 0:  # SUCCESS
            # Return data if present, otherwise return the message or full result
            return result.get('data') or result.get('message') or result
        else:
            return None
        
    except Exception:
        return None


def _output_json(data: Any, pretty: bool = False):
    """Output data as JSON."""
    if pretty:
        print(json.dumps(data, indent=2, default=str))
    else:
        print(json.dumps(data, default=str))


def _format_timestamp(ts) -> str:
    """Format timestamp for display. Accepts float (Unix) or string (ISO) timestamps."""
    if not ts:
        return 'N/A'
    
    try:
        # Handle float (Unix timestamp)
        if isinstance(ts, (int, float)):
            dt = datetime.fromtimestamp(ts)
            return dt.strftime('%Y-%m-%d %H:%M:%S')
        
        # Handle ISO string
        if isinstance(ts, str):
            if 'T' in ts:
                dt = datetime.fromisoformat(ts.replace('Z', '+00:00'))
                return dt.strftime('%Y-%m-%d %H:%M:%S')
            # Already formatted or unknown format
            return ts
        
        return str(ts)
    except Exception:
        return str(ts) if ts else 'N/A'


def _format_duration(seconds: float) -> str:
    """Format duration in seconds to human-readable string."""
    if not seconds or seconds <= 0:
        return '0s'
    
    seconds = int(seconds)
    
    days = seconds // 86400
    hours = (seconds % 86400) // 3600
    minutes = (seconds % 3600) // 60
    secs = seconds % 60
    
    parts = []
    if days > 0:
        parts.append(f"{days}d")
    if hours > 0:
        parts.append(f"{hours}h")
    if minutes > 0:
        parts.append(f"{minutes}m")
    if secs > 0 or not parts:
        parts.append(f"{secs}s")
    
    return ' '.join(parts)


def _get_collection_period() -> tuple:
    """
    Get collection period info from daemon or file.
    
    Returns:
        tuple: (started_timestamp, uptime_seconds) or (None, None) if unavailable
    """
    # Try daemon first
    data = _query_daemon_stats({'action': 'summary'})
    
    # Fall back to file
    if data is None:
        data = _get_stats_from_file()
    
    if not data:
        return None, None
    
    summary = data.get('summary', data)
    started = summary.get('collection_started', data.get('collection_started'))
    uptime = summary.get('uptime_seconds', data.get('uptime_seconds', 0))
    
    return started, uptime


def _print_collection_header(title: str):
    """
    Print a stats header with collection period info.
    
    Args:
        title: The title to display
    """
    started, uptime = _get_collection_period()
    
    if uptime and uptime > 0:
        period_str = f" (collected over {_format_duration(uptime)})"
    else:
        period_str = ""
    
    print(f"\n" + "=" * 90)
    print(f"  {title}{period_str}")
    print("=" * 90 + "\n")


def _sort_stats_list(stats_list: List[Dict], sort_by: str) -> List[Dict]:
    """Sort a list of stats dictionaries by the specified field."""
    if not stats_list:
        return stats_list
    
    if sort_by == 'total':
        return sorted(stats_list, key=lambda x: x.get('total_traps', 0), reverse=True)
    elif sort_by == 'rate':
        return sorted(stats_list, key=lambda x: x.get('rate_per_minute', 0), reverse=True)
    elif sort_by == 'blocked':
        return sorted(stats_list, key=lambda x: x.get('blocked', 0), reverse=True)
    elif sort_by == 'recent':
        return sorted(stats_list, key=lambda x: x.get('last_seen', ''), reverse=True)
    else:
        return stats_list


# =============================================================================
# COMMAND HANDLERS
# =============================================================================

def handle_stats_summary(args: Namespace) -> int:
    """Handle --stats-summary command."""
    use_json = getattr(args, 'json', False)
    pretty = getattr(args, 'pretty', False)
    
    # Try daemon first - returns summary dict directly on success
    data = _query_daemon_stats({'action': 'summary'})
    
    # Fall back to file if daemon query failed
    if data is None:
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
    averages = summary.get('averages', {})
    
    # Collection period information
    uptime_seconds = summary.get('uptime_seconds', data.get('uptime_seconds', 0))
    collection_started = summary.get('collection_started', data.get('collection_started'))
    
    print("COLLECTION PERIOD:")
    if collection_started:
        print(f"  Started:           {_format_timestamp(collection_started)}")
    print(f"  Duration:          {_format_duration(uptime_seconds)}")
    
    print("\nTOTALS:")
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
        print("\nCURRENT RATES (last minute):")
        print(f"  Per Second:        {rates.get('per_second', 0):>12.2f}")
        print(f"  Per Minute:        {rates.get('per_minute', 0):>12.2f}")
        print(f"  Per Hour:          {rates.get('per_hour', 0):>12.2f}")
    
    if averages:
        print(f"\nAVERAGE RATES (over {_format_duration(uptime_seconds)}):")
        print(f"  Per Second:        {averages.get('traps_per_second', 0):>12.2f}")
        print(f"  Per Minute:        {averages.get('traps_per_minute', 0):>12.2f}")
        print(f"  Per Hour:          {averages.get('traps_per_hour', 0):>12.2f}")
    
    limits = data.get('limits', summary.get('limits', {}))
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
    
    # Try daemon first - returns list directly on success
    ips = _query_daemon_stats({
        'action': 'top_ips',
        'count': count,
        'sort_by': sort_by
    })
    
    # Fall back to file if daemon query failed
    if ips is None:
        file_data = _get_stats_from_file()
        if file_data:
            # File data needs to be sorted since it's pre-sorted by 'total'
            ip_list = file_data.get('top_ips', [])
            ips = _sort_stats_list(ip_list, sort_by)[:count]
    
    if not ips:
        print("Error: Could not retrieve IP statistics.")
        print("Make sure TrapNinja is running with granular stats enabled.")
        return 1
    
    if use_json:
        _output_json(ips, pretty)
        return 0
    
    _print_collection_header(f"Top {count} Source IPs (sorted by {sort_by})")
    
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
    
    # Try daemon first - returns list directly on success
    oids = _query_daemon_stats({
        'action': 'top_oids',
        'count': count,
        'sort_by': sort_by
    })
    
    # Fall back to file if daemon query failed
    if oids is None:
        file_data = _get_stats_from_file()
        if file_data:
            # File data needs to be sorted since it's pre-sorted by 'total'
            oid_list = file_data.get('top_oids', [])
            oids = _sort_stats_list(oid_list, sort_by)[:count]
    
    if not oids:
        print("Error: Could not retrieve OID statistics.")
        print("Make sure TrapNinja is running with granular stats enabled.")
        return 1
    
    if use_json:
        _output_json(oids, pretty)
        return 0
    
    _print_collection_header(f"Top {count} OIDs (sorted by {sort_by})")
    
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
    
    if not ip_address:
        print("Error: IP address required. Use --ip <address>")
        return 1
    
    # Query daemon for real-time data - returns IP data dict directly on success
    ip_data = _query_daemon_stats({
        'action': 'ip_detail',
        'ip_address': ip_address
    })
    
    if ip_data is None:
        print(f"Error: IP address '{ip_address}' not found in statistics.")
        print("Note: Only IPs that have sent traps since last restart are tracked.")
        return 1
    
    if use_json:
        _output_json(ip_data, pretty)
        return 0
    
    started, uptime = _get_collection_period()
    period_info = f" (stats from last {_format_duration(uptime)})" if uptime else ""
    
    print("\n" + "=" * 60)
    print(f"  Statistics for IP: {ip_address}{period_info}")
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
    
    if not oid:
        print("Error: OID required. Use --oid <oid>")
        return 1
    
    # Query daemon for real-time data - returns OID data dict directly on success
    oid_data = _query_daemon_stats({
        'action': 'oid_detail',
        'oid': oid
    })
    
    if oid_data is None:
        print(f"Error: OID '{oid}' not found in statistics.")
        print("Note: Only OIDs that have been seen since last restart are tracked.")
        return 1
    
    if use_json:
        _output_json(oid_data, pretty)
        return 0
    
    started, uptime = _get_collection_period()
    period_info = f" (stats from last {_format_duration(uptime)})" if uptime else ""
    
    print("\n" + "=" * 60)
    print(f"  Statistics for OID{period_info}")
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
    
    # Try daemon first - returns list directly on success
    dests = _query_daemon_stats({'action': 'destinations'})
    
    # Fall back to file if daemon query failed
    if dests is None:
        file_data = _get_stats_from_file()
        if file_data:
            dests = file_data.get('top_destinations', [])
    
    if not dests:
        print("Error: Could not retrieve destination statistics.")
        print("Make sure TrapNinja is running with granular stats enabled.")
        return 1
    
    if use_json:
        _output_json(dests, pretty)
        return 0
    
    _print_collection_header("Destination Statistics")
    
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
    
    # Fall back to file if daemon query failed
    if data is None:
        data = _get_stats_from_file()
    
    if not data:
        print("Error: Could not retrieve dashboard data.")
        print("Make sure TrapNinja is running with granular stats enabled.")
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
    
    # Send reset command to daemon - returns message on success
    result = _query_daemon_stats({'action': 'reset'})
    
    if result is not None:
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
