#!/usr/bin/env python3
"""
TrapNinja CLI - Granular Statistics Commands

Commands for viewing detailed per-IP and per-OID statistics.

Author: TrapNinja Team
Version: 1.0.0
"""

import argparse
import json
import sys
from datetime import datetime
from typing import Optional


def add_stats_parser(subparsers):
    """Add stats subcommand parser."""
    parser = subparsers.add_parser(
        'stats',
        help='View granular statistics (per-IP, per-OID)',
        description='View detailed statistics by source IP, OID, or destination'
    )
    
    # Create sub-subparsers for stats commands
    stats_sub = parser.add_subparsers(dest='stats_cmd', help='Statistics commands')
    
    # stats summary
    summary_parser = stats_sub.add_parser('summary', help='Show statistics summary')
    summary_parser.add_argument('--json', action='store_true', help='Output as JSON')
    
    # stats top-ips
    top_ips_parser = stats_sub.add_parser('top-ips', help='Show top source IPs')
    top_ips_parser.add_argument('-n', '--count', type=int, default=20, 
                                help='Number of IPs to show (default: 20)')
    top_ips_parser.add_argument('--sort', choices=['total', 'rate', 'blocked', 'recent'],
                                default='total', help='Sort by (default: total)')
    top_ips_parser.add_argument('--json', action='store_true', help='Output as JSON')
    
    # stats top-oids
    top_oids_parser = stats_sub.add_parser('top-oids', help='Show top OIDs')
    top_oids_parser.add_argument('-n', '--count', type=int, default=20,
                                 help='Number of OIDs to show (default: 20)')
    top_oids_parser.add_argument('--sort', choices=['total', 'rate', 'blocked', 'recent'],
                                 default='total', help='Sort by (default: total)')
    top_oids_parser.add_argument('--json', action='store_true', help='Output as JSON')
    
    # stats ip <ip>
    ip_parser = stats_sub.add_parser('ip', help='Show details for specific IP')
    ip_parser.add_argument('ip_address', help='IP address to query')
    ip_parser.add_argument('--json', action='store_true', help='Output as JSON')
    
    # stats oid <oid>
    oid_parser = stats_sub.add_parser('oid', help='Show details for specific OID')
    oid_parser.add_argument('oid', help='OID to query')
    oid_parser.add_argument('--json', action='store_true', help='Output as JSON')
    
    # stats destinations
    dest_parser = stats_sub.add_parser('destinations', help='Show destination statistics')
    dest_parser.add_argument('--json', action='store_true', help='Output as JSON')
    
    # stats search
    search_parser = stats_sub.add_parser('search', help='Search IPs or OIDs')
    search_parser.add_argument('type', choices=['ip', 'oid'], help='Search type')
    search_parser.add_argument('pattern', help='Pattern to search (prefix match)')
    search_parser.add_argument('-n', '--count', type=int, default=50,
                               help='Maximum results (default: 50)')
    search_parser.add_argument('--json', action='store_true', help='Output as JSON')
    
    # stats export
    export_parser = stats_sub.add_parser('export', help='Export full statistics')
    export_parser.add_argument('-o', '--output', help='Output file (default: stdout)')
    export_parser.add_argument('--format', choices=['json', 'prometheus'], default='json',
                               help='Export format (default: json)')
    
    # stats reset
    reset_parser = stats_sub.add_parser('reset', help='Reset all statistics')
    reset_parser.add_argument('--confirm', action='store_true', required=True,
                              help='Confirm reset')
    
    return parser


def handle_stats(args) -> int:
    """Handle stats commands."""
    if not hasattr(args, 'stats_cmd') or args.stats_cmd is None:
        print("Usage: trapninja stats <command>")
        print("\nCommands:")
        print("  summary        Show statistics summary")
        print("  top-ips        Show top source IPs")
        print("  top-oids       Show top OIDs")
        print("  ip <addr>      Show details for specific IP")
        print("  oid <oid>      Show details for specific OID")
        print("  destinations   Show destination statistics")
        print("  search         Search IPs or OIDs")
        print("  export         Export full statistics")
        print("  reset          Reset all statistics")
        return 1
    
    # Try to get stats from running daemon via socket
    stats_data = _query_daemon_stats(args)
    
    if stats_data is None:
        # Fall back to reading from file
        stats_data = _read_stats_file(args)
    
    if stats_data is None:
        print("Error: Could not retrieve statistics.")
        print("Make sure TrapNinja is running or check metrics files.")
        return 1
    
    return _display_stats(args, stats_data)


def _query_daemon_stats(args) -> Optional[dict]:
    """Query running daemon for stats via Unix socket."""
    import socket
    import os
    
    socket_path = "/var/run/trapninja/control.sock"
    if not os.path.exists(socket_path):
        return None
    
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        sock.connect(socket_path)
        
        # Build command based on stats_cmd
        cmd = {'command': 'stats', 'subcommand': args.stats_cmd}
        
        if args.stats_cmd == 'top-ips':
            cmd['count'] = getattr(args, 'count', 20)
            cmd['sort_by'] = getattr(args, 'sort', 'total')
        elif args.stats_cmd == 'top-oids':
            cmd['count'] = getattr(args, 'count', 20)
            cmd['sort_by'] = getattr(args, 'sort', 'total')
        elif args.stats_cmd == 'ip':
            cmd['ip_address'] = args.ip_address
        elif args.stats_cmd == 'oid':
            cmd['oid'] = args.oid
        elif args.stats_cmd == 'search':
            cmd['search_type'] = args.type
            cmd['pattern'] = args.pattern
            cmd['limit'] = getattr(args, 'count', 50)
        
        sock.sendall((json.dumps(cmd) + '\n').encode())
        
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
        
    except Exception as e:
        return None


def _read_stats_file(args) -> Optional[dict]:
    """Read stats from JSON file."""
    import os
    
    json_path = "/var/log/trapninja/metrics/trapninja_granular.json"
    
    if not os.path.exists(json_path):
        return None
    
    try:
        with open(json_path) as f:
            data = json.load(f)
        
        # Wrap in structure expected by display functions
        return {
            'source': 'file',
            'data': data
        }
    except Exception:
        return None


def _display_stats(args, stats_data: dict) -> int:
    """Display statistics based on command."""
    cmd = args.stats_cmd
    use_json = getattr(args, 'json', False)
    
    # Handle file-based data
    if stats_data.get('source') == 'file':
        data = stats_data.get('data', {})
        if cmd == 'summary':
            return _display_summary_from_file(data, use_json)
        elif cmd == 'top-ips':
            return _display_top_ips_from_file(data, getattr(args, 'count', 20), use_json)
        elif cmd == 'top-oids':
            return _display_top_oids_from_file(data, getattr(args, 'count', 20), use_json)
        elif cmd == 'destinations':
            return _display_destinations_from_file(data, use_json)
        else:
            print(f"Command '{cmd}' requires running daemon for real-time data.")
            return 1
    
    # Handle daemon response
    if stats_data.get('status') == 'error':
        print(f"Error: {stats_data.get('message', 'Unknown error')}")
        return 1
    
    data = stats_data.get('data', stats_data)
    
    if use_json:
        print(json.dumps(data, indent=2))
        return 0
    
    if cmd == 'summary':
        _display_summary(data)
    elif cmd == 'top-ips':
        _display_top_ips(data)
    elif cmd == 'top-oids':
        _display_top_oids(data)
    elif cmd == 'ip':
        _display_ip_details(data)
    elif cmd == 'oid':
        _display_oid_details(data)
    elif cmd == 'destinations':
        _display_destinations(data)
    elif cmd == 'search':
        _display_search_results(data)
    elif cmd == 'export':
        return _handle_export(args, data)
    elif cmd == 'reset':
        print("Statistics reset successfully.")
    
    return 0


def _display_summary(data: dict):
    """Display summary statistics."""
    print("\n=== TrapNinja Statistics Summary ===\n")
    
    totals = data.get('totals', data.get('summary', {}))
    counts = data.get('counts', {})
    rates = data.get('rates', {})
    
    print("Totals:")
    print(f"  Total Traps:     {totals.get('traps', totals.get('total_traps', 0)):,}")
    print(f"  Forwarded:       {totals.get('forwarded', totals.get('total_forwarded', 0)):,}")
    print(f"  Blocked:         {totals.get('blocked', totals.get('total_blocked', 0)):,}")
    print(f"  Redirected:      {totals.get('redirected', totals.get('total_redirected', 0)):,}")
    print(f"  Dropped:         {totals.get('dropped', totals.get('total_dropped', 0)):,}")
    
    print("\nCounts:")
    print(f"  Unique IPs:      {counts.get('unique_ips', 0):,}")
    print(f"  Unique OIDs:     {counts.get('unique_oids', 0):,}")
    print(f"  Destinations:    {counts.get('destinations', 0)}")
    
    print("\nRates:")
    print(f"  Per Second:      {rates.get('per_second', 0):.2f}")
    print(f"  Per Minute:      {rates.get('per_minute', 0):.2f}")
    print(f"  Per Hour:        {rates.get('per_hour', 0):.2f}")
    
    limits = data.get('limits', {})
    if limits:
        print("\nMemory Usage:")
        print(f"  IP Tracking:     {limits.get('ip_usage', 'N/A')}")
        print(f"  OID Tracking:    {limits.get('oid_usage', 'N/A')}")
    
    print()


def _display_summary_from_file(data: dict, use_json: bool) -> int:
    """Display summary from file data."""
    if use_json:
        print(json.dumps(data.get('summary', {}), indent=2))
        return 0
    
    _display_summary(data)
    return 0


def _display_top_ips(data: list):
    """Display top IPs table."""
    print("\n=== Top Source IPs ===\n")
    
    if not data:
        print("No IP statistics available.")
        return
    
    # Header
    print(f"{'IP Address':<20} {'Total':>10} {'Fwd':>8} {'Blk':>8} {'Rate/min':>10} {'Last Seen':<20}")
    print("-" * 80)
    
    for ip in data:
        last_seen = ip.get('last_seen', '')
        if last_seen and 'T' in last_seen:
            # Parse ISO format
            try:
                dt = datetime.fromisoformat(last_seen.replace('Z', '+00:00'))
                last_seen = dt.strftime('%Y-%m-%d %H:%M:%S')
            except:
                pass
        
        print(f"{ip.get('ip_address', 'N/A'):<20} "
              f"{ip.get('total_traps', 0):>10,} "
              f"{ip.get('forwarded', 0):>8,} "
              f"{ip.get('blocked', 0):>8,} "
              f"{ip.get('rate_per_minute', 0):>10.2f} "
              f"{last_seen:<20}")
    
    print()


def _display_top_ips_from_file(data: dict, count: int, use_json: bool) -> int:
    """Display top IPs from file data."""
    ips = data.get('top_ips', [])[:count]
    
    if use_json:
        print(json.dumps(ips, indent=2))
        return 0
    
    _display_top_ips(ips)
    return 0


def _display_top_oids(data: list):
    """Display top OIDs table."""
    print("\n=== Top OIDs ===\n")
    
    if not data:
        print("No OID statistics available.")
        return
    
    # Header
    print(f"{'OID':<45} {'Total':>10} {'Rate/min':>10} {'Sources':>8}")
    print("-" * 80)
    
    for oid in data:
        oid_str = oid.get('oid', 'N/A')
        # Truncate long OIDs
        if len(oid_str) > 43:
            oid_str = oid_str[:40] + '...'
        
        print(f"{oid_str:<45} "
              f"{oid.get('total_traps', 0):>10,} "
              f"{oid.get('rate_per_minute', 0):>10.2f} "
              f"{oid.get('unique_sources', 0):>8}")
    
    print()


def _display_top_oids_from_file(data: dict, count: int, use_json: bool) -> int:
    """Display top OIDs from file data."""
    oids = data.get('top_oids', [])[:count]
    
    if use_json:
        print(json.dumps(oids, indent=2))
        return 0
    
    _display_top_oids(oids)
    return 0


def _display_ip_details(data: dict):
    """Display detailed IP statistics."""
    if not data:
        print("IP not found in statistics.")
        return
    
    print(f"\n=== Statistics for {data.get('ip_address', 'Unknown')} ===\n")
    
    print("Counts:")
    print(f"  Total Traps:   {data.get('total_traps', 0):,}")
    print(f"  Forwarded:     {data.get('forwarded', 0):,}")
    print(f"  Blocked:       {data.get('blocked', 0):,}")
    print(f"  Redirected:    {data.get('redirected', 0):,}")
    print(f"  Dropped:       {data.get('dropped', 0):,}")
    
    print("\nTiming:")
    print(f"  First Seen:    {data.get('first_seen', 'N/A')}")
    print(f"  Last Seen:     {data.get('last_seen', 'N/A')}")
    print(f"  Age:           {data.get('age_seconds', 0):.0f} seconds")
    print(f"  Idle:          {data.get('idle_seconds', 0):.0f} seconds")
    
    print("\nRates:")
    print(f"  Per Second:    {data.get('rate_per_second', 0):.4f}")
    print(f"  Per Minute:    {data.get('rate_per_minute', 0):.2f}")
    
    top_oids = data.get('top_oids', [])
    if top_oids:
        print(f"\nTop OIDs ({data.get('unique_oids', 0)} unique):")
        for i, oid_info in enumerate(top_oids[:10], 1):
            oid = oid_info.get('oid', 'N/A')
            count = oid_info.get('count', 0)
            print(f"  {i:2}. {oid} ({count:,})")
    
    destinations = data.get('destinations', {})
    if destinations:
        print("\nDestinations:")
        for dest, count in destinations.items():
            print(f"  {dest}: {count:,}")
    
    print()


def _display_oid_details(data: dict):
    """Display detailed OID statistics."""
    if not data:
        print("OID not found in statistics.")
        return
    
    print(f"\n=== Statistics for OID ===")
    print(f"OID: {data.get('oid', 'Unknown')}\n")
    
    print("Counts:")
    print(f"  Total Traps:   {data.get('total_traps', 0):,}")
    print(f"  Forwarded:     {data.get('forwarded', 0):,}")
    print(f"  Blocked:       {data.get('blocked', 0):,}")
    print(f"  Redirected:    {data.get('redirected', 0):,}")
    print(f"  Dropped:       {data.get('dropped', 0):,}")
    
    print("\nTiming:")
    print(f"  First Seen:    {data.get('first_seen', 'N/A')}")
    print(f"  Last Seen:     {data.get('last_seen', 'N/A')}")
    
    print("\nRates:")
    print(f"  Per Second:    {data.get('rate_per_second', 0):.4f}")
    print(f"  Per Minute:    {data.get('rate_per_minute', 0):.2f}")
    
    top_ips = data.get('top_source_ips', [])
    if top_ips:
        print(f"\nTop Source IPs ({data.get('unique_sources', 0)} unique):")
        for i, ip_info in enumerate(top_ips[:10], 1):
            ip = ip_info.get('ip', 'N/A')
            count = ip_info.get('count', 0)
            print(f"  {i:2}. {ip} ({count:,})")
    
    print()


def _display_destinations(data: list):
    """Display destination statistics."""
    print("\n=== Destination Statistics ===\n")
    
    if not data:
        print("No destination statistics available.")
        return
    
    for dest in data:
        print(f"Destination: {dest.get('destination', 'Unknown')}")
        print(f"  Total Forwards:  {dest.get('total_forwarded', 0):,}")
        print(f"  Successful:      {dest.get('successful', 0):,}")
        print(f"  Failed:          {dest.get('failed', 0):,}")
        print(f"  Success Rate:    {dest.get('success_rate', 100):.1f}%")
        print(f"  Rate/Minute:     {dest.get('rate_per_minute', 0):.2f}")
        print()


def _display_destinations_from_file(data: dict, use_json: bool) -> int:
    """Display destinations from file data."""
    dests = data.get('top_destinations', [])
    
    if use_json:
        print(json.dumps(dests, indent=2))
        return 0
    
    _display_destinations(dests)
    return 0


def _display_search_results(data: list):
    """Display search results."""
    print(f"\n=== Search Results ({len(data)} matches) ===\n")
    
    if not data:
        print("No matches found.")
        return
    
    for item in data:
        if 'ip_address' in item:
            print(f"  {item['ip_address']}: {item.get('total_traps', 0):,} traps, "
                  f"{item.get('rate_per_minute', 0):.2f}/min")
        elif 'oid' in item:
            print(f"  {item['oid']}: {item.get('total_traps', 0):,} traps")
    
    print()


def _handle_export(args, data: dict) -> int:
    """Handle export command."""
    output = getattr(args, 'output', None)
    fmt = getattr(args, 'format', 'json')
    
    if fmt == 'json':
        content = json.dumps(data, indent=2)
    else:
        # Prometheus format would be handled by daemon
        content = str(data)
    
    if output:
        with open(output, 'w') as f:
            f.write(content)
        print(f"Exported to {output}")
    else:
        print(content)
    
    return 0


# Entry point for direct execution
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='TrapNinja Statistics')
    subparsers = parser.add_subparsers(dest='command')
    add_stats_parser(subparsers)
    
    args = parser.parse_args()
    sys.exit(handle_stats(args))
