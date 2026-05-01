#!/usr/bin/env python3
"""
TrapNinja Stats Parser - Statistics and monitoring subcommands.

Commands: summary, top-ips, top-oids, ip, oid, destinations,
          dashboard, export, reset, debug
"""

import argparse
import textwrap

from .base import TrapNinjaHelpFormatter, validated_ip, validated_oid


def add_stats_subcommands(subparsers):
    """Add statistics subcommands."""
    stats_parser = subparsers.add_parser(
        'stats',
        help='Granular statistics and monitoring',
        description='View and export detailed trap statistics.',
        formatter_class=TrapNinjaHelpFormatter,
        epilog=textwrap.dedent('''\
            Examples:
              trapninja stats summary               Overview of all statistics
              trapninja stats top-ips -n 20         Top 20 source IPs
              trapninja stats top-oids -s rate      Top OIDs by rate
              trapninja stats ip 10.0.0.1           Details for specific IP
              trapninja stats oid 1.3.6.1.4.1.9     Details for specific OID
              trapninja stats export -f prometheus  Export for Prometheus
        ''')
    )
    stats_parser.set_defaults(command_category='stats')

    stats_cmds = stats_parser.add_subparsers(dest='command', metavar='<command>')

    # summary
    stats_cmds.add_parser('summary', help='Show statistics summary')

    # top-ips
    top_ips = stats_cmds.add_parser('top-ips', help='Show top source IPs')
    _add_stats_display_options(top_ips)

    # top-oids
    top_oids = stats_cmds.add_parser('top-oids', help='Show top OIDs')
    _add_stats_display_options(top_oids)

    # ip
    ip_detail = stats_cmds.add_parser('ip', help='Show details for IP')
    ip_detail.add_argument('ip', type=validated_ip, help='IP address to query')
    ip_detail.add_argument('--oids', type=int, default=10,
                           help='Top OIDs to show (default: 10, max: 500)')

    # oid
    oid_detail = stats_cmds.add_parser('oid', help='Show details for OID')
    oid_detail.add_argument('oid', type=validated_oid, help='OID to query')
    oid_detail.add_argument('--sources', type=int, default=10,
                            help='Top sources to show (default: 10, max: 500)')

    # destinations
    stats_cmds.add_parser('destinations', help='Show destination statistics')

    # dashboard
    stats_cmds.add_parser('dashboard', help='Export dashboard data as JSON')

    # export
    export_cmd = stats_cmds.add_parser('export', help='Export statistics')
    export_cmd.add_argument('-f', '--format', choices=['json', 'prometheus'],
                            default='json', help='Export format')
    export_cmd.add_argument('-o', '--output', help='Output file')

    # reset
    stats_cmds.add_parser('reset', help='Reset all statistics')

    # debug
    stats_cmds.add_parser('debug', help='Show diagnostic info')

    # help
    stats_cmds.add_parser('help', help='Show statistics help')


def _add_stats_display_options(parser: argparse.ArgumentParser):
    """Add common stats display options."""
    parser.add_argument('-n', '--count', type=int, default=10,
                        help='Number of items')
    parser.add_argument('-s', '--sort',
                        choices=['total', 'rate', 'peak', 'blocked', 'recent'],
                        default='total', help='Sort order')
