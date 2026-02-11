#!/usr/bin/env python3
"""
TrapNinja HA Parser - High Availability subcommands.

Commands: configure, status, promote, demote, force-failover, disable
"""

import textwrap

from .base import TrapNinjaHelpFormatter, validated_ip, validated_port


def add_ha_subcommands(subparsers):
    """Add High Availability subcommands."""
    ha_parser = subparsers.add_parser(
        'ha',
        help='High Availability configuration',
        description='Configure and manage High Availability clustering.',
        formatter_class=TrapNinjaHelpFormatter,
        epilog=textwrap.dedent('''\
            Examples:
              trapninja ha configure --mode primary --peer 192.168.1.102
              trapninja ha status              Check HA status
              trapninja ha promote             Promote to PRIMARY
              trapninja ha demote              Demote to SECONDARY
              trapninja ha disable             Disable HA
        ''')
    )
    ha_parser.set_defaults(command_category='ha')

    ha_cmds = ha_parser.add_subparsers(dest='command', metavar='<command>')

    # configure
    configure_cmd = ha_cmds.add_parser('configure', help='Configure HA')
    configure_cmd.add_argument('--mode', choices=['primary', 'secondary'],
                               required=True, help='HA mode')
    configure_cmd.add_argument('--peer', '--peer-host', type=validated_ip,
                               required=True, dest='ha_peer_host',
                               help='Peer IP address')
    configure_cmd.add_argument('--peer-port', type=validated_port, default=8162,
                               help='Peer port (default: 8162)')
    configure_cmd.add_argument('--listen-port', type=validated_port, default=8162,
                               help='Listen port (default: 8162)')
    configure_cmd.add_argument('--priority', type=int, default=100,
                               help='Priority 1-1000 (default: 100)')

    # status
    ha_cmds.add_parser('status', help='Show HA status')

    # promote
    promote_cmd = ha_cmds.add_parser('promote', help='Promote to PRIMARY')
    promote_cmd.add_argument('--force', action='store_true',
                             help='Force without peer coordination')

    # demote
    ha_cmds.add_parser('demote', help='Demote to SECONDARY')

    # force-failover
    ha_cmds.add_parser('force-failover', help='Force failover (maintenance)')

    # disable
    ha_cmds.add_parser('disable', help='Disable HA')

    # help
    ha_cmds.add_parser('help', help='Show comprehensive HA help')
