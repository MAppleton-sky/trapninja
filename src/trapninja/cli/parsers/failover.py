#!/usr/bin/env python3
"""
TrapNinja Failover Parser - Failover replay subcommands.

Commands: status, detect, replay
"""

import textwrap

from .base import TrapNinjaHelpFormatter


def add_failover_subcommands(subparsers):
    """Add failover replay subcommands."""
    failover_parser = subparsers.add_parser(
        'failover',
        help='Failover replay for zero trap loss',
        description='Manage failover gap detection and replay.',
        formatter_class=TrapNinjaHelpFormatter,
        epilog=textwrap.dedent('''\
            Examples:
              trapninja failover status          Show failover tracking info
              trapninja failover detect          Detect forwarding gaps
              trapninja failover replay          Trigger gap replay
        ''')
    )
    failover_parser.set_defaults(command_category='failover')

    failover_cmds = failover_parser.add_subparsers(dest='command',
                                                     metavar='<command>')

    # status
    failover_cmds.add_parser('status', help='Show failover status')

    # detect
    failover_cmds.add_parser('detect', help='Detect forwarding gaps')

    # replay
    replay_cmd = failover_cmds.add_parser('replay', help='Trigger gap replay')
    replay_cmd.add_argument('--destination',
                            help='Destination (or "detect")')
    replay_cmd.add_argument('--from', dest='from_time', help='Start time')
    replay_cmd.add_argument('--to', dest='to_time', help='End time')
    replay_cmd.add_argument('--rate-limit', type=int, help='Max traps/sec')
    replay_cmd.add_argument('--dry-run', action='store_true',
                            help='Preview only')

    # help
    failover_cmds.add_parser('help', help='Show failover replay help')
