#!/usr/bin/env python3
"""
TrapNinja Sync Parser - Configuration synchronization subcommands.

Commands: now, status
"""

import textwrap

from .base import TrapNinjaHelpFormatter


def add_sync_subcommands(subparsers):
    """Add config sync subcommands."""
    sync_parser = subparsers.add_parser(
        'sync',
        help='Configuration synchronization (HA)',
        description='Manage configuration sync between HA nodes.',
        formatter_class=TrapNinjaHelpFormatter,
        epilog=textwrap.dedent('''\
            Examples:
              trapninja sync now                 Sync with peer
              trapninja sync status              Show sync status
        ''')
    )
    sync_parser.set_defaults(command_category='sync')

    sync_cmds = sync_parser.add_subparsers(dest='command', metavar='<command>')

    # now (sync)
    sync_now = sync_cmds.add_parser('now', help='Sync configs with peer')
    sync_now.add_argument('--force', action='store_true', help='Force sync')

    # status
    sync_cmds.add_parser('status', help='Show sync status')

    # help
    sync_cmds.add_parser('help', help='Show sync help')
