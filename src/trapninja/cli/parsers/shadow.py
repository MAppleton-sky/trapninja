#!/usr/bin/env python3
"""
TrapNinja Shadow Parser - Shadow/mirror mode subcommands.

Commands: status, export
"""

import textwrap

from .base import TrapNinjaHelpFormatter


def add_shadow_subcommands(subparsers):
    """Add shadow/mirror mode subcommands."""
    shadow_parser = subparsers.add_parser(
        'shadow',
        help='Shadow/mirror mode for testing',
        description='Run in observation or parallel testing modes.',
        formatter_class=TrapNinjaHelpFormatter,
        epilog=textwrap.dedent('''\
            Examples:
              trapninja shadow status            Show shadow mode statistics
              trapninja shadow export            Export statistics to JSON

            Running Shadow/Parallel Modes:
              trapninja daemon start --shadow-mode    Background shadow mode (observe only)
              trapninja daemon start --mirror-mode    Background mirror mode (parallel capture)
              trapninja daemon start --parallel       Background parallel operation
              trapninja daemon foreground --shadow-mode   Foreground shadow mode
        ''')
    )
    shadow_parser.set_defaults(command_category='shadow')

    shadow_cmds = shadow_parser.add_subparsers(dest='command', metavar='<command>')

    # status
    shadow_cmds.add_parser('status', help='Show shadow mode statistics')

    # export
    shadow_cmds.add_parser('export', help='Export statistics to JSON')

    # help
    shadow_cmds.add_parser('help', help='Show shadow mode help')
