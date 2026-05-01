#!/usr/bin/env python3
"""
TrapNinja Cache Parser - Trap caching and replay subcommands.

Commands: status, query, replay, clear, trim
"""

import textwrap

from .base import TrapNinjaHelpFormatter


def add_cache_subcommands(subparsers):
    """Add cache management subcommands."""
    cache_parser = subparsers.add_parser(
        'cache',
        help='Trap caching and replay',
        description='Manage the Redis-based trap cache for backfill operations.',
        formatter_class=TrapNinjaHelpFormatter,
        epilog=textwrap.dedent('''\
            Examples:
              trapninja cache status                     Show cache status
              trapninja cache query --destination default --from "-2h" --to now
              trapninja cache replay --destination voice_noc --from "14:30" --to "15:45"
              trapninja cache clear --destination default
        ''')
    )
    cache_parser.set_defaults(command_category='cache')

    cache_cmds = cache_parser.add_subparsers(dest='command', metavar='<command>')

    # status
    cache_cmds.add_parser('status', help='Show cache status')

    # query
    query_cmd = cache_cmds.add_parser('query', help='Query cached traps')
    query_cmd.add_argument('--destination', required=True, help='Destination name')
    query_cmd.add_argument('--from', dest='from_time', required=True,
                           help='Start time')
    query_cmd.add_argument('--to', dest='to_time', required=True, help='End time')
    query_cmd.add_argument('--limit', type=int, default=20,
                           help='Max entries (default: 20)')

    # replay
    replay_cmd = cache_cmds.add_parser('replay', help='Replay cached traps')
    replay_cmd.add_argument('--destination', required=True, help='Destination name')
    replay_cmd.add_argument('--from', dest='from_time', required=True,
                            help='Start time')
    replay_cmd.add_argument('--to', dest='to_time', required=True, help='End time')
    replay_cmd.add_argument('--replay-to', metavar='HOST:PORT',
                            help='Custom replay target')
    replay_cmd.add_argument('--rate-limit', type=int, default=500,
                            help='Max traps/sec')
    replay_cmd.add_argument('--dry-run', action='store_true',
                            help='Preview without sending')
    replay_cmd.add_argument('--oid-filter', help='OID prefix filter')
    replay_cmd.add_argument('--source-filter', help='Source IP filter')
    replay_cmd.add_argument('--exclude-oid', help='OID to exclude')

    # clear
    clear_cmd = cache_cmds.add_parser('clear', help='Clear cached entries')
    clear_cmd.add_argument('--destination', help='Destination to clear')

    # trim
    cache_cmds.add_parser('trim', help='Trigger retention trim')

    # help
    cache_cmds.add_parser('help', help='Show comprehensive cache help')
