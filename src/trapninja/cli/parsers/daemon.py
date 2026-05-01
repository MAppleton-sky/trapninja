#!/usr/bin/env python3
"""
TrapNinja Daemon Parser - Service control subcommands.

Commands: start, stop, restart, status, foreground, config, queue-stats
"""

import argparse
import textwrap

from .base import TrapNinjaHelpFormatter


def add_daemon_subcommands(subparsers):
    """Add daemon control subcommands."""
    daemon_parser = subparsers.add_parser(
        'daemon',
        help='Service control commands',
        description='Control the TrapNinja daemon service.',
        formatter_class=TrapNinjaHelpFormatter,
        epilog=textwrap.dedent('''\
            Examples:
              trapninja daemon start              Start as background daemon
              trapninja daemon start --debug      Start with debug logging
              trapninja daemon start --shadow-mode   Start in shadow mode (observe only)
              trapninja daemon start --mirror-mode   Start in mirror mode (parallel capture)
              trapninja daemon start --parallel      Start with sniff capture for coexistence
              trapninja daemon foreground         Run in foreground
              trapninja daemon status             Check if running
              trapninja daemon config             Show configuration
        ''')
    )
    daemon_parser.set_defaults(command_category='daemon')

    daemon_cmds = daemon_parser.add_subparsers(dest='command', metavar='<command>')

    # start
    start_cmd = daemon_cmds.add_parser('start', help='Start the daemon')
    start_cmd.add_argument('--interface', type=str, help='Network interface')
    start_cmd.add_argument('--ports', type=str, help='Comma-separated UDP ports')
    _add_shadow_mode_options(start_cmd)
    _add_logging_options(start_cmd)

    # stop
    daemon_cmds.add_parser('stop', help='Stop the daemon')

    # restart
    restart_cmd = daemon_cmds.add_parser('restart', help='Restart the daemon')
    restart_cmd.add_argument('--interface', type=str, help='Network interface')
    restart_cmd.add_argument('--ports', type=str, help='Comma-separated UDP ports')
    _add_shadow_mode_options(restart_cmd)
    _add_logging_options(restart_cmd)

    # status
    daemon_cmds.add_parser('status', help='Check daemon status')

    # foreground
    fg_cmd = daemon_cmds.add_parser('foreground',
                                     help='Run in foreground (not as daemon)')
    fg_cmd.add_argument('--interface', type=str, help='Network interface')
    fg_cmd.add_argument('--ports', type=str, help='Comma-separated UDP ports')
    _add_shadow_mode_options(fg_cmd)
    _add_logging_options(fg_cmd)

    # config
    config_cmd = daemon_cmds.add_parser('config', help='Show current configuration')
    config_cmd.add_argument('--validate', action='store_true',
                            help='Validate configuration without starting')

    # queue-stats
    daemon_cmds.add_parser('queue-stats', help='Show packet queue statistics')

    # help
    daemon_cmds.add_parser('help', help='Show daemon command help')


def _add_shadow_mode_options(parser: argparse.ArgumentParser):
    """Add shadow/parallel mode options to a parser."""
    shadow_group = parser.add_argument_group('Shadow/Parallel Mode Options')
    shadow_group.add_argument('--shadow-mode', action='store_true',
                              help='Run in shadow mode (observe only, no forwarding)')
    shadow_group.add_argument('--mirror-mode', action='store_true',
                              help='Run in mirror mode (parallel capture and forward)')
    shadow_group.add_argument('--parallel', action='store_true',
                              help='Enable parallel operation (sniff capture)')
    shadow_group.add_argument('--capture-mode', choices=['auto', 'sniff', 'socket'],
                              help='Packet capture mode')
    shadow_group.add_argument('--log-traps', type=str, metavar='FILE',
                              help='Log observed traps to file')


def _add_logging_options(parser: argparse.ArgumentParser):
    """Add logging configuration options to a parser."""
    log_group = parser.add_argument_group('Logging Options')
    log_group.add_argument('--log-level',
                           choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                           help='Set logging level')
    log_group.add_argument('--log-max-size', type=str, metavar='SIZE',
                           help='Max log file size (e.g., "10M", "1G")')
    log_group.add_argument('--log-backup-count', type=int, metavar='COUNT',
                           help='Number of backup log files')
    log_group.add_argument('--log-compress', action='store_true',
                           help='Compress rotated log files')
