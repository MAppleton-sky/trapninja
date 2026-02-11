#!/usr/bin/env python3
"""
TrapNinja Metrics Parser - Prometheus metrics configuration subcommands.

Commands: config, set-dir, add-label, remove-label, set-interval
"""

import textwrap

from .base import TrapNinjaHelpFormatter


def add_metrics_subcommands(subparsers):
    """Add Prometheus metrics configuration subcommands."""
    metrics_parser = subparsers.add_parser(
        'metrics',
        help='Prometheus metrics configuration',
        description='Configure Prometheus metrics export.',
        formatter_class=TrapNinjaHelpFormatter,
        epilog=textwrap.dedent('''\
            Examples:
              trapninja metrics config            Show current configuration
              trapninja metrics set-dir /opt/metrics
              trapninja metrics add-label --name region --value us-west
              trapninja metrics set-interval 30
        ''')
    )
    metrics_parser.set_defaults(command_category='metrics')

    metrics_cmds = metrics_parser.add_subparsers(dest='command', metavar='<command>')

    # config
    metrics_cmds.add_parser('config', help='Show metrics configuration')

    # set-dir
    set_dir = metrics_cmds.add_parser('set-dir', help='Set output directory')
    set_dir.add_argument('directory', help='Directory path')

    # add-label
    add_label = metrics_cmds.add_parser('add-label', help='Add global label')
    add_label.add_argument('--name', required=True, help='Label name')
    add_label.add_argument('--value', required=True, help='Label value')

    # remove-label
    remove_label = metrics_cmds.add_parser('remove-label',
                                            help='Remove global label')
    remove_label.add_argument('name', help='Label name to remove')

    # set-interval
    set_interval = metrics_cmds.add_parser('set-interval',
                                            help='Set export interval')
    set_interval.add_argument('seconds', type=int, help='Interval in seconds')

    # help
    metrics_cmds.add_parser('help', help='Show metrics configuration help')
