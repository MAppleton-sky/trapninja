#!/usr/bin/env python3
"""
TrapNinja CLI Parsers Package

Modular argument parser definitions organised by command category.
Each module defines the subcommands for one category (daemon, filter, ha, etc.)
while shared components (formatters, validators, base parser) live in base.py.

Module structure:
    base.py       - Help formatters, type validators, TrapNinjaArgumentParser
    daemon.py     - Service control (start, stop, restart, status, foreground)
    filtering.py  - IP/OID blocking and redirection
    ha.py         - High Availability clustering
    snmpv3.py     - SNMPv3 credential management
    cache.py      - Redis trap cache and replay
    stats.py      - Statistics and monitoring
    metrics.py    - Prometheus metrics configuration
    shadow.py     - Shadow/mirror mode
    failover.py   - Failover gap detection and replay
    sync.py       - Configuration synchronization
    legacy.py     - Backward-compatible flat-style --flags

Public API:
    create_argument_parser() → argparse.ArgumentParser
"""

import argparse
import textwrap

from .base import (
    TrapNinjaArgumentParser,
    TrapNinjaRootHelpFormatter,
    add_global_options,
)
from .daemon import add_daemon_subcommands
from .filtering import add_filter_subcommands
from .ha import add_ha_subcommands
from .snmpv3 import add_snmpv3_subcommands
from .cache import add_cache_subcommands
from .stats import add_stats_subcommands
from .metrics import add_metrics_subcommands
from .shadow import add_shadow_subcommands
from .failover import add_failover_subcommands
from .sync import add_sync_subcommands
from .legacy import add_legacy_arguments

__all__ = ['create_argument_parser']


def create_argument_parser() -> argparse.ArgumentParser:
    """
    Create and configure the argument parser with all TrapNinja commands.

    Assembles the complete CLI by delegating to per-category parser modules.
    Each module is responsible for its own subcommands, help text, and
    argument definitions.

    Returns:
        Configured ArgumentParser instance
    """
    # Root parser with category overview
    parser = TrapNinjaArgumentParser(
        prog='trapninja',
        description=textwrap.dedent('''\
            \033[1mTrapNinja - High-Performance SNMP Trap Forwarder\033[0m

            A telecommunications-grade trap processing system with HA support,
            SNMPv3 decryption, and intelligent filtering.
        '''),
        formatter_class=TrapNinjaRootHelpFormatter,
        epilog=textwrap.dedent('''\
            \033[1mQuick Start:\033[0m
              trapninja daemon start              Start the service
              trapninja daemon status             Check service status
              trapninja filter block-ip 10.0.0.1  Block an IP
              trapninja stats summary             View statistics

            Use \033[93mtrapninja <category> --help\033[0m for detailed command help.
        ''')
    )

    # Add global options
    add_global_options(parser)

    # Create subparsers for command categories
    subparsers = parser.add_subparsers(
        title='Command Categories',
        dest='category',
        metavar='<category>'
    )

    # Add each command category (order determines help listing order)
    add_daemon_subcommands(subparsers)
    add_filter_subcommands(subparsers)
    add_ha_subcommands(subparsers)
    add_snmpv3_subcommands(subparsers)
    add_cache_subcommands(subparsers)
    add_stats_subcommands(subparsers)
    add_metrics_subcommands(subparsers)
    add_shadow_subcommands(subparsers)
    add_failover_subcommands(subparsers)
    add_sync_subcommands(subparsers)

    # Add legacy flat-style arguments (hidden, for backward compatibility)
    add_legacy_arguments(parser)

    return parser
