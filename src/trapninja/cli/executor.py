#!/usr/bin/env python3
"""
TrapNinja Command Executor Module

Orchestrates command execution based on parsed arguments.
Supports both:
- Subcommand style: trapninja daemon start
- Legacy flat style: trapninja --start

Command routing is handled by the declarative registry in registry.py.
This module provides:
  - execute_command()           — main entry point for CLI dispatch
  - update_global_config()     — applies global CLI options to config
  - _execute_foreground_daemon() — hidden daemon entry point
  - _show_category_help()      — help display
  - _show_missing_command_help() — missing command guidance

Refactoring: A4/A5 from CODE-REVIEW-REFACTORING-ANALYSIS.md
Reduced from ~950 lines to ~350 lines via declarative command registry.
"""

import os
import sys
import logging
from argparse import Namespace

from .validation import InputValidator, parse_size
from .registry import dispatch_subcommand, dispatch_legacy, get_categories


logger = logging.getLogger("trapninja")


# =============================================================================
# HELP DISPLAY
# =============================================================================

def _show_category_help(category: str) -> int:
    """
    Show help for a specific command category.

    Args:
        category: Category name (daemon, filter, ha, etc.)

    Returns:
        Exit code (0 for success)
    """
    from .parser import create_argument_parser
    parser = create_argument_parser()
    for action in parser._subparsers._actions:
        if hasattr(action, 'choices') and category in action.choices:
            action.choices[category].print_help()
            return 0
    print(f"Run 'trapninja {category} --help' to see available commands.")
    return 0


def _show_missing_command_help(category: str) -> int:
    """
    Show helpful message when a category is used without a command.

    Args:
        category: Category name (daemon, filter, ha, etc.)

    Returns:
        Exit code (1 to indicate user needs to provide more info)
    """
    print(f"\n\033[93mNo command specified for '{category}'\033[0m")
    print(f"\nRun \033[92mtrapninja {category} --help\033[0m to see available commands.")
    print(f"\nQuick examples:")

    examples = {
        'daemon': [
            ('daemon start', 'Start the service'),
            ('daemon status', 'Check service status'),
            ('daemon foreground', 'Run in foreground'),
        ],
        'filter': [
            ('filter block-ip 10.0.0.1', 'Block an IP'),
            ('filter list-blocked-ips', 'List blocked IPs'),
            ('filter redirect-ip 10.0.0.1 --tag noc', 'Redirect IP'),
        ],
        'ha': [
            ('ha status', 'Check HA status'),
            ('ha configure --mode primary --peer 192.168.1.102', 'Configure HA'),
            ('ha promote', 'Promote to PRIMARY'),
        ],
        'snmpv3': [
            ('snmpv3 list-users', 'List SNMPv3 users'),
            ('snmpv3 status', 'Check SNMPv3 status'),
            ('snmpv3 add-user --username USER --engine-id ID', 'Add user'),
        ],
        'cache': [
            ('cache status', 'Show cache status'),
            ('cache query --destination default --from "-2h" --to now', 'Query cache'),
            ('cache replay --destination default --from "-1h" --to now', 'Replay cache'),
        ],
        'stats': [
            ('stats summary', 'Show statistics summary'),
            ('stats top-ips', 'Show top source IPs'),
            ('stats top-oids -n 20 -s rate', 'Top 20 OIDs by rate'),
        ],
        'metrics': [
            ('metrics config', 'Show metrics configuration'),
            ('metrics set-dir /opt/metrics', 'Set output directory'),
            ('metrics add-label --name region --value us-west', 'Add label'),
        ],
        'shadow': [
            ('shadow status', 'Show shadow mode statistics'),
            ('shadow export', 'Export statistics'),
        ],
        'failover': [
            ('failover status', 'Show failover status'),
            ('failover detect', 'Detect gaps'),
            ('failover replay', 'Trigger gap replay'),
        ],
        'sync': [
            ('sync status', 'Show sync status'),
            ('sync now', 'Sync with peer'),
        ],
    }

    if category in examples:
        for cmd, desc in examples[category]:
            print(f"  trapninja {cmd}")
            print(f"      {desc}")

    print()
    return 1


# =============================================================================
# GLOBAL CONFIG UPDATE
# =============================================================================

def update_global_config(args: Namespace) -> None:
    """
    Update global configuration variables based on command-line arguments.

    Args:
        args: Parsed command-line arguments
    """
    from .. import config

    # Interface
    if hasattr(args, 'interface') and args.interface:
        sanitized = InputValidator.sanitize_string(args.interface, max_length=16)
        if sanitized:
            config.INTERFACE = sanitized
        else:
            print(f"Invalid interface name: {args.interface}")
            sys.exit(1)

    # Config directory
    if hasattr(args, 'config_dir') and args.config_dir:
        sanitized = InputValidator.sanitize_string(
            args.config_dir, max_length=512, allow_special=True
        )
        if sanitized:
            config.CONFIG_DIR = os.path.abspath(sanitized)
            config.DESTINATIONS_FILE = os.path.join(config.CONFIG_DIR, "destinations.json")
            config.BLOCKED_TRAPS_FILE = os.path.join(config.CONFIG_DIR, "blocked_traps.json")
            config.BLOCKED_IPS_FILE = os.path.join(config.CONFIG_DIR, "blocked_ips.json")
            config.REDIRECTED_IPS_FILE = os.path.join(config.CONFIG_DIR, "redirected_ips.json")
            config.REDIRECTED_OIDS_FILE = os.path.join(config.CONFIG_DIR, "redirected_oids.json")
            config.REDIRECTED_DESTINATIONS_FILE = os.path.join(
                config.CONFIG_DIR, "redirected_destinations.json"
            )
        else:
            print(f"Invalid config directory: {args.config_dir}")
            sys.exit(1)

    # Log file
    if hasattr(args, 'log_file') and args.log_file:
        sanitized = InputValidator.sanitize_string(
            args.log_file, max_length=512, allow_special=True
        )
        if sanitized:
            config.LOG_FILE = os.path.abspath(sanitized)
        else:
            print(f"Invalid log file path: {args.log_file}")
            sys.exit(1)

    # PID file
    if hasattr(args, 'pid_file') and args.pid_file:
        sanitized = InputValidator.sanitize_string(
            args.pid_file, max_length=512, allow_special=True
        )
        if sanitized:
            config.PID_FILE = os.path.abspath(sanitized)
        else:
            print(f"Invalid PID file path: {args.pid_file}")
            sys.exit(1)

    # Log rotation
    if hasattr(args, 'log_max_size') and args.log_max_size:
        max_size = parse_size(args.log_max_size)
        if max_size is not None:
            config.LOG_MAX_SIZE = max_size
        else:
            print(f"Invalid log max size: {args.log_max_size}")
            print("Format should be a number with optional K, M, or G suffix (e.g., 10M, 1.5G)")
            sys.exit(1)

    if hasattr(args, 'log_backup_count') and args.log_backup_count is not None:
        if args.log_backup_count >= 0:
            config.LOG_BACKUP_COUNT = args.log_backup_count
        else:
            print("Log backup count must be a non-negative integer")
            sys.exit(1)

    if hasattr(args, 'log_compress') and args.log_compress:
        config.LOG_COMPRESS = True

    # Listen ports
    if hasattr(args, 'ports') and args.ports:
        try:
            port_list = []
            for p in args.ports.split(','):
                port = InputValidator.validate_port(p.strip())
                if port:
                    port_list.append(port)
                else:
                    print(f"Warning: Ignoring invalid port: {p.strip()}")

            if port_list:
                config.LISTEN_PORTS = port_list
                from .filtering_commands import config_manager
                if config_manager.save_json(config.LISTEN_PORTS_FILE, config.LISTEN_PORTS):
                    print(f"Updated listen ports: {config.LISTEN_PORTS}")
                else:
                    print("Warning: Failed to update listen ports file")
            else:
                print("No valid ports provided, using default")
        except Exception as e:
            print(f"Error parsing ports: {e}")
            print("Using default port configuration")


# =============================================================================
# FOREGROUND DAEMON (HIDDEN ENTRY POINT)
# =============================================================================

def _execute_foreground_daemon(args: Namespace) -> int:
    """
    Execute the actual daemon process (called via --foreground-daemon).

    This is the hidden entry point used by start_daemon() when spawning
    the background daemon process. It sets up logging, writes the PID file,
    and runs the service.
    """
    from ..logger import setup_logging
    from ..config import ensure_config_dir, LOG_MAX_SIZE, LOG_BACKUP_COUNT, LOG_COMPRESS
    from ..service import run_service
    from ..config import PID_FILE

    debug_mode = getattr(args, 'debug', False)
    shadow_mode = getattr(args, 'shadow_mode', False)
    mirror_mode = getattr(args, 'mirror_mode', False)
    parallel = getattr(args, 'parallel', False)
    capture_mode = getattr(args, 'capture_mode', None)
    log_traps = getattr(args, 'log_traps', None)
    log_level = getattr(args, 'log_level', None)

    setup_logging(
        console=False,
        log_level=log_level,
        max_size=LOG_MAX_SIZE,
        backup_count=LOG_BACKUP_COUNT,
        compress=LOG_COMPRESS,
    )

    ensure_config_dir()

    daemon_pid = os.getpid()
    with open(PID_FILE, 'w') as f:
        f.write(str(daemon_pid))

    daemon_logger = logging.getLogger("trapninja")
    daemon_logger.info(f"TrapNinja daemon started with HA support - PID {daemon_pid}")
    daemon_logger.info(
        f"Log rotation settings: max_size={LOG_MAX_SIZE} bytes, "
        f"backup_count={LOG_BACKUP_COUNT}, "
        f"compression={'enabled' if LOG_COMPRESS else 'disabled'}"
    )

    if shadow_mode:
        daemon_logger.info("Running in SHADOW MODE (observe only, no forwarding)")
    elif mirror_mode:
        daemon_logger.info("Running in MIRROR MODE (parallel capture and forward)")
    elif parallel:
        daemon_logger.info("Running in PARALLEL MODE (sniff capture for coexistence)")

    return run_service(
        debug=debug_mode,
        shadow_mode=shadow_mode,
        mirror_mode=mirror_mode,
        parallel=parallel,
        capture_mode=capture_mode,
        log_traps=log_traps,
    )


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

def execute_command(args: Namespace) -> int:
    """
    Execute the appropriate command based on parsed arguments.

    Supports both:
    - Subcommand style: args.category and args.command are set
    - Legacy flat style: args.start, args.block_ip, etc. are set

    Args:
        args: Parsed command-line arguments

    Returns:
        Exit code (0 for success, non-zero for failure)
    """
    # CRITICAL: Handle --foreground-daemon FIRST
    # This hidden flag is used by start_daemon() to run the actual daemon
    # process. Must be handled before any routing to avoid recursive spawning.
    if getattr(args, 'foreground_daemon', False):
        return _execute_foreground_daemon(args)

    # Check for subcommand style (new)
    category = getattr(args, 'category', None)
    command = getattr(args, 'command', None)

    if category:
        # Update global config from any global options
        update_global_config(args)

        if not command:
            return _show_missing_command_help(category)

        if command == 'help':
            return _show_category_help(category)

        return dispatch_subcommand(args, category, command)

    # Legacy flat-style routing: update global config then dispatch
    update_global_config(args)
    result = dispatch_legacy(args)

    if result is not None:
        return result

    # No command matched — show help
    from .parser import create_argument_parser
    parser = create_argument_parser()
    parser.print_help()
    return 0
