#!/usr/bin/env python3
"""
TrapNinja Command Executor Module

Orchestrates command execution based on parsed arguments.
Supports both:
- Subcommand style: trapninja daemon start
- Legacy flat style: trapninja --start

UPDATED: Now handles subcommand-based routing in addition to legacy arguments
"""

import os
import sys
import logging
from typing import Any
from argparse import Namespace

from . import daemon_commands
from . import filtering_commands
from . import ha_commands
from . import snmpv3_commands
from . import cache_commands
from . import stats_commands
from . import shadow_commands
from .validation import InputValidator, parse_size


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
    # Navigate to the subparser for this category
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
    
    # Show category-specific examples
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


def update_global_config(args: Namespace) -> None:
    """
    Update global configuration variables based on command-line arguments

    Args:
        args: Parsed command-line arguments
    """
    from .. import config

    # Update interface if provided
    if hasattr(args, 'interface') and args.interface:
        sanitized_interface = InputValidator.sanitize_string(args.interface, max_length=16)
        if sanitized_interface:
            config.INTERFACE = sanitized_interface
        else:
            print(f"Invalid interface name: {args.interface}")
            sys.exit(1)

    # Update config directory if provided
    if hasattr(args, 'config_dir') and args.config_dir:
        sanitized_config_dir = InputValidator.sanitize_string(
            args.config_dir, max_length=512, allow_special=True
        )
        if sanitized_config_dir:
            config.CONFIG_DIR = os.path.abspath(sanitized_config_dir)
            # Update all config file paths
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

    # Update log file if provided
    if hasattr(args, 'log_file') and args.log_file:
        sanitized_log_file = InputValidator.sanitize_string(
            args.log_file, max_length=512, allow_special=True
        )
        if sanitized_log_file:
            config.LOG_FILE = os.path.abspath(sanitized_log_file)
        else:
            print(f"Invalid log file path: {args.log_file}")
            sys.exit(1)

    # Update PID file if provided
    if hasattr(args, 'pid_file') and args.pid_file:
        sanitized_pid_file = InputValidator.sanitize_string(
            args.pid_file, max_length=512, allow_special=True
        )
        if sanitized_pid_file:
            config.PID_FILE = os.path.abspath(sanitized_pid_file)
        else:
            print(f"Invalid PID file path: {args.pid_file}")
            sys.exit(1)

    # Update log rotation settings
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

    # Update listen ports if provided
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
                # Also update the config file
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
    # CRITICAL: Check for --foreground-daemon FIRST before any routing
    # This is a hidden flag used by start_daemon() to run the actual daemon process
    # It must be handled before subcommand routing to avoid recursive spawning
    if getattr(args, 'foreground_daemon', False):
        return _execute_foreground_daemon(args)
    
    # Check if using subcommand style (new)
    category = getattr(args, 'category', None)
    command = getattr(args, 'command', None)
    
    if category:
        # Route to appropriate subcommand handler
        return _execute_subcommand(args, category, command)
    
    # Otherwise, try legacy flat-style routing
    return _execute_legacy_command(args)


def _execute_foreground_daemon(args: Namespace) -> int:
    """
    Execute the actual daemon process (called via --foreground-daemon).
    
    This is the hidden entry point used by start_daemon() when spawning
    the background daemon process. It sets up logging, writes the PID file,
    and runs the service.
    
    Args:
        args: Parsed arguments
        
    Returns:
        Exit code from the service
    """
    from ..logger import setup_logging
    from ..config import ensure_config_dir, LOG_MAX_SIZE, LOG_BACKUP_COUNT, LOG_COMPRESS
    from ..service import run_service
    from ..config import PID_FILE

    # Extract runtime options from args
    debug_mode = getattr(args, 'debug', False)
    shadow_mode = getattr(args, 'shadow_mode', False)
    mirror_mode = getattr(args, 'mirror_mode', False)
    parallel = getattr(args, 'parallel', False)
    capture_mode = getattr(args, 'capture_mode', None)
    log_traps = getattr(args, 'log_traps', None)

    # Set log level if specified
    log_level = getattr(args, 'log_level', None)

    # Set up logging with rotation settings
    # Note: console=False since we're running as daemon (stdout goes to /dev/null)
    setup_logging(
        console=False,
        log_level=log_level,
        max_size=LOG_MAX_SIZE,
        backup_count=LOG_BACKUP_COUNT,
        compress=LOG_COMPRESS
    )

    ensure_config_dir()

    # Write PID file
    daemon_pid = os.getpid()
    with open(PID_FILE, 'w') as f:
        f.write(str(daemon_pid))

    # Log startup
    logger = logging.getLogger("trapninja")
    logger.info(f"TrapNinja daemon started with HA support - PID {daemon_pid}")

    # Log the log rotation settings
    logger.info(
        f"Log rotation settings: max_size={LOG_MAX_SIZE} bytes, "
        f"backup_count={LOG_BACKUP_COUNT}, "
        f"compression={'enabled' if LOG_COMPRESS else 'disabled'}"
    )

    # Log runtime mode if any special modes are enabled
    if shadow_mode:
        logger.info("Running in SHADOW MODE (observe only, no forwarding)")
    elif mirror_mode:
        logger.info("Running in MIRROR MODE (parallel capture and forward)")
    elif parallel:
        logger.info("Running in PARALLEL MODE (sniff capture for coexistence)")

    # Run the service with all runtime options
    return run_service(
        debug=debug_mode,
        shadow_mode=shadow_mode,
        mirror_mode=mirror_mode,
        parallel=parallel,
        capture_mode=capture_mode,
        log_traps=log_traps
    )


def _execute_subcommand(args: Namespace, category: str, command: str) -> int:
    """
    Execute a subcommand-style command.
    
    Args:
        args: Parsed arguments
        category: Command category (daemon, filter, ha, etc.)
        command: Specific command within category
        
    Returns:
        Exit code
    """
    # Update global config from any global options
    update_global_config(args)
    
    # Route by category
    if category == 'daemon':
        return _execute_daemon_command(args, command)
    elif category == 'filter':
        return _execute_filter_command(args, command)
    elif category == 'ha':
        return _execute_ha_command(args, command)
    elif category == 'snmpv3':
        return _execute_snmpv3_command(args, command)
    elif category == 'cache':
        return _execute_cache_command(args, command)
    elif category == 'stats':
        return _execute_stats_command(args, command)
    elif category == 'metrics':
        return _execute_metrics_command(args, command)
    elif category == 'shadow':
        return _execute_shadow_command(args, command)
    elif category == 'failover':
        return _execute_failover_command(args, command)
    elif category == 'sync':
        return _execute_sync_command(args, command)
    else:
        print(f"Unknown command category: {category}")
        print("Run 'trapninja --help' to see available categories.")
        return 1


# =============================================================================
# Daemon Commands
# =============================================================================

def _execute_daemon_command(args: Namespace, command: str) -> int:
    """Execute daemon-related commands."""
    if not command:
        return _show_missing_command_help('daemon')
    
    if command == 'help':
        return _show_category_help('daemon')
    
    if command == 'start':
        return daemon_commands.start(
            shadow_mode=getattr(args, 'shadow_mode', False),
            mirror_mode=getattr(args, 'mirror_mode', False),
            parallel=getattr(args, 'parallel', False),
            capture_mode=getattr(args, 'capture_mode', None),
            log_traps=getattr(args, 'log_traps', None)
        )
    elif command == 'stop':
        return daemon_commands.stop()
    elif command == 'restart':
        return daemon_commands.restart(
            shadow_mode=getattr(args, 'shadow_mode', False),
            mirror_mode=getattr(args, 'mirror_mode', False),
            parallel=getattr(args, 'parallel', False),
            capture_mode=getattr(args, 'capture_mode', None),
            log_traps=getattr(args, 'log_traps', None)
        )
    elif command == 'status':
        return daemon_commands.status()
    elif command == 'foreground':
        return daemon_commands.run_foreground(
            debug=getattr(args, 'debug', False),
            shadow_mode=getattr(args, 'shadow_mode', False),
            mirror_mode=getattr(args, 'mirror_mode', False),
            parallel=getattr(args, 'parallel', False),
            capture_mode=getattr(args, 'capture_mode', None),
            log_traps=getattr(args, 'log_traps', None)
        )
    elif command == 'config':
        if getattr(args, 'validate', False):
            return daemon_commands.validate_config()
        return daemon_commands.show_config(json_output=getattr(args, 'json', False))
    elif command == 'queue-stats':
        return daemon_commands.queue_stats(json_output=getattr(args, 'json', False))
    else:
        print(f"Unknown daemon command: {command}")
        print("Run 'trapninja daemon --help' to see available commands.")
        return 1


# =============================================================================
# Filter Commands
# =============================================================================

def _execute_filter_command(args: Namespace, command: str) -> int:
    """Execute filtering-related commands."""
    if not command:
        return _show_missing_command_help('filter')
    
    if command == 'help':
        return _show_category_help('filter')
    
    # IP blocking
    if command == 'block-ip':
        return 0 if filtering_commands.block_ip(args.ip) else 1
    elif command == 'unblock-ip':
        return 0 if filtering_commands.unblock_ip(args.ip) else 1
    elif command == 'list-blocked-ips':
        return 0 if filtering_commands.list_blocked_ips() else 1
    
    # OID blocking
    elif command == 'block-oid':
        return 0 if filtering_commands.block_oid(args.oid) else 1
    elif command == 'unblock-oid':
        return 0 if filtering_commands.unblock_oid(args.oid) else 1
    elif command == 'list-blocked-oids':
        return 0 if filtering_commands.list_blocked_oids() else 1
    
    # IP redirection
    elif command == 'redirect-ip':
        return 0 if filtering_commands.redirect_ip(args.ip, args.tag) else 1
    elif command == 'unredirect-ip':
        return 0 if filtering_commands.unredirect_ip(args.ip) else 1
    elif command == 'list-redirected-ips':
        return 0 if filtering_commands.list_redirected_ips() else 1
    
    # OID redirection
    elif command == 'redirect-oid':
        return 0 if filtering_commands.redirect_oid(args.oid, args.tag) else 1
    elif command == 'unredirect-oid':
        return 0 if filtering_commands.unredirect_oid(args.oid) else 1
    elif command == 'list-redirected-oids':
        return 0 if filtering_commands.list_redirected_oids() else 1
    
    # Redirect destinations
    elif command == 'add-redirect-dest':
        return 0 if filtering_commands.add_redirect_destination(args.tag, args.ip, args.port) else 1
    elif command == 'remove-redirect-dest':
        return 0 if filtering_commands.remove_redirect_destination(args.tag, args.ip, args.port) else 1
    elif command == 'list-redirect-dests':
        return 0 if filtering_commands.list_redirect_destinations() else 1
    
    else:
        print(f"Unknown filter command: {command}")
        print("Run 'trapninja filter --help' to see available commands.")
        return 1


# =============================================================================
# HA Commands
# =============================================================================

def _execute_ha_command(args: Namespace, command: str) -> int:
    """Execute HA-related commands."""
    if not command:
        return _show_missing_command_help('ha')
    
    if command == 'help':
        return _show_category_help('ha')
    
    if command == 'configure':
        return 0 if ha_commands.configure_ha(
            args.mode,
            args.ha_peer_host,
            getattr(args, 'priority', 100),
            getattr(args, 'peer_port', 8162),
            getattr(args, 'listen_port', 8162)
        ) else 1
    elif command == 'status':
        return 0 if ha_commands.show_ha_status() else 1
    elif command == 'promote':
        return 0 if ha_commands.promote_to_primary(force=getattr(args, 'force', False)) else 1
    elif command == 'demote':
        return 0 if ha_commands.demote_to_secondary() else 1
    elif command == 'force-failover':
        return 0 if ha_commands.force_failover() else 1
    elif command == 'disable':
        return 0 if ha_commands.disable_ha() else 1
    else:
        print(f"Unknown HA command: {command}")
        print("Run 'trapninja ha --help' to see available commands.")
        return 1


# =============================================================================
# SNMPv3 Commands
# =============================================================================

def _execute_snmpv3_command(args: Namespace, command: str) -> int:
    """Execute SNMPv3-related commands."""
    if not command:
        return _show_missing_command_help('snmpv3')
    
    if command == 'help':
        return _show_category_help('snmpv3')
    
    if command == 'add-user':
        return snmpv3_commands.handle_snmpv3_add_user(args)
    elif command == 'remove-user':
        return snmpv3_commands.handle_snmpv3_remove_user(args)
    elif command == 'list-users':
        return snmpv3_commands.handle_snmpv3_list_users(args)
    elif command == 'show-user':
        return snmpv3_commands.handle_snmpv3_show_user(args)
    elif command == 'status':
        return snmpv3_commands.handle_snmpv3_status(args)
    elif command == 'test-decrypt':
        return snmpv3_commands.handle_snmpv3_test_decrypt(args)
    else:
        print(f"Unknown SNMPv3 command: {command}")
        print("Run 'trapninja snmpv3 --help' to see available commands.")
        return 1


# =============================================================================
# Cache Commands
# =============================================================================

def _execute_cache_command(args: Namespace, command: str) -> int:
    """Execute cache-related commands."""
    if not command:
        return _show_missing_command_help('cache')
    
    if command == 'help':
        return _show_category_help('cache')
    
    verbose = getattr(args, 'verbose', False)
    yes = getattr(args, 'yes', False)
    
    if command == 'status':
        return 0 if cache_commands.show_cache_status(verbose=verbose) else 1
    elif command == 'query':
        return 0 if cache_commands.query_cache(
            destination=args.destination,
            start_time=args.from_time,
            end_time=args.to_time,
            limit=getattr(args, 'limit', 20),
            show_oids=True
        ) else 1
    elif command == 'replay':
        return 0 if cache_commands.replay_cache(
            destination=args.destination,
            start_time=args.from_time,
            end_time=args.to_time,
            rate_limit=getattr(args, 'rate_limit', 500),
            dry_run=getattr(args, 'dry_run', False),
            oid_filter=getattr(args, 'oid_filter', None),
            source_filter=getattr(args, 'source_filter', None),
            exclude_oid=getattr(args, 'exclude_oid', None),
            yes=yes,
            replay_to=getattr(args, 'replay_to', None)
        ) else 1
    elif command == 'clear':
        return 0 if cache_commands.clear_cache(
            destination=getattr(args, 'destination', None),
            yes=yes
        ) else 1
    elif command == 'trim':
        return 0 if cache_commands.trim_cache(yes=yes) else 1
    else:
        print(f"Unknown cache command: {command}")
        print("Run 'trapninja cache --help' to see available commands.")
        return 1


# =============================================================================
# Stats Commands
# =============================================================================

def _execute_stats_command(args: Namespace, command: str) -> int:
    """Execute statistics-related commands."""
    if not command:
        return _show_missing_command_help('stats')
    
    if command == 'help':
        return _show_category_help('stats')
    
    if command == 'summary':
        return stats_commands.handle_stats_summary(args)
    elif command == 'top-ips':
        return stats_commands.handle_stats_top_ips(args)
    elif command == 'top-oids':
        return stats_commands.handle_stats_top_oids(args)
    elif command == 'ip':
        return stats_commands.handle_stats_ip_detail(args)
    elif command == 'oid':
        return stats_commands.handle_stats_oid_detail(args)
    elif command == 'destinations':
        return stats_commands.handle_stats_destinations(args)
    elif command == 'dashboard':
        return stats_commands.handle_stats_dashboard(args)
    elif command == 'export':
        return stats_commands.handle_stats_export(args)
    elif command == 'reset':
        return stats_commands.handle_stats_reset(args)
    elif command == 'debug':
        return stats_commands.handle_stats_debug(args)
    else:
        print(f"Unknown stats command: {command}")
        print("Run 'trapninja stats --help' to see available commands.")
        return 1


# =============================================================================
# Metrics Commands
# =============================================================================

def _execute_metrics_command(args: Namespace, command: str) -> int:
    """Execute metrics-related commands."""
    from . import metrics_commands
    
    if not command:
        return _show_missing_command_help('metrics')
    
    if command == 'help':
        return _show_category_help('metrics')
    
    json_output = getattr(args, 'json', False)
    
    if command == 'config':
        return metrics_commands.show_metrics_config(json_output=json_output)
    elif command == 'set-dir':
        return metrics_commands.set_metrics_directory(args.directory)
    elif command == 'add-label':
        return metrics_commands.add_metrics_label(args.name, args.value)
    elif command == 'remove-label':
        return metrics_commands.remove_metrics_label(args.name)
    elif command == 'set-interval':
        return metrics_commands.set_export_interval(args.seconds)
    else:
        print(f"Unknown metrics command: {command}")
        print("Run 'trapninja metrics --help' to see available commands.")
        return 1


# =============================================================================
# Shadow Commands
# =============================================================================

def _execute_shadow_command(args: Namespace, command: str) -> int:
    """Execute shadow mode-related commands."""
    if not command:
        return _show_missing_command_help('shadow')
    
    if command == 'help':
        return _show_category_help('shadow')
    
    if command == 'status':
        return shadow_commands.handle_shadow_status(args)
    elif command == 'export':
        return shadow_commands.handle_shadow_export(args)
    else:
        print(f"Unknown shadow command: {command}")
        print("Run 'trapninja shadow --help' to see available commands.")
        return 1


# =============================================================================
# Failover Commands
# =============================================================================

def _execute_failover_command(args: Namespace, command: str) -> int:
    """Execute failover-related commands."""
    from . import failover_commands
    
    if not command:
        return _show_missing_command_help('failover')
    
    if command == 'help':
        return _show_category_help('failover')
    
    verbose = getattr(args, 'verbose', False)
    yes = getattr(args, 'yes', False)
    
    if command == 'status':
        return 0 if failover_commands.show_failover_status(verbose=verbose) else 1
    elif command == 'detect':
        return 0 if failover_commands.detect_gaps(verbose=verbose) else 1
    elif command == 'replay':
        destination = getattr(args, 'destination', None) or 'detect'
        from_time = getattr(args, 'from_time', None) or '-5m'
        to_time = getattr(args, 'to_time', None) or 'now'
        rate_limit = getattr(args, 'rate_limit', None)
        dry_run = getattr(args, 'dry_run', False)
        
        return 0 if failover_commands.trigger_manual_replay(
            destination=destination,
            start_time=from_time,
            end_time=to_time,
            rate_limit=rate_limit,
            dry_run=dry_run,
            yes=yes
        ) else 1
    else:
        print(f"Unknown failover command: {command}")
        print("Run 'trapninja failover --help' to see available commands.")
        return 1


# =============================================================================
# Sync Commands
# =============================================================================

def _execute_sync_command(args: Namespace, command: str) -> int:
    """Execute sync-related commands."""
    from . import sync_commands
    
    if not command:
        return _show_missing_command_help('sync')
    
    if command == 'help':
        return _show_category_help('sync')
    
    if command == 'now':
        force = getattr(args, 'force', False)
        return 0 if sync_commands.sync_now(force=force) else 1
    elif command == 'status':
        return 0 if sync_commands.show_sync_status() else 1
    else:
        print(f"Unknown sync command: {command}")
        print("Run 'trapninja sync --help' to see available commands.")
        return 1


# =============================================================================
# Legacy Command Execution
# =============================================================================

def _execute_legacy_command(args: Namespace) -> int:
    """
    Execute legacy flat-style commands for backward compatibility.
    
    Args:
        args: Parsed arguments with flat-style flags
        
    Returns:
        Exit code
    """
    # Handle HA commands first
    if getattr(args, 'configure_ha', False):
        if not getattr(args, 'ha_mode', None) or not getattr(args, 'ha_peer_host', None):
            print("Error: --ha-mode and --ha-peer-host are required for HA configuration")
            print("Example: --configure-ha --ha-mode primary --ha-peer-host 192.168.1.101")
            return 1

        return 0 if ha_commands.configure_ha(
            args.ha_mode,
            args.ha_peer_host,
            getattr(args, 'ha_priority', 100),
            getattr(args, 'ha_peer_port', 8162),
            getattr(args, 'ha_listen_port', 8162)
        ) else 1

    elif getattr(args, 'disable_ha', False):
        return 0 if ha_commands.disable_ha() else 1

    elif getattr(args, 'ha_status', False):
        return 0 if ha_commands.show_ha_status() else 1

    # HA manual control commands
    elif getattr(args, 'promote', False):
        force = getattr(args, 'force', False)
        return 0 if ha_commands.promote_to_primary(force=force) else 1

    elif getattr(args, 'demote', False):
        return 0 if ha_commands.demote_to_secondary() else 1

    elif getattr(args, 'force_failover', False):
        return 0 if ha_commands.force_failover() else 1

    elif getattr(args, 'ha_help', False):
        return 0 if ha_commands.show_ha_help() else 1

    # Config sync commands
    elif getattr(args, 'ha_sync', False):
        from . import sync_commands
        force = getattr(args, 'force', False)
        return 0 if sync_commands.sync_now(force=force) else 1

    elif getattr(args, 'sync_status', False):
        from . import sync_commands
        return 0 if sync_commands.show_sync_status() else 1
    
    elif getattr(args, 'sync_help', False):
        from . import sync_commands
        return 0 if sync_commands.show_sync_help() else 1

    # Update global configuration before executing commands
    update_global_config(args)

    # Handle filtering commands
    if getattr(args, 'block_ip', None):
        return 0 if filtering_commands.block_ip(args.block_ip) else 1
    
    elif getattr(args, 'unblock_ip', None):
        return 0 if filtering_commands.unblock_ip(args.unblock_ip) else 1
    
    elif getattr(args, 'list_blocked_ips', False):
        return 0 if filtering_commands.list_blocked_ips() else 1

    elif getattr(args, 'block_oid', None):
        return 0 if filtering_commands.block_oid(args.block_oid) else 1
    
    elif getattr(args, 'unblock_oid', None):
        return 0 if filtering_commands.unblock_oid(args.unblock_oid) else 1
    
    elif getattr(args, 'list_blocked_oids', False):
        return 0 if filtering_commands.list_blocked_oids() else 1

    # Handle IP redirection commands
    elif getattr(args, 'redirect_ip', None):
        if not getattr(args, 'tag', None):
            print("Error: --tag is required for --redirect-ip")
            print("Example: --redirect-ip 10.0.0.1 --tag security")
            return 1
        return 0 if filtering_commands.redirect_ip(args.redirect_ip, args.tag) else 1
    
    elif getattr(args, 'unredirect_ip', None):
        return 0 if filtering_commands.unredirect_ip(args.unredirect_ip) else 1
    
    elif getattr(args, 'list_redirected_ips', False):
        return 0 if filtering_commands.list_redirected_ips() else 1

    # Handle OID redirection commands
    elif getattr(args, 'redirect_oid', None):
        if not getattr(args, 'tag', None):
            print("Error: --tag is required for --redirect-oid")
            print("Example: --redirect-oid 1.3.6.1.4.1.9.9.41.2.0.1 --tag security")
            return 1
        return 0 if filtering_commands.redirect_oid(args.redirect_oid, args.tag) else 1
    
    elif getattr(args, 'unredirect_oid', None):
        return 0 if filtering_commands.unredirect_oid(args.unredirect_oid) else 1
    
    elif getattr(args, 'list_redirected_oids', False):
        return 0 if filtering_commands.list_redirected_oids() else 1

    # Handle redirect destination commands
    elif getattr(args, 'add_redirect_dest', False):
        if not getattr(args, 'tag', None) or not getattr(args, 'ip', None) or not getattr(args, 'port', None):
            print("Error: --tag, --ip, and --port are required for --add-redirect-dest")
            print("Example: --add-redirect-dest --tag security --ip 10.1.1.100 --port 162")
            return 1
        return 0 if filtering_commands.add_redirect_destination(args.tag, args.ip, args.port) else 1
    
    elif getattr(args, 'remove_redirect_dest', False):
        if not getattr(args, 'tag', None) or not getattr(args, 'ip', None) or not getattr(args, 'port', None):
            print("Error: --tag, --ip, and --port are required for --remove-redirect-dest")
            print("Example: --remove-redirect-dest --tag security --ip 10.1.1.100 --port 162")
            return 1
        return 0 if filtering_commands.remove_redirect_destination(args.tag, args.ip, args.port) else 1
    
    elif getattr(args, 'list_redirect_dests', False):
        return 0 if filtering_commands.list_redirect_destinations() else 1
    
    elif getattr(args, 'redirection_help', False):
        return 0 if filtering_commands.show_redirection_help() else 1

    # Handle SNMPv3 commands
    elif getattr(args, 'snmpv3_add_user', False):
        if not getattr(args, 'username', None) or not getattr(args, 'engine_id', None):
            print("Error: --username and --engine-id are required")
            print("Example: --snmpv3-add-user --username myuser --engine-id 80001f888056565656565656 --auth-protocol SHA --priv-protocol AES128")
            return 1
        return snmpv3_commands.handle_snmpv3_add_user(args)
    
    elif getattr(args, 'snmpv3_remove_user', False):
        if not getattr(args, 'username', None) or not getattr(args, 'engine_id', None):
            print("Error: --username and --engine-id are required")
            return 1
        return snmpv3_commands.handle_snmpv3_remove_user(args)
    
    elif getattr(args, 'snmpv3_list_users', False):
        return snmpv3_commands.handle_snmpv3_list_users(args)
    
    elif getattr(args, 'snmpv3_show_user', False):
        if not getattr(args, 'username', None) or not getattr(args, 'engine_id', None):
            print("Error: --username and --engine-id are required")
            return 1
        return snmpv3_commands.handle_snmpv3_show_user(args)
    
    elif getattr(args, 'snmpv3_status', False):
        return snmpv3_commands.handle_snmpv3_status(args)
    
    elif getattr(args, 'snmpv3_test_decrypt', False):
        return snmpv3_commands.handle_snmpv3_test_decrypt(args)

    # Handle cache commands
    elif getattr(args, 'cache_status', False):
        return 0 if cache_commands.show_cache_status(verbose=getattr(args, 'verbose', False)) else 1
    
    elif getattr(args, 'cache_query', False):
        if not getattr(args, 'destination', None) or not getattr(args, 'from_time', None) or not getattr(args, 'to_time', None):
            print("Error: --destination, --from, and --to are required for cache query")
            print("Example: --cache-query --destination voice_noc --from \"14:30\" --to \"15:45\"")
            return 1
        return 0 if cache_commands.query_cache(
            destination=args.destination,
            start_time=args.from_time,
            end_time=args.to_time,
            limit=getattr(args, 'limit', 20),
            show_oids=True
        ) else 1
    
    elif getattr(args, 'cache_replay', False):
        if not getattr(args, 'destination', None) or not getattr(args, 'from_time', None) or not getattr(args, 'to_time', None):
            print("Error: --destination, --from, and --to are required for cache replay")
            print("Example: --cache-replay --destination voice_noc --from \"14:30\" --to \"15:45\"")
            print("Use --dry-run to preview without sending")
            print("Use --replay-to HOST:PORT to send to a custom destination")
            return 1
        return 0 if cache_commands.replay_cache(
            destination=args.destination,
            start_time=args.from_time,
            end_time=args.to_time,
            rate_limit=getattr(args, 'rate_limit', 500),
            dry_run=getattr(args, 'dry_run', False),
            oid_filter=getattr(args, 'oid_filter', None),
            source_filter=getattr(args, 'source_filter', None),
            exclude_oid=getattr(args, 'exclude_oid', None),
            yes=getattr(args, 'yes', False),
            replay_to=getattr(args, 'replay_to', None)
        ) else 1
    
    elif getattr(args, 'cache_clear', False):
        return 0 if cache_commands.clear_cache(
            destination=getattr(args, 'destination', None),
            yes=getattr(args, 'yes', False)
        ) else 1
    
    elif getattr(args, 'cache_trim', False):
        return 0 if cache_commands.trim_cache(yes=getattr(args, 'yes', False)) else 1
    
    elif getattr(args, 'cache_help', False):
        return 0 if cache_commands.show_cache_help() else 1

    # Handle failover replay commands
    elif getattr(args, 'failover_status', False):
        from . import failover_commands
        return 0 if failover_commands.show_failover_status(verbose=getattr(args, 'verbose', False)) else 1
    
    elif getattr(args, 'failover_detect', False):
        from . import failover_commands
        return 0 if failover_commands.detect_gaps(verbose=getattr(args, 'verbose', False)) else 1
    
    elif getattr(args, 'failover_replay', False):
        from . import failover_commands
        # Auto-detect mode if no times specified
        from_time = getattr(args, 'from_time', None)
        to_time = getattr(args, 'to_time', None)
        if not from_time or not to_time:
            destination = getattr(args, 'destination', None) or 'detect'
        else:
            if not getattr(args, 'destination', None):
                print("Error: --destination is required for manual replay")
                print("Example: --failover-replay --destination default --from \"-5m\" --to \"now\"")
                print("Use 'detect' as destination to auto-detect gaps: --failover-replay --destination detect")
                return 1
            destination = args.destination
        return 0 if failover_commands.trigger_manual_replay(
            destination=destination,
            start_time=from_time or '-5m',
            end_time=to_time or 'now',
            rate_limit=getattr(args, 'rate_limit', 500) if getattr(args, 'rate_limit', 500) != 500 else None,
            dry_run=getattr(args, 'dry_run', False),
            yes=getattr(args, 'yes', False)
        ) else 1
    
    elif getattr(args, 'failover_help', False):
        from . import failover_commands
        return 0 if failover_commands.show_failover_help() else 1

    # Handle queue statistics
    elif getattr(args, 'queue_stats', False):
        return daemon_commands.queue_stats(json_output=getattr(args, 'json', False))

    # Handle granular statistics commands
    elif getattr(args, 'stats_summary', False):
        return stats_commands.handle_stats_summary(args)

    elif getattr(args, 'stats_top_ips', False):
        return stats_commands.handle_stats_top_ips(args)

    elif getattr(args, 'stats_top_oids', False):
        return stats_commands.handle_stats_top_oids(args)

    elif getattr(args, 'stats_ip', False):
        if not getattr(args, 'ip', None):
            print("Error: --ip is required for --stats-ip")
            print("Example: --stats-ip --ip 10.0.0.1")
            return 1
        return stats_commands.handle_stats_ip_detail(args)

    elif getattr(args, 'stats_oid', False):
        if not getattr(args, 'oid', None):
            print("Error: --oid is required for --stats-oid")
            print("Example: --stats-oid --oid 1.3.6.1.4.1.9.9.41.2.0.1")
            return 1
        return stats_commands.handle_stats_oid_detail(args)

    elif getattr(args, 'stats_destinations', False):
        return stats_commands.handle_stats_destinations(args)

    elif getattr(args, 'stats_dashboard', False):
        return stats_commands.handle_stats_dashboard(args)

    elif getattr(args, 'stats_export', False):
        return stats_commands.handle_stats_export(args)

    elif getattr(args, 'stats_reset', False):
        return stats_commands.handle_stats_reset(args)

    elif getattr(args, 'stats_help', False):
        return stats_commands.handle_stats_help(args)

    elif getattr(args, 'stats_debug', False):
        return stats_commands.handle_stats_debug(args)

    # Handle shadow mode commands
    elif getattr(args, 'shadow_status', False):
        return shadow_commands.handle_shadow_status(args)
    
    elif getattr(args, 'shadow_export', False):
        return shadow_commands.handle_shadow_export(args)
    
    # Handle metrics configuration commands
    elif getattr(args, 'metrics_config', False):
        from . import metrics_commands
        return metrics_commands.show_metrics_config(json_output=getattr(args, 'json', False))
    
    elif getattr(args, 'metrics_set_dir', None):
        from . import metrics_commands
        return metrics_commands.set_metrics_directory(args.metrics_set_dir)
    
    elif getattr(args, 'metrics_add_label', False):
        from . import metrics_commands
        label_name = getattr(args, 'label_name', None)
        label_value = getattr(args, 'label_value', None)
        if not label_name or label_value is None:
            print("Error: --label-name and --label-value are required for --metrics-add-label")
            print("Example: --metrics-add-label --label-name on_prem --label-value 1")
            return 1
        return metrics_commands.add_metrics_label(label_name, label_value)
    
    elif getattr(args, 'metrics_remove_label', None):
        from . import metrics_commands
        return metrics_commands.remove_metrics_label(args.metrics_remove_label)
    
    elif getattr(args, 'metrics_set_interval', None):
        from . import metrics_commands
        return metrics_commands.set_export_interval(args.metrics_set_interval)
    
    elif getattr(args, 'metrics_help', False):
        from . import metrics_commands
        return metrics_commands.show_metrics_help()

    # Handle configuration commands
    elif getattr(args, 'show_config', False):
        return daemon_commands.show_config(json_output=getattr(args, 'json', False))
    
    elif getattr(args, 'validate_config', False):
        return daemon_commands.validate_config()

    # Handle daemon control commands
    elif getattr(args, 'start', False):
        return daemon_commands.start(
            shadow_mode=getattr(args, 'shadow_mode', False),
            mirror_mode=getattr(args, 'mirror_mode', False),
            parallel=getattr(args, 'parallel', False),
            capture_mode=getattr(args, 'capture_mode', None),
            log_traps=getattr(args, 'log_traps', None)
        )
    
    elif getattr(args, 'stop', False):
        return daemon_commands.stop()
    
    elif getattr(args, 'restart', False):
        return daemon_commands.restart(
            shadow_mode=getattr(args, 'shadow_mode', False),
            mirror_mode=getattr(args, 'mirror_mode', False),
            parallel=getattr(args, 'parallel', False),
            capture_mode=getattr(args, 'capture_mode', None),
            log_traps=getattr(args, 'log_traps', None)
        )
    
    elif getattr(args, 'status', False):
        return daemon_commands.status()
    
    elif getattr(args, 'foreground', False):
        return daemon_commands.run_foreground(
            debug=getattr(args, 'debug', False),
            shadow_mode=getattr(args, 'shadow_mode', False),
            mirror_mode=getattr(args, 'mirror_mode', False),
            parallel=getattr(args, 'parallel', False),
            capture_mode=getattr(args, 'capture_mode', None),
            log_traps=getattr(args, 'log_traps', None)
        )

    # No command specified - show help
    # Import parser to show help
    from .parser import create_argument_parser
    parser = create_argument_parser()
    parser.print_help()
    return 0
