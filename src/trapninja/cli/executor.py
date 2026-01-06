#!/usr/bin/env python3
"""
TrapNinja Command Executor Module

Orchestrates command execution based on parsed arguments.
Coordinates between different command modules (daemon, filtering, HA).
UPDATED: Added handlers for new HA manual control commands
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


def update_global_config(args: Namespace) -> None:
    """
    Update global configuration variables based on command-line arguments

    Args:
        args: Parsed command-line arguments
    """
    from .. import config

    # Update interface if provided
    if args.interface:
        sanitized_interface = InputValidator.sanitize_string(args.interface, max_length=16)
        if sanitized_interface:
            config.INTERFACE = sanitized_interface
        else:
            print(f"Invalid interface name: {args.interface}")
            sys.exit(1)

    # Update config directory if provided
    if args.config_dir:
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
    if args.log_file:
        sanitized_log_file = InputValidator.sanitize_string(
            args.log_file, max_length=512, allow_special=True
        )
        if sanitized_log_file:
            config.LOG_FILE = os.path.abspath(sanitized_log_file)
        else:
            print(f"Invalid log file path: {args.log_file}")
            sys.exit(1)

    # Update PID file if provided
    if args.pid_file:
        sanitized_pid_file = InputValidator.sanitize_string(
            args.pid_file, max_length=512, allow_special=True
        )
        if sanitized_pid_file:
            config.PID_FILE = os.path.abspath(sanitized_pid_file)
        else:
            print(f"Invalid PID file path: {args.pid_file}")
            sys.exit(1)

    # Update log rotation settings
    if args.log_max_size:
        max_size = parse_size(args.log_max_size)
        if max_size is not None:
            config.LOG_MAX_SIZE = max_size
        else:
            print(f"Invalid log max size: {args.log_max_size}")
            print("Format should be a number with optional K, M, or G suffix (e.g., 10M, 1.5G)")
            sys.exit(1)

    if args.log_backup_count is not None:
        if args.log_backup_count >= 0:
            config.LOG_BACKUP_COUNT = args.log_backup_count
        else:
            print("Log backup count must be a non-negative integer")
            sys.exit(1)

    if args.log_compress:
        config.LOG_COMPRESS = True

    # Update listen ports if provided
    if args.ports:
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
    Execute the appropriate command based on parsed arguments

    Args:
        args: Parsed command-line arguments

    Returns:
        Exit code (0 for success, non-zero for failure)
    """
    # Handle HA commands first
    if args.configure_ha:
        if not args.ha_mode or not args.ha_peer_host:
            print("Error: --ha-mode and --ha-peer-host are required for HA configuration")
            print("Example: --configure-ha --ha-mode primary --ha-peer-host 192.168.1.101")
            return 1

        return 0 if ha_commands.configure_ha(
            args.ha_mode,
            args.ha_peer_host,
            args.ha_priority,
            args.ha_peer_port,
            args.ha_listen_port
        ) else 1

    elif args.disable_ha:
        return 0 if ha_commands.disable_ha() else 1

    elif args.ha_status:
        return 0 if ha_commands.show_ha_status() else 1

    # NEW: HA manual control commands
    elif args.promote:
        force = getattr(args, 'force', False)
        return 0 if ha_commands.promote_to_primary(force=force) else 1

    elif args.demote:
        return 0 if ha_commands.demote_to_secondary() else 1

    elif args.force_failover:
        return 0 if ha_commands.force_failover() else 1

    elif args.ha_help:
        return 0 if ha_commands.show_ha_help() else 1

    # Config sync commands
    elif hasattr(args, 'ha_sync') and args.ha_sync:
        from . import sync_commands
        force = getattr(args, 'force', False)
        return 0 if sync_commands.sync_now(force=force) else 1

    elif hasattr(args, 'sync_status') and args.sync_status:
        from . import sync_commands
        return 0 if sync_commands.show_sync_status() else 1
    
    elif hasattr(args, 'sync_help') and args.sync_help:
        from . import sync_commands
        return 0 if sync_commands.show_sync_help() else 1

    # Update global configuration before executing commands
    update_global_config(args)

    # Handle filtering commands
    if args.block_ip:
        return 0 if filtering_commands.block_ip(args.block_ip) else 1
    
    elif args.unblock_ip:
        return 0 if filtering_commands.unblock_ip(args.unblock_ip) else 1
    
    elif args.list_blocked_ips:
        return 0 if filtering_commands.list_blocked_ips() else 1

    elif args.block_oid:
        return 0 if filtering_commands.block_oid(args.block_oid) else 1
    
    elif args.unblock_oid:
        return 0 if filtering_commands.unblock_oid(args.unblock_oid) else 1
    
    elif args.list_blocked_oids:
        return 0 if filtering_commands.list_blocked_oids() else 1

    # Handle IP redirection commands
    elif args.redirect_ip:
        if not args.tag:
            print("Error: --tag is required for --redirect-ip")
            print("Example: --redirect-ip 10.0.0.1 --tag security")
            return 1
        return 0 if filtering_commands.redirect_ip(args.redirect_ip, args.tag) else 1
    
    elif args.unredirect_ip:
        return 0 if filtering_commands.unredirect_ip(args.unredirect_ip) else 1
    
    elif args.list_redirected_ips:
        return 0 if filtering_commands.list_redirected_ips() else 1

    # Handle OID redirection commands
    elif args.redirect_oid:
        if not args.tag:
            print("Error: --tag is required for --redirect-oid")
            print("Example: --redirect-oid 1.3.6.1.4.1.9.9.41.2.0.1 --tag security")
            return 1
        return 0 if filtering_commands.redirect_oid(args.redirect_oid, args.tag) else 1
    
    elif args.unredirect_oid:
        return 0 if filtering_commands.unredirect_oid(args.unredirect_oid) else 1
    
    elif args.list_redirected_oids:
        return 0 if filtering_commands.list_redirected_oids() else 1

    # Handle redirect destination commands
    elif args.add_redirect_dest:
        if not args.tag or not args.ip or not args.port:
            print("Error: --tag, --ip, and --port are required for --add-redirect-dest")
            print("Example: --add-redirect-dest --tag security --ip 10.1.1.100 --port 162")
            return 1
        return 0 if filtering_commands.add_redirect_destination(args.tag, args.ip, args.port) else 1
    
    elif args.remove_redirect_dest:
        if not args.tag or not args.ip or not args.port:
            print("Error: --tag, --ip, and --port are required for --remove-redirect-dest")
            print("Example: --remove-redirect-dest --tag security --ip 10.1.1.100 --port 162")
            return 1
        return 0 if filtering_commands.remove_redirect_destination(args.tag, args.ip, args.port) else 1
    
    elif args.list_redirect_dests:
        return 0 if filtering_commands.list_redirect_destinations() else 1
    
    elif args.redirection_help:
        return 0 if filtering_commands.show_redirection_help() else 1

    # Handle SNMPv3 commands
    elif args.snmpv3_add_user:
        if not args.username or not args.engine_id:
            print("Error: --username and --engine-id are required")
            print("Example: --snmpv3-add-user --username myuser --engine-id 80001f888056565656565656 --auth-protocol SHA --priv-protocol AES128")
            return 1
        return snmpv3_commands.handle_snmpv3_add_user(args)
    
    elif args.snmpv3_remove_user:
        if not args.username or not args.engine_id:
            print("Error: --username and --engine-id are required")
            return 1
        return snmpv3_commands.handle_snmpv3_remove_user(args)
    
    elif args.snmpv3_list_users:
        return snmpv3_commands.handle_snmpv3_list_users(args)
    
    elif args.snmpv3_show_user:
        if not args.username or not args.engine_id:
            print("Error: --username and --engine-id are required")
            return 1
        return snmpv3_commands.handle_snmpv3_show_user(args)
    
    elif args.snmpv3_status:
        return snmpv3_commands.handle_snmpv3_status(args)
    
    elif args.snmpv3_test_decrypt:
        return snmpv3_commands.handle_snmpv3_test_decrypt(args)

    # Handle cache commands
    elif args.cache_status:
        return 0 if cache_commands.show_cache_status(verbose=args.verbose) else 1
    
    elif args.cache_query:
        if not args.destination or not args.from_time or not args.to_time:
            print("Error: --destination, --from, and --to are required for cache query")
            print("Example: --cache-query --destination voice_noc --from \"14:30\" --to \"15:45\"")
            return 1
        return 0 if cache_commands.query_cache(
            destination=args.destination,
            start_time=args.from_time,
            end_time=args.to_time,
            limit=args.limit,
            show_oids=True
        ) else 1
    
    elif args.cache_replay:
        if not args.destination or not args.from_time or not args.to_time:
            print("Error: --destination, --from, and --to are required for cache replay")
            print("Example: --cache-replay --destination voice_noc --from \"14:30\" --to \"15:45\"")
            print("Use --dry-run to preview without sending")
            print("Use --replay-to HOST:PORT to send to a custom destination")
            return 1
        return 0 if cache_commands.replay_cache(
            destination=args.destination,
            start_time=args.from_time,
            end_time=args.to_time,
            rate_limit=args.rate_limit,
            dry_run=args.dry_run,
            oid_filter=args.oid_filter,
            source_filter=args.source_filter,
            exclude_oid=args.exclude_oid,
            yes=args.yes,
            replay_to=args.replay_to
        ) else 1
    
    elif args.cache_clear:
        return 0 if cache_commands.clear_cache(
            destination=args.destination,
            yes=args.yes
        ) else 1
    
    elif args.cache_trim:
        return 0 if cache_commands.trim_cache(yes=args.yes) else 1
    
    elif args.cache_help:
        return 0 if cache_commands.show_cache_help() else 1

    # Handle failover replay commands
    elif args.failover_status:
        from . import failover_commands
        return 0 if failover_commands.show_failover_status(verbose=args.verbose) else 1
    
    elif args.failover_detect:
        from . import failover_commands
        return 0 if failover_commands.detect_gaps(verbose=args.verbose) else 1
    
    elif args.failover_replay:
        from . import failover_commands
        # Auto-detect mode if no times specified
        if not args.from_time or not args.to_time:
            destination = args.destination or 'detect'
        else:
            if not args.destination:
                print("Error: --destination is required for manual replay")
                print("Example: --failover-replay --destination default --from \"-5m\" --to \"now\"")
                print("Use 'detect' as destination to auto-detect gaps: --failover-replay --destination detect")
                return 1
            destination = args.destination
        return 0 if failover_commands.trigger_manual_replay(
            destination=destination,
            start_time=args.from_time or '-5m',
            end_time=args.to_time or 'now',
            rate_limit=args.rate_limit if args.rate_limit != 500 else None,
            dry_run=args.dry_run,
            yes=args.yes
        ) else 1
    
    elif args.failover_help:
        from . import failover_commands
        return 0 if failover_commands.show_failover_help() else 1

    # Handle queue statistics
    elif args.queue_stats:
        return daemon_commands.queue_stats(json_output=getattr(args, 'json', False))

    # Handle granular statistics commands
    elif args.stats_summary:
        return stats_commands.handle_stats_summary(args)

    elif args.stats_top_ips:
        return stats_commands.handle_stats_top_ips(args)

    elif args.stats_top_oids:
        return stats_commands.handle_stats_top_oids(args)

    elif args.stats_ip:
        if not args.ip:
            print("Error: --ip is required for --stats-ip")
            print("Example: --stats-ip --ip 10.0.0.1")
            return 1
        return stats_commands.handle_stats_ip_detail(args)

    elif args.stats_oid:
        if not args.oid:
            print("Error: --oid is required for --stats-oid")
            print("Example: --stats-oid --oid 1.3.6.1.4.1.9.9.41.2.0.1")
            return 1
        return stats_commands.handle_stats_oid_detail(args)

    elif args.stats_destinations:
        return stats_commands.handle_stats_destinations(args)

    elif args.stats_dashboard:
        return stats_commands.handle_stats_dashboard(args)

    elif args.stats_export:
        return stats_commands.handle_stats_export(args)

    elif args.stats_reset:
        return stats_commands.handle_stats_reset(args)

    elif args.stats_help:
        return stats_commands.handle_stats_help(args)

    elif args.stats_debug:
        return stats_commands.handle_stats_debug(args)

    # Handle shadow mode commands
    elif args.shadow_status:
        return shadow_commands.handle_shadow_status(args)
    
    elif args.shadow_export:
        return shadow_commands.handle_shadow_export(args)
    
    # Handle metrics configuration commands
    elif hasattr(args, 'metrics_config') and args.metrics_config:
        from . import metrics_commands
        return metrics_commands.show_metrics_config(json_output=getattr(args, 'json', False))
    
    elif hasattr(args, 'metrics_set_dir') and args.metrics_set_dir:
        from . import metrics_commands
        return metrics_commands.set_metrics_directory(args.metrics_set_dir)
    
    elif hasattr(args, 'metrics_add_label') and args.metrics_add_label:
        from . import metrics_commands
        label_name = getattr(args, 'label_name', None)
        label_value = getattr(args, 'label_value', None)
        if not label_name or label_value is None:
            print("Error: --label-name and --label-value are required for --metrics-add-label")
            print("Example: --metrics-add-label --label-name on_prem --label-value 1")
            return 1
        return metrics_commands.add_metrics_label(label_name, label_value)
    
    elif hasattr(args, 'metrics_remove_label') and args.metrics_remove_label:
        from . import metrics_commands
        return metrics_commands.remove_metrics_label(args.metrics_remove_label)
    
    elif hasattr(args, 'metrics_set_interval') and args.metrics_set_interval:
        from . import metrics_commands
        return metrics_commands.set_export_interval(args.metrics_set_interval)
    
    elif hasattr(args, 'metrics_help') and args.metrics_help:
        from . import metrics_commands
        return metrics_commands.show_metrics_help()

    # Handle configuration commands
    elif args.show_config:
        return daemon_commands.show_config(json_output=getattr(args, 'json', False))
    
    elif args.validate_config:
        return daemon_commands.validate_config()

    # Handle daemon control commands
    elif args.start:
        return daemon_commands.start()
    
    elif args.stop:
        return daemon_commands.stop()
    
    elif args.restart:
        return daemon_commands.restart()
    
    elif args.status:
        return daemon_commands.status()
    
    elif args.foreground:
        return daemon_commands.run_foreground(
            debug=args.debug,
            shadow_mode=getattr(args, 'shadow_mode', False),
            mirror_mode=getattr(args, 'mirror_mode', False),
            parallel=getattr(args, 'parallel', False),
            capture_mode=getattr(args, 'capture_mode', None),
            log_traps=getattr(args, 'log_traps', None)
        )
    
    elif args.foreground_daemon:
        # Hidden mode used by start_daemon() to run the actual daemon
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

    return 0
