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
        return daemon_commands.run_foreground(debug=args.debug)
    
    elif args.foreground_daemon:
        # Hidden mode used by start_daemon() to run the actual daemon
        from ..logger import setup_logging
        from ..config import ensure_config_dir, LOG_MAX_SIZE, LOG_BACKUP_COUNT, LOG_COMPRESS
        from ..service import run_service
        from ..config import PID_FILE

        # Check if debug mode is enabled
        debug_mode = '--debug' in sys.argv

        # Set log level if specified
        log_level = args.log_level if args.log_level else None

        # Set up logging with rotation settings
        setup_logging(
            console=debug_mode,
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

        # Run the service with debug flag if needed
        return run_service(debug=debug_mode)

    return 0
