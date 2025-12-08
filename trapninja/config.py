#!/usr/bin/env python3
"""
TrapNinja Configuration Module - Fixed Version

Handles loading, parsing, and updating the configuration files with
improved efficiency and better data structures.
"""
import os
import sys
import json
import logging
import time
from threading import Timer, Event
from collections import defaultdict

# Configuration defaults
INTERFACE = "ens192"  # Change to your interface name
LISTEN_PORTS = [162]  # Default listening port for SNMP traps
CONFIG_CHECK_INTERVAL = 60  # Check config files every 60 seconds

# Packet capture mode configuration
# Options:
#   "auto"   - Use eBPF if available, fall back to sniff (recommended)
#   "sniff"  - Use Scapy sniff() with libpcap (reliable, cross-platform)
#   "socket" - Use UDP socket listeners (lower overhead, but may conflict with other services)
# WARNING: Never use both socket and sniff simultaneously - it will duplicate packets!
CAPTURE_MODE = "auto"

# Paths to config files
CONFIG_DIR = "/opt/trapninja/config"
DESTINATIONS_FILE = os.path.join(CONFIG_DIR, "destinations.json")
BLOCKED_TRAPS_FILE = os.path.join(CONFIG_DIR, "blocked_traps.json")
LISTEN_PORTS_FILE = os.path.join(CONFIG_DIR, "listen_ports.json")
BLOCKED_IPS_FILE = os.path.join(CONFIG_DIR, "blocked_ips.json")
REDIRECTED_IPS_FILE = os.path.join(CONFIG_DIR, "redirected_ips.json")
REDIRECTED_OIDS_FILE = os.path.join(CONFIG_DIR, "redirected_oids.json")
REDIRECTED_DESTINATIONS_FILE = os.path.join(CONFIG_DIR, "redirected_destinations.json")

# Daemon settings
PID_FILE = "/var/run/trapninja.pid"
LOG_FILE = "/var/log/trapninja/trapninja.log"
LOG_LEVEL = "INFO"

# Log rotation settings
LOG_MAX_SIZE = 10 * 1024 * 1024  # 10 MB
LOG_BACKUP_COUNT = 5
LOG_COMPRESS = False

# Global variables to store config - optimized data structures
destinations = []
blocked_traps = set()  # Using set for O(1) lookups
blocked_dest = [("127.0.0.1", 1462)]
blocked_ips = set()  # IPs that should be blocked - using set for O(1) lookups
redirected_ips = defaultdict(str)  # Maps IP -> tag
redirected_oids = defaultdict(str)  # Maps OID -> tag
redirected_destinations = defaultdict(list)  # Maps tag -> list of (ip, port) destinations

# Cache metadata about config files
dest_mtime = 0
blocked_mtime = 0
ports_mtime = 0
blocked_ips_mtime = 0
redirected_ips_mtime = 0
redirected_oids_mtime = 0
redirected_destinations_mtime = 0

# Event to signal termination
stop_event = Event()

# Get logger but don't import directly from logger module
logger = logging.getLogger("trapninja")


def ensure_config_dir():
    """
    Ensure the configuration directory exists
    Creates example config files if they don't exist
    """
    # Use existing logger instance
    log = logging.getLogger("trapninja")

    if not os.path.exists(CONFIG_DIR):
        try:
            os.makedirs(CONFIG_DIR)
            log.info(f"Created configuration directory: {CONFIG_DIR}")

            # Create example config files if they don't exist
            if not os.path.exists(DESTINATIONS_FILE):
                with open(DESTINATIONS_FILE, 'w') as f:
                    json.dump([["192.168.1.100", 162]], f, indent=2)
                log.info(f"Created example destinations file: {DESTINATIONS_FILE}")

            if not os.path.exists(BLOCKED_TRAPS_FILE):
                with open(BLOCKED_TRAPS_FILE, 'w') as f:
                    json.dump([], f, indent=2)
                log.info(f"Created example blocked traps file: {BLOCKED_TRAPS_FILE}")

            if not os.path.exists(LISTEN_PORTS_FILE):
                with open(LISTEN_PORTS_FILE, 'w') as f:
                    json.dump([162], f, indent=2)
                log.info(f"Created example listen ports file: {LISTEN_PORTS_FILE}")

            if not os.path.exists(BLOCKED_IPS_FILE):
                with open(BLOCKED_IPS_FILE, 'w') as f:
                    json.dump([], f, indent=2)
                log.info(f"Created example blocked IPs file: {BLOCKED_IPS_FILE}")

            if not os.path.exists(REDIRECTED_IPS_FILE):
                with open(REDIRECTED_IPS_FILE, 'w') as f:
                    json.dump([["192.168.10.50", "security"]], f, indent=2)
                log.info(f"Created example redirected IPs file: {REDIRECTED_IPS_FILE}")

            if not os.path.exists(REDIRECTED_OIDS_FILE):
                with open(REDIRECTED_OIDS_FILE, 'w') as f:
                    json.dump([["1.3.6.1.4.1.8072.2.3.0.1", "security"]], f, indent=2)
                log.info(f"Created example redirected OIDs file: {REDIRECTED_OIDS_FILE}")

            if not os.path.exists(REDIRECTED_DESTINATIONS_FILE):
                with open(REDIRECTED_DESTINATIONS_FILE, 'w') as f:
                    example_destinations = {
                        "security": [["127.0.0.1", 1362]],
                        "config": [["127.0.0.1", 1462]]
                    }
                    json.dump(example_destinations, f, indent=2)
                log.info(f"Created example redirected destinations file: {REDIRECTED_DESTINATIONS_FILE}")
        except Exception as e:
            log.error(f"Failed to create config directory: {e}")
            sys.exit(1)


def safe_load_json(file_path, fallback):
    """
    Safely load JSON from file with error handling

    Args:
        file_path (str): Path to the JSON file
        fallback: Default value to return if loading fails

    Returns:
        The loaded JSON data or fallback value
    """
    # Use existing logger instance
    log = logging.getLogger("trapninja")

    try:
        if os.path.exists(file_path):
            with open(file_path, 'r') as f:
                data = json.load(f)
                log.debug(f"Loaded JSON from {file_path}: {data}")
                return data
        else:
            log.warning(f"Config file {file_path} not found. Using fallback values.")
            return fallback
    except json.JSONDecodeError as e:
        log.error(f"JSON parsing failed for {file_path}: {e}")
        return fallback
    except Exception as e:
        log.error(f"Unexpected error loading {file_path}: {e}")
        return fallback


def load_config(restart_udp_listeners_callback=None):
    """
    Load configuration files and update global variables
    Optimized to only reload files that have changed

    Args:
        restart_udp_listeners_callback: Callback function to restart UDP listeners when needed

    Returns:
        bool: True if any configuration changed, False otherwise
    """
    global destinations, blocked_traps, LISTEN_PORTS, dest_mtime, blocked_mtime, ports_mtime
    global blocked_ips, blocked_ips_mtime, redirected_ips, redirected_oids, redirected_destinations
    global redirected_ips_mtime, redirected_oids_mtime, redirected_destinations_mtime

    # Use existing logger instance
    log = logging.getLogger("trapninja")
    log.debug("Loading configuration files...")

    # Track if any config changed
    config_changed = False

    try:
        # Check and load destinations file if modified
        if os.path.exists(DESTINATIONS_FILE):
            current_dest_mtime = os.path.getmtime(DESTINATIONS_FILE)
            if current_dest_mtime != dest_mtime:
                loaded_destinations = safe_load_json(DESTINATIONS_FILE, [])
                if loaded_destinations:
                    destinations = loaded_destinations
                    log.debug(f"Destinations loaded: {destinations}")
                    dest_mtime = current_dest_mtime
                    config_changed = True
                    log.info(f"Reloaded destinations: {destinations}")
                else:
                    log.warning("Loaded empty destinations list, maintaining current destinations")
        else:
            log.warning(f"Destinations file does not exist: {DESTINATIONS_FILE}")
    except Exception as e:
        log.error(f"Loading destinations failed: {e}", exc_info=True)

    try:
        # Check and load blocked traps file if modified
        if os.path.exists(BLOCKED_TRAPS_FILE):
            current_blocked_mtime = os.path.getmtime(BLOCKED_TRAPS_FILE)
            if current_blocked_mtime != blocked_mtime:
                # Use set for more efficient lookups
                blocked_traps = set(safe_load_json(BLOCKED_TRAPS_FILE, []))
                blocked_mtime = current_blocked_mtime
                config_changed = True
                log.info(f"Reloaded {len(blocked_traps)} blocked traps")
        else:
            log.warning(f"Blocked traps file does not exist: {BLOCKED_TRAPS_FILE}")
    except Exception as e:
        log.error(f"Loading blocked traps failed: {e}")

    try:
        # Check and load blocked IPs file if modified
        if os.path.exists(BLOCKED_IPS_FILE):
            current_blocked_ips_mtime = os.path.getmtime(BLOCKED_IPS_FILE)
            if current_blocked_ips_mtime != blocked_ips_mtime:
                # Use set for more efficient lookups
                blocked_ips = set(safe_load_json(BLOCKED_IPS_FILE, []))
                blocked_ips_mtime = current_blocked_ips_mtime
                config_changed = True
                log.info(f"Reloaded {len(blocked_ips)} blocked IPs")
        else:
            log.warning(f"Blocked IPs file does not exist: {BLOCKED_IPS_FILE}")
    except Exception as e:
        log.error(f"Loading blocked IPs failed: {e}")

    try:
        # Load redirection configuration
        try:
            # Simplified approach to avoid circular imports
            if os.path.exists(REDIRECTED_IPS_FILE):
                current_time = os.path.getmtime(REDIRECTED_IPS_FILE)
                if current_time != redirected_ips_mtime:
                    loaded_data = safe_load_json(REDIRECTED_IPS_FILE, [])
                    temp_dict = defaultdict(str)
                    for item in loaded_data:
                        if len(item) == 2:
                            ip, tag = item
                            if isinstance(tag, str):
                                temp_dict[ip] = tag
                    redirected_ips = temp_dict
                    redirected_ips_mtime = current_time
                    config_changed = True
                    log.info(f"Loaded {len(redirected_ips)} IP redirection rules")

            if os.path.exists(REDIRECTED_OIDS_FILE):
                current_time = os.path.getmtime(REDIRECTED_OIDS_FILE)
                if current_time != redirected_oids_mtime:
                    loaded_data = safe_load_json(REDIRECTED_OIDS_FILE, [])
                    temp_dict = defaultdict(str)
                    for item in loaded_data:
                        if len(item) == 2:
                            oid, tag = item
                            if isinstance(tag, str):
                                temp_dict[oid] = tag
                    redirected_oids = temp_dict
                    redirected_oids_mtime = current_time
                    config_changed = True
                    log.info(f"Loaded {len(redirected_oids)} OID redirection rules")

            if os.path.exists(REDIRECTED_DESTINATIONS_FILE):
                current_time = os.path.getmtime(REDIRECTED_DESTINATIONS_FILE)
                if current_time != redirected_destinations_mtime:
                    loaded_data = safe_load_json(REDIRECTED_DESTINATIONS_FILE, {})
                    temp_dict = defaultdict(list)
                    for tag, destinations_list in loaded_data.items():
                        if isinstance(tag, str) and isinstance(destinations_list, list):
                            valid_destinations = []
                            for dest in destinations_list:
                                if isinstance(dest, list) and len(dest) == 2:
                                    try:
                                        ip, port = dest
                                        port = int(port)
                                        if 1 <= port <= 65535:
                                            valid_destinations.append((ip, port))
                                    except (ValueError, TypeError):
                                        pass
                            if valid_destinations:
                                temp_dict[tag] = valid_destinations
                    redirected_destinations = temp_dict
                    redirected_destinations_mtime = current_time
                    config_changed = True
                    log.info(f"Loaded {len(redirected_destinations)} destination groups")

        except Exception as inner_e:
            log.error(f"Loading redirection config failed: {inner_e}")
    except Exception as e:
        log.error(f"Loading redirection configuration failed: {e}")

    try:
        # Check and load listen ports file if modified
        if os.path.exists(LISTEN_PORTS_FILE):
            current_ports_mtime = os.path.getmtime(LISTEN_PORTS_FILE)
            if current_ports_mtime != ports_mtime:
                new_ports = safe_load_json(LISTEN_PORTS_FILE, [162])
                log.debug(f"Loaded ports from file: {new_ports}")

                # Fix for nested arrays - flatten if needed
                if new_ports and isinstance(new_ports, list) and len(new_ports) > 0:
                    if isinstance(new_ports[0], list):
                        log.warning(f"Found nested port array, flattening: {new_ports}")
                        new_ports = [item for sublist in new_ports for item in sublist]

                # Validate ports - must be integers between 1-65535
                valid_ports = []
                for port in new_ports:
                    try:
                        port_num = int(port)
                        if 1 <= port_num <= 65535:
                            valid_ports.append(port_num)
                        else:
                            log.warning(f"Invalid port number {port_num} (must be 1-65535)")
                    except (ValueError, TypeError):
                        log.warning(f"Ignoring non-integer port: {port}")

                if not valid_ports:
                    log.warning("No valid ports found, using default port 162")
                    valid_ports = [162]

                # Only update if the new ports are different from current ports
                if set(valid_ports) != set(LISTEN_PORTS):
                    # Update global variable
                    LISTEN_PORTS = valid_ports
                    ports_mtime = current_ports_mtime
                    config_changed = True
                    log.info(f"Reloaded listen ports: {LISTEN_PORTS}")

                    # Restart UDP listeners when ports config changes
                    if restart_udp_listeners_callback:
                        restart_udp_listeners_callback()
                else:
                    # Just update the timestamp if ports haven't changed
                    ports_mtime = current_ports_mtime
        else:
            log.warning(f"Listen ports file does not exist: {LISTEN_PORTS_FILE}")
    except Exception as e:
        log.error(f"Loading listen ports failed: {e}")

    # Debug output for final configuration
    log.debug(f"Final configuration:")
    log.debug(f"  Destinations: {destinations}")
    log.debug(f"  Listen ports: {LISTEN_PORTS}")
    log.debug(f"  Blocked traps: {len(blocked_traps)}")
    log.debug(f"  Blocked IPs: {len(blocked_ips)}")

    # Schedule next config check if not stopping
    if not stop_event.is_set():
        Timer(CONFIG_CHECK_INTERVAL, load_config, args=[restart_udp_listeners_callback]).start()

    return config_changed