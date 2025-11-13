#!/usr/bin/env python3
"""
TrapNinja Redirection Module - Optimized Version

Handles redirection of SNMP traps based on source IP addresses or trap OIDs.
Optimized with caching and more efficient data structures.
"""
import os
import json
import logging
import re
import time
import functools
from threading import Timer
from collections import defaultdict

# Get logger instance
logger = logging.getLogger("trapninja")

# Global dictionaries for redirection configuration - optimized data structures
redirected_ips = defaultdict(str)  # Maps IP -> tag
redirected_oids = defaultdict(str)  # Maps OID -> tag
redirected_destinations = defaultdict(list)  # Maps tag -> list of (ip, port) destinations

# Cache metadata about config files for efficient reloading
redirected_ips_mtime = 0
redirected_oids_mtime = 0
redirected_destinations_mtime = 0


def get_config_path(filename):
    """
    Get the full path to a configuration file

    Args:
        filename (str): Name of the configuration file

    Returns:
        str: Full path to the configuration file
    """
    from .config import CONFIG_DIR
    return os.path.join(CONFIG_DIR, filename)


def safe_load_json(file_path, fallback, log_prefix=""):
    """
    Safely load JSON from file with error handling and better logging

    Args:
        file_path (str): Path to the JSON file
        fallback: Default value to return if loading fails
        log_prefix (str): Prefix for log messages

    Returns:
        The loaded JSON data or fallback value
    """
    try:
        if os.path.exists(file_path):
            with open(file_path, 'r') as f:
                return json.load(f)
        else:
            logger.warning(f"{log_prefix}Config file {file_path} not found. Using fallback values.")
            return fallback
    except json.JSONDecodeError as e:
        logger.error(f"{log_prefix}JSON parsing failed for {file_path}: {e}")
        return fallback
    except Exception as e:
        logger.error(f"{log_prefix}Unexpected error loading {file_path}: {e}")
        return fallback


def validate_ip(ip_str):
    """
    Validate an IP address string

    Args:
        ip_str (str): IP address as string

    Returns:
        str: Valid IP address or None
    """
    import ipaddress
    try:
        # Using ipaddress module to validate IP
        ip_obj = ipaddress.ip_address(ip_str)
        return str(ip_obj)
    except ValueError:
        return None


def validate_oid(oid_str):
    """
    Validate an OID (Object Identifier) string

    Args:
        oid_str (str): OID string to validate

    Returns:
        str: Valid OID or None
    """
    # OIDs typically follow the format: 1.3.6.1.2.1... (numeric segments separated by dots)
    oid_pattern = r'^(\d+\.)+\d+$'
    if re.match(oid_pattern, oid_str):
        return oid_str
    return None


def load_redirected_ips():
    """
    Load IP redirection mappings from configuration file
    Optimized to only load if file has changed

    Returns:
        dict: Mapping of IP addresses to destination tags
    """
    global redirected_ips, redirected_ips_mtime

    file_path = get_config_path("redirected_ips.json")

    try:
        if os.path.exists(file_path):
            current_mtime = os.path.getmtime(file_path)

            # Only reload if file has been modified
            if current_mtime != redirected_ips_mtime:
                loaded_data = safe_load_json(file_path, [], "Redirection IP: ")

                # Use defaultdict for more efficient lookups
                temp_dict = defaultdict(str)

                # Convert list of [ip, tag] pairs to dictionary
                for item in loaded_data:
                    if len(item) == 2:
                        ip, tag = item
                        valid_ip = validate_ip(ip)
                        if valid_ip and isinstance(tag, str):
                            temp_dict[valid_ip] = tag
                        else:
                            logger.warning(f"Invalid IP redirection entry: {item}")

                redirected_ips = temp_dict
                redirected_ips_mtime = current_mtime
                logger.info(f"Loaded {len(redirected_ips)} IP redirection rules")

                # Log a few entries as examples if there are any
                if redirected_ips:
                    sample = list(redirected_ips.items())[:3]  # First 3 entries
                    logger.info(f"Sample IP redirections: {sample}")
        else:
            if redirected_ips_mtime != 0:  # Only log if it's not the first check
                logger.info(f"Redirected IPs file not found: {file_path}")
            redirected_ips = defaultdict(str)
            redirected_ips_mtime = 0

    except Exception as e:
        logger.error(f"Error loading redirected IPs: {e}")

    return redirected_ips


def load_redirected_oids():
    """
    Load OID redirection mappings from configuration file
    Optimized to only load if file has changed

    Returns:
        dict: Mapping of OIDs to destination tags
    """
    global redirected_oids, redirected_oids_mtime

    file_path = get_config_path("redirected_oids.json")

    try:
        if os.path.exists(file_path):
            current_mtime = os.path.getmtime(file_path)

            # Only reload if file has been modified
            if current_mtime != redirected_oids_mtime:
                loaded_data = safe_load_json(file_path, [], "Redirection OID: ")

                # Use defaultdict for more efficient lookups
                temp_dict = defaultdict(str)

                # Convert list of [oid, tag] pairs to dictionary
                for item in loaded_data:
                    if len(item) == 2:
                        oid, tag = item
                        valid_oid = validate_oid(oid)
                        if valid_oid and isinstance(tag, str):
                            temp_dict[valid_oid] = tag
                        else:
                            logger.warning(f"Invalid OID redirection entry: {item}")

                redirected_oids = temp_dict
                redirected_oids_mtime = current_mtime
                logger.info(f"Loaded {len(redirected_oids)} OID redirection rules")

                # Log a few entries as examples if there are any
                if redirected_oids:
                    sample = list(redirected_oids.items())[:3]  # First 3 entries
                    logger.info(f"Sample OID redirections: {sample}")
        else:
            if redirected_oids_mtime != 0:  # Only log if it's not the first check
                logger.info(f"Redirected OIDs file not found: {file_path}")
            redirected_oids = defaultdict(str)
            redirected_oids_mtime = 0

    except Exception as e:
        logger.error(f"Error loading redirected OIDs: {e}")

    return redirected_oids


def load_redirected_destinations():
    """
    Load destination group mappings from configuration file
    Optimized with better validation and data structures

    Returns:
        dict: Mapping of tags to lists of destination tuples (ip, port)
    """
    global redirected_destinations, redirected_destinations_mtime

    file_path = get_config_path("redirected_destinations.json")

    try:
        if os.path.exists(file_path):
            current_mtime = os.path.getmtime(file_path)

            # Only reload if file has been modified
            if current_mtime != redirected_destinations_mtime:
                loaded_data = safe_load_json(file_path, {}, "Redirection Destinations: ")

                # Use defaultdict for more efficient lookups
                temp_dict = defaultdict(list)

                # Validate the destination entries
                for tag, destinations in loaded_data.items():
                    if isinstance(tag, str) and isinstance(destinations, list):
                        valid_destinations = []
                        for dest in destinations:
                            if isinstance(dest, list) and len(dest) == 2:
                                ip, port = dest
                                valid_ip = validate_ip(ip)
                                try:
                                    port = int(port)
                                    if valid_ip and 1 <= port <= 65535:
                                        valid_destinations.append((valid_ip, port))
                                    else:
                                        logger.warning(f"Invalid destination in {tag} group: {dest}")
                                except (ValueError, TypeError):
                                    logger.warning(f"Invalid port in destination: {dest}")

                        if valid_destinations:
                            temp_dict[tag] = valid_destinations

                redirected_destinations = temp_dict
                redirected_destinations_mtime = current_mtime
                logger.info(f"Loaded {len(redirected_destinations)} destination groups")

                # Log the destination groups
                for tag, destinations in redirected_destinations.items():
                    logger.info(f"Destination group '{tag}': {destinations}")
        else:
            if redirected_destinations_mtime != 0:  # Only log if it's not the first check
                logger.info(f"Redirected destinations file not found: {file_path}")
            redirected_destinations = defaultdict(list)
            redirected_destinations_mtime = 0

    except Exception as e:
        logger.error(f"Error loading redirected destinations: {e}")

    return redirected_destinations


def load_redirection_config():
    """
    Load all redirection configuration files in a single operation
    for better efficiency

    Returns:
        tuple: (redirected_ips, redirected_oids, redirected_destinations)
    """
    ips = load_redirected_ips()
    oids = load_redirected_oids()
    destinations = load_redirected_destinations()

    return ips, oids, destinations


# Use lru_cache for better performance
@functools.lru_cache(maxsize=1024)
def lookup_redirection_tag(source_ip, trap_oid):
    """
    Look up redirection tag based on source IP or trap OID
    Separated for better caching and performance

    Args:
        source_ip (str): Source IP address
        trap_oid (str): OID of the trap

    Returns:
        str: Redirection tag or empty string if not found
    """
    # First check IP-based redirection
    tag = redirected_ips.get(source_ip, "")

    # If not found and trap_oid is provided, check OID-based redirection
    if not tag and trap_oid:
        tag = redirected_oids.get(trap_oid, "")

    return tag


def check_for_redirection(source_ip, trap_oid):
    """
    Check if a trap should be redirected based on source IP or trap OID
    Optimized with caching and better data structures

    Args:
        source_ip (str): Source IP address of the trap
        trap_oid (str): OID of the trap

    Returns:
        tuple: (is_redirected, list of destination tuples, tag)
    """
    # Look up redirection tag using cached function
    tag = lookup_redirection_tag(source_ip, trap_oid)

    # If a redirection tag was found, get the associated destinations
    if tag:
        destinations = redirected_destinations.get(tag, [])
        if destinations:
            return True, destinations, tag
        else:
            logger.warning(f"Redirection tag '{tag}' has no configured destinations")

    # No redirection found
    return False, [], None


def clear_redirection_caches():
    """
    Clear any caches used by redirection functions
    Called when configuration changes
    """
    # Clear LRU cache for redirection lookup
    lookup_redirection_tag.cache_clear()
    logger.debug("Cleared redirection lookup caches")


def schedule_config_check(interval=60):
    """
    Schedule periodic checks of redirection configuration files
    Optimized to be more efficient and handle exceptions better

    Args:
        interval (int): Interval in seconds between checks
    """
    from .config import stop_event

    try:
        # Load the configuration
        load_redirection_config()

        # Clear caches if needed
        clear_redirection_caches()

        # Schedule next check if not stopping
        if not stop_event.is_set():
            Timer(interval, schedule_config_check, args=[interval]).start()
    except Exception as e:
        logger.error(f"Error in redirection config check: {e}")
        # Still schedule next check to maintain operation
        if not stop_event.is_set():
            Timer(interval, schedule_config_check, args=[interval]).start()