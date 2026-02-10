#!/usr/bin/env python3
"""
TrapNinja Redirection Module - Consolidated Version

Provides redirection cache management and periodic config refresh.
Actual config loading is handled by config.py to maintain a single
source of truth for all configuration data.

Note: The hot path (processing/worker.py) reads redirection config
directly from config.py globals for performance. This module provides:
- Periodic config refresh scheduling
- Cache clearing when config changes
- Utility functions for redirection lookups (optional use)

Author: TrapNinja Team
Version: 2.0.0 (Consolidated)
"""
import os
import functools
import logging
from threading import Timer

logger = logging.getLogger("trapninja")


def get_config_path(filename: str) -> str:
    """
    Get the full path to a configuration file.

    Args:
        filename: Name of the configuration file

    Returns:
        Full path to the configuration file
    """
    from .config import CONFIG_DIR
    return os.path.join(CONFIG_DIR, filename)


@functools.lru_cache(maxsize=1024)
def lookup_redirection_tag(source_ip: str, trap_oid: str) -> str:
    """
    Look up redirection tag based on source IP or trap OID.
    
    Uses config.py globals for data (single source of truth).
    Results are cached for performance.

    Args:
        source_ip: Source IP address
        trap_oid: OID of the trap

    Returns:
        Redirection tag or empty string if not found
    """
    from .config import redirected_ips, redirected_oids
    
    # First check IP-based redirection
    tag = redirected_ips.get(source_ip, "")
    
    # If not found and trap_oid is provided, check OID-based redirection
    if not tag and trap_oid:
        tag = redirected_oids.get(trap_oid, "")
    
    return tag


def check_for_redirection(source_ip: str, trap_oid: str) -> tuple:
    """
    Check if a trap should be redirected based on source IP or trap OID.
    
    Note: This function is available for external use but the hot path
    in processing/worker.py accesses config.py globals directly for
    maximum performance.

    Args:
        source_ip: Source IP address of the trap
        trap_oid: OID of the trap

    Returns:
        tuple: (is_redirected, list of destination tuples, tag)
    """
    from .config import redirected_destinations
    
    tag = lookup_redirection_tag(source_ip, trap_oid)
    
    if tag:
        destinations = redirected_destinations.get(tag, [])
        if destinations:
            return True, destinations, tag
        else:
            logger.warning(f"Redirection tag '{tag}' has no configured destinations")
    
    return False, [], None


def clear_redirection_caches():
    """
    Clear LRU cache for redirection lookups.
    
    Called when configuration changes to ensure fresh lookups.
    """
    lookup_redirection_tag.cache_clear()
    logger.debug("Cleared redirection lookup caches")


def schedule_config_check(interval: int = 60):
    """
    Schedule periodic checks of configuration files.
    
    Delegates actual loading to config.py's load_config() to maintain
    a single source of truth. This function ensures:
    1. Config files are periodically re-read for hot-reload
    2. Caches are cleared when config changes
    3. Scheduling continues until stop_event is set

    Args:
        interval: Interval in seconds between checks (default: 60)
    """
    from .config import stop_event, load_config
    
    try:
        # Trigger config reload - updates config.py globals
        # Pass None for callback since we don't need UDP listener restart here
        config_changed = load_config(None)
        
        if config_changed:
            # Clear caches since config has changed
            clear_redirection_caches()
            logger.debug("Configuration changed, caches cleared")
        
        # Schedule next check if not stopping
        if not stop_event.is_set():
            Timer(interval, schedule_config_check, args=[interval]).start()
            
    except Exception as e:
        logger.error(f"Error in config check: {e}")
        # Still schedule next check to maintain operation
        if not stop_event.is_set():
            Timer(interval, schedule_config_check, args=[interval]).start()


def load_redirection_config():
    """
    Load all redirection configuration.
    
    This is a convenience wrapper that triggers config.py's load_config().
    Maintained for backward compatibility with service.py imports.

    Returns:
        tuple: (redirected_ips, redirected_oids, redirected_destinations)
               from config.py globals
    """
    from .config import (
        load_config,
        redirected_ips,
        redirected_oids, 
        redirected_destinations
    )
    
    # Trigger config reload
    load_config(None)
    
    # Return references to config.py globals
    return redirected_ips, redirected_oids, redirected_destinations
