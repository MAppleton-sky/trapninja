#!/usr/bin/env python3
"""
TrapNinja HA Public API

Provides the public interface for HA functionality.
These are the functions that should be used by other modules.

Author: TrapNinja Team
Version: 2.0.0
"""

import logging
from typing import Optional, Dict, Any, Callable

from .state import HAState
from .config import HAConfig, load_ha_config
from .cluster import HACluster

logger = logging.getLogger("trapninja")

# Global HA cluster instance
_ha_cluster: Optional[HACluster] = None


def get_ha_cluster() -> Optional[HACluster]:
    """
    Get the global HA cluster instance.
    
    Returns:
        HACluster instance or None if not initialized
    """
    return _ha_cluster


def initialize_ha(
    config: HAConfig,
    trap_forwarder_callback: Callable[[bool], None]
) -> bool:
    """
    Initialize the global HA cluster.
    
    Args:
        config: HA configuration
        trap_forwarder_callback: Callback to enable/disable forwarding
        
    Returns:
        True if initialized successfully
    """
    global _ha_cluster
    
    try:
        _ha_cluster = HACluster(config, trap_forwarder_callback)
        return _ha_cluster.start()
    except Exception as e:
        logger.error(f"Failed to initialize HA cluster: {e}")
        return False


def shutdown_ha():
    """Shutdown the global HA cluster."""
    global _ha_cluster
    
    if _ha_cluster:
        _ha_cluster.stop()
        _ha_cluster = None


def get_ha_status() -> Dict[str, Any]:
    """
    Get current HA status.
    
    Returns:
        Dictionary with HA status information
    """
    if _ha_cluster:
        return _ha_cluster.get_status()
    return {"enabled": False, "state": "disabled"}


def is_forwarding_enabled() -> bool:
    """
    Check if trap forwarding is currently enabled.
    
    In HA mode, forwarding is only enabled on the PRIMARY node.
    In standalone mode, forwarding is always enabled.
    
    IMPORTANT: This function is called on every packet, so it must be fast.
    Logging is only done periodically or when state changes.
    
    Returns:
        True if forwarding is enabled
    """
    if _ha_cluster:
        enabled = _ha_cluster.is_forwarding
        # Debug logging to help diagnose HA issues
        # Only log when disabled to avoid log spam
        if not enabled:
            logger.debug(
                f"HA check: forwarding={enabled}, "
                f"state={_ha_cluster.current_state.value}"
            )
        return enabled
    
    # No HA cluster - check if HA was supposed to be enabled
    # This helps catch initialization issues
    logger.debug("HA cluster not initialized - forwarding allowed by default")
    return True


def notify_trap_processed():
    """
    Notify HA system that a trap was processed.
    
    Used for tracking activity and leader election.
    """
    if _ha_cluster:
        _ha_cluster.notify_trap_processed()


def promote_to_primary(force: bool = False) -> bool:
    """
    Manually promote this instance to PRIMARY.
    
    Args:
        force: If True, become PRIMARY immediately without coordination
        
    Returns:
        True if successful
    """
    if _ha_cluster:
        return _ha_cluster.promote_to_primary(force=force)
    logger.error("HA cluster not running")
    return False


def demote_to_secondary() -> bool:
    """
    Manually demote this instance to SECONDARY.
    
    Returns:
        True if successful
    """
    if _ha_cluster:
        return _ha_cluster.demote_to_secondary()
    logger.error("HA cluster not running")
    return False


def is_ha_enabled() -> bool:
    """
    Check if HA is enabled.
    
    Returns:
        True if HA is enabled and running
    """
    if _ha_cluster:
        return _ha_cluster.config.enabled
    return False


def get_ha_state() -> Optional[HAState]:
    """
    Get current HA state.
    
    Returns:
        Current HAState or None if HA not running
    """
    if _ha_cluster:
        return _ha_cluster.current_state
    return None


def is_primary() -> bool:
    """
    Check if this instance is PRIMARY.
    
    Returns:
        True if this instance is PRIMARY
    """
    if _ha_cluster:
        return _ha_cluster.current_state == HAState.PRIMARY
    return True  # If no HA, we're the only instance


def is_secondary() -> bool:
    """
    Check if this instance is SECONDARY.
    
    Returns:
        True if this instance is SECONDARY
    """
    if _ha_cluster:
        return _ha_cluster.current_state == HAState.SECONDARY
    return False


def force_failover() -> bool:
    """
    Force failover to secondary (for testing/maintenance).
    
    This is equivalent to demote_to_secondary() but provides
    a more intuitive name for operational use.
    
    Returns:
        True if successful
    """
    return demote_to_secondary()
