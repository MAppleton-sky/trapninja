#!/usr/bin/env python3
"""
TrapNinja HA Compatibility Layer

Provides a single source of truth for HA module availability, ensuring
all modules handle missing HA dependencies identically.

This module should be used instead of direct HA imports in modules that
need graceful fallback when HA is not configured or available.

Usage:
    from .ha_compat import is_forwarding_enabled, notify_trap_processed, HA_AVAILABLE
"""

import logging

logger = logging.getLogger("trapninja")

# Attempt to import HA components
try:
    from .ha import is_forwarding_enabled as _is_forwarding_enabled
    from .ha import notify_trap_processed as _notify_trap_processed
    HA_AVAILABLE = True
except ImportError:
    HA_AVAILABLE = False
    logger.info("HA module unavailable - running in standalone mode")
    _is_forwarding_enabled = None
    _notify_trap_processed = None


def is_forwarding_enabled() -> bool:
    """
    Check if forwarding is enabled based on HA state.
    
    Returns:
        True if forwarding should occur (always True in standalone mode)
    """
    if HA_AVAILABLE:
        return _is_forwarding_enabled()
    return True


def notify_trap_processed() -> None:
    """
    Notify HA system that a trap was processed.
    
    No-op in standalone mode.
    """
    if HA_AVAILABLE:
        _notify_trap_processed()
