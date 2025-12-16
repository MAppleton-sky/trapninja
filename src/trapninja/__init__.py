#!/usr/bin/env python3
"""
TrapNinja - SNMP Trap Forwarder

A daemon service that listens for SNMP traps on specified UDP ports,
filters them based on configured rules, and forwards them to
designated destinations.
"""

# Import version information from single source of truth
from .__version__ import (
    __version__,
    __author__,
    __license__,
    __copyright__,
    __description__,
    get_version,
    get_version_info,
    has_feature,
    get_available_features,
)

# Public API
__all__ = [
    '__version__',
    '__author__',
    '__license__',
    '__copyright__',
    '__description__',
    'get_version',
    'get_version_info',
    'has_feature',
    'get_available_features',
]

# Avoid circular imports - modules will be imported where needed
