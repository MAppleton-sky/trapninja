#!/usr/bin/env python3
"""
TrapNinja Version Information

This is the single source of truth for version information.
All other version references should import from here.

Usage:
    from trapninja.__version__ import __version__, has_feature
    
    print(f"TrapNinja v{__version__}")
    if has_feature('ebpf'):
        print("eBPF acceleration available")
"""
import os
from pathlib import Path

# Read version from VERSION file (single source of truth)
_version_file = Path(__file__).parent.parent / 'VERSION'
try:
    with open(_version_file, 'r') as f:
        __version__ = f.read().strip()
except FileNotFoundError:
    __version__ = '0.0.0-dev'

# Package metadata
__author__ = 'Matthew Appleton'
__license__ = 'Proprietary'
__copyright__ = '2024-2025 Matthew Appleton'
__description__ = 'High-performance SNMP trap forwarding system with eBPF acceleration'

# Version info tuple for programmatic comparison
# Example: (0, 5, 0)
try:
    VERSION_INFO = tuple(int(x) for x in __version__.split('-')[0].split('.'))
except (ValueError, AttributeError):
    VERSION_INFO = (0, 0, 0)

# Feature flags based on version
# These indicate when major features were introduced
# Note: TrapNinja is in BETA - using 0.x.x versions until 1.0.0 release
FEATURES = {
    'basic_forwarding': VERSION_INFO >= (0, 1, 0),
    'filtering': VERSION_INFO >= (0, 2, 0),
    'multi_port': VERSION_INFO >= (0, 2, 0),
    'metrics': VERSION_INFO >= (0, 3, 0),
    'oid_filtering': VERSION_INFO >= (0, 3, 0),
    'ebpf': VERSION_INFO >= (0, 4, 0),
    'ha': VERSION_INFO >= (0, 5, 0),
    'snmpv3': VERSION_INFO >= (0, 5, 0),
    'cli_v2': VERSION_INFO >= (0, 5, 0),
    'modular_cli': VERSION_INFO >= (0, 5, 0),
}


def get_version() -> str:
    """
    Return the version string.
    
    Returns:
        str: Version string (e.g., "0.5.0")
    """
    return __version__


def get_version_info() -> tuple:
    """
    Return version as tuple for programmatic comparison.
    
    Returns:
        tuple: Version tuple (e.g., (0, 5, 0))
        
    Example:
        >>> version = get_version_info()
        >>> if version >= (0, 5, 0):
        ...     print("Using HA and SNMPv3")
    """
    return VERSION_INFO


def has_feature(feature: str) -> bool:
    """
    Check if a feature is available in this version.
    
    Args:
        feature: Feature name (e.g., 'ebpf', 'ha', 'snmpv3')
        
    Returns:
        bool: True if feature is available, False otherwise
        
    Example:
        >>> if has_feature('ebpf'):
        ...     print("eBPF acceleration is available")
    """
    return FEATURES.get(feature, False)


def get_available_features() -> dict:
    """
    Get dictionary of all features and their availability.
    
    Returns:
        dict: Feature names mapped to availability (bool)
        
    Example:
        >>> features = get_available_features()
        >>> enabled = [f for f, avail in features.items() if avail]
        >>> print(f"Enabled: {', '.join(enabled)}")
    """
    return FEATURES.copy()


def get_version_string_detailed() -> str:
    """
    Get detailed version string including enabled features.
    
    Returns:
        str: Detailed version string
        
    Example:
        >>> print(get_version_string_detailed())
        TrapNinja v0.5.0 (eBPF, HA, SNMPv3, CLI v2) [BETA]
    """
    enabled_features = [name for name, available in FEATURES.items() if available]
    feature_str = ', '.join(sorted(enabled_features))
    beta_marker = ' [BETA]' if VERSION_INFO[0] == 0 else ''
    return f"TrapNinja v{__version__} ({feature_str}){beta_marker}"


def get_version_banner() -> str:
    """
    Get formatted version banner for display.
    
    Returns:
        str: Multi-line version banner
    """
    enabled = [name.upper() for name, avail in FEATURES.items() if avail]
    feature_list = ' + '.join(enabled[:4])  # Show first 4 features
    if len(enabled) > 4:
        feature_list += f" + {len(enabled) - 4} more"
    
    # Add BETA indicator for 0.x.x versions
    beta_indicator = ' [BETA]' if VERSION_INFO[0] == 0 else ''
    
    banner = f"""
  _____                _   _ _       _       
 |_   _| __ __ _ _ __ | \ | (_)_ __ (_) __ _ 
   | || '__/ _` | '_ \|  \| | | '_ \| |/ _` |
   | || | | (_| | |_) | |\  | | | | | | (_| |
   |_||_|  \__,_| .__/|_| \_|_|_| |_| |\__,_|
                |_|               |___|
                         
         v{__version__}{beta_indicator} - SNMP Trap Forwarder
         Features: {feature_list}
    """
    return banner


# Module-level exports
__all__ = [
    '__version__',
    '__author__',
    '__license__',
    '__copyright__',
    '__description__',
    'VERSION_INFO',
    'FEATURES',
    'get_version',
    'get_version_info',
    'has_feature',
    'get_available_features',
    'get_version_string_detailed',
    'get_version_banner',
]
