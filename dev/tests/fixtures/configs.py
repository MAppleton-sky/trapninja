#!/usr/bin/env python3
"""
TrapNinja Test Fixtures - Configurations

Configuration builders and sample configurations for testing.
Includes both raw data and pytest fixtures.

Author: TrapNinja Team
"""

from typing import Dict, List, Set, Any, Optional, Tuple
from .sample_data import SampleOIDs, SampleIPs


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def create_packet_data(
    src_ip: str,
    payload: bytes,
    dst_port: int = 162
) -> Dict[str, Any]:
    """
    Create a packet data dictionary for worker tests.
    
    Args:
        src_ip: Source IP address
        payload: SNMP payload bytes
        dst_port: Destination port (default 162)
        
    Returns:
        Packet data dictionary
    """
    return {
        'src_ip': src_ip,
        'dst_port': dst_port,
        'payload': payload
    }


def create_config(
    destinations: Optional[List[Tuple[str, int]]] = None,
    blocked_traps: Optional[Set[str]] = None,
    blocked_dest: Optional[List[Tuple[str, int]]] = None,
    blocked_ips: Optional[Set[str]] = None,
    redirected_ips: Optional[Dict[str, str]] = None,
    redirected_oids: Optional[Dict[str, str]] = None,
    redirected_destinations: Optional[Dict[str, List[Tuple[str, int]]]] = None
) -> Dict[str, Any]:
    """
    Create a configuration dictionary with sensible defaults.
    
    Args:
        All config components (use None for empty/default)
        
    Returns:
        Configuration dictionary
    """
    return {
        'destinations': destinations or [],
        'blocked_traps': blocked_traps or set(),
        'blocked_dest': blocked_dest or [],
        'blocked_ips': blocked_ips or set(),
        'redirected_ips': redirected_ips or {},
        'redirected_oids': redirected_oids or {},
        'redirected_destinations': redirected_destinations or {},
    }


# =============================================================================
# SAMPLE DATA GENERATORS
# =============================================================================

def get_sample_destinations() -> List[Tuple[str, int]]:
    """Standard destination list."""
    return [
        (SampleIPs.DEST_PRIMARY, 162),
        (SampleIPs.DEST_SECONDARY, 162),
    ]


def get_sample_destinations_json() -> List[List]:
    """Destination list in JSON format (for config file tests)."""
    # JSON has no tuple type - use lists
    return [
        [SampleIPs.DEST_PRIMARY, 162],
        [SampleIPs.DEST_SECONDARY, 162],
    ]


def get_multi_destinations() -> List[Tuple[str, int]]:
    """Multiple destinations for fan-out tests."""
    return [
        (SampleIPs.DEST_PRIMARY, 162),
        (SampleIPs.DEST_SECONDARY, 162),
        (SampleIPs.DEST_TERTIARY, 162),
        ("10.0.0.50", 162),
    ]


def get_single_destination() -> List[Tuple[str, int]]:
    """Single destination for basic tests."""
    return [(SampleIPs.DEST_PRIMARY, 162)]


def get_sample_blocked_ips() -> List[str]:
    """List of blocked IPs."""
    return [SampleIPs.BLOCKED_1, SampleIPs.BLOCKED_2, SampleIPs.BLOCKED_3]


def get_sample_blocked_ips_set() -> Set[str]:
    """Set of blocked IPs."""
    return {SampleIPs.BLOCKED_1, SampleIPs.BLOCKED_2, SampleIPs.BLOCKED_3}


def get_sample_blocked_traps() -> List[str]:
    """List of blocked OIDs."""
    return [SampleOIDs.BLOCKED_1, SampleOIDs.BLOCKED_2, SampleOIDs.BLOCKED_3]


def get_sample_blocked_traps_set() -> Set[str]:
    """Set of blocked OIDs."""
    return {SampleOIDs.BLOCKED_1, SampleOIDs.BLOCKED_2, SampleOIDs.BLOCKED_3}


def get_sample_redirected_ips() -> List[List]:
    """IP redirection rules (JSON format)."""
    return [
        [SampleIPs.REDIRECT_SECURITY_1, 'security'],
        [SampleIPs.REDIRECT_SECURITY_2, 'security'],
        [SampleIPs.REDIRECT_VOICE, 'voice'],
        [SampleIPs.REDIRECT_DATA, 'data'],
    ]


def get_sample_redirected_ips_dict() -> Dict[str, str]:
    """IP redirection rules as dict."""
    return {
        SampleIPs.REDIRECT_SECURITY_1: 'security',
        SampleIPs.REDIRECT_SECURITY_2: 'security',
        SampleIPs.REDIRECT_VOICE: 'voice',
        SampleIPs.REDIRECT_DATA: 'data',
    }


def get_sample_redirected_oids() -> List[List]:
    """OID redirection rules (JSON format)."""
    return [
        [SampleOIDs.REDIRECT_VOICE, 'voice'],
        [SampleOIDs.REDIRECT_DATA, 'data'],
        [SampleOIDs.REDIRECT_SECURITY, 'security'],
    ]


def get_sample_redirected_oids_dict() -> Dict[str, str]:
    """OID redirection rules as dict."""
    return {
        SampleOIDs.REDIRECT_VOICE: 'voice',
        SampleOIDs.REDIRECT_DATA: 'data',
        SampleOIDs.REDIRECT_SECURITY: 'security',
    }


def get_sample_redirected_destinations() -> Dict[str, List[List]]:
    """Destination groups (JSON format)."""
    return {
        'security': [[SampleIPs.DEST_SECURITY_1, 162], [SampleIPs.DEST_SECURITY_2, 162]],
        'voice': [[SampleIPs.DEST_VOICE_1, 162]],
        'data': [[SampleIPs.DEST_DATA_1, 162], [SampleIPs.DEST_DATA_2, 162]],
        'blocked_archive': [[SampleIPs.DEST_BLOCKED, 1162]],
    }


def get_sample_redirected_destinations_tuples() -> Dict[str, List[Tuple[str, int]]]:
    """Destination groups with tuple format."""
    return {
        'security': [(SampleIPs.DEST_SECURITY_1, 162), (SampleIPs.DEST_SECURITY_2, 162)],
        'voice': [(SampleIPs.DEST_VOICE_1, 162)],
        'data': [(SampleIPs.DEST_DATA_1, 162), (SampleIPs.DEST_DATA_2, 162)],
        'blocked_archive': [(SampleIPs.DEST_BLOCKED, 1162)],
    }


# =============================================================================
# COMPLETE CONFIGURATIONS
# =============================================================================

def get_mock_config() -> Dict[str, Any]:
    """Complete mock configuration for worker tests."""
    return {
        'destinations': get_sample_destinations(),
        'blocked_traps': get_sample_blocked_traps_set(),
        'blocked_dest': [(SampleIPs.DEST_BLOCKED, 1162)],
        'blocked_ips': get_sample_blocked_ips_set(),
        'redirected_ips': get_sample_redirected_ips_dict(),
        'redirected_oids': get_sample_redirected_oids_dict(),
        'redirected_destinations': get_sample_redirected_destinations_tuples(),
    }


def get_minimal_config() -> Dict[str, Any]:
    """Minimal configuration with just destinations."""
    return {
        'destinations': get_sample_destinations(),
        'blocked_traps': set(),
        'blocked_dest': [],
        'blocked_ips': set(),
        'redirected_ips': {},
        'redirected_oids': {},
        'redirected_destinations': {},
    }


def get_empty_config() -> Dict[str, Any]:
    """Empty configuration."""
    return {
        'destinations': [],
        'blocked_traps': set(),
        'blocked_dest': [],
        'blocked_ips': set(),
        'redirected_ips': {},
        'redirected_oids': {},
        'redirected_destinations': {},
    }
