#!/usr/bin/env python3
"""
TrapNinja Core Module

Provides shared constants, types, and exceptions used across all TrapNinja modules.
This module ensures consistency and reduces code duplication throughout the codebase.

Author: TrapNinja Team
Version: 1.0.0
"""

from .constants import (
    SNMP_VERSION_MAP,
    SNMP_V1, SNMP_V2C, SNMP_V3,
    DEFAULT_TRAP_PORT,
    DEFAULT_QUEUE_SIZE,
    ASN1_SEQUENCE, ASN1_INTEGER, ASN1_OCTET_STRING, ASN1_OID,
    SNMPTRAPOID_BYTES,
)

from .types import (
    PacketData,
    Destination,
    DestinationList,
    RedirectionRule,
    ForwardingResult,
)

from .exceptions import (
    TrapNinjaError,
    ConfigurationError,
    ParsingError,
    ForwardingError,
    HAError,
    SecurityError,
)

# Import fragmentation support with fallback
try:
    from .fragmentation import (
        FragmentReassemblyBuffer,
        IPFragment,
        parse_ip_header,
        is_fragment,
        is_udp_fragment,
        generate_fragment_aware_filter,
        generate_simple_filter,
        get_fragment_buffer,
        initialize_fragment_buffer,
        shutdown_fragment_buffer,
        get_fragment_stats,
    )
    FRAGMENTATION_AVAILABLE = True
except ImportError:
    FRAGMENTATION_AVAILABLE = False

__all__ = [
    # Constants
    'SNMP_VERSION_MAP',
    'SNMP_V1', 'SNMP_V2C', 'SNMP_V3',
    'DEFAULT_TRAP_PORT',
    'DEFAULT_QUEUE_SIZE',
    'ASN1_SEQUENCE', 'ASN1_INTEGER', 'ASN1_OCTET_STRING', 'ASN1_OID',
    'SNMPTRAPOID_BYTES',
    # Types
    'PacketData',
    'Destination',
    'DestinationList',
    'RedirectionRule',
    'ForwardingResult',
    # Exceptions
    'TrapNinjaError',
    'ConfigurationError',
    'ParsingError',
    'ForwardingError',
    'HAError',
    'SecurityError',
    # Fragmentation
    'FRAGMENTATION_AVAILABLE',
    'FragmentReassemblyBuffer',
    'IPFragment',
    'parse_ip_header',
    'is_fragment',
    'is_udp_fragment',
    'generate_fragment_aware_filter',
    'generate_simple_filter',
    'get_fragment_buffer',
    'initialize_fragment_buffer',
    'shutdown_fragment_buffer',
    'get_fragment_stats',
]
