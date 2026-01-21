#!/usr/bin/env python3
"""
TrapNinja Test Fixtures Package

Provides shared test utilities, sample data, and helper functions.

Usage:
    from fixtures import build_snmpv2c_trap, SampleOIDs, SampleIPs
    from fixtures.configs import create_config, get_mock_config

Author: TrapNinja Team
"""

# Packet builders
from .packets import (
    encode_oid_component,
    encode_oid,
    build_snmpv2c_trap,
    build_snmpv1_trap,
    build_snmpv3_packet,
    build_invalid_snmp_packet,
    build_non_snmp_packet,
)

# Sample data classes
from .sample_data import (
    SampleOIDs,
    SampleIPs,
)

# Configuration helpers and generators
from .configs import (
    create_packet_data,
    create_config,
    get_sample_destinations,
    get_sample_destinations_json,
    get_multi_destinations,
    get_single_destination,
    get_sample_blocked_ips,
    get_sample_blocked_ips_set,
    get_sample_blocked_traps,
    get_sample_blocked_traps_set,
    get_sample_redirected_ips,
    get_sample_redirected_ips_dict,
    get_sample_redirected_oids,
    get_sample_redirected_oids_dict,
    get_sample_redirected_destinations,
    get_sample_redirected_destinations_tuples,
    get_mock_config,
    get_minimal_config,
    get_empty_config,
)

__all__ = [
    # Encoding helpers
    'encode_oid_component',
    'encode_oid',
    # Packet builders
    'build_snmpv2c_trap',
    'build_snmpv1_trap',
    'build_snmpv3_packet',
    'build_invalid_snmp_packet',
    'build_non_snmp_packet',
    # Sample data classes
    'SampleOIDs',
    'SampleIPs',
    # Configuration helpers
    'create_packet_data',
    'create_config',
    # Sample data generators
    'get_sample_destinations',
    'get_sample_destinations_json',
    'get_multi_destinations',
    'get_single_destination',
    'get_sample_blocked_ips',
    'get_sample_blocked_ips_set',
    'get_sample_blocked_traps',
    'get_sample_blocked_traps_set',
    'get_sample_redirected_ips',
    'get_sample_redirected_ips_dict',
    'get_sample_redirected_oids',
    'get_sample_redirected_oids_dict',
    'get_sample_redirected_destinations',
    'get_sample_redirected_destinations_tuples',
    # Complete configurations
    'get_mock_config',
    'get_minimal_config',
    'get_empty_config',
]
