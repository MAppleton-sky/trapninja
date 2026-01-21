#!/usr/bin/env python3
"""
TrapNinja Test Suite - pytest Configuration

Registers pytest fixtures that wrap the fixtures module utilities.
Actual implementations live in the fixtures/ directory.

Author: TrapNinja Team
"""

import os
import sys
import tempfile
import threading
import queue
import pytest
from pathlib import Path
from unittest.mock import MagicMock

# =============================================================================
# PATH SETUP
# =============================================================================

TEST_DIR = Path(__file__).parent
PROJECT_ROOT = TEST_DIR.parent.parent
SRC_DIR = PROJECT_ROOT / "src"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

# Import from fixtures module
from fixtures import (
    # Packet builders (re-exported for direct use in tests)
    build_snmpv2c_trap,
    build_snmpv1_trap,
    build_snmpv3_packet,
    build_invalid_snmp_packet,
    build_non_snmp_packet,
    encode_oid,
    encode_oid_component,
    # Sample data classes
    SampleOIDs,
    SampleIPs,
    # Helper functions
    create_packet_data,
    create_config,
    # Generators
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


# =============================================================================
# CONFIGURATION FIXTURES
# =============================================================================

@pytest.fixture
def sample_destinations():
    """Standard destination list."""
    return get_sample_destinations()


@pytest.fixture
def sample_destinations_json():
    """Destination list in JSON format."""
    return get_sample_destinations_json()


@pytest.fixture
def multi_destinations():
    """Multiple destinations for fan-out tests."""
    return get_multi_destinations()


@pytest.fixture
def single_destination():
    """Single destination for basic tests."""
    return get_single_destination()


@pytest.fixture
def sample_blocked_ips():
    """List of blocked IPs."""
    return get_sample_blocked_ips()


@pytest.fixture
def sample_blocked_ips_set():
    """Set of blocked IPs."""
    return get_sample_blocked_ips_set()


@pytest.fixture
def sample_blocked_traps():
    """List of blocked OIDs."""
    return get_sample_blocked_traps()


@pytest.fixture
def sample_blocked_traps_set():
    """Set of blocked OIDs."""
    return get_sample_blocked_traps_set()


@pytest.fixture
def sample_redirected_ips():
    """IP redirection rules (JSON format)."""
    return get_sample_redirected_ips()


@pytest.fixture
def sample_redirected_ips_dict():
    """IP redirection rules as dict."""
    return get_sample_redirected_ips_dict()


@pytest.fixture
def sample_redirected_oids():
    """OID redirection rules (JSON format)."""
    return get_sample_redirected_oids()


@pytest.fixture
def sample_redirected_oids_dict():
    """OID redirection rules as dict."""
    return get_sample_redirected_oids_dict()


@pytest.fixture
def sample_redirected_destinations():
    """Destination groups (JSON format)."""
    return get_sample_redirected_destinations()


@pytest.fixture
def sample_redirected_destinations_tuples():
    """Destination groups with tuple format."""
    return get_sample_redirected_destinations_tuples()


@pytest.fixture
def destination_groups():
    """Alias for sample_redirected_destinations_tuples."""
    return get_sample_redirected_destinations_tuples()


@pytest.fixture
def mock_config():
    """Complete mock configuration for worker tests."""
    return get_mock_config()


@pytest.fixture
def minimal_config():
    """Minimal configuration with just destinations."""
    return get_minimal_config()


@pytest.fixture
def empty_config():
    """Empty configuration."""
    return get_empty_config()


# =============================================================================
# PACKET FIXTURES
# =============================================================================

@pytest.fixture
def sample_snmpv2c_payload():
    """Standard SNMPv2c trap payload."""
    return build_snmpv2c_trap()


@pytest.fixture
def sample_snmpv1_payload():
    """Standard SNMPv1 trap payload."""
    return build_snmpv1_trap()


@pytest.fixture
def sample_snmpv3_payload():
    """Standard SNMPv3 packet payload."""
    return build_snmpv3_packet()


@pytest.fixture
def sample_payload():
    """Alias for sample_snmpv2c_payload."""
    return build_snmpv2c_trap()


@pytest.fixture
def blocked_oid_payload():
    """SNMPv2c trap with blocked OID."""
    return build_snmpv2c_trap(trap_oid=SampleOIDs.BLOCKED_1)


@pytest.fixture
def redirect_voice_oid_payload():
    """SNMPv2c trap with voice-redirect OID."""
    return build_snmpv2c_trap(trap_oid=SampleOIDs.REDIRECT_VOICE)


@pytest.fixture
def redirect_security_oid_payload():
    """SNMPv2c trap with security-redirect OID."""
    return build_snmpv2c_trap(trap_oid=SampleOIDs.REDIRECT_SECURITY)


# =============================================================================
# PACKET DATA FIXTURES
# =============================================================================

@pytest.fixture
def normal_packet_data(sample_snmpv2c_payload):
    """Normal packet data dict for worker tests."""
    return create_packet_data(SampleIPs.NORMAL_1, sample_snmpv2c_payload)


@pytest.fixture
def blocked_ip_packet_data(sample_snmpv2c_payload):
    """Packet data from blocked IP."""
    return create_packet_data(SampleIPs.BLOCKED_1, sample_snmpv2c_payload)


@pytest.fixture
def blocked_oid_packet_data(blocked_oid_payload):
    """Packet data with blocked OID."""
    return create_packet_data(SampleIPs.NORMAL_1, blocked_oid_payload)


@pytest.fixture
def redirect_ip_packet_data(sample_snmpv2c_payload):
    """Packet data from redirected IP."""
    return create_packet_data(SampleIPs.REDIRECT_SECURITY_1, sample_snmpv2c_payload)


@pytest.fixture
def redirect_oid_packet_data(redirect_voice_oid_payload):
    """Packet data with redirected OID."""
    return create_packet_data(SampleIPs.NORMAL_1, redirect_voice_oid_payload)


# =============================================================================
# TEMPORARY DIRECTORIES
# =============================================================================

@pytest.fixture
def temp_config_dir():
    """Create a temporary config directory."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


@pytest.fixture
def temp_log_dir():
    """Create a temporary log directory."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


# =============================================================================
# WORKER FIXTURES
# =============================================================================

@pytest.fixture
def worker_queue():
    """Create a queue for worker tests."""
    return queue.Queue()


@pytest.fixture
def worker_stop_event():
    """Create a stop event for worker tests."""
    return threading.Event()


@pytest.fixture
def mock_socket():
    """Create a mock socket for forwarding tests."""
    sock = MagicMock()
    sock.sendto = MagicMock()
    return sock


@pytest.fixture
def mock_socket_pool(mock_socket):
    """Create a mock socket pool."""
    pool = MagicMock()
    pool.is_raw_available = True
    pool.acquire.return_value = mock_socket
    return pool
