#!/usr/bin/env python3
"""
TrapNinja Test Suite - Common Fixtures and Configuration

This conftest.py provides shared fixtures, configuration, and utilities
for all TrapNinja tests.

Author: TrapNinja Team
"""

import os
import sys
import json
import tempfile
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch
from collections import defaultdict

# Add src directory to path for imports
TEST_DIR = Path(__file__).parent
PROJECT_ROOT = TEST_DIR.parent.parent
SRC_DIR = PROJECT_ROOT / "src"

# Ensure src is in the path
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))


# =============================================================================
# COMMON TEST DATA
# =============================================================================

# Sample IP addresses for testing
SAMPLE_IPS = {
    "valid": ["192.168.1.1", "10.0.0.1", "172.16.0.1", "8.8.8.8"],
    "invalid": ["999.999.999.999", "abc.def.ghi.jkl", "", "192.168.1"],
    "localhost": ["127.0.0.1", "::1"],
}

# Sample OIDs for testing
SAMPLE_OIDS = {
    "valid": [
        "1.3.6.1.4.1.8072.2.3.0.1",
        "1.3.6.1.6.3.1.1.4.1.0",
        "1.3.6.1.2.1.1.3.0",
    ],
    "invalid": ["invalid.oid", "1.3.6.1.abc", "", "1"],
    "enterprise": ["1.3.6.1.4.1.9.9.1.1.1"],
}

# Sample SNMP payloads (hex encoded for clarity)
SAMPLE_PAYLOADS = {
    # SNMPv2c trap with basic structure
    "snmpv2c_basic": bytes.fromhex(
        "30819e020101040670756276696ca78190020401"
        "0204000201003082007f30820010060a2b060106"
        "03010104010006080800000000000000"
    ),
    # Minimal SNMP packet
    "minimal": bytes.fromhex("30050201010400"),
    # Empty/invalid
    "invalid": b"\x00\x01\x02\x03",
}


# =============================================================================
# FIXTURES - Configuration
# =============================================================================

@pytest.fixture
def temp_config_dir(tmp_path):
    """Create a temporary configuration directory with sample configs."""
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    
    # Create sample configuration files
    destinations = [["192.168.1.100", 162], ["192.168.1.101", 162]]
    (config_dir / "destinations.json").write_text(json.dumps(destinations))
    
    blocked_traps = ["1.3.6.1.4.1.9999.1", "1.3.6.1.4.1.9999.2"]
    (config_dir / "blocked_traps.json").write_text(json.dumps(blocked_traps))
    
    listen_ports = [162, 1162]
    (config_dir / "listen_ports.json").write_text(json.dumps(listen_ports))
    
    blocked_ips = ["10.0.0.99", "10.0.0.100"]
    (config_dir / "blocked_ips.json").write_text(json.dumps(blocked_ips))
    
    redirected_ips = [["192.168.10.50", "security"]]
    (config_dir / "redirected_ips.json").write_text(json.dumps(redirected_ips))
    
    redirected_oids = [["1.3.6.1.4.1.8072.2.3.0.1", "security"]]
    (config_dir / "redirected_oids.json").write_text(json.dumps(redirected_oids))
    
    redirected_destinations = {
        "security": [["127.0.0.1", 1362]],
        "config": [["127.0.0.1", 1462]],
    }
    (config_dir / "redirected_destinations.json").write_text(
        json.dumps(redirected_destinations)
    )
    
    main_config = {
        "interface": "eth0",
        "capture_mode": "auto",
        "config_check_interval": 60,
    }
    (config_dir / "trapninja.json").write_text(json.dumps(main_config))
    
    return config_dir


@pytest.fixture
def mock_config_dir(temp_config_dir, monkeypatch):
    """Patch the config module to use temporary directory."""
    monkeypatch.setenv("TRAPNINJA_CONFIG", str(temp_config_dir))
    return temp_config_dir


# =============================================================================
# FIXTURES - Mocking
# =============================================================================

@pytest.fixture
def mock_logger():
    """Create a mock logger for testing."""
    logger = MagicMock()
    logger.debug = MagicMock()
    logger.info = MagicMock()
    logger.warning = MagicMock()
    logger.error = MagicMock()
    logger.critical = MagicMock()
    return logger


@pytest.fixture
def mock_socket():
    """Create a mock socket for network testing."""
    sock = MagicMock()
    sock.sendto = MagicMock(return_value=100)
    sock.recvfrom = MagicMock(return_value=(b"test_data", ("127.0.0.1", 162)))
    sock.bind = MagicMock()
    sock.close = MagicMock()
    sock.setsockopt = MagicMock()
    return sock


@pytest.fixture
def mock_redis():
    """Create a mock Redis client."""
    redis_mock = MagicMock()
    redis_mock.ping = MagicMock(return_value=True)
    redis_mock.set = MagicMock(return_value=True)
    redis_mock.get = MagicMock(return_value=None)
    redis_mock.delete = MagicMock(return_value=1)
    redis_mock.keys = MagicMock(return_value=[])
    redis_mock.pipeline = MagicMock(return_value=MagicMock())
    return redis_mock


# =============================================================================
# FIXTURES - Time Control
# =============================================================================

@pytest.fixture
def frozen_time():
    """
    Fixture to freeze time at a specific point.
    Returns a context manager that patches time.time().
    """
    class FrozenTime:
        def __init__(self):
            self._time = 1704067200.0  # 2024-01-01 00:00:00 UTC
        
        @property
        def value(self):
            return self._time
        
        def advance(self, seconds):
            self._time += seconds
        
        def __call__(self):
            return self._time
    
    return FrozenTime()


@pytest.fixture
def mock_time(frozen_time, monkeypatch):
    """Patch time.time() to use frozen time."""
    monkeypatch.setattr("time.time", frozen_time)
    return frozen_time


# =============================================================================
# FIXTURES - Packet Data
# =============================================================================

@pytest.fixture
def sample_packet_data():
    """Create sample packet data for testing."""
    return {
        "src_ip": "192.168.1.50",
        "dst_port": 162,
        "payload": SAMPLE_PAYLOADS["snmpv2c_basic"],
        "timestamp": 1704067200.0,
    }


@pytest.fixture
def sample_trap_oid():
    """Return a sample trap OID."""
    return "1.3.6.1.4.1.8072.2.3.0.1"


# =============================================================================
# FIXTURES - Statistics
# =============================================================================

@pytest.fixture
def clean_stats():
    """Reset all statistics before and after each test."""
    # Setup: nothing to do, stats should start clean
    yield
    # Teardown: reset any global stats (if they exist)
    try:
        from trapninja.metrics import reset_metrics
        reset_metrics()
    except ImportError:
        pass


# =============================================================================
# UTILITIES
# =============================================================================

def assert_no_logging_errors(caplog):
    """Assert that no ERROR or CRITICAL messages were logged."""
    for record in caplog.records:
        assert record.levelno < 40, f"Unexpected error logged: {record.message}"


def create_test_snmp_packet(version=1, community="public", trap_oid=None):
    """
    Create a test SNMP packet for testing.
    
    Args:
        version: SNMP version (0=v1, 1=v2c, 3=v3)
        community: Community string
        trap_oid: Optional trap OID
    
    Returns:
        bytes: Encoded SNMP packet
    """
    # This is a simplified packet builder for testing
    # In reality, you'd use Scapy or a proper ASN.1 encoder
    if version == 1:  # SNMPv2c
        # Basic SNMPv2c trap structure
        return bytes([
            0x30, 0x20,  # SEQUENCE
            0x02, 0x01, 0x01,  # INTEGER version=1 (SNMPv2c)
            0x04, len(community), *community.encode(),  # OCTET STRING community
            0xa7, 0x10,  # Trap PDU
            # Simplified content
            0x02, 0x01, 0x00,  # request-id
            0x02, 0x01, 0x00,  # error-status
            0x02, 0x01, 0x00,  # error-index
            0x30, 0x00,  # varbindlist
        ])
    return b""


# =============================================================================
# MARKERS
# =============================================================================

def pytest_configure(config):
    """Configure custom pytest markers."""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )
    config.addinivalue_line(
        "markers", "integration: marks tests as integration tests"
    )
    config.addinivalue_line(
        "markers", "requires_root: marks tests that require root privileges"
    )
    config.addinivalue_line(
        "markers", "requires_redis: marks tests that require Redis"
    )
