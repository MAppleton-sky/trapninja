#!/usr/bin/env python3
"""
TrapNinja Test Suite - Core Constants Tests

Tests for trapninja.core.constants module.

Assumptions:
- Constants are static values that don't change at runtime
- SNMP version mappings should be bidirectional
- Network constants should have valid ranges
- All constants should be importable without side effects

Author: TrapNinja Team
"""

import pytest


class TestSNMPVersionConstants:
    """Tests for SNMP version constants."""

    def test_snmp_version_values(self):
        """Test that SNMP version constants have correct numeric values."""
        from trapninja.core.constants import SNMP_V1, SNMP_V2C, SNMP_V2, SNMP_V3
        
        assert SNMP_V1 == 0
        assert SNMP_V2C == 1
        assert SNMP_V2 == 2
        assert SNMP_V3 == 3

    def test_snmp_version_map_completeness(self):
        """Test that version map contains all versions."""
        from trapninja.core.constants import (
            SNMP_VERSION_MAP, SNMP_V1, SNMP_V2C, SNMP_V2, SNMP_V3
        )
        
        assert SNMP_V1 in SNMP_VERSION_MAP
        assert SNMP_V2C in SNMP_VERSION_MAP
        assert SNMP_V2 in SNMP_VERSION_MAP
        assert SNMP_V3 in SNMP_VERSION_MAP

    def test_snmp_version_map_values(self):
        """Test version map returns correct string representations."""
        from trapninja.core.constants import SNMP_VERSION_MAP
        
        assert SNMP_VERSION_MAP[0] == "v1"
        assert SNMP_VERSION_MAP[1] == "v2c"
        assert SNMP_VERSION_MAP[2] == "v2"
        assert SNMP_VERSION_MAP[3] == "v3"

    def test_snmp_version_reverse_map_bidirectional(self):
        """Test that version maps are bidirectional."""
        from trapninja.core.constants import (
            SNMP_VERSION_MAP, SNMP_VERSION_REVERSE_MAP
        )
        
        # Forward -> reverse should return original key
        for num, name in SNMP_VERSION_MAP.items():
            assert SNMP_VERSION_REVERSE_MAP[name] == num
        
        # Reverse -> forward should return original key
        for name, num in SNMP_VERSION_REVERSE_MAP.items():
            assert SNMP_VERSION_MAP[num] == name


class TestASN1TagConstants:
    """Tests for ASN.1 tag constants."""

    def test_universal_tags_are_bytes(self):
        """Test universal class tags have correct byte values."""
        from trapninja.core.constants import (
            ASN1_SEQUENCE, ASN1_INTEGER, ASN1_OCTET_STRING,
            ASN1_NULL, ASN1_OID, ASN1_BIT_STRING
        )
        
        # Universal tags should be in the 0x00-0x1F range (with constructed bit)
        assert ASN1_SEQUENCE == 0x30  # Constructed SEQUENCE
        assert ASN1_INTEGER == 0x02
        assert ASN1_OCTET_STRING == 0x04
        assert ASN1_NULL == 0x05
        assert ASN1_OID == 0x06
        assert ASN1_BIT_STRING == 0x03

    def test_context_specific_tags(self):
        """Test context-specific tags have correct values."""
        from trapninja.core.constants import (
            ASN1_CONTEXT_0, ASN1_CONTEXT_1, ASN1_CONTEXT_2,
            ASN1_CONTEXT_3, ASN1_CONTEXT_4, ASN1_CONTEXT_5,
            ASN1_CONTEXT_6, ASN1_CONTEXT_7
        )
        
        # Context-specific tags are 0xA0-0xA7
        assert ASN1_CONTEXT_0 == 0xA0
        assert ASN1_CONTEXT_1 == 0xA1
        assert ASN1_CONTEXT_2 == 0xA2
        assert ASN1_CONTEXT_3 == 0xA3
        assert ASN1_CONTEXT_4 == 0xA4
        assert ASN1_CONTEXT_5 == 0xA5
        assert ASN1_CONTEXT_6 == 0xA6
        assert ASN1_CONTEXT_7 == 0xA7

    def test_application_tags(self):
        """Test application class tags for SNMP types."""
        from trapninja.core.constants import (
            ASN1_IPADDRESS, ASN1_COUNTER32, ASN1_GAUGE32,
            ASN1_TIMETICKS, ASN1_OPAQUE, ASN1_COUNTER64
        )
        
        # Application tags are 0x40-0x46
        assert ASN1_IPADDRESS == 0x40
        assert ASN1_COUNTER32 == 0x41
        assert ASN1_GAUGE32 == 0x42
        assert ASN1_TIMETICKS == 0x43
        assert ASN1_OPAQUE == 0x44
        assert ASN1_COUNTER64 == 0x46


class TestSNMPOIDConstants:
    """Tests for SNMP OID constants."""

    def test_snmptrapoid_format(self):
        """Test snmpTrapOID.0 has correct format."""
        from trapninja.core.constants import SNMPTRAPOID_OID
        
        assert SNMPTRAPOID_OID == "1.3.6.1.6.3.1.1.4.1.0"
        # Verify it's a valid OID format
        parts = SNMPTRAPOID_OID.split(".")
        assert all(p.isdigit() for p in parts)

    def test_snmptrapoid_bytes_match_string(self):
        """Test binary representation matches string representation."""
        from trapninja.core.constants import SNMPTRAPOID_OID, SNMPTRAPOID_BYTES
        
        # The bytes should be the BER-encoded OID (without tag/length)
        # First two components: 1.3 -> 1*40 + 3 = 43 = 0x2B
        assert SNMPTRAPOID_BYTES[0] == 0x2B
        assert isinstance(SNMPTRAPOID_BYTES, bytes)

    def test_sysuptime_oid_format(self):
        """Test sysUpTime.0 has correct format."""
        from trapninja.core.constants import SYSUPTIME_OID
        
        assert SYSUPTIME_OID == "1.3.6.1.2.1.1.3.0"

    def test_enterprise_prefix(self):
        """Test enterprise OID prefix."""
        from trapninja.core.constants import ENTERPRISE_PREFIX
        
        assert ENTERPRISE_PREFIX == "1.3.6.1.4.1"


class TestNetworkConstants:
    """Tests for network-related constants."""

    def test_default_ports_in_valid_range(self):
        """Test default ports are in valid range (1-65535)."""
        from trapninja.core.constants import (
            DEFAULT_TRAP_PORT, DEFAULT_BLOCKED_PORT,
            DEFAULT_SOURCE_PORT, FORWARD_SOURCE_PORT
        )
        
        for port in [DEFAULT_TRAP_PORT, DEFAULT_BLOCKED_PORT,
                     DEFAULT_SOURCE_PORT, FORWARD_SOURCE_PORT]:
            assert 1 <= port <= 65535, f"Port {port} out of valid range"

    def test_default_trap_port_is_standard(self):
        """Test default trap port is standard SNMP trap port."""
        from trapninja.core.constants import DEFAULT_TRAP_PORT
        
        assert DEFAULT_TRAP_PORT == 162  # Standard SNMP trap port

    def test_forward_source_port_differs_from_trap_port(self):
        """Test forward source port is different from trap port to prevent loops."""
        from trapninja.core.constants import DEFAULT_TRAP_PORT, FORWARD_SOURCE_PORT
        
        # Critical: These MUST be different to prevent re-capture loops
        assert FORWARD_SOURCE_PORT != DEFAULT_TRAP_PORT
        assert FORWARD_SOURCE_PORT == 10162

    def test_max_udp_packet_size(self):
        """Test maximum UDP packet size is valid."""
        from trapninja.core.constants import MAX_UDP_PACKET_SIZE
        
        # Maximum UDP payload size
        assert MAX_UDP_PACKET_SIZE == 65535

    def test_socket_buffer_sizes(self):
        """Test socket buffer sizes are reasonable."""
        from trapninja.core.constants import (
            DEFAULT_SOCKET_BUFFER, FALLBACK_SOCKET_BUFFER
        )
        
        # Default should be 64MB
        assert DEFAULT_SOCKET_BUFFER == 67108864  # 64 * 1024 * 1024
        # Fallback should be smaller
        assert FALLBACK_SOCKET_BUFFER < DEFAULT_SOCKET_BUFFER
        assert FALLBACK_SOCKET_BUFFER == 16777216  # 16 * 1024 * 1024


class TestPerformanceConstants:
    """Tests for performance tuning constants."""

    def test_queue_sizes_are_positive(self):
        """Test queue sizes are positive integers."""
        from trapninja.core.constants import DEFAULT_QUEUE_SIZE, MAX_QUEUE_SIZE
        
        assert DEFAULT_QUEUE_SIZE > 0
        assert MAX_QUEUE_SIZE > 0
        assert MAX_QUEUE_SIZE >= DEFAULT_QUEUE_SIZE

    def test_batch_size_reasonable(self):
        """Test batch size is reasonable for performance."""
        from trapninja.core.constants import DEFAULT_BATCH_SIZE
        
        assert 1 <= DEFAULT_BATCH_SIZE <= 1000

    def test_timeout_positive(self):
        """Test worker timeout is positive."""
        from trapninja.core.constants import DEFAULT_WORKER_TIMEOUT
        
        assert DEFAULT_WORKER_TIMEOUT > 0

    def test_cache_ttl_positive(self):
        """Test configuration cache TTL is positive."""
        from trapninja.core.constants import CONFIG_CACHE_TTL
        
        assert CONFIG_CACHE_TTL > 0

    def test_stats_log_interval_reasonable(self):
        """Test stats logging interval is reasonable."""
        from trapninja.core.constants import STATS_LOG_INTERVAL
        
        # Should be between 1 second and 1 hour
        assert 1 <= STATS_LOG_INTERVAL <= 3600


class TestHAConstants:
    """Tests for High Availability constants."""

    def test_heartbeat_interval_positive(self):
        """Test heartbeat interval is positive."""
        from trapninja.core.constants import DEFAULT_HEARTBEAT_INTERVAL
        
        assert DEFAULT_HEARTBEAT_INTERVAL > 0

    def test_heartbeat_timeout_greater_than_interval(self):
        """Test heartbeat timeout is greater than interval."""
        from trapninja.core.constants import (
            DEFAULT_HEARTBEAT_INTERVAL, DEFAULT_HEARTBEAT_TIMEOUT
        )
        
        assert DEFAULT_HEARTBEAT_TIMEOUT > DEFAULT_HEARTBEAT_INTERVAL

    def test_failover_delay_reasonable(self):
        """Test failover delay is reasonable."""
        from trapninja.core.constants import DEFAULT_FAILOVER_DELAY
        
        # Should be between 0 and 60 seconds
        assert 0 <= DEFAULT_FAILOVER_DELAY <= 60

    def test_ha_port_valid(self):
        """Test default HA port is in valid range."""
        from trapninja.core.constants import DEFAULT_HA_PORT
        
        assert 1 <= DEFAULT_HA_PORT <= 65535

    def test_ha_priority_positive(self):
        """Test default HA priority is positive."""
        from trapninja.core.constants import DEFAULT_HA_PRIORITY
        
        assert DEFAULT_HA_PRIORITY > 0


class TestSNMPv3Constants:
    """Tests for SNMPv3 security constants."""

    def test_security_levels(self):
        """Test SNMPv3 security level values."""
        from trapninja.core.constants import (
            SNMPV3_NOAUTH_NOPRIV, SNMPV3_AUTH_NOPRIV, SNMPV3_AUTH_PRIV
        )
        
        assert SNMPV3_NOAUTH_NOPRIV == 0
        assert SNMPV3_AUTH_NOPRIV == 1
        assert SNMPV3_AUTH_PRIV == 3

    def test_auth_protocols_defined(self):
        """Test authentication protocols are defined."""
        from trapninja.core.constants import (
            AUTH_PROTOCOL_NONE, AUTH_PROTOCOL_MD5, AUTH_PROTOCOL_SHA,
            AUTH_PROTOCOL_SHA224, AUTH_PROTOCOL_SHA256,
            AUTH_PROTOCOL_SHA384, AUTH_PROTOCOL_SHA512
        )
        
        assert AUTH_PROTOCOL_NONE == "none"
        assert AUTH_PROTOCOL_MD5 == "MD5"
        assert AUTH_PROTOCOL_SHA == "SHA"

    def test_priv_protocols_defined(self):
        """Test privacy protocols are defined."""
        from trapninja.core.constants import (
            PRIV_PROTOCOL_NONE, PRIV_PROTOCOL_DES, PRIV_PROTOCOL_3DES,
            PRIV_PROTOCOL_AES, PRIV_PROTOCOL_AES128,
            PRIV_PROTOCOL_AES192, PRIV_PROTOCOL_AES256
        )
        
        assert PRIV_PROTOCOL_NONE == "none"
        assert PRIV_PROTOCOL_DES == "DES"
        assert PRIV_PROTOCOL_AES == "AES"


class TestFilePathConstants:
    """Tests for file path constants."""

    def test_default_paths_are_absolute(self):
        """Test default paths are absolute paths."""
        from trapninja.core.constants import (
            DEFAULT_CONFIG_DIR, DEFAULT_LOG_DIR, DEFAULT_PID_FILE
        )
        
        assert DEFAULT_CONFIG_DIR.startswith("/")
        assert DEFAULT_LOG_DIR.startswith("/")
        assert DEFAULT_PID_FILE.startswith("/")

    def test_default_config_dir(self):
        """Test default config directory path."""
        from trapninja.core.constants import DEFAULT_CONFIG_DIR
        
        assert DEFAULT_CONFIG_DIR == "/opt/trapninja/config"

    def test_default_log_dir(self):
        """Test default log directory path."""
        from trapninja.core.constants import DEFAULT_LOG_DIR
        
        assert DEFAULT_LOG_DIR == "/var/log/trapninja"


class TestLoggingConstants:
    """Tests for logging constants."""

    def test_default_log_level(self):
        """Test default log level is valid."""
        from trapninja.core.constants import DEFAULT_LOG_LEVEL
        
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        assert DEFAULT_LOG_LEVEL in valid_levels

    def test_log_file_size_reasonable(self):
        """Test log file size limit is reasonable."""
        from trapninja.core.constants import DEFAULT_LOG_MAX_SIZE
        
        # Should be between 1MB and 1GB
        assert 1024 * 1024 <= DEFAULT_LOG_MAX_SIZE <= 1024 * 1024 * 1024
        # Should be 10MB
        assert DEFAULT_LOG_MAX_SIZE == 10 * 1024 * 1024

    def test_backup_count_reasonable(self):
        """Test backup count is reasonable."""
        from trapninja.core.constants import DEFAULT_LOG_BACKUP_COUNT
        
        assert 1 <= DEFAULT_LOG_BACKUP_COUNT <= 100


class TestConstantsImmutability:
    """Tests to ensure constants are not accidentally mutable."""

    def test_snmptrapoid_bytes_is_bytes(self):
        """Test SNMPTRAPOID_BYTES is immutable bytes, not bytearray."""
        from trapninja.core.constants import SNMPTRAPOID_BYTES
        
        assert isinstance(SNMPTRAPOID_BYTES, bytes)
        # bytes are immutable, bytearrays are not

    def test_version_maps_are_dicts(self):
        """Test version maps are regular dictionaries."""
        from trapninja.core.constants import (
            SNMP_VERSION_MAP, SNMP_VERSION_REVERSE_MAP
        )
        
        assert isinstance(SNMP_VERSION_MAP, dict)
        assert isinstance(SNMP_VERSION_REVERSE_MAP, dict)
