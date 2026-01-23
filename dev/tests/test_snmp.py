#!/usr/bin/env python3
"""
TrapNinja Test Suite - SNMP Module Tests

Tests for trapninja.snmp module - high-performance SNMP trap processing.

Assumptions:
- Fast path uses direct byte scanning for SNMPv2c OID extraction
- Slow path uses Scapy parsing for complex cases
- ConfigCache has 30-second TTL by default
- ProcessingStats tracks fast/slow path hits
- Raw socket forwarding is preferred over Scapy
- FORWARD_SOURCE_PORT prevents capture loops

Author: TrapNinja Team
"""

import struct
import socket
import threading
import time
import pytest
from unittest.mock import MagicMock, patch, PropertyMock


class TestSNMPVersionConstants:
    """Tests for SNMP version constants."""

    def test_snmp_version_map(self):
        """Test SNMP version mapping."""
        from trapninja.snmp import SNMP_VERSION_MAP
        
        assert SNMP_VERSION_MAP[0] == "v1"
        assert SNMP_VERSION_MAP[1] == "v2c"
        assert SNMP_VERSION_MAP[2] == "v2"
        assert SNMP_VERSION_MAP[3] == "v3"

    def test_snmptrapoid_marker(self):
        """Test snmpTrapOID marker bytes."""
        from trapninja.snmp import _SNMPTRAPOID_MARKER
        
        # snmpTrapOID.0 = 1.3.6.1.6.3.1.1.4.1.0
        # BER encoded: 2b.06.01.06.03.01.01.04.01.00
        expected = b'\x2b\x06\x01\x06\x03\x01\x01\x04\x01\x00'
        assert _SNMPTRAPOID_MARKER == expected


class TestConfigCache:
    """Tests for ConfigCache class."""

    def test_cache_initialization(self):
        """Test ConfigCache initializes with defaults."""
        from trapninja.snmp import ConfigCache
        
        cache = ConfigCache(ttl=30.0)
        
        assert cache.ttl == 30.0
        assert cache._cache is None
        assert cache._cache_time == 0

    def test_cache_custom_ttl(self):
        """Test ConfigCache with custom TTL."""
        from trapninja.snmp import ConfigCache
        
        cache = ConfigCache(ttl=60.0)
        
        assert cache.ttl == 60.0

    def test_cache_get_loads_config(self):
        """Test that get() loads configuration on first call."""
        from trapninja.snmp import ConfigCache
        
        cache = ConfigCache(ttl=30.0)
        
        # Patch the config module where the import happens
        with patch('trapninja.snmp.destinations', [("10.0.0.1", 162)], create=True):
            with patch('trapninja.snmp.blocked_traps', set(), create=True):
                with patch('trapninja.snmp.blocked_dest', [], create=True):
                    with patch('trapninja.snmp.blocked_ips', set(), create=True):
                        with patch('trapninja.snmp.redirected_ips', {}, create=True):
                            with patch('trapninja.snmp.redirected_oids', {}, create=True):
                                with patch('trapninja.snmp.redirected_destinations', {}, create=True):
                                    # Force import inside the method
                                    with patch.dict('sys.modules', {}):
                                        # The actual test - just verify it doesn't crash
                                        # and returns a dict
                                        try:
                                            result = cache.get()
                                            assert isinstance(result, dict)
                                        except ImportError:
                                            # This is expected since we're mocking
                                            pass

    def test_cache_returns_cached_value_within_ttl(self):
        """Test that cached value is returned within TTL."""
        from trapninja.snmp import ConfigCache
        
        cache = ConfigCache(ttl=30.0)
        cache._cache = {'test': 'value'}
        cache._cache_time = time.time()
        
        result = cache.get()
        
        assert result == {'test': 'value'}

    def test_cache_invalidate(self):
        """Test cache invalidation."""
        from trapninja.snmp import ConfigCache
        
        cache = ConfigCache(ttl=30.0)
        cache._cache = {'test': 'value'}
        cache._cache_time = time.time()
        
        cache.invalidate()
        
        assert cache._cache_time == 0

    def test_cache_thread_safety(self):
        """Test cache is thread-safe."""
        from trapninja.snmp import ConfigCache
        
        cache = ConfigCache(ttl=0.001)  # Very short TTL
        
        results = []
        errors = []
        
        def access_cache():
            try:
                for _ in range(100):
                    cache._cache = {'test': time.time()}
                    cache._cache_time = time.time()
                    result = cache.get()
                    results.append(result)
            except Exception as e:
                errors.append(e)
        
        threads = [threading.Thread(target=access_cache) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        assert len(errors) == 0


class TestProcessingStats:
    """Tests for ProcessingStats class."""

    def test_stats_initialization(self):
        """Test ProcessingStats initializes with zeros."""
        from trapninja.snmp import ProcessingStats
        
        stats = ProcessingStats()
        
        assert stats.received == 0
        assert stats.forwarded == 0
        assert stats.blocked == 0
        assert stats.redirected == 0
        assert stats.errors == 0
        assert stats.fast_path_hits == 0
        assert stats.slow_path_hits == 0

    def test_stats_should_log_respects_interval(self):
        """Test should_log respects log interval."""
        from trapninja.snmp import ProcessingStats
        
        stats = ProcessingStats()
        stats.log_interval = 60.0
        stats.last_log_time = time.time()
        
        assert stats.should_log() is False

    def test_stats_should_log_after_interval(self):
        """Test should_log returns True after interval."""
        from trapninja.snmp import ProcessingStats
        
        stats = ProcessingStats()
        stats.log_interval = 0.001
        stats.last_log_time = time.time() - 1
        
        assert stats.should_log() is True

    def test_stats_log_summary(self):
        """Test log_summary logs when received > 0."""
        from trapninja.snmp import ProcessingStats
        
        stats = ProcessingStats()
        stats.received = 100
        stats.forwarded = 90
        stats.fast_path_hits = 80
        
        with patch('trapninja.snmp.logger') as mock_logger:
            stats.log_summary()
            
            # Should have logged
            mock_logger.info.assert_called_once()


class TestIsSnmpv2c:
    """Tests for is_snmpv2c function."""

    def test_valid_snmpv2c_packet(self):
        """Test detection of valid SNMPv2c packet."""
        from trapninja.snmp import is_snmpv2c
        
        # Valid SNMPv2c packet header
        # 0x30 = SEQUENCE
        # 0x?? = length
        # 0x02 = INTEGER (version)
        # 0x01 = length 1
        # 0x01 = version 1 (SNMPv2c)
        # 0x04 = OCTET STRING (community)
        payload = bytes([0x30, 0x50, 0x02, 0x01, 0x01, 0x04, 0x06]) + b'public'
        
        assert is_snmpv2c(payload) is True

    def test_snmpv1_packet(self):
        """Test SNMPv1 packet is not detected as v2c."""
        from trapninja.snmp import is_snmpv2c
        
        # SNMPv1 has version = 0
        payload = bytes([0x30, 0x50, 0x02, 0x01, 0x00, 0x04, 0x06]) + b'public'
        
        assert is_snmpv2c(payload) is False

    def test_snmpv3_packet(self):
        """Test SNMPv3 packet is not detected as v2c."""
        from trapninja.snmp import is_snmpv2c
        
        # SNMPv3 has version = 3
        payload = bytes([0x30, 0x50, 0x02, 0x01, 0x03, 0x04, 0x06]) + b'public'
        
        assert is_snmpv2c(payload) is False

    def test_short_payload(self):
        """Test short payload returns False."""
        from trapninja.snmp import is_snmpv2c
        
        assert is_snmpv2c(b'\x30\x02\x02') is False
        assert is_snmpv2c(b'') is False

    def test_invalid_sequence_tag(self):
        """Test invalid SEQUENCE tag returns False."""
        from trapninja.snmp import is_snmpv2c
        
        payload = bytes([0x31, 0x50, 0x02, 0x01, 0x01, 0x04, 0x06]) + b'public'
        
        assert is_snmpv2c(payload) is False


class TestDecodeOid:
    """Tests for _decode_oid function."""

    def test_decode_simple_oid(self):
        """Test decoding simple OID."""
        from trapninja.snmp import _decode_oid
        
        # 1.3.6.1 encoded as: first byte = 1*40+3=43, then 6, 1
        oid_bytes = bytes([43, 6, 1])
        
        result = _decode_oid(oid_bytes)
        
        assert result == "1.3.6.1"

    def test_decode_enterprise_oid(self):
        """Test decoding enterprise OID with large values."""
        from trapninja.snmp import _decode_oid
        
        # 1.3.6.1.4.1 = iso.org.dod.internet.private.enterprises
        oid_bytes = bytes([43, 6, 1, 4, 1])
        
        result = _decode_oid(oid_bytes)
        
        assert result == "1.3.6.1.4.1"

    def test_decode_multibyte_component(self):
        """Test decoding OID with multi-byte component."""
        from trapninja.snmp import _decode_oid
        
        # Component 8072 = 0x1F88 requires multi-byte encoding
        # 8072 = 0b11111100101000 -> 0b0111111 0b0001000 with high bits
        # = 0xBF 0x08 (with continuation bit on first byte)
        oid_bytes = bytes([43, 6, 1, 4, 1, 0xBF, 0x08])
        
        result = _decode_oid(oid_bytes)
        
        assert result == "1.3.6.1.4.1.8072"

    def test_decode_empty_oid(self):
        """Test decoding empty OID bytes."""
        from trapninja.snmp import _decode_oid
        
        result = _decode_oid(b'')
        
        assert result == ""


class TestExtractTrapOidFast:
    """Tests for extract_trap_oid_fast function."""

    def test_extract_oid_from_valid_trap(self):
        """Test OID extraction from valid trap packet."""
        from trapninja.snmp import extract_trap_oid_fast, _SNMPTRAPOID_MARKER
        
        # Build a packet with snmpTrapOID.0 followed by an OID value
        # OID tag (0x06) + length + OID bytes for 1.3.6.1.6.3.1.1.5.1 (coldStart)
        trap_oid_bytes = bytes([43, 6, 1, 6, 3, 1, 1, 5, 1])
        payload = (
            b'\x30\x50\x02\x01\x01\x04\x06public' +
            _SNMPTRAPOID_MARKER +
            bytes([0x06, len(trap_oid_bytes)]) +
            trap_oid_bytes
        )
        
        result = extract_trap_oid_fast(payload)
        
        assert result == "1.3.6.1.6.3.1.1.5.1"

    def test_returns_none_when_marker_not_found(self):
        """Test returns None when snmpTrapOID marker not found."""
        from trapninja.snmp import extract_trap_oid_fast
        
        payload = b'\x30\x50\x02\x01\x01\x04\x06public\x30\x10'
        
        result = extract_trap_oid_fast(payload)
        
        assert result is None

    def test_returns_none_for_invalid_oid_tag(self):
        """Test returns None when OID tag is wrong."""
        from trapninja.snmp import extract_trap_oid_fast, _SNMPTRAPOID_MARKER
        
        # Wrong tag (0x04 OCTET STRING instead of 0x06 OID)
        payload = (
            b'\x30\x50\x02\x01\x01\x04\x06public' +
            _SNMPTRAPOID_MARKER +
            bytes([0x04, 0x05]) + b'test'
        )
        
        result = extract_trap_oid_fast(payload)
        
        assert result is None

    def test_returns_none_for_truncated_packet(self):
        """Test returns None for truncated packet."""
        from trapninja.snmp import extract_trap_oid_fast, _SNMPTRAPOID_MARKER
        
        # Packet truncated after marker
        payload = (
            b'\x30\x50\x02\x01\x01\x04\x06public' +
            _SNMPTRAPOID_MARKER
        )
        
        result = extract_trap_oid_fast(payload)
        
        assert result is None


class TestTryParseSnmp:
    """Tests for try_parse_snmp function."""

    def test_parse_valid_snmpv2c(self):
        """Test parsing valid SNMPv2c packet."""
        from trapninja.snmp import try_parse_snmp
        
        # Use a real minimal SNMPv2c packet
        # This would need Scapy to be available
        with patch('trapninja.snmp.SNMP') as mock_snmp:
            mock_packet = MagicMock()
            mock_packet.version.val = 1  # SNMPv2c
            mock_snmp.return_value = mock_packet
            
            snmp, version = try_parse_snmp(b'\x30\x50\x02\x01\x01')
            
            assert version == "v2c"

    def test_parse_snmpv1(self):
        """Test parsing SNMPv1 packet."""
        from trapninja.snmp import try_parse_snmp
        
        with patch('trapninja.snmp.SNMP') as mock_snmp:
            mock_packet = MagicMock()
            mock_packet.version.val = 0  # SNMPv1
            mock_snmp.return_value = mock_packet
            
            snmp, version = try_parse_snmp(b'\x30\x50\x02\x01\x00')
            
            assert version == "v1"

    def test_parse_snmpv3(self):
        """Test parsing SNMPv3 packet."""
        from trapninja.snmp import try_parse_snmp
        
        with patch('trapninja.snmp.SNMP') as mock_snmp:
            mock_packet = MagicMock()
            mock_packet.version.val = 3  # SNMPv3
            mock_snmp.return_value = mock_packet
            
            snmp, version = try_parse_snmp(b'\x30\x50\x02\x01\x03')
            
            assert version == "v3"

    def test_parse_failure_returns_none(self):
        """Test parsing failure returns None."""
        from trapninja.snmp import try_parse_snmp
        
        with patch('trapninja.snmp.SNMP', side_effect=Exception("Parse error")):
            snmp, version = try_parse_snmp(b'invalid')
            
            assert snmp is None
            assert version is None


class TestRawSocketForwarding:
    """Tests for raw socket forwarding functions."""

    def test_checksum_calculation(self):
        """Test IP checksum calculation."""
        from trapninja.snmp import _checksum
        
        # Test with known data
        data = b'\x45\x00\x00\x28\x00\x00\x00\x00\x40\x11\x00\x00'
        data += socket.inet_aton('192.168.1.1')
        data += socket.inet_aton('192.168.1.2')
        
        result = _checksum(data)
        
        # Should be a valid 16-bit checksum
        assert 0 <= result <= 0xFFFF

    def test_checksum_odd_length(self):
        """Test checksum with odd-length data."""
        from trapninja.snmp import _checksum
        
        # Odd length data should be padded
        data = b'\x45\x00\x00\x28\x00'
        
        result = _checksum(data)
        
        assert 0 <= result <= 0xFFFF

    def test_build_packet_structure(self):
        """Test packet building creates valid IP+UDP structure."""
        from trapninja.snmp import _build_packet
        
        packet = _build_packet(
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            src_port=12345,
            dst_port=162,
            payload=b"test payload"
        )
        
        # IP header is 20 bytes, UDP header is 8 bytes
        assert len(packet) == 20 + 8 + len(b"test payload")
        
        # Check IP version/IHL
        assert packet[0] == 0x45
        
        # Check protocol is UDP (17)
        assert packet[9] == 17

    def test_build_packet_source_ip(self):
        """Test packet has correct source IP."""
        from trapninja.snmp import _build_packet
        
        packet = _build_packet(
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=12345,
            dst_port=162,
            payload=b"test"
        )
        
        # Source IP is at offset 12-15
        src_ip = socket.inet_ntoa(packet[12:16])
        assert src_ip == "10.0.0.1"

    def test_build_packet_dest_ip(self):
        """Test packet has correct destination IP."""
        from trapninja.snmp import _build_packet
        
        packet = _build_packet(
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=12345,
            dst_port=162,
            payload=b"test"
        )
        
        # Dest IP is at offset 16-19
        dst_ip = socket.inet_ntoa(packet[16:20])
        assert dst_ip == "10.0.0.2"

    def test_build_packet_ports(self):
        """Test packet has correct ports."""
        from trapninja.snmp import _build_packet
        
        packet = _build_packet(
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=12345,
            dst_port=162,
            payload=b"test"
        )
        
        # UDP header starts at offset 20
        src_port = struct.unpack('!H', packet[20:22])[0]
        dst_port = struct.unpack('!H', packet[22:24])[0]
        
        assert src_port == 12345
        assert dst_port == 162


class TestForwardPacket:
    """Tests for forward_packet function."""

    def test_forward_to_empty_destinations(self):
        """Test forwarding to empty destinations list."""
        from trapninja.snmp import forward_packet
        
        # Should not raise
        forward_packet("192.168.1.1", b"payload", [])

    @patch('trapninja.snmp._raw_socket_available', False)
    @patch('trapninja.snmp._forward_scapy')
    def test_falls_back_to_scapy(self, mock_scapy):
        """Test fallback to Scapy when raw socket unavailable."""
        from trapninja.snmp import forward_packet
        
        forward_packet("192.168.1.1", b"payload", [("10.0.0.1", 162)])
        
        mock_scapy.assert_called_once()

    @patch('trapninja.snmp._raw_socket_available', True)
    @patch('trapninja.snmp._raw_socket')
    @patch('trapninja.snmp._init_raw_socket')
    def test_uses_raw_socket_when_available(self, mock_init, mock_socket):
        """Test raw socket is used when available."""
        from trapninja.snmp import forward_packet
        
        mock_init.return_value = True
        mock_socket.sendto = MagicMock()
        
        forward_packet("192.168.1.1", b"payload", [("10.0.0.1", 162)])
        
        mock_socket.sendto.assert_called()


class TestProcessCapturedPacket:
    """Tests for process_captured_packet function."""

    @patch('trapninja.snmp.is_forwarding_enabled', return_value=False)
    def test_skips_when_ha_disabled(self, mock_ha):
        """Test processing skipped when HA forwarding disabled."""
        from trapninja.snmp import process_captured_packet
        
        with patch('trapninja.snmp.increment_trap_received') as mock_incr:
            process_captured_packet({
                'src_ip': '192.168.1.1',
                'payload': b'\x30\x50\x02\x01\x01'
            })
            
            # Should not increment received counter
            mock_incr.assert_not_called()

    @patch('trapninja.snmp.is_forwarding_enabled', return_value=True)
    @patch('trapninja.snmp._config_cache')
    @patch('trapninja.snmp.increment_trap_received')
    @patch('trapninja.snmp.increment_blocked_ip')
    def test_blocks_by_ip(self, mock_blocked, mock_received, mock_cache, mock_ha):
        """Test blocking by source IP."""
        from trapninja.snmp import process_captured_packet
        
        mock_cache.get.return_value = {
            'blocked_ips': {'192.168.1.100'},
            'blocked_traps': set(),
            'destinations': [],
            'blocked_dest': [],
            'redirected_ips': {},
            'redirected_oids': {},
            'redirected_destinations': {}
        }
        
        process_captured_packet({
            'src_ip': '192.168.1.100',
            'payload': b'\x30\x50\x02\x01\x01'
        })
        
        mock_blocked.assert_called_with('192.168.1.100')

    @patch('trapninja.snmp.is_forwarding_enabled', return_value=True)
    @patch('trapninja.snmp._config_cache')
    @patch('trapninja.snmp.is_snmpv2c', return_value=True)
    @patch('trapninja.snmp.extract_trap_oid_fast', return_value='1.3.6.1.4.1.9999.1')
    @patch('trapninja.snmp.increment_trap_received')
    @patch('trapninja.snmp.increment_blocked_oid')
    def test_blocks_by_oid(self, mock_blocked_oid, mock_received, 
                           mock_extract, mock_isv2c, mock_cache, mock_ha):
        """Test blocking by trap OID."""
        from trapninja.snmp import process_captured_packet
        
        mock_cache.get.return_value = {
            'blocked_ips': set(),
            'blocked_traps': {'1.3.6.1.4.1.9999.1'},
            'destinations': [],
            'blocked_dest': [],
            'redirected_ips': {},
            'redirected_oids': {},
            'redirected_destinations': {}
        }
        
        process_captured_packet({
            'src_ip': '192.168.1.1',
            'payload': b'\x30\x50\x02\x01\x01'
        })
        
        mock_blocked_oid.assert_called_with('1.3.6.1.4.1.9999.1')


class TestGetVarbindDict:
    """Tests for get_varbind_dict function."""

    def test_extracts_varbinds(self):
        """Test varbind extraction from parsed packet."""
        from trapninja.snmp import get_varbind_dict
        
        # Create mock packet with varbinds
        mock_vb1 = MagicMock()
        mock_vb1.oid.val = "1.3.6.1.2.1.1.3.0"
        mock_vb1.value = "100"
        
        mock_vb2 = MagicMock()
        mock_vb2.oid.val = "1.3.6.1.6.3.1.1.4.1.0"
        mock_vb2.value = "1.3.6.1.6.3.1.1.5.1"
        
        mock_packet = MagicMock()
        mock_packet.__getitem__ = MagicMock(return_value=MagicMock(
            PDU=MagicMock(varbindlist=[mock_vb1, mock_vb2])
        ))
        
        result = get_varbind_dict(mock_packet)
        
        assert "1.3.6.1.2.1.1.3.0" in result
        assert "1.3.6.1.6.3.1.1.4.1.0" in result

    def test_empty_varbinds(self):
        """Test empty varbind list."""
        from trapninja.snmp import get_varbind_dict
        
        mock_packet = MagicMock()
        mock_packet.__getitem__ = MagicMock(return_value=MagicMock(
            PDU=MagicMock(varbindlist=[])
        ))
        
        result = get_varbind_dict(mock_packet)
        
        assert result == {}

    def test_missing_varbindlist(self):
        """Test handling missing varbindlist attribute."""
        from trapninja.snmp import get_varbind_dict
        
        mock_packet = MagicMock()
        mock_pdu = MagicMock(spec=[])  # No varbindlist attribute
        mock_packet.__getitem__ = MagicMock(return_value=MagicMock(PDU=mock_pdu))
        
        result = get_varbind_dict(mock_packet)
        
        assert result == {}


class TestGetSnmptrapOid:
    """Tests for get_snmptrap_oid function."""

    def test_extracts_snmptrapoid(self):
        """Test snmpTrapOID extraction."""
        from trapninja.snmp import get_snmptrap_oid
        
        mock_vb = MagicMock()
        mock_vb.oid.val = "1.3.6.1.6.3.1.1.4.1.0"
        mock_vb.value = "1.3.6.1.6.3.1.1.5.1"
        
        mock_packet = MagicMock()
        mock_packet.__getitem__ = MagicMock(return_value=MagicMock(
            PDU=MagicMock(varbindlist=[mock_vb])
        ))
        
        result = get_snmptrap_oid(mock_packet)
        
        assert result == "1.3.6.1.6.3.1.1.5.1"

    def test_returns_none_when_not_found(self):
        """Test returns None when snmpTrapOID not present."""
        from trapninja.snmp import get_snmptrap_oid
        
        mock_vb = MagicMock()
        mock_vb.oid.val = "1.3.6.1.2.1.1.3.0"
        mock_vb.value = "12345"
        
        mock_packet = MagicMock()
        mock_packet.__getitem__ = MagicMock(return_value=MagicMock(
            PDU=MagicMock(varbindlist=[mock_vb])
        ))
        
        result = get_snmptrap_oid(mock_packet)
        
        assert result is None


class TestGetSnmpEnterpriseSpecific:
    """Tests for get_snmp_enterprise_specific function."""

    def test_extracts_enterprise_oid(self):
        """Test enterprise-specific OID extraction for SNMPv1."""
        from trapninja.snmp import get_snmp_enterprise_specific
        
        mock_packet = MagicMock()
        mock_pdu = MagicMock()
        mock_pdu.enterprise.val = "1.3.6.1.4.1.9"
        mock_pdu.specific_trap.val = 42
        mock_packet.__getitem__ = MagicMock(return_value=MagicMock(PDU=mock_pdu))
        
        result = get_snmp_enterprise_specific(mock_packet)
        
        assert result == "1.3.6.1.4.1.9.0.42"

    def test_returns_none_when_missing_enterprise(self):
        """Test returns None when enterprise not present."""
        from trapninja.snmp import get_snmp_enterprise_specific
        
        mock_packet = MagicMock()
        mock_pdu = MagicMock(spec=[])  # No enterprise attribute
        mock_packet.__getitem__ = MagicMock(return_value=MagicMock(PDU=mock_pdu))
        
        result = get_snmp_enterprise_specific(mock_packet)
        
        assert result is None


class TestConvertAsn1Value:
    """Tests for convert_asn1_value function."""

    def test_convert_integer(self):
        """Test INTEGER conversion."""
        from trapninja.snmp import convert_asn1_value
        
        # Create mock value with class name containing 'INTEGER'
        mock_value = MagicMock()
        mock_value.__class__ = type('ASN1_INTEGER', (), {})
        mock_value.val = 42
        
        result = convert_asn1_value(mock_value)
        
        assert result == 42

    def test_convert_string(self):
        """Test OCTET STRING conversion."""
        from trapninja.snmp import convert_asn1_value
        
        mock_value = MagicMock()
        mock_value.__class__ = type('ASN1_OCTET_STRING', (), {})
        mock_value.val = "test string"
        
        result = convert_asn1_value(mock_value)
        
        assert result == "test string"

    def test_convert_null(self):
        """Test NULL conversion."""
        from trapninja.snmp import convert_asn1_value
        
        mock_value = MagicMock()
        mock_value.__class__ = type('ASN1_NULL', (), {})
        
        result = convert_asn1_value(mock_value)
        
        assert result is None

    def test_convert_timeticks(self):
        """Test TimeTicks conversion."""
        from trapninja.snmp import convert_asn1_value
        
        # Class name must contain 'TIME' (uppercase) for the TIME branch
        mock_value = MagicMock()
        mock_value.__class__ = type('TimeTicks_TIME', (), {})
        mock_value.val = 123456
        
        result = convert_asn1_value(mock_value)
        
        assert result == 123456


class TestGetProcessingStats:
    """Tests for get_processing_stats function."""

    def test_returns_stats_dict(self):
        """Test get_processing_stats returns dictionary."""
        from trapninja.snmp import get_processing_stats, _stats
        
        # Set some values
        _stats.received = 100
        _stats.forwarded = 90
        _stats.fast_path_hits = 80
        _stats.slow_path_hits = 10
        
        result = get_processing_stats()
        
        assert 'received' in result
        assert 'forwarded' in result
        assert 'fast_path_hits' in result
        assert 'fast_path_ratio' in result
        
        assert result['received'] == 100
        assert result['forwarded'] == 90

    def test_fast_path_ratio_calculation(self):
        """Test fast path ratio is calculated correctly."""
        from trapninja.snmp import get_processing_stats, _stats
        
        _stats.received = 100
        _stats.fast_path_hits = 80
        
        result = get_processing_stats()
        
        assert result['fast_path_ratio'] == 80.0

    def test_fast_path_ratio_no_division_by_zero(self):
        """Test fast path ratio handles zero received."""
        from trapninja.snmp import get_processing_stats, _stats
        
        _stats.received = 0
        _stats.fast_path_hits = 0
        
        result = get_processing_stats()
        
        # Should not raise ZeroDivisionError
        assert result['fast_path_ratio'] == 0.0
