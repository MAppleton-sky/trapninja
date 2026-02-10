#!/usr/bin/env python3
"""
TrapNinja Test Suite - SNMP Processing Module Tests

Tests for trapninja.processing module - high-performance SNMP trap processing.

Note: This file previously tested trapninja.snmp which has been removed.
The processing module (processing/parser.py, processing/worker.py, etc.)
is now the canonical implementation.

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
    """Tests for SNMP version constants in parser module."""

    def test_snmptrapoid_marker(self):
        """Test snmpTrapOID marker bytes."""
        from trapninja.processing.parser import SNMPTRAPOID_MARKER
        
        # snmpTrapOID.0 = 1.3.6.1.6.3.1.1.4.1.0
        # BER encoded: 2b.06.01.06.03.01.01.04.01.00
        expected = b'\x2b\x06\x01\x06\x03\x01\x01\x04\x01\x00'
        assert SNMPTRAPOID_MARKER == expected

    def test_asn1_constants(self):
        """Test ASN.1 tag constants."""
        from trapninja.processing.parser import (
            ASN1_SEQUENCE, ASN1_INTEGER, ASN1_OCTET_STRING, ASN1_OID
        )
        
        assert ASN1_SEQUENCE == 0x30
        assert ASN1_INTEGER == 0x02
        assert ASN1_OCTET_STRING == 0x04
        assert ASN1_OID == 0x06

    def test_snmp_version_constants(self):
        """Test SNMP version constants."""
        from trapninja.processing.parser import SNMP_V1, SNMP_V2C, SNMP_V3
        
        assert SNMP_V1 == 0
        assert SNMP_V2C == 1
        assert SNMP_V3 == 3


class TestConfigCache:
    """Tests for ConfigCache class in worker module."""

    def test_cache_initialization(self):
        """Test ConfigCache initializes with defaults."""
        from trapninja.processing.worker import ConfigCache
        
        cache = ConfigCache(ttl=30.0)
        
        assert cache.ttl == 30.0
        assert cache._cache is None
        assert cache._cache_time == 0

    def test_cache_custom_ttl(self):
        """Test ConfigCache with custom TTL."""
        from trapninja.processing.worker import ConfigCache
        
        cache = ConfigCache(ttl=60.0)
        
        assert cache.ttl == 60.0

    def test_cache_returns_cached_value_within_ttl(self):
        """Test that cached value is returned within TTL."""
        from trapninja.processing.worker import ConfigCache
        
        cache = ConfigCache(ttl=30.0)
        cache._cache = {'test': 'value'}
        cache._cache_time = time.time()
        
        result = cache.get()
        
        assert result == {'test': 'value'}

    def test_cache_invalidate(self):
        """Test cache invalidation."""
        from trapninja.processing.worker import ConfigCache
        
        cache = ConfigCache(ttl=30.0)
        cache._cache = {'test': 'value'}
        cache._cache_time = time.time()
        
        cache.invalidate()
        
        assert cache._cache_time == 0

    def test_cache_thread_safety(self):
        """Test cache is thread-safe."""
        from trapninja.processing.worker import ConfigCache
        
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
    """Tests for ProcessingStats class in processing/stats module."""

    def test_stats_initialization(self):
        """Test ProcessingStats initializes with zeros."""
        from trapninja.processing.stats import ProcessingStats
        
        stats = ProcessingStats()
        
        assert stats.packets_processed == 0
        assert stats.packets_forwarded == 0
        assert stats.packets_blocked == 0
        assert stats.packets_redirected == 0
        assert stats.processing_errors == 0
        assert stats.fast_path_hits == 0
        assert stats.slow_path_hits == 0


class TestIsSnmpv2c:
    """Tests for is_snmpv2c function."""

    def test_valid_snmpv2c_packet(self):
        """Test detection of valid SNMPv2c packet."""
        from trapninja.processing.parser import is_snmpv2c
        
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
        from trapninja.processing.parser import is_snmpv2c
        
        # SNMPv1 has version = 0
        payload = bytes([0x30, 0x50, 0x02, 0x01, 0x00, 0x04, 0x06]) + b'public'
        
        assert is_snmpv2c(payload) is False

    def test_snmpv3_packet(self):
        """Test SNMPv3 packet is not detected as v2c."""
        from trapninja.processing.parser import is_snmpv2c
        
        # SNMPv3 has version = 3
        payload = bytes([0x30, 0x50, 0x02, 0x01, 0x03, 0x04, 0x06]) + b'public'
        
        assert is_snmpv2c(payload) is False

    def test_short_payload(self):
        """Test short payload returns False."""
        from trapninja.processing.parser import is_snmpv2c
        
        assert is_snmpv2c(b'\x30\x02\x02') is False
        assert is_snmpv2c(b'') is False

    def test_invalid_sequence_tag(self):
        """Test invalid SEQUENCE tag returns False."""
        from trapninja.processing.parser import is_snmpv2c
        
        payload = bytes([0x31, 0x50, 0x02, 0x01, 0x01, 0x04, 0x06]) + b'public'
        
        assert is_snmpv2c(payload) is False


class TestIsSnmpv1:
    """Tests for is_snmpv1 function."""

    def test_valid_snmpv1_packet(self):
        """Test detection of valid SNMPv1 packet."""
        from trapninja.processing.parser import is_snmpv1
        
        # Valid SNMPv1 packet header (version = 0)
        payload = bytes([0x30, 0x50, 0x02, 0x01, 0x00, 0x04, 0x06]) + b'public'
        
        assert is_snmpv1(payload) is True

    def test_snmpv2c_packet(self):
        """Test SNMPv2c packet is not detected as v1."""
        from trapninja.processing.parser import is_snmpv1
        
        payload = bytes([0x30, 0x50, 0x02, 0x01, 0x01, 0x04, 0x06]) + b'public'
        
        assert is_snmpv1(payload) is False


class TestIsSnmpv3:
    """Tests for is_snmpv3 function."""

    def test_valid_snmpv3_packet(self):
        """Test detection of valid SNMPv3 packet."""
        from trapninja.processing.parser import is_snmpv3
        
        # SNMPv3 has version = 3, followed by SEQUENCE (msgGlobalData)
        # not OCTET STRING like v1/v2c community
        payload = bytes([
            0x30, 0x50,  # SEQUENCE
            0x02, 0x01, 0x03,  # INTEGER version = 3
            0x30, 0x10,  # SEQUENCE (msgGlobalData) - this distinguishes v3
        ]) + b'\x00' * 20
        
        assert is_snmpv3(payload) is True

    def test_snmpv2c_packet(self):
        """Test SNMPv2c packet is not detected as v3."""
        from trapninja.processing.parser import is_snmpv3
        
        # SNMPv2c has OCTET STRING after version, not SEQUENCE
        payload = bytes([0x30, 0x50, 0x02, 0x01, 0x01, 0x04, 0x06]) + b'public'
        
        assert is_snmpv3(payload) is False


class TestDecodeOid:
    """Tests for decode_oid function."""

    def test_decode_simple_oid(self):
        """Test decoding simple OID."""
        from trapninja.processing.parser import decode_oid
        
        # 1.3.6.1 encoded as: first byte = 1*40+3=43, then 6, 1
        oid_bytes = bytes([43, 6, 1])
        
        result = decode_oid(oid_bytes)
        
        assert result == "1.3.6.1"

    def test_decode_enterprise_oid(self):
        """Test decoding enterprise OID with large values."""
        from trapninja.processing.parser import decode_oid
        
        # 1.3.6.1.4.1 = iso.org.dod.internet.private.enterprises
        oid_bytes = bytes([43, 6, 1, 4, 1])
        
        result = decode_oid(oid_bytes)
        
        assert result == "1.3.6.1.4.1"

    def test_decode_multibyte_component(self):
        """Test decoding OID with multi-byte component."""
        from trapninja.processing.parser import decode_oid
        
        # Component 8072 = 0x1F88 requires multi-byte encoding
        # 8072 = 0b11111100101000 -> 0b0111111 0b0001000 with high bits
        # = 0xBF 0x08 (with continuation bit on first byte)
        oid_bytes = bytes([43, 6, 1, 4, 1, 0xBF, 0x08])
        
        result = decode_oid(oid_bytes)
        
        assert result == "1.3.6.1.4.1.8072"

    def test_decode_empty_oid(self):
        """Test decoding empty OID bytes."""
        from trapninja.processing.parser import decode_oid
        
        result = decode_oid(b'')
        
        assert result == ""


class TestEncodeOid:
    """Tests for encode_oid function."""

    def test_encode_simple_oid(self):
        """Test encoding simple OID."""
        from trapninja.processing.parser import encode_oid
        
        result = encode_oid("1.3.6.1")
        
        # 1.3.6.1 encoded as: first byte = 1*40+3=43, then 6, 1
        assert result == bytes([43, 6, 1])

    def test_encode_decode_roundtrip(self):
        """Test encode/decode roundtrip."""
        from trapninja.processing.parser import encode_oid, decode_oid
        
        original = "1.3.6.1.4.1.8072"
        encoded = encode_oid(original)
        decoded = decode_oid(encoded)
        
        assert decoded == original


class TestExtractTrapOidFast:
    """Tests for extract_trap_oid_fast function."""

    def test_extract_oid_from_valid_trap(self):
        """Test OID extraction from valid trap packet."""
        from trapninja.processing.parser import extract_trap_oid_fast, SNMPTRAPOID_MARKER
        
        # Build a packet with snmpTrapOID.0 followed by an OID value
        # OID tag (0x06) + length + OID bytes for 1.3.6.1.6.3.1.1.5.1 (coldStart)
        trap_oid_bytes = bytes([43, 6, 1, 6, 3, 1, 1, 5, 1])
        payload = (
            b'\x30\x50\x02\x01\x01\x04\x06public' +
            SNMPTRAPOID_MARKER +
            bytes([0x06, len(trap_oid_bytes)]) +
            trap_oid_bytes
        )
        
        result = extract_trap_oid_fast(payload)
        
        assert result == "1.3.6.1.6.3.1.1.5.1"

    def test_returns_none_when_marker_not_found(self):
        """Test returns None when snmpTrapOID marker not found."""
        from trapninja.processing.parser import extract_trap_oid_fast
        
        payload = b'\x30\x50\x02\x01\x01\x04\x06public\x30\x10'
        
        result = extract_trap_oid_fast(payload)
        
        assert result is None

    def test_returns_none_for_invalid_oid_tag(self):
        """Test returns None when OID tag is wrong."""
        from trapninja.processing.parser import extract_trap_oid_fast, SNMPTRAPOID_MARKER
        
        # Wrong tag (0x04 OCTET STRING instead of 0x06 OID)
        payload = (
            b'\x30\x50\x02\x01\x01\x04\x06public' +
            SNMPTRAPOID_MARKER +
            bytes([0x04, 0x05]) + b'test'
        )
        
        result = extract_trap_oid_fast(payload)
        
        assert result is None

    def test_returns_none_for_truncated_packet(self):
        """Test returns None for truncated packet."""
        from trapninja.processing.parser import extract_trap_oid_fast, SNMPTRAPOID_MARKER
        
        # Packet truncated after marker
        payload = (
            b'\x30\x50\x02\x01\x01\x04\x06public' +
            SNMPTRAPOID_MARKER
        )
        
        result = extract_trap_oid_fast(payload)
        
        assert result is None


class TestParseSnmpPacket:
    """Tests for parse_snmp_packet function."""

    def test_parse_valid_snmpv2c(self):
        """Test parsing valid SNMPv2c packet."""
        from trapninja.processing.parser import parse_snmp_packet
        
        # Use a real minimal SNMPv2c packet
        # Mock where SNMP is imported inside the function
        with patch('scapy.layers.snmp.SNMP') as mock_snmp:
            mock_packet = MagicMock()
            mock_packet.version.val = 1  # SNMPv2c
            mock_snmp.return_value = mock_packet
            
            snmp, version = parse_snmp_packet(b'\x30\x50\x02\x01\x01')
            
            assert version == "v2c"

    def test_parse_snmpv1(self):
        """Test parsing SNMPv1 packet."""
        from trapninja.processing.parser import parse_snmp_packet
        
        with patch('scapy.layers.snmp.SNMP') as mock_snmp:
            mock_packet = MagicMock()
            mock_packet.version.val = 0  # SNMPv1
            mock_snmp.return_value = mock_packet
            
            snmp, version = parse_snmp_packet(b'\x30\x50\x02\x01\x00')
            
            assert version == "v1"

    def test_parse_snmpv3(self):
        """Test parsing SNMPv3 packet."""
        from trapninja.processing.parser import parse_snmp_packet
        
        with patch('scapy.layers.snmp.SNMP') as mock_snmp:
            mock_packet = MagicMock()
            mock_packet.version.val = 3  # SNMPv3
            mock_snmp.return_value = mock_packet
            
            snmp, version = parse_snmp_packet(b'\x30\x50\x02\x01\x03')
            
            assert version == "v3"

    def test_parse_failure_returns_none(self):
        """Test parsing failure returns None."""
        from trapninja.processing.parser import parse_snmp_packet
        
        with patch('scapy.layers.snmp.SNMP', side_effect=Exception("Parse error")):
            snmp, version = parse_snmp_packet(b'invalid')
            
            assert snmp is None
            assert version is None


class TestGetVarbinds:
    """Tests for get_varbinds function."""

    def test_extracts_varbinds(self):
        """Test varbind extraction from parsed packet."""
        from trapninja.processing.parser import get_varbinds
        
        # Create mock packet with varbinds
        mock_vb1 = MagicMock()
        mock_vb1.oid.val = "1.3.6.1.2.1.1.3.0"
        mock_vb1.value = MagicMock()
        mock_vb1.value.__class__ = type('ASN1_INTEGER', (), {})
        mock_vb1.value.val = 100
        
        mock_vb2 = MagicMock()
        mock_vb2.oid.val = "1.3.6.1.6.3.1.1.4.1.0"
        mock_vb2.value = MagicMock()
        mock_vb2.value.__class__ = type('ASN1_OID', (), {})
        mock_vb2.value.val = "1.3.6.1.6.3.1.1.5.1"
        
        mock_packet = MagicMock()
        mock_packet.__getitem__ = MagicMock(return_value=MagicMock(
            PDU=MagicMock(varbindlist=[mock_vb1, mock_vb2])
        ))
        
        result = get_varbinds(mock_packet)
        
        assert "1.3.6.1.2.1.1.3.0" in result
        assert "1.3.6.1.6.3.1.1.4.1.0" in result

    def test_empty_varbinds(self):
        """Test empty varbind list."""
        from trapninja.processing.parser import get_varbinds
        
        mock_packet = MagicMock()
        mock_packet.__getitem__ = MagicMock(return_value=MagicMock(
            PDU=MagicMock(varbindlist=[])
        ))
        
        result = get_varbinds(mock_packet)
        
        assert result == {}

    def test_missing_varbindlist(self):
        """Test handling missing varbindlist attribute."""
        from trapninja.processing.parser import get_varbinds
        
        mock_packet = MagicMock()
        mock_pdu = MagicMock(spec=[])  # No varbindlist attribute
        mock_packet.__getitem__ = MagicMock(return_value=MagicMock(PDU=mock_pdu))
        
        result = get_varbinds(mock_packet)
        
        assert result == {}


class TestGetSnmptrapOid:
    """Tests for get_snmptrap_oid function."""

    def test_extracts_snmptrapoid(self):
        """Test snmpTrapOID extraction."""
        from trapninja.processing.parser import get_snmptrap_oid
        
        mock_vb = MagicMock()
        mock_vb.oid.val = "1.3.6.1.6.3.1.1.4.1.0"
        mock_vb.value = MagicMock()
        mock_vb.value.__class__ = type('ASN1_OID', (), {})
        mock_vb.value.val = "1.3.6.1.6.3.1.1.5.1"
        
        mock_packet = MagicMock()
        mock_packet.__getitem__ = MagicMock(return_value=MagicMock(
            PDU=MagicMock(varbindlist=[mock_vb])
        ))
        
        result = get_snmptrap_oid(mock_packet)
        
        assert result == "1.3.6.1.6.3.1.1.5.1"

    def test_returns_none_when_not_found(self):
        """Test returns None when snmpTrapOID not present."""
        from trapninja.processing.parser import get_snmptrap_oid
        
        mock_vb = MagicMock()
        mock_vb.oid.val = "1.3.6.1.2.1.1.3.0"
        mock_vb.value = MagicMock()
        mock_vb.value.__class__ = type('ASN1_INTEGER', (), {})
        mock_vb.value.val = 12345
        
        mock_packet = MagicMock()
        mock_packet.__getitem__ = MagicMock(return_value=MagicMock(
            PDU=MagicMock(varbindlist=[mock_vb])
        ))
        
        result = get_snmptrap_oid(mock_packet)
        
        assert result is None


class TestGetEnterpriseOid:
    """Tests for get_enterprise_oid function."""

    def test_extracts_enterprise_oid(self):
        """Test enterprise-specific OID extraction for SNMPv1."""
        from trapninja.processing.parser import get_enterprise_oid
        
        mock_packet = MagicMock()
        mock_pdu = MagicMock()
        mock_pdu.enterprise.val = "1.3.6.1.4.1.9"
        mock_pdu.specific_trap.val = 42
        mock_packet.__getitem__ = MagicMock(return_value=MagicMock(PDU=mock_pdu))
        
        result = get_enterprise_oid(mock_packet)
        
        assert result == "1.3.6.1.4.1.9.0.42"

    def test_returns_none_when_missing_enterprise(self):
        """Test returns None when enterprise not present."""
        from trapninja.processing.parser import get_enterprise_oid
        
        mock_packet = MagicMock()
        mock_pdu = MagicMock(spec=[])  # No enterprise attribute
        mock_packet.__getitem__ = MagicMock(return_value=MagicMock(PDU=mock_pdu))
        
        result = get_enterprise_oid(mock_packet)
        
        assert result is None


class TestGetSnmpVersion:
    """Tests for get_snmp_version function."""

    def test_snmpv1_version(self):
        """Test SNMPv1 version detection."""
        from trapninja.processing.parser import get_snmp_version
        
        payload = bytes([0x30, 0x50, 0x02, 0x01, 0x00, 0x04])
        
        result = get_snmp_version(payload)
        
        assert result == 0  # SNMPv1

    def test_snmpv2c_version(self):
        """Test SNMPv2c version detection."""
        from trapninja.processing.parser import get_snmp_version
        
        payload = bytes([0x30, 0x50, 0x02, 0x01, 0x01, 0x04])
        
        result = get_snmp_version(payload)
        
        assert result == 1  # SNMPv2c

    def test_snmpv3_version(self):
        """Test SNMPv3 version detection."""
        from trapninja.processing.parser import get_snmp_version
        
        payload = bytes([0x30, 0x50, 0x02, 0x01, 0x03, 0x30])
        
        result = get_snmp_version(payload)
        
        assert result == 3  # SNMPv3

    def test_invalid_payload(self):
        """Test invalid payload returns None."""
        from trapninja.processing.parser import get_snmp_version
        
        assert get_snmp_version(b'') is None
        assert get_snmp_version(b'\x31\x50') is None  # Wrong tag


class TestCompleteForwardHelper:
    """Tests for _complete_forward helper method in PacketWorker."""

    def test_complete_forward_calls_all_bookkeeping(self):
        """Test _complete_forward calls all required functions."""
        from trapninja.processing.worker import PacketWorker
        import queue
        import threading
        
        q = queue.Queue()
        stop = threading.Event()
        worker = PacketWorker(0, q, stop)
        
        # Mock all the methods
        worker.stats = MagicMock()
        worker._record_granular_stats = MagicMock()
        worker._store_trap_in_cache = MagicMock()
        
        with patch('trapninja.processing.worker.forward_packet') as mock_forward:
            with patch('trapninja.processing.worker.notify_trap_processed') as mock_notify:
                worker._complete_forward(
                    source_ip='192.168.1.1',
                    payload=b'test',
                    destinations=[('10.0.0.1', 162)],
                    trap_oid='1.3.6.1.4.1.9999.1',
                    destination_tag='default',
                    action='forwarded'
                )
                
                # Verify all calls
                mock_forward.assert_called_once_with(
                    '192.168.1.1', b'test', [('10.0.0.1', 162)]
                )
                worker.stats.increment_forwarded.assert_called_once()
                worker._record_granular_stats.assert_called_once_with(
                    '192.168.1.1', '1.3.6.1.4.1.9999.1', 'forwarded', 'default'
                )
                worker._store_trap_in_cache.assert_called_once_with(
                    '192.168.1.1', b'test', '1.3.6.1.4.1.9999.1', 'default'
                )
                mock_notify.assert_called_once()

    def test_complete_forward_redirected_action(self):
        """Test _complete_forward with redirected action."""
        from trapninja.processing.worker import PacketWorker
        import queue
        import threading
        
        q = queue.Queue()
        stop = threading.Event()
        worker = PacketWorker(0, q, stop)
        
        worker.stats = MagicMock()
        worker._record_granular_stats = MagicMock()
        worker._store_trap_in_cache = MagicMock()
        
        with patch('trapninja.processing.worker.forward_packet'):
            with patch('trapninja.processing.worker.notify_trap_processed'):
                worker._complete_forward(
                    source_ip='192.168.1.1',
                    payload=b'test',
                    destinations=[('10.0.0.1', 162)],
                    trap_oid='1.3.6.1.4.1.9999.1',
                    destination_tag='voice',
                    action='redirected'
                )
                
                worker.stats.increment_redirected.assert_called_once()
                worker.stats.increment_forwarded.assert_not_called()
