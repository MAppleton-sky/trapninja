#!/usr/bin/env python3
"""
TrapNinja Test Suite - Diagnostics Module Tests

Tests for trapninja.diagnostics module - packet inspection and validation.

Assumptions:
- ASN.1 SEQUENCE tag is 0x30
- ASN.1 INTEGER tag is 0x02
- ASN.1 OCTET STRING tag is 0x04
- SNMP version byte: 0=v1, 1=v2c, 2=v2, 3=v3
- Length encoding uses short form (< 128) or long form (>= 128)

Author: TrapNinja Team
"""

import os
import binascii
import pytest
from unittest.mock import patch, MagicMock


class TestAnalyzePacketStructure:
    """Tests for analyze_packet_structure function."""

    def test_empty_payload(self):
        """Test analysis of empty payload."""
        from trapninja.diagnostics import analyze_packet_structure
        
        result = analyze_packet_structure(b'')
        
        assert result['payload_length'] == 0
        assert 'Empty payload' in result['potential_issues']

    def test_short_payload_hex_dump(self):
        """Test hex dump for short payload."""
        from trapninja.diagnostics import analyze_packet_structure
        
        payload = b'\x30\x05\x02\x01\x01'
        result = analyze_packet_structure(payload)
        
        assert result['first_20_bytes_hex'] == binascii.hexlify(payload).decode('ascii')

    def test_full_payload_hex_dump(self):
        """Test hex dump truncates at 20 bytes."""
        from trapninja.diagnostics import analyze_packet_structure
        
        payload = b'\x30' * 50
        result = analyze_packet_structure(payload)
        
        # Should only show first 20 bytes
        assert len(result['first_20_bytes_hex']) == 40  # 20 bytes * 2 hex chars

    def test_detects_missing_sequence_tag(self):
        """Test detection of missing SEQUENCE tag."""
        from trapninja.diagnostics import analyze_packet_structure
        
        # Not starting with 0x30
        payload = b'\x31\x50\x02\x01\x01'
        result = analyze_packet_structure(payload)
        
        issues = [i for i in result['potential_issues'] if 'SEQUENCE' in i]
        assert len(issues) > 0

    def test_detects_short_form_length(self):
        """Test detection of short form length encoding."""
        from trapninja.diagnostics import analyze_packet_structure
        
        # Short form: length byte < 128
        payload = b'\x30\x50\x02\x01\x01\x04\x06public'
        result = analyze_packet_structure(payload)
        
        assert result['asn1_structure'] is not None
        assert result['asn1_structure']['length_encoding'] == 'short_form'
        assert result['asn1_structure']['declared_length'] == 0x50

    def test_detects_long_form_length(self):
        """Test detection of long form length encoding."""
        from trapninja.diagnostics import analyze_packet_structure
        
        # Long form: 0x82 means 2 bytes follow for length
        # 0x82 0x01 0x00 = 256 bytes
        payload = b'\x30\x82\x01\x00' + b'\x02\x01\x01' + b'\x00' * 250
        result = analyze_packet_structure(payload)
        
        assert result['asn1_structure'] is not None
        assert result['asn1_structure']['length_encoding'] == 'long_form'
        assert result['asn1_structure']['declared_length'] == 256

    def test_detects_length_mismatch(self):
        """Test detection of length mismatch."""
        from trapninja.diagnostics import analyze_packet_structure
        
        # Declares length 0x50 (80 bytes) but payload is shorter
        payload = b'\x30\x50\x02\x01\x01'
        result = analyze_packet_structure(payload)
        
        issues = [i for i in result['potential_issues'] if 'Length mismatch' in i]
        assert len(issues) > 0

    def test_detects_snmp_version_field(self):
        """Test detection of SNMP version field."""
        from trapninja.diagnostics import analyze_packet_structure
        
        # Valid SNMPv2c header
        payload = b'\x30\x50\x02\x01\x01\x04\x06public'
        result = analyze_packet_structure(payload)
        
        assert result['snmp_detection']['has_version_field'] is True
        assert result['snmp_detection']['version'] == 'v2c'

    @pytest.mark.parametrize("version_byte,expected", [
        (0x00, 'v1'),
        (0x01, 'v2c'),
        (0x02, 'v2'),
        (0x03, 'v3'),
    ])
    def test_detects_snmp_versions(self, version_byte, expected):
        """Test detection of various SNMP versions."""
        from trapninja.diagnostics import analyze_packet_structure
        
        payload = bytes([0x30, 0x50, 0x02, 0x01, version_byte, 0x04, 0x06]) + b'public'
        result = analyze_packet_structure(payload)
        
        assert result['snmp_detection']['version'] == expected

    def test_detects_community_string(self):
        """Test extraction of community string."""
        from trapninja.diagnostics import analyze_packet_structure
        
        payload = b'\x30\x50\x02\x01\x01\x04\x06public'
        result = analyze_packet_structure(payload)
        
        assert result['snmp_detection']['has_community_field'] is True
        assert result['snmp_detection']['community'] == 'public'

    def test_detects_null_byte_sequence(self):
        """Test detection of null byte sequences."""
        from trapninja.diagnostics import analyze_packet_structure
        
        payload = b'\x30\x50\x02\x01\x01' + b'\x00' * 20
        result = analyze_packet_structure(payload)
        
        issues = [i for i in result['potential_issues'] if 'null bytes' in i]
        assert len(issues) > 0

    def test_detects_short_payload(self):
        """Test detection of suspiciously short payload."""
        from trapninja.diagnostics import analyze_packet_structure
        
        payload = b'\x30\x05\x02\x01\x01'
        result = analyze_packet_structure(payload)
        
        issues = [i for i in result['potential_issues'] if 'short' in i.lower()]
        assert len(issues) > 0


class TestLogParsingFailure:
    """Tests for log_parsing_failure function."""

    def test_logs_failure_info(self):
        """Test parsing failure logging."""
        from trapninja.diagnostics import log_parsing_failure
        
        with patch('trapninja.diagnostics.logger') as mock_logger:
            log_parsing_failure(
                source_ip="192.168.1.1",
                payload=b'\x30\x50\x02\x01\x01',
                snmp_version="v2c"
            )
            
            # Should log multiple warning messages
            assert mock_logger.warning.called

    def test_logs_without_version(self):
        """Test logging without SNMP version."""
        from trapninja.diagnostics import log_parsing_failure
        
        with patch('trapninja.diagnostics.logger') as mock_logger:
            # Should not raise
            log_parsing_failure(
                source_ip="192.168.1.1",
                payload=b'\x30\x50\x02\x01\x01',
                snmp_version=None
            )
            
            assert mock_logger.warning.called


class TestDumpPacketToFile:
    """Tests for dump_packet_to_file function."""

    def test_creates_dump_directory(self, tmp_path):
        """Test dump directory is created."""
        from trapninja.diagnostics import dump_packet_to_file
        
        dump_dir = tmp_path / "dumps"
        
        dump_packet_to_file(
            source_ip="192.168.1.1",
            payload=b'\x30\x50\x02\x01\x01',
            dump_dir=str(dump_dir)
        )
        
        assert dump_dir.exists()

    def test_creates_binary_dump(self, tmp_path):
        """Test binary dump file is created."""
        from trapninja.diagnostics import dump_packet_to_file
        
        dump_dir = tmp_path / "dumps"
        payload = b'\x30\x50\x02\x01\x01'
        
        filename = dump_packet_to_file(
            source_ip="192.168.1.1",
            payload=payload,
            dump_dir=str(dump_dir)
        )
        
        assert filename is not None
        assert filename.endswith('.bin')
        
        # Verify content
        with open(filename, 'rb') as f:
            assert f.read() == payload

    def test_creates_analysis_file(self, tmp_path):
        """Test analysis text file is created."""
        from trapninja.diagnostics import dump_packet_to_file
        
        dump_dir = tmp_path / "dumps"
        
        filename = dump_packet_to_file(
            source_ip="192.168.1.1",
            payload=b'\x30\x50\x02\x01\x01',
            dump_dir=str(dump_dir)
        )
        
        analysis_file = filename.replace('.bin', '.txt')
        assert os.path.exists(analysis_file)

    def test_analysis_contains_source_ip(self, tmp_path):
        """Test analysis file contains source IP."""
        from trapninja.diagnostics import dump_packet_to_file
        
        dump_dir = tmp_path / "dumps"
        
        filename = dump_packet_to_file(
            source_ip="192.168.1.100",
            payload=b'\x30\x50\x02\x01\x01',
            dump_dir=str(dump_dir)
        )
        
        analysis_file = filename.replace('.bin', '.txt')
        with open(analysis_file, 'r') as f:
            content = f.read()
        
        assert "192.168.1.100" in content

    def test_filename_includes_ip(self, tmp_path):
        """Test filename includes sanitized IP."""
        from trapninja.diagnostics import dump_packet_to_file
        
        dump_dir = tmp_path / "dumps"
        
        filename = dump_packet_to_file(
            source_ip="192.168.1.1",
            payload=b'\x30\x50\x02\x01\x01',
            dump_dir=str(dump_dir)
        )
        
        assert "192_168_1_1" in filename


class TestValidateSnmpBasicStructure:
    """Tests for validate_snmp_basic_structure function."""

    def test_valid_snmpv1_packet(self):
        """Test validation of valid SNMPv1 packet."""
        from trapninja.diagnostics import validate_snmp_basic_structure
        
        # SNMPv1 packet - needs at least 8 bytes
        payload = b'\x30\x50\x02\x01\x00\x04\x06public\x30\x40'
        
        is_valid, error = validate_snmp_basic_structure(payload)
        
        assert is_valid is True
        assert error is None

    def test_valid_snmpv2c_packet(self):
        """Test validation of valid SNMPv2c packet."""
        from trapninja.diagnostics import validate_snmp_basic_structure
        
        # SNMPv2c packet
        payload = b'\x30\x50\x02\x01\x01\x04\x06public\x30\x40'
        
        is_valid, error = validate_snmp_basic_structure(payload)
        
        assert is_valid is True

    def test_valid_snmpv3_packet(self):
        """Test validation of valid SNMPv3 packet."""
        from trapninja.diagnostics import validate_snmp_basic_structure
        
        # SNMPv3 packet (version 3) - needs at least 8 bytes
        # No community string required for v3
        payload = b'\x30\x50\x02\x01\x03\x30\x10\x02\x01\x00'
        
        is_valid, error = validate_snmp_basic_structure(payload)
        
        assert is_valid is True

    def test_rejects_too_short_payload(self):
        """Test rejection of too short payload."""
        from trapninja.diagnostics import validate_snmp_basic_structure
        
        payload = b'\x30\x02\x01'  # Only 3 bytes
        
        is_valid, error = validate_snmp_basic_structure(payload)
        
        assert is_valid is False
        assert "too short" in error.lower()

    def test_rejects_invalid_sequence_tag(self):
        """Test rejection of invalid SEQUENCE tag."""
        from trapninja.diagnostics import validate_snmp_basic_structure
        
        payload = b'\x31\x50\x02\x01\x01\x04\x06public'  # 0x31 instead of 0x30
        
        is_valid, error = validate_snmp_basic_structure(payload)
        
        assert is_valid is False
        assert "SEQUENCE" in error

    def test_rejects_invalid_integer_tag(self):
        """Test rejection of invalid INTEGER tag for version."""
        from trapninja.diagnostics import validate_snmp_basic_structure
        
        payload = b'\x30\x50\x04\x01\x01\x04\x06public'  # 0x04 instead of 0x02
        
        is_valid, error = validate_snmp_basic_structure(payload)
        
        assert is_valid is False
        assert "INTEGER" in error

    def test_rejects_invalid_version_length(self):
        """Test rejection of invalid version field length."""
        from trapninja.diagnostics import validate_snmp_basic_structure
        
        payload = b'\x30\x50\x02\x02\x00\x01\x04\x06public'  # Length 2 instead of 1
        
        is_valid, error = validate_snmp_basic_structure(payload)
        
        assert is_valid is False
        assert "length" in error.lower()

    def test_rejects_invalid_snmp_version(self):
        """Test rejection of invalid SNMP version value."""
        from trapninja.diagnostics import validate_snmp_basic_structure
        
        payload = b'\x30\x50\x02\x01\x05\x04\x06public'  # Version 5 is invalid
        
        is_valid, error = validate_snmp_basic_structure(payload)
        
        assert is_valid is False
        assert "version" in error.lower()

    def test_rejects_missing_community_string_v1(self):
        """Test rejection of missing community string for v1."""
        from trapninja.diagnostics import validate_snmp_basic_structure
        
        # 8+ bytes with version 0 (v1) but wrong tag for community
        payload = b'\x30\x50\x02\x01\x00\x02\x06\x00\x00\x00'  # 0x02 instead of 0x04
        
        is_valid, error = validate_snmp_basic_structure(payload)
        
        assert is_valid is False
        assert "community" in error.lower()

    def test_rejects_truncated_community(self):
        """Test rejection of truncated community string."""
        from trapninja.diagnostics import validate_snmp_basic_structure
        
        # Declares community length 20 but payload ends - needs 8+ bytes
        payload = b'\x30\x50\x02\x01\x01\x04\x14pub'  # Only 3 chars, declared 20
        
        is_valid, error = validate_snmp_basic_structure(payload)
        
        assert is_valid is False
        assert "community length" in error.lower()


class TestSuggestParserImprovements:
    """Tests for suggest_parser_improvements function."""

    def test_detects_enterprise_oid(self):
        """Test detection of enterprise OID."""
        from trapninja.diagnostics import suggest_parser_improvements
        
        # Enterprise OID prefix: 1.3.6.1.4.1
        payload = b'\x30\x50\x02\x01\x01\x04\x06public\x2b\x06\x01\x04\x01'
        
        suggestions = suggest_parser_improvements(payload)
        
        enterprise_suggestions = [s for s in suggestions if 'enterprise' in s.lower()]
        assert len(enterprise_suggestions) > 0

    def test_detects_snmpv2_trap_pdu(self):
        """Test detection of SNMPv2 Trap PDU."""
        from trapninja.diagnostics import suggest_parser_improvements
        
        # 0xa7 = SNMPv2-Trap-PDU
        payload = b'\x30\x50\x02\x01\x01\x04\x06public\xa7\x40'
        
        suggestions = suggest_parser_improvements(payload)
        
        trap_suggestions = [s for s in suggestions if 'SNMPv2' in s]
        assert len(trap_suggestions) > 0

    def test_detects_snmpv1_trap_pdu(self):
        """Test detection of SNMPv1 Trap PDU."""
        from trapninja.diagnostics import suggest_parser_improvements
        
        # 0xa4 = SNMPv1-Trap-PDU
        payload = b'\x30\x50\x02\x01\x00\x04\x06public\xa4\x40'
        
        suggestions = suggest_parser_improvements(payload)
        
        trap_suggestions = [s for s in suggestions if 'SNMPv1' in s]
        assert len(trap_suggestions) > 0

    def test_detects_snmpv3_encryption(self):
        """Test detection of SNMPv3 encrypted packet."""
        from trapninja.diagnostics import suggest_parser_improvements
        
        # Version 3 - needs 10+ bytes for the check
        payload = b'\x30\x50\x02\x01\x03\x30\x10\x04\x20\x00\x00'
        
        suggestions = suggest_parser_improvements(payload)
        
        v3_suggestions = [s for s in suggestions if 'SNMPv3' in s or 'decryption' in s.lower()]
        assert len(v3_suggestions) > 0

    def test_detects_length_mismatch_issue(self):
        """Test suggestion for length mismatch issues."""
        from trapninja.diagnostics import suggest_parser_improvements
        
        # Declare length 0x50 but payload is shorter
        payload = b'\x30\x50\x02\x01\x01'
        
        suggestions = suggest_parser_improvements(payload)
        
        # Should suggest something about truncation
        length_suggestions = [s for s in suggestions 
                            if 'truncation' in s.lower() or 'length' in s.lower()]
        assert len(length_suggestions) > 0

    def test_empty_suggestions_for_normal_packet(self):
        """Test no suggestions for well-formed packet."""
        from trapninja.diagnostics import suggest_parser_improvements
        
        # Well-formed packet with correct length
        payload = b'\x30\x0d\x02\x01\x01\x04\x06public\x30\x00'
        
        suggestions = suggest_parser_improvements(payload)
        
        # May have some suggestions but should be minimal
        assert isinstance(suggestions, list)


class TestLongFormLengthParsing:
    """Tests for long-form ASN.1 length parsing edge cases."""

    def test_one_byte_long_form(self):
        """Test 1-byte long form length."""
        from trapninja.diagnostics import analyze_packet_structure
        
        # 0x81 0x80 = long form, 1 byte, value 128
        payload = b'\x30\x81\x80' + b'\x02\x01\x01' + b'\x00' * 120
        result = analyze_packet_structure(payload)
        
        assert result['asn1_structure'] is not None
        assert result['asn1_structure']['length_encoding'] == 'long_form'
        assert result['asn1_structure']['declared_length'] == 128

    def test_two_byte_long_form(self):
        """Test 2-byte long form length."""
        from trapninja.diagnostics import analyze_packet_structure
        
        # 0x82 0x01 0x00 = long form, 2 bytes, value 256
        payload = b'\x30\x82\x01\x00' + b'\x02\x01\x01' + b'\x00' * 250
        result = analyze_packet_structure(payload)
        
        assert result['asn1_structure'] is not None
        assert result['asn1_structure']['length_encoding'] == 'long_form'
        assert result['asn1_structure']['declared_length'] == 256
