#!/usr/bin/env python3
"""
TrapNinja Implementation Tests - Phase 10D: SNMPv3 Pipeline

Validates the complete SNMPv3 processing pipeline including:
- Engine ID / username extraction from raw bytes
- Key localization (passphrase to engine-specific key)
- USM parameter parsing
- Decryption with AES/DES
- ScopedPDU parsing and varbind extraction
- SNMPv2c message conversion
- Credential store integration
- Error handling for malformed/encrypted traps

ASSUMPTIONS:
- SNMPv3 traps have msgSecurityModel = 3 (USM)
- Engine ID is extracted from USM security parameters
- Key localization uses 1MB password expansion per RFC 3414
- AES uses CFB mode with 128-bit segments
- DES uses CBC mode
- SNMPv2c conversion preserves all varbinds
- Credential store provides users keyed by engine ID

Author: TrapNinja Team
"""

import os
import sys
import struct
import hashlib
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

# Shared fixtures and utilities from fixtures/ directory
from fixtures import (
    build_snmpv2c_trap,
    build_snmpv3_packet,
    SampleOIDs,
    SampleIPs,
    create_config,
)


# =============================================================================
# TEST HELPERS - SNMPv3 Message Building
# =============================================================================

def build_usm_params(
    engine_id: bytes,
    engine_boots: int = 1,
    engine_time: int = 100,
    username: str = "testuser",
    auth_params: bytes = b'\x00' * 12,
    priv_params: bytes = b'\x00' * 8
) -> bytes:
    """Build USM security parameters structure."""
    
    def encode_length(length: int) -> bytes:
        if length < 128:
            return bytes([length])
        elif length < 256:
            return bytes([0x81, length])
        else:
            return bytes([0x82, (length >> 8) & 0xff, length & 0xff])
    
    # Engine ID
    engine_id_enc = bytes([0x04]) + encode_length(len(engine_id)) + engine_id
    
    # Engine boots
    boots_bytes = engine_boots.to_bytes((engine_boots.bit_length() + 7) // 8 or 1, 'big')
    boots_enc = bytes([0x02]) + encode_length(len(boots_bytes)) + boots_bytes
    
    # Engine time
    time_bytes = engine_time.to_bytes((engine_time.bit_length() + 7) // 8 or 1, 'big')
    time_enc = bytes([0x02]) + encode_length(len(time_bytes)) + time_bytes
    
    # Username
    username_bytes = username.encode('utf-8')
    username_enc = bytes([0x04]) + encode_length(len(username_bytes)) + username_bytes
    
    # Auth params
    auth_enc = bytes([0x04]) + encode_length(len(auth_params)) + auth_params
    
    # Priv params
    priv_enc = bytes([0x04]) + encode_length(len(priv_params)) + priv_params
    
    # USM SEQUENCE
    content = engine_id_enc + boots_enc + time_enc + username_enc + auth_enc + priv_enc
    return bytes([0x30]) + encode_length(len(content)) + content


def build_snmpv3_message(
    msg_id: int = 1,
    msg_max_size: int = 65507,
    msg_flags: int = 0x07,  # auth + priv + reportable
    security_model: int = 3,  # USM
    engine_id: bytes = b'\x80\x00\x1f\x88\x80',
    username: str = "testuser",
    engine_boots: int = 1,
    engine_time: int = 100,
    scoped_pdu: bytes = None,
    encrypted: bool = True
) -> bytes:
    """
    Build a complete SNMPv3 message with configurable parameters.
    
    Args:
        msg_id: Message ID
        msg_max_size: Maximum message size
        msg_flags: Message flags (auth, priv, reportable bits)
        security_model: Security model (3 = USM)
        engine_id: Engine ID bytes
        username: USM username
        engine_boots: Engine boots counter
        engine_time: Engine time counter
        scoped_pdu: Optional ScopedPDU content (built default if None)
        encrypted: If True, wrap scoped_pdu as OCTET STRING (encrypted)
    """
    
    def encode_length(length: int) -> bytes:
        if length < 128:
            return bytes([length])
        elif length < 256:
            return bytes([0x81, length])
        else:
            return bytes([0x82, (length >> 8) & 0xff, length & 0xff])
    
    # Version (3)
    version_enc = bytes([0x02, 0x01, 0x03])
    
    # msgGlobalData
    msgid_bytes = msg_id.to_bytes(4, 'big')
    msgid_enc = bytes([0x02, 0x04]) + msgid_bytes
    
    maxsize_enc = bytes([0x02, 0x02]) + msg_max_size.to_bytes(2, 'big')
    
    flags_enc = bytes([0x04, 0x01, msg_flags])
    
    secmodel_enc = bytes([0x02, 0x01, security_model])
    
    global_content = msgid_enc + maxsize_enc + flags_enc + secmodel_enc
    global_enc = bytes([0x30]) + encode_length(len(global_content)) + global_content
    
    # USM security parameters (wrapped in OCTET STRING)
    usm_params = build_usm_params(
        engine_id=engine_id,
        engine_boots=engine_boots,
        engine_time=engine_time,
        username=username
    )
    sec_params_enc = bytes([0x04]) + encode_length(len(usm_params)) + usm_params
    
    # Build default ScopedPDU if not provided
    if scoped_pdu is None:
        # Simple ScopedPDU with context engine ID, empty context name, and trap PDU
        ctx_engine_enc = bytes([0x04]) + encode_length(len(engine_id)) + engine_id
        ctx_name_enc = bytes([0x04, 0x00])  # Empty context name
        
        # Simple trap PDU content
        request_id_enc = bytes([0x02, 0x04, 0x00, 0x00, 0x00, 0x01])
        error_status_enc = bytes([0x02, 0x01, 0x00])
        error_index_enc = bytes([0x02, 0x01, 0x00])
        varbind_list_enc = bytes([0x30, 0x00])  # Empty varbind list
        
        pdu_content = request_id_enc + error_status_enc + error_index_enc + varbind_list_enc
        pdu_enc = bytes([0xa7]) + encode_length(len(pdu_content)) + pdu_content
        
        scoped_content = ctx_engine_enc + ctx_name_enc + pdu_enc
        scoped_pdu = bytes([0x30]) + encode_length(len(scoped_content)) + scoped_content
    
    # msgData - encrypted or plaintext
    if encrypted:
        # Wrap as OCTET STRING (simulated encrypted data)
        msg_data_enc = bytes([0x04]) + encode_length(len(scoped_pdu)) + scoped_pdu
    else:
        # Plaintext ScopedPDU
        msg_data_enc = scoped_pdu
    
    # Complete message
    message_content = version_enc + global_enc + sec_params_enc + msg_data_enc
    return bytes([0x30]) + encode_length(len(message_content)) + message_content


def build_scoped_pdu_with_varbinds(
    engine_id: bytes,
    request_id: int = 1,
    varbinds: List[Dict] = None
) -> bytes:
    """Build a ScopedPDU with specified varbinds."""
    
    def encode_length(length: int) -> bytes:
        if length < 128:
            return bytes([length])
        elif length < 256:
            return bytes([0x81, length])
        else:
            return bytes([0x82, (length >> 8) & 0xff, length & 0xff])
    
    def encode_oid(oid_str: str) -> bytes:
        components = [int(c) for c in oid_str.split('.') if c]
        if len(components) < 2:
            return bytes([0x06, 0x00])
        
        result = bytes([components[0] * 40 + components[1]])
        for comp in components[2:]:
            if comp < 128:
                result += bytes([comp])
            else:
                enc = []
                while comp > 0:
                    enc.insert(0, (comp & 0x7f) | 0x80)
                    comp >>= 7
                enc[-1] &= 0x7f
                result += bytes(enc)
        
        return bytes([0x06]) + encode_length(len(result)) + result
    
    # Context engine ID
    ctx_engine_enc = bytes([0x04]) + encode_length(len(engine_id)) + engine_id
    ctx_name_enc = bytes([0x04, 0x00])  # Empty context name
    
    # Build varbinds
    if varbinds is None:
        varbinds = [
            {'oid': SampleOIDs.NET_SNMP_TEST, 'type': 0x04, 'value': b'test value'}
        ]
    
    varbinds_bytes = b''
    for vb in varbinds:
        oid_enc = encode_oid(vb['oid'])
        value_type = vb.get('type', 0x04)
        value = vb.get('value', b'')
        if isinstance(value, str):
            value = value.encode('utf-8')
        elif isinstance(value, int):
            value = value.to_bytes((value.bit_length() + 7) // 8 or 1, 'big')
        
        value_enc = bytes([value_type]) + encode_length(len(value)) + value
        vb_content = oid_enc + value_enc
        varbinds_bytes += bytes([0x30]) + encode_length(len(vb_content)) + vb_content
    
    varbind_list_enc = bytes([0x30]) + encode_length(len(varbinds_bytes)) + varbinds_bytes
    
    # PDU
    reqid_bytes = request_id.to_bytes(4, 'big')
    request_id_enc = bytes([0x02, 0x04]) + reqid_bytes
    error_status_enc = bytes([0x02, 0x01, 0x00])
    error_index_enc = bytes([0x02, 0x01, 0x00])
    
    pdu_content = request_id_enc + error_status_enc + error_index_enc + varbind_list_enc
    pdu_enc = bytes([0xa7]) + encode_length(len(pdu_content)) + pdu_content
    
    # ScopedPDU
    scoped_content = ctx_engine_enc + ctx_name_enc + pdu_enc
    return bytes([0x30]) + encode_length(len(scoped_content)) + scoped_content


# =============================================================================
# MOCK CREDENTIAL USER
# =============================================================================

@dataclass
class MockSNMPv3User:
    """Mock SNMPv3 user for testing."""
    username: str = "testuser"
    auth_protocol: str = "SHA"
    auth_passphrase: str = "authpass123"
    priv_protocol: str = "AES128"
    priv_passphrase: str = "privpass123"
    engine_id: str = "80001f8880"


# =============================================================================
# TEST CLASS: ENGINE ID EXTRACTION
# =============================================================================

class TestEngineIDExtraction:
    """Test engine ID extraction from SNMPv3 messages."""
    
    def test_build_snmpv3_message_structure(self):
        """Verify our test message builder produces parseable messages."""
        from trapninja.snmpv3_decryption import extract_engine_id_from_bytes, extract_username_from_bytes
        
        engine_id = b'\x80\x00\x1f\x88\x80'
        username = "testuser"
        message = build_snmpv3_message(engine_id=engine_id, username=username)
        
        # Should be a SEQUENCE
        assert message[0] == 0x30, f"Expected SEQUENCE (0x30), got 0x{message[0]:02x}"
        
        # Should be able to extract engine ID
        extracted_eid = extract_engine_id_from_bytes(message)
        assert extracted_eid is not None, f"Failed to extract engine ID from message: {message[:50].hex()}"
        assert extracted_eid.lower() == engine_id.hex().lower()
        
        # Should be able to extract username
        extracted_user = extract_username_from_bytes(message)
        assert extracted_user == username
    
    def test_extract_engine_id_valid_message(self):
        """Engine ID extracted from valid SNMPv3 message."""
        from trapninja.snmpv3_decryption import extract_engine_id_from_bytes
        
        engine_id = b'\x80\x00\x1f\x88\x80\x12\x34\x56'
        message = build_snmpv3_message(engine_id=engine_id)
        
        result = extract_engine_id_from_bytes(message)
        
        assert result is not None
        assert result.lower() == engine_id.hex().lower()
    
    def test_extract_engine_id_short_engine(self):
        """Short engine IDs are extracted correctly."""
        from trapninja.snmpv3_decryption import extract_engine_id_from_bytes
        
        engine_id = b'\x80\x00'  # Minimal engine ID
        message = build_snmpv3_message(engine_id=engine_id)
        
        result = extract_engine_id_from_bytes(message)
        
        assert result == '8000'
    
    def test_extract_engine_id_long_engine(self):
        """Long engine IDs (up to 32 bytes) are extracted correctly."""
        from trapninja.snmpv3_decryption import extract_engine_id_from_bytes
        
        engine_id = b'\x80\x00\x1f\x88' + bytes(range(28))  # 32 bytes total
        message = build_snmpv3_message(engine_id=engine_id)
        
        result = extract_engine_id_from_bytes(message)
        
        assert result is not None
        assert len(result) == 64  # 32 bytes = 64 hex chars
    
    def test_extract_engine_id_too_short_message(self):
        """Too short messages return None."""
        from trapninja.snmpv3_decryption import extract_engine_id_from_bytes
        
        result = extract_engine_id_from_bytes(b'\x30\x05\x02\x01\x03')
        
        assert result is None
    
    def test_extract_engine_id_not_sequence(self):
        """Non-SEQUENCE messages return None."""
        from trapninja.snmpv3_decryption import extract_engine_id_from_bytes
        
        result = extract_engine_id_from_bytes(b'\x02\x01\x03')  # INTEGER, not SEQUENCE
        
        assert result is None
    
    def test_extract_engine_id_wrong_version(self):
        """Non-v3 version returns None."""
        from trapninja.snmpv3_decryption import extract_engine_id_from_bytes
        
        # Build v2c message structure
        message = build_snmpv2c_trap()
        
        result = extract_engine_id_from_bytes(message)
        
        assert result is None


# =============================================================================
# TEST CLASS: USERNAME EXTRACTION
# =============================================================================

class TestUsernameExtraction:
    """Test username extraction from SNMPv3 messages."""
    
    def test_extract_username_valid_message(self):
        """Username extracted from valid SNMPv3 message."""
        from trapninja.snmpv3_decryption import extract_username_from_bytes
        
        message = build_snmpv3_message(username="snmpv3admin")
        
        result = extract_username_from_bytes(message)
        
        assert result == "snmpv3admin"
    
    def test_extract_username_empty(self):
        """Empty username is extracted correctly."""
        from trapninja.snmpv3_decryption import extract_username_from_bytes
        
        message = build_snmpv3_message(username="")
        
        result = extract_username_from_bytes(message)
        
        assert result == ""
    
    def test_extract_username_long_name(self):
        """Long usernames (up to 32 chars) are extracted correctly."""
        from trapninja.snmpv3_decryption import extract_username_from_bytes
        
        long_name = "verylongusernamefortesting12345"  # 31 chars
        message = build_snmpv3_message(username=long_name)
        
        result = extract_username_from_bytes(message)
        
        assert result == long_name
    
    def test_extract_username_invalid_message(self):
        """Invalid message returns None."""
        from trapninja.snmpv3_decryption import extract_username_from_bytes
        
        result = extract_username_from_bytes(b'\x30\x05\x02\x01\x03')
        
        assert result is None


# =============================================================================
# TEST CLASS: KEY LOCALIZATION
# =============================================================================

class TestKeyLocalization:
    """Test SNMPv3 key localization algorithm."""
    
    def test_localize_key_sha1(self):
        """Key localization with SHA1 produces correct length."""
        from trapninja.snmpv3_decryption import _localize_key
        
        passphrase = "testpassword123"
        engine_id = bytes.fromhex("80001f8880")
        
        key = _localize_key(passphrase, engine_id, "SHA")
        
        # SHA1 produces 20-byte key
        assert len(key) == 20
    
    def test_localize_key_md5(self):
        """Key localization with MD5 produces correct length."""
        from trapninja.snmpv3_decryption import _localize_key
        
        passphrase = "testpassword123"
        engine_id = bytes.fromhex("80001f8880")
        
        key = _localize_key(passphrase, engine_id, "MD5")
        
        # MD5 produces 16-byte key
        assert len(key) == 16
    
    def test_localize_key_sha256(self):
        """Key localization with SHA256 produces correct length."""
        from trapninja.snmpv3_decryption import _localize_key
        
        passphrase = "testpassword123"
        engine_id = bytes.fromhex("80001f8880")
        
        key = _localize_key(passphrase, engine_id, "SHA256")
        
        # SHA256 produces 32-byte key
        assert len(key) == 32
    
    def test_localize_key_deterministic(self):
        """Same inputs produce same key."""
        from trapninja.snmpv3_decryption import _localize_key
        
        passphrase = "testpassword123"
        engine_id = bytes.fromhex("80001f8880")
        
        key1 = _localize_key(passphrase, engine_id, "SHA")
        key2 = _localize_key(passphrase, engine_id, "SHA")
        
        assert key1 == key2
    
    def test_localize_key_different_engines_different_keys(self):
        """Different engine IDs produce different keys."""
        from trapninja.snmpv3_decryption import _localize_key
        
        passphrase = "testpassword123"
        engine_id_1 = bytes.fromhex("80001f8880")
        engine_id_2 = bytes.fromhex("80001f8881")
        
        key1 = _localize_key(passphrase, engine_id_1, "SHA")
        key2 = _localize_key(passphrase, engine_id_2, "SHA")
        
        assert key1 != key2
    
    def test_localize_key_different_passphrases_different_keys(self):
        """Different passphrases produce different keys."""
        from trapninja.snmpv3_decryption import _localize_key
        
        engine_id = bytes.fromhex("80001f8880")
        
        key1 = _localize_key("password1", engine_id, "SHA")
        key2 = _localize_key("password2", engine_id, "SHA")
        
        assert key1 != key2


# =============================================================================
# TEST CLASS: USM PARAMETER PARSING
# =============================================================================

class TestUSMParameterParsing:
    """Test USM security parameter parsing."""
    
    def test_parse_usm_params_complete(self):
        """Complete USM parameters are parsed correctly."""
        from trapninja.snmpv3_decryption import SNMPv3Decryptor
        
        mock_store = MagicMock()
        decryptor = SNMPv3Decryptor(mock_store)
        
        engine_id = b'\x80\x00\x1f\x88\x80'
        usm_data = build_usm_params(
            engine_id=engine_id,
            engine_boots=100,
            engine_time=5000,
            username="testadmin"
        )
        
        result = decryptor._parse_usm_params(usm_data)
        
        assert result is not None
        assert result['engine_id'] == engine_id
        assert result['engine_boots'] == 100
        assert result['engine_time'] == 5000
        assert result['username'] == "testadmin"
    
    def test_parse_usm_params_zero_boots_time(self):
        """Zero engine boots and time are handled."""
        from trapninja.snmpv3_decryption import SNMPv3Decryptor
        
        mock_store = MagicMock()
        decryptor = SNMPv3Decryptor(mock_store)
        
        usm_data = build_usm_params(
            engine_id=b'\x80\x00',
            engine_boots=0,
            engine_time=0,
            username="user"
        )
        
        result = decryptor._parse_usm_params(usm_data)
        
        assert result is not None
        assert result['engine_boots'] == 0
        assert result['engine_time'] == 0
    
    def test_parse_usm_params_auth_priv_params(self):
        """Auth and priv parameters are extracted."""
        from trapninja.snmpv3_decryption import SNMPv3Decryptor
        
        mock_store = MagicMock()
        decryptor = SNMPv3Decryptor(mock_store)
        
        auth_params = b'\xaa' * 12
        priv_params = b'\xbb' * 8
        
        usm_data = build_usm_params(
            engine_id=b'\x80\x00\x1f\x88\x80',
            auth_params=auth_params,
            priv_params=priv_params
        )
        
        result = decryptor._parse_usm_params(usm_data)
        
        assert result is not None
        assert result['auth_params'] == auth_params
        assert result['priv_params'] == priv_params
    
    def test_parse_usm_params_invalid_structure(self):
        """Invalid USM structure returns None."""
        from trapninja.snmpv3_decryption import SNMPv3Decryptor
        
        mock_store = MagicMock()
        decryptor = SNMPv3Decryptor(mock_store)
        
        # Not a SEQUENCE
        result = decryptor._parse_usm_params(b'\x04\x05hello')
        
        assert result is None


# =============================================================================
# TEST CLASS: SCOPED PDU PARSING
# =============================================================================

class TestScopedPDUParsing:
    """Test ScopedPDU parsing and varbind extraction."""
    
    def test_parse_scoped_pdu_with_varbinds(self):
        """ScopedPDU with varbinds is parsed correctly."""
        from trapninja.snmpv3_decryption import SNMPv3Decryptor
        
        mock_store = MagicMock()
        decryptor = SNMPv3Decryptor(mock_store)
        
        engine_id = b'\x80\x00\x1f\x88\x80'
        scoped_pdu = build_scoped_pdu_with_varbinds(
            engine_id=engine_id,
            request_id=12345,
            varbinds=[
                {'oid': SampleOIDs.COLD_START, 'type': 0x06, 'value': SampleOIDs.NET_SNMP_TEST},
                {'oid': '1.3.6.1.2.1.1.3.0', 'type': 0x43, 'value': 100},  # TimeTicks
            ]
        )
        
        result = decryptor._parse_scoped_pdu(scoped_pdu)
        
        assert result is not None
        assert result['version'] == 'v3'
        assert result['request_id'] == 12345
        assert len(result['varbinds']) == 2
    
    def test_parse_scoped_pdu_empty_varbinds(self):
        """ScopedPDU with empty varbind list is handled."""
        from trapninja.snmpv3_decryption import SNMPv3Decryptor
        
        mock_store = MagicMock()
        decryptor = SNMPv3Decryptor(mock_store)
        
        scoped_pdu = build_scoped_pdu_with_varbinds(
            engine_id=b'\x80\x00',
            varbinds=[]
        )
        
        result = decryptor._parse_scoped_pdu(scoped_pdu)
        
        assert result is not None
        assert result['varbinds'] == []
    
    def test_parse_scoped_pdu_octet_string_value(self):
        """OctetString varbind values are decoded."""
        from trapninja.snmpv3_decryption import SNMPv3Decryptor
        
        mock_store = MagicMock()
        decryptor = SNMPv3Decryptor(mock_store)
        
        scoped_pdu = build_scoped_pdu_with_varbinds(
            engine_id=b'\x80\x00',
            varbinds=[
                {'oid': '1.3.6.1.2.1.1.1.0', 'type': 0x04, 'value': b'Test System Description'}
            ]
        )
        
        result = decryptor._parse_scoped_pdu(scoped_pdu)
        
        assert result is not None
        assert len(result['varbinds']) == 1
        assert result['varbinds'][0]['type'] == 'OctetString'
    
    def test_parse_scoped_pdu_integer_value(self):
        """Integer varbind values are decoded."""
        from trapninja.snmpv3_decryption import SNMPv3Decryptor
        
        mock_store = MagicMock()
        decryptor = SNMPv3Decryptor(mock_store)
        
        scoped_pdu = build_scoped_pdu_with_varbinds(
            engine_id=b'\x80\x00',
            varbinds=[
                {'oid': '1.3.6.1.2.1.1.7.0', 'type': 0x02, 'value': 72}  # sysServices
            ]
        )
        
        result = decryptor._parse_scoped_pdu(scoped_pdu)
        
        assert result is not None
        assert len(result['varbinds']) == 1
        assert result['varbinds'][0]['type'] == 'Integer'
    
    def test_parse_scoped_pdu_ip_address_value(self):
        """IpAddress varbind values are decoded."""
        from trapninja.snmpv3_decryption import SNMPv3Decryptor
        
        mock_store = MagicMock()
        decryptor = SNMPv3Decryptor(mock_store)
        
        scoped_pdu = build_scoped_pdu_with_varbinds(
            engine_id=b'\x80\x00',
            varbinds=[
                {'oid': '1.3.6.1.6.3.18.1.3.0', 'type': 0x40, 'value': bytes([192, 168, 1, 1])}
            ]
        )
        
        result = decryptor._parse_scoped_pdu(scoped_pdu)
        
        assert result is not None
        assert result['varbinds'][0]['type'] == 'IpAddress'
        assert result['varbinds'][0]['value'] == '192.168.1.1'


# =============================================================================
# TEST CLASS: SNMPv2c CONVERSION
# =============================================================================

class TestSNMPv2cConversion:
    """Test conversion of decrypted SNMPv3 data to SNMPv2c format."""
    
    def test_convert_basic_trap(self):
        """Basic trap data converts to valid SNMPv2c message."""
        from trapninja.snmpv3_decryption import SNMPv3Decryptor
        
        mock_store = MagicMock()
        decryptor = SNMPv3Decryptor(mock_store)
        
        trap_data = {
            'version': 'v3',
            'request_id': 12345,
            'varbinds': [
                {
                    'oid': '1.3.6.1.2.1.1.3.0',
                    'value': 100,
                    'type': 'TimeTicks',
                    'raw_tag': 0x43,
                    'raw_bytes': b'\x00\x00\x00\x64'
                }
            ]
        }
        
        result = decryptor.convert_to_snmpv2c(trap_data, community="public")
        
        assert result is not None
        assert len(result) > 25  # Minimum valid message size
        assert result[0] == 0x30  # SEQUENCE
    
    def test_convert_preserves_varbinds(self):
        """All varbinds are preserved in conversion."""
        from trapninja.snmpv3_decryption import SNMPv3Decryptor
        
        mock_store = MagicMock()
        decryptor = SNMPv3Decryptor(mock_store)
        
        trap_data = {
            'version': 'v3',
            'request_id': 1,
            'varbinds': [
                {'oid': '1.3.6.1.2.1.1.3.0', 'value': 100, 'type': 'TimeTicks'},
                {'oid': '1.3.6.1.6.3.1.1.4.1.0', 'value': SampleOIDs.COLD_START, 'type': 'ObjectIdentifier'},
                {'oid': '1.3.6.1.2.1.1.1.0', 'value': 'Test', 'type': 'OctetString'},
            ]
        }
        
        result = decryptor.convert_to_snmpv2c(trap_data)
        
        assert result is not None
        # Message should be valid and contain content
        assert len(result) > 50  # Should have substantial content with 3 varbinds
        # Verify it's a valid SEQUENCE
        assert result[0] == 0x30
        # Verify it passes validation
        assert decryptor._validate_snmpv2c_message(result)
    
    def test_convert_custom_community(self):
        """Custom community string is used in conversion."""
        from trapninja.snmpv3_decryption import SNMPv3Decryptor
        
        mock_store = MagicMock()
        decryptor = SNMPv3Decryptor(mock_store)
        
        trap_data = {
            'version': 'v3',
            'request_id': 1,
            'varbinds': []
        }
        
        result = decryptor.convert_to_snmpv2c(trap_data, community="customcommunity")
        
        assert result is not None
        assert b'customcommunity' in result
    
    def test_convert_empty_varbinds(self):
        """Empty varbind list produces valid message."""
        from trapninja.snmpv3_decryption import SNMPv3Decryptor
        
        mock_store = MagicMock()
        decryptor = SNMPv3Decryptor(mock_store)
        
        trap_data = {
            'version': 'v3',
            'request_id': 0,
            'varbinds': []
        }
        
        result = decryptor.convert_to_snmpv2c(trap_data)
        
        assert result is not None
        # Should still validate
        assert decryptor._validate_snmpv2c_message(result)
    
    def test_convert_validates_output(self):
        """Converted message passes validation."""
        from trapninja.snmpv3_decryption import SNMPv3Decryptor
        
        mock_store = MagicMock()
        decryptor = SNMPv3Decryptor(mock_store)
        
        trap_data = {
            'version': 'v3',
            'request_id': 99999,
            'varbinds': [
                {'oid': SampleOIDs.NET_SNMP_TEST, 'value': 'test', 'type': 'OctetString'}
            ]
        }
        
        result = decryptor.convert_to_snmpv2c(trap_data)
        
        assert result is not None
        assert decryptor._validate_snmpv2c_message(result) is True


# =============================================================================
# TEST CLASS: MESSAGE VALIDATION
# =============================================================================

class TestSNMPv2cMessageValidation:
    """Test SNMPv2c message structure validation."""
    
    def test_validate_valid_message(self):
        """Valid SNMPv2c message passes validation."""
        from trapninja.snmpv3_decryption import SNMPv3Decryptor
        
        mock_store = MagicMock()
        decryptor = SNMPv3Decryptor(mock_store)
        
        # Build a valid v2c trap
        message = build_snmpv2c_trap()
        
        result = decryptor._validate_snmpv2c_message(message)
        
        assert result is True
    
    def test_validate_wrong_version(self):
        """Wrong version fails validation."""
        from trapninja.snmpv3_decryption import SNMPv3Decryptor
        
        mock_store = MagicMock()
        decryptor = SNMPv3Decryptor(mock_store)
        
        # Build v3 message
        message = build_snmpv3_message()
        
        result = decryptor._validate_snmpv2c_message(message)
        
        assert result is False
    
    def test_validate_truncated_message(self):
        """Truncated message fails validation."""
        from trapninja.snmpv3_decryption import SNMPv3Decryptor
        
        mock_store = MagicMock()
        decryptor = SNMPv3Decryptor(mock_store)
        
        # Truncated message
        message = b'\x30\x10\x02\x01\x01'  # Incomplete
        
        result = decryptor._validate_snmpv2c_message(message)
        
        assert result is False


# =============================================================================
# TEST CLASS: DECRYPTOR INITIALIZATION
# =============================================================================

class TestDecryptorInitialization:
    """Test SNMPv3 decryptor initialization."""
    
    def test_decryptor_init_with_store(self):
        """Decryptor initializes with credential store."""
        from trapninja.snmpv3_decryption import SNMPv3Decryptor
        
        mock_store = MagicMock()
        
        decryptor = SNMPv3Decryptor(mock_store)
        
        assert decryptor.credential_store is mock_store
    
    def test_global_decryptor_initialization(self):
        """Global decryptor can be initialized."""
        from trapninja import snmpv3_decryption
        
        # Mock credential store
        mock_store = MagicMock()
        
        with patch.object(snmpv3_decryption, 'PYSNMP_AVAILABLE', True), \
             patch('trapninja.snmpv3_credentials.get_credential_store', return_value=mock_store):
            
            result = snmpv3_decryption.initialize_snmpv3_decryptor()
            
            assert result is not None
            assert snmpv3_decryption.get_snmpv3_decryptor() is not None
    
    def test_global_decryptor_unavailable_without_pysnmp(self):
        """Global decryptor returns None without pysnmp."""
        from trapninja import snmpv3_decryption
        
        with patch.object(snmpv3_decryption, 'PYSNMP_AVAILABLE', False):
            result = snmpv3_decryption.initialize_snmpv3_decryptor()
            
            assert result is None


# =============================================================================
# TEST CLASS: CREDENTIAL STORE INTEGRATION
# =============================================================================

class TestCredentialStoreIntegration:
    """Test integration with credential store."""
    
    def test_decrypt_uses_credential_store(self):
        """Decryption retrieves credentials from store."""
        from trapninja import snmpv3_decryption
        from trapninja.snmpv3_decryption import SNMPv3Decryptor, extract_engine_id_from_bytes
        
        mock_store = MagicMock()
        mock_user = MockSNMPv3User()
        mock_store.get_users_for_engine.return_value = [mock_user]
        
        decryptor = SNMPv3Decryptor(mock_store)
        
        engine_id = b'\x80\x00\x1f\x88\x80'
        message = build_snmpv3_message(engine_id=engine_id, username="testuser")
        
        # Verify engine ID can be extracted from our message
        extracted_id = extract_engine_id_from_bytes(message)
        assert extracted_id is not None, "Engine ID extraction failed - test message may be malformed"
        
        # Patch PYSNMP_AVAILABLE to ensure the method doesn't return early
        with patch.object(snmpv3_decryption, 'PYSNMP_AVAILABLE', True):
            # Will fail decryption but should query store
            decryptor.decrypt_snmpv3_trap(message)
        
        # Should have called get_users_for_engine with the extracted engine ID
        mock_store.get_users_for_engine.assert_called_once_with(extracted_id.lower())
    
    def test_decrypt_no_credentials_returns_none(self):
        """Decryption with no matching credentials returns None."""
        from trapninja import snmpv3_decryption
        from trapninja.snmpv3_decryption import SNMPv3Decryptor
        
        mock_store = MagicMock()
        mock_store.get_users_for_engine.return_value = []  # No users
        
        decryptor = SNMPv3Decryptor(mock_store)
        
        message = build_snmpv3_message(engine_id=b'\x80\x00\x1f\x88\x80')
        
        # Patch PYSNMP_AVAILABLE to ensure the method doesn't return early
        with patch.object(snmpv3_decryption, 'PYSNMP_AVAILABLE', True):
            result = decryptor.decrypt_snmpv3_trap(message)
        
        assert result is None
    
    def test_decrypt_tries_matching_username_first(self):
        """Decryption tries matching username first."""
        from trapninja import snmpv3_decryption
        from trapninja.snmpv3_decryption import SNMPv3Decryptor, extract_engine_id_from_bytes
        
        mock_store = MagicMock()
        user1 = MockSNMPv3User(username="other")
        user2 = MockSNMPv3User(username="target")
        mock_store.get_users_for_engine.return_value = [user1, user2]
        
        decryptor = SNMPv3Decryptor(mock_store)
        
        # Build message with username "target"
        engine_id = b'\x80\x00\x1f\x88\x80'
        message = build_snmpv3_message(engine_id=engine_id, username="target")
        
        # Verify engine ID can be extracted
        extracted_id = extract_engine_id_from_bytes(message)
        assert extracted_id is not None, "Engine ID extraction failed"
        
        # Track call order via side_effect
        call_order = []
        
        def tracking_try_decrypt(msg, eid, user):
            call_order.append(user.username)
            return None  # Fail all attempts
        
        decryptor._try_decrypt_with_user = tracking_try_decrypt
        
        # Patch PYSNMP_AVAILABLE to ensure the method doesn't return early
        with patch.object(snmpv3_decryption, 'PYSNMP_AVAILABLE', True):
            decryptor.decrypt_snmpv3_trap(message)
        
        # Should have made calls
        assert len(call_order) > 0, f"No decrypt attempts were made. Store was called: {mock_store.get_users_for_engine.called}"
        
        # Should try "target" before "other" since it matches the username in the message
        assert call_order[0] == "target", f"Expected 'target' first, got order: {call_order}"


# =============================================================================
# TEST CLASS: BER ENCODING
# =============================================================================

class TestBEREncoding:
    """Test BER encoding utilities."""
    
    def test_encode_length_short(self):
        """Short lengths encode correctly."""
        from trapninja.snmpv3_decryption import SNMPv3Decryptor
        
        mock_store = MagicMock()
        decryptor = SNMPv3Decryptor(mock_store)
        
        assert decryptor._encode_length(0) == bytes([0])
        assert decryptor._encode_length(50) == bytes([50])
        assert decryptor._encode_length(127) == bytes([127])
    
    def test_encode_length_medium(self):
        """Medium lengths encode correctly."""
        from trapninja.snmpv3_decryption import SNMPv3Decryptor
        
        mock_store = MagicMock()
        decryptor = SNMPv3Decryptor(mock_store)
        
        assert decryptor._encode_length(128) == bytes([0x81, 128])
        assert decryptor._encode_length(255) == bytes([0x81, 255])
    
    def test_encode_length_long(self):
        """Long lengths encode correctly."""
        from trapninja.snmpv3_decryption import SNMPv3Decryptor
        
        mock_store = MagicMock()
        decryptor = SNMPv3Decryptor(mock_store)
        
        result = decryptor._encode_length(256)
        assert result == bytes([0x82, 0x01, 0x00])
        
        result = decryptor._encode_length(65535)
        assert result == bytes([0x82, 0xff, 0xff])
    
    def test_encode_integer_zero(self):
        """Zero integer encodes correctly."""
        from trapninja.snmpv3_decryption import SNMPv3Decryptor
        
        mock_store = MagicMock()
        decryptor = SNMPv3Decryptor(mock_store)
        
        result = decryptor._encode_integer(0)
        assert result == bytes([0x02, 0x01, 0x00])
    
    def test_encode_integer_positive(self):
        """Positive integers encode correctly."""
        from trapninja.snmpv3_decryption import SNMPv3Decryptor
        
        mock_store = MagicMock()
        decryptor = SNMPv3Decryptor(mock_store)
        
        result = decryptor._encode_integer(127)
        assert result == bytes([0x02, 0x01, 0x7f])
        
        result = decryptor._encode_integer(128)
        assert result == bytes([0x02, 0x02, 0x00, 0x80])  # Need leading zero
    
    def test_encode_oid(self):
        """OID encoding works correctly."""
        from trapninja.snmpv3_decryption import SNMPv3Decryptor
        
        mock_store = MagicMock()
        decryptor = SNMPv3Decryptor(mock_store)
        
        # 1.3.6.1 -> first byte = 1*40+3 = 43, then 6, 1
        result = decryptor._encode_oid("1.3.6.1")
        assert result[0] == 0x06  # OID tag
        assert result[2] == 43  # 1*40 + 3


# =============================================================================
# TEST CLASS: OID DECODING
# =============================================================================

class TestOIDDecoding:
    """Test OID decoding from BER."""
    
    def test_decode_simple_oid(self):
        """Simple OIDs decode correctly."""
        from trapninja.snmpv3_decryption import SNMPv3Decryptor
        
        mock_store = MagicMock()
        decryptor = SNMPv3Decryptor(mock_store)
        
        # 1.3.6.1 encoded as: 43 (1*40+3), 6, 1
        oid_bytes = bytes([43, 6, 1])
        
        result = decryptor._decode_oid(oid_bytes)
        
        assert result == "1.3.6.1"
    
    def test_decode_oid_with_large_component(self):
        """OIDs with large components (>127) decode correctly."""
        from trapninja.snmpv3_decryption import SNMPv3Decryptor
        
        mock_store = MagicMock()
        decryptor = SNMPv3Decryptor(mock_store)
        
        # 1.3.6.1.4.1.8072 -> 8072 = 0x1F88 = encoded as 0xBF 0x08
        # First byte: 43 (1*40+3)
        # Then: 6, 1, 4, 1
        # Then: 8072 multi-byte: ((8072 >> 7) | 0x80), (8072 & 0x7f) = 0xBF, 0x08
        oid_bytes = bytes([43, 6, 1, 4, 1, 0xBF, 0x08])
        
        result = decryptor._decode_oid(oid_bytes)
        
        assert result == "1.3.6.1.4.1.8072"
    
    def test_decode_empty_oid(self):
        """Empty OID bytes return empty string."""
        from trapninja.snmpv3_decryption import SNMPv3Decryptor
        
        mock_store = MagicMock()
        decryptor = SNMPv3Decryptor(mock_store)
        
        result = decryptor._decode_oid(b'')
        
        assert result == ""


# =============================================================================
# TEST CLASS: VALUE DECODING
# =============================================================================

class TestValueDecoding:
    """Test value decoding based on type tags."""
    
    def test_decode_integer(self):
        """INTEGER values decode correctly."""
        from trapninja.snmpv3_decryption import SNMPv3Decryptor
        
        mock_store = MagicMock()
        decryptor = SNMPv3Decryptor(mock_store)
        
        value, vtype = decryptor._decode_value(0x02, bytes([0x00, 0x64]))  # 100
        
        assert value == 100
        assert vtype == 'Integer'
    
    def test_decode_octet_string_utf8(self):
        """UTF-8 OCTET STRING values decode correctly."""
        from trapninja.snmpv3_decryption import SNMPv3Decryptor
        
        mock_store = MagicMock()
        decryptor = SNMPv3Decryptor(mock_store)
        
        value, vtype = decryptor._decode_value(0x04, b'Hello World')
        
        assert value == 'Hello World'
        assert vtype == 'OctetString'
    
    def test_decode_octet_string_binary(self):
        """Binary OCTET STRING values return hex."""
        from trapninja.snmpv3_decryption import SNMPv3Decryptor
        
        mock_store = MagicMock()
        decryptor = SNMPv3Decryptor(mock_store)
        
        value, vtype = decryptor._decode_value(0x04, bytes([0xff, 0xfe, 0xfd]))
        
        assert value == 'fffefd'
        assert vtype == 'OctetString'
    
    def test_decode_null(self):
        """NULL values decode correctly."""
        from trapninja.snmpv3_decryption import SNMPv3Decryptor
        
        mock_store = MagicMock()
        decryptor = SNMPv3Decryptor(mock_store)
        
        value, vtype = decryptor._decode_value(0x05, b'')
        
        assert value is None
        assert vtype == 'Null'
    
    def test_decode_ip_address(self):
        """IpAddress values decode correctly."""
        from trapninja.snmpv3_decryption import SNMPv3Decryptor
        
        mock_store = MagicMock()
        decryptor = SNMPv3Decryptor(mock_store)
        
        value, vtype = decryptor._decode_value(0x40, bytes([192, 168, 1, 1]))
        
        assert value == '192.168.1.1'
        assert vtype == 'IpAddress'
    
    def test_decode_counter32(self):
        """Counter32 values decode correctly."""
        from trapninja.snmpv3_decryption import SNMPv3Decryptor
        
        mock_store = MagicMock()
        decryptor = SNMPv3Decryptor(mock_store)
        
        value, vtype = decryptor._decode_value(0x41, bytes([0x00, 0x01, 0x00, 0x00]))  # 65536
        
        assert value == 65536
        assert vtype == 'Counter32'
    
    def test_decode_timeticks(self):
        """TimeTicks values decode correctly."""
        from trapninja.snmpv3_decryption import SNMPv3Decryptor
        
        mock_store = MagicMock()
        decryptor = SNMPv3Decryptor(mock_store)
        
        value, vtype = decryptor._decode_value(0x43, bytes([0x00, 0x00, 0x03, 0xe8]))  # 1000
        
        assert value == 1000
        assert vtype == 'TimeTicks'
    
    def test_decode_counter64(self):
        """Counter64 values decode correctly."""
        from trapninja.snmpv3_decryption import SNMPv3Decryptor
        
        mock_store = MagicMock()
        decryptor = SNMPv3Decryptor(mock_store)
        
        value, vtype = decryptor._decode_value(0x46, bytes([0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]))
        
        assert value == 4294967296  # 2^32
        assert vtype == 'Counter64'
    
    def test_decode_unknown_type(self):
        """Unknown type tags return hex and type identifier."""
        from trapninja.snmpv3_decryption import SNMPv3Decryptor
        
        mock_store = MagicMock()
        decryptor = SNMPv3Decryptor(mock_store)
        
        value, vtype = decryptor._decode_value(0x99, bytes([0xaa, 0xbb]))
        
        assert value == 'aabb'
        assert 'Unknown' in vtype


# =============================================================================
# TEST CLASS: END-TO-END CONVENIENCE FUNCTION
# =============================================================================

class TestDecryptAndConvertFunction:
    """Test the convenience function for decrypt and convert."""
    
    def test_decrypt_and_convert_no_decryptor(self):
        """Returns None when decryptor not initialized."""
        from trapninja import snmpv3_decryption
        
        # Ensure no decryptor
        snmpv3_decryption._snmpv3_decryptor = None
        
        result = snmpv3_decryption.decrypt_and_convert_trap(b'\x30\x00')
        
        assert result is None
    
    def test_decrypt_and_convert_with_decryptor(self):
        """Uses decryptor when available."""
        from trapninja import snmpv3_decryption
        
        mock_decryptor = MagicMock()
        mock_decryptor.decrypt_snmpv3_trap.return_value = ('80001f88', {'varbinds': []})
        mock_decryptor.convert_to_snmpv2c.return_value = b'\x30\x10...'
        
        snmpv3_decryption._snmpv3_decryptor = mock_decryptor
        
        result = snmpv3_decryption.decrypt_and_convert_trap(b'\x30\x00', community="test")
        
        assert result is not None
        mock_decryptor.decrypt_snmpv3_trap.assert_called_once()
        mock_decryptor.convert_to_snmpv2c.assert_called_once()
        
        # Cleanup
        snmpv3_decryption._snmpv3_decryptor = None


# =============================================================================
# TEST CLASS: ERROR HANDLING
# =============================================================================

class TestErrorHandling:
    """Test error handling in SNMPv3 pipeline."""
    
    def test_malformed_message_handled(self):
        """Malformed messages don't crash."""
        from trapninja.snmpv3_decryption import extract_engine_id_from_bytes
        
        malformed_messages = [
            b'',
            b'\x00',
            b'\x30',  # Incomplete SEQUENCE
            b'\x30\x00',  # Empty SEQUENCE
            b'\x30\xff' + b'\x00' * 10,  # Invalid length encoding
            bytes([random_byte for random_byte in range(50)]),  # Random bytes
        ]
        
        for msg in malformed_messages:
            # Should not raise
            result = extract_engine_id_from_bytes(msg)
            # Result is either None or a valid string
            assert result is None or isinstance(result, str)
    
    def test_invalid_usm_handled(self):
        """Invalid USM parameters don't crash."""
        from trapninja.snmpv3_decryption import SNMPv3Decryptor
        
        mock_store = MagicMock()
        decryptor = SNMPv3Decryptor(mock_store)
        
        invalid_usm = [
            b'',
            b'\x30\x00',  # Empty SEQUENCE
            b'\x04\x05hello',  # Not a SEQUENCE
            b'\x30\x05\x04\x03abc',  # Truncated
        ]
        
        for usm in invalid_usm:
            # Should not raise
            result = decryptor._parse_usm_params(usm)
            assert result is None
    
    def test_conversion_failure_returns_none(self):
        """Conversion failure returns None, doesn't crash."""
        from trapninja.snmpv3_decryption import SNMPv3Decryptor
        
        mock_store = MagicMock()
        decryptor = SNMPv3Decryptor(mock_store)
        
        # Invalid trap data
        invalid_data = {
            'version': 'v3',
            'request_id': 'not_an_int',  # Should be int
            'varbinds': 'not_a_list'  # Should be list
        }
        
        # Should handle gracefully
        result = decryptor.convert_to_snmpv2c(invalid_data)
        
        # May return None or a message
        assert result is None or isinstance(result, bytes)


# =============================================================================
# TEST CLASS: PYSNMP/CRYPTO AVAILABILITY
# =============================================================================

class TestDependencyAvailability:
    """Test handling of optional dependencies."""
    
    def test_pysnmp_availability_flag(self):
        """PYSNMP_AVAILABLE flag is boolean."""
        from trapninja import snmpv3_decryption
        
        assert isinstance(snmpv3_decryption.PYSNMP_AVAILABLE, bool)
    
    def test_crypto_availability_flag(self):
        """CRYPTO_AVAILABLE flag is boolean."""
        from trapninja import snmpv3_decryption
        
        assert isinstance(snmpv3_decryption.CRYPTO_AVAILABLE, bool)
    
    def test_version_detected(self):
        """pysnmp version is detected if available."""
        from trapninja import snmpv3_decryption
        
        if snmpv3_decryption.PYSNMP_AVAILABLE:
            assert snmpv3_decryption.PYSNMP_VERSION is not None
