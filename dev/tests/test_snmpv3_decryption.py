#!/usr/bin/env python3
"""
TrapNinja Test Suite - SNMPv3 Decryption Module Tests

Tests for trapninja.snmpv3_decryption module - decryption and conversion.

Assumptions:
- SNMPv3 messages use BER encoding
- Engine ID is extracted from msgSecurityParameters
- Key localization uses PBKDF2-style algorithm
- AES uses CFB mode with 128-bit segments
- DES uses CBC mode
- Converted SNMPv2c messages have version=1 and tag 0xa7 for trap PDU

Author: TrapNinja Team
"""

import hashlib
import struct
import pytest
from unittest.mock import MagicMock, patch


def _build_snmpv3_message(engine_id: bytes, username: bytes = b'') -> bytes:
    """
    Helper to build a valid SNMPv3 message structure.
    
    SNMPv3 message structure:
    SEQUENCE {
        INTEGER version (3)
        SEQUENCE msgGlobalData { msgID, msgMaxSize, msgFlags, msgSecurityModel }
        OCTET STRING msgSecurityParameters (contains USM SEQUENCE)
        SEQUENCE or OCTET STRING msgData
    }
    """
    # Build USM security parameters SEQUENCE
    # SEQUENCE { engineID, engineBoots, engineTime, username, authParams, privParams }
    usm_content = (
        b'\x04' + bytes([len(engine_id)]) + engine_id +  # OCTET STRING engineID
        b'\x02\x01\x00' +  # INTEGER engineBoots = 0
        b'\x02\x01\x00' +  # INTEGER engineTime = 0
        b'\x04' + bytes([len(username)]) + username +  # OCTET STRING username
        b'\x04\x00' +  # OCTET STRING authParams (empty)
        b'\x04\x00'   # OCTET STRING privParams (empty)
    )
    usm = b'\x30' + bytes([len(usm_content)]) + usm_content
    
    # Wrap USM in OCTET STRING for msgSecurityParameters
    usm_wrapped = b'\x04' + bytes([len(usm)]) + usm
    
    # Build msgGlobalData SEQUENCE
    # { msgID=1, msgMaxSize=1500, msgFlags=0x00, msgSecurityModel=3 }
    global_data_content = (
        b'\x02\x01\x01' +     # INTEGER msgID = 1
        b'\x02\x02\x05\xdc' +  # INTEGER msgMaxSize = 1500
        b'\x04\x01\x00' +     # OCTET STRING msgFlags = 0x00
        b'\x02\x01\x03'       # INTEGER msgSecurityModel = 3 (USM)
    )
    global_data = b'\x30' + bytes([len(global_data_content)]) + global_data_content
    
    # Build msgData (empty ScopedPDU for testing)
    msg_data = b'\x30\x00'
    
    # Build complete message content
    content = (
        b'\x02\x01\x03' +  # INTEGER version = 3
        global_data +
        usm_wrapped +
        msg_data
    )
    
    # Wrap in outer SEQUENCE
    return b'\x30' + bytes([len(content)]) + content


class TestExtractEngineIdFromBytes:
    """Tests for extract_engine_id_from_bytes function."""

    def test_extracts_valid_engine_id(self):
        """Test extraction of engine ID from valid SNMPv3 message."""
        from trapninja.snmpv3_decryption import extract_engine_id_from_bytes
        
        engine_id = bytes.fromhex('80001234abcdef')
        message = _build_snmpv3_message(engine_id)
        
        result = extract_engine_id_from_bytes(message)
        
        assert result == '80001234abcdef'

    def test_extracts_short_engine_id(self):
        """Test extraction of short engine ID."""
        from trapninja.snmpv3_decryption import extract_engine_id_from_bytes
        
        engine_id = bytes.fromhex('8000')
        message = _build_snmpv3_message(engine_id)
        
        result = extract_engine_id_from_bytes(message)
        
        assert result == '8000'

    def test_returns_none_for_short_message(self):
        """Test returns None for too short message."""
        from trapninja.snmpv3_decryption import extract_engine_id_from_bytes
        
        result = extract_engine_id_from_bytes(b'\x30\x02\x02')
        
        assert result is None

    def test_returns_none_for_invalid_sequence(self):
        """Test returns None for invalid SEQUENCE tag."""
        from trapninja.snmpv3_decryption import extract_engine_id_from_bytes
        
        result = extract_engine_id_from_bytes(b'\x31\x50\x02\x01\x03')
        
        assert result is None

    def test_returns_none_for_non_v3_message(self):
        """Test returns None for non-SNMPv3 message."""
        from trapninja.snmpv3_decryption import extract_engine_id_from_bytes
        
        # SNMPv2c message (version = 1)
        message = b'\x30\x10\x02\x01\x01\x04\x06public'
        
        result = extract_engine_id_from_bytes(message)
        
        assert result is None

    def test_returns_none_for_empty_message(self):
        """Test returns None for empty message."""
        from trapninja.snmpv3_decryption import extract_engine_id_from_bytes
        
        result = extract_engine_id_from_bytes(b'')
        
        assert result is None


class TestExtractUsernameFromBytes:
    """Tests for extract_username_from_bytes function."""

    def test_extracts_username(self):
        """Test extraction of username from USM parameters."""
        from trapninja.snmpv3_decryption import extract_username_from_bytes
        
        engine_id = bytes.fromhex('80001234')
        username = b'testuser'
        message = _build_snmpv3_message(engine_id, username)
        
        result = extract_username_from_bytes(message)
        
        assert result == 'testuser'

    def test_extracts_empty_username(self):
        """Test extraction of empty username."""
        from trapninja.snmpv3_decryption import extract_username_from_bytes
        
        engine_id = bytes.fromhex('80001234')
        message = _build_snmpv3_message(engine_id, b'')
        
        result = extract_username_from_bytes(message)
        
        assert result == ''

    def test_returns_none_for_invalid_message(self):
        """Test returns None for invalid message."""
        from trapninja.snmpv3_decryption import extract_username_from_bytes
        
        result = extract_username_from_bytes(b'invalid')
        
        assert result is None

    def test_returns_none_for_v2c_message(self):
        """Test returns None for SNMPv2c message."""
        from trapninja.snmpv3_decryption import extract_username_from_bytes
        
        message = b'\x30\x10\x02\x01\x01\x04\x06public'
        
        result = extract_username_from_bytes(message)
        
        assert result is None


class TestParseBerLength:
    """Tests for _parse_ber_length function."""

    def test_short_form_length(self):
        """Test parsing short form length."""
        from trapninja.snmpv3_decryption import _parse_ber_length
        
        data = bytes([0x50, 0x02, 0x01])  # Length 0x50 = 80
        
        length, new_idx = _parse_ber_length(data, 0)
        
        assert length == 0x50
        assert new_idx == 1

    def test_long_form_one_byte(self):
        """Test parsing long form with one length byte."""
        from trapninja.snmpv3_decryption import _parse_ber_length
        
        data = bytes([0x81, 0x80, 0x02])  # Long form, 1 byte, value 128
        
        length, new_idx = _parse_ber_length(data, 0)
        
        assert length == 128
        assert new_idx == 2

    def test_long_form_two_bytes(self):
        """Test parsing long form with two length bytes."""
        from trapninja.snmpv3_decryption import _parse_ber_length
        
        data = bytes([0x82, 0x01, 0x00, 0x02])  # Long form, 2 bytes, value 256
        
        length, new_idx = _parse_ber_length(data, 0)
        
        assert length == 256
        assert new_idx == 3


class TestLocalizeKey:
    """Tests for _localize_key function."""

    def test_key_derivation_md5(self):
        """Test key derivation with MD5."""
        from trapninja.snmpv3_decryption import _localize_key
        
        passphrase = "authpassword"
        engine_id = bytes.fromhex('80001234')
        
        key = _localize_key(passphrase, engine_id, 'MD5')
        
        assert len(key) == 16  # MD5 produces 16 bytes

    def test_key_derivation_sha1(self):
        """Test key derivation with SHA1."""
        from trapninja.snmpv3_decryption import _localize_key
        
        passphrase = "authpassword"
        engine_id = bytes.fromhex('80001234')
        
        key = _localize_key(passphrase, engine_id, 'SHA')
        
        assert len(key) == 20  # SHA1 produces 20 bytes

    def test_key_derivation_sha256(self):
        """Test key derivation with SHA256."""
        from trapninja.snmpv3_decryption import _localize_key
        
        passphrase = "authpassword"
        engine_id = bytes.fromhex('80001234')
        
        key = _localize_key(passphrase, engine_id, 'SHA256')
        
        assert len(key) == 32  # SHA256 produces 32 bytes

    def test_key_derivation_deterministic(self):
        """Test key derivation is deterministic."""
        from trapninja.snmpv3_decryption import _localize_key
        
        passphrase = "authpassword"
        engine_id = bytes.fromhex('80001234')
        
        key1 = _localize_key(passphrase, engine_id, 'SHA')
        key2 = _localize_key(passphrase, engine_id, 'SHA')
        
        assert key1 == key2

    def test_different_engines_produce_different_keys(self):
        """Test different engine IDs produce different keys."""
        from trapninja.snmpv3_decryption import _localize_key
        
        passphrase = "authpassword"
        
        key1 = _localize_key(passphrase, bytes.fromhex('80001234'), 'SHA')
        key2 = _localize_key(passphrase, bytes.fromhex('80005678'), 'SHA')
        
        assert key1 != key2


class TestSNMPv3Decryptor:
    """Tests for SNMPv3Decryptor class."""

    @pytest.fixture
    def decryptor(self, tmp_path):
        """Create a decryptor with mock credential store."""
        from trapninja.snmpv3_decryption import SNMPv3Decryptor
        from trapninja.snmpv3_credentials import SNMPv3CredentialStore
        
        store = SNMPv3CredentialStore(str(tmp_path / "creds.json"))
        return SNMPv3Decryptor(store)

    def test_initialization(self, decryptor):
        """Test decryptor initializes correctly."""
        assert decryptor.credential_store is not None

    def test_decrypt_returns_none_for_no_credentials(self, decryptor):
        """Test decrypt returns None when no credentials found."""
        engine_id = bytes.fromhex('80001234')
        message = _build_snmpv3_message(engine_id)
        
        result = decryptor.decrypt_snmpv3_trap(message, engine_id='80001234')
        
        assert result is None


class TestSNMPv3DecryptorOIDEncoding:
    """Tests for OID encoding in SNMPv3Decryptor."""

    @pytest.fixture
    def decryptor(self, tmp_path):
        """Create a decryptor."""
        from trapninja.snmpv3_decryption import SNMPv3Decryptor
        from trapninja.snmpv3_credentials import SNMPv3CredentialStore
        
        store = SNMPv3CredentialStore(str(tmp_path / "creds.json"))
        return SNMPv3Decryptor(store)

    def test_encode_simple_oid(self, decryptor):
        """Test encoding simple OID."""
        oid = "1.3.6.1"
        
        encoded = decryptor._encode_oid(oid)
        
        # Should start with 0x06 (OID tag)
        assert encoded[0] == 0x06
        # First subidentifier: 1*40 + 3 = 43
        assert encoded[2] == 43

    def test_encode_enterprise_oid(self, decryptor):
        """Test encoding enterprise OID."""
        oid = "1.3.6.1.4.1.8072"
        
        encoded = decryptor._encode_oid(oid)
        
        assert encoded[0] == 0x06

    def test_encode_oid_with_large_component(self, decryptor):
        """Test encoding OID with component > 127."""
        oid = "1.3.6.1.4.1.8072"  # 8072 requires multi-byte encoding
        
        encoded = decryptor._encode_oid(oid)
        
        assert encoded[0] == 0x06

    def test_decode_oid_roundtrip(self, decryptor):
        """Test OID encode/decode roundtrip."""
        original = "1.3.6.1.4.1.9"
        
        encoded = decryptor._encode_oid(original)
        # Skip tag and length
        oid_bytes = encoded[2:]
        decoded = decryptor._decode_oid(oid_bytes)
        
        assert decoded == original


class TestSNMPv3DecryptorValueEncoding:
    """Tests for value encoding in SNMPv3Decryptor."""

    @pytest.fixture
    def decryptor(self, tmp_path):
        """Create a decryptor."""
        from trapninja.snmpv3_decryption import SNMPv3Decryptor
        from trapninja.snmpv3_credentials import SNMPv3CredentialStore
        
        store = SNMPv3CredentialStore(str(tmp_path / "creds.json"))
        return SNMPv3Decryptor(store)

    def test_encode_integer(self, decryptor):
        """Test encoding INTEGER value."""
        encoded = decryptor._encode_integer(42)
        
        assert encoded[0] == 0x02  # INTEGER tag
        # Value should decode to 42

    def test_encode_integer_zero(self, decryptor):
        """Test encoding zero INTEGER."""
        encoded = decryptor._encode_integer(0)
        
        assert encoded[0] == 0x02
        assert encoded[1] == 0x01  # Length 1
        assert encoded[2] == 0x00  # Value 0

    def test_encode_integer_negative(self, decryptor):
        """Test encoding negative INTEGER."""
        encoded = decryptor._encode_integer(-1)
        
        assert encoded[0] == 0x02

    def test_encode_octet_string(self, decryptor):
        """Test encoding OCTET STRING value."""
        encoded = decryptor._encode_value("test", "OctetString")
        
        assert encoded[0] == 0x04  # OCTET STRING tag

    def test_encode_ip_address(self, decryptor):
        """Test encoding IpAddress value."""
        encoded = decryptor._encode_value("192.168.1.1", "IpAddress")
        
        assert encoded[0] == 0x40  # IpAddress tag
        # Should be 4 bytes for IPv4

    def test_encode_counter32(self, decryptor):
        """Test encoding Counter32 value."""
        encoded = decryptor._encode_value(12345, "Counter32")
        
        assert encoded[0] == 0x41  # Counter32 tag

    def test_encode_gauge32(self, decryptor):
        """Test encoding Gauge32 value."""
        encoded = decryptor._encode_value(999, "Gauge32")
        
        assert encoded[0] == 0x42  # Gauge32 tag

    def test_encode_timeticks(self, decryptor):
        """Test encoding TimeTicks value."""
        encoded = decryptor._encode_value(100000, "TimeTicks")
        
        assert encoded[0] == 0x43  # TimeTicks tag

    def test_encode_counter64(self, decryptor):
        """Test encoding Counter64 value."""
        encoded = decryptor._encode_value(9999999999, "Counter64")
        
        assert encoded[0] == 0x46  # Counter64 tag

    def test_encode_null(self, decryptor):
        """Test encoding NULL value."""
        encoded = decryptor._encode_value(None, "Null")
        
        assert encoded[0] == 0x05  # NULL tag
        assert encoded[1] == 0x00  # Length 0


class TestSNMPv3DecryptorLengthEncoding:
    """Tests for BER length encoding in SNMPv3Decryptor."""

    @pytest.fixture
    def decryptor(self, tmp_path):
        """Create a decryptor."""
        from trapninja.snmpv3_decryption import SNMPv3Decryptor
        from trapninja.snmpv3_credentials import SNMPv3CredentialStore
        
        store = SNMPv3CredentialStore(str(tmp_path / "creds.json"))
        return SNMPv3Decryptor(store)

    def test_encode_short_form_length(self, decryptor):
        """Test encoding length < 128."""
        encoded = decryptor._encode_length(50)
        
        assert len(encoded) == 1
        assert encoded[0] == 50

    def test_encode_length_127(self, decryptor):
        """Test encoding length = 127 (boundary)."""
        encoded = decryptor._encode_length(127)
        
        assert len(encoded) == 1
        assert encoded[0] == 127

    def test_encode_long_form_one_byte(self, decryptor):
        """Test encoding length 128-255."""
        encoded = decryptor._encode_length(200)
        
        assert encoded[0] == 0x81  # Long form, 1 byte
        assert encoded[1] == 200

    def test_encode_long_form_two_bytes(self, decryptor):
        """Test encoding length 256-65535."""
        encoded = decryptor._encode_length(500)
        
        assert encoded[0] == 0x82  # Long form, 2 bytes
        assert (encoded[1] << 8) + encoded[2] == 500


class TestConvertToSNMPv2c:
    """Tests for convert_to_snmpv2c function."""

    @pytest.fixture
    def decryptor(self, tmp_path):
        """Create a decryptor."""
        from trapninja.snmpv3_decryption import SNMPv3Decryptor
        from trapninja.snmpv3_credentials import SNMPv3CredentialStore
        
        store = SNMPv3CredentialStore(str(tmp_path / "creds.json"))
        return SNMPv3Decryptor(store)

    def test_converts_empty_varbinds(self, decryptor):
        """Test conversion with empty varbinds."""
        trap_data = {
            'varbinds': [],
            'request_id': 12345
        }
        
        result = decryptor.convert_to_snmpv2c(trap_data)
        
        assert result is not None
        # Should be valid SNMPv2c structure
        assert result[0] == 0x30  # SEQUENCE

    def test_converts_with_varbinds(self, decryptor):
        """Test conversion with varbinds."""
        trap_data = {
            'varbinds': [
                {'oid': '1.3.6.1.2.1.1.3.0', 'value': 12345, 'type': 'TimeTicks'},
                {'oid': '1.3.6.1.6.3.1.1.4.1.0', 'value': '1.3.6.1.6.3.1.1.5.1', 'type': 'ObjectIdentifier'}
            ],
            'request_id': 99999
        }
        
        result = decryptor.convert_to_snmpv2c(trap_data)
        
        assert result is not None
        assert result[0] == 0x30  # SEQUENCE

    def test_sets_correct_version(self, decryptor):
        """Test converted message has SNMPv2c version."""
        trap_data = {
            'varbinds': [],
            'request_id': 1
        }
        
        result = decryptor.convert_to_snmpv2c(trap_data)
        
        # Find version field (after outer SEQUENCE)
        # Skip SEQUENCE tag and length
        idx = 2
        if result[1] & 0x80:
            idx += (result[1] & 0x7f) + 1
        
        assert result[idx] == 0x02  # INTEGER tag
        assert result[idx + 2] == 0x01  # Version 1 = SNMPv2c

    def test_sets_custom_community(self, decryptor):
        """Test custom community string is set."""
        trap_data = {
            'varbinds': [],
            'request_id': 1
        }
        
        result = decryptor.convert_to_snmpv2c(trap_data, community="private")
        
        assert result is not None
        assert b'private' in result

    def test_validates_output_message(self, decryptor):
        """Test output message passes validation."""
        trap_data = {
            'varbinds': [
                {'oid': '1.3.6.1.2.1.1.3.0', 'value': 100, 'type': 'TimeTicks'}
            ],
            'request_id': 12345
        }
        
        result = decryptor.convert_to_snmpv2c(trap_data)
        
        # Internal validation should pass
        is_valid = decryptor._validate_snmpv2c_message(result)
        assert is_valid is True


class TestGlobalDecryptor:
    """Tests for global decryptor functions."""

    def test_get_decryptor_returns_none_before_init(self):
        """Test get_snmpv3_decryptor returns None before initialization."""
        from trapninja import snmpv3_decryption
        
        # Reset global
        snmpv3_decryption._snmpv3_decryptor = None
        
        result = snmpv3_decryption.get_snmpv3_decryptor()
        
        assert result is None

    def test_initialize_creates_decryptor(self, tmp_path, monkeypatch):
        """Test initialize_snmpv3_decryptor creates instance."""
        from trapninja import snmpv3_decryption
        
        snmpv3_decryption._snmpv3_decryptor = None
        monkeypatch.setattr('trapninja.config.CONFIG_DIR', str(tmp_path))
        
        result = snmpv3_decryption.initialize_snmpv3_decryptor()
        
        if snmpv3_decryption.PYSNMP_AVAILABLE:
            assert result is not None
        else:
            assert result is None


class TestDecryptAndConvertTrap:
    """Tests for decrypt_and_convert_trap convenience function."""

    def test_returns_none_without_decryptor(self):
        """Test returns None when decryptor not initialized."""
        from trapninja import snmpv3_decryption
        
        snmpv3_decryption._snmpv3_decryptor = None
        
        result = snmpv3_decryption.decrypt_and_convert_trap(
            b'\x30\x50\x02\x01\x03',
            engine_id='80001234'
        )
        
        assert result is None


class TestModuleAvailabilityFlags:
    """Tests for module availability flags."""

    def test_pysnmp_available_flag_exists(self):
        """Test PYSNMP_AVAILABLE flag exists."""
        from trapninja.snmpv3_decryption import PYSNMP_AVAILABLE
        
        assert isinstance(PYSNMP_AVAILABLE, bool)

    def test_crypto_available_flag_exists(self):
        """Test CRYPTO_AVAILABLE flag exists."""
        from trapninja.snmpv3_decryption import CRYPTO_AVAILABLE
        
        assert isinstance(CRYPTO_AVAILABLE, bool)

    def test_pysnmp_version_exists(self):
        """Test PYSNMP_VERSION is set."""
        from trapninja.snmpv3_decryption import PYSNMP_VERSION
        
        # Either None (not installed) or a version string
        assert PYSNMP_VERSION is None or isinstance(PYSNMP_VERSION, str)
