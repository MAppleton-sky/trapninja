#!/usr/bin/env python3
"""
Tests for TrapNinja SNMPv3 Generator module.

Tests cover:
- TrapEvent dataclass creation and serialization
- VarBind encoding
- SNMPv3Generator message building
- Key localization and encryption
"""
import unittest
from unittest.mock import MagicMock, patch, PropertyMock
from dataclasses import asdict


# =============================================================================
# TEST FIXTURES
# =============================================================================

def _make_mock_user():
    """Create a mock SNMPv3User for testing."""
    user = MagicMock()
    user.username = 'testuser'
    user.auth_protocol = 'SHA256'
    user.auth_passphrase = 'authpass12345678'
    user.priv_protocol = 'AES128'
    user.priv_passphrase = 'privpass12345678'
    user.engine_id = '80001234567890abcdef'
    return user


def _make_mock_credential_store(users=None):
    """Create a mock credential store."""
    store = MagicMock()
    if users is None:
        users = [_make_mock_user()]
    store.get_users_for_engine.return_value = users
    store.get_engine_ids.return_value = ['80001234567890abcdef']
    return store


def _make_sample_trap_data():
    """Create sample trap data as returned by SNMPv3Decryptor."""
    return {
        'version': 'v3',
        'request_id': 12345,
        'context_name': '',
        'varbinds': [
            {
                'oid': '1.3.6.1.2.1.1.3.0',  # sysUpTime
                'value': 123456,
                'type': 'TimeTicks'
            },
            {
                'oid': '1.3.6.1.6.3.1.1.4.1.0',  # snmpTrapOID
                'value': '1.3.6.1.4.1.9.9.1.0.1',
                'type': 'ObjectIdentifier'
            },
            {
                'oid': '1.3.6.1.4.1.9.9.1.1.1.0',
                'value': 'Test alarm message',
                'type': 'OctetString'
            }
        ]
    }


# =============================================================================
# VARBIND TESTS
# =============================================================================

class TestVarBind(unittest.TestCase):
    """Tests for VarBind dataclass."""

    def test_varbind_creation(self):
        """VarBind can be created with oid, value, and type."""
        from trapninja.snmpv3_generator import VarBind
        
        vb = VarBind(
            oid='1.3.6.1.2.1.1.3.0',
            value=12345,
            value_type='TimeTicks'
        )
        
        self.assertEqual(vb.oid, '1.3.6.1.2.1.1.3.0')
        self.assertEqual(vb.value, 12345)
        self.assertEqual(vb.value_type, 'TimeTicks')

    def test_varbind_to_dict(self):
        """VarBind.to_dict() returns correct dictionary."""
        from trapninja.snmpv3_generator import VarBind
        
        vb = VarBind(oid='1.3.6.1.2.1.1.1.0', value='test', value_type='OctetString')
        d = vb.to_dict()
        
        self.assertEqual(d['oid'], '1.3.6.1.2.1.1.1.0')
        self.assertEqual(d['value'], 'test')
        self.assertEqual(d['value_type'], 'OctetString')

    def test_varbind_from_dict(self):
        """VarBind.from_dict() creates correct VarBind."""
        from trapninja.snmpv3_generator import VarBind
        
        d = {'oid': '1.3.6.1.2.1.1.1.0', 'value': 'test', 'value_type': 'OctetString'}
        vb = VarBind.from_dict(d)
        
        self.assertEqual(vb.oid, '1.3.6.1.2.1.1.1.0')
        self.assertEqual(vb.value, 'test')
        self.assertEqual(vb.value_type, 'OctetString')

    def test_varbind_from_dict_with_type_key(self):
        """VarBind.from_dict() handles 'type' key (from decryptor output)."""
        from trapninja.snmpv3_generator import VarBind
        
        # Decryptor returns 'type' not 'value_type'
        d = {'oid': '1.3.6.1.2.1.1.1.0', 'value': 42, 'type': 'Integer'}
        vb = VarBind.from_dict(d)
        
        self.assertEqual(vb.value_type, 'Integer')


# =============================================================================
# TRAP EVENT TESTS
# =============================================================================

class TestTrapEvent(unittest.TestCase):
    """Tests for TrapEvent dataclass."""

    def test_trap_event_creation(self):
        """TrapEvent can be created with required fields."""
        from trapninja.snmpv3_generator import TrapEvent, VarBind
        
        varbinds = [
            VarBind('1.3.6.1.2.1.1.3.0', 12345, 'TimeTicks'),
            VarBind('1.3.6.1.6.3.1.1.4.1.0', '1.3.6.1.4.1.9.0.1', 'ObjectIdentifier'),
        ]
        
        event = TrapEvent(
            source_ip='10.0.0.1',
            trap_oid='1.3.6.1.4.1.9.0.1',
            varbinds=varbinds,
            engine_id='80001234567890abcdef'
        )
        
        self.assertEqual(event.source_ip, '10.0.0.1')
        self.assertEqual(event.trap_oid, '1.3.6.1.4.1.9.0.1')
        self.assertEqual(len(event.varbinds), 2)
        self.assertEqual(event.engine_id, '80001234567890abcdef')
        self.assertEqual(event.original_version, 'v3')

    def test_trap_event_from_decrypted_trap(self):
        """TrapEvent.from_decrypted_trap() correctly parses decryptor output."""
        from trapninja.snmpv3_generator import TrapEvent
        
        trap_data = _make_sample_trap_data()
        
        event = TrapEvent.from_decrypted_trap(
            source_ip='192.168.1.100',
            engine_id='80001234567890abcdef',
            trap_data=trap_data
        )
        
        self.assertEqual(event.source_ip, '192.168.1.100')
        self.assertEqual(event.engine_id, '80001234567890abcdef')
        self.assertEqual(event.request_id, 12345)
        self.assertEqual(len(event.varbinds), 3)
        # Should extract trap OID from snmpTrapOID varbind
        self.assertEqual(event.trap_oid, '1.3.6.1.4.1.9.9.1.0.1')

    def test_trap_event_from_decrypted_trap_empty_varbinds(self):
        """TrapEvent handles empty varbinds list."""
        from trapninja.snmpv3_generator import TrapEvent
        
        trap_data = {'version': 'v3', 'request_id': 1, 'varbinds': []}
        
        event = TrapEvent.from_decrypted_trap(
            source_ip='10.0.0.1',
            engine_id='8000123456',
            trap_data=trap_data
        )
        
        self.assertEqual(len(event.varbinds), 0)
        self.assertEqual(event.trap_oid, '')


# =============================================================================
# SNMPV3 GENERATOR TESTS
# =============================================================================

class TestSNMPv3Generator(unittest.TestCase):
    """Tests for SNMPv3Generator class."""

    def test_generator_initialization(self):
        """SNMPv3Generator initializes with credential store."""
        from trapninja.snmpv3_generator import SNMPv3Generator
        
        store = _make_mock_credential_store()
        generator = SNMPv3Generator(store)
        
        self.assertEqual(generator.credential_store, store)

    def test_generator_returns_none_without_credentials(self):
        """Generator returns None when no credentials for engine ID."""
        from trapninja.snmpv3_generator import SNMPv3Generator, TrapEvent, VarBind, CRYPTO_AVAILABLE
        
        # Skip if crypto not available (would fail before credential check)
        if not CRYPTO_AVAILABLE:
            self.skipTest("pycryptodome not available")
        
        store = _make_mock_credential_store(users=[])
        generator = SNMPv3Generator(store)
        
        event = TrapEvent(
            source_ip='10.0.0.1',
            trap_oid='1.3.6.1.4.1.9.0.1',
            varbinds=[VarBind('1.3.6.1.2.1.1.3.0', 100, 'TimeTicks')],
            engine_id='80001234567890abcdef'
        )
        
        result = generator.generate(event)
        
        self.assertIsNone(result)
        store.get_users_for_engine.assert_called_once_with('80001234567890abcdef')

    @patch('trapninja.snmpv3_generator.CRYPTO_AVAILABLE', False)
    def test_generator_returns_none_without_crypto(self):
        """Generator returns None when pycryptodome not available."""
        from trapninja.snmpv3_generator import SNMPv3Generator, TrapEvent, VarBind
        
        store = _make_mock_credential_store()
        generator = SNMPv3Generator(store)
        
        event = TrapEvent(
            source_ip='10.0.0.1',
            trap_oid='1.3.6.1.4.1.9.0.1',
            varbinds=[VarBind('1.3.6.1.2.1.1.3.0', 100, 'TimeTicks')],
            engine_id='80001234567890abcdef'
        )
        
        result = generator.generate(event)
        
        self.assertIsNone(result)

    def test_generator_returns_bytes(self):
        """Generator returns bytes when credentials available."""
        from trapninja.snmpv3_generator import SNMPv3Generator, TrapEvent, VarBind, CRYPTO_AVAILABLE
        
        # Skip if crypto not available
        if not CRYPTO_AVAILABLE:
            self.skipTest("pycryptodome not available")
        
        store = _make_mock_credential_store()
        generator = SNMPv3Generator(store)
        
        event = TrapEvent(
            source_ip='10.0.0.1',
            trap_oid='1.3.6.1.4.1.9.0.1',
            varbinds=[
                VarBind('1.3.6.1.2.1.1.3.0', 100, 'TimeTicks'),
                VarBind('1.3.6.1.6.3.1.1.4.1.0', '1.3.6.1.4.1.9.0.1', 'ObjectIdentifier'),
            ],
            engine_id='80001234567890abcdef',
            request_id=12345
        )
        
        result = generator.generate(event)
        
        self.assertIsInstance(result, bytes)
        self.assertGreater(len(result), 0)
        # Should start with SEQUENCE tag
        self.assertEqual(result[0], 0x30)

    def test_generator_selects_specific_user(self):
        """Generator uses specific username when provided."""
        from trapninja.snmpv3_generator import SNMPv3Generator, TrapEvent, VarBind
        
        user1 = _make_mock_user()
        user1.username = 'user1'
        user2 = _make_mock_user()
        user2.username = 'user2'
        
        store = _make_mock_credential_store(users=[user1, user2])
        generator = SNMPv3Generator(store)
        
        event = TrapEvent(
            source_ip='10.0.0.1',
            trap_oid='1.3.6.1.4.1.9.0.1',
            varbinds=[],
            engine_id='80001234567890abcdef'
        )
        
        # Should not raise - just returns None if user not found
        result = generator.generate(event, username='nonexistent')
        self.assertIsNone(result)


# =============================================================================
# ASN.1 ENCODING TESTS
# =============================================================================

class TestASN1Encoding(unittest.TestCase):
    """Tests for ASN.1 BER encoding methods."""

    def test_encode_integer_zero(self):
        """Integer encoding handles zero correctly."""
        from trapninja.snmpv3_generator import SNMPv3Generator
        
        store = _make_mock_credential_store()
        gen = SNMPv3Generator(store)
        
        result = gen._encode_integer(0)
        self.assertEqual(result, b'\x02\x01\x00')

    def test_encode_integer_small(self):
        """Integer encoding handles small positive numbers."""
        from trapninja.snmpv3_generator import SNMPv3Generator
        
        store = _make_mock_credential_store()
        gen = SNMPv3Generator(store)
        
        result = gen._encode_integer(3)  # SNMPv3 version
        self.assertEqual(result, b'\x02\x01\x03')

    def test_encode_integer_large(self):
        """Integer encoding handles larger numbers with proper length."""
        from trapninja.snmpv3_generator import SNMPv3Generator
        
        store = _make_mock_credential_store()
        gen = SNMPv3Generator(store)
        
        result = gen._encode_integer(256)
        # 256 = 0x0100, needs 2 bytes
        self.assertEqual(result[0], 0x02)  # INTEGER tag
        self.assertEqual(result[1], 0x02)  # length 2

    def test_encode_octet_string_empty(self):
        """Octet string encoding handles empty bytes."""
        from trapninja.snmpv3_generator import SNMPv3Generator
        
        store = _make_mock_credential_store()
        gen = SNMPv3Generator(store)
        
        result = gen._encode_octet_string(b'')
        self.assertEqual(result, b'\x04\x00')

    def test_encode_octet_string_short(self):
        """Octet string encoding handles short strings."""
        from trapninja.snmpv3_generator import SNMPv3Generator
        
        store = _make_mock_credential_store()
        gen = SNMPv3Generator(store)
        
        result = gen._encode_octet_string(b'test')
        self.assertEqual(result, b'\x04\x04test')

    def test_encode_oid_simple(self):
        """OID encoding handles simple OIDs."""
        from trapninja.snmpv3_generator import SNMPv3Generator
        
        store = _make_mock_credential_store()
        gen = SNMPv3Generator(store)
        
        # 1.3 encodes as 1*40+3 = 43 = 0x2B
        result = gen._encode_oid('1.3.6.1.2.1.1.3.0')
        self.assertEqual(result[0], 0x06)  # OID tag
        # First byte of OID content should be 43 (1*40+3)
        self.assertEqual(result[2], 0x2B)

    def test_encode_sequence(self):
        """Sequence encoding wraps content correctly."""
        from trapninja.snmpv3_generator import SNMPv3Generator
        
        store = _make_mock_credential_store()
        gen = SNMPv3Generator(store)
        
        content = b'\x02\x01\x03'  # INTEGER 3
        result = gen._encode_sequence(content)
        
        self.assertEqual(result[0], 0x30)  # SEQUENCE tag
        self.assertEqual(result[1], 3)  # length
        self.assertEqual(result[2:], content)

    def test_encode_ip_address(self):
        """IP address encoding produces correct bytes."""
        from trapninja.snmpv3_generator import SNMPv3Generator
        
        store = _make_mock_credential_store()
        gen = SNMPv3Generator(store)
        
        result = gen._encode_ip_address('192.168.1.1')
        self.assertEqual(result, b'\x40\x04\xc0\xa8\x01\x01')


# =============================================================================
# KEY LOCALIZATION TESTS
# =============================================================================

class TestKeyLocalization(unittest.TestCase):
    """Tests for SNMPv3 key localization."""

    def test_localize_key_sha256(self):
        """Key localization with SHA256 produces correct length key."""
        from trapninja.snmpv3_generator import SNMPv3Generator
        
        store = _make_mock_credential_store()
        gen = SNMPv3Generator(store)
        
        engine_id = bytes.fromhex('80001234567890abcdef')
        key = gen._localize_key('testpassphrase', engine_id, 'SHA256')
        
        # SHA256 produces 32-byte digest
        self.assertEqual(len(key), 32)

    def test_localize_key_sha512(self):
        """Key localization with SHA512 produces correct length key."""
        from trapninja.snmpv3_generator import SNMPv3Generator
        
        store = _make_mock_credential_store()
        gen = SNMPv3Generator(store)
        
        engine_id = bytes.fromhex('80001234567890abcdef')
        key = gen._localize_key('testpassphrase', engine_id, 'SHA512')
        
        # SHA512 produces 64-byte digest
        self.assertEqual(len(key), 64)

    def test_localize_key_md5(self):
        """Key localization with MD5 produces correct length key."""
        from trapninja.snmpv3_generator import SNMPv3Generator
        
        store = _make_mock_credential_store()
        gen = SNMPv3Generator(store)
        
        engine_id = bytes.fromhex('80001234567890abcdef')
        key = gen._localize_key('testpassphrase', engine_id, 'MD5')
        
        # MD5 produces 16-byte digest
        self.assertEqual(len(key), 16)


if __name__ == '__main__':
    unittest.main()
