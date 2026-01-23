#!/usr/bin/env python3
"""
TrapNinja Test Suite - SNMPv3 Credentials Module Tests

Tests for trapninja.snmpv3_credentials module - encrypted credential management.

Assumptions:
- Credentials are encrypted using Fernet (AES-128-CBC)
- Key derivation uses PBKDF2 with 100,000 iterations
- Engine ID is used as the basis for encryption key
- File permissions are set to 0o600 (owner read/write only)
- Audit logging captures all credential operations
- Passphrases must be at least 8 characters

Author: TrapNinja Team
"""

import os
import json
import pytest
from unittest.mock import MagicMock, patch, mock_open
from dataclasses import asdict


class TestSNMPv3User:
    """Tests for SNMPv3User dataclass."""

    def test_user_creation(self):
        """Test SNMPv3User can be created with valid data."""
        from trapninja.snmpv3_credentials import SNMPv3User
        
        user = SNMPv3User(
            username="testuser",
            auth_protocol="SHA",
            auth_passphrase="authpass123",
            priv_protocol="AES128",
            priv_passphrase="privpass123",
            engine_id="80001234"
        )
        
        assert user.username == "testuser"
        assert user.auth_protocol == "SHA"
        assert user.priv_protocol == "AES128"
        assert user.engine_id == "80001234"

    def test_user_to_dict(self):
        """Test SNMPv3User to_dict method."""
        from trapninja.snmpv3_credentials import SNMPv3User
        
        user = SNMPv3User(
            username="testuser",
            auth_protocol="SHA",
            auth_passphrase="authpass123",
            priv_protocol="AES128",
            priv_passphrase="privpass123",
            engine_id="80001234"
        )
        
        result = user.to_dict()
        
        assert isinstance(result, dict)
        assert result['username'] == "testuser"
        assert result['auth_protocol'] == "SHA"

    def test_user_from_dict(self):
        """Test SNMPv3User from_dict class method."""
        from trapninja.snmpv3_credentials import SNMPv3User
        
        data = {
            'username': 'testuser',
            'auth_protocol': 'SHA',
            'auth_passphrase': 'authpass123',
            'priv_protocol': 'AES128',
            'priv_passphrase': 'privpass123',
            'engine_id': '80001234'
        }
        
        user = SNMPv3User.from_dict(data)
        
        assert user.username == "testuser"
        assert user.engine_id == "80001234"


class TestSNMPv3UserValidation:
    """Tests for SNMPv3User.validate method."""

    def test_valid_user(self):
        """Test validation passes for valid user."""
        from trapninja.snmpv3_credentials import SNMPv3User
        
        user = SNMPv3User(
            username="testuser",
            auth_protocol="SHA",
            auth_passphrase="authpass123",
            priv_protocol="AES128",
            priv_passphrase="privpass123",
            engine_id="80001234"
        )
        
        is_valid, error = user.validate()
        
        assert is_valid is True
        assert error == ""

    def test_empty_username(self):
        """Test validation fails for empty username."""
        from trapninja.snmpv3_credentials import SNMPv3User
        
        user = SNMPv3User(
            username="",
            auth_protocol="SHA",
            auth_passphrase="authpass123",
            priv_protocol="AES128",
            priv_passphrase="privpass123",
            engine_id="80001234"
        )
        
        is_valid, error = user.validate()
        
        assert is_valid is False
        assert "Username" in error

    def test_username_too_long(self):
        """Test validation fails for username > 32 chars."""
        from trapninja.snmpv3_credentials import SNMPv3User
        
        user = SNMPv3User(
            username="a" * 33,
            auth_protocol="SHA",
            auth_passphrase="authpass123",
            priv_protocol="AES128",
            priv_passphrase="privpass123",
            engine_id="80001234"
        )
        
        is_valid, error = user.validate()
        
        assert is_valid is False
        assert "Username" in error

    @pytest.mark.parametrize("protocol", [
        "MD5", "SHA", "SHA224", "SHA256", "SHA384", "SHA512", "NONE"
    ])
    def test_valid_auth_protocols(self, protocol):
        """Test validation accepts valid auth protocols."""
        from trapninja.snmpv3_credentials import SNMPv3User
        
        passphrase = "authpass123" if protocol != "NONE" else ""
        
        user = SNMPv3User(
            username="testuser",
            auth_protocol=protocol,
            auth_passphrase=passphrase,
            priv_protocol="NONE",
            priv_passphrase="",
            engine_id="80001234"
        )
        
        is_valid, error = user.validate()
        
        assert is_valid is True, f"Protocol {protocol} should be valid: {error}"

    def test_invalid_auth_protocol(self):
        """Test validation fails for invalid auth protocol."""
        from trapninja.snmpv3_credentials import SNMPv3User
        
        user = SNMPv3User(
            username="testuser",
            auth_protocol="INVALID",
            auth_passphrase="authpass123",
            priv_protocol="AES128",
            priv_passphrase="privpass123",
            engine_id="80001234"
        )
        
        is_valid, error = user.validate()
        
        assert is_valid is False
        assert "auth protocol" in error.lower()

    @pytest.mark.parametrize("protocol", [
        "DES", "3DES", "AES128", "AES192", "AES256", "NONE"
    ])
    def test_valid_priv_protocols(self, protocol):
        """Test validation accepts valid priv protocols."""
        from trapninja.snmpv3_credentials import SNMPv3User
        
        passphrase = "privpass123" if protocol != "NONE" else ""
        
        user = SNMPv3User(
            username="testuser",
            auth_protocol="SHA",
            auth_passphrase="authpass123",
            priv_protocol=protocol,
            priv_passphrase=passphrase,
            engine_id="80001234"
        )
        
        is_valid, error = user.validate()
        
        assert is_valid is True, f"Protocol {protocol} should be valid: {error}"

    def test_invalid_priv_protocol(self):
        """Test validation fails for invalid priv protocol."""
        from trapninja.snmpv3_credentials import SNMPv3User
        
        user = SNMPv3User(
            username="testuser",
            auth_protocol="SHA",
            auth_passphrase="authpass123",
            priv_protocol="INVALID",
            priv_passphrase="privpass123",
            engine_id="80001234"
        )
        
        is_valid, error = user.validate()
        
        assert is_valid is False
        assert "priv protocol" in error.lower()

    def test_auth_passphrase_too_short(self):
        """Test validation fails for short auth passphrase."""
        from trapninja.snmpv3_credentials import SNMPv3User
        
        user = SNMPv3User(
            username="testuser",
            auth_protocol="SHA",
            auth_passphrase="short",  # < 8 chars
            priv_protocol="AES128",
            priv_passphrase="privpass123",
            engine_id="80001234"
        )
        
        is_valid, error = user.validate()
        
        assert is_valid is False
        assert "8 characters" in error

    def test_priv_passphrase_too_short(self):
        """Test validation fails for short priv passphrase."""
        from trapninja.snmpv3_credentials import SNMPv3User
        
        user = SNMPv3User(
            username="testuser",
            auth_protocol="SHA",
            auth_passphrase="authpass123",
            priv_protocol="AES128",
            priv_passphrase="short",  # < 8 chars
            engine_id="80001234"
        )
        
        is_valid, error = user.validate()
        
        assert is_valid is False
        assert "8 characters" in error

    def test_empty_engine_id(self):
        """Test validation fails for empty engine ID."""
        from trapninja.snmpv3_credentials import SNMPv3User
        
        user = SNMPv3User(
            username="testuser",
            auth_protocol="SHA",
            auth_passphrase="authpass123",
            priv_protocol="AES128",
            priv_passphrase="privpass123",
            engine_id=""
        )
        
        is_valid, error = user.validate()
        
        assert is_valid is False
        assert "Engine ID" in error

    def test_invalid_engine_id_hex(self):
        """Test validation fails for non-hex engine ID."""
        from trapninja.snmpv3_credentials import SNMPv3User
        
        user = SNMPv3User(
            username="testuser",
            auth_protocol="SHA",
            auth_passphrase="authpass123",
            priv_protocol="AES128",
            priv_passphrase="privpass123",
            engine_id="not-hex-value"
        )
        
        is_valid, error = user.validate()
        
        assert is_valid is False
        assert "hexadecimal" in error.lower()

    def test_noauth_allows_empty_passphrase(self):
        """Test NONE auth protocol allows empty passphrase."""
        from trapninja.snmpv3_credentials import SNMPv3User
        
        user = SNMPv3User(
            username="testuser",
            auth_protocol="NONE",
            auth_passphrase="",
            priv_protocol="NONE",
            priv_passphrase="",
            engine_id="80001234"
        )
        
        is_valid, error = user.validate()
        
        assert is_valid is True


class TestSNMPv3CredentialStore:
    """Tests for SNMPv3CredentialStore class."""

    @pytest.fixture
    def store(self, tmp_path):
        """Create a credential store with temp file."""
        from trapninja.snmpv3_credentials import SNMPv3CredentialStore
        
        cred_file = tmp_path / "credentials.json"
        return SNMPv3CredentialStore(str(cred_file))

    @pytest.fixture
    def valid_user(self):
        """Create a valid SNMPv3User."""
        from trapninja.snmpv3_credentials import SNMPv3User
        
        return SNMPv3User(
            username="testuser",
            auth_protocol="SHA",
            auth_passphrase="authpass123",
            priv_protocol="AES128",
            priv_passphrase="privpass123",
            engine_id="80001234abcd"
        )

    def test_store_initialization(self, tmp_path):
        """Test store initializes correctly."""
        from trapninja.snmpv3_credentials import SNMPv3CredentialStore
        
        cred_file = tmp_path / "subdir" / "credentials.json"
        store = SNMPv3CredentialStore(str(cred_file))
        
        assert store.credentials_file == str(cred_file)
        assert store.credentials == {}
        # Directory should be created
        assert cred_file.parent.exists()

    def test_add_user_success(self, store, valid_user):
        """Test adding a valid user."""
        success, message = store.add_user(valid_user)
        
        assert success is True
        assert "Added" in message or "Updated" in message

    def test_add_user_stores_credentials(self, store, valid_user):
        """Test added user is stored in memory."""
        store.add_user(valid_user)
        
        engine_id = valid_user.engine_id.lower()
        assert engine_id in store.credentials
        assert valid_user.username in store.credentials[engine_id]

    def test_add_user_normalizes_engine_id(self, store, valid_user):
        """Test engine ID is normalized to lowercase."""
        valid_user.engine_id = "80001234ABCD"  # Uppercase
        
        store.add_user(valid_user)
        
        assert "80001234abcd" in store.credentials
        assert "80001234ABCD" not in store.credentials

    def test_add_user_invalid_fails(self, store):
        """Test adding invalid user fails."""
        from trapninja.snmpv3_credentials import SNMPv3User
        
        invalid_user = SNMPv3User(
            username="",  # Invalid
            auth_protocol="SHA",
            auth_passphrase="authpass123",
            priv_protocol="AES128",
            priv_passphrase="privpass123",
            engine_id="80001234"
        )
        
        success, message = store.add_user(invalid_user)
        
        assert success is False

    def test_add_user_creates_file(self, store, valid_user, tmp_path):
        """Test adding user creates credentials file."""
        store.add_user(valid_user)
        
        cred_file = tmp_path / "credentials.json"
        # File is created in store's credentials_file path
        assert os.path.exists(store.credentials_file)

    def test_remove_user_success(self, store, valid_user):
        """Test removing existing user."""
        store.add_user(valid_user)
        
        success, message = store.remove_user(
            valid_user.engine_id,
            valid_user.username
        )
        
        assert success is True
        assert "Removed" in message

    def test_remove_user_not_found(self, store):
        """Test removing non-existent user."""
        success, message = store.remove_user("80001234", "nonexistent")
        
        assert success is False

    def test_remove_user_cleans_empty_engine(self, store, valid_user):
        """Test removing last user for engine removes engine entry."""
        store.add_user(valid_user)
        engine_id = valid_user.engine_id.lower()
        
        store.remove_user(valid_user.engine_id, valid_user.username)
        
        assert engine_id not in store.credentials

    def test_get_user_success(self, store, valid_user):
        """Test getting existing user."""
        store.add_user(valid_user)
        
        result = store.get_user(valid_user.engine_id, valid_user.username)
        
        assert result is not None
        assert result.username == valid_user.username

    def test_get_user_not_found(self, store):
        """Test getting non-existent user."""
        result = store.get_user("80001234", "nonexistent")
        
        assert result is None

    def test_get_user_case_insensitive_engine(self, store, valid_user):
        """Test get_user normalizes engine ID case."""
        valid_user.engine_id = "80001234abcd"
        store.add_user(valid_user)
        
        # Query with uppercase
        result = store.get_user("80001234ABCD", valid_user.username)
        
        assert result is not None

    def test_get_users_for_engine(self, store, valid_user):
        """Test getting all users for an engine."""
        from trapninja.snmpv3_credentials import SNMPv3User
        
        user1 = valid_user
        user2 = SNMPv3User(
            username="user2",
            auth_protocol="SHA",
            auth_passphrase="authpass123",
            priv_protocol="AES128",
            priv_passphrase="privpass123",
            engine_id=valid_user.engine_id
        )
        
        store.add_user(user1)
        store.add_user(user2)
        
        users = store.get_users_for_engine(valid_user.engine_id)
        
        assert len(users) == 2

    def test_get_users_for_engine_empty(self, store):
        """Test getting users for non-existent engine."""
        users = store.get_users_for_engine("nonexistent")
        
        assert users == []

    def test_list_all_users(self, store, valid_user):
        """Test listing all users."""
        store.add_user(valid_user)
        
        result = store.list_all_users()
        
        assert len(result) == 1
        assert result[0]['username'] == valid_user.username
        # Passphrases should be masked
        assert result[0]['auth_passphrase'] == '***'
        assert result[0]['priv_passphrase'] == '***'

    def test_get_engine_ids(self, store, valid_user):
        """Test getting list of engine IDs."""
        from trapninja.snmpv3_credentials import SNMPv3User
        
        user1 = valid_user
        user2 = SNMPv3User(
            username="user2",
            auth_protocol="SHA",
            auth_passphrase="authpass123",
            priv_protocol="AES128",
            priv_passphrase="privpass123",
            engine_id="aaaa1111"
        )
        
        store.add_user(user1)
        store.add_user(user2)
        
        engine_ids = store.get_engine_ids()
        
        assert len(engine_ids) == 2
        assert user1.engine_id.lower() in engine_ids
        assert "aaaa1111" in engine_ids


class TestCredentialEncryption:
    """Tests for credential encryption/decryption."""

    @pytest.fixture
    def store(self, tmp_path):
        """Create a credential store."""
        from trapninja.snmpv3_credentials import SNMPv3CredentialStore
        
        return SNMPv3CredentialStore(str(tmp_path / "credentials.json"))

    def test_key_derivation_deterministic(self, store):
        """Test key derivation is deterministic for same engine ID."""
        key1 = store._derive_key_from_engine_id("80001234")
        key2 = store._derive_key_from_engine_id("80001234")
        
        assert key1 == key2

    def test_key_derivation_different_for_different_engines(self, store):
        """Test different engine IDs produce different keys."""
        key1 = store._derive_key_from_engine_id("80001234")
        key2 = store._derive_key_from_engine_id("80005678")
        
        assert key1 != key2

    def test_encrypt_decrypt_roundtrip(self, store):
        """Test credentials survive encrypt/decrypt roundtrip."""
        from trapninja.snmpv3_credentials import SNMPv3User
        
        user = SNMPv3User(
            username="testuser",
            auth_protocol="SHA",
            auth_passphrase="authpass123",
            priv_protocol="AES128",
            priv_passphrase="privpass123",
            engine_id="80001234"
        )
        
        encrypted = store._encrypt_credentials(user)
        decrypted = store._decrypt_credentials(encrypted, "80001234")
        
        assert decrypted is not None
        assert decrypted.username == user.username
        assert decrypted.auth_passphrase == user.auth_passphrase

    def test_decrypt_with_wrong_engine_fails(self, store):
        """Test decryption fails with wrong engine ID."""
        from trapninja.snmpv3_credentials import SNMPv3User
        
        user = SNMPv3User(
            username="testuser",
            auth_protocol="SHA",
            auth_passphrase="authpass123",
            priv_protocol="AES128",
            priv_passphrase="privpass123",
            engine_id="80001234"
        )
        
        encrypted = store._encrypt_credentials(user)
        
        # Try to decrypt with different engine ID
        decrypted = store._decrypt_credentials(encrypted, "80005678")
        
        assert decrypted is None

    def test_decrypt_corrupted_data_returns_none(self, store):
        """Test decryption of corrupted data returns None."""
        result = store._decrypt_credentials("corrupted_base64_data!", "80001234")
        
        assert result is None


class TestCredentialPersistence:
    """Tests for credential file persistence."""

    @pytest.fixture
    def store(self, tmp_path):
        """Create a credential store."""
        from trapninja.snmpv3_credentials import SNMPv3CredentialStore
        
        return SNMPv3CredentialStore(str(tmp_path / "credentials.json"))

    @pytest.fixture
    def valid_user(self):
        """Create a valid user."""
        from trapninja.snmpv3_credentials import SNMPv3User
        
        return SNMPv3User(
            username="testuser",
            auth_protocol="SHA",
            auth_passphrase="authpass123",
            priv_protocol="AES128",
            priv_passphrase="privpass123",
            engine_id="80001234"
        )

    def test_save_creates_file(self, store, valid_user):
        """Test saving creates credentials file."""
        store.add_user(valid_user)
        
        assert os.path.exists(store.credentials_file)

    def test_save_sets_permissions(self, store, valid_user):
        """Test saved file has restrictive permissions."""
        store.add_user(valid_user)
        
        # Check file permissions (0o600 = owner read/write only)
        mode = os.stat(store.credentials_file).st_mode & 0o777
        assert mode == 0o600

    def test_load_restores_credentials(self, tmp_path):
        """Test loading restores saved credentials."""
        from trapninja.snmpv3_credentials import SNMPv3CredentialStore, SNMPv3User
        
        cred_file = tmp_path / "credentials.json"
        
        # Create and save
        store1 = SNMPv3CredentialStore(str(cred_file))
        user = SNMPv3User(
            username="testuser",
            auth_protocol="SHA",
            auth_passphrase="authpass123",
            priv_protocol="AES128",
            priv_passphrase="privpass123",
            engine_id="80001234"
        )
        store1.add_user(user)
        
        # Create new store - should load existing file
        store2 = SNMPv3CredentialStore(str(cred_file))
        
        loaded_user = store2.get_user("80001234", "testuser")
        
        assert loaded_user is not None
        assert loaded_user.username == "testuser"
        assert loaded_user.auth_passphrase == "authpass123"

    def test_load_missing_file_ok(self, tmp_path):
        """Test loading non-existent file doesn't raise."""
        from trapninja.snmpv3_credentials import SNMPv3CredentialStore
        
        cred_file = tmp_path / "nonexistent.json"
        
        # Should not raise
        store = SNMPv3CredentialStore(str(cred_file))
        
        assert store.credentials == {}


class TestAuditLogging:
    """Tests for audit logging functionality."""

    def test_log_audit_success(self):
        """Test successful audit logging."""
        from trapninja.snmpv3_credentials import _log_audit, AuditEvent
        
        with patch('trapninja.snmpv3_credentials.audit_logger') as mock_logger:
            _log_audit(AuditEvent.CREDENTIAL_ADD, {
                'username': 'testuser',
                'engine_id': '80001234'
            })
            
            mock_logger.info.assert_called_once()

    def test_log_audit_failure(self):
        """Test failed operation audit logging."""
        from trapninja.snmpv3_credentials import _log_audit, AuditEvent
        
        with patch('trapninja.snmpv3_credentials.audit_logger') as mock_logger:
            _log_audit(AuditEvent.CREDENTIAL_ADD, {
                'username': 'testuser',
                'error': 'validation failed'
            }, success=False)
            
            mock_logger.warning.assert_called_once()

    def test_log_audit_strips_sensitive_data(self):
        """Test audit logging strips sensitive data."""
        from trapninja.snmpv3_credentials import _log_audit, AuditEvent
        
        with patch('trapninja.snmpv3_credentials.audit_logger') as mock_logger:
            _log_audit(AuditEvent.CREDENTIAL_ADD, {
                'username': 'testuser',
                'auth_passphrase': 'secret123',  # Should be stripped
                'priv_passphrase': 'secret456',  # Should be stripped
                'password': 'password123'  # Should be stripped
            })
            
            # Get the logged message
            call_args = mock_logger.info.call_args[0][0]
            
            assert 'secret123' not in call_args
            assert 'secret456' not in call_args
            assert 'password123' not in call_args


class TestGlobalCredentialStore:
    """Tests for global credential store functions."""

    def test_get_credential_store_creates_instance(self, tmp_path, monkeypatch):
        """Test get_credential_store creates global instance."""
        from trapninja import snmpv3_credentials
        
        # Reset global
        snmpv3_credentials._credential_store = None
        
        monkeypatch.setattr('trapninja.config.CONFIG_DIR', str(tmp_path))
        
        store = snmpv3_credentials.get_credential_store()
        
        assert store is not None
        assert isinstance(store, snmpv3_credentials.SNMPv3CredentialStore)

    def test_get_credential_store_returns_same_instance(self, tmp_path, monkeypatch):
        """Test get_credential_store returns same instance."""
        from trapninja import snmpv3_credentials
        
        snmpv3_credentials._credential_store = None
        monkeypatch.setattr('trapninja.config.CONFIG_DIR', str(tmp_path))
        
        store1 = snmpv3_credentials.get_credential_store()
        store2 = snmpv3_credentials.get_credential_store()
        
        assert store1 is store2

    def test_initialize_credential_store(self, tmp_path):
        """Test initialize_credential_store with custom path."""
        from trapninja import snmpv3_credentials
        
        cred_file = tmp_path / "custom_creds.json"
        
        store = snmpv3_credentials.initialize_credential_store(str(cred_file))
        
        assert store is not None
        assert store.credentials_file == str(cred_file)


class TestAuditEvent:
    """Tests for AuditEvent constants."""

    def test_audit_event_constants(self):
        """Test AuditEvent has required constants."""
        from trapninja.snmpv3_credentials import AuditEvent
        
        assert hasattr(AuditEvent, 'CREDENTIAL_ADD')
        assert hasattr(AuditEvent, 'CREDENTIAL_UPDATE')
        assert hasattr(AuditEvent, 'CREDENTIAL_REMOVE')
        assert hasattr(AuditEvent, 'CREDENTIAL_ACCESS')
        assert hasattr(AuditEvent, 'CREDENTIAL_LIST')
        assert hasattr(AuditEvent, 'CREDENTIAL_DECRYPT_FAIL')
        assert hasattr(AuditEvent, 'STORE_LOAD')
        assert hasattr(AuditEvent, 'STORE_SAVE')
