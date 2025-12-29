#!/usr/bin/env python3
"""
TrapNinja SNMPv3 Credentials Module

Manages SNMPv3 user credentials with encrypted storage.
Uses Engine ID as the encryption key for credential protection.

Security Features:
- Encrypted storage using Fernet (AES-128-CBC)
- PBKDF2 key derivation with 100,000 iterations
- Restrictive file permissions (0o600)
- Audit logging for all credential operations
"""
import os
import json
import logging
import hashlib
import base64
import getpass
import socket
import time
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Get logger instances
logger = logging.getLogger("trapninja")

# Separate audit logger for security-sensitive operations
audit_logger = logging.getLogger("trapninja.audit")


class AuditEvent:
    """Security audit event types."""
    CREDENTIAL_ADD = "CREDENTIAL_ADD"
    CREDENTIAL_UPDATE = "CREDENTIAL_UPDATE"
    CREDENTIAL_REMOVE = "CREDENTIAL_REMOVE"
    CREDENTIAL_ACCESS = "CREDENTIAL_ACCESS"
    CREDENTIAL_LIST = "CREDENTIAL_LIST"
    CREDENTIAL_DECRYPT_FAIL = "CREDENTIAL_DECRYPT_FAIL"
    STORE_LOAD = "STORE_LOAD"
    STORE_SAVE = "STORE_SAVE"


def _log_audit(event: str, details: Dict, success: bool = True):
    """
    Log a security audit event.
    
    All credential operations are logged for security auditing purposes.
    Sensitive data (passphrases) are never logged.
    
    Args:
        event: Audit event type from AuditEvent
        details: Event details (username, engine_id, etc.)
        success: Whether the operation succeeded
    """
    try:
        # Get caller info
        try:
            caller_user = getpass.getuser()
        except Exception:
            caller_user = "unknown"
        
        hostname = socket.gethostname()
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        
        # Build audit record
        audit_record = {
            "timestamp": timestamp,
            "event": event,
            "success": success,
            "host": hostname,
            "user": caller_user,
            **details
        }
        
        # Remove any accidentally included sensitive fields
        for sensitive_key in ['auth_passphrase', 'priv_passphrase', 'passphrase', 'password', 'secret']:
            audit_record.pop(sensitive_key, None)
        
        # Log at appropriate level
        if success:
            audit_logger.info(f"AUDIT: {json.dumps(audit_record)}")
        else:
            audit_logger.warning(f"AUDIT: {json.dumps(audit_record)}")
            
    except Exception as e:
        # Don't let audit logging failures break functionality
        logger.debug(f"Audit logging error: {e}")


@dataclass
class SNMPv3User:
    """
    SNMPv3 User credentials
    
    Attributes:
        username: SNMP username
        auth_protocol: Authentication protocol (MD5, SHA, SHA224, SHA256, SHA384, SHA512)
        auth_passphrase: Authentication passphrase
        priv_protocol: Privacy protocol (DES, 3DES, AES128, AES192, AES256)
        priv_passphrase: Privacy passphrase
        engine_id: SNMP Engine ID (hex string)
    """
    username: str
    auth_protocol: str
    auth_passphrase: str
    priv_protocol: str
    priv_passphrase: str
    engine_id: str
    
    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: dict) -> 'SNMPv3User':
        """Create from dictionary"""
        return cls(**data)
    
    def validate(self) -> Tuple[bool, str]:
        """
        Validate user credentials
        
        Returns:
            Tuple of (is_valid, error_message)
        """
        # Validate username
        if not self.username or len(self.username) < 1 or len(self.username) > 32:
            return False, "Username must be 1-32 characters"
        
        # Validate auth protocol
        valid_auth = ['MD5', 'SHA', 'SHA224', 'SHA256', 'SHA384', 'SHA512', 'NONE']
        if self.auth_protocol.upper() not in valid_auth:
            return False, f"Invalid auth protocol. Must be one of: {', '.join(valid_auth)}"
        
        # Validate priv protocol
        valid_priv = ['DES', '3DES', 'AES128', 'AES192', 'AES256', 'NONE']
        if self.priv_protocol.upper() not in valid_priv:
            return False, f"Invalid priv protocol. Must be one of: {', '.join(valid_priv)}"
        
        # Validate passphrases if not NONE
        if self.auth_protocol.upper() != 'NONE':
            if not self.auth_passphrase or len(self.auth_passphrase) < 8:
                return False, "Auth passphrase must be at least 8 characters"
        
        if self.priv_protocol.upper() != 'NONE':
            if not self.priv_passphrase or len(self.priv_passphrase) < 8:
                return False, "Priv passphrase must be at least 8 characters"
        
        # Validate engine ID (must be hex string)
        if not self.engine_id:
            return False, "Engine ID is required"
        
        try:
            bytes.fromhex(self.engine_id)
        except ValueError:
            return False, "Engine ID must be a valid hexadecimal string"
        
        return True, ""


class SNMPv3CredentialStore:
    """
    Manages encrypted storage of SNMPv3 credentials with security auditing.
    
    Uses Engine ID as the basis for encryption keys to provide
    engine-specific protection of credentials.
    
    All credential operations are logged for security audit purposes.
    """
    
    def __init__(self, credentials_file: str):
        """
        Initialize credential store
        
        Args:
            credentials_file: Path to encrypted credentials file
        """
        self.credentials_file = credentials_file
        self.credentials: Dict[str, Dict[str, SNMPv3User]] = {}  # engine_id -> username -> user
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(credentials_file), exist_ok=True)
        
        # Load existing credentials
        self._load_credentials()
    
    def _derive_key_from_engine_id(self, engine_id: str) -> bytes:
        """
        Derive encryption key from Engine ID
        
        Uses PBKDF2 to derive a Fernet-compatible key from the Engine ID.
        This ensures that credentials are encrypted with a key unique to
        their Engine ID.
        
        Args:
            engine_id: SNMP Engine ID (hex string)
            
        Returns:
            32-byte encryption key
        """
        # Use the engine ID as the password material
        password = engine_id.encode()
        
        # Use a fixed salt derived from the engine ID
        # This makes the encryption deterministic for a given engine ID
        salt = hashlib.sha256(password).digest()
        
        # Derive key using PBKDF2
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        
        key = kdf.derive(password)
        return base64.urlsafe_b64encode(key)
    
    def _encrypt_credentials(self, user: SNMPv3User) -> str:
        """
        Encrypt user credentials
        
        Args:
            user: SNMPv3 user to encrypt
            
        Returns:
            Base64-encoded encrypted credentials
        """
        # Derive key from engine ID
        key = self._derive_key_from_engine_id(user.engine_id)
        fernet = Fernet(key)
        
        # Convert user to JSON
        user_json = json.dumps(user.to_dict())
        
        # Encrypt
        encrypted = fernet.encrypt(user_json.encode())
        
        return base64.b64encode(encrypted).decode()
    
    def _decrypt_credentials(self, encrypted_data: str, engine_id: str) -> Optional[SNMPv3User]:
        """
        Decrypt user credentials
        
        Args:
            encrypted_data: Base64-encoded encrypted credentials
            engine_id: SNMP Engine ID for key derivation
            
        Returns:
            Decrypted SNMPv3User or None if decryption fails
        """
        try:
            # Derive key from engine ID
            key = self._derive_key_from_engine_id(engine_id)
            fernet = Fernet(key)
            
            # Decode and decrypt
            encrypted = base64.b64decode(encrypted_data.encode())
            decrypted = fernet.decrypt(encrypted)
            
            # Parse JSON
            user_data = json.loads(decrypted.decode())
            
            return SNMPv3User.from_dict(user_data)
            
        except (InvalidToken, json.JSONDecodeError, Exception) as e:
            logger.error(f"Failed to decrypt credentials: {e}")
            _log_audit(AuditEvent.CREDENTIAL_DECRYPT_FAIL, {
                "engine_id": engine_id,
                "error": str(e)
            }, success=False)
            return None
    
    def _load_credentials(self):
        """Load credentials from file with audit logging."""
        if not os.path.exists(self.credentials_file):
            logger.info(f"No SNMPv3 credentials file found at {self.credentials_file}")
            return
        
        try:
            with open(self.credentials_file, 'r') as f:
                data = json.load(f)
            
            # Data structure: {engine_id: {username: encrypted_credentials}}
            loaded_count = 0
            failed_count = 0
            
            for engine_id, users in data.items():
                self.credentials[engine_id] = {}
                
                for username, encrypted_creds in users.items():
                    user = self._decrypt_credentials(encrypted_creds, engine_id)
                    if user:
                        self.credentials[engine_id][username] = user
                        loaded_count += 1
                    else:
                        logger.warning(f"Failed to decrypt credentials for {username}@{engine_id}")
                        failed_count += 1
            
            logger.info(f"Loaded SNMPv3 credentials for {len(self.credentials)} engine IDs")
            
            _log_audit(AuditEvent.STORE_LOAD, {
                "file": self.credentials_file,
                "engine_count": len(self.credentials),
                "user_count": loaded_count,
                "failed_count": failed_count
            })
            
        except Exception as e:
            logger.error(f"Error loading SNMPv3 credentials: {e}")
            _log_audit(AuditEvent.STORE_LOAD, {
                "file": self.credentials_file,
                "error": str(e)
            }, success=False)
            self.credentials = {}
    
    def _save_credentials(self):
        """Save credentials to file with audit logging."""
        try:
            # Build storage structure with encrypted credentials
            data = {}
            user_count = 0
            
            for engine_id, users in self.credentials.items():
                data[engine_id] = {}
                
                for username, user in users.items():
                    encrypted = self._encrypt_credentials(user)
                    data[engine_id][username] = encrypted
                    user_count += 1
            
            # Write to file with proper permissions
            with open(self.credentials_file, 'w') as f:
                json.dump(data, f, indent=2)
            
            # Set restrictive permissions (owner read/write only)
            os.chmod(self.credentials_file, 0o600)
            
            logger.info(f"Saved SNMPv3 credentials to {self.credentials_file}")
            
            _log_audit(AuditEvent.STORE_SAVE, {
                "file": self.credentials_file,
                "engine_count": len(self.credentials),
                "user_count": user_count
            })
            
        except Exception as e:
            logger.error(f"Error saving SNMPv3 credentials: {e}")
            _log_audit(AuditEvent.STORE_SAVE, {
                "file": self.credentials_file,
                "error": str(e)
            }, success=False)
    
    def add_user(self, user: SNMPv3User) -> Tuple[bool, str]:
        """
        Add or update SNMPv3 user credentials with audit logging.
        
        Args:
            user: SNMPv3 user to add
            
        Returns:
            Tuple of (success, message)
        """
        # Validate user
        is_valid, error_msg = user.validate()
        if not is_valid:
            _log_audit(AuditEvent.CREDENTIAL_ADD, {
                "username": user.username,
                "engine_id": user.engine_id,
                "error": error_msg
            }, success=False)
            return False, error_msg
        
        # Normalize engine ID to lowercase
        engine_id = user.engine_id.lower()
        user.engine_id = engine_id
        
        # Check if updating existing user
        is_update = (engine_id in self.credentials and 
                    user.username in self.credentials[engine_id])
        
        # Add user
        if engine_id not in self.credentials:
            self.credentials[engine_id] = {}
        
        self.credentials[engine_id][user.username] = user
        
        # Save to file
        self._save_credentials()
        
        action = "Updated" if is_update else "Added"
        event = AuditEvent.CREDENTIAL_UPDATE if is_update else AuditEvent.CREDENTIAL_ADD
        
        logger.info(f"{action} SNMPv3 user {user.username} for engine {engine_id}")
        
        _log_audit(event, {
            "username": user.username,
            "engine_id": engine_id,
            "auth_protocol": user.auth_protocol,
            "priv_protocol": user.priv_protocol
        })
        
        return True, f"{action} user {user.username} for engine {engine_id}"
    
    def remove_user(self, engine_id: str, username: str) -> Tuple[bool, str]:
        """
        Remove SNMPv3 user credentials with audit logging.
        
        Args:
            engine_id: SNMP Engine ID
            username: Username to remove
            
        Returns:
            Tuple of (success, message)
        """
        # Normalize engine ID
        engine_id = engine_id.lower()
        
        # Check if user exists
        if engine_id not in self.credentials:
            _log_audit(AuditEvent.CREDENTIAL_REMOVE, {
                "username": username,
                "engine_id": engine_id,
                "error": "Engine ID not found"
            }, success=False)
            return False, f"No credentials found for engine {engine_id}"
        
        if username not in self.credentials[engine_id]:
            _log_audit(AuditEvent.CREDENTIAL_REMOVE, {
                "username": username,
                "engine_id": engine_id,
                "error": "Username not found"
            }, success=False)
            return False, f"User {username} not found for engine {engine_id}"
        
        # Remove user
        del self.credentials[engine_id][username]
        
        # Remove engine ID if no more users
        if not self.credentials[engine_id]:
            del self.credentials[engine_id]
        
        # Save to file
        self._save_credentials()
        
        logger.info(f"Removed SNMPv3 user {username} for engine {engine_id}")
        
        _log_audit(AuditEvent.CREDENTIAL_REMOVE, {
            "username": username,
            "engine_id": engine_id
        })
        
        return True, f"Removed user {username} for engine {engine_id}"
    
    def get_user(self, engine_id: str, username: str) -> Optional[SNMPv3User]:
        """
        Get SNMPv3 user credentials with audit logging.
        
        Args:
            engine_id: SNMP Engine ID
            username: Username to retrieve
            
        Returns:
            SNMPv3User or None if not found
        """
        # Normalize engine ID
        engine_id = engine_id.lower()
        
        user = None
        if engine_id in self.credentials:
            user = self.credentials[engine_id].get(username)
        
        # Log access attempt
        _log_audit(AuditEvent.CREDENTIAL_ACCESS, {
            "username": username,
            "engine_id": engine_id,
            "found": user is not None
        })
        
        return user
    
    def get_users_for_engine(self, engine_id: str) -> List[SNMPv3User]:
        """
        Get all users for a specific engine ID
        
        Args:
            engine_id: SNMP Engine ID
            
        Returns:
            List of SNMPv3User objects
        """
        # Normalize engine ID
        engine_id = engine_id.lower()
        
        if engine_id in self.credentials:
            return list(self.credentials[engine_id].values())
        
        return []
    
    def list_all_users(self) -> List[Dict]:
        """
        List all configured users with masked passphrases.
        
        Audit logged for security tracking.
        
        Returns:
            List of user info dictionaries
        """
        result = []
        
        for engine_id, users in self.credentials.items():
            for username, user in users.items():
                result.append({
                    'engine_id': engine_id,
                    'username': username,
                    'auth_protocol': user.auth_protocol,
                    'priv_protocol': user.priv_protocol,
                    'auth_passphrase': '***' if user.auth_passphrase else '',
                    'priv_passphrase': '***' if user.priv_passphrase else ''
                })
        
        _log_audit(AuditEvent.CREDENTIAL_LIST, {
            "user_count": len(result)
        })
        
        return result
    
    def get_engine_ids(self) -> List[str]:
        """
        Get list of configured engine IDs
        
        Returns:
            List of engine ID strings
        """
        return list(self.credentials.keys())


# Global credential store instance
_credential_store: Optional[SNMPv3CredentialStore] = None


def get_credential_store() -> SNMPv3CredentialStore:
    """
    Get the global credential store instance
    
    Returns:
        SNMPv3CredentialStore instance
    """
    global _credential_store
    
    if _credential_store is None:
        from .config import CONFIG_DIR
        credentials_file = os.path.join(CONFIG_DIR, "snmpv3_credentials.json")
        _credential_store = SNMPv3CredentialStore(credentials_file)
    
    return _credential_store


def initialize_credential_store(credentials_file: str = None) -> SNMPv3CredentialStore:
    """
    Initialize the global credential store
    
    Args:
        credentials_file: Optional custom path to credentials file
        
    Returns:
        SNMPv3CredentialStore instance
    """
    global _credential_store
    
    if credentials_file is None:
        from .config import CONFIG_DIR
        credentials_file = os.path.join(CONFIG_DIR, "snmpv3_credentials.json")
    
    _credential_store = SNMPv3CredentialStore(credentials_file)
    return _credential_store
