#!/usr/bin/env python3
"""
TrapNinja SNMPv3 Trap Generator Module

Generates fresh SNMPv3 trap messages with valid security state.
Used by the replay engine when --regenerate-v3 flag is set.

This module:
1. Defines TrapEvent - a neutral, version-agnostic trap representation
2. Provides SNMPv3Generator - generates authenticated/encrypted v3 traps

Security Notes:
- Credentials are obtained from SNMPv3CredentialStore (never stored here)
- No credentials are logged at any level
- Engine boots/time are set to current values for freshness
"""

import hashlib
import logging
import struct
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("trapninja")

# Check for pycryptodome
CRYPTO_AVAILABLE = False
try:
    from Crypto.Cipher import AES, DES
    from Crypto.Random import get_random_bytes
    CRYPTO_AVAILABLE = True
except ImportError:
    logger.debug("pycryptodome not available - SNMPv3 generation will not work")


# =============================================================================
# TRAP EVENT - NEUTRAL REPRESENTATION
# =============================================================================

@dataclass
class VarBind:
    """
    A single variable binding (OID + value).
    
    Attributes:
        oid: Object identifier as dotted string (e.g. "1.3.6.1.2.1.1.3.0")
        value: The value (type depends on value_type)
        value_type: Type name (Integer, OctetString, ObjectIdentifier, etc.)
    """
    oid: str
    value: Any
    value_type: str
    
    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            'oid': self.oid,
            'value': self.value,
            'value_type': self.value_type
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'VarBind':
        """Create from dictionary."""
        return cls(
            oid=data['oid'],
            value=data['value'],
            value_type=data.get('value_type', data.get('type', 'OctetString'))
        )


@dataclass
class TrapEvent:
    """
    Version-agnostic trap representation.
    
    This is the neutral format used between decryption and regeneration.
    Contains all information needed to reconstruct a trap in any SNMP version.
    
    Security Note: This object should only exist in memory during processing.
    Never persist TrapEvent to disk or log its contents.
    
    Attributes:
        source_ip: Original source IP address
        trap_oid: The trap OID (snmpTrapOID value)
        varbinds: List of variable bindings
        engine_id: Original SNMPv3 engine ID (hex string)
        context_name: SNMPv3 context name
        request_id: Original request ID
        timestamp: Event timestamp (defaults to now)
        original_version: Original SNMP version ('v1', 'v2c', 'v3')
    """
    source_ip: str
    trap_oid: str
    varbinds: List[VarBind]
    engine_id: str = ""
    context_name: str = ""
    request_id: int = 0
    timestamp: float = field(default_factory=time.time)
    original_version: str = "v3"
    
    @classmethod
    def from_decrypted_trap(
        cls,
        source_ip: str,
        engine_id: str,
        trap_data: Dict
    ) -> 'TrapEvent':
        """
        Create TrapEvent from SNMPv3Decryptor output.
        
        Args:
            source_ip: Source IP of the trap
            engine_id: Engine ID from decryption
            trap_data: Dictionary from SNMPv3Decryptor.decrypt_snmpv3_trap()
            
        Returns:
            TrapEvent instance
        """
        # Extract trap OID from varbinds (snmpTrapOID.0 = 1.3.6.1.6.3.1.1.4.1.0)
        trap_oid = ""
        varbinds = []
        
        for vb in trap_data.get('varbinds', []):
            oid = vb.get('oid', '')
            value = vb.get('value')
            value_type = vb.get('type', 'OctetString')
            
            # Check if this is snmpTrapOID
            if oid == '1.3.6.1.6.3.1.1.4.1.0':
                trap_oid = value if isinstance(value, str) else str(value)
            
            varbinds.append(VarBind(
                oid=oid,
                value=value,
                value_type=value_type
            ))
        
        return cls(
            source_ip=source_ip,
            trap_oid=trap_oid,
            varbinds=varbinds,
            engine_id=engine_id,
            context_name=trap_data.get('context_name', ''),
            request_id=trap_data.get('request_id', 0),
            original_version='v3'
        )


# =============================================================================
# SNMPV3 GENERATOR
# =============================================================================

class SNMPv3Generator:
    """
    Generates authenticated and encrypted SNMPv3 trap messages.
    
    Uses credentials from SNMPv3CredentialStore to build valid SNMPv3 traps
    with fresh security state (engine boots, engine time, auth/priv params).
    
    Usage:
        generator = SNMPv3Generator(credential_store)
        trap_bytes = generator.generate(trap_event, username='monitor')
    """
    
    def __init__(self, credential_store):
        """
        Initialize the generator.
        
        Args:
            credential_store: SNMPv3CredentialStore instance
        """
        self.credential_store = credential_store
        # Track engine boots per engine ID (simulated - in production would persist)
        self._engine_boots: Dict[str, int] = {}
        self._start_time = time.time()
    
    def _get_engine_time(self) -> int:
        """Get current engine time (seconds since start, wrapped at 2^31)."""
        elapsed = int(time.time() - self._start_time)
        return elapsed % (2 ** 31)
    
    def _get_engine_boots(self, engine_id: str) -> int:
        """Get engine boots for an engine ID."""
        if engine_id not in self._engine_boots:
            self._engine_boots[engine_id] = 1
        return self._engine_boots[engine_id]
    
    def generate(
        self,
        event: TrapEvent,
        username: Optional[str] = None
    ) -> Optional[bytes]:
        """
        Generate an SNMPv3 trap message from a TrapEvent.
        
        Args:
            event: TrapEvent containing trap data
            username: Specific username to use (if None, uses first available)
            
        Returns:
            Raw SNMPv3 message bytes, or None if generation fails
        """
        if not CRYPTO_AVAILABLE:
            logger.warning("Cannot generate SNMPv3: pycryptodome not available")
            return None
        
        # Get credentials for this engine ID
        engine_id = event.engine_id.lower()
        users = self.credential_store.get_users_for_engine(engine_id)
        
        if not users:
            logger.warning(f"No credentials for engine ID: {engine_id}")
            return None
        
        # Select user
        if username:
            user = next((u for u in users if u.username == username), None)
            if not user:
                logger.warning(f"User '{username}' not found for engine {engine_id}")
                return None
        else:
            user = users[0]
        
        try:
            return self._build_snmpv3_message(event, user)
        except Exception as e:
            logger.warning(f"SNMPv3 generation failed: {e}")
            logger.debug(f"Generation error details", exc_info=True)
            return None
    
    def _build_snmpv3_message(self, event: TrapEvent, user) -> bytes:
        """
        Build the complete SNMPv3 message.
        
        SNMPv3 message structure:
        - SEQUENCE (message)
          - INTEGER (version = 3)
          - SEQUENCE (msgGlobalData)
          - OCTET STRING (msgSecurityParameters - USM)
          - SEQUENCE or OCTET STRING (msgData - ScopedPDU, possibly encrypted)
        """
        engine_id_bytes = bytes.fromhex(user.engine_id)
        engine_boots = self._get_engine_boots(user.engine_id)
        engine_time = self._get_engine_time()
        
        # Build ScopedPDU
        scoped_pdu = self._build_scoped_pdu(event, engine_id_bytes)
        
        # Determine security level
        auth_protocol = user.auth_protocol.upper()
        priv_protocol = user.priv_protocol.upper()
        
        has_auth = auth_protocol != 'NONE'
        has_priv = priv_protocol != 'NONE'
        
        # Security flags: bit 0 = auth, bit 1 = priv, bit 2 = reportable
        msg_flags = 0x04  # reportable
        if has_auth:
            msg_flags |= 0x01
        if has_priv:
            msg_flags |= 0x02
        
        # Generate privacy parameters if needed
        if has_priv:
            priv_params = get_random_bytes(8)
            encrypted_pdu = self._encrypt_scoped_pdu(
                scoped_pdu, user, engine_boots, engine_time, priv_params
            )
            msg_data = self._encode_octet_string(encrypted_pdu)
        else:
            priv_params = b''
            msg_data = scoped_pdu
        
        # Build USM security parameters (initially with empty auth params)
        auth_params_placeholder = b'\x00' * 12 if has_auth else b''
        
        usm_params = self._build_usm_params(
            engine_id_bytes,
            engine_boots,
            engine_time,
            user.username.encode('utf-8'),
            auth_params_placeholder,
            priv_params
        )
        
        # Build msgGlobalData
        msg_id = event.request_id if event.request_id else int(time.time()) & 0x7FFFFFFF
        msg_global_data = self._build_msg_global_data(msg_id, msg_flags)
        
        # Build message without auth
        version = self._encode_integer(3)
        usm_params_octet = self._encode_octet_string(usm_params)
        
        message_content = version + msg_global_data + usm_params_octet + msg_data
        message = self._encode_sequence(message_content)
        
        # Calculate and insert authentication if needed
        if has_auth:
            auth_key = self._localize_key(
                user.auth_passphrase,
                engine_id_bytes,
                auth_protocol
            )
            
            # Find position of auth params in message
            auth_pos = message.find(auth_params_placeholder)
            if auth_pos > 0:
                # Calculate HMAC over entire message with zeroed auth field
                auth_value = self._calculate_auth(message, auth_key, auth_protocol)
                
                # Replace placeholder with actual auth value
                message = (
                    message[:auth_pos] +
                    auth_value[:12] +
                    message[auth_pos + 12:]
                )
        
        return message
    
    def _build_scoped_pdu(self, event: TrapEvent, engine_id: bytes) -> bytes:
        """Build the ScopedPDU containing the trap PDU."""
        context_engine_id = self._encode_octet_string(engine_id)
        context_name = self._encode_octet_string(
            event.context_name.encode('utf-8') if event.context_name else b''
        )
        
        # Build SNMPv2-Trap-PDU (tag 0xA7)
        trap_pdu = self._build_trap_pdu(event)
        
        scoped_content = context_engine_id + context_name + trap_pdu
        return self._encode_sequence(scoped_content)
    
    def _build_trap_pdu(self, event: TrapEvent) -> bytes:
        """Build the SNMPv2-Trap-PDU."""
        request_id = self._encode_integer(event.request_id or 0)
        error_status = self._encode_integer(0)
        error_index = self._encode_integer(0)
        
        # Build varbind list
        varbind_list = b''
        for vb in event.varbinds:
            varbind_list += self._encode_varbind(vb)
        
        varbind_seq = self._encode_sequence(varbind_list)
        
        pdu_content = request_id + error_status + error_index + varbind_seq
        
        # SNMPv2-Trap-PDU has implicit tag [7] (0xA7)
        return self._encode_implicit_tag(7, pdu_content)
    
    def _encode_varbind(self, vb: VarBind) -> bytes:
        """Encode a single varbind as SEQUENCE { OID, value }."""
        oid_encoded = self._encode_oid(vb.oid)
        value_encoded = self._encode_value(vb.value, vb.value_type)
        return self._encode_sequence(oid_encoded + value_encoded)
    
    def _encode_value(self, value: Any, value_type: str) -> bytes:
        """Encode a value based on its type."""
        vtype = value_type.lower()
        
        if vtype == 'integer' or vtype == 'integer32':
            return self._encode_integer(int(value) if value else 0)
        
        elif vtype == 'octetstring':
            if isinstance(value, bytes):
                return self._encode_octet_string(value)
            elif isinstance(value, str):
                # Check if it's a hex string
                if all(c in '0123456789abcdefABCDEF' for c in value) and len(value) % 2 == 0:
                    try:
                        return self._encode_octet_string(bytes.fromhex(value))
                    except ValueError:
                        pass
                return self._encode_octet_string(value.encode('utf-8'))
            return self._encode_octet_string(str(value).encode('utf-8'))
        
        elif vtype == 'objectidentifier' or vtype == 'oid':
            return self._encode_oid(str(value))
        
        elif vtype == 'null':
            return b'\x05\x00'
        
        elif vtype == 'ipaddress':
            return self._encode_ip_address(str(value))
        
        elif vtype == 'counter32':
            return self._encode_application_integer(0x41, int(value) if value else 0)
        
        elif vtype == 'gauge32' or vtype == 'unsigned32':
            return self._encode_application_integer(0x42, int(value) if value else 0)
        
        elif vtype == 'timeticks':
            return self._encode_application_integer(0x43, int(value) if value else 0)
        
        elif vtype == 'opaque':
            if isinstance(value, str):
                try:
                    return self._encode_tagged(0x44, bytes.fromhex(value))
                except ValueError:
                    return self._encode_tagged(0x44, value.encode('utf-8'))
            return self._encode_tagged(0x44, bytes(value) if value else b'')
        
        elif vtype == 'counter64':
            return self._encode_application_integer(0x46, int(value) if value else 0)
        
        else:
            # Default to octet string
            if isinstance(value, bytes):
                return self._encode_octet_string(value)
            return self._encode_octet_string(str(value).encode('utf-8'))
    
    def _build_usm_params(
        self,
        engine_id: bytes,
        engine_boots: int,
        engine_time: int,
        username: bytes,
        auth_params: bytes,
        priv_params: bytes
    ) -> bytes:
        """Build USM security parameters."""
        content = (
            self._encode_octet_string(engine_id) +
            self._encode_integer(engine_boots) +
            self._encode_integer(engine_time) +
            self._encode_octet_string(username) +
            self._encode_octet_string(auth_params) +
            self._encode_octet_string(priv_params)
        )
        return self._encode_sequence(content)
    
    def _build_msg_global_data(self, msg_id: int, msg_flags: int) -> bytes:
        """Build msgGlobalData SEQUENCE."""
        content = (
            self._encode_integer(msg_id) +
            self._encode_integer(65507) +  # msgMaxSize
            self._encode_octet_string(bytes([msg_flags])) +
            self._encode_integer(3)  # msgSecurityModel = USM
        )
        return self._encode_sequence(content)
    
    # =========================================================================
    # ASN.1 BER ENCODING HELPERS
    # =========================================================================
    
    def _encode_length(self, length: int) -> bytes:
        """Encode ASN.1 length."""
        if length < 128:
            return bytes([length])
        elif length < 256:
            return bytes([0x81, length])
        elif length < 65536:
            return bytes([0x82, length >> 8, length & 0xFF])
        else:
            return bytes([0x83, length >> 16, (length >> 8) & 0xFF, length & 0xFF])
    
    def _encode_sequence(self, content: bytes) -> bytes:
        """Encode as SEQUENCE."""
        return b'\x30' + self._encode_length(len(content)) + content
    
    def _encode_integer(self, value: int) -> bytes:
        """Encode as INTEGER."""
        if value == 0:
            return b'\x02\x01\x00'
        
        # Handle negative numbers
        if value < 0:
            # Calculate minimum bytes needed
            byte_len = (value.bit_length() + 8) // 8
            value_bytes = value.to_bytes(byte_len, 'big', signed=True)
        else:
            # Positive number
            byte_len = (value.bit_length() + 7) // 8
            value_bytes = value.to_bytes(byte_len, 'big')
            # Add leading zero if high bit is set
            if value_bytes[0] & 0x80:
                value_bytes = b'\x00' + value_bytes
        
        return b'\x02' + self._encode_length(len(value_bytes)) + value_bytes
    
    def _encode_octet_string(self, value: bytes) -> bytes:
        """Encode as OCTET STRING."""
        return b'\x04' + self._encode_length(len(value)) + value
    
    def _encode_oid(self, oid_str: str) -> bytes:
        """Encode as OBJECT IDENTIFIER."""
        components = [int(c) for c in oid_str.split('.') if c]
        
        if len(components) < 2:
            return b'\x06\x00'
        
        # First two components combined
        encoded = [components[0] * 40 + components[1]]
        
        # Remaining components
        for comp in components[2:]:
            if comp == 0:
                encoded.append(0)
            else:
                # Encode in base-128 with continuation bits
                subid = []
                while comp > 0:
                    subid.insert(0, (comp & 0x7F) | (0x80 if subid else 0))
                    comp >>= 7
                encoded.extend(subid)
        
        oid_bytes = bytes(encoded)
        return b'\x06' + self._encode_length(len(oid_bytes)) + oid_bytes
    
    def _encode_implicit_tag(self, tag_num: int, content: bytes) -> bytes:
        """Encode with implicit context-specific tag."""
        tag = 0xA0 | tag_num
        return bytes([tag]) + self._encode_length(len(content)) + content
    
    def _encode_tagged(self, tag: int, content: bytes) -> bytes:
        """Encode with specific tag."""
        return bytes([tag]) + self._encode_length(len(content)) + content
    
    def _encode_application_integer(self, tag: int, value: int) -> bytes:
        """Encode an application-tagged unsigned integer."""
        if value == 0:
            return bytes([tag, 1, 0])
        
        byte_len = (value.bit_length() + 7) // 8
        value_bytes = value.to_bytes(byte_len, 'big')
        
        return bytes([tag]) + self._encode_length(len(value_bytes)) + value_bytes
    
    def _encode_ip_address(self, ip_str: str) -> bytes:
        """Encode as IpAddress (application tag 0x40)."""
        parts = ip_str.split('.')
        if len(parts) == 4:
            try:
                ip_bytes = bytes(int(p) for p in parts)
                return b'\x40\x04' + ip_bytes
            except ValueError:
                pass
        return b'\x40\x04\x00\x00\x00\x00'
    
    # =========================================================================
    # CRYPTOGRAPHIC OPERATIONS
    # =========================================================================
    
    def _localize_key(
        self,
        passphrase: str,
        engine_id: bytes,
        auth_protocol: str
    ) -> bytes:
        """
        Localize a passphrase to an engine-specific key.
        
        Uses the standard SNMPv3 key localization algorithm (RFC 3414).
        """
        # Select hash function
        if auth_protocol in ('MD5',):
            hash_func = hashlib.md5
        elif auth_protocol == 'SHA224':
            hash_func = hashlib.sha224
        elif auth_protocol == 'SHA256':
            hash_func = hashlib.sha256
        elif auth_protocol == 'SHA384':
            hash_func = hashlib.sha384
        elif auth_protocol == 'SHA512':
            hash_func = hashlib.sha512
        else:
            hash_func = hashlib.sha1  # Default SHA1
        
        # Generate Ku from passphrase
        password = passphrase.encode('utf-8')
        h = hash_func()
        password_buf = password * ((1048576 // len(password)) + 1)
        
        for i in range(0, 1048576, 64):
            h.update(password_buf[i:i+64])
        
        ku = h.digest()
        
        # Localize with engine ID
        h = hash_func()
        h.update(ku + engine_id + ku)
        return h.digest()
    
    def _calculate_auth(
        self,
        message: bytes,
        auth_key: bytes,
        auth_protocol: str
    ) -> bytes:
        """Calculate authentication HMAC."""
        import hmac
        
        if auth_protocol in ('MD5',):
            return hmac.new(auth_key[:16], message, hashlib.md5).digest()[:12]
        elif auth_protocol == 'SHA224':
            return hmac.new(auth_key[:28], message, hashlib.sha224).digest()[:12]
        elif auth_protocol == 'SHA256':
            return hmac.new(auth_key[:32], message, hashlib.sha256).digest()[:12]
        elif auth_protocol == 'SHA384':
            return hmac.new(auth_key[:48], message, hashlib.sha384).digest()[:12]
        elif auth_protocol == 'SHA512':
            return hmac.new(auth_key[:64], message, hashlib.sha512).digest()[:12]
        else:
            return hmac.new(auth_key[:20], message, hashlib.sha1).digest()[:12]
    
    def _encrypt_scoped_pdu(
        self,
        scoped_pdu: bytes,
        user,
        engine_boots: int,
        engine_time: int,
        priv_params: bytes
    ) -> bytes:
        """Encrypt the ScopedPDU."""
        auth_protocol = user.auth_protocol.upper()
        priv_protocol = user.priv_protocol.upper()
        
        # Get localized key
        engine_id = bytes.fromhex(user.engine_id)
        priv_key = self._localize_key(user.priv_passphrase, engine_id, auth_protocol)
        
        if priv_protocol in ('DES', '3DES'):
            # DES encryption
            des_key = priv_key[:8]
            pre_iv = priv_key[8:16]
            iv = bytes(a ^ b for a, b in zip(pre_iv, priv_params[:8]))
            
            # Pad to block size
            pad_len = 8 - (len(scoped_pdu) % 8)
            padded = scoped_pdu + bytes([pad_len] * pad_len)
            
            cipher = DES.new(des_key, DES.MODE_CBC, iv)
            return cipher.encrypt(padded)
        
        elif priv_protocol.startswith('AES'):
            # AES encryption
            if priv_protocol == 'AES128':
                key_len = 16
            elif priv_protocol == 'AES192':
                key_len = 24
            else:  # AES256
                key_len = 32
            
            # Extend key if needed
            if len(priv_key) < key_len:
                priv_key = self._extend_key(priv_key, key_len, auth_protocol)
            
            aes_key = priv_key[:key_len]
            
            # IV: engineBoots(4) + engineTime(4) + privParams(8)
            iv = (
                engine_boots.to_bytes(4, 'big') +
                engine_time.to_bytes(4, 'big') +
                priv_params[:8]
            )
            
            cipher = AES.new(aes_key, AES.MODE_CFB, iv, segment_size=128)
            return cipher.encrypt(scoped_pdu)
        
        else:
            raise ValueError(f"Unsupported privacy protocol: {priv_protocol}")
    
    def _extend_key(self, key: bytes, target_len: int, auth_protocol: str) -> bytes:
        """Extend key to required length for AES192/256."""
        if auth_protocol in ('MD5',):
            hash_func = hashlib.md5
        elif auth_protocol == 'SHA224':
            hash_func = hashlib.sha224
        elif auth_protocol == 'SHA256':
            hash_func = hashlib.sha256
        elif auth_protocol == 'SHA384':
            hash_func = hashlib.sha384
        elif auth_protocol == 'SHA512':
            hash_func = hashlib.sha512
        else:
            hash_func = hashlib.sha1
        
        extended = key
        while len(extended) < target_len:
            h = hash_func()
            h.update(key)
            extended += h.digest()
        
        return extended[:target_len]
