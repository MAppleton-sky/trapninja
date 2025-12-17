#!/usr/bin/env python3
"""
TrapNinja SNMPv3 Decryption Module

Handles decryption of SNMPv3 traps and conversion to SNMPv2c format.
Integrates with the credential management system for authentication.

Supports both pysnmp 4.x and 7.x API versions.
"""
import logging
import struct
import hashlib
from typing import Optional, Tuple, Dict, List, Any

# Get logger instance
logger = logging.getLogger("trapninja")

# Try to detect pysnmp version and import accordingly
PYSNMP_AVAILABLE = False
PYSNMP_VERSION = None

try:
    import pysnmp
    PYSNMP_VERSION = getattr(pysnmp, '__version__', '0.0.0')
    major_version = int(PYSNMP_VERSION.split('.')[0])
    
    if major_version >= 7:
        # pysnmp 7.x imports
        from pysnmp.smi.rfc1902 import ObjectIdentity, ObjectType
        from pyasn1.codec.ber import decoder, encoder
        from pyasn1.type import univ
        PYSNMP_AVAILABLE = True
        logger.info(f"Using pysnmp {PYSNMP_VERSION} (v7.x API)")
    else:
        # pysnmp 4.x imports
        from pysnmp.proto import api as snmp_api
        from pysnmp.proto.rfc1902 import (
            Integer32, OctetString, ObjectIdentifier as OID,
            IpAddress, Counter32, Gauge32, TimeTicks, Counter64
        )
        from pyasn1.codec.ber import decoder, encoder
        from pyasn1.type import univ
        PYSNMP_AVAILABLE = True
        logger.info(f"Using pysnmp {PYSNMP_VERSION} (v4.x API)")
        
except ImportError as e:
    logger.warning(f"pysnmp not available: {e}")
    logger.warning("SNMPv3 decryption will not be available")
    logger.warning("Install with: pip3 install --break-system-packages pysnmp pyasn1")

# Check for pycryptodome
CRYPTO_AVAILABLE = False
try:
    from Crypto.Cipher import AES, DES
    CRYPTO_AVAILABLE = True
except ImportError:
    logger.warning("pycryptodome not available - encrypted SNMPv3 traps cannot be decrypted")
    logger.warning("Install with: pip3 install --break-system-packages pycryptodome")


def extract_engine_id_from_bytes(data: bytes) -> Optional[str]:
    """
    Extract the authoritative engine ID from raw SNMPv3 message bytes.
    
    SNMPv3 message structure:
    - SEQUENCE
      - INTEGER (version = 3)
      - SEQUENCE (msgGlobalData)
      - OCTET STRING (msgSecurityParameters - contains USM data)
      - SEQUENCE or OCTET STRING (msgData)
    
    Args:
        data: Raw SNMPv3 message bytes
        
    Returns:
        Engine ID as hex string, or None if extraction fails
    """
    try:
        if len(data) < 10:
            return None
        
        idx = 0
        
        # Parse outer SEQUENCE
        if data[idx] != 0x30:
            return None
        idx += 1
        
        # Skip length
        if data[idx] & 0x80:
            len_bytes = data[idx] & 0x7f
            idx += 1 + len_bytes
        else:
            idx += 1
        
        # Check version INTEGER
        if data[idx] != 0x02:
            return None
        idx += 1
        ver_len = data[idx]
        idx += 1
        version = int.from_bytes(data[idx:idx+ver_len], 'big')
        if version != 3:
            return None
        idx += ver_len
        
        # Skip msgGlobalData SEQUENCE
        if data[idx] != 0x30:
            return None
        idx += 1
        if data[idx] & 0x80:
            len_bytes = data[idx] & 0x7f
            global_len = int.from_bytes(data[idx+1:idx+1+len_bytes], 'big')
            idx += 1 + len_bytes
        else:
            global_len = data[idx]
            idx += 1
        idx += global_len
        
        # Get msgSecurityParameters OCTET STRING
        if data[idx] != 0x04:
            return None
        idx += 1
        if data[idx] & 0x80:
            len_bytes = data[idx] & 0x7f
            sec_len = int.from_bytes(data[idx+1:idx+1+len_bytes], 'big')
            idx += 1 + len_bytes
        else:
            sec_len = data[idx]
            idx += 1
        
        # Parse USM security parameters
        usm_data = data[idx:idx+sec_len]
        usm_idx = 0
        
        if len(usm_data) < 2 or usm_data[usm_idx] != 0x30:
            return None
        usm_idx += 1
        
        if usm_data[usm_idx] & 0x80:
            len_bytes = usm_data[usm_idx] & 0x7f
            usm_idx += 1 + len_bytes
        else:
            usm_idx += 1
        
        # First element is msgAuthoritativeEngineID
        if usm_data[usm_idx] != 0x04:
            return None
        usm_idx += 1
        
        if usm_data[usm_idx] & 0x80:
            len_bytes = usm_data[usm_idx] & 0x7f
            engine_len = int.from_bytes(usm_data[usm_idx+1:usm_idx+1+len_bytes], 'big')
            usm_idx += 1 + len_bytes
        else:
            engine_len = usm_data[usm_idx]
            usm_idx += 1
        
        engine_id_bytes = usm_data[usm_idx:usm_idx+engine_len]
        return engine_id_bytes.hex()
        
    except Exception as e:
        logger.debug(f"Failed to extract engine ID: {e}")
        return None


def extract_username_from_bytes(data: bytes) -> Optional[str]:
    """
    Extract the username from raw SNMPv3 message bytes.
    """
    try:
        idx = 0
        
        # Skip to msgSecurityParameters (similar to engine ID extraction)
        if data[idx] != 0x30:
            return None
        idx += 1
        
        if data[idx] & 0x80:
            len_bytes = data[idx] & 0x7f
            idx += 1 + len_bytes
        else:
            idx += 1
        
        # Skip version
        if data[idx] != 0x02:
            return None
        idx += 1
        ver_len = data[idx]
        idx += 1 + ver_len
        
        # Skip msgGlobalData
        if data[idx] != 0x30:
            return None
        idx += 1
        if data[idx] & 0x80:
            len_bytes = data[idx] & 0x7f
            global_len = int.from_bytes(data[idx+1:idx+1+len_bytes], 'big')
            idx += 1 + len_bytes
        else:
            global_len = data[idx]
            idx += 1
        idx += global_len
        
        # Get msgSecurityParameters
        if data[idx] != 0x04:
            return None
        idx += 1
        if data[idx] & 0x80:
            len_bytes = data[idx] & 0x7f
            sec_len = int.from_bytes(data[idx+1:idx+1+len_bytes], 'big')
            idx += 1 + len_bytes
        else:
            sec_len = data[idx]
            idx += 1
        
        usm_data = data[idx:idx+sec_len]
        usm_idx = 0
        
        # Parse USM SEQUENCE
        if usm_data[usm_idx] != 0x30:
            return None
        usm_idx += 1
        if usm_data[usm_idx] & 0x80:
            len_bytes = usm_data[usm_idx] & 0x7f
            usm_idx += 1 + len_bytes
        else:
            usm_idx += 1
        
        # Skip engine ID
        if usm_data[usm_idx] != 0x04:
            return None
        usm_idx += 1
        if usm_data[usm_idx] & 0x80:
            len_bytes = usm_data[usm_idx] & 0x7f
            engine_len = int.from_bytes(usm_data[usm_idx+1:usm_idx+1+len_bytes], 'big')
            usm_idx += 1 + len_bytes
        else:
            engine_len = usm_data[usm_idx]
            usm_idx += 1
        usm_idx += engine_len
        
        # Skip msgAuthoritativeEngineBoots (INTEGER)
        if usm_data[usm_idx] != 0x02:
            return None
        usm_idx += 1
        boots_len = usm_data[usm_idx]
        usm_idx += 1 + boots_len
        
        # Skip msgAuthoritativeEngineTime (INTEGER)
        if usm_data[usm_idx] != 0x02:
            return None
        usm_idx += 1
        time_len = usm_data[usm_idx]
        usm_idx += 1 + time_len
        
        # Get msgUserName (OCTET STRING)
        if usm_data[usm_idx] != 0x04:
            return None
        usm_idx += 1
        if usm_data[usm_idx] & 0x80:
            len_bytes = usm_data[usm_idx] & 0x7f
            name_len = int.from_bytes(usm_data[usm_idx+1:usm_idx+1+len_bytes], 'big')
            usm_idx += 1 + len_bytes
        else:
            name_len = usm_data[usm_idx]
            usm_idx += 1
        
        username = usm_data[usm_idx:usm_idx+name_len].decode('utf-8')
        return username
        
    except Exception as e:
        logger.debug(f"Failed to extract username: {e}")
        return None


def _parse_ber_length(data: bytes, idx: int) -> Tuple[int, int]:
    """Parse BER length and return (length, new_idx)."""
    if data[idx] & 0x80:
        len_bytes = data[idx] & 0x7f
        length = int.from_bytes(data[idx+1:idx+1+len_bytes], 'big')
        return length, idx + 1 + len_bytes
    else:
        return data[idx], idx + 1


def _localize_key(passphrase: str, engine_id: bytes, auth_protocol: str) -> bytes:
    """
    Localize a passphrase to an engine-specific key using SNMPv3 key localization.
    
    Args:
        passphrase: User passphrase
        engine_id: Engine ID bytes
        auth_protocol: Authentication protocol name
        
    Returns:
        Localized key bytes
    """
    # Select hash function based on auth protocol
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
    
    # Step 1: Generate Ku from passphrase (password to key)
    password = passphrase.encode('utf-8')
    
    # Repeat password to create 1MB of data
    h = hash_func()
    password_buf = password * ((1048576 // len(password)) + 1)
    
    for i in range(0, 1048576, 64):
        h.update(password_buf[i:i+64])
    
    ku = h.digest()
    
    # Step 2: Localize Ku with engine ID to get Kul
    h = hash_func()
    h.update(ku + engine_id + ku)
    kul = h.digest()
    
    return kul


class SNMPv3Decryptor:
    """
    Decrypts SNMPv3 messages and converts them to SNMPv2c format.
    """
    
    def __init__(self, credential_store):
        """
        Initialize SNMPv3 decryptor.
        
        Args:
            credential_store: SNMPv3CredentialStore instance
        """
        self.credential_store = credential_store
        logger.info("SNMPv3 Decryptor initialized")
    
    def decrypt_snmpv3_trap(
        self,
        snmpv3_message: bytes,
        engine_id: str = None
    ) -> Optional[Tuple[str, Dict]]:
        """
        Decrypt SNMPv3 trap message.
        
        Args:
            snmpv3_message: Raw SNMPv3 message bytes
            engine_id: Optional Engine ID (will be extracted if not provided)
            
        Returns:
            Tuple of (engine_id, trap_data_dict) or None if decryption fails
        """
        if not PYSNMP_AVAILABLE:
            logger.debug("pysnmp not available for SNMPv3 decryption")
            return None
        
        # Extract engine ID and username from message
        if not engine_id:
            engine_id = extract_engine_id_from_bytes(snmpv3_message)
            if not engine_id:
                logger.debug("Could not extract engine ID from SNMPv3 message")
                return None
        
        engine_id = engine_id.lower()
        username = extract_username_from_bytes(snmpv3_message)
        
        logger.debug(f"SNMPv3 trap from engine {engine_id}, user {username}")
        
        # Get credentials for this engine
        users = self.credential_store.get_users_for_engine(engine_id)
        if not users:
            logger.warning(f"No credentials for engine ID: {engine_id}")
            return None
        
        # If we extracted a username, try that user first
        if username:
            users = sorted(users, key=lambda u: u.username != username)
        
        # Try decryption with each user
        for user in users:
            try:
                result = self._try_decrypt_with_user(snmpv3_message, engine_id, user)
                if result:
                    logger.info(f"Decrypted SNMPv3 trap with user {user.username}")
                    return (engine_id, result)
            except Exception as e:
                logger.debug(f"Decryption failed with user {user.username}: {e}")
                continue
        
        logger.warning(f"Failed to decrypt SNMPv3 trap for engine {engine_id}")
        return None
    
    def _try_decrypt_with_user(
        self,
        message: bytes,
        engine_id: str,
        user
    ) -> Optional[Dict]:
        """
        Attempt to decrypt message with specific user credentials.
        """
        try:
            # Parse the SNMPv3 message structure manually
            idx = 0
            
            # Outer SEQUENCE
            if message[idx] != 0x30:
                return None
            idx += 1
            _, idx = _parse_ber_length(message, idx)
            
            # Version INTEGER (should be 3)
            if message[idx] != 0x02:
                return None
            idx += 1
            ver_len = message[idx]
            idx += 1
            version = int.from_bytes(message[idx:idx+ver_len], 'big')
            if version != 3:
                return None
            idx += ver_len
            
            # msgGlobalData SEQUENCE
            if message[idx] != 0x30:
                return None
            idx += 1
            global_len, idx = _parse_ber_length(message, idx)
            
            # Extract msgID, msgMaxSize, msgFlags from msgGlobalData
            global_start = idx
            
            # msgID INTEGER
            if message[idx] != 0x02:
                return None
            idx += 1
            msgid_len = message[idx]
            idx += 1
            msg_id = int.from_bytes(message[idx:idx+msgid_len], 'big')
            idx += msgid_len
            
            # msgMaxSize INTEGER
            if message[idx] != 0x02:
                return None
            idx += 1
            maxsize_len = message[idx]
            idx += 1
            idx += maxsize_len
            
            # msgFlags OCTET STRING (1 byte)
            if message[idx] != 0x04:
                return None
            idx += 1
            flags_len = message[idx]
            idx += 1
            msg_flags = message[idx]
            idx += flags_len
            
            # Determine security level from flags
            auth_flag = bool(msg_flags & 0x01)
            priv_flag = bool(msg_flags & 0x02)
            
            # Skip remaining msgGlobalData (msgSecurityModel)
            idx = global_start + global_len
            
            # msgSecurityParameters OCTET STRING
            if message[idx] != 0x04:
                return None
            idx += 1
            sec_len, idx = _parse_ber_length(message, idx)
            
            # Parse USM security parameters
            usm_data = message[idx:idx+sec_len]
            usm_params = self._parse_usm_params(usm_data)
            if not usm_params:
                return None
            
            idx += sec_len
            
            # msgData - either plaintext ScopedPDU or encryptedPDU
            if priv_flag:
                # Encrypted - OCTET STRING containing encrypted ScopedPDU
                if message[idx] != 0x04:
                    return None
                idx += 1
                encrypted_len, idx = _parse_ber_length(message, idx)
                encrypted_data = message[idx:idx+encrypted_len]
                
                # Decrypt the data
                if not CRYPTO_AVAILABLE:
                    logger.warning("Cannot decrypt - pycryptodome not available")
                    return None
                
                decrypted_data = self._decrypt_pdu(
                    encrypted_data,
                    user,
                    usm_params['priv_params'],
                    usm_params['engine_boots'],
                    usm_params['engine_time'],
                    bytes.fromhex(engine_id)
                )
                
                if decrypted_data is None:
                    return None
                
                # Parse the decrypted ScopedPDU
                scoped_pdu_data = decrypted_data
            else:
                # Plaintext ScopedPDU SEQUENCE
                if message[idx] != 0x30:
                    return None
                scoped_pdu_data = message[idx:]
            
            # Parse ScopedPDU to extract varbinds
            trap_data = self._parse_scoped_pdu(scoped_pdu_data)
            
            return trap_data
            
        except Exception as e:
            logger.debug(f"Decryption attempt failed: {e}")
            import traceback
            logger.debug(traceback.format_exc())
            return None
    
    def _parse_usm_params(self, usm_data: bytes) -> Optional[Dict]:
        """Parse USM security parameters."""
        try:
            idx = 0
            
            # SEQUENCE
            if usm_data[idx] != 0x30:
                return None
            idx += 1
            _, idx = _parse_ber_length(usm_data, idx)
            
            # msgAuthoritativeEngineID OCTET STRING
            if usm_data[idx] != 0x04:
                return None
            idx += 1
            engine_len, idx = _parse_ber_length(usm_data, idx)
            engine_id = usm_data[idx:idx+engine_len]
            idx += engine_len
            
            # msgAuthoritativeEngineBoots INTEGER
            if usm_data[idx] != 0x02:
                return None
            idx += 1
            boots_len = usm_data[idx]
            idx += 1
            engine_boots = int.from_bytes(usm_data[idx:idx+boots_len], 'big')
            idx += boots_len
            
            # msgAuthoritativeEngineTime INTEGER
            if usm_data[idx] != 0x02:
                return None
            idx += 1
            time_len = usm_data[idx]
            idx += 1
            engine_time = int.from_bytes(usm_data[idx:idx+time_len], 'big')
            idx += time_len
            
            # msgUserName OCTET STRING
            if usm_data[idx] != 0x04:
                return None
            idx += 1
            name_len, idx = _parse_ber_length(usm_data, idx)
            username = usm_data[idx:idx+name_len].decode('utf-8')
            idx += name_len
            
            # msgAuthenticationParameters OCTET STRING
            if usm_data[idx] != 0x04:
                return None
            idx += 1
            auth_len, idx = _parse_ber_length(usm_data, idx)
            auth_params = usm_data[idx:idx+auth_len]
            idx += auth_len
            
            # msgPrivacyParameters OCTET STRING
            if usm_data[idx] != 0x04:
                return None
            idx += 1
            priv_len, idx = _parse_ber_length(usm_data, idx)
            priv_params = usm_data[idx:idx+priv_len]
            
            return {
                'engine_id': engine_id,
                'engine_boots': engine_boots,
                'engine_time': engine_time,
                'username': username,
                'auth_params': auth_params,
                'priv_params': priv_params
            }
            
        except Exception as e:
            logger.debug(f"Failed to parse USM params: {e}")
            return None
    
    def _decrypt_pdu(
        self,
        encrypted_data: bytes,
        user,
        priv_params: bytes,
        engine_boots: int,
        engine_time: int,
        engine_id: bytes
    ) -> Optional[bytes]:
        """Decrypt the encrypted PDU data."""
        try:
            priv_protocol = user.priv_protocol.upper()
            auth_protocol = user.auth_protocol.upper()
            
            # Localize the privacy key
            priv_key = _localize_key(user.priv_passphrase, engine_id, auth_protocol)
            
            if priv_protocol in ('DES', '3DES'):
                # DES decryption
                des_key = priv_key[:8]
                pre_iv = priv_key[8:16]
                iv = bytes(a ^ b for a, b in zip(pre_iv, priv_params[:8]))
                
                cipher = DES.new(des_key, DES.MODE_CBC, iv)
                decrypted = cipher.decrypt(encrypted_data)
                
            elif priv_protocol.startswith('AES'):
                # AES decryption
                if priv_protocol == 'AES128':
                    key_len = 16
                elif priv_protocol == 'AES192':
                    key_len = 24
                else:  # AES256
                    key_len = 32
                
                # Extend key if needed using key extension
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
                decrypted = cipher.decrypt(encrypted_data)
                
            else:
                logger.warning(f"Unsupported privacy protocol: {priv_protocol}")
                return None
            
            return decrypted
            
        except Exception as e:
            logger.debug(f"PDU decryption failed: {e}")
            return None
    
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
    
    def _parse_scoped_pdu(self, data: bytes) -> Optional[Dict]:
        """Parse ScopedPDU and extract trap varbinds."""
        try:
            idx = 0
            
            # ScopedPDU SEQUENCE
            if data[idx] != 0x30:
                return None
            idx += 1
            _, idx = _parse_ber_length(data, idx)
            
            # contextEngineID OCTET STRING
            if data[idx] != 0x04:
                return None
            idx += 1
            ctx_engine_len, idx = _parse_ber_length(data, idx)
            idx += ctx_engine_len
            
            # contextName OCTET STRING
            if data[idx] != 0x04:
                return None
            idx += 1
            ctx_name_len, idx = _parse_ber_length(data, idx)
            idx += ctx_name_len
            
            # PDU - could be various types, trap is typically 0xa7
            pdu_tag = data[idx]
            idx += 1
            pdu_len, idx = _parse_ber_length(data, idx)
            
            # Parse PDU contents
            # request-id INTEGER
            if data[idx] != 0x02:
                return None
            idx += 1
            reqid_len = data[idx]
            idx += 1
            request_id = int.from_bytes(data[idx:idx+reqid_len], 'big')
            idx += reqid_len
            
            # error-status INTEGER
            if data[idx] != 0x02:
                return None
            idx += 1
            err_len = data[idx]
            idx += 1 + err_len
            
            # error-index INTEGER
            if data[idx] != 0x02:
                return None
            idx += 1
            erridx_len = data[idx]
            idx += 1 + erridx_len
            
            # variable-bindings SEQUENCE
            if data[idx] != 0x30:
                return None
            idx += 1
            vb_len, idx = _parse_ber_length(data, idx)
            
            varbinds = []
            vb_end = idx + vb_len
            
            while idx < vb_end:
                # VarBind SEQUENCE
                if data[idx] != 0x30:
                    break
                idx += 1
                vb_item_len, idx = _parse_ber_length(data, idx)
                vb_item_end = idx + vb_item_len
                
                # name OBJECT IDENTIFIER
                if data[idx] != 0x06:
                    idx = vb_item_end
                    continue
                idx += 1
                oid_len, idx = _parse_ber_length(data, idx)
                oid_bytes = data[idx:idx+oid_len]
                oid_str = self._decode_oid(oid_bytes)
                idx += oid_len
                
                # value - various types
                value_tag = data[idx]
                idx += 1
                value_len, idx = _parse_ber_length(data, idx)
                value_bytes = data[idx:idx+value_len]
                
                value, value_type = self._decode_value(value_tag, value_bytes)
                
                varbinds.append({
                    'oid': oid_str,
                    'value': value,
                    'type': value_type,
                    'raw_tag': value_tag,
                    'raw_bytes': value_bytes
                })
                
                idx = vb_item_end
            
            return {
                'version': 'v3',
                'request_id': request_id,
                'varbinds': varbinds
            }
            
        except Exception as e:
            logger.debug(f"Failed to parse ScopedPDU: {e}")
            import traceback
            logger.debug(traceback.format_exc())
            return None
    
    def _decode_oid(self, oid_bytes: bytes) -> str:
        """Decode BER-encoded OID to string."""
        if not oid_bytes:
            return ""
        
        components = []
        
        # First byte encodes first two components
        first = oid_bytes[0]
        components.append(str(first // 40))
        components.append(str(first % 40))
        
        # Remaining bytes
        idx = 1
        while idx < len(oid_bytes):
            value = 0
            while idx < len(oid_bytes):
                byte = oid_bytes[idx]
                value = (value << 7) | (byte & 0x7f)
                idx += 1
                if not (byte & 0x80):
                    break
            components.append(str(value))
        
        return '.'.join(components)
    
    def _decode_value(self, tag: int, value_bytes: bytes) -> Tuple[Any, str]:
        """Decode BER value based on tag."""
        if tag == 0x02:  # INTEGER
            if not value_bytes:
                return 0, 'Integer'
            value = int.from_bytes(value_bytes, 'big', signed=True)
            return value, 'Integer'
        
        elif tag == 0x04:  # OCTET STRING
            try:
                return value_bytes.decode('utf-8'), 'OctetString'
            except UnicodeDecodeError:
                return value_bytes.hex(), 'OctetString'
        
        elif tag == 0x05:  # NULL
            return None, 'Null'
        
        elif tag == 0x06:  # OBJECT IDENTIFIER
            return self._decode_oid(value_bytes), 'ObjectIdentifier'
        
        elif tag == 0x40:  # IpAddress
            if len(value_bytes) == 4:
                return '.'.join(str(b) for b in value_bytes), 'IpAddress'
            return value_bytes.hex(), 'IpAddress'
        
        elif tag == 0x41:  # Counter32
            return int.from_bytes(value_bytes, 'big'), 'Counter32'
        
        elif tag == 0x42:  # Gauge32/Unsigned32
            return int.from_bytes(value_bytes, 'big'), 'Gauge32'
        
        elif tag == 0x43:  # TimeTicks
            return int.from_bytes(value_bytes, 'big'), 'TimeTicks'
        
        elif tag == 0x44:  # Opaque
            return value_bytes.hex(), 'Opaque'
        
        elif tag == 0x46:  # Counter64
            return int.from_bytes(value_bytes, 'big'), 'Counter64'
        
        else:
            # Unknown type - return hex
            return value_bytes.hex(), f'Unknown(0x{tag:02x})'
    
    def convert_to_snmpv2c(
        self,
        trap_data: Dict,
        community: str = "public"
    ) -> Optional[bytes]:
        """
        Convert decrypted SNMPv3 trap data to SNMPv2c format.
        
        Builds a proper SNMPv2c trap message from scratch using BER encoding.
        """
        try:
            # Build varbinds
            varbinds_bytes = b''
            
            for vb in trap_data.get('varbinds', []):
                oid_str = vb['oid']
                value = vb['value']
                value_type = vb['type']
                
                # Encode OID
                oid_encoded = self._encode_oid(oid_str)
                
                # Encode value based on type
                if 'raw_tag' in vb and 'raw_bytes' in vb:
                    # Use original encoding if available
                    value_encoded = bytes([vb['raw_tag']]) + self._encode_length(len(vb['raw_bytes'])) + vb['raw_bytes']
                else:
                    value_encoded = self._encode_value(value, value_type)
                
                # VarBind SEQUENCE
                vb_content = oid_encoded + value_encoded
                vb_bytes = bytes([0x30]) + self._encode_length(len(vb_content)) + vb_content
                varbinds_bytes += vb_bytes
            
            # VarBindList SEQUENCE
            varbind_list = bytes([0x30]) + self._encode_length(len(varbinds_bytes)) + varbinds_bytes
            
            # Build PDU
            request_id = trap_data.get('request_id', 0)
            request_id_bytes = self._encode_integer(request_id)
            error_status = self._encode_integer(0)
            error_index = self._encode_integer(0)
            
            pdu_content = request_id_bytes + error_status + error_index + varbind_list
            
            # SNMPv2-Trap-PDU (implicit tag 0xa7)
            pdu = bytes([0xa7]) + self._encode_length(len(pdu_content)) + pdu_content
            
            # Build message
            version = self._encode_integer(1)  # SNMPv2c = version 1
            community_bytes = bytes([0x04]) + self._encode_length(len(community)) + community.encode('utf-8')
            
            message_content = version + community_bytes + pdu
            message = bytes([0x30]) + self._encode_length(len(message_content)) + message_content
            
            logger.debug(f"Built SNMPv2c message: {len(message)} bytes, {len(trap_data.get('varbinds', []))} varbinds")
            
            return message
            
        except Exception as e:
            logger.error(f"SNMPv2c conversion failed: {e}")
            import traceback
            logger.debug(traceback.format_exc())
            return None
    
    def _encode_length(self, length: int) -> bytes:
        """Encode BER length."""
        if length < 128:
            return bytes([length])
        elif length < 256:
            return bytes([0x81, length])
        elif length < 65536:
            return bytes([0x82, (length >> 8) & 0xff, length & 0xff])
        else:
            return bytes([0x83, (length >> 16) & 0xff, (length >> 8) & 0xff, length & 0xff])
    
    def _encode_integer(self, value: int) -> bytes:
        """Encode BER INTEGER."""
        if value == 0:
            return bytes([0x02, 0x01, 0x00])
        
        # Handle negative numbers
        if value < 0:
            # Two's complement
            byte_len = (value.bit_length() + 8) // 8
            value_bytes = value.to_bytes(byte_len, 'big', signed=True)
        else:
            byte_len = (value.bit_length() + 7) // 8
            value_bytes = value.to_bytes(byte_len, 'big')
            # Add leading zero if high bit is set
            if value_bytes[0] & 0x80:
                value_bytes = bytes([0x00]) + value_bytes
        
        return bytes([0x02]) + self._encode_length(len(value_bytes)) + value_bytes
    
    def _encode_oid(self, oid_str: str) -> bytes:
        """Encode OID string to BER."""
        components = [int(c) for c in oid_str.split('.') if c]
        
        if len(components) < 2:
            return bytes([0x06, 0x00])
        
        # First two components combined
        result = bytes([components[0] * 40 + components[1]])
        
        # Remaining components
        for comp in components[2:]:
            if comp < 128:
                result += bytes([comp])
            else:
                # Multi-byte encoding
                enc = []
                while comp > 0:
                    enc.insert(0, (comp & 0x7f) | 0x80)
                    comp >>= 7
                enc[-1] &= 0x7f  # Clear high bit of last byte
                result += bytes(enc)
        
        return bytes([0x06]) + self._encode_length(len(result)) + result
    
    def _encode_value(self, value: Any, value_type: str) -> bytes:
        """Encode value based on type."""
        if value_type == 'Integer' or 'Integer' in value_type:
            return self._encode_integer(int(value) if value else 0)
        
        elif value_type == 'OctetString':
            if isinstance(value, bytes):
                data = value
            else:
                data = str(value).encode('utf-8')
            return bytes([0x04]) + self._encode_length(len(data)) + data
        
        elif value_type == 'ObjectIdentifier':
            return self._encode_oid(str(value))
        
        elif value_type == 'IpAddress':
            parts = str(value).split('.')
            if len(parts) == 4:
                data = bytes([int(p) for p in parts])
            else:
                data = bytes.fromhex(str(value))
            return bytes([0x40]) + self._encode_length(len(data)) + data
        
        elif value_type == 'Counter32':
            val = int(value) if value else 0
            data = val.to_bytes((val.bit_length() + 7) // 8 or 1, 'big')
            return bytes([0x41]) + self._encode_length(len(data)) + data
        
        elif value_type == 'Gauge32':
            val = int(value) if value else 0
            data = val.to_bytes((val.bit_length() + 7) // 8 or 1, 'big')
            return bytes([0x42]) + self._encode_length(len(data)) + data
        
        elif value_type == 'TimeTicks':
            val = int(value) if value else 0
            data = val.to_bytes((val.bit_length() + 7) // 8 or 1, 'big')
            return bytes([0x43]) + self._encode_length(len(data)) + data
        
        elif value_type == 'Counter64':
            val = int(value) if value else 0
            data = val.to_bytes((val.bit_length() + 7) // 8 or 1, 'big')
            return bytes([0x46]) + self._encode_length(len(data)) + data
        
        elif value_type == 'Null':
            return bytes([0x05, 0x00])
        
        else:
            # Default to OctetString
            if isinstance(value, bytes):
                data = value
            else:
                data = str(value).encode('utf-8')
            return bytes([0x04]) + self._encode_length(len(data)) + data


# Global decryptor instance
_snmpv3_decryptor: Optional[SNMPv3Decryptor] = None


def get_snmpv3_decryptor() -> Optional[SNMPv3Decryptor]:
    """Get the global SNMPv3 decryptor instance."""
    return _snmpv3_decryptor


def initialize_snmpv3_decryptor() -> Optional[SNMPv3Decryptor]:
    """Initialize the global SNMPv3 decryptor."""
    global _snmpv3_decryptor
    
    if not PYSNMP_AVAILABLE:
        logger.warning("Cannot initialize SNMPv3 decryptor - pysnmp not available")
        return None
    
    from .snmpv3_credentials import get_credential_store
    
    credential_store = get_credential_store()
    _snmpv3_decryptor = SNMPv3Decryptor(credential_store)
    
    logger.info("SNMPv3 decryptor initialized")
    return _snmpv3_decryptor


def decrypt_and_convert_trap(
    snmpv3_message: bytes,
    engine_id: str = None,
    community: str = "public"
) -> Optional[bytes]:
    """
    Convenience function to decrypt SNMPv3 trap and convert to SNMPv2c.
    """
    decryptor = get_snmpv3_decryptor()
    
    if not decryptor:
        logger.warning("SNMPv3 decryptor not initialized")
        return None
    
    result = decryptor.decrypt_snmpv3_trap(snmpv3_message, engine_id)
    if not result:
        return None
    
    engine_id, trap_data = result
    return decryptor.convert_to_snmpv2c(trap_data, community)
