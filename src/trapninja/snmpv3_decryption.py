#!/usr/bin/env python3
"""
TrapNinja SNMPv3 Decryption Module

Handles decryption of SNMPv3 traps and conversion to SNMPv2c format.
Integrates with the credential management system for authentication.

This module uses pysnmp's USM (User-based Security Model) to properly
decrypt SNMPv3 messages before converting them to SNMPv2c format.
"""
import logging
import struct
from typing import Optional, Tuple, Dict, List, Any

try:
    from pysnmp.hlapi import (
        SnmpEngine, CommunityData, UdpTransportTarget,
        ContextData, ObjectType, ObjectIdentity,
        UsmUserData, usmHMACMD5AuthProtocol, usmHMACSHAAuthProtocol,
        usmHMAC128SHA224AuthProtocol, usmHMAC192SHA256AuthProtocol,
        usmHMAC256SHA384AuthProtocol, usmHMAC384SHA512AuthProtocol,
        usmDESPrivProtocol, usm3DESEDEPrivProtocol,
        usmAesCfb128Protocol, usmAesCfb192Protocol, usmAesCfb256Protocol,
        usmNoAuthProtocol, usmNoPrivProtocol
    )
    from pysnmp.proto import api as snmp_api
    from pysnmp.proto.rfc1902 import (
        Integer32, OctetString, ObjectIdentifier as OID,
        IpAddress, Counter32, Gauge32, TimeTicks, Counter64, Opaque
    )
    from pysnmp.proto.rfc1905 import VarBind, VarBindList
    from pyasn1.codec.ber import decoder, encoder
    from pyasn1.type import univ, tag
    PYSNMP_AVAILABLE = True
except ImportError as e:
    PYSNMP_AVAILABLE = False
    import_error = str(e)

# Get logger instance
logger = logging.getLogger("trapninja")

# Check if pysnmp is available
if not PYSNMP_AVAILABLE:
    logger.warning(f"pysnmp not available: {import_error}")
    logger.warning("SNMPv3 decryption will not be available")
    logger.warning("Install with: pip3 install --break-system-packages pysnmp pyasn1")


# Protocol mappings
AUTH_PROTOCOLS = {
    'NONE': usmNoAuthProtocol if PYSNMP_AVAILABLE else None,
    'MD5': usmHMACMD5AuthProtocol if PYSNMP_AVAILABLE else None,
    'SHA': usmHMACSHAAuthProtocol if PYSNMP_AVAILABLE else None,
    'SHA224': usmHMAC128SHA224AuthProtocol if PYSNMP_AVAILABLE else None,
    'SHA256': usmHMAC192SHA256AuthProtocol if PYSNMP_AVAILABLE else None,
    'SHA384': usmHMAC256SHA384AuthProtocol if PYSNMP_AVAILABLE else None,
    'SHA512': usmHMAC384SHA512AuthProtocol if PYSNMP_AVAILABLE else None,
}

PRIV_PROTOCOLS = {
    'NONE': usmNoPrivProtocol if PYSNMP_AVAILABLE else None,
    'DES': usmDESPrivProtocol if PYSNMP_AVAILABLE else None,
    '3DES': usm3DESEDEPrivProtocol if PYSNMP_AVAILABLE else None,
    'AES128': usmAesCfb128Protocol if PYSNMP_AVAILABLE else None,
    'AES192': usmAesCfb192Protocol if PYSNMP_AVAILABLE else None,
    'AES256': usmAesCfb256Protocol if PYSNMP_AVAILABLE else None,
}


def extract_engine_id_from_bytes(data: bytes) -> Optional[str]:
    """
    Extract the authoritative engine ID from raw SNMPv3 message bytes.
    
    SNMPv3 message structure:
    - SEQUENCE
      - INTEGER (version = 3)
      - SEQUENCE (msgGlobalData)
        - INTEGER (msgID)
        - INTEGER (msgMaxSize)
        - OCTET STRING (msgFlags)
        - INTEGER (msgSecurityModel)
      - OCTET STRING (msgSecurityParameters - contains USM data)
      - SEQUENCE (msgData - encrypted or plaintext)
    
    The USM security parameters contain:
    - SEQUENCE
      - OCTET STRING (msgAuthoritativeEngineID)
      - ...
    
    Args:
        data: Raw SNMPv3 message bytes
        
    Returns:
        Engine ID as hex string, or None if extraction fails
    """
    try:
        # Quick check for SNMPv3
        if len(data) < 10:
            return None
        
        # Parse the outer SEQUENCE
        idx = 0
        if data[idx] != 0x30:  # SEQUENCE tag
            return None
        idx += 1
        
        # Skip length
        if data[idx] & 0x80:
            len_bytes = data[idx] & 0x7f
            idx += 1 + len_bytes
        else:
            idx += 1
        
        # Check version (should be INTEGER 3)
        if data[idx] != 0x02:  # INTEGER tag
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
        
        # Now at msgSecurityParameters (OCTET STRING containing BER-encoded USM)
        if data[idx] != 0x04:  # OCTET STRING tag
            return None
        idx += 1
        if data[idx] & 0x80:
            len_bytes = data[idx] & 0x7f
            sec_len = int.from_bytes(data[idx+1:idx+1+len_bytes], 'big')
            idx += 1 + len_bytes
        else:
            sec_len = data[idx]
            idx += 1
        
        # Parse USM security parameters (nested SEQUENCE)
        usm_data = data[idx:idx+sec_len]
        usm_idx = 0
        
        if usm_data[usm_idx] != 0x30:  # SEQUENCE
            return None
        usm_idx += 1
        if usm_data[usm_idx] & 0x80:
            len_bytes = usm_data[usm_idx] & 0x7f
            usm_idx += 1 + len_bytes
        else:
            usm_idx += 1
        
        # First element is msgAuthoritativeEngineID (OCTET STRING)
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
    
    Args:
        data: Raw SNMPv3 message bytes
        
    Returns:
        Username string, or None if extraction fails
    """
    try:
        # Similar parsing as engine ID, but go further into USM params
        idx = 0
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


class SNMPv3Decryptor:
    """
    Decrypts SNMPv3 messages and converts them to SNMPv2c format.
    
    Uses pysnmp's USM implementation for proper decryption.
    """
    
    def __init__(self, credential_store):
        """
        Initialize SNMPv3 decryptor.
        
        Args:
            credential_store: SNMPv3CredentialStore instance
        """
        self.credential_store = credential_store
        self._engines: Dict[str, SnmpEngine] = {}
        logger.info("SNMPv3 Decryptor initialized")
    
    def _get_user_data(self, user) -> Optional['UsmUserData']:
        """
        Create UsmUserData from stored credentials.
        
        Args:
            user: SNMPv3User object
            
        Returns:
            UsmUserData instance or None
        """
        if not PYSNMP_AVAILABLE:
            return None
        
        auth_proto = AUTH_PROTOCOLS.get(user.auth_protocol.upper())
        priv_proto = PRIV_PROTOCOLS.get(user.priv_protocol.upper())
        
        if auth_proto is None or priv_proto is None:
            logger.warning(f"Unknown protocol for user {user.username}")
            return None
        
        try:
            return UsmUserData(
                userName=user.username,
                authKey=user.auth_passphrase if user.auth_passphrase else None,
                privKey=user.priv_passphrase if user.priv_passphrase else None,
                authProtocol=auth_proto,
                privProtocol=priv_proto
            )
        except Exception as e:
            logger.error(f"Failed to create UsmUserData: {e}")
            return None
    
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
            logger.warning("pysnmp not available for SNMPv3 decryption")
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
            for user in users:
                if user.username == username:
                    users = [user] + [u for u in users if u.username != username]
                    break
        
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
        
        This uses pysnmp's internal message processing to handle decryption.
        
        Args:
            message: Raw SNMPv3 message bytes
            engine_id: Engine ID hex string
            user: SNMPv3User object
            
        Returns:
            Trap data dictionary or None
        """
        try:
            from pysnmp.proto.secmod.rfc3414.service import SnmpUSMSecurityModel
            from pysnmp.proto.secmod.rfc3414 import auth, priv
            from pysnmp.proto import rfc3411, rfc3412
            from pysnmp.proto.mpmod.rfc3412 import SnmpV3MessageProcessingModel
            from pysnmp.entity import engine as snmp_engine
            from pysnmp.entity import config as snmp_config
            from pyasn1.codec.ber import decoder as ber_decoder
            from pyasn1.codec.ber import encoder as ber_encoder
            
            # Create or get SNMP engine for this engine ID
            engine_id_bytes = bytes.fromhex(engine_id)
            
            # Create a new engine each time to avoid caching issues
            snmpEngine = snmp_engine.SnmpEngine()
            
            # Configure the user
            auth_proto = AUTH_PROTOCOLS.get(user.auth_protocol.upper(), usmNoAuthProtocol)
            priv_proto = PRIV_PROTOCOLS.get(user.priv_protocol.upper(), usmNoPrivProtocol)
            
            snmp_config.addV3User(
                snmpEngine,
                user.username,
                auth_proto,
                user.auth_passphrase if user.auth_passphrase else None,
                priv_proto,
                user.priv_passphrase if user.priv_passphrase else None,
                securityEngineId=univ.OctetString(hexValue=engine_id)
            )
            
            # Use pysnmp's message processing to decode the message
            from pysnmp.proto.rfc3412 import MsgAndPduDispatcher
            from pysnmp.proto import errind
            
            # Parse the outer structure first
            msg, remaining = ber_decoder.decode(message, asn1Spec=rfc3412.SNMPv3Message())
            
            # Extract components we need
            msg_version = msg.getComponentByName('msgVersion')
            msg_global_data = msg.getComponentByName('msgGlobalData')
            msg_security_params = msg.getComponentByName('msgSecurityParameters')
            msg_data = msg.getComponentByName('msgData')
            
            # Decode security parameters
            usm_params, _ = ber_decoder.decode(
                msg_security_params,
                asn1Spec=rfc3411.UsmSecurityParameters()
            )
            
            msg_auth_engine_id = usm_params.getComponentByName('msgAuthoritativeEngineID')
            msg_auth_engine_boots = usm_params.getComponentByName('msgAuthoritativeEngineBoots')
            msg_auth_engine_time = usm_params.getComponentByName('msgAuthoritativeEngineTime')
            msg_user_name = usm_params.getComponentByName('msgUserName')
            msg_auth_params = usm_params.getComponentByName('msgAuthenticationParameters')
            msg_priv_params = usm_params.getComponentByName('msgPrivacyParameters')
            
            # Check if message is encrypted
            scoped_pdu_data = msg_data.getComponentByName('encryptedPDU')
            if scoped_pdu_data is None:
                # Try plaintext
                scoped_pdu_data = msg_data.getComponentByName('plaintext')
            
            if scoped_pdu_data is None:
                logger.debug("No PDU data found in message")
                return None
            
            # If encrypted, we need to decrypt
            if msg_data.getName() == 'encryptedPDU':
                encrypted_data = bytes(scoped_pdu_data)
                
                # Get the privacy module
                if user.priv_protocol.upper() == 'NONE':
                    logger.debug("Message appears encrypted but user has no priv protocol")
                    return None
                
                # Decrypt using the appropriate algorithm
                decrypted_data = self._decrypt_pdu(
                    encrypted_data,
                    user,
                    bytes(msg_priv_params),
                    int(msg_auth_engine_boots),
                    int(msg_auth_engine_time),
                    bytes(msg_auth_engine_id)
                )
                
                if decrypted_data is None:
                    return None
                
                # Decode the decrypted ScopedPDU
                scoped_pdu, _ = ber_decoder.decode(
                    decrypted_data,
                    asn1Spec=rfc3412.ScopedPDU()
                )
            else:
                # Already plaintext
                scoped_pdu = scoped_pdu_data
            
            # Extract the PDU from ScopedPDU
            pdu = scoped_pdu.getComponentByName('data')
            
            # Get the actual PDU (could be various types)
            # For traps, it should be SNMPv2-Trap-PDU
            trap_pdu = pdu.getComponent()
            
            # Extract varbinds
            varbind_list = trap_pdu.getComponentByName('variable-bindings')
            if varbind_list is None:
                # Try alternative names
                for name in ['variableBindings', 'variable_bindings']:
                    varbind_list = trap_pdu.getComponentByName(name)
                    if varbind_list:
                        break
            
            if varbind_list is None:
                # Last resort - try positional access (index 3 for most PDUs)
                try:
                    varbind_list = trap_pdu.getComponentByPosition(3)
                except Exception:
                    logger.debug("Could not find varbinds in PDU")
                    return None
            
            # Build trap data dictionary
            trap_data = {
                'version': 'v3',
                'engine_id': engine_id,
                'username': str(msg_user_name),
                'varbinds': []
            }
            
            # Extract request-id if present
            try:
                request_id = trap_pdu.getComponentByName('request-id')
                if request_id is not None:
                    trap_data['request_id'] = int(request_id)
            except Exception:
                trap_data['request_id'] = 0
            
            # Process varbinds
            for vb in varbind_list:
                try:
                    oid = vb.getComponentByName('name')
                    value = vb.getComponentByName('value')
                    
                    # Get the actual value component
                    if hasattr(value, 'getComponent'):
                        actual_value = value.getComponent()
                    else:
                        actual_value = value
                    
                    trap_data['varbinds'].append({
                        'oid': str(oid),
                        'value': actual_value,
                        'type': actual_value.__class__.__name__
                    })
                except Exception as e:
                    logger.debug(f"Error extracting varbind: {e}")
            
            logger.debug(f"Extracted {len(trap_data['varbinds'])} varbinds")
            return trap_data
            
        except Exception as e:
            logger.debug(f"Decryption attempt failed: {e}")
            import traceback
            logger.debug(traceback.format_exc())
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
        """
        Decrypt the encrypted PDU data.
        
        Args:
            encrypted_data: Encrypted PDU bytes
            user: SNMPv3User with credentials
            priv_params: Privacy parameters from message
            engine_boots: Engine boots value
            engine_time: Engine time value
            engine_id: Engine ID bytes
            
        Returns:
            Decrypted PDU bytes or None
        """
        try:
            from pysnmp.proto.secmod.rfc3414.priv import des, aes, aes192, aes256
            from pysnmp.proto.secmod.rfc3414.auth import hmacmd5, hmacsha
            from Crypto.Cipher import DES, AES
            
            priv_protocol = user.priv_protocol.upper()
            auth_protocol = user.auth_protocol.upper()
            
            # Localize the privacy key
            priv_key = self._localize_key(
                user.priv_passphrase,
                engine_id,
                auth_protocol
            )
            
            if priv_protocol in ('DES', '3DES'):
                # DES decryption
                # DES key is first 8 bytes of localized key
                des_key = priv_key[:8]
                # IV is priv_params XOR'd with last 8 bytes of key
                pre_iv = priv_key[8:16]
                iv = bytes(a ^ b for a, b in zip(pre_iv, priv_params[:8]))
                
                cipher = DES.new(des_key, DES.MODE_CBC, iv)
                decrypted = cipher.decrypt(encrypted_data)
                
            elif priv_protocol.startswith('AES'):
                # AES decryption
                # Key length depends on variant
                if priv_protocol == 'AES128':
                    key_len = 16
                elif priv_protocol == 'AES192':
                    key_len = 24
                else:  # AES256
                    key_len = 32
                
                aes_key = priv_key[:key_len]
                
                # IV for AES: engineBoots(4) + engineTime(4) + privParams(8)
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
            
        except ImportError:
            logger.error("pycryptodome required for SNMPv3 decryption. "
                        "Install with: pip3 install --break-system-packages pycryptodome")
            return None
        except Exception as e:
            logger.debug(f"PDU decryption failed: {e}")
            return None
    
    def _localize_key(
        self,
        passphrase: str,
        engine_id: bytes,
        auth_protocol: str
    ) -> bytes:
        """
        Localize a passphrase to an engine-specific key.
        
        Uses the standard SNMPv3 key localization algorithm.
        
        Args:
            passphrase: User passphrase
            engine_id: Engine ID bytes
            auth_protocol: Authentication protocol name
            
        Returns:
            Localized key bytes
        """
        import hashlib
        
        # Select hash function
        if auth_protocol in ('MD5',):
            hash_func = hashlib.md5
            digest_size = 16
        else:
            # SHA and variants
            if auth_protocol == 'SHA224':
                hash_func = hashlib.sha224
                digest_size = 28
            elif auth_protocol == 'SHA256':
                hash_func = hashlib.sha256
                digest_size = 32
            elif auth_protocol == 'SHA384':
                hash_func = hashlib.sha384
                digest_size = 48
            elif auth_protocol == 'SHA512':
                hash_func = hashlib.sha512
                digest_size = 64
            else:  # Default SHA1
                hash_func = hashlib.sha1
                digest_size = 20
        
        # Step 1: Generate Ku from passphrase
        # Repeat passphrase to get 1MB of data
        password = passphrase.encode('utf-8')
        password_len = len(password)
        
        h = hash_func()
        count = 0
        password_buf = password * (1048576 // password_len + 1)
        
        for i in range(0, 1048576, 64):
            h.update(password_buf[i:i+64])
        
        ku = h.digest()
        
        # Step 2: Localize Ku with engine ID to get Kul
        h = hash_func()
        h.update(ku + engine_id + ku)
        kul = h.digest()
        
        return kul
    
    def convert_to_snmpv2c(
        self,
        trap_data: Dict,
        community: str = "public"
    ) -> Optional[bytes]:
        """
        Convert decrypted SNMPv3 trap data to SNMPv2c format.
        
        Args:
            trap_data: Trap data dictionary from decrypt_snmpv3_trap
            community: SNMPv2c community string to use
            
        Returns:
            SNMPv2c trap message bytes, or None if conversion fails
        """
        if not PYSNMP_AVAILABLE:
            return None
        
        try:
            from pysnmp.proto.api import v2c
            from pyasn1.codec.ber import encoder as ber_encoder
            
            # Create SNMPv2c message
            msg = v2c.Message()
            msg.setComponentByPosition(0, v2c.Integer(1))  # version = 1 (SNMPv2c)
            msg.setComponentByPosition(1, v2c.OctetString(community))
            
            # Create trap PDU
            pdu = v2c.TrapPDU()
            pdu.setComponentByPosition(0, v2c.Integer(trap_data.get('request_id', 0)))
            pdu.setComponentByPosition(1, v2c.Integer(0))  # error-status
            pdu.setComponentByPosition(2, v2c.Integer(0))  # error-index
            
            # Create varbind list
            varbinds = v2c.VarBindList()
            
            for idx, vb in enumerate(trap_data['varbinds']):
                var_bind = v2c.VarBind()
                
                # Set OID
                oid_str = vb['oid']
                var_bind.setComponentByPosition(0, v2c.ObjectIdentifier(oid_str))
                
                # Set value - handle the actual pysnmp value objects
                value = vb['value']
                value_type = vb['type']
                
                if hasattr(value, 'prettyPrint'):
                    # It's already a pysnmp object, use it directly
                    var_bind.setComponentByPosition(1, value)
                else:
                    # Convert string representation to appropriate type
                    value_str = str(value)
                    
                    if 'Integer' in value_type:
                        try:
                            var_bind.setComponentByPosition(1, Integer32(int(value_str)))
                        except ValueError:
                            var_bind.setComponentByPosition(1, OctetString(value_str))
                    elif 'ObjectIdentifier' in value_type or 'ObjectName' in value_type:
                        var_bind.setComponentByPosition(1, OID(value_str))
                    elif 'IpAddress' in value_type:
                        var_bind.setComponentByPosition(1, IpAddress(value_str))
                    elif 'Counter32' in value_type or 'Counter' in value_type:
                        var_bind.setComponentByPosition(1, Counter32(int(value_str)))
                    elif 'Counter64' in value_type:
                        var_bind.setComponentByPosition(1, Counter64(int(value_str)))
                    elif 'Gauge' in value_type or 'Unsigned' in value_type:
                        var_bind.setComponentByPosition(1, Gauge32(int(value_str)))
                    elif 'TimeTicks' in value_type:
                        var_bind.setComponentByPosition(1, TimeTicks(int(value_str)))
                    else:
                        # Default to OctetString
                        if isinstance(value, bytes):
                            var_bind.setComponentByPosition(1, OctetString(value))
                        else:
                            var_bind.setComponentByPosition(1, OctetString(str(value)))
                
                varbinds.setComponentByPosition(idx, var_bind)
            
            pdu.setComponentByPosition(3, varbinds)
            msg.setComponentByPosition(2, pdu)
            
            # Encode to bytes
            encoded = ber_encoder.encode(msg)
            
            logger.debug(f"Converted to SNMPv2c: {len(encoded)} bytes, "
                        f"{len(trap_data['varbinds'])} varbinds")
            
            return bytes(encoded)
            
        except Exception as e:
            logger.error(f"SNMPv2c conversion failed: {e}")
            import traceback
            logger.debug(traceback.format_exc())
            return None


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
    
    Args:
        snmpv3_message: Raw SNMPv3 message bytes
        engine_id: Optional Engine ID
        community: SNMPv2c community string
        
    Returns:
        SNMPv2c trap message bytes, or None if operation fails
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
