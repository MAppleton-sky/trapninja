#!/usr/bin/env python3
"""
TrapNinja SNMPv3 Decryption Module

Handles decryption of SNMPv3 traps and conversion to SNMPv2c format.
Integrates with the credential management system for authentication.
"""
import logging
import binascii
from typing import Optional, Tuple, Dict

try:
    # Try importing from pysnmp
    from pysnmp.proto import api, rfc1902
    from pysnmp.entity import engine, config
    from pyasn1.codec.ber import encoder, decoder
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


class SNMPv3Decryptor:
    """
    Decrypts SNMPv3 messages and converts them to SNMPv2c format
    
    This class uses pysnmp to decrypt SNMPv3 traps using stored credentials,
    then converts the decrypted content to SNMPv2c format for forwarding.
    """
    
    def __init__(self, credential_store):
        """
        Initialize SNMPv3 decryptor
        
        Args:
            credential_store: SNMPv3CredentialStore instance
        """
        self.credential_store = credential_store
        self.snmp_engines: Dict[str, engine.SnmpEngine] = {}
        
        logger.info("SNMPv3 Decryptor initialized")
    
    def _get_or_create_engine(self, engine_id: str) -> engine.SnmpEngine:
        """
        Get or create an SNMP engine for a specific engine ID
        
        Args:
            engine_id: SNMP Engine ID (hex string)
            
        Returns:
            SnmpEngine instance
        """
        if engine_id not in self.snmp_engines:
            # Create new engine
            snmp_engine = engine.SnmpEngine(
                snmpEngineID=binascii.unhexlify(engine_id)
            )
            self.snmp_engines[engine_id] = snmp_engine
            logger.debug(f"Created SNMP engine for Engine ID: {engine_id}")
        
        return self.snmp_engines[engine_id]
    
    def _configure_user(self, snmp_engine: engine.SnmpEngine, user):
        """
        Configure SNMPv3 user credentials in the SNMP engine
        
        Args:
            snmp_engine: SnmpEngine instance
            user: SNMPv3User object with credentials
        """
        # Map protocol strings to pysnmp constants
        auth_protocol_map = {
            'NONE': config.usmNoAuthProtocol,
            'MD5': config.usmHMACMD5AuthProtocol,
            'SHA': config.usmHMACSHAAuthProtocol,
            'SHA224': config.usmHMAC128SHA224AuthProtocol,
            'SHA256': config.usmHMAC192SHA256AuthProtocol,
            'SHA384': config.usmHMAC256SHA384AuthProtocol,
            'SHA512': config.usmHMAC384SHA512AuthProtocol,
        }
        
        priv_protocol_map = {
            'NONE': config.usmNoPrivProtocol,
            'DES': config.usmDESPrivProtocol,
            '3DES': config.usm3DESEDEPrivProtocol,
            'AES128': config.usmAesCfb128Protocol,
            'AES192': config.usmAesCfb192Protocol,
            'AES256': config.usmAesCfb256Protocol,
        }
        
        # Get protocols
        auth_protocol = auth_protocol_map.get(
            user.auth_protocol.upper(),
            config.usmNoAuthProtocol
        )
        
        priv_protocol = priv_protocol_map.get(
            user.priv_protocol.upper(),
            config.usmNoPrivProtocol
        )
        
        # Add user to engine
        try:
            config.addV3User(
                snmp_engine,
                userName=user.username,
                authProtocol=auth_protocol,
                authKey=user.auth_passphrase if user.auth_passphrase else None,
                privProtocol=priv_protocol,
                privKey=user.priv_passphrase if user.priv_passphrase else None
            )
            
            logger.debug(f"Configured SNMPv3 user: {user.username}")
            
        except Exception as e:
            logger.error(f"Error configuring SNMPv3 user {user.username}: {e}")
            raise
    
    def extract_engine_id(self, snmpv3_message: bytes) -> Optional[str]:
        """
        Extract Engine ID from SNMPv3 message
        
        Args:
            snmpv3_message: Raw SNMPv3 message bytes
            
        Returns:
            Engine ID as hex string, or None if extraction fails
        """
        try:
            # Parse the message to extract engine ID
            msg = api.Message()
            msg.setComponentByPosition(0, api.Integer(3))  # SNMPv3
            
            # Decode the message
            remaining_msg = msg.clone()
            while snmpv3_message:
                try:
                    remaining_msg, snmpv3_message = decoder.decode(
                        snmpv3_message, asn1Spec=remaining_msg
                    )
                except Exception:
                    break
            
            # Extract engine ID from msgAuthoritativeEngineID
            if remaining_msg.hasComponentByPosition(3):
                header_data = remaining_msg.getComponentByPosition(3)
                if header_data.hasComponentByPosition(2):
                    engine_id_bytes = bytes(header_data.getComponentByPosition(2))
                    engine_id = binascii.hexlify(engine_id_bytes).decode()
                    logger.debug(f"Extracted Engine ID: {engine_id}")
                    return engine_id
            
            return None
            
        except Exception as e:
            logger.debug(f"Failed to extract Engine ID: {e}")
            return None
    
    def decrypt_snmpv3_trap(
        self,
        snmpv3_message: bytes,
        engine_id: str = None
    ) -> Optional[Tuple[str, Dict]]:
        """
        Decrypt SNMPv3 trap message
        
        Args:
            snmpv3_message: Raw SNMPv3 message bytes
            engine_id: Optional Engine ID (will be extracted if not provided)
            
        Returns:
            Tuple of (engine_id, trap_data_dict) or None if decryption fails
        """
        # Extract engine ID if not provided
        if not engine_id:
            engine_id = self.extract_engine_id(snmpv3_message)
            if not engine_id:
                logger.warning("Could not extract Engine ID from SNMPv3 message")
                return None
        
        # Normalize engine ID
        engine_id = engine_id.lower()
        
        # Get users for this engine
        users = self.credential_store.get_users_for_engine(engine_id)
        if not users:
            logger.warning(f"No credentials configured for Engine ID: {engine_id}")
            return None
        
        # Try each user until one succeeds
        for user in users:
            try:
                # Get or create engine for this engine ID
                snmp_engine = self._get_or_create_engine(engine_id)
                
                # Configure user credentials
                self._configure_user(snmp_engine, user)
                
                # Attempt to decrypt the message
                msg_ver = api.protoVersion1
                req_msg = api.Message()
                
                try:
                    req_msg, remaining = decoder.decode(
                        snmpv3_message,
                        asn1Spec=req_msg
                    )
                except Exception as e:
                    logger.debug(f"Message decode failed with user {user.username}: {e}")
                    continue
                
                # Extract PDU
                req_pdu = req_msg.getComponentByPosition(3)
                
                # Check if it's a trap/notification
                if not isinstance(req_pdu, (api.v1.TrapPDU, api.v2c.SNMPv2TrapPDU)):
                    logger.debug(f"Not a trap message from user {user.username}")
                    continue
                
                # Successfully decrypted - extract trap data
                trap_data = self._extract_trap_data(req_pdu, req_msg)
                
                logger.info(f"Successfully decrypted SNMPv3 trap with user {user.username}")
                return (engine_id, trap_data)
                
            except Exception as e:
                logger.debug(f"Decryption failed with user {user.username}: {e}")
                continue
        
        logger.warning(f"Failed to decrypt SNMPv3 trap for Engine ID {engine_id} with any configured user")
        return None
    
    def _extract_trap_data(self, pdu, message) -> Dict:
        """
        Extract trap data from decrypted PDU
        
        Args:
            pdu: Decrypted PDU object
            message: SNMP message object
            
        Returns:
            Dictionary containing trap data
        """
        trap_data = {
            'version': 'v3',
            'varbinds': []
        }
        
        try:
            # Extract varbinds
            varbinds = pdu.getComponentByPosition(3)  # variable-bindings
            
            for idx in range(len(varbinds)):
                varbind = varbinds.getComponentByPosition(idx)
                oid = varbind.getComponentByPosition(0)  # OID
                value = varbind.getComponentByPosition(1)  # Value
                
                trap_data['varbinds'].append({
                    'oid': str(oid),
                    'value': str(value),
                    'type': value.__class__.__name__
                })
            
            # Extract specific trap fields if available
            if hasattr(pdu, 'getComponentByPosition'):
                try:
                    # For SNMPv2c Trap PDU
                    request_id = pdu.getComponentByPosition(0)
                    trap_data['request_id'] = int(request_id)
                except Exception:
                    pass
            
            logger.debug(f"Extracted {len(trap_data['varbinds'])} varbinds from trap")
            
        except Exception as e:
            logger.error(f"Error extracting trap data: {e}")
        
        return trap_data
    
    def convert_to_snmpv2c(
        self,
        trap_data: Dict,
        community: str = "public"
    ) -> Optional[bytes]:
        """
        Convert decrypted SNMPv3 trap data to SNMPv2c format
        
        Args:
            trap_data: Trap data dictionary from decrypt_snmpv3_trap
            community: SNMPv2c community string to use
            
        Returns:
            SNMPv2c trap message bytes, or None if conversion fails
        """
        try:
            # Create SNMPv2c message
            msg = api.v2c.Message()
            msg.setComponentByPosition(0, api.Integer(1))  # SNMPv2c
            msg.setComponentByPosition(1, api.OctetString(community))
            
            # Create SNMPv2c Trap PDU
            pdu = api.v2c.SNMPv2TrapPDU()
            
            # Set request ID
            if 'request_id' in trap_data:
                pdu.setComponentByPosition(0, api.Integer(trap_data['request_id']))
            else:
                pdu.setComponentByPosition(0, api.Integer(1))
            
            # Error status and index (always 0 for traps)
            pdu.setComponentByPosition(1, api.Integer(0))
            pdu.setComponentByPosition(2, api.Integer(0))
            
            # Create varbinds
            varbinds = api.VarBindList()
            
            for idx, varbind in enumerate(trap_data['varbinds']):
                # Create varbind
                vb = api.VarBind()
                vb.setComponentByPosition(0, api.ObjectIdentifier(varbind['oid']))
                
                # Convert value based on type
                value_type = varbind['type']
                value_str = varbind['value']
                
                # Map common types
                if 'Integer' in value_type:
                    value = rfc1902.Integer(int(value_str))
                elif 'OctetString' in value_type:
                    value = rfc1902.OctetString(value_str)
                elif 'ObjectIdentifier' in value_type:
                    value = rfc1902.ObjectIdentifier(value_str)
                elif 'IpAddress' in value_type:
                    value = rfc1902.IpAddress(value_str)
                elif 'Counter' in value_type:
                    value = rfc1902.Counter32(int(value_str))
                elif 'Gauge' in value_type:
                    value = rfc1902.Gauge32(int(value_str))
                elif 'TimeTicks' in value_type:
                    value = rfc1902.TimeTicks(int(value_str))
                else:
                    # Default to octet string
                    value = rfc1902.OctetString(value_str)
                
                vb.setComponentByPosition(1, value)
                varbinds.setComponentByPosition(idx, vb)
            
            # Set varbinds in PDU
            pdu.setComponentByPosition(3, varbinds)
            
            # Set PDU in message
            msg.setComponentByPosition(2, pdu)
            
            # Encode to bytes
            snmpv2c_message = encoder.encode(msg)
            
            logger.debug(f"Converted SNMPv3 trap to SNMPv2c ({len(snmpv2c_message)} bytes)")
            
            return bytes(snmpv2c_message)
            
        except Exception as e:
            logger.error(f"Error converting trap to SNMPv2c: {e}")
            return None


# Global decryptor instance
_snmpv3_decryptor: Optional[SNMPv3Decryptor] = None


def get_snmpv3_decryptor() -> Optional[SNMPv3Decryptor]:
    """
    Get the global SNMPv3 decryptor instance
    
    Returns:
        SNMPv3Decryptor instance or None if not initialized
    """
    return _snmpv3_decryptor


def initialize_snmpv3_decryptor() -> Optional[SNMPv3Decryptor]:
    """
    Initialize the global SNMPv3 decryptor
    
    Returns:
        SNMPv3Decryptor instance or None if pysnmp not available
    """
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
    Convenience function to decrypt SNMPv3 trap and convert to SNMPv2c
    
    Args:
        snmpv3_message: Raw SNMPv3 message bytes
        engine_id: Optional Engine ID
        community: SNMPv2c community string to use
        
    Returns:
        SNMPv2c trap message bytes, or None if operation fails
    """
    decryptor = get_snmpv3_decryptor()
    
    if not decryptor:
        logger.warning("SNMPv3 decryptor not initialized")
        return None
    
    # Decrypt
    result = decryptor.decrypt_snmpv3_trap(snmpv3_message, engine_id)
    if not result:
        return None
    
    engine_id, trap_data = result
    
    # Convert to SNMPv2c
    snmpv2c_message = decryptor.convert_to_snmpv2c(trap_data, community)
    
    return snmpv2c_message
