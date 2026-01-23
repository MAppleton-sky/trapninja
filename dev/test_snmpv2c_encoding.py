#!/usr/bin/env python3
"""
Quick test for SNMPv2c message generation.

This tests the BER encoding functions independently of live traffic.
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from trapninja.snmpv3_decryption import SNMPv3Decryptor

def test_encoding():
    """Test the encoding functions produce valid SNMP."""
    
    # Create a mock credential store
    class MockCredStore:
        def get_users_for_engine(self, engine_id):
            return []
    
    decryptor = SNMPv3Decryptor(MockCredStore())
    
    print("=== Testing BER Encoding Functions ===\n")
    
    # Test _encode_integer
    print("Testing _encode_integer:")
    test_ints = [0, 1, 127, 128, 255, 256, 65535, -1]
    for val in test_ints:
        encoded = decryptor._encode_integer(val)
        print(f"  {val:6d} -> {encoded.hex()}")
    
    # Test _encode_length  
    print("\nTesting _encode_length:")
    test_lens = [0, 1, 127, 128, 255, 256, 1000]
    for val in test_lens:
        encoded = decryptor._encode_length(val)
        print(f"  {val:6d} -> {encoded.hex()}")
    
    # Test _encode_oid
    print("\nTesting _encode_oid:")
    test_oids = [
        "1.3.6.1.2.1.1.3.0",  # sysUpTime
        "1.3.6.1.6.3.1.1.4.1.0",  # snmpTrapOID
        "1.3.6.1.4.1.9.9.43.2.0.1",  # Cisco trap
    ]
    for oid in test_oids:
        encoded = decryptor._encode_oid(oid)
        print(f"  {oid}")
        print(f"    -> {encoded.hex()}")
    
    # Test full message generation
    print("\n=== Testing Full Message Generation ===\n")
    
    # Create sample trap data similar to what decryption would produce
    sample_trap_data = {
        'version': 'v3',
        'request_id': 12345,
        'varbinds': [
            {
                'oid': '1.3.6.1.2.1.1.3.0',
                'value': 123456,
                'type': 'TimeTicks',
                'raw_tag': 0x43,
                'raw_bytes': b'\x00\x01\xe2\x40'
            },
            {
                'oid': '1.3.6.1.6.3.1.1.4.1.0',
                'value': '1.3.6.1.4.1.9.9.43.2.0.1',
                'type': 'ObjectIdentifier',
                'raw_tag': 0x06,
                'raw_bytes': bytes([0x2b, 0x06, 0x01, 0x04, 0x01, 0x09, 0x09, 0x2b, 0x02, 0x00, 0x01])
            },
            {
                'oid': '1.3.6.1.4.1.9.9.43.1.1.6.1.3.1',
                'value': 'Test message',
                'type': 'OctetString',
                'raw_tag': 0x04,
                'raw_bytes': b'Test message'
            }
        ]
    }
    
    print(f"Input trap data:")
    print(f"  request_id: {sample_trap_data['request_id']}")
    print(f"  varbinds: {len(sample_trap_data['varbinds'])}")
    for i, vb in enumerate(sample_trap_data['varbinds']):
        print(f"    {i}: {vb['oid']} = {vb['type']}({vb['value']})")
    
    # Convert to SNMPv2c
    print("\nConverting to SNMPv2c...")
    v2c_message = decryptor.convert_to_snmpv2c(sample_trap_data, "public")
    
    if v2c_message:
        print(f"\n✓ Conversion succeeded: {len(v2c_message)} bytes")
        print(f"\nHex dump:")
        # Print in rows of 16 bytes
        for i in range(0, len(v2c_message), 16):
            hex_part = v2c_message[i:i+16].hex()
            hex_spaced = ' '.join(hex_part[j:j+2] for j in range(0, len(hex_part), 2))
            ascii_part = ''.join(
                chr(b) if 32 <= b < 127 else '.' 
                for b in v2c_message[i:i+16]
            )
            print(f"  {i:04x}: {hex_spaced:<48} {ascii_part}")
        
        # Validate structure
        print("\nValidating structure...")
        if decryptor._validate_snmpv2c_message(v2c_message):
            print("✓ Structure validation passed")
        else:
            print("✗ Structure validation FAILED")
        
        # Try to parse with Scapy
        print("\nTrying to parse with Scapy...")
        try:
            from scapy.layers.snmp import SNMP
            parsed = SNMP(v2c_message)
            print(f"✓ Scapy parsed successfully")
            print(f"  Version: {parsed.version.val}")
            print(f"  Community: {parsed.community.val}")
            print(f"  PDU type: {type(parsed.PDU).__name__}")
            if hasattr(parsed.PDU, 'varbindlist'):
                print(f"  Varbinds: {len(parsed.PDU.varbindlist)}")
                for vb in parsed.PDU.varbindlist:
                    print(f"    {vb.oid.val} = {vb.value}")
        except Exception as e:
            print(f"✗ Scapy parsing failed: {e}")
            import traceback
            traceback.print_exc()
    else:
        print("\n✗ Conversion returned None!")


if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.DEBUG, format='%(message)s')
    test_encoding()
