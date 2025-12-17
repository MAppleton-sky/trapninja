#!/usr/bin/env python3
"""
SNMPv3 Decryption Diagnostic Tool

This script helps diagnose SNMPv3 decryption issues by testing the
decryption and conversion pipeline step by step.

Usage:
    python3 snmpv3_diagnostic.py [--trap-file FILE] [--engine-id ID]
"""
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def check_dependencies():
    """Check all required dependencies."""
    print("=" * 60)
    print("SNMPv3 Decryption Diagnostic Tool")
    print("=" * 60)
    print()
    
    print("Checking dependencies...")
    print()
    
    # Check pysnmp
    try:
        import pysnmp
        print(f"  ✓ pysnmp: {pysnmp.__version__ if hasattr(pysnmp, '__version__') else 'installed'}")
    except ImportError as e:
        print(f"  ✗ pysnmp: NOT INSTALLED - {e}")
        print("    Install with: pip3 install --break-system-packages pysnmp")
        return False
    
    # Check pyasn1
    try:
        import pyasn1
        print(f"  ✓ pyasn1: {pyasn1.__version__ if hasattr(pyasn1, '__version__') else 'installed'}")
    except ImportError as e:
        print(f"  ✗ pyasn1: NOT INSTALLED - {e}")
        print("    Install with: pip3 install --break-system-packages pyasn1")
        return False
    
    # Check cryptography
    try:
        import cryptography
        print(f"  ✓ cryptography: {cryptography.__version__}")
    except ImportError as e:
        print(f"  ✗ cryptography: NOT INSTALLED - {e}")
        print("    Install with: pip3 install --break-system-packages cryptography")
        return False
    
    # Check pycryptodome
    try:
        from Crypto.Cipher import AES, DES
        print("  ✓ pycryptodome: installed")
    except ImportError as e:
        print(f"  ✗ pycryptodome: NOT INSTALLED - {e}")
        print("    Install with: pip3 install --break-system-packages pycryptodome")
        return False
    
    print()
    return True


def check_credentials():
    """Check configured SNMPv3 credentials."""
    print("Checking SNMPv3 credentials...")
    print()
    
    try:
        from trapninja.snmpv3_credentials import get_credential_store
        
        store = get_credential_store()
        users = store.list_all_users()
        engine_ids = store.get_engine_ids()
        
        if not users:
            print("  ⚠ No SNMPv3 users configured")
            print("    Add users with: python3.9 -O trapninja.py --snmpv3-add-user ...")
            return []
        
        print(f"  ✓ Found {len(users)} configured user(s) for {len(engine_ids)} engine(s)")
        print()
        
        for engine_id in engine_ids:
            engine_users = store.get_users_for_engine(engine_id)
            print(f"  Engine ID: {engine_id}")
            for user in engine_users:
                print(f"    - User: {user.username}")
                print(f"      Auth: {user.auth_protocol}, Priv: {user.priv_protocol}")
        
        print()
        return users
        
    except Exception as e:
        print(f"  ✗ Error loading credentials: {e}")
        import traceback
        traceback.print_exc()
        return []


def check_decryptor():
    """Check if decryptor can be initialized."""
    print("Checking decryptor initialization...")
    print()
    
    try:
        from trapninja.snmpv3_decryption import initialize_snmpv3_decryptor, PYSNMP_AVAILABLE
        
        if not PYSNMP_AVAILABLE:
            print("  ✗ pysnmp not available for decryption")
            return None
        
        decryptor = initialize_snmpv3_decryptor()
        
        if decryptor:
            print("  ✓ Decryptor initialized successfully")
            return decryptor
        else:
            print("  ✗ Decryptor initialization failed")
            return None
            
    except Exception as e:
        print(f"  ✗ Error initializing decryptor: {e}")
        import traceback
        traceback.print_exc()
        return None


def test_engine_id_extraction(trap_data: bytes):
    """Test engine ID extraction from trap data."""
    print("Testing engine ID extraction...")
    print()
    
    try:
        from trapninja.snmpv3_decryption import extract_engine_id_from_bytes, extract_username_from_bytes
        
        engine_id = extract_engine_id_from_bytes(trap_data)
        username = extract_username_from_bytes(trap_data)
        
        if engine_id:
            print(f"  ✓ Engine ID: {engine_id}")
        else:
            print("  ✗ Could not extract engine ID")
        
        if username:
            print(f"  ✓ Username: {username}")
        else:
            print("  ⚠ Could not extract username (may be empty)")
        
        print()
        return engine_id, username
        
    except Exception as e:
        print(f"  ✗ Error extracting engine ID: {e}")
        import traceback
        traceback.print_exc()
        return None, None


def test_decryption(decryptor, trap_data: bytes, engine_id: str = None):
    """Test trap decryption."""
    print("Testing decryption...")
    print()
    
    try:
        result = decryptor.decrypt_snmpv3_trap(trap_data, engine_id)
        
        if result:
            engine_id, trap_info = result
            print(f"  ✓ Decryption successful!")
            print(f"    Engine ID: {engine_id}")
            print(f"    Varbinds: {len(trap_info.get('varbinds', []))}")
            
            if trap_info.get('varbinds'):
                print()
                print("    Varbind details:")
                for i, vb in enumerate(trap_info['varbinds'][:5]):  # Show first 5
                    print(f"      {i+1}. OID: {vb.get('oid', 'N/A')}")
                    print(f"         Type: {vb.get('type', 'N/A')}")
                    value = str(vb.get('value', ''))[:50]
                    print(f"         Value: {value}{'...' if len(str(vb.get('value', ''))) > 50 else ''}")
                
                if len(trap_info['varbinds']) > 5:
                    print(f"      ... and {len(trap_info['varbinds']) - 5} more")
            
            print()
            return trap_info
        else:
            print("  ✗ Decryption failed - no result returned")
            print("    Possible causes:")
            print("    - Wrong credentials (auth/priv passwords)")
            print("    - Wrong engine ID")
            print("    - Unsupported protocol combination")
            return None
            
    except Exception as e:
        print(f"  ✗ Decryption error: {e}")
        import traceback
        traceback.print_exc()
        return None


def test_conversion(decryptor, trap_info: dict):
    """Test conversion to SNMPv2c."""
    print("Testing SNMPv2c conversion...")
    print()
    
    try:
        v2c_data = decryptor.convert_to_snmpv2c(trap_info, "public")
        
        if v2c_data and len(v2c_data) > 20:
            print(f"  ✓ Conversion successful!")
            print(f"    Output size: {len(v2c_data)} bytes")
            print(f"    First bytes (hex): {v2c_data[:20].hex()}")
            
            # Try to decode the SNMPv2c message
            try:
                from pyasn1.codec.ber import decoder
                from pysnmp.proto.api import v2c
                
                msg, _ = decoder.decode(v2c_data, asn1Spec=v2c.Message())
                version = int(msg.getComponentByPosition(0))
                community = str(msg.getComponentByPosition(1))
                
                print(f"    Version: {version} (should be 1 for SNMPv2c)")
                print(f"    Community: {community}")
                
                pdu = msg.getComponentByPosition(2)
                if pdu:
                    try:
                        varbinds = pdu.getComponentByPosition(3)
                        print(f"    Varbinds in output: {len(varbinds) if varbinds else 0}")
                    except Exception:
                        print("    Could not extract varbinds from PDU")
                
            except Exception as e:
                print(f"    ⚠ Could not decode output: {e}")
            
            print()
            return v2c_data
        else:
            print(f"  ✗ Conversion failed or produced invalid output")
            print(f"    Output size: {len(v2c_data) if v2c_data else 0} bytes")
            return None
            
    except Exception as e:
        print(f"  ✗ Conversion error: {e}")
        import traceback
        traceback.print_exc()
        return None


def capture_live_trap():
    """Capture a live SNMPv3 trap for testing."""
    print("Attempting to capture a live SNMPv3 trap...")
    print("(Will wait up to 30 seconds)")
    print()
    
    try:
        from scapy.all import sniff, UDP
        
        def is_snmpv3(pkt):
            if UDP in pkt and pkt[UDP].dport == 162:
                payload = bytes(pkt[UDP].payload)
                if len(payload) > 10:
                    # Check for SNMPv3 (version = 3)
                    # Simple check: look for version integer
                    try:
                        if payload[0] == 0x30:  # SEQUENCE
                            # Skip length bytes
                            idx = 1
                            if payload[idx] & 0x80:
                                idx += (payload[idx] & 0x7f) + 1
                            else:
                                idx += 1
                            # Check for INTEGER with value 3
                            if payload[idx] == 0x02:  # INTEGER
                                idx += 1
                                int_len = payload[idx]
                                idx += 1
                                version = int.from_bytes(payload[idx:idx+int_len], 'big')
                                return version == 3
                    except Exception:
                        pass
            return False
        
        packets = sniff(
            filter="udp port 162",
            count=1,
            timeout=30,
            lfilter=is_snmpv3
        )
        
        if packets:
            pkt = packets[0]
            payload = bytes(pkt[UDP].payload)
            print(f"  ✓ Captured SNMPv3 trap ({len(payload)} bytes)")
            return payload
        else:
            print("  ⚠ No SNMPv3 traps captured within timeout")
            return None
            
    except Exception as e:
        print(f"  ✗ Capture error: {e}")
        return None


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='SNMPv3 Decryption Diagnostic Tool')
    parser.add_argument('--trap-file', help='File containing raw SNMPv3 trap bytes')
    parser.add_argument('--engine-id', help='Override engine ID for testing')
    parser.add_argument('--capture', action='store_true', help='Capture a live trap for testing')
    args = parser.parse_args()
    
    # Check dependencies
    if not check_dependencies():
        print("Please install missing dependencies and try again.")
        return 1
    
    # Check credentials
    users = check_credentials()
    
    # Check decryptor
    decryptor = check_decryptor()
    if not decryptor:
        print("Cannot continue without decryptor.")
        return 1
    
    # Get trap data
    trap_data = None
    
    if args.trap_file:
        print(f"Loading trap data from {args.trap_file}...")
        try:
            with open(args.trap_file, 'rb') as f:
                trap_data = f.read()
            print(f"  ✓ Loaded {len(trap_data)} bytes")
            print()
        except Exception as e:
            print(f"  ✗ Error loading file: {e}")
            return 1
    
    elif args.capture:
        trap_data = capture_live_trap()
        if not trap_data:
            return 1
    
    else:
        print("No trap data provided.")
        print("Use --trap-file FILE or --capture to provide test data.")
        print()
        print("To capture a trap to file, use:")
        print("  tcpdump -i any udp port 162 -w /tmp/trap.pcap -c 1")
        print("  # Then extract payload with tshark or similar")
        return 0
    
    # Test extraction
    engine_id, username = test_engine_id_extraction(trap_data)
    
    if args.engine_id:
        print(f"Using override engine ID: {args.engine_id}")
        engine_id = args.engine_id
    
    # Test decryption
    trap_info = test_decryption(decryptor, trap_data, engine_id)
    
    if trap_info:
        # Test conversion
        v2c_data = test_conversion(decryptor, trap_info)
        
        if v2c_data:
            # Save output for inspection
            output_file = '/tmp/snmpv2c_output.bin'
            with open(output_file, 'wb') as f:
                f.write(v2c_data)
            print(f"SNMPv2c output saved to: {output_file}")
            print()
            print("You can inspect this with:")
            print(f"  snmptrapd -f -Lo -n -C -c /dev/null")
            print(f"  # Then send: nc -u localhost 162 < {output_file}")
    
    print("=" * 60)
    print("Diagnostic complete")
    print("=" * 60)
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
