#!/usr/bin/env python3
"""
TrapNinja SNMPv3 Decryption Diagnostic Tool

Run this to diagnose SNMPv3 decryption issues.
Usage: python3 diagnose_snmpv3.py [--capture <seconds>]
"""
import sys
import os
import logging

# Add the trapninja module path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def setup_logging():
    """Setup verbose logging for diagnostics."""
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        handlers=[logging.StreamHandler()]
    )
    return logging.getLogger("trapninja")

def check_dependencies():
    """Check if required dependencies are available."""
    print("\n=== Checking Dependencies ===")
    
    deps = {
        'pysnmp': None,
        'pyasn1': None,
        'cryptography': None,
        'Crypto': None,  # pycryptodome
    }
    
    for dep in deps:
        try:
            mod = __import__(dep)
            version = getattr(mod, '__version__', 'unknown')
            deps[dep] = version
            print(f"  ✓ {dep}: {version}")
        except ImportError as e:
            print(f"  ✗ {dep}: NOT INSTALLED - {e}")
    
    return deps

def check_credential_store():
    """Check the credential store status."""
    print("\n=== Checking Credential Store ===")
    
    try:
        from trapninja.snmpv3_credentials import get_credential_store
        store = get_credential_store()
        
        engine_ids = store.get_engine_ids()
        print(f"  Credential file: {store.credentials_file}")
        print(f"  Configured engines: {len(engine_ids)}")
        
        for engine_id in engine_ids:
            users = store.get_users_for_engine(engine_id)
            print(f"\n  Engine: {engine_id}")
            for user in users:
                print(f"    - User: {user.username}")
                print(f"      Auth: {user.auth_protocol}")
                print(f"      Priv: {user.priv_protocol}")
        
        return store
    except Exception as e:
        print(f"  ✗ Error: {e}")
        import traceback
        traceback.print_exc()
        return None

def check_decryptor():
    """Check the decryptor status."""
    print("\n=== Checking Decryptor ===")
    
    try:
        from trapninja.snmpv3_decryption import (
            initialize_snmpv3_decryptor, 
            get_snmpv3_decryptor,
            PYSNMP_AVAILABLE,
            CRYPTO_AVAILABLE
        )
        
        print(f"  PYSNMP_AVAILABLE: {PYSNMP_AVAILABLE}")
        print(f"  CRYPTO_AVAILABLE: {CRYPTO_AVAILABLE}")
        
        # Initialize decryptor
        decryptor = initialize_snmpv3_decryptor()
        
        if decryptor:
            print("  ✓ Decryptor initialized successfully")
            return decryptor
        else:
            print("  ✗ Decryptor initialization failed")
            return None
    except Exception as e:
        print(f"  ✗ Error: {e}")
        import traceback
        traceback.print_exc()
        return None

def test_decryption_with_sample(decryptor, sample_file=None):
    """Test decryption with a sample file or captured packet."""
    print("\n=== Testing Decryption ===")
    
    if sample_file and os.path.exists(sample_file):
        print(f"  Loading sample from: {sample_file}")
        with open(sample_file, 'rb') as f:
            sample_data = f.read()
    else:
        print("  No sample file provided")
        print("  To test, capture a packet with:")
        print("    tcpdump -i any udp port 162 -w /tmp/snmpv3_trap.pcap -c 1")
        print("  Then extract the SNMP payload and save to a file")
        return
    
    try:
        from trapninja.snmpv3_decryption import (
            extract_engine_id_from_bytes,
            extract_username_from_bytes
        )
        
        print(f"  Sample size: {len(sample_data)} bytes")
        print(f"  First bytes: {sample_data[:20].hex()}")
        
        # Extract metadata
        engine_id = extract_engine_id_from_bytes(sample_data)
        username = extract_username_from_bytes(sample_data)
        
        print(f"  Extracted engine_id: {engine_id}")
        print(f"  Extracted username: {username}")
        
        # Try decryption
        result = decryptor.decrypt_snmpv3_trap(sample_data)
        
        if result:
            result_engine_id, trap_data = result
            print(f"\n  ✓ Decryption succeeded!")
            print(f"    Engine ID: {result_engine_id}")
            print(f"    Username: {trap_data.get('username', 'N/A')}")
            print(f"    Request ID: {trap_data.get('request_id', 'N/A')}")
            print(f"    Varbinds: {len(trap_data.get('varbinds', []))}")
            
            # Show varbinds
            for i, vb in enumerate(trap_data.get('varbinds', [])):
                print(f"\n    Varbind {i}:")
                print(f"      OID: {vb.get('oid', 'N/A')}")
                print(f"      Type: {vb.get('type', 'N/A')}")
                print(f"      Value: {vb.get('value', 'N/A')}")
            
            # Test conversion
            print(f"\n  Testing v2c conversion...")
            v2c_payload = decryptor.convert_to_snmpv2c(trap_data, "public")
            
            if v2c_payload:
                print(f"    ✓ Conversion succeeded: {len(v2c_payload)} bytes")
                print(f"    First bytes: {v2c_payload[:20].hex()}")
            else:
                print(f"    ✗ Conversion returned None!")
        else:
            print(f"\n  ✗ Decryption failed!")
            print(f"    Check credentials for engine {engine_id}")
    except Exception as e:
        print(f"  ✗ Error: {e}")
        import traceback
        traceback.print_exc()

def live_capture(seconds=10):
    """Capture live SNMPv3 packets and test decryption."""
    print(f"\n=== Live Capture ({seconds}s) ===")
    
    try:
        from scapy.all import sniff, UDP
        from trapninja.snmpv3_decryption import (
            initialize_snmpv3_decryptor,
            extract_engine_id_from_bytes,
            is_snmpv3
        )
        from trapninja.processing.parser import is_snmpv3 as parser_is_snmpv3
        
        decryptor = initialize_snmpv3_decryptor()
        packets_seen = []
        
        def packet_callback(pkt):
            if UDP in pkt and pkt[UDP].dport == 162:
                payload = bytes(pkt[UDP].payload)
                
                # Check if SNMPv3
                if parser_is_snmpv3(payload):
                    print(f"\n  SNMPv3 packet from {pkt['IP'].src}")
                    print(f"    Size: {len(payload)} bytes")
                    
                    engine_id = extract_engine_id_from_bytes(payload)
                    print(f"    Engine ID: {engine_id}")
                    
                    if decryptor:
                        result = decryptor.decrypt_snmpv3_trap(payload)
                        if result:
                            _, trap_data = result
                            varbinds = trap_data.get('varbinds', [])
                            print(f"    ✓ Decrypted: {len(varbinds)} varbinds")
                            
                            # Test conversion
                            v2c = decryptor.convert_to_snmpv2c(trap_data)
                            if v2c and len(v2c) > 20:
                                print(f"    ✓ Converted: {len(v2c)} bytes")
                            else:
                                print(f"    ✗ Conversion failed: {len(v2c) if v2c else 0} bytes")
                                print(f"      Varbind details:")
                                for i, vb in enumerate(varbinds):
                                    print(f"        {i}: oid={vb.get('oid')}, type={vb.get('type')}")
                        else:
                            print(f"    ✗ Decryption failed")
                    
                    packets_seen.append(payload)
        
        print(f"  Listening for SNMPv3 packets on UDP port 162...")
        print(f"  Press Ctrl+C to stop early")
        
        try:
            sniff(filter="udp dst port 162", prn=packet_callback, 
                  timeout=seconds, store=0)
        except KeyboardInterrupt:
            pass
        
        print(f"\n  Captured {len(packets_seen)} SNMPv3 packets")
        
    except Exception as e:
        print(f"  ✗ Error: {e}")
        import traceback
        traceback.print_exc()

def main():
    import argparse
    parser = argparse.ArgumentParser(description='SNMPv3 Decryption Diagnostics')
    parser.add_argument('--capture', type=int, default=0,
                        help='Capture live packets for N seconds')
    parser.add_argument('--sample', type=str, default=None,
                        help='Path to sample SNMPv3 packet file')
    args = parser.parse_args()
    
    print("=" * 60)
    print("TrapNinja SNMPv3 Decryption Diagnostics")
    print("=" * 60)
    
    # Setup logging
    logger = setup_logging()
    
    # Check dependencies
    deps = check_dependencies()
    
    # Check credential store
    store = check_credential_store()
    
    # Check decryptor
    decryptor = check_decryptor()
    
    # Test with sample if provided
    if args.sample:
        test_decryption_with_sample(decryptor, args.sample)
    
    # Live capture if requested
    if args.capture > 0:
        live_capture(args.capture)
    
    print("\n" + "=" * 60)
    print("Diagnostics complete")
    print("=" * 60)
    
    # Summary
    print("\nSummary:")
    if not deps.get('Crypto'):
        print("  ⚠ pycryptodome not installed - encrypted v3 traps cannot be decrypted")
    if not store or not store.get_engine_ids():
        print("  ⚠ No SNMPv3 credentials configured")
    if not decryptor:
        print("  ⚠ Decryptor not initialized")
    
    if args.capture == 0 and not args.sample:
        print("\nTo test with live traffic:")
        print(f"  python3 {sys.argv[0]} --capture 30")
        print("\nTo test with a captured packet:")
        print(f"  python3 {sys.argv[0]} --sample /path/to/packet.bin")

if __name__ == "__main__":
    main()
