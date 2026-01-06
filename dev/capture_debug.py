#!/usr/bin/env python3
"""
TrapNinja SNMPv3 Capture Diagnostic

Captures live SNMPv3 traps and logs the exact bytes at each stage:
1. Original v3 packet
2. Decrypted trap data
3. Converted v2c packet

Run with: python3 capture_debug.py

Captures to /tmp/trapninja_debug/ for analysis.
"""
import sys
import os
import time
import json
import logging
from datetime import datetime

# Add the trapninja module path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Setup logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
logger = logging.getLogger("trapninja")

# Create output directory
OUTPUT_DIR = "/tmp/trapninja_debug"
os.makedirs(OUTPUT_DIR, exist_ok=True)

def save_capture(name: str, data: bytes, metadata: dict = None):
    """Save captured data to file."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    base_path = os.path.join(OUTPUT_DIR, f"{timestamp}_{name}")
    
    # Save raw bytes
    with open(f"{base_path}.bin", 'wb') as f:
        f.write(data)
    
    # Save hex dump
    with open(f"{base_path}.hex", 'w') as f:
        f.write(f"Length: {len(data)} bytes\n\n")
        for i in range(0, len(data), 16):
            hex_part = data[i:i+16].hex()
            hex_spaced = ' '.join(hex_part[j:j+2] for j in range(0, len(hex_part), 2))
            ascii_part = ''.join(
                chr(b) if 32 <= b < 127 else '.' 
                for b in data[i:i+16]
            )
            f.write(f"{i:04x}: {hex_spaced:<48} {ascii_part}\n")
    
    # Save metadata
    if metadata:
        with open(f"{base_path}.json", 'w') as f:
            json.dump(metadata, f, indent=2, default=str)
    
    print(f"Saved: {base_path}.*")


def test_conversion_pipeline():
    """Test the full conversion pipeline with captured packets."""
    print("\n" + "="*60)
    print("SNMPv3 Conversion Pipeline Test")
    print("="*60)
    
    try:
        from scapy.all import sniff, UDP, IP
        from trapninja.snmpv3_decryption import (
            initialize_snmpv3_decryptor,
            extract_engine_id_from_bytes,
            extract_username_from_bytes,
        )
        from trapninja.processing.parser import is_snmpv3
        
        # Initialize decryptor
        print("\nInitializing decryptor...")
        decryptor = initialize_snmpv3_decryptor()
        
        if not decryptor:
            print("ERROR: Failed to initialize decryptor")
            return
        
        print("Decryptor initialized successfully")
        
        capture_count = [0]
        
        def process_packet(pkt):
            if UDP not in pkt or pkt[UDP].dport != 162:
                return
            
            payload = bytes(pkt[UDP].payload)
            
            if not is_snmpv3(payload):
                return
            
            capture_count[0] += 1
            src_ip = pkt[IP].src if IP in pkt else "unknown"
            
            print(f"\n{'='*60}")
            print(f"SNMPv3 Trap #{capture_count[0]} from {src_ip}")
            print(f"{'='*60}")
            
            # Stage 1: Original packet
            print(f"\n[Stage 1] Original SNMPv3 packet: {len(payload)} bytes")
            print(f"First 40 bytes: {payload[:40].hex()}")
            save_capture(f"trap{capture_count[0]:03d}_01_original_v3", payload, {
                'source_ip': src_ip,
                'stage': 'original_v3',
                'length': len(payload)
            })
            
            # Extract metadata
            engine_id = extract_engine_id_from_bytes(payload)
            username = extract_username_from_bytes(payload)
            print(f"Engine ID: {engine_id}")
            print(f"Username: {username}")
            
            # Stage 2: Attempt decryption
            print(f"\n[Stage 2] Attempting decryption...")
            result = decryptor.decrypt_snmpv3_trap(payload)
            
            if not result:
                print("ERROR: Decryption returned None")
                return
            
            result_engine_id, trap_data = result
            print(f"Decryption successful!")
            print(f"  Request ID: {trap_data.get('request_id')}")
            print(f"  Username: {trap_data.get('username')}")
            print(f"  Varbinds: {len(trap_data.get('varbinds', []))}")
            
            # Show varbind details
            for i, vb in enumerate(trap_data.get('varbinds', [])):
                oid = vb.get('oid', 'N/A')
                vtype = vb.get('type', 'N/A')
                value = vb.get('value', 'N/A')
                raw_tag = vb.get('raw_tag', 'N/A')
                raw_len = len(vb.get('raw_bytes', b''))
                print(f"  Varbind {i}: {oid}")
                print(f"    Type: {vtype} (raw_tag=0x{raw_tag:02x})" if isinstance(raw_tag, int) else f"    Type: {vtype}")
                print(f"    Value: {value}")
                print(f"    Raw bytes: {raw_len} bytes")
            
            save_capture(f"trap{capture_count[0]:03d}_02_decrypted_data", 
                        json.dumps(trap_data, indent=2, default=str).encode(), {
                'source_ip': src_ip,
                'stage': 'decrypted_data',
                'engine_id': result_engine_id,
                'varbind_count': len(trap_data.get('varbinds', []))
            })
            
            # Stage 3: Convert to v2c
            print(f"\n[Stage 3] Converting to SNMPv2c...")
            v2c_payload = decryptor.convert_to_snmpv2c(trap_data, "public")
            
            if not v2c_payload:
                print("ERROR: Conversion returned None!")
                return
            
            print(f"Conversion produced {len(v2c_payload)} bytes")
            print(f"First 40 bytes: {v2c_payload[:40].hex()}")
            
            save_capture(f"trap{capture_count[0]:03d}_03_converted_v2c", v2c_payload, {
                'source_ip': src_ip,
                'stage': 'converted_v2c',
                'length': len(v2c_payload)
            })
            
            # Stage 4: Validate structure
            print(f"\n[Stage 4] Validating SNMPv2c structure...")
            
            # Manual structure check
            idx = 0
            try:
                # SEQUENCE tag
                if v2c_payload[idx] != 0x30:
                    print(f"ERROR: Expected SEQUENCE (0x30), got 0x{v2c_payload[idx]:02x}")
                else:
                    print(f"  OK: Outer SEQUENCE (0x30)")
                idx += 1
                
                # Skip length
                if v2c_payload[idx] & 0x80:
                    len_bytes = v2c_payload[idx] & 0x7f
                    outer_len = int.from_bytes(v2c_payload[idx+1:idx+1+len_bytes], 'big')
                    idx += 1 + len_bytes
                    print(f"  OK: Long form length: {outer_len} bytes")
                else:
                    outer_len = v2c_payload[idx]
                    idx += 1
                    print(f"  OK: Short form length: {outer_len} bytes")
                
                # Version INTEGER
                if v2c_payload[idx] != 0x02:
                    print(f"ERROR: Expected INTEGER (0x02), got 0x{v2c_payload[idx]:02x}")
                else:
                    print(f"  OK: Version INTEGER (0x02)")
                idx += 1
                ver_len = v2c_payload[idx]
                idx += 1
                version = int.from_bytes(v2c_payload[idx:idx+ver_len], 'big')
                if version != 1:
                    print(f"ERROR: Expected version 1, got {version}")
                else:
                    print(f"  OK: Version = 1 (SNMPv2c)")
                idx += ver_len
                
                # Community OCTET STRING
                if v2c_payload[idx] != 0x04:
                    print(f"ERROR: Expected OCTET STRING (0x04), got 0x{v2c_payload[idx]:02x}")
                else:
                    print(f"  OK: Community OCTET STRING (0x04)")
                idx += 1
                if v2c_payload[idx] & 0x80:
                    len_bytes = v2c_payload[idx] & 0x7f
                    comm_len = int.from_bytes(v2c_payload[idx+1:idx+1+len_bytes], 'big')
                    idx += 1 + len_bytes
                else:
                    comm_len = v2c_payload[idx]
                    idx += 1
                community = v2c_payload[idx:idx+comm_len].decode('utf-8', errors='replace')
                print(f"  OK: Community = '{community}'")
                idx += comm_len
                
                # PDU tag
                if v2c_payload[idx] != 0xa7:
                    print(f"ERROR: Expected SNMPv2-Trap-PDU (0xa7), got 0x{v2c_payload[idx]:02x}")
                else:
                    print(f"  OK: SNMPv2-Trap-PDU (0xa7)")
                
                print("\nStructure validation: PASSED")
                
            except Exception as e:
                print(f"Structure validation error: {e}")
            
            # Stage 5: Try parsing with Scapy
            print(f"\n[Stage 5] Parsing with Scapy...")
            try:
                from scapy.layers.snmp import SNMP
                parsed = SNMP(v2c_payload)
                print(f"  Scapy parse: SUCCESS")
                print(f"  Version: {parsed.version.val}")
                print(f"  Community: {parsed.community.val}")
                print(f"  PDU type: {type(parsed.PDU).__name__}")
                if hasattr(parsed.PDU, 'varbindlist'):
                    print(f"  Varbinds: {len(parsed.PDU.varbindlist)}")
                    for vb in parsed.PDU.varbindlist:
                        print(f"    {vb.oid.val} = {vb.value}")
            except Exception as e:
                print(f"  Scapy parse: FAILED - {e}")
                import traceback
                traceback.print_exc()
            
            print(f"\n{'='*60}")
            print(f"Captures saved to: {OUTPUT_DIR}")
            print(f"{'='*60}")
        
        print(f"\nListening for SNMPv3 traps on UDP port 162...")
        print(f"Captures will be saved to: {OUTPUT_DIR}")
        print("Press Ctrl+C to stop\n")
        
        try:
            sniff(filter="udp dst port 162", prn=process_packet, store=0)
        except KeyboardInterrupt:
            print(f"\n\nStopped. Captured {capture_count[0]} traps.")
            print(f"Files saved to: {OUTPUT_DIR}")
    
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    test_conversion_pipeline()
