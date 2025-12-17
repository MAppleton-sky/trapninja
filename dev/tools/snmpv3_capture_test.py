#!/usr/bin/env python3
"""
SNMPv3 Packet Capture Diagnostic

This script captures packets on port 162 and shows what's being received,
to help diagnose why SNMPv3 traps might not be detected.

Usage:
    sudo python3.9 snmpv3_capture_test.py [interface]
"""
import sys
import os

def main():
    interface = sys.argv[1] if len(sys.argv) > 1 else "any"
    
    print("=" * 60)
    print("SNMPv3 Packet Capture Diagnostic")
    print("=" * 60)
    print(f"Interface: {interface}")
    print("Listening for SNMP traps on port 162...")
    print("Press Ctrl+C to stop")
    print()
    
    try:
        from scapy.all import sniff, UDP, IP, Raw
    except ImportError:
        print("ERROR: Scapy not installed")
        print("Install with: pip3 install --break-system-packages scapy")
        return 1
    
    def analyze_packet(pkt):
        if UDP not in pkt:
            return
        
        src_ip = pkt[IP].src if IP in pkt else "unknown"
        dst_port = pkt[UDP].dport
        src_port = pkt[UDP].sport
        
        # Get payload
        if Raw in pkt:
            payload = bytes(pkt[Raw].load)
        else:
            payload = bytes(pkt[UDP].payload)
        
        if not payload:
            print(f"[{src_ip}:{src_port} -> port {dst_port}] Empty payload")
            return
        
        print(f"\n{'='*60}")
        print(f"Packet from {src_ip}:{src_port} -> port {dst_port}")
        print(f"Payload size: {len(payload)} bytes")
        print(f"First 20 bytes (hex): {payload[:20].hex()}")
        
        # Analyze SNMP version
        if len(payload) < 10:
            print("Status: Too short to be SNMP")
            return
        
        if payload[0] != 0x30:
            print(f"Status: Not SNMP (first byte is 0x{payload[0]:02x}, expected 0x30)")
            return
        
        # Parse length
        idx = 1
        if payload[idx] & 0x80:
            len_bytes = payload[idx] & 0x7f
            outer_len = int.from_bytes(payload[idx+1:idx+1+len_bytes], 'big')
            idx += len_bytes + 1
            print(f"Outer SEQUENCE: long form length ({len_bytes} bytes) = {outer_len}")
        else:
            outer_len = payload[idx]
            idx += 1
            print(f"Outer SEQUENCE: short form length = {outer_len}")
        
        # Check version
        if idx >= len(payload) or payload[idx] != 0x02:
            print(f"Status: No INTEGER tag at position {idx}")
            return
        
        idx += 1
        ver_len = payload[idx]
        idx += 1
        
        version = int.from_bytes(payload[idx:idx+ver_len], 'big')
        idx += ver_len
        
        version_names = {0: "v1", 1: "v2c", 3: "v3"}
        version_name = version_names.get(version, f"unknown({version})")
        
        print(f"SNMP Version: {version_name}")
        
        if version == 3:
            print("*** THIS IS AN SNMPv3 PACKET ***")
            
            # Check what comes after version
            if idx < len(payload):
                next_tag = payload[idx]
                if next_tag == 0x30:
                    print("Next element: SEQUENCE (msgGlobalData) - confirms SNMPv3")
                elif next_tag == 0x04:
                    print("Next element: OCTET STRING - unexpected for v3!")
                else:
                    print(f"Next element: tag 0x{next_tag:02x}")
            
            # Try to extract engine ID
            try:
                # Skip to msgSecurityParameters
                # First skip msgGlobalData SEQUENCE
                if payload[idx] == 0x30:
                    idx += 1
                    if payload[idx] & 0x80:
                        lb = payload[idx] & 0x7f
                        global_len = int.from_bytes(payload[idx+1:idx+1+lb], 'big')
                        idx += lb + 1
                    else:
                        global_len = payload[idx]
                        idx += 1
                    idx += global_len
                
                # Now at msgSecurityParameters OCTET STRING
                if payload[idx] == 0x04:
                    idx += 1
                    if payload[idx] & 0x80:
                        lb = payload[idx] & 0x7f
                        sec_len = int.from_bytes(payload[idx+1:idx+1+lb], 'big')
                        idx += lb + 1
                    else:
                        sec_len = payload[idx]
                        idx += 1
                    
                    usm_data = payload[idx:idx+sec_len]
                    
                    # Parse USM to get engine ID
                    usm_idx = 0
                    if usm_data[usm_idx] == 0x30:
                        usm_idx += 1
                        if usm_data[usm_idx] & 0x80:
                            lb = usm_data[usm_idx] & 0x7f
                            usm_idx += lb + 1
                        else:
                            usm_idx += 1
                        
                        if usm_data[usm_idx] == 0x04:
                            usm_idx += 1
                            if usm_data[usm_idx] & 0x80:
                                lb = usm_data[usm_idx] & 0x7f
                                engine_len = int.from_bytes(usm_data[usm_idx+1:usm_idx+1+lb], 'big')
                                usm_idx += lb + 1
                            else:
                                engine_len = usm_data[usm_idx]
                                usm_idx += 1
                            
                            engine_id = usm_data[usm_idx:usm_idx+engine_len].hex()
                            print(f"Engine ID: {engine_id}")
                            
                            # Try to get username
                            usm_idx += engine_len
                            # Skip boots (INTEGER)
                            if usm_data[usm_idx] == 0x02:
                                usm_idx += 1
                                usm_idx += usm_data[usm_idx] + 1
                            # Skip time (INTEGER)
                            if usm_data[usm_idx] == 0x02:
                                usm_idx += 1
                                usm_idx += usm_data[usm_idx] + 1
                            # Get username (OCTET STRING)
                            if usm_data[usm_idx] == 0x04:
                                usm_idx += 1
                                name_len = usm_data[usm_idx]
                                usm_idx += 1
                                username = usm_data[usm_idx:usm_idx+name_len].decode('utf-8', errors='replace')
                                print(f"Username: {username}")
                
            except Exception as e:
                print(f"Could not parse SNMPv3 details: {e}")
        
        elif version == 1:
            # v2c - show community
            if idx < len(payload) and payload[idx] == 0x04:
                idx += 1
                comm_len = payload[idx]
                idx += 1
                community = payload[idx:idx+comm_len].decode('utf-8', errors='replace')
                print(f"Community: {community}")
        
        # Test is_snmpv2c function (with proper length handling)
        is_v2c = False
        if len(payload) >= 8 and payload[0] == 0x30:
            idx = 1
            if payload[idx] & 0x80:
                num_len_bytes = payload[idx] & 0x7f
                idx += 1 + num_len_bytes
            else:
                idx += 1
            
            if idx + 4 <= len(payload):
                is_v2c = (payload[idx] == 0x02 and      # INTEGER tag
                          payload[idx+1] == 0x01 and    # length 1
                          payload[idx+2] == 1 and       # version v2c
                          payload[idx+3] == 0x04)       # OCTET STRING
        
        print(f"is_snmpv2c() would return: {is_v2c}")
        
        # Test is_snmpv3 detection (with proper length handling)
        is_v3 = False
        if len(payload) >= 10 and payload[0] == 0x30:
            idx = 1
            if payload[idx] & 0x80:
                num_len_bytes = payload[idx] & 0x7f
                idx += 1 + num_len_bytes
            else:
                idx += 1
            
            if idx + 4 <= len(payload):
                # Check INTEGER tag for version
                if payload[idx] == 0x02:
                    idx += 1
                    vlen = payload[idx]
                    idx += 1
                    if idx + vlen <= len(payload):
                        v = int.from_bytes(payload[idx:idx+vlen], 'big')
                        idx += vlen
                        # v3 has version=3 and next element is SEQUENCE (msgGlobalData)
                        if v == 3 and idx < len(payload) and payload[idx] == 0x30:
                            is_v3 = True
        
        print(f"is_snmpv3() would return: {is_v3}")
        
        if version == 3 and not is_v3:
            print("WARNING: SNMPv3 packet but is_snmpv3() returns False!")
            print("This is a BUG - please report with the hex dump above")
    
    try:
        print("Starting capture...")
        sniff(
            iface=interface,
            filter="udp port 162",
            prn=analyze_packet,
            store=0
        )
    except KeyboardInterrupt:
        print("\nCapture stopped")
    except PermissionError:
        print("ERROR: Permission denied. Run with sudo.")
        return 1
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
