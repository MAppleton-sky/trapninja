#!/usr/bin/env python3
"""
Packet Duplication Diagnostic Tool for TrapNinja

This tool helps diagnose packet duplication issues when tcpdump shows
higher trap volumes than TrapNinja reports. Common causes include:

1. tcpdump capturing both ingress AND egress (forwarded) packets
2. Samplicator feedback loops or duplicate destinations
3. Network-level packet mirroring/duplication
4. Multiple forwarders (Samplicator + TrapNinja) both active

Usage:
    sudo python3 packet_duplication_diagnostic.py [options]

Author: TrapNinja Development Team
"""

import argparse
import subprocess
import sys
import socket
import struct
import time
import hashlib
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Tuple, Optional
import os
import re


class PacketDuplicationDiagnostic:
    """Diagnose packet duplication issues in SNMP trap forwarding."""
    
    def __init__(self, interface: str = None, port: int = 162, duration: int = 30):
        self.interface = interface or self._detect_interface()
        self.port = port
        self.duration = duration
        self.packet_hashes: Dict[str, List[dict]] = defaultdict(list)
        self.direction_stats = {'ingress': 0, 'egress': 0, 'unknown': 0}
        self.source_stats = defaultdict(int)
        self.dest_stats = defaultdict(int)
        
    def _detect_interface(self) -> str:
        """Detect the primary network interface."""
        try:
            result = subprocess.run(
                ['ip', 'route', 'get', '8.8.8.8'],
                capture_output=True, text=True
            )
            # Parse output like "8.8.8.8 via 10.0.0.1 dev eth0 src 10.0.0.100"
            match = re.search(r'dev\s+(\S+)', result.stdout)
            if match:
                return match.group(1)
        except Exception:
            pass
        return 'any'
    
    def check_samplicator_config(self) -> dict:
        """Check Samplicator configuration for potential issues."""
        result = {
            'running': False,
            'config_file': None,
            'destinations': [],
            'issues': []
        }
        
        # Check if samplicator is running
        try:
            ps_result = subprocess.run(
                ['pgrep', '-a', 'samplicator'],
                capture_output=True, text=True
            )
            if ps_result.returncode == 0:
                result['running'] = True
                result['process_info'] = ps_result.stdout.strip()
                
                # Try to find config file from process args
                for line in ps_result.stdout.split('\n'):
                    if '-c' in line:
                        parts = line.split('-c')
                        if len(parts) > 1:
                            config_path = parts[1].strip().split()[0]
                            result['config_file'] = config_path
        except FileNotFoundError:
            pass
        
        # Check common config locations
        config_paths = [
            '/etc/samplicator.conf',
            '/etc/samplicate.conf',
            '/usr/local/etc/samplicator.conf',
        ]
        
        for path in config_paths:
            if os.path.exists(path):
                result['config_file'] = path
                break
        
        # Parse config if found
        if result['config_file'] and os.path.exists(result['config_file']):
            try:
                with open(result['config_file'], 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        line = line.strip()
                        if not line or line.startswith('#'):
                            continue
                        
                        # Parse destination lines
                        parts = line.split()
                        if len(parts) >= 2:
                            dest = parts[1] if '/' in parts[0] else parts[0]
                            result['destinations'].append({
                                'line': line_num,
                                'raw': line,
                                'destination': dest
                            })
                
                # Check for duplicate destinations
                dest_list = [d['destination'] for d in result['destinations']]
                seen = set()
                for dest in dest_list:
                    if dest in seen:
                        result['issues'].append(
                            f"DUPLICATE DESTINATION: {dest} appears multiple times"
                        )
                    seen.add(dest)
                
                # Check for potential feedback loops
                local_ips = self._get_local_ips()
                for dest in result['destinations']:
                    dest_ip = dest['destination'].split(':')[0]
                    if dest_ip in local_ips or dest_ip in ('127.0.0.1', 'localhost'):
                        dest_port = dest['destination'].split(':')[1] if ':' in dest['destination'] else '162'
                        if dest_port == str(self.port):
                            result['issues'].append(
                                f"POTENTIAL LOOP: Forwarding to local address {dest['destination']} "
                                f"on same port {self.port}"
                            )
            except Exception as e:
                result['issues'].append(f"Error reading config: {e}")
        
        return result
    
    def _get_local_ips(self) -> set:
        """Get all local IP addresses."""
        local_ips = {'127.0.0.1', 'localhost'}
        try:
            result = subprocess.run(
                ['ip', '-4', 'addr', 'show'],
                capture_output=True, text=True
            )
            for match in re.finditer(r'inet\s+(\d+\.\d+\.\d+\.\d+)', result.stdout):
                local_ips.add(match.group(1))
        except Exception:
            pass
        return local_ips
    
    def check_listening_processes(self) -> List[dict]:
        """Check what processes are listening on SNMP ports."""
        listeners = []
        
        try:
            # Use ss or netstat to find listeners
            result = subprocess.run(
                ['ss', '-tulnp'],
                capture_output=True, text=True
            )
            
            for line in result.stdout.split('\n'):
                if f':{self.port}' in line or ':161 ' in line:
                    listeners.append({
                        'raw': line.strip(),
                        'port': self.port if f':{self.port}' in line else 161
                    })
        except Exception as e:
            print(f"Warning: Could not check listening processes: {e}")
        
        return listeners
    
    def capture_and_analyze(self, dest_filter: str = None) -> dict:
        """
        Capture packets and analyze for duplication.
        
        Args:
            dest_filter: Optional destination IP to filter on
        """
        print(f"\n{'='*60}")
        print(f"Starting packet capture on interface: {self.interface}")
        print(f"Duration: {self.duration} seconds")
        print(f"Port: {self.port}")
        if dest_filter:
            print(f"Destination filter: {dest_filter}")
        print(f"{'='*60}\n")
        
        # Build tcpdump filter
        # IMPORTANT: We need to capture BOTH directions to understand the flow
        filter_parts = [f'udp port {self.port}']
        
        tcpdump_cmd = [
            'tcpdump', '-i', self.interface,
            '-nn',  # Don't resolve names
            '-tt',  # Unix timestamps
            '-c', '10000',  # Max packets
            '-l',   # Line buffered
        ]
        
        if dest_filter:
            # Capture both TO and FROM the destination to see the full picture
            filter_parts.append(f'and (host {dest_filter})')
        
        tcpdump_cmd.extend(filter_parts)
        
        print(f"Running: {' '.join(tcpdump_cmd)}")
        print(f"\nCapturing for {self.duration} seconds...\n")
        
        results = {
            'packets': [],
            'by_hash': defaultdict(list),
            'by_source': defaultdict(int),
            'by_dest': defaultdict(int),
            'by_direction': {'ingress': 0, 'egress': 0},
            'duplicates': [],
            'total': 0
        }
        
        local_ips = self._get_local_ips()
        
        try:
            proc = subprocess.Popen(
                tcpdump_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            start_time = time.time()
            
            while time.time() - start_time < self.duration:
                line = proc.stdout.readline()
                if not line:
                    break
                
                # Parse tcpdump output
                # Format: timestamp IP src.port > dst.port: UDP, length X
                packet_info = self._parse_tcpdump_line(line, local_ips)
                if packet_info:
                    results['packets'].append(packet_info)
                    results['total'] += 1
                    
                    # Track by source and destination
                    results['by_source'][packet_info['src_ip']] += 1
                    results['by_dest'][packet_info['dst_ip']] += 1
                    
                    # Determine direction based on local IPs
                    if packet_info['src_ip'] in local_ips:
                        results['by_direction']['egress'] += 1
                        packet_info['direction'] = 'egress'
                    else:
                        results['by_direction']['ingress'] += 1
                        packet_info['direction'] = 'ingress'
                    
                    # Create hash for duplicate detection
                    # Use src_ip + raw payload signature if available
                    hash_key = f"{packet_info['src_ip']}:{packet_info.get('length', 0)}"
                    results['by_hash'][hash_key].append(packet_info)
            
            proc.terminate()
            
        except Exception as e:
            print(f"Error during capture: {e}")
            return results
        
        # Analyze results
        self._analyze_results(results, local_ips)
        
        return results
    
    def _parse_tcpdump_line(self, line: str, local_ips: set) -> Optional[dict]:
        """Parse a tcpdump output line."""
        # Example: 1704825600.123456 IP 10.1.1.1.32768 > 10.2.2.2.162: UDP, length 245
        try:
            parts = line.strip().split()
            if len(parts) < 8 or 'UDP' not in line:
                return None
            
            timestamp = parts[0]
            src_full = parts[2]
            dst_full = parts[4].rstrip(':')
            
            # Parse IP and port
            src_parts = src_full.rsplit('.', 1)
            dst_parts = dst_full.rsplit('.', 1)
            
            if len(src_parts) != 2 or len(dst_parts) != 2:
                return None
            
            # Extract length
            length = 0
            for i, part in enumerate(parts):
                if part == 'length':
                    length = int(parts[i + 1])
                    break
            
            return {
                'timestamp': timestamp,
                'src_ip': src_parts[0],
                'src_port': src_parts[1],
                'dst_ip': dst_parts[0],
                'dst_port': dst_parts[1],
                'length': length,
                'raw': line.strip()
            }
        except Exception:
            return None
    
    def _analyze_results(self, results: dict, local_ips: set) -> None:
        """Analyze captured results for issues."""
        print(f"\n{'='*60}")
        print("CAPTURE ANALYSIS RESULTS")
        print(f"{'='*60}\n")
        
        print(f"Total packets captured: {results['total']}")
        print(f"  - Ingress (from network): {results['by_direction']['ingress']}")
        print(f"  - Egress (from this host): {results['by_direction']['egress']}")
        
        # Calculate amplification factor
        if results['by_direction']['ingress'] > 0:
            amp_factor = results['by_direction']['egress'] / results['by_direction']['ingress']
            print(f"\n  AMPLIFICATION FACTOR: {amp_factor:.2f}x")
            print(f"  (For each ingress packet, {amp_factor:.2f} egress packets are generated)")
        
        print(f"\n--- Packets by Source IP ---")
        for ip, count in sorted(results['by_source'].items(), key=lambda x: -x[1])[:10]:
            direction = "LOCAL" if ip in local_ips else "REMOTE"
            print(f"  {ip}: {count} packets [{direction}]")
        
        print(f"\n--- Packets by Destination IP ---")
        for ip, count in sorted(results['by_dest'].items(), key=lambda x: -x[1])[:10]:
            direction = "LOCAL" if ip in local_ips else "REMOTE"
            print(f"  {ip}: {count} packets [{direction}]")
        
        # Check for duplicate patterns
        print(f"\n--- Potential Duplicate Detection ---")
        duplicate_groups = 0
        for hash_key, packets in results['by_hash'].items():
            if len(packets) > 5:  # Groups with many similar packets
                duplicate_groups += 1
                if duplicate_groups <= 5:
                    print(f"  Pattern '{hash_key}': {len(packets)} similar packets")
        
        if duplicate_groups > 5:
            print(f"  ... and {duplicate_groups - 5} more patterns")
        
        # Generate diagnosis
        print(f"\n{'='*60}")
        print("DIAGNOSIS")
        print(f"{'='*60}\n")
        
        issues_found = []
        
        # Check for forwarding amplification
        if results['by_direction']['egress'] > results['by_direction']['ingress'] * 1.5:
            num_destinations = int(round(
                results['by_direction']['egress'] / max(1, results['by_direction']['ingress'])
            ))
            issues_found.append(
                f"PACKET AMPLIFICATION DETECTED: Each incoming trap is being forwarded "
                f"to approximately {num_destinations} destinations.\n"
                f"   This is EXPECTED if you have {num_destinations} configured destinations.\n"
                f"   This is a PROBLEM if you expect 1:1 forwarding."
            )
        
        # Check for tcpdump seeing both ingress and egress
        if results['by_direction']['ingress'] > 0 and results['by_direction']['egress'] > 0:
            issues_found.append(
                "tcpdump is capturing BOTH ingress and egress packets.\n"
                "   When you filter by 'dst host X', you're seeing:\n"
                "   1. Packets coming IN destined for forwarding\n"
                "   2. Packets going OUT from Samplicator/TrapNinja to that destination\n"
                "   This explains why tcpdump shows higher volume than TrapNinja reports."
            )
        
        if issues_found:
            for i, issue in enumerate(issues_found, 1):
                print(f"{i}. {issue}\n")
        else:
            print("No obvious issues detected in packet flow.")
    
    def run_full_diagnostic(self, dest_filter: str = None) -> None:
        """Run a complete diagnostic check."""
        print("\n" + "="*70)
        print(" PACKET DUPLICATION DIAGNOSTIC TOOL")
        print("="*70)
        
        # Check Samplicator
        print("\n[1/3] Checking Samplicator configuration...")
        samp_result = self.check_samplicator_config()
        
        if samp_result['running']:
            print(f"  ✓ Samplicator is RUNNING")
            print(f"    Process: {samp_result.get('process_info', 'N/A')}")
        else:
            print(f"  ○ Samplicator is NOT running or not found")
        
        if samp_result['config_file']:
            print(f"  Config file: {samp_result['config_file']}")
            print(f"  Destinations configured: {len(samp_result['destinations'])}")
            for dest in samp_result['destinations']:
                print(f"    - {dest['destination']}")
        
        if samp_result['issues']:
            print(f"\n  ⚠ ISSUES FOUND:")
            for issue in samp_result['issues']:
                print(f"    - {issue}")
        
        # Check listeners
        print("\n[2/3] Checking processes listening on SNMP ports...")
        listeners = self.check_listening_processes()
        if listeners:
            for l in listeners:
                print(f"  - {l['raw']}")
        else:
            print("  No listeners found (or need root to see process info)")
        
        # Capture packets
        print("\n[3/3] Capturing packets for analysis...")
        self.capture_and_analyze(dest_filter)
        
        # Final recommendations
        print("\n" + "="*70)
        print(" RECOMMENDATIONS")
        print("="*70)
        print("""
1. To see ONLY incoming traps (before forwarding):
   tcpdump -i <interface> 'udp port 162 and src not <your_server_ip>'

2. To see ONLY outgoing forwarded traps:
   tcpdump -i <interface> 'udp port 162 and src <your_server_ip>'

3. To count unique traps by source IP:
   tcpdump -i <interface> -nn 'udp port 162' | 
     awk '{print $3}' | cut -d. -f1-4 | sort | uniq -c | sort -rn

4. If Samplicator has N destinations, expect N times the traffic on egress.

5. If running both Samplicator AND TrapNinja, ensure only ONE is active
   or they're configured to not conflict.

6. To validate TrapNinja's count matches actual unique incoming traps:
   - TrapNinja should report ingress traps only
   - tcpdump with source filter should match TrapNinja's rate
""")


def main():
    parser = argparse.ArgumentParser(
        description='Diagnose packet duplication in SNMP trap forwarding',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full diagnostic
  sudo python3 packet_duplication_diagnostic.py
  
  # Filter to specific destination
  sudo python3 packet_duplication_diagnostic.py --dest 1.2.3.4
  
  # Longer capture duration
  sudo python3 packet_duplication_diagnostic.py --duration 60
  
  # Specific interface
  sudo python3 packet_duplication_diagnostic.py --interface eth0
        """
    )
    
    parser.add_argument(
        '--interface', '-i',
        help='Network interface to capture on (default: auto-detect)'
    )
    parser.add_argument(
        '--port', '-p',
        type=int, default=162,
        help='SNMP trap port (default: 162)'
    )
    parser.add_argument(
        '--duration', '-d',
        type=int, default=30,
        help='Capture duration in seconds (default: 30)'
    )
    parser.add_argument(
        '--dest',
        help='Destination IP to filter on'
    )
    
    args = parser.parse_args()
    
    # Check for root
    if os.geteuid() != 0:
        print("WARNING: Running without root privileges.")
        print("Some features (packet capture, process info) may not work.")
        print("Run with: sudo python3 packet_duplication_diagnostic.py\n")
    
    diag = PacketDuplicationDiagnostic(
        interface=args.interface,
        port=args.port,
        duration=args.duration
    )
    
    diag.run_full_diagnostic(dest_filter=args.dest)


if __name__ == '__main__':
    main()
