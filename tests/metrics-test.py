#!/usr/bin/env python3
"""
TrapNinja Metrics Test

A simple test script to verify the metrics functionality of TrapNinja.
"""
import os
import sys
import time
import json
import socket
import argparse
from scapy.all import IP, UDP, send
from scapy.layers.snmp import SNMP, SNMPtrap, SNMPvarbind, ASN1_OID

# Add parent directory to path to import trapninja modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import metrics module
try:
    from trapninja.metrics import (
        init_metrics, get_metrics_summary,
        increment_trap_received, increment_trap_forwarded,
        increment_blocked_ip, increment_blocked_oid,
        increment_redirected_ip, increment_redirected_oid,
        reset_metrics
    )

    METRICS_AVAILABLE = True
except ImportError:
    METRICS_AVAILABLE = False
    print("WARNING: Metrics module not available")

# Constants
TEST_DIR = os.path.abspath(os.path.dirname(__file__))
METRICS_DIR = os.path.join(TEST_DIR, "metrics_test")
LISTEN_PORT = 16200  # Test port
TRAP_OID = "1.3.6.1.4.1.9999.1.1.1.1"
SNMPTRAP_OID = "1.3.6.1.6.3.1.1.4.1.0"
COMMUNITY = "public"

# Create metrics directory if it doesn't exist
os.makedirs(METRICS_DIR, exist_ok=True)


def create_snmpv2c_trap(trap_oid=TRAP_OID, community=COMMUNITY):
    """Create a simple SNMPv2c trap packet"""
    # Add trap OID as the first varbind
    trap_varbind = SNMPvarbind(
        oid=ASN1_OID(SNMPTRAP_OID),
        value=ASN1_OID(trap_oid)
    )

    # Create the packet
    packet = (
            IP(dst="127.0.0.1") /
            UDP(sport=161, dport=LISTEN_PORT) /
            SNMP(
                version=1,  # 0=v1, 1=v2c
                community=community,
                PDU=SNMPtrap(
                    varbindlist=[trap_varbind]
                )
            )
    )

    return bytes(packet)


def send_udp_packet(dest_port=LISTEN_PORT, data=b"test packet"):
    """Send a simple UDP packet directly"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(data, ('127.0.0.1', dest_port))
        print(f"Sent packet to port {dest_port}")
    finally:
        sock.close()


def test_metrics_direct():
    """Test metrics functions directly"""
    if not METRICS_AVAILABLE:
        print("Metrics module not available, skipping test")
        return

    print("Testing metrics functions directly...")

    # Initialize metrics
    init_metrics(metrics_directory=METRICS_DIR, export_interval=1)

    # Reset metrics to start fresh
    reset_metrics()

    # Generate some test metrics
    print("Generating test metrics...")

    # Simulate receiving traps
    for _ in range(10):
        increment_trap_received()

    # Simulate forwarding traps
    for _ in range(8):
        increment_trap_forwarded()

    # Simulate blocked IPs
    blocked_ips = ["192.168.1.100", "10.0.0.1", "192.168.1.100"]
    for ip in blocked_ips:
        increment_blocked_ip(ip)

    # Simulate blocked OIDs
    blocked_oids = ["1.3.6.1.4.1.9999.1.1.1", "1.3.6.1.4.1.8072.2.3.0.1"]
    for oid in blocked_oids:
        increment_blocked_oid(oid)

    # Simulate redirected IPs
    redirected_ips = [
        ("10.0.0.2", "security"),
        ("192.168.2.100", "config"),
        ("10.0.0.2", "security")
    ]
    for ip, tag in redirected_ips:
        increment_redirected_ip(ip, tag)

    # Simulate redirected OIDs
    redirected_oids = [
        ("1.3.6.1.4.1.9999.2.1.1", "security"),
        ("1.3.6.1.4.1.9999.3.1.1", "config")
    ]
    for oid, tag in redirected_oids:
        increment_redirected_oid(oid, tag)

    # Wait for export to complete
    print("Waiting for metrics export...")
    time.sleep(2)

    # Get and display metrics summary
    metrics = get_metrics_summary()
    print("\nMetrics Summary:")
    print(f"Total Traps Received:  {metrics['total_traps_received']}")
    print(f"Total Traps Forwarded: {metrics['total_traps_forwarded']}")
    print(f"Total Traps Blocked:   {metrics['total_traps_blocked']}")
    print(f"Total Traps Redirected: {metrics['total_traps_redirected']}")

    print("\nBlocked IPs:")
    for ip, count in metrics['blocked_ips'].items():
        print(f"  {ip}: {count}")

    print("\nBlocked OIDs:")
    for oid, count in metrics['blocked_oids'].items():
        print(f"  {oid}: {count}")

    print("\nRedirected IPs:")
    for tag, ip_dict in metrics['redirected_ips'].items():
        print(f"  Group '{tag}':")
        for ip, count in ip_dict.items():
            print(f"    {ip}: {count}")

    print("\nRedirected OIDs:")
    for tag, oid_dict in metrics['redirected_oids'].items():
        print(f"  Group '{tag}':")
        for oid, count in oid_dict.items():
            print(f"    {oid}: {count}")

    # Check metrics file
    metrics_file = os.path.join(METRICS_DIR, "trapninja_metrics.prom")
    metrics_json = os.path.join(METRICS_DIR, "trapninja_metrics.json")

    if os.path.exists(metrics_file):
        print(f"\nMetrics file created: {metrics_file}")
        with open(metrics_file, 'r') as f:
            print("\nPrometheus format file sample:")
            for i, line in enumerate(f):
                print(line.strip())
                if i > 5:
                    print("...")
                    break
    else:
        print(f"\nWARNING: Metrics file not found: {metrics_file}")

    if os.path.exists(metrics_json):
        print(f"\nJSON metrics file created: {metrics_json}")
    else:
        print(f"\nWARNING: JSON metrics file not found: {metrics_json}")


def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="TrapNinja Metrics Test")
    parser.add_argument('--direct', action='store_true', help='Test metrics functions directly')
    args = parser.parse_args()

    if args.direct:
        test_metrics_direct()
    else:
        print("Please specify a test to run (--direct)")


if __name__ == "__main__":
    main()