#!/usr/bin/env python3
"""
TrapNinja Network Tests

Comprehensive tests for the network functionality in TrapNinja,
focusing on packet forwarding, socket management, and reliability.
"""

import os
import sys
import time
import socket
import unittest
import threading
import subprocess
import tempfile
import shutil
import json
import signal
from queue import Queue
from contextlib import contextmanager

# Import scapy components when available
try:
    from scapy.all import IP, UDP, send, raw, sr1, Ether
    from scapy.layers.snmp import SNMP, SNMPtrap, SNMPvarbind, ASN1_OID, ASN1_INTEGER

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("WARNING: Scapy not available, some tests will be skipped")

# Add parent directory to path to import trapninja modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Test configuration
TEST_DIR = os.path.abspath(os.path.dirname(__file__))
TEMP_DIR = tempfile.mkdtemp()
TEST_CONFIG_DIR = os.path.join(TEMP_DIR, "config")

# Network test parameters (use high ports for testing)
BASE_PORT = 16400  # Starting port number
LISTEN_PORT = BASE_PORT
FORWARD_PORT_1 = BASE_PORT + 1
FORWARD_PORT_2 = BASE_PORT + 2
SECURITY_PORT = BASE_PORT + 100
CONFIG_PORT = BASE_PORT + 200

# SNMP parameters
COMMUNITY = "public"
SNMPTRAP_OID = "1.3.6.1.6.3.1.1.4.1.0"
TEST_TRAP_OID = "1.3.6.1.4.1.9999.1.1.1"


class UDPListener(threading.Thread):
    """Thread for receiving UDP packets on a specified port"""

    def __init__(self, port, expected_count=1, timeout=5):
        """Initialize the UDP listener thread

        Args:
            port (int): Port to listen on
            expected_count (int): Number of expected packets
            timeout (int): Timeout in seconds
        """
        super().__init__()
        self.port = port
        self.expected_count = expected_count
        self.timeout = timeout
        self.received_packets = Queue()
        self.stop_event = threading.Event()
        self.daemon = True

    def run(self):
        """Run the listener thread"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(0.5)  # Short timeout to check stop_event frequently

        try:
            sock.bind(('0.0.0.0', self.port))
            print(f"UDP listener started on port {self.port}")

            start_time = time.time()
            while not self.stop_event.is_set() and time.time() - start_time < self.timeout:
                try:
                    data, addr = sock.recvfrom(4096)
                    print(f"Received {len(data)} bytes from {addr} on port {self.port}")
                    self.received_packets.put((data, addr))

                    # If we've received the expected number of packets, exit early
                    if self.received_packets.qsize() >= self.expected_count:
                        print(f"Received {self.expected_count} packets on port {self.port}")
                        break
                except socket.timeout:
                    continue
        finally:
            sock.close()
            print(f"UDP listener on port {self.port} stopped, received {self.received_packets.qsize()} packets")

    def stop(self):
        """Stop the listener thread"""
        self.stop_event.set()
        self.join(2)  # Wait up to 2 seconds

    def get_packet_count(self):
        """Get number of received packets

        Returns:
            int: Number of packets received
        """
        return self.received_packets.qsize()

    def get_packets(self):
        """Get all received packets

        Returns:
            list: List of (data, addr) tuples
        """
        packets = []
        while not self.received_packets.empty():
            packets.append(self.received_packets.get())
        return packets


class MultiPortListener:
    """Manages multiple UDP listeners on different ports"""

    def __init__(self, ports=None):
        """Initialize multiple UDP listeners

        Args:
            ports (dict, optional): Dictionary mapping port names to port numbers
        """
        self.listeners = {}
        self.ports = ports or {}

    def start_listener(self, name, port, expected_count=1, timeout=5):
        """Start a listener on a specific port

        Args:
            name (str): Name of the listener for reference
            port (int): Port to listen on
            expected_count (int): Number of expected packets
            timeout (int): Timeout in seconds
        """
        listener = UDPListener(port, expected_count, timeout)
        listener.start()
        self.listeners[name] = listener
        self.ports[name] = port

    def start_all(self, expected_count=1, timeout=5):
        """Start all listeners with the same parameters

        Args:
            expected_count (int): Number of expected packets
            timeout (int): Timeout in seconds
        """
        for name, port in self.ports.items():
            self.start_listener(name, port, expected_count, timeout)

    def stop_all(self):
        """Stop all listeners"""
        for name, listener in list(self.listeners.items()):
            listener.stop()

    def get_results(self):
        """Get results from all listeners

        Returns:
            dict: Dictionary mapping listener names to packet counts
        """
        results = {}
        for name, listener in self.listeners.items():
            results[name] = listener.get_packet_count()
        return results

    def reset(self):
        """Stop all listeners and clear the list"""
        self.stop_all()
        self.listeners.clear()


@contextmanager
def temp_config_files(config_data=None):
    """Create temporary configuration files

    Args:
        config_data (dict, optional): Dictionary with config content

    Yields:
        str: Path to the temporary config directory
    """
    if config_data is None:
        config_data = {}

    # Create config directory
    os.makedirs(TEST_CONFIG_DIR, exist_ok=True)

    # Default configuration
    default_config = {
        "destinations.json": [["127.0.0.1", FORWARD_PORT_1], ["127.0.0.1", FORWARD_PORT_2]],
        "blocked_traps.json": [],
        "listen_ports.json": [LISTEN_PORT],
        "blocked_ips.json": [],
        "redirected_ips.json": [],
        "redirected_oids.json": [],
        "redirected_destinations.json": {
            "security": [["127.0.0.1", SECURITY_PORT]],
            "config": [["127.0.0.1", CONFIG_PORT]]
        }
    }

    # Update with provided config
    for key, value in config_data.items():
        default_config[key] = value

    # Write config files
    for filename, content in default_config.items():
        with open(os.path.join(TEST_CONFIG_DIR, filename), 'w') as f:
            json.dump(content, f, indent=2)

    try:
        yield TEST_CONFIG_DIR
    finally:
        # Clean up
        try:
            shutil.rmtree(TEST_CONFIG_DIR)
        except:
            pass


def start_service(config_dir=TEST_CONFIG_DIR, foreground=True, debug=True):
    """Start the trapninja service

    Args:
        config_dir (str): Path to config directory
        foreground (bool): Run in foreground
        debug (bool): Enable debug mode

    Returns:
        subprocess.Popen: Process object
    """
    # Build command
    cmd = [
        sys.executable,
        "-m", "trapninja",
        "--foreground" if foreground else "--start",
        "--interface", "lo",  # Use loopback interface for testing
        "--config-dir", config_dir,
        "--ports", str(LISTEN_PORT)
    ]

    if debug:
        cmd.append("--debug")

    # Start process
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True
    )

    # Allow time for startup
    time.sleep(2)

    return proc


def send_udp_packet(dest_port, data=b"test packet", source_port=40000, count=1):
    """Send a simple UDP packet directly

    Args:
        dest_port (int): Destination port
        data (bytes): Packet data
        source_port (int): Source port
        count (int): Number of packets to send
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        for i in range(count):
            sock.sendto(data, ('127.0.0.1', dest_port))
            print(f"Sent packet to port {dest_port}")
            # Small delay to avoid overwhelming socket
            time.sleep(0.01)
    finally:
        sock.close()


def create_snmp_trap_packet(trap_oid=TEST_TRAP_OID, community=COMMUNITY):
    """Create a basic SNMPv2c trap packet

    Args:
        trap_oid (str): Trap OID
        community (str): SNMP community string

    Returns:
        bytes: Raw packet bytes or None if Scapy not available
    """
    if not SCAPY_AVAILABLE:
        return None

    # Create the trap varbind
    trap_varbind = SNMPvarbind(
        oid=ASN1_OID(SNMPTRAP_OID),
        value=ASN1_OID(trap_oid)
    )

    # Create the packet
    packet = (
            IP(dst="127.0.0.1") /
            UDP(sport=40000, dport=LISTEN_PORT) /
            SNMP(
                version=1,  # 0=v1, 1=v2c
                community=community,
                PDU=SNMPtrap(
                    varbindlist=[trap_varbind]
                )
            )
    )

    return bytes(packet)


class BasicNetworkTests(unittest.TestCase):
    """Basic network functionality tests"""

    def test_udp_listener_basic(self):
        """Test basic UDP listener functionality"""
        # Create a listener
        listener = UDPListener(FORWARD_PORT_1)
        listener.start()

        try:
            # Send a packet
            send_udp_packet(FORWARD_PORT_1)

            # Wait for packet processing
            time.sleep(1)

            # Check if packet was received
            self.assertEqual(listener.get_packet_count(), 1,
                             "UDP listener did not receive the packet")
        finally:
            listener.stop()

    def test_multiple_listeners(self):
        """Test multiple UDP listeners"""
        # Create a multi-port listener
        multi_listener = MultiPortListener({
            "primary": FORWARD_PORT_1,
            "secondary": FORWARD_PORT_2,
            "security": SECURITY_PORT
        })

        try:
            # Start all listeners
            multi_listener.start_all()

            # Send packets to each port
            send_udp_packet(FORWARD_PORT_1)
            send_udp_packet(FORWARD_PORT_2)
            send_udp_packet(SECURITY_PORT)

            # Wait for packet processing
            time.sleep(1)

            # Check results
            results = multi_listener.get_results()
            self.assertEqual(results["primary"], 1, "Primary listener did not receive the packet")
            self.assertEqual(results["secondary"], 1, "Secondary listener did not receive the packet")
            self.assertEqual(results["security"], 1, "Security listener did not receive the packet")
        finally:
            multi_listener.stop_all()


class ForwardingTests(unittest.TestCase):
    """Tests for packet forwarding functionality"""

    def test_basic_forwarding(self):
        """Test basic packet forwarding"""
        with temp_config_files() as config_dir:
            # Set up listeners for forward ports
            multi_listener = MultiPortListener({
                "primary": FORWARD_PORT_1,
                "secondary": FORWARD_PORT_2
            })

            multi_listener.start_all()

            try:
                # Start service
                proc = start_service(config_dir)

                try:
                    # Send a UDP packet to the listen port
                    if SCAPY_AVAILABLE:
                        # Use SNMP trap if available
                        packet = create_snmp_trap_packet()
                        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        sock.sendto(packet, ('127.0.0.1', LISTEN_PORT))
                        sock.close()
                    else:
                        # Use simple UDP packet as fallback
                        send_udp_packet(LISTEN_PORT, b"test packet")

                    # Wait for processing and forwarding
                    time.sleep(3)

                    # Check results
                    results = multi_listener.get_results()
                    self.assertGreaterEqual(results["primary"] + results["secondary"], 1,
                                            "Packet was not forwarded to any destination")
                finally:
                    # Stop service
                    proc.terminate()
                    proc.wait(timeout=2)
            finally:
                multi_listener.stop_all()

    @unittest.skipIf(not SCAPY_AVAILABLE, "Scapy not available")
    def test_forwarding_with_redirection(self):
        """Test forwarding with OID-based redirection"""
        # Configure OID redirection
        config = {
            "redirected_oids.json": [[TEST_TRAP_OID, "security"]]
        }

        with temp_config_files(config) as config_dir:
            # Set up listeners for regular and security destinations
            multi_listener = MultiPortListener({
                "primary": FORWARD_PORT_1,
                "secondary": FORWARD_PORT_2,
                "security": SECURITY_PORT
            })

            multi_listener.start_all()

            try:
                # Start service
                proc = start_service(config_dir)

                try:
                    # Send SNMP trap packet
                    packet = create_snmp_trap_packet(trap_oid=TEST_TRAP_OID)
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.sendto(packet, ('127.0.0.1', LISTEN_PORT))
                    sock.close()

                    # Wait for processing
                    time.sleep(3)

                    # Check results
                    results = multi_listener.get_results()

                    # Packet should be redirected to security port
                    self.assertEqual(results["primary"], 0,
                                     "Redirected packet was forwarded to primary destination")
                    self.assertEqual(results["secondary"], 0,
                                     "Redirected packet was forwarded to secondary destination")
                    self.assertGreaterEqual(results["security"], 1,
                                            "Packet was not redirected to security destination")
                finally:
                    # Stop service
                    proc.terminate()
                    proc.wait(timeout=2)
            finally:
                multi_listener.stop_all()

    def test_high_volume_forwarding(self):
        """Test forwarding a high volume of packets"""
        packet_count = 50

        with temp_config_files() as config_dir:
            # Set up listeners for forward ports
            multi_listener = MultiPortListener({
                "primary": FORWARD_PORT_1,
                "secondary": FORWARD_PORT_2
            })

            multi_listener.start_all(expected_count=packet_count, timeout=10)

            try:
                # Start service
                proc = start_service(config_dir)

                try:
                    # Send multiple packets
                    if SCAPY_AVAILABLE:
                        # Use SNMP trap if available
                        packet = create_snmp_trap_packet()
                        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        for _ in range(packet_count):
                            sock.sendto(packet, ('127.0.0.1', LISTEN_PORT))
                            time.sleep(0.01)  # Small delay
                        sock.close()
                    else:
                        # Use simple UDP packet as fallback
                        send_udp_packet(LISTEN_PORT, b"test packet", count=packet_count)

                    # Wait for processing
                    time.sleep(5)

                    # Check results
                    results = multi_listener.get_results()
                    total_received = results["primary"] + results["secondary"]

                    # Allow for some packet loss, but should handle most packets
                    self.assertGreaterEqual(total_received, packet_count * 0.8,
                                            f"Only {total_received}/{packet_count * 2} expected packets received")
                finally:
                    # Stop service
                    proc.terminate()
                    proc.wait(timeout=2)
            finally:
                multi_listener.stop_all()


class SocketManagementTests(unittest.TestCase):
    """Tests for socket management functionality"""

    def test_socket_error_handling(self):
        """Test handling of socket errors"""
        # First start a "conflicting" service on the same port
        conflict_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        conflict_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        conflict_sock.bind(('0.0.0.0', LISTEN_PORT))

        try:
            with temp_config_files() as config_dir:
                # Set up listeners for forward ports
                multi_listener = MultiPortListener({
                    "primary": FORWARD_PORT_1,
                    "secondary": FORWARD_PORT_2
                })

                multi_listener.start_all()

                try:
                    # Start service - should continue despite socket conflict
                    proc = start_service(config_dir)

                    try:
                        # Check that the service started despite socket conflict
                        self.assertIsNone(proc.poll(),
                                          "Service crashed when port was in use")

                        # Add a small delay to ensure service has time to start
                        time.sleep(2)

                        # Try sending a packet via the conflicting socket
                        # (simulates another service forwarding to our listener)
                        test_data = b"test packet via conflict socket"
                        conflict_sock.sendto(test_data, ('127.0.0.1', FORWARD_PORT_1))

                        # Wait for processing
                        time.sleep(1)

                        # Check results - trap might be detected indirectly
                        # through pcap/libpcap even though direct binding failed
                        results = multi_listener.get_results()

                        # This test mainly ensures the service doesn't crash
                        # but we do expect it to receive packets through libpcap
                    finally:
                        # Stop service
                        proc.terminate()
                        proc.wait(timeout=2)
                finally:
                    multi_listener.stop_all()
        finally:
            conflict_sock.close()

    def test_port_reconfiguration(self):
        """Test changing listen ports during operation"""
        original_port = LISTEN_PORT
        new_port = LISTEN_PORT + 50

        with temp_config_files() as config_dir:
            # Set up listeners for forward ports
            multi_listener = MultiPortListener({
                "primary": FORWARD_PORT_1,
                "secondary": FORWARD_PORT_2
            })

            multi_listener.start_all()

            try:
                # Start service on original port
                proc = start_service(config_dir)

                try:
                    # Send a packet to the original port
                    send_udp_packet(original_port, b"test packet 1")

                    # Wait for processing
                    time.sleep(2)

                    # Update listen ports config
                    with open(os.path.join(config_dir, "listen_ports.json"), 'w') as f:
                        json.dump([new_port], f, indent=2)

                    # Wait for config reload - might need to restart service
                    time.sleep(2)
                    proc.terminate()
                    proc.wait(timeout=2)

                    # Clear listener results before restarting
                    multi_listener.reset()
                    multi_listener.start_all()

                    # Restart service with new port
                    proc = start_service(config_dir)
                    time.sleep(2)

                    # Send packet to new port
                    send_udp_packet(new_port, b"test packet 2")

                    # Wait for processing
                    time.sleep(2)

                    # Check results
                    results = multi_listener.get_results()
                    self.assertGreaterEqual(results["primary"] + results["secondary"], 1,
                                            "No packets forwarded after port change")
                finally:
                    # Stop service
                    if proc is not None:
                        proc.terminate()
                        proc.wait(timeout=2)
            finally:
                multi_listener.stop_all()


class ReliabilityTests(unittest.TestCase):
    """Tests for service reliability under different conditions"""

    def test_continuous_operation(self):
        """Test continuous operation with periodic packets"""
        test_duration = 10  # seconds
        packet_interval = 0.5  # seconds

        with temp_config_files() as config_dir:
            # Set up listeners for forward ports
            multi_listener = MultiPortListener({
                "primary": FORWARD_PORT_1,
                "secondary": FORWARD_PORT_2
            })

            # Set higher expected count and timeout
            expected_count = int(test_duration / packet_interval) * 2
            multi_listener.start_all(expected_count=expected_count, timeout=test_duration + 5)

            try:
                # Start service
                proc = start_service(config_dir)

                try:
                    # Create test packet
                    if SCAPY_AVAILABLE:
                        packet = create_snmp_trap_packet()
                    else:
                        packet = b"test packet"

                    # Prepare socket for sending
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

                    # Send packets at regular intervals
                    start_time = time.time()
                    packet_count = 0

                    while time.time() - start_time < test_duration:
                        sock.sendto(packet, ('127.0.0.1', LISTEN_PORT))
                        packet_count += 1
                        time.sleep(packet_interval)

                    sock.close()

                    # Wait for final packets to be processed
                    time.sleep(2)

                    # Check results
                    results = multi_listener.get_results()
                    total_received = results["primary"] + results["secondary"]

                    print(f"Sent {packet_count} packets, received {total_received} forwarded packets")

                    # Service should forward reliably (allow for some loss)
                    self.assertGreaterEqual(total_received, packet_count * 0.7,
                                            f"Received only {total_received}/{packet_count * 2} expected packets")
                finally:
                    # Stop service
                    proc.terminate()
                    proc.wait(timeout=2)
            finally:
                multi_listener.stop_all()

    def test_config_reloading(self):
        """Test service response to configuration changes during operation"""
        with temp_config_files() as config_dir:
            # Set up listeners for all potential destinations
            multi_listener = MultiPortListener({
                "primary": FORWARD_PORT_1,
                "secondary": FORWARD_PORT_2,
                "security": SECURITY_PORT,
                "config": CONFIG_PORT
            })

            multi_listener.start_all()

            try:
                # Start service
                proc = start_service(config_dir)

                try:
                    # 1. Test with initial configuration
                    send_udp_packet(LISTEN_PORT, b"test packet 1")
                    time.sleep(2)

                    # Clear results after first test
                    results1 = multi_listener.get_results()
                    multi_listener.reset()
                    multi_listener.start_all()

                    # 2. Update configuration to add blocking
                    with open(os.path.join(config_dir, "blocked_ips.json"), 'w') as f:
                        json.dump(["127.0.0.1"], f, indent=2)

                    # Wait for config reload
                    time.sleep(2)

                    # Send another packet (should be blocked)
                    send_udp_packet(LISTEN_PORT, b"test packet 2")
                    time.sleep(2)

                    # Clear results after second test
                    results2 = multi_listener.get_results()
                    multi_listener.reset()
                    multi_listener.start_all()

                    # 3. Update configuration to remove blocking but add redirection
                    with open(os.path.join(config_dir, "blocked_ips.json"), 'w') as f:
                        json.dump([], f, indent=2)

                    with open(os.path.join(config_dir, "redirected_ips.json"), 'w') as f:
                        json.dump([["127.0.0.1", "security"]], f, indent=2)

                    # Wait for config reload
                    time.sleep(2)

                    # Send another packet (should be redirected)
                    send_udp_packet(LISTEN_PORT, b"test packet 3")
                    time.sleep(2)

                    # Get final results
                    results3 = multi_listener.get_results()

                    # Validate each test case
                    # 1. Initial config: should forward to primary/secondary
                    self.assertGreaterEqual(results1["primary"] + results1["secondary"], 1,
                                            "Initial packet not forwarded properly")

                    # 2. Blocked config: should not forward anywhere or only to blocked destination
                    self.assertEqual(results2["primary"] + results2["secondary"], 0,
                                     "Blocked packet was forwarded to normal destinations")

                    # 3. Redirected config: should forward to security
                    self.assertEqual(results3["primary"] + results3["secondary"], 0,
                                     "Redirected packet forwarded to normal destinations")
                    self.assertGreaterEqual(results3["security"], 1,
                                            "Packet not redirected to security destination")
                finally:
                    # Stop service
                    proc.terminate()
                    proc.wait(timeout=2)
            finally:
                multi_listener.stop_all()

    def test_service_recovery(self):
        """Test service recovery after interruption (SIGTERM handling)"""
        with temp_config_files() as config_dir:
            # Set up listeners for forward ports
            multi_listener = MultiPortListener({
                "primary": FORWARD_PORT_1,
                "secondary": FORWARD_PORT_2
            })

            try:
                # First test normal forwarding
                multi_listener.start_all()
                proc = start_service(config_dir)

                # Send a packet
                send_udp_packet(LISTEN_PORT, b"test packet 1")
                time.sleep(2)

                # Get results
                results1 = multi_listener.get_results()

                # Send SIGTERM to simulate interruption
                proc.send_signal(signal.SIGTERM)
                proc.wait(timeout=5)

                # Clear results and restart listeners
                multi_listener.reset()
                multi_listener.start_all()

                # Restart service
                proc = start_service(config_dir)

                # Send another packet
                send_udp_packet(LISTEN_PORT, b"test packet 2")
                time.sleep(2)

                # Get results after restart
                results2 = multi_listener.get_results()

                # Both tests should forward packets correctly
                self.assertGreaterEqual(results1["primary"] + results1["secondary"], 1,
                                        "Initial packet not forwarded properly")
                self.assertGreaterEqual(results2["primary"] + results2["secondary"], 1,
                                        "Packet after restart not forwarded properly")
            finally:
                # Stop service and listeners
                if proc is not None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=2)
                    except:
                        proc.kill()
                multi_listener.stop_all()


def clean_up():
    """Clean up temporary files after tests"""
    if os.path.exists(TEMP_DIR):
        try:
            shutil.rmtree(TEMP_DIR)
        except:
            print(f"Warning: Could not clean up {TEMP_DIR}")


if __name__ == "__main__":
    try:
        unittest.main()
    finally:
        clean_up()