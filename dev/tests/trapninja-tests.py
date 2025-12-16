#!/usr/bin/env python3
"""
TrapNinja Test Suite

Comprehensive tests for the TrapNinja application using real
SNMP trap packets and actual network communication.
"""

import os
import sys
import json
import time
import unittest
import shutil
import socket
import threading
import tempfile
import subprocess
from queue import Queue
from contextlib import contextmanager

# Import scapy components for generating and sending SNMP traps
try:
    from scapy.all import send, IP, UDP, raw
    from scapy.layers.snmp import SNMP, SNMPtrap, SNMPvarbind, SNMPget, ASN1_OID, ASN1_INTEGER, ASN1_STRING, ASN1_NULL

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

# Test parameters
LISTEN_PORT = 16200  # Use a high port for testing to avoid needing root
FORWARD_PORT = 16262  # Port to forward traps to

# Define test SNMPv2c community string
COMMUNITY = "public"

# Test-specific OIDs
TEST_TRAP_OID = "1.3.6.1.4.1.9999.1.1.1.1"
TEST_ENTERPRISE_OID = "1.3.6.1.4.1.9999"
TEST_NOTIFICATION_OID = "1.3.6.1.4.1.9999.2.1.1"
SNMPTRAP_OID = "1.3.6.1.6.3.1.1.4.1.0"


class TestTrapReceiverThread(threading.Thread):
    """Thread to receive and verify SNMP traps"""

    def __init__(self, port, expected_count=1, timeout=5):
        """Initialize the receiver thread

        Args:
            port (int): Port to listen on
            expected_count (int): Number of expected traps
            timeout (int): Timeout in seconds
        """
        super().__init__()
        self.port = port
        self.expected_count = expected_count
        self.timeout = timeout
        self.received_traps = Queue()
        self.stop_event = threading.Event()
        self.daemon = True

    def run(self):
        """Run the receiver thread"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(1)  # Short timeout to check stop_event frequently

        try:
            sock.bind(('0.0.0.0', self.port))
            print(f"Test receiver listening on port {self.port}")

            start_time = time.time()
            while not self.stop_event.is_set() and time.time() - start_time < self.timeout:
                try:
                    data, addr = sock.recvfrom(4096)
                    print(f"Received {len(data)} bytes from {addr}")
                    self.received_traps.put((data, addr))

                    # If we've received enough traps, exit early
                    if self.received_traps.qsize() >= self.expected_count:
                        break
                except socket.timeout:
                    continue
                except Exception as e:
                    print(f"Error receiving: {e}")
        finally:
            sock.close()

    def stop(self):
        """Stop the receiver thread"""
        self.stop_event.set()
        self.join(2)  # Wait up to 2 seconds


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
        "destinations.json": [[f"127.0.0.1", FORWARD_PORT]],
        "blocked_traps.json": [],
        "listen_ports.json": [LISTEN_PORT],
        "blocked_ips.json": [],
        "redirected_ips.json": [],
        "redirected_oids.json": [],
        "redirected_destinations.json": {
            "security": [["127.0.0.1", FORWARD_PORT + 100]],
            "config": [["127.0.0.1", FORWARD_PORT + 200]]
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


def create_snmpv2c_trap(trap_oid=TEST_TRAP_OID, varbinds=None, community=COMMUNITY):
    """Create a SNMPv2c trap packet

    Args:
        trap_oid (str): Trap OID
        varbinds (list, optional): Additional varbinds
        community (str): SNMP community string

    Returns:
        bytes: Raw packet bytes
    """
    if not SCAPY_AVAILABLE:
        raise ImportError("Scapy is required to create SNMP trap packets")

    if varbinds is None:
        varbinds = []

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
                    varbindlist=[trap_varbind] + varbinds
                )
            )
    )

    return bytes(packet)


def create_snmpv1_trap(specific_trap=1, enterprise_oid=TEST_ENTERPRISE_OID, varbinds=None, community=COMMUNITY):
    """Create a SNMPv1 trap packet

    Args:
        specific_trap (int): Specific trap ID
        enterprise_oid (str): Enterprise OID
        varbinds (list, optional): Varbinds
        community (str): SNMP community string

    Returns:
        bytes: Raw packet bytes
    """
    if not SCAPY_AVAILABLE:
        raise ImportError("Scapy is required to create SNMP trap packets")

    if varbinds is None:
        varbinds = []

    # SNMPv1 trap parameters
    packet = (
            IP(dst="127.0.0.1") /
            UDP(sport=161, dport=LISTEN_PORT) /
            SNMP(
                version=0,  # 0=v1
                community=community,
                PDU=SNMPtrap(
                    enterprise=ASN1_OID(enterprise_oid),
                    generic_trap=6,  # Enterprise-specific trap
                    specific_trap=specific_trap,
                    varbindlist=varbinds
                )
            )
    )

    return bytes(packet)


def send_trap(packet_bytes):
    """Send a trap packet

    Args:
        packet_bytes (bytes): Raw packet bytes
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(packet_bytes, ('127.0.0.1', LISTEN_PORT))
    finally:
        sock.close()


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
    time.sleep(1)

    return proc


class TrapNinjaBasicTests(unittest.TestCase):
    """Basic functionality tests"""

    @unittest.skipIf(not SCAPY_AVAILABLE, "Scapy not available")
    def test_forward_basic_trap(self):
        """Test basic trap forwarding"""
        with temp_config_files() as config_dir:
            # Start receiver thread
            receiver = TestTrapReceiverThread(FORWARD_PORT)
            receiver.start()

            try:
                # Start service
                proc = start_service(config_dir)

                try:
                    # Create and send trap
                    trap = create_snmpv2c_trap()
                    send_trap(trap)

                    # Wait for processing
                    time.sleep(2)

                    # Check if trap was received
                    self.assertGreater(receiver.received_traps.qsize(), 0,
                                       "No trap received at forward port")
                finally:
                    # Stop service
                    proc.terminate()
                    proc.wait(timeout=2)
            finally:
                # Stop receiver
                receiver.stop()

    @unittest.skipIf(not SCAPY_AVAILABLE, "Scapy not available")
    def test_trap_blocking_by_oid(self):
        """Test blocking traps by OID"""
        # Configure with a blocked trap OID
        config = {
            "blocked_traps.json": [TEST_TRAP_OID]
        }

        with temp_config_files(config) as config_dir:
            # Start receivers
            main_receiver = TestTrapReceiverThread(FORWARD_PORT)
            blocked_receiver = TestTrapReceiverThread(FORWARD_PORT + 200)  # Config group port

            main_receiver.start()
            blocked_receiver.start()

            try:
                # Start service
                proc = start_service(config_dir)

                try:
                    # Create and send trap with blocked OID
                    trap = create_snmpv2c_trap(trap_oid=TEST_TRAP_OID)
                    send_trap(trap)

                    # Wait for processing
                    time.sleep(2)

                    # Check that trap was not forwarded to normal destination
                    self.assertEqual(main_receiver.received_traps.qsize(), 0,
                                     "Trap with blocked OID was forwarded to normal destination")

                    # Check that trap was forwarded to blocked destination
                    self.assertGreater(blocked_receiver.received_traps.qsize(), 0,
                                       "Trap with blocked OID was not forwarded to blocked destination")
                finally:
                    # Stop service
                    proc.terminate()
                    proc.wait(timeout=2)
            finally:
                # Stop receivers
                main_receiver.stop()
                blocked_receiver.stop()

    @unittest.skipIf(not SCAPY_AVAILABLE, "Scapy not available")
    def test_trap_blocking_by_ip(self):
        """Test blocking traps by source IP"""
        # Configure with a blocked IP
        config = {
            "blocked_ips.json": ["127.0.0.1"]
        }

        with temp_config_files(config) as config_dir:
            # Start receiver
            receiver = TestTrapReceiverThread(FORWARD_PORT)
            receiver.start()

            try:
                # Start service
                proc = start_service(config_dir)

                try:
                    # Create and send trap
                    trap = create_snmpv2c_trap()
                    send_trap(trap)

                    # Wait for processing
                    time.sleep(2)

                    # Check that trap was not forwarded
                    self.assertEqual(receiver.received_traps.qsize(), 0,
                                     "Trap from blocked IP was forwarded")
                finally:
                    # Stop service
                    proc.terminate()
                    proc.wait(timeout=2)
            finally:
                # Stop receiver
                receiver.stop()

    @unittest.skipIf(not SCAPY_AVAILABLE, "Scapy not available")
    def test_trap_redirection_by_oid(self):
        """Test redirecting traps by OID"""
        # Configure OID redirection
        config = {
            "redirected_oids.json": [[TEST_TRAP_OID, "security"]]
        }

        with temp_config_files(config) as config_dir:
            # Start receivers
            main_receiver = TestTrapReceiverThread(FORWARD_PORT)
            security_receiver = TestTrapReceiverThread(FORWARD_PORT + 100)  # Security group port

            main_receiver.start()
            security_receiver.start()

            try:
                # Start service
                proc = start_service(config_dir)

                try:
                    # Create and send trap with redirected OID
                    trap = create_snmpv2c_trap(trap_oid=TEST_TRAP_OID)
                    send_trap(trap)

                    # Wait for processing
                    time.sleep(2)

                    # Check that trap was not forwarded to normal destination
                    self.assertEqual(main_receiver.received_traps.qsize(), 0,
                                     "Redirected trap was forwarded to normal destination")

                    # Check that trap was forwarded to security destination
                    self.assertGreater(security_receiver.received_traps.qsize(), 0,
                                       "Trap with redirected OID was not forwarded to security destination")
                finally:
                    # Stop service
                    proc.terminate()
                    proc.wait(timeout=2)
            finally:
                # Stop receivers
                main_receiver.stop()
                security_receiver.stop()

    @unittest.skipIf(not SCAPY_AVAILABLE, "Scapy not available")
    def test_trap_redirection_by_ip(self):
        """Test redirecting traps by source IP"""
        # Configure IP redirection
        config = {
            "redirected_ips.json": [["127.0.0.1", "security"]]
        }

        with temp_config_files(config) as config_dir:
            # Start receivers
            main_receiver = TestTrapReceiverThread(FORWARD_PORT)
            security_receiver = TestTrapReceiverThread(FORWARD_PORT + 100)  # Security group port

            main_receiver.start()
            security_receiver.start()

            try:
                # Start service
                proc = start_service(config_dir)

                try:
                    # Create and send trap
                    trap = create_snmpv2c_trap()
                    send_trap(trap)

                    # Wait for processing
                    time.sleep(2)

                    # Check that trap was not forwarded to normal destination
                    self.assertEqual(main_receiver.received_traps.qsize(), 0,
                                     "Redirected trap was forwarded to normal destination")

                    # Check that trap was forwarded to security destination
                    self.assertGreater(security_receiver.received_traps.qsize(), 0,
                                       "Trap with redirected IP was not forwarded to security destination")
                finally:
                    # Stop service
                    proc.terminate()
                    proc.wait(timeout=2)
            finally:
                # Stop receivers
                main_receiver.stop()
                security_receiver.stop()


class TrapNinjaSnmpTests(unittest.TestCase):
    """SNMP-specific functionality tests"""

    @unittest.skipIf(not SCAPY_AVAILABLE, "Scapy not available")
    def test_snmpv1_trap_handling(self):
        """Test SNMPv1 trap handling"""
        with temp_config_files() as config_dir:
            # Start receiver
            receiver = TestTrapReceiverThread(FORWARD_PORT)
            receiver.start()

            try:
                # Start service
                proc = start_service(config_dir)

                try:
                    # Create and send SNMPv1 trap
                    trap = create_snmpv1_trap()
                    send_trap(trap)

                    # Wait for processing
                    time.sleep(2)

                    # Check if trap was received
                    self.assertGreater(receiver.received_traps.qsize(), 0,
                                       "SNMPv1 trap was not forwarded")
                finally:
                    # Stop service
                    proc.terminate()
                    proc.wait(timeout=2)
            finally:
                # Stop receiver
                receiver.stop()

    @unittest.skipIf(not SCAPY_AVAILABLE, "Scapy not available")
    def test_snmpv1_trap_blocking(self):
        """Test blocking SNMPv1 traps"""
        # Build the SNMPv2c-style OID that would be generated from the SNMPv1 trap
        v2c_format_oid = f"{TEST_ENTERPRISE_OID}.0.1"  # .0.{specific_trap}

        config = {
            "blocked_traps.json": [v2c_format_oid]
        }

        with temp_config_files(config) as config_dir:
            # Start receivers
            main_receiver = TestTrapReceiverThread(FORWARD_PORT)
            blocked_receiver = TestTrapReceiverThread(FORWARD_PORT + 200)  # Config group port

            main_receiver.start()
            blocked_receiver.start()

            try:
                # Start service
                proc = start_service(config_dir)

                try:
                    # Create and send SNMPv1 trap
                    trap = create_snmpv1_trap(enterprise_oid=TEST_ENTERPRISE_OID, specific_trap=1)
                    send_trap(trap)

                    # Wait for processing
                    time.sleep(2)

                    # Check that trap was not forwarded to normal destination
                    self.assertEqual(main_receiver.received_traps.qsize(), 0,
                                     "Blocked SNMPv1 trap was forwarded to normal destination")

                    # Check that trap was forwarded to blocked destination
                    self.assertGreater(blocked_receiver.received_traps.qsize(), 0,
                                       "Blocked SNMPv1 trap was not forwarded to blocked destination")
                finally:
                    # Stop service
                    proc.terminate()
                    proc.wait(timeout=2)
            finally:
                # Stop receivers
                main_receiver.stop()
                blocked_receiver.stop()

    @unittest.skipIf(not SCAPY_AVAILABLE, "Scapy not available")
    def test_multiple_varbinds(self):
        """Test handling traps with multiple varbinds"""
        with temp_config_files() as config_dir:
            # Start receiver
            receiver = TestTrapReceiverThread(FORWARD_PORT)
            receiver.start()

            try:
                # Start service
                proc = start_service(config_dir)

                try:
                    # Create additional varbinds
                    extra_varbinds = [
                        SNMPvarbind(
                            oid=ASN1_OID("1.3.6.1.4.1.9999.1.2.1"),
                            value=ASN1_INTEGER(42)
                        ),
                        SNMPvarbind(
                            oid=ASN1_OID("1.3.6.1.4.1.9999.1.2.2"),
                            value=ASN1_STRING("Test String Value")
                        )
                    ]

                    # Create and send trap with extra varbinds
                    trap = create_snmpv2c_trap(varbinds=extra_varbinds)
                    send_trap(trap)

                    # Wait for processing
                    time.sleep(2)

                    # Check if trap was received
                    self.assertGreater(receiver.received_traps.qsize(), 0,
                                       "Trap with multiple varbinds was not forwarded")
                finally:
                    # Stop service
                    proc.terminate()
                    proc.wait(timeout=2)
            finally:
                # Stop receiver
                receiver.stop()


class TrapNinjaPerformanceTests(unittest.TestCase):
    """Performance and reliability tests"""

    @unittest.skipIf(not SCAPY_AVAILABLE, "Scapy not available")
    def test_high_volume_forwarding(self):
        """Test forwarding a high volume of traps"""
        num_traps = 50

        with temp_config_files() as config_dir:
            # Start receiver with higher expected count
            receiver = TestTrapReceiverThread(FORWARD_PORT, expected_count=num_traps, timeout=10)
            receiver.start()

            try:
                # Start service
                proc = start_service(config_dir)

                try:
                    # Send multiple traps quickly
                    trap = create_snmpv2c_trap()

                    for _ in range(num_traps):
                        send_trap(trap)
                        # Small delay to avoid overwhelming socket
                        time.sleep(0.01)

                    # Wait for processing
                    time.sleep(5)

                    # Check received count
                    received = receiver.received_traps.qsize()
                    self.assertGreaterEqual(received, num_traps * 0.8,  # Allow for some packet loss
                                            f"Only {received}/{num_traps} traps were forwarded")
                finally:
                    # Stop service
                    proc.terminate()
                    proc.wait(timeout=2)
            finally:
                # Stop receiver
                receiver.stop()

    @unittest.skipIf(not SCAPY_AVAILABLE, "Scapy not available")
    def test_config_reload(self):
        """Test config reload during operation"""
        with temp_config_files() as config_dir:
            # Start receivers
            main_receiver = TestTrapReceiverThread(FORWARD_PORT)
            security_receiver = TestTrapReceiverThread(FORWARD_PORT + 100)

            main_receiver.start()
            security_receiver.start()

            try:
                # Start service
                proc = start_service(config_dir)

                try:
                    # Send initial trap
                    trap = create_snmpv2c_trap()
                    send_trap(trap)

                    # Wait for processing
                    time.sleep(2)

                    # Verify it went to main destination
                    self.assertGreater(main_receiver.received_traps.qsize(), 0,
                                       "Initial trap was not forwarded to main destination")
                    self.assertEqual(security_receiver.received_traps.qsize(), 0,
                                     "Initial trap was incorrectly forwarded to security destination")

                    # Clear receiver queues
                    while not main_receiver.received_traps.empty():
                        main_receiver.received_traps.get()

                    # Update config to add redirection
                    with open(os.path.join(config_dir, "redirected_oids.json"), 'w') as f:
                        json.dump([[TEST_TRAP_OID, "security"]], f, indent=2)

                    # Wait for config reload (should happen automatically)
                    time.sleep(2)

                    # Send another trap
                    send_trap(trap)

                    # Wait for processing
                    time.sleep(2)

                    # Verify it was redirected to security destination
                    self.assertEqual(main_receiver.received_traps.qsize(), 0,
                                     "Post-config trap was forwarded to main destination")
                    self.assertGreater(security_receiver.received_traps.qsize(), 0,
                                       "Post-config trap was not forwarded to security destination")
                finally:
                    # Stop service
                    proc.terminate()
                    proc.wait(timeout=2)
            finally:
                # Stop receivers
                main_receiver.stop()
                security_receiver.stop()


class TrapNinjaConfigTests(unittest.TestCase):
    """Configuration-related tests"""

    def test_config_validation(self):
        """Test configuration file validation"""
        # Create invalid configurations to test validation
        invalid_configs = {
            "Invalid port": {
                "listen_ports.json": [9999999]  # Invalid port number
            },
            "Invalid IP": {
                "blocked_ips.json": ["999.999.999.999"]  # Invalid IP address
            },
            "Invalid OID": {
                "redirected_oids.json": [["invalid-oid", "security"]]  # Invalid OID format
            }
        }

        for test_name, config in invalid_configs.items():
            with self.subTest(test_name=test_name):
                with temp_config_files(config) as config_dir:
                    # Start service
                    proc = start_service(config_dir)

                    try:
                        # Wait for startup
                        time.sleep(1)

                        # Check if service started despite invalid config
                        # The service should still start but log warnings, not crash
                        self.assertIsNone(proc.poll(),
                                          f"Service crashed with {test_name}")
                    finally:
                        # Stop service
                        proc.terminate()
                        proc.wait(timeout=2)

    def test_empty_config(self):
        """Test with empty configuration files"""
        empty_config = {
            "destinations.json": [],
            "blocked_traps.json": [],
            "listen_ports.json": [LISTEN_PORT],  # Keep valid port
            "blocked_ips.json": [],
            "redirected_ips.json": [],
            "redirected_oids.json": [],
            "redirected_destinations.json": {}
        }

        with temp_config_files(empty_config) as config_dir:
            # Start service
            proc = start_service(config_dir)

            try:
                # Wait for startup
                time.sleep(1)

                # Check if service started despite empty config
                self.assertIsNone(proc.poll(),
                                  "Service crashed with empty configuration")
            finally:
                # Stop service
                proc.terminate()
                proc.wait(timeout=2)


class TrapNinjaCommandLineTests(unittest.TestCase):
    """Command-line interface tests"""

    def test_command_line_options(self):
        """Test command-line options"""
        with temp_config_files() as config_dir:
            # Test various command combinations
            test_commands = [
                # Basic operation modes
                ["--foreground", "--config-dir", config_dir],
                ["--status"],
                # Configuration options
                ["--foreground", "--config-dir", config_dir, "--ports", f"{LISTEN_PORT}"],
                ["--foreground", "--config-dir", config_dir, "--debug"],
                # Configuration management
                ["--list-blocked-ips", "--config-dir", config_dir],
                ["--list-blocked-oids", "--config-dir", config_dir],
                ["--list-redirected-ips", "--config-dir", config_dir],
                ["--list-redirected-oids", "--config-dir", config_dir],
                ["--list-groups", "--config-dir", config_dir]
            ]

            for cmd_args in test_commands:
                with self.subTest(command=cmd_args):
                    # Construct full command
                    cmd = [sys.executable, "-m", "trapninja"] + cmd_args

                    # Execute command
                    try:
                        result = subprocess.run(
                            cmd,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            timeout=2
                        )

                        # Check for critical errors
                        self.assertNotIn("Traceback (most recent call last)", result.stderr.decode('utf-8'),
                                         f"Command {cmd_args} caused an exception")
                    except subprocess.TimeoutExpired:
                        # Some commands like --foreground are expected to timeout
                        pass


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