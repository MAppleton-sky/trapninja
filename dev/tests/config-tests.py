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


class ConfigValidationTests(unittest.TestCase):
    """Tests for configuration validation functionality"""

    @unittest.skipIf(not DIRECT_IMPORTS, "Direct imports not available")
    def test_safe_load_json(self):
        """Test safe JSON loading with error handling"""
        # Create test files
        with tempfile.TemporaryDirectory() as temp_dir:
            # Valid JSON file
            valid_path = os.path.join(temp_dir, "valid.json")
            with open(valid_path, 'w') as f:
                f.write('{"test": true, "value": 42}')

            # Invalid JSON file
            invalid_path = os.path.join(temp_dir, "invalid.json")
            with open(invalid_path, 'w') as f:
                f.write('{"test": true, invalid json}')

            # Non-existent file
            nonexistent_path = os.path.join(temp_dir, "nonexistent.json")

            # Test with valid file
            result = safe_load_json(valid_path, None)
            self.assertEqual(result, {"test": True, "value": 42})

            # Test with invalid file
            fallback = {"fallback": True}
            result = safe_load_json(invalid_path, fallback)
            self.assertEqual(result, fallback)

            # Test with non-existent file
            result = safe_load_json(nonexistent_path, fallback)
            self.assertEqual(result, fallback)

    @unittest.skipIf(not DIRECT_IMPORTS, "Direct imports not available")
    def test_parse_size(self):
        """Test size string parsing functionality"""
        # Test valid size strings
        self.assertEqual(parse_size("100"), 100)
        self.assertEqual(parse_size("1K"), 1024)
        self.assertEqual(parse_size("1KB"), 1024)
        self.assertEqual(parse_size("1.5K"), 1536)
        self.assertEqual(parse_size("2M"), 2 * 1024 * 1024)
        self.assertEqual(parse_size("2MB"), 2 * 1024 * 1024)
        self.assertEqual(parse_size("1G"), 1024 * 1024 * 1024)
        self.assertEqual(parse_size("1GB"), 1024 * 1024 * 1024)

        # Test invalid size strings
        self.assertIsNone(parse_size("invalid"))
        self.assertIsNone(parse_size("K100"))
        self.assertIsNone(parse_size("100X"))

    @unittest.skipIf(not DIRECT_IMPORTS, "Direct imports not available")
    def test_validate_ip(self):
        """Test IP address validation"""
        # Test valid IP addresses
        self.assertEqual(validate_ip("127.0.0.1"), "127.0.0.1")
        self.assertEqual(validate_ip("192.168.1.1"), "192.168.1.1")
        self.assertEqual(validate_ip("10.0.0.1"), "10.0.0.1")
        self.assertEqual(validate_ip("8.8.8.8"), "8.8.8.8")

        # Test invalid IP addresses
        self.assertIsNone(validate_ip("256.0.0.1"))
        self.assertIsNone(validate_ip("192.168.1"))
        self.assertIsNone(validate_ip("not-an-ip"))
        self.assertIsNone(validate_ip(""))

    @unittest.skipIf(not DIRECT_IMPORTS, "Direct imports not available")
    def test_validate_oid(self):
        """Test OID validation"""
        # Test valid OIDs
        self.assertEqual(validate_oid("1.3.6.1"), "1.3.6.1")
        self.assertEqual(validate_oid("1.3.6.1.4.1.9999"), "1.3.6.1.4.1.9999")
        self.assertEqual(validate_oid("0.0"), "0.0")

        # Test invalid OIDs
        self.assertIsNone(validate_oid("not-an-oid"))
        self.assertIsNone(validate_oid("1.3.6.a.1"))
        self.assertIsNone(validate_oid("1.3.6..1"))
        self.assertIsNone(validate_oid(""))


class ConfigLoadingTests(unittest.TestCase):
    """Tests for configuration loading functionality"""

    @unittest.skipIf(not DIRECT_IMPORTS, "Direct imports not available")
    def test_ensure_config_dir(self):
        """Test config directory creation"""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Set CONFIG_DIR to the temp directory for testing
            original_config_dir = os.path.abspath(getattr(ensure_config_dir, "__globals__", {}).get("CONFIG_DIR", ""))

            try:
                # Use a subdirectory in the temp dir
                test_config_dir = os.path.join(temp_dir, "config")
                ensure_config_dir.__globals__["CONFIG_DIR"] = test_config_dir

                # Call the function
                ensure_config_dir()

                # Check that directory was created
                self.assertTrue(os.path.exists(test_config_dir))

                # Check that example files were created
                expected_files = [
                    "destinations.json",
                    "blocked_traps.json",
                    "listen_ports.json",
                    "blocked_ips.json",
                    "redirected_ips.json",
                    "redirected_oids.json",
                    "redirected_destinations.json"
                ]

                for filename in expected_files:
                    file_path = os.path.join(test_config_dir, filename)
                    self.assertTrue(os.path.exists(file_path), f"Example file {filename} was not created")

                    # Check that file contains valid JSON
                    with open(file_path, 'r') as f:
                        content = json.load(f)
                        self.assertIsNotNone(content)
            finally:
                # Restore original CONFIG_DIR
                if original_config_dir:
                    ensure_config_dir.__globals__["CONFIG_DIR"] = original_config_dir

    @unittest.skipIf(not DIRECT_IMPORTS, "Direct imports not available")
    def test_load_config(self):
        """Test configuration loading"""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create test config files
            test_config_dir = os.path.join(temp_dir, "config")
            os.makedirs(test_config_dir, exist_ok=True)

            # Create test configurations
            dest_file = os.path.join(test_config_dir, "destinations.json")
            with open(dest_file, 'w') as f:
                json.dump([["192.168.1.100", 162], ["10.0.0.1", 1162]], f)

            blocked_file = os.path.join(test_config_dir, "blocked_traps.json")
            with open(blocked_file, 'w') as f:
                json.dump(["1.3.6.1.4.1.9999.1.1.1"], f)

            ports_file = os.path.join(test_config_dir, "listen_ports.json")
            with open(ports_file, 'w') as f:
                json.dump([162, 1162], f)

            # Store original config paths
            original_paths = {
                "CONFIG_DIR": getattr(load_config, "__globals__", {}).get("CONFIG_DIR", ""),
                "DESTINATIONS_FILE": getattr(load_config, "__globals__", {}).get("DESTINATIONS_FILE", ""),
                "BLOCKED_TRAPS_FILE": getattr(load_config, "__globals__", {}).get("BLOCKED_TRAPS_FILE", ""),
                "LISTEN_PORTS_FILE": getattr(load_config, "__globals__", {}).get("LISTEN_PORTS_FILE", ""),
            }

            try:
                # Update paths to test directory
                load_config.__globals__["CONFIG_DIR"] = test_config_dir
                load_config.__globals__["DESTINATIONS_FILE"] = dest_file
                load_config.__globals__["BLOCKED_TRAPS_FILE"] = blocked_file
                load_config.__globals__["LISTEN_PORTS_FILE"] = ports_file

                # Create a test callback to track if it was called
                callback_called = False

                def test_callback():
                    nonlocal callback_called
                    callback_called = True

                # Load the configuration
                result = load_config(test_callback)

                # Check that callback was called if port configuration changed
                if getattr(load_config, "__globals__", {}).get("LISTEN_PORTS", []) != [162, 1162]:
                    self.assertTrue(callback_called, "Callback was not called when ports changed")

                # Check that function returned True for changed configuration
                self.assertTrue(result, "load_config should return True when config changed")

                # Verify configuration was loaded
                destinations_loaded = getattr(load_config, "__globals__", {}).get("destinations", [])
                blocked_traps_loaded = getattr(load_config, "__globals__", {}).get("blocked_traps", set())
                ports_loaded = getattr(load_config, "__globals__", {}).get("LISTEN_PORTS", [])

                self.assertEqual(len(destinations_loaded), 2, "Destinations not loaded correctly")
                self.assertIn("1.3.6.1.4.1.9999.1.1.1", blocked_traps_loaded, "Blocked traps not loaded correctly")
                self.assertEqual(set(ports_loaded), set([162, 1162]), "Listen ports not loaded correctly")
            finally:
                # Restore original paths
                for key, value in original_paths.items():
                    if value and key in load_config.__globals__:
                        load_config.__globals__[key] = value

    @unittest.skipIf(not DIRECT_IMPORTS, "Direct imports not available")
    def test_redirection_config_loading(self):
        """Test loading redirection configuration"""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create test config files
            test_config_dir = os.path.join(temp_dir, "config")
            os.makedirs(test_config_dir, exist_ok=True)

            # Create test redirection configurations
            redirected_ips_file = os.path.join(test_config_dir, "redirected_ips.json")
            with open(redirected_ips_file, 'w') as f:
                json.dump([["192.168.1.100", "security"], ["10.0.0.1", "config"]], f)

            redirected_oids_file = os.path.join(test_config_dir, "redirected_oids.json")
            with open(redirected_oids_file, 'w') as f:
                json.dump([["1.3.6.1.4.1.9999.1.1.1", "security"]], f)

            redirected_dest_file = os.path.join(test_config_dir, "redirected_destinations.json")
            with open(redirected_dest_file, 'w') as f:
                json.dump({
                    "security": [["127.0.0.1", 1362]],
                    "config": [["127.0.0.1", 1462]]
                }, f)

            # Get original function for get_config_path to restore later
            if hasattr(load_redirected_ips, "__globals__") and "get_config_path" in load_redirected_ips.__globals__:
                original_get_config_path = load_redirected_ips.__globals__["get_config_path"]

                try:
                    # Create a mock get_config_path function
                    def mock_get_config_path(filename):
                        return os.path.join(test_config_dir, filename)

                    # Replace the get_config_path function
                    load_redirected_ips.__globals__["get_config_path"] = mock_get_config_path
                    load_redirected_oids.__globals__["get_config_path"] = mock_get_config_path
                    load_redirected_destinations.__globals__["get_config_path"] = mock_get_config_path

                    # Load redirection configuration
                    redirected_ips = load_redirected_ips()
                    redirected_oids = load_redirected_oids()
                    redirected_destinations = load_redirected_destinations()

                    # Check loaded configurations
                    self.assertEqual(redirected_ips.get("192.168.1.100"), "security",
                                     "Redirected IPs not loaded correctly")
                    self.assertEqual(redirected_ips.get("10.0.0.1"), "config",
                                     "Redirected IPs not loaded correctly")

                    self.assertEqual(redirected_oids.get("1.3.6.1.4.1.9999.1.1.1"), "security",
                                     "Redirected OIDs not loaded correctly")

                    self.assertIn("security", redirected_destinations,
                                  "Redirected destinations not loaded correctly")
                    self.assertIn("config", redirected_destinations,
                                  "Redirected destinations not loaded correctly")
                finally:
                    # Restore original function
                    load_redirected_ips.__globals__["get_config_path"] = original_get_config_path
                    load_redirected_oids.__globals__["get_config_path"] = original_get_config_path
                    load_redirected_destinations.__globals__["get_config_path"] = original_get_config_path


class ConfigIntegrationTests(unittest.TestCase):
    """Integration tests for configuration management"""

    def test_config_validation_integration(self):
        """Test configuration validation in service"""
        # Test with various invalid configurations
        test_cases = [
            # Invalid port configuration
            {
                "name": "Invalid port number",
                "config": {"listen_ports.json": [99999]},
                "expected_port": 162  # Should revert to default
            },
            # Invalid IP in destinations
            {
                "name": "Invalid IP in destinations",
                "config": {"destinations.json": [["999.999.999.999", FORWARD_PORT_1]]},
                "expected_forwards": 0  # Should not forward to invalid IP
            },
            # Empty configuration
            {
                "name": "Empty configuration",
                "config": {
                    "destinations.json": [],
                    "blocked_traps.json": [],
                    "listen_ports.json": [LISTEN_PORT],  # Keep valid port
                    "blocked_ips.json": []
                },
                "expected_forwards": 0  # No destinations configured
            }
        ]

        for test_case in test_cases:
            with self.subTest(test_case["name"]):
                with temp_config_files(test_case["config"]) as config_dir:
                    # Start listener on forward port
                    listener = UDPListener(FORWARD_PORT_1)
                    listener.start()

                    try:
                        # Start service
                        proc = start_service(config_dir)

                        try:
                            # Service should start despite config issues
                            self.assertIsNone(proc.poll(),
                                              f"Service crashed with {test_case['name']}")

                            # Send a test packet
                            send_udp_packet(LISTEN_PORT, b"test packet")

                            # Wait for processing
                            time.sleep(2)

                            # Check forwarding based on test case expectations
                            self.assertEqual(listener.get_packet_count(),
                                             test_case.get("expected_forwards", 0),
                                             f"Unexpected forwarding with {test_case['name']}")
                        finally:
                            # Stop service
                            proc.terminate()
                            proc.wait(timeout=2)
                    finally:
                        listener.stop()

    def test_dynamic_config_update(self):
        """Test dynamic configuration updates"""
        with temp_config_files() as config_dir:
            # Set up listeners for all potential destinations
            listeners = {}
            try:
                # Start primary listener
                primary_listener = UDPListener(FORWARD_PORT_1)
                primary_listener.start()
                listeners["primary"] = primary_listener

                # Start security listener
                security_listener = UDPListener(SECURITY_PORT)
                security_listener.start()
                listeners["security"] = security_listener

                # Start service
                proc = start_service(config_dir)

                try:
                    # Send initial packet
                    send_udp_packet(LISTEN_PORT, b"test packet 1")
                    time.sleep(2)

                    # Check initial forwarding
                    self.assertGreaterEqual(primary_listener.get_packet_count(), 1,
                                            "Packet not forwarded to primary destination")

                    # Update config to redirect source IP to security group
                    with open(os.path.join(config_dir, "redirected_ips.json"), 'w') as f:
                        json.dump([["127.0.0.1", "security"]], f)

                    # Wait for config reload
                    time.sleep(2)  # Config check interval might be up to 60 seconds in production

                    # Clear listener queues
                    while not primary_listener.received_packets.empty():
                        primary_listener.received_packets.get()

                    # Send another packet
                    send_udp_packet(LISTEN_PORT, b"test packet 2")
                    time.sleep(2)

                    # Check updated forwarding
                    self.assertEqual(primary_listener.get_packet_count(), 0,
                                     "Packet forwarded to primary despite redirection")
                    self.assertGreaterEqual(security_listener.get_packet_count(), 1,
                                            "Packet not redirected to security destination")
                finally:
                    # Stop service
                    proc.terminate()
                    proc.wait(timeout=2)
            finally:
                # Stop all listeners
                for listener in listeners.values():
                    listener.stop()

    def test_invalid_config_recovery(self):
        """Test service recovery from invalid configuration"""
        with temp_config_files() as config_dir:
            # Set up listeners for forward port
            listener = UDPListener(FORWARD_PORT_1)
            listener.start()

            try:
                # Start service
                proc = start_service(config_dir)

                try:
                    # Send initial packet
                    send_udp_packet(LISTEN_PORT, b"test packet 1")
                    time.sleep(2)

                    # Check initial forwarding
                    initial_count = listener.get_packet_count()
                    self.assertGreaterEqual(initial_count, 1,
                                            "Initial packet not forwarded")

                    # Create invalid configuration
                    with open(os.path.join(config_dir, "destinations.json"), 'w') as f:
                        f.write("{ invalid json }")

                    # Wait for config reload attempt
                    time.sleep(2)

                    # Send another packet
                    send_udp_packet(LISTEN_PORT, b"test packet 2")
                    time.sleep(2)

                    # Service should continue using last valid configuration
                    new_count = listener.get_packet_count()
                    self.assertGreaterEqual(new_count, initial_count + 1,
                                            "Service didn't continue after invalid config")

                    # Fix the configuration
                    with open(os.path.join(config_dir, "destinations.json"), 'w') as f:
                        json.dump([["127.0.0.1", FORWARD_PORT_1]], f)

                    # Wait for valid config reload
                    time.sleep(2)
                finally:
                    # Stop service
                    proc.terminate()
                    proc.wait(timeout=2)
            finally:
                listener.stop()

    def test_config_priority(self):
        """Test configuration priority and override behavior"""
        # Create initial configuration with multiple rules
        initial_config = {
            "redirected_ips.json": [["127.0.0.1", "security"]],
            "blocked_ips.json": []  # Not blocking initially
        }

        with temp_config_files(initial_config) as config_dir:
            # Set up listeners
            primary_listener = UDPListener(FORWARD_PORT_1)
            security_listener = UDPListener(SECURITY_PORT)
            blocked_listener = UDPListener(CONFIG_PORT)  # Used for blocked destinations

            primary_listener.start()
            security_listener.start()
            blocked_listener.start()

            try:
                # Start service
                proc = start_service(config_dir)

                try:
                    # Send initial packet - should be redirected to security
                    send_udp_packet(LISTEN_PORT, b"test packet 1")
                    time.sleep(2)

                    # Check initial redirection
                    self.assertEqual(primary_listener.get_packet_count(), 0,
                                     "Packet forwarded to primary despite redirection")
                    self.assertGreaterEqual(security_listener.get_packet_count(), 1,
                                            "Packet not redirected to security destination")

                    # Now add IP to blocked list
                    with open(os.path.join(config_dir, "blocked_ips.json"), 'w') as f:
                        json.dump(["127.0.0.1"], f)

                    # Configure blocked destination
                    with open(os.path.join(config_dir, "redirected_destinations.json"), 'w') as f:
                        config = {
                            "security": [["127.0.0.1", SECURITY_PORT]],
                            "config": [["127.0.0.1", CONFIG_PORT]]
                        }
                        json.dump(config, f)

                    # Wait for config reload
                    time.sleep(2)

                    # Clear existing packets from queues
                    while not security_listener.received_packets.empty():
                        security_listener.received_packets.get()

                    # Send another packet - should be blocked (not redirected)
                    send_udp_packet(LISTEN_PORT, b"test packet 2")
                    time.sleep(2)

                    # Check priority: blocking should override redirection
                    self.assertEqual(primary_listener.get_packet_count(), 0,
                                     "Packet forwarded to primary despite blocking")
                    self.assertEqual(security_listener.get_packet_count(), 0,
                                     "Packet redirected despite being blocked")
                    self.assertGreaterEqual(blocked_listener.get_packet_count(), 1,
                                            "Blocked packet not sent to blocked destination")
                finally:
                    # Stop service
                    proc.terminate()
                    proc.wait(timeout=2)
            finally:
                primary_listener.stop()
                security_listener.stop()
                blocked_listener.stop()


class CommandLineConfigTests(unittest.TestCase):
    """Tests for command-line configuration management"""

    def test_cli_config_commands(self):
        """Test command-line configuration management commands"""
        with temp_config_files() as config_dir:
            # Test various configuration commands
            test_commands = [
                # IP management
                ["--block-ip", "192.168.1.100", "--config-dir", config_dir],
                ["--list-blocked-ips", "--config-dir", config_dir],
                ["--unblock-ip", "192.168.1.100", "--config-dir", config_dir],

                # OID management
                ["--block-oid", "1.3.6.1.4.1.9999.1.1.1", "--config-dir", config_dir],
                ["--list-blocked-oids", "--config-dir", config_dir],
                ["--unblock-oid", "1.3.6.1.4.1.9999.1.1.1", "--config-dir", config_dir],

                # Redirection management
                ["--redirect-ip", "192.168.1.100", "--tag", "security", "--config-dir", config_dir],
                ["--list-redirected-ips", "--config-dir", config_dir],
                ["--unredirect-ip", "192.168.1.100", "--config-dir", config_dir],

                ["--redirect-oid", "1.3.6.1.4.1.9999.1.1.1", "--tag", "security", "--config-dir", config_dir],
                ["--list-redirected-oids", "--config-dir", config_dir],
                ["--unredirect-oid", "1.3.6.1.4.1.9999.1.1.1", "--config-dir", config_dir],

                # Destination group management
                ["--add-destination", "security", "--ip", "10.0.0.1", "--port", "162", "--config-dir", config_dir],
                ["--list-groups", "--config-dir", config_dir],
                ["--remove-destination", "security", "--ip", "10.0.0.1", "--port", "162", "--config-dir", config_dir]
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
                            timeout=5
                        )

                        # Check for critical errors
                        self.assertEqual(result.returncode, 0,
                                         f"Command {cmd_args} failed with return code {result.returncode}")
                        self.assertNotIn("Traceback (most recent call last)", result.stderr.decode('utf-8'),
                                         f"Command {cmd_args} caused an exception")
                    except subprocess.TimeoutExpired:
                        self.fail(f"Command {cmd_args} timed out")

    def test_cli_port_config(self):
        """Test command-line port configuration"""
        with temp_config_files() as config_dir:
            # Set up listener
            listener = UDPListener(FORWARD_PORT_1)
            listener.start()

            try:
                # Start service with modified port
                custom_port = LISTEN_PORT + 10
                cmd = [
                    sys.executable,
                    "-m", "trapninja",
                    "--foreground",
                    "--interface", "lo",
                    "--config-dir", config_dir,
                    "--ports", f"{custom_port}"
                ]

                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True
                )

                try:
                    # Allow time for startup
                    time.sleep(2)

                    # Send packet to the custom port
                    send_udp_packet(custom_port, b"test packet")
                    time.sleep(2)

                    # Check that packet was forwarded
                    self.assertGreaterEqual(listener.get_packet_count(), 1,
                                            "Packet not forwarded when using custom port")

                    # Check that config file was updated with new port
                    with open(os.path.join(config_dir, "listen_ports.json"), 'r') as f:
                        ports = json.load(f)
                        self.assertIn(custom_port, ports,
                                      "Listen ports configuration file not updated")
                finally:
                    # Stop service
                    proc.terminate()
                    proc.wait(timeout=2)
            finally:
                listener.stop()

    def test_cli_log_config(self):
        """Test command-line logging configuration"""
        with temp_config_files() as config_dir:
            # Set log file path
            log_file = os.path.join(config_dir, "test.log")

            # Start service with custom log settings
            cmd = [
                sys.executable,
                "-m", "trapninja",
                "--foreground",
                "--interface", "lo",
                "--config-dir", config_dir,
                "--ports", f"{LISTEN_PORT}",
                "--log-file", log_file,
                "--log-level", "DEBUG",
                "--log-max-size", "1M",
                "--log-backup-count", "3",
                "--log-compress"
            ]

            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )

            try:
                # Allow time for startup
                time.sleep(2)

                # Send a test packet
                send_udp_packet(LISTEN_PORT, b"test packet")
                time.sleep(2)

                # Check that log file was created
                self.assertTrue(os.path.exists(log_file),
                                "Log file not created with custom path")

                # Check log content
                with open(log_file, 'r') as f:
                    log_content = f.read()
                    self.assertIn("TrapNinja", log_content,
                                  "Log file doesn't contain expected content")
            finally:
                # Stop service
                proc.terminate()
                proc.wait(timeout=2)


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
# !/usr/bin/env python3
"""
TrapNinja Configuration Tests

Tests for the configuration management functionality in TrapNinja,
focusing on config validation, loading, and dynamic updates.
"""

import os
import sys
import time
import json
import unittest
import tempfile
import shutil
import socket
import subprocess
import threading
from queue import Queue
from contextlib import contextmanager

# Add parent directory to path to import trapninja modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Try to import directly from trapninja for unit tests
try:
    from trapninja.config import (
        safe_load_json, load_config, ensure_config_dir, parse_size,
        destinations, blocked_traps, blocked_ips, LISTEN_PORTS
    )
    from trapninja.redirection import (
        load_redirected_ips, load_redirected_oids, load_redirected_destinations,
        validate_ip, validate_oid
    )

    DIRECT_IMPORTS = True
except ImportError:
    DIRECT_IMPORTS = False
    print("WARNING: Direct imports from trapninja failed, some unit tests will be skipped")

# Test configuration
TEST_DIR = os.path.abspath(os.path.dirname(__file__))
TEMP_DIR = tempfile.mkdtemp()
TEST_CONFIG_DIR = os.path.join(TEMP_DIR, "config")

# Network test parameters (use high ports for testing)
BASE_PORT = 16600  # Starting port number
LISTEN_PORT = BASE_PORT
FORWARD_PORT_1 = BASE_PORT + 1
FORWARD_PORT_2 = BASE_PORT + 2
SECURITY_PORT = BASE_PORT + 100
CONFIG_PORT = BASE_PORT + 200


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
                        break
                except socket.timeout:
                    continue
        finally:
            sock.close()

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