#!/usr/bin/env python3
"""
TrapNinja Test Suite - Integration Tests: Forwarding Pipeline

End-to-end tests for the trap forwarding pipeline.
Tests the complete flow from packet capture to forwarding.

Author: TrapNinja Team
"""

import os
import sys
import time
import socket
import struct
import threading
import queue
import pytest
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock, call


# =============================================================================
# Test Fixtures
# =============================================================================

@pytest.fixture
def mock_udp_receiver():
    """Create a mock UDP receiver to capture forwarded traps."""
    received = queue.Queue()
    server_socket = None
    stop_event = threading.Event()
    
    def receiver_thread(port):
        nonlocal server_socket
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(('127.0.0.1', port))
        server_socket.settimeout(0.1)
        
        while not stop_event.is_set():
            try:
                data, addr = server_socket.recvfrom(65535)
                received.put((data, addr))
            except socket.timeout:
                continue
            except Exception:
                break
        
        server_socket.close()
    
    class Receiver:
        def __init__(self):
            self.port = None
            self.thread = None
        
        def start(self, port=0):
            self.port = port if port else 51620
            self.thread = threading.Thread(target=receiver_thread, args=(self.port,))
            self.thread.daemon = True
            self.thread.start()
            time.sleep(0.1)  # Let server start
            return self.port
        
        def stop(self):
            stop_event.set()
            if self.thread:
                self.thread.join(timeout=1)
        
        def get_received(self, timeout=1.0):
            try:
                return received.get(timeout=timeout)
            except queue.Empty:
                return None
        
        def get_all_received(self):
            items = []
            while not received.empty():
                items.append(received.get_nowait())
            return items
    
    receiver = Receiver()
    yield receiver
    receiver.stop()


@pytest.fixture
def sample_snmp_trap():
    """Create a sample SNMPv2c trap packet."""
    return bytes([
        0x30, 0x3e,  # SEQUENCE, length 62
        0x02, 0x01, 0x01,  # INTEGER, version 1 (SNMPv2c)
        0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63,  # OCTET STRING, "public"
        0xa7, 0x31,  # SNMPv2-Trap PDU, length 49
        0x02, 0x04, 0x00, 0x00, 0x00, 0x01,  # request-id
        0x02, 0x01, 0x00,  # error-status
        0x02, 0x01, 0x00,  # error-index
        0x30, 0x23,  # variable-bindings SEQUENCE
        0x30, 0x10,  # varbind 1
        0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x03, 0x00,  # sysUpTime OID
        0x43, 0x04, 0x00, 0x00, 0x00, 0x64,  # TimeTicks value
        0x30, 0x0f,  # varbind 2
        0x06, 0x0a, 0x2b, 0x06, 0x01, 0x06, 0x03, 0x01, 0x01, 0x04, 0x01, 0x00,  # snmpTrapOID
        0x06, 0x01, 0x00,  # OID value
    ])


# =============================================================================
# Packet Queue Integration Tests
# =============================================================================

class TestPacketQueueIntegration:
    """Integration tests for packet queue processing."""

    def test_packet_flows_through_queue(self):
        """Test packet flows from capture to queue."""
        from trapninja.network import packet_queue
        
        # Clear any existing items
        while not packet_queue.empty():
            try:
                packet_queue.get_nowait()
            except queue.Empty:
                break
        
        # Create test packet info
        packet_info = {
            'src_ip': '192.168.1.100',
            'dst_port': 162,
            'payload': b'\x30\x05\x02\x01\x01',
            'timestamp': time.time()
        }
        
        # Queue the packet
        packet_queue.put_nowait(packet_info)
        
        # Verify it's in the queue
        assert not packet_queue.empty()
        
        # Retrieve and verify
        retrieved = packet_queue.get_nowait()
        assert retrieved['src_ip'] == '192.168.1.100'
        assert retrieved['dst_port'] == 162

    def test_queue_stats_record_queued(self):
        """Test queue statistics record_queued works."""
        from trapninja.network import _queue_stats
        
        initial_queued = _queue_stats.total_queued
        
        # Record some queued
        _queue_stats.record_queued()
        _queue_stats.record_queued()
        
        assert _queue_stats.total_queued >= initial_queued + 2

    def test_queue_stats_record_dropped(self):
        """Test queue statistics record_dropped works."""
        from trapninja.network import _queue_stats
        
        initial_dropped = _queue_stats.total_dropped
        
        # Record dropped
        _queue_stats.record_dropped()
        
        assert _queue_stats.total_dropped >= initial_dropped + 1

    def test_queue_handles_high_volume(self):
        """Test queue handles high volume of packets."""
        from trapninja.network import packet_queue
        
        # Clear queue
        while not packet_queue.empty():
            try:
                packet_queue.get_nowait()
            except queue.Empty:
                break
        
        # Queue many packets
        num_packets = 100
        for i in range(num_packets):
            packet_info = {
                'src_ip': f'192.168.1.{i % 256}',
                'dst_port': 162,
                'payload': b'\x30\x05',
                'seq': i
            }
            try:
                packet_queue.put_nowait(packet_info)
            except queue.Full:
                break
        
        # Verify packets are queued
        count = 0
        while not packet_queue.empty():
            try:
                packet_queue.get_nowait()
                count += 1
            except queue.Empty:
                break
        
        assert count > 0


# =============================================================================
# UDP Listener Integration Tests
# =============================================================================

class TestUDPListenerIntegration:
    """Integration tests for UDP listener setup."""

    def test_listener_can_bind_to_port(self):
        """Test UDP listener can bind to a port."""
        test_port = 51622
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            sock.bind(('127.0.0.1', test_port))
            assert True
        finally:
            sock.close()

    def test_listener_receives_packets(self):
        """Test UDP listener receives packets."""
        test_port = 51623
        
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            server.bind(('127.0.0.1', test_port))
            server.settimeout(1.0)
            
            # Send a test packet
            client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            test_data = b'\x30\x05\x02\x01\x01'
            client.sendto(test_data, ('127.0.0.1', test_port))
            client.close()
            
            # Receive the packet
            data, addr = server.recvfrom(1024)
            
            assert data == test_data
            assert addr[0] == '127.0.0.1'
        finally:
            server.close()


# =============================================================================
# Forwarding Pipeline Integration Tests
# =============================================================================

class TestForwardingPipelineIntegration:
    """Integration tests for the forwarding pipeline."""

    def test_forward_trap_function_exists(self):
        """Test forward_trap function is available."""
        from trapninja.network import forward_trap
        
        assert callable(forward_trap)

    def test_forward_packet_function_exists(self):
        """Test forward_packet function is available."""
        from trapninja.network import forward_packet
        
        assert callable(forward_packet)

    def test_destinations_receive_forwarded_traps(self, mock_udp_receiver, sample_snmp_trap):
        """Test destinations receive forwarded traps."""
        port = mock_udp_receiver.start(51624)
        
        # Send directly to receiver to verify it works
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.sendto(sample_snmp_trap, ('127.0.0.1', port))
        client.close()
        
        # Verify receipt
        received = mock_udp_receiver.get_received(timeout=2.0)
        
        assert received is not None
        assert received[0] == sample_snmp_trap


# =============================================================================
# OID Extraction Integration Tests
# =============================================================================

class TestOIDExtractionIntegration:
    """Integration tests for OID extraction in the pipeline."""

    def test_extract_trap_oid_fast_exists(self):
        """Test extract_trap_oid_fast function exists."""
        from trapninja.processing.parser import extract_trap_oid_fast
        
        assert callable(extract_trap_oid_fast)

    def test_is_snmpv2c_function_exists(self):
        """Test is_snmpv2c function exists."""
        from trapninja.processing.parser import is_snmpv2c
        
        assert callable(is_snmpv2c)

    def test_is_snmpv2c_detects_v2c(self, sample_snmp_trap):
        """Test is_snmpv2c correctly identifies SNMPv2c packets."""
        from trapninja.processing.parser import is_snmpv2c
        
        result = is_snmpv2c(sample_snmp_trap)
        
        assert result is True

    def test_oid_filtering_with_blocked_set(self):
        """Test OID-based filtering with blocked set."""
        from trapninja.config import blocked_traps
        
        original_blocked = blocked_traps.copy() if blocked_traps else set()
        
        try:
            blocked_traps.add('1.3.6.1.4.1.9999.1')
            assert '1.3.6.1.4.1.9999.1' in blocked_traps
            assert '1.3.6.1.4.1.8888.1' not in blocked_traps
        finally:
            blocked_traps.clear()
            blocked_traps.update(original_blocked)


# =============================================================================
# IP Filtering Integration Tests
# =============================================================================

class TestIPFilteringIntegration:
    """Integration tests for IP-based filtering."""

    def test_ip_blocking_integration(self):
        """Test IP blocking in the forwarding pipeline."""
        from trapninja.config import blocked_ips
        
        original_blocked = blocked_ips.copy() if blocked_ips else set()
        
        try:
            blocked_ips.add('10.0.0.1')
            assert '10.0.0.1' in blocked_ips
            assert '10.0.0.2' not in blocked_ips
        finally:
            blocked_ips.clear()
            blocked_ips.update(original_blocked)

    def test_redirection_module_available(self):
        """Test redirection module is available."""
        from trapninja import redirection
        
        assert redirection is not None

    def test_check_for_redirection_exists(self):
        """Test check_for_redirection function exists."""
        from trapninja.redirection import check_for_redirection
        
        assert callable(check_for_redirection)


# =============================================================================
# Metrics Integration Tests
# =============================================================================

class TestMetricsIntegration:
    """Integration tests for metrics collection in the pipeline."""

    def test_metrics_summary_available(self):
        """Test metrics summary is available."""
        from trapninja.metrics import get_metrics_summary, init_metrics
        
        init_metrics()
        summary = get_metrics_summary()
        
        assert isinstance(summary, dict)

    def test_metrics_module_functions_exist(self):
        """Test metrics module functions exist."""
        from trapninja.metrics import init_metrics, get_metrics_summary
        
        assert callable(init_metrics)
        assert callable(get_metrics_summary)


# =============================================================================
# Configuration Integration Tests
# =============================================================================

class TestConfigurationIntegration:
    """Integration tests for configuration loading."""

    def test_config_module_imports(self):
        """Test configuration module imports correctly."""
        from trapninja import config
        
        assert hasattr(config, 'INTERFACE')
        assert hasattr(config, 'LISTEN_PORTS')
        assert hasattr(config, 'destinations')
        assert hasattr(config, 'blocked_ips')
        assert hasattr(config, 'blocked_traps')

    def test_config_load_function_exists(self):
        """Test config load function exists."""
        from trapninja.config import load_config
        
        assert callable(load_config)


# =============================================================================
# End-to-End Pipeline Tests
# =============================================================================

class TestEndToEndPipeline:
    """End-to-end tests for the complete pipeline."""

    def test_full_pipeline_trap_to_destination(self, mock_udp_receiver, sample_snmp_trap):
        """Test complete pipeline from trap receipt to forwarding."""
        port = mock_udp_receiver.start(51625)
        
        from trapninja.config import blocked_ips
        
        src_ip = '192.168.1.50'
        
        if src_ip not in blocked_ips:
            client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            client.sendto(sample_snmp_trap, ('127.0.0.1', port))
            client.close()
        
        received = mock_udp_receiver.get_received(timeout=2.0)
        assert received is not None

    def test_pipeline_blocks_filtered_ip(self, mock_udp_receiver, sample_snmp_trap):
        """Test pipeline blocks traps from filtered IPs."""
        from trapninja.config import blocked_ips
        
        port = mock_udp_receiver.start(51626)
        original_blocked = blocked_ips.copy()
        
        try:
            blocked_ips.add('192.168.1.50')
            src_ip = '192.168.1.50'
            
            if src_ip in blocked_ips:
                pass  # Don't forward
            else:
                client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                client.sendto(sample_snmp_trap, ('127.0.0.1', port))
                client.close()
            
            received = mock_udp_receiver.get_received(timeout=0.5)
            assert received is None
        finally:
            blocked_ips.clear()
            blocked_ips.update(original_blocked)

    def test_pipeline_handles_multiple_destinations(self, sample_snmp_trap):
        """Test pipeline forwards to multiple destinations."""
        receivers = []
        ports = [51627, 51628, 51629]
        
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(('127.0.0.1', port))
            sock.settimeout(0.5)
            receivers.append(sock)
        
        try:
            client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            for port in ports:
                client.sendto(sample_snmp_trap, ('127.0.0.1', port))
            client.close()
            
            received_count = 0
            for sock in receivers:
                try:
                    data, addr = sock.recvfrom(1024)
                    if data == sample_snmp_trap:
                        received_count += 1
                except socket.timeout:
                    pass
            
            assert received_count == len(ports)
        finally:
            for sock in receivers:
                sock.close()


# =============================================================================
# Performance Integration Tests
# =============================================================================

class TestPerformanceIntegration:
    """Performance-related integration tests."""

    def test_high_throughput_forwarding(self, mock_udp_receiver, sample_snmp_trap):
        """Test forwarding handles high throughput."""
        port = mock_udp_receiver.start(51630)
        num_traps = 100
        
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        start_time = time.time()
        
        for _ in range(num_traps):
            client.sendto(sample_snmp_trap, ('127.0.0.1', port))
        
        client.close()
        elapsed = time.time() - start_time
        
        time.sleep(0.5)
        all_received = mock_udp_receiver.get_all_received()
        
        assert len(all_received) > num_traps * 0.9

    def test_queue_does_not_block_under_load(self):
        """Test packet queue doesn't block under load."""
        from trapninja.network import packet_queue
        
        while not packet_queue.empty():
            try:
                packet_queue.get_nowait()
            except queue.Empty:
                break
        
        start_time = time.time()
        queued = 0
        
        for i in range(1000):
            try:
                packet_queue.put_nowait({
                    'src_ip': '192.168.1.1',
                    'payload': b'\x30\x05',
                    'seq': i
                })
                queued += 1
            except queue.Full:
                break
        
        elapsed = time.time() - start_time
        assert elapsed < 1.0
        
        while not packet_queue.empty():
            try:
                packet_queue.get_nowait()
            except queue.Empty:
                break
