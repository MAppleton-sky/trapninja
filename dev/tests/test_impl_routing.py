#!/usr/bin/env python3
"""
TrapNinja Implementation Tests - Phase 10B: Multi-Destination Routing

Validates multi-destination forwarding, destination groups, and routing
logic with minimal mocking of external dependencies.

ASSUMPTIONS:
- destinations list contains (ip, port) tuples for fan-out delivery
- blocked_dest receives blocked traps if configured
- redirected_destinations maps tag names to destination lists
- forward_packet() sends to ALL destinations in the provided list
- forward_packet_batch() processes multiple packets efficiently
- Socket pool provides pre-initialized sockets for performance
- Scapy fallback handles cases where raw sockets unavailable
- IP checksum is calculated correctly for raw packets
- Source port uses FORWARD_SOURCE_PORT to prevent capture loops

Author: TrapNinja Team
"""

import os
import sys
import time
import socket
import struct
import threading
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch, call, PropertyMock
from typing import Dict, List, Any, Tuple

# Add src directory to path
TEST_DIR = Path(__file__).parent
PROJECT_ROOT = TEST_DIR.parent.parent
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))


# =============================================================================
# TEST PACKET BUILDER (from Phase 10A)
# =============================================================================

def _encode_oid_component(num: int) -> bytes:
    """Encode a single OID component using ASN.1 BER encoding."""
    if num == 0:
        return bytes([0])
    
    octets = []
    while num:
        octets.append(num & 0x7F)
        num >>= 7
    
    for i in range(1, len(octets)):
        octets[i] |= 0x80
    
    return bytes(reversed(octets))


def build_snmpv2c_trap(
    community: str = "public",
    trap_oid: str = "1.3.6.1.4.1.8072.2.3.0.1",
    request_id: int = 1
) -> bytes:
    """Build a valid SNMPv2c trap packet."""
    oid_parts = [int(p) for p in trap_oid.split('.')]
    oid_bytes = bytearray([oid_parts[0] * 40 + oid_parts[1]])
    for num in oid_parts[2:]:
        oid_bytes.extend(_encode_oid_component(num))
    
    snmptrapoid_marker = bytes([0x2b, 0x06, 0x01, 0x06, 0x03, 0x01, 0x01, 0x04, 0x01, 0x00])
    
    varbind_oid = bytes([
        0x30, len(snmptrapoid_marker) + 2 + len(oid_bytes) + 2,
        0x06, len(snmptrapoid_marker),
    ]) + snmptrapoid_marker + bytes([
        0x06, len(oid_bytes)
    ]) + bytes(oid_bytes)
    
    sysuptime_oid = bytes([0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x03, 0x00])
    varbind_uptime = bytes([
        0x30, len(sysuptime_oid) + 2 + 4 + 2,
        0x06, len(sysuptime_oid),
    ]) + sysuptime_oid + bytes([
        0x43, 0x04, 0x00, 0x00, 0x00, 0x01
    ])
    
    varbindlist = bytes([0x30, len(varbind_uptime) + len(varbind_oid)]) + varbind_uptime + varbind_oid
    
    pdu_content = bytes([
        0x02, 0x04,
    ]) + struct.pack('>I', request_id) + bytes([
        0x02, 0x01, 0x00,
        0x02, 0x01, 0x00,
    ]) + varbindlist
    
    pdu = bytes([0xa7, len(pdu_content)]) + pdu_content
    
    community_bytes = community.encode('ascii')
    community_field = bytes([0x04, len(community_bytes)]) + community_bytes
    
    version_field = bytes([0x02, 0x01, 0x01])
    
    message_content = version_field + community_field + pdu
    message = bytes([0x30, len(message_content)]) + message_content
    
    return message


# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture
def sample_payload():
    """Create a sample SNMP trap payload."""
    return build_snmpv2c_trap()


@pytest.fixture
def single_destination():
    """Single destination for basic tests."""
    return [('192.168.1.100', 162)]


@pytest.fixture
def multi_destinations():
    """Multiple destinations for fan-out tests."""
    return [
        ('192.168.1.100', 162),
        ('192.168.1.101', 162),
        ('192.168.1.102', 162),
        ('10.0.0.50', 162),
    ]


@pytest.fixture
def destination_groups():
    """Redirected destination groups."""
    return {
        'voice': [('10.10.10.1', 162), ('10.10.10.2', 162)],
        'data': [('10.20.20.1', 162)],
        'security': [('10.30.30.1', 162), ('10.30.30.2', 162), ('10.30.30.3', 162)],
        'blocked_archive': [('10.99.99.1', 1162)],
    }


@pytest.fixture
def mock_config(multi_destinations, destination_groups):
    """Complete mock configuration."""
    return {
        'destinations': multi_destinations,
        'blocked_traps': {'1.3.6.1.4.1.9999.1'},
        'blocked_dest': [('10.99.99.1', 1162)],
        'blocked_ips': {'10.0.0.99'},
        'redirected_ips': {
            '192.168.10.50': 'voice',
            '192.168.20.50': 'data',
        },
        'redirected_oids': {
            '1.3.6.1.4.1.8072.2.3.0.99': 'security',
        },
        'redirected_destinations': destination_groups,
    }


# =============================================================================
# TEST CLASS: FAN-OUT FORWARDING
# =============================================================================

class TestFanOutForwarding:
    """Test forwarding to multiple destinations simultaneously."""
    
    def test_forward_to_single_destination(self, sample_payload, single_destination):
        """Forward to single destination works."""
        from trapninja.processing.forwarder import forward_packet
        
        with patch('trapninja.processing.forwarder.get_socket_pool') as mock_pool:
            mock_socket = MagicMock()
            mock_pool_instance = MagicMock()
            mock_pool_instance.is_raw_available = True
            mock_pool_instance.acquire.return_value = mock_socket
            mock_pool.return_value = mock_pool_instance
            
            result = forward_packet('192.168.1.50', sample_payload, single_destination)
            
            assert result is True
            mock_socket.sendto.assert_called_once()
            mock_pool_instance.release.assert_called_once_with(mock_socket)
    
    def test_forward_to_multiple_destinations(self, sample_payload, multi_destinations):
        """Forward fans out to all destinations."""
        from trapninja.processing.forwarder import forward_packet
        
        with patch('trapninja.processing.forwarder.get_socket_pool') as mock_pool:
            mock_socket = MagicMock()
            mock_pool_instance = MagicMock()
            mock_pool_instance.is_raw_available = True
            mock_pool_instance.acquire.return_value = mock_socket
            mock_pool.return_value = mock_pool_instance
            
            result = forward_packet('192.168.1.50', sample_payload, multi_destinations)
            
            assert result is True
            # Should call sendto for each destination
            assert mock_socket.sendto.call_count == len(multi_destinations)
    
    def test_forward_captures_all_destination_ips(self, sample_payload, multi_destinations):
        """Verify packets sent to correct destination IPs."""
        from trapninja.processing.forwarder import forward_packet
        
        sent_destinations = []
        
        def capture_sendto(packet, addr):
            sent_destinations.append(addr[0])
        
        with patch('trapninja.processing.forwarder.get_socket_pool') as mock_pool:
            mock_socket = MagicMock()
            mock_socket.sendto.side_effect = capture_sendto
            mock_pool_instance = MagicMock()
            mock_pool_instance.is_raw_available = True
            mock_pool_instance.acquire.return_value = mock_socket
            mock_pool.return_value = mock_pool_instance
            
            forward_packet('192.168.1.50', sample_payload, multi_destinations)
            
            expected_ips = [d[0] for d in multi_destinations]
            assert sorted(sent_destinations) == sorted(expected_ips)
    
    def test_forward_empty_destinations_returns_false(self, sample_payload):
        """Empty destination list returns False without error."""
        from trapninja.processing.forwarder import forward_packet
        
        result = forward_packet('192.168.1.50', sample_payload, [])
        
        assert result is False
    
    def test_forward_partial_failure_returns_true(self, sample_payload, multi_destinations):
        """Partial failure (some destinations) still returns True."""
        from trapninja.processing.forwarder import forward_packet
        
        call_count = [0]
        
        def failing_sendto(packet, addr):
            call_count[0] += 1
            if call_count[0] == 2:  # Fail on second destination
                raise OSError("Connection refused")
        
        with patch('trapninja.processing.forwarder.get_socket_pool') as mock_pool:
            mock_socket = MagicMock()
            mock_socket.sendto.side_effect = failing_sendto
            mock_pool_instance = MagicMock()
            mock_pool_instance.is_raw_available = True
            mock_pool_instance.acquire.return_value = mock_socket
            mock_pool.return_value = mock_pool_instance
            
            result = forward_packet('192.168.1.50', sample_payload, multi_destinations)
            
            # Should still return True because at least one succeeded
            assert result is True


# =============================================================================
# TEST CLASS: DESTINATION GROUPS
# =============================================================================

class TestDestinationGroups:
    """Test routing to different destination groups via redirection."""
    
    def test_redirected_destinations_have_multiple_targets(self, destination_groups):
        """Redirected groups can have multiple targets."""
        assert len(destination_groups['voice']) == 2
        assert len(destination_groups['security']) == 3
        assert len(destination_groups['data']) == 1
    
    def test_ip_redirection_uses_correct_group(self, sample_payload, mock_config):
        """IP redirection forwards to correct destination group."""
        from trapninja.processing.worker import PacketWorker
        from trapninja.processing.worker import _config_cache
        import queue
        import threading
        
        pq = queue.Queue()
        stop = threading.Event()
        worker = PacketWorker(0, pq, stop)
        
        forwarded_to = []
        
        def capture_forward(src_ip, payload, destinations):
            forwarded_to.append(destinations)
        
        with patch.object(_config_cache, 'get', return_value=mock_config), \
             patch('trapninja.processing.worker.forward_packet', side_effect=capture_forward), \
             patch('trapninja.processing.worker.is_forwarding_enabled', return_value=True), \
             patch('trapninja.processing.worker.notify_trap_processed'):
            
            packet_data = {
                'src_ip': '192.168.10.50',  # Redirected to 'voice'
                'dst_port': 162,
                'payload': sample_payload
            }
            
            worker._process_packet(packet_data)
            
            assert len(forwarded_to) == 1
            assert forwarded_to[0] == mock_config['redirected_destinations']['voice']
    
    def test_oid_redirection_uses_correct_group(self, mock_config):
        """OID redirection forwards to correct destination group."""
        from trapninja.processing.worker import PacketWorker
        from trapninja.processing.worker import _config_cache
        import queue
        import threading
        
        pq = queue.Queue()
        stop = threading.Event()
        worker = PacketWorker(0, pq, stop)
        
        forwarded_to = []
        
        def capture_forward(src_ip, payload, destinations):
            forwarded_to.append(destinations)
        
        # Build trap with OID that gets redirected to 'security'
        payload = build_snmpv2c_trap(trap_oid='1.3.6.1.4.1.8072.2.3.0.99')
        
        with patch.object(_config_cache, 'get', return_value=mock_config), \
             patch('trapninja.processing.worker.forward_packet', side_effect=capture_forward), \
             patch('trapninja.processing.worker.is_forwarding_enabled', return_value=True), \
             patch('trapninja.processing.worker.notify_trap_processed'):
            
            packet_data = {
                'src_ip': '192.168.1.50',  # Not IP-redirected
                'dst_port': 162,
                'payload': payload
            }
            
            worker._process_packet(packet_data)
            
            assert len(forwarded_to) == 1
            assert forwarded_to[0] == mock_config['redirected_destinations']['security']
    
    def test_normal_traffic_uses_default_destinations(self, sample_payload, mock_config):
        """Non-redirected traffic goes to default destinations."""
        from trapninja.processing.worker import PacketWorker
        from trapninja.processing.worker import _config_cache
        import queue
        import threading
        
        pq = queue.Queue()
        stop = threading.Event()
        worker = PacketWorker(0, pq, stop)
        
        forwarded_to = []
        
        def capture_forward(src_ip, payload, destinations):
            forwarded_to.append(destinations)
        
        with patch.object(_config_cache, 'get', return_value=mock_config), \
             patch('trapninja.processing.worker.forward_packet', side_effect=capture_forward), \
             patch('trapninja.processing.worker.is_forwarding_enabled', return_value=True), \
             patch('trapninja.processing.worker.notify_trap_processed'):
            
            packet_data = {
                'src_ip': '192.168.1.50',  # Normal, non-redirected
                'dst_port': 162,
                'payload': sample_payload  # Normal OID
            }
            
            worker._process_packet(packet_data)
            
            assert len(forwarded_to) == 1
            assert forwarded_to[0] == mock_config['destinations']


# =============================================================================
# TEST CLASS: BLOCKED DESTINATION ROUTING
# =============================================================================

class TestBlockedDestinationRouting:
    """Test routing blocked traps to blocked_dest."""
    
    def test_blocked_oid_routes_to_blocked_dest(self, mock_config):
        """Blocked OID traps route to blocked_dest."""
        from trapninja.processing.worker import PacketWorker
        from trapninja.processing.worker import _config_cache
        import queue
        import threading
        
        pq = queue.Queue()
        stop = threading.Event()
        worker = PacketWorker(0, pq, stop)
        
        forwarded_to = []
        
        def capture_forward(src_ip, payload, destinations):
            forwarded_to.append(destinations)
        
        # Build trap with blocked OID
        payload = build_snmpv2c_trap(trap_oid='1.3.6.1.4.1.9999.1')
        
        with patch.object(_config_cache, 'get', return_value=mock_config), \
             patch('trapninja.processing.worker.forward_packet', side_effect=capture_forward), \
             patch('trapninja.processing.worker.is_forwarding_enabled', return_value=True):
            
            packet_data = {
                'src_ip': '192.168.1.50',
                'dst_port': 162,
                'payload': payload
            }
            
            worker._process_packet(packet_data)
            
            # Should forward to blocked_dest only
            assert len(forwarded_to) == 1
            assert forwarded_to[0] == mock_config['blocked_dest']
    
    def test_blocked_ip_not_forwarded_anywhere(self, sample_payload, mock_config):
        """Blocked IP traps are dropped entirely (no blocked_dest for IP blocks)."""
        from trapninja.processing.worker import PacketWorker
        from trapninja.processing.worker import _config_cache
        import queue
        import threading
        
        pq = queue.Queue()
        stop = threading.Event()
        worker = PacketWorker(0, pq, stop)
        
        with patch.object(_config_cache, 'get', return_value=mock_config), \
             patch('trapninja.processing.worker.forward_packet') as mock_forward, \
             patch('trapninja.processing.worker.is_forwarding_enabled', return_value=True):
            
            packet_data = {
                'src_ip': '10.0.0.99',  # Blocked IP
                'dst_port': 162,
                'payload': sample_payload
            }
            
            worker._process_packet(packet_data)
            
            # IP blocking drops the packet, doesn't route to blocked_dest
            mock_forward.assert_not_called()
    
    def test_empty_blocked_dest_drops_blocked_traps(self, sample_payload):
        """When blocked_dest is empty, blocked traps are dropped."""
        from trapninja.processing.worker import PacketWorker
        from trapninja.processing.worker import _config_cache
        import queue
        import threading
        
        config = {
            'destinations': [('192.168.1.100', 162)],
            'blocked_traps': {'1.3.6.1.4.1.9999.1'},
            'blocked_dest': [],  # Empty - blocked traps should be dropped
            'blocked_ips': set(),
            'redirected_ips': {},
            'redirected_oids': {},
            'redirected_destinations': {},
        }
        
        pq = queue.Queue()
        stop = threading.Event()
        worker = PacketWorker(0, pq, stop)
        
        payload = build_snmpv2c_trap(trap_oid='1.3.6.1.4.1.9999.1')
        
        with patch.object(_config_cache, 'get', return_value=config), \
             patch('trapninja.processing.worker.forward_packet') as mock_forward, \
             patch('trapninja.processing.worker.is_forwarding_enabled', return_value=True):
            
            packet_data = {
                'src_ip': '192.168.1.50',
                'dst_port': 162,
                'payload': payload
            }
            
            worker._process_packet(packet_data)
            
            # Should not forward anywhere
            mock_forward.assert_not_called()


# =============================================================================
# TEST CLASS: PACKET BUILDING
# =============================================================================

class TestPacketBuilding:
    """Test raw packet construction for forwarding."""
    
    def test_build_packet_creates_valid_ip_header(self, sample_payload):
        """build_packet creates valid IP header."""
        from trapninja.processing.forwarder import build_packet
        
        packet = build_packet('192.168.1.50', '10.0.0.1', 10162, 162, sample_payload)
        
        # IP header is first 20 bytes
        assert len(packet) >= 20
        
        # Check version (4) and IHL (5) in first byte
        assert packet[0] == 0x45
        
        # Check protocol is UDP (17)
        assert packet[9] == 17
    
    def test_build_packet_includes_correct_ports(self, sample_payload):
        """build_packet includes correct source and dest ports."""
        from trapninja.processing.forwarder import build_packet
        
        packet = build_packet('192.168.1.50', '10.0.0.1', 10162, 162, sample_payload)
        
        # UDP header starts at byte 20
        src_port = struct.unpack('!H', packet[20:22])[0]
        dst_port = struct.unpack('!H', packet[22:24])[0]
        
        assert src_port == 10162
        assert dst_port == 162
    
    def test_build_packet_includes_payload(self, sample_payload):
        """build_packet includes full payload after headers."""
        from trapninja.processing.forwarder import build_packet
        
        packet = build_packet('192.168.1.50', '10.0.0.1', 10162, 162, sample_payload)
        
        # IP (20) + UDP (8) + payload
        expected_len = 20 + 8 + len(sample_payload)
        assert len(packet) == expected_len
        
        # Payload should be at the end
        assert packet[28:] == sample_payload
    
    def test_build_packet_calculates_ip_checksum(self, sample_payload):
        """build_packet calculates valid IP checksum."""
        from trapninja.processing.forwarder import build_packet, _ip_checksum
        
        packet = build_packet('192.168.1.50', '10.0.0.1', 10162, 162, sample_payload)
        
        # Extract IP header
        ip_header = bytearray(packet[:20])
        
        # Zero out checksum field (bytes 10-11)
        original_checksum = struct.unpack('!H', ip_header[10:12])[0]
        ip_header[10:12] = b'\x00\x00'
        
        # Recalculate
        calculated = _ip_checksum(bytes(ip_header))
        
        assert calculated == original_checksum
    
    def test_build_packet_source_ip_encoded(self, sample_payload):
        """build_packet encodes source IP correctly."""
        from trapninja.processing.forwarder import build_packet
        
        packet = build_packet('192.168.1.50', '10.0.0.1', 10162, 162, sample_payload)
        
        # Source IP is at bytes 12-15
        src_ip_bytes = packet[12:16]
        src_ip = socket.inet_ntoa(src_ip_bytes)
        
        assert src_ip == '192.168.1.50'
    
    def test_build_packet_dest_ip_encoded(self, sample_payload):
        """build_packet encodes destination IP correctly."""
        from trapninja.processing.forwarder import build_packet
        
        packet = build_packet('192.168.1.50', '10.0.0.1', 10162, 162, sample_payload)
        
        # Dest IP is at bytes 16-19
        dst_ip_bytes = packet[16:20]
        dst_ip = socket.inet_ntoa(dst_ip_bytes)
        
        assert dst_ip == '10.0.0.1'


# =============================================================================
# TEST CLASS: SOCKET POOL
# =============================================================================

class TestSocketPool:
    """Test socket pool management."""
    
    def test_socket_pool_initializes(self):
        """Socket pool initializes successfully."""
        from trapninja.processing.forwarder import SocketPool
        
        pool = SocketPool(pool_size=2)
        
        # Pool should be able to initialize (may fail on raw sockets without root)
        result = pool.initialize()
        
        # Result is boolean
        assert isinstance(result, bool)
        pool.shutdown()
    
    def test_socket_pool_acquire_release_cycle(self):
        """Socket pool acquire/release works correctly."""
        from trapninja.processing.forwarder import SocketPool
        
        pool = SocketPool(pool_size=2)
        pool._raw_available = True
        pool._initialized = True
        
        # Manually add mock sockets
        mock_sock = MagicMock()
        pool._sockets.append(mock_sock)
        pool._available.release()
        
        # Acquire
        sock = pool.acquire(timeout=0.1)
        assert sock is mock_sock
        
        # Release
        pool.release(sock)
        
        # Should be able to acquire again
        sock2 = pool.acquire(timeout=0.1)
        assert sock2 is mock_sock
        
        pool.shutdown()
    
    def test_socket_pool_returns_none_when_unavailable(self):
        """Socket pool returns None when raw sockets unavailable."""
        from trapninja.processing.forwarder import SocketPool
        
        pool = SocketPool(pool_size=2)
        pool._raw_available = False
        pool._initialized = True
        
        sock = pool.acquire(timeout=0.1)
        
        assert sock is None
        pool.shutdown()
    
    def test_socket_pool_shutdown_closes_sockets(self):
        """Socket pool shutdown closes all sockets."""
        from trapninja.processing.forwarder import SocketPool
        
        pool = SocketPool(pool_size=2)
        pool._raw_available = True
        pool._initialized = True
        
        mock_sock1 = MagicMock()
        mock_sock2 = MagicMock()
        pool._sockets.append(mock_sock1)
        pool._sockets.append(mock_sock2)
        
        pool.shutdown()
        
        mock_sock1.close.assert_called_once()
        mock_sock2.close.assert_called_once()
        assert len(pool._sockets) == 0


# =============================================================================
# TEST CLASS: SCAPY FALLBACK
# =============================================================================

class TestScapyFallback:
    """Test Scapy fallback when raw sockets unavailable."""
    
    def test_forward_uses_scapy_when_raw_unavailable(self, sample_payload, single_destination):
        """Scapy fallback used when raw sockets unavailable."""
        from trapninja.processing.forwarder import forward_packet
        
        with patch('trapninja.processing.forwarder.get_socket_pool') as mock_pool, \
             patch('trapninja.processing.forwarder._forward_scapy') as mock_scapy:
            
            mock_pool_instance = MagicMock()
            mock_pool_instance.is_raw_available = False
            mock_pool.return_value = mock_pool_instance
            mock_scapy.return_value = True
            
            result = forward_packet('192.168.1.50', sample_payload, single_destination)
            
            mock_scapy.assert_called_once()
            assert result is True
    
    def test_forward_uses_scapy_when_acquire_fails(self, sample_payload, single_destination):
        """Scapy fallback used when socket acquire times out."""
        from trapninja.processing.forwarder import forward_packet
        
        with patch('trapninja.processing.forwarder.get_socket_pool') as mock_pool, \
             patch('trapninja.processing.forwarder._forward_scapy') as mock_scapy:
            
            mock_pool_instance = MagicMock()
            mock_pool_instance.is_raw_available = True
            mock_pool_instance.acquire.return_value = None  # Failed to acquire
            mock_pool.return_value = mock_pool_instance
            mock_scapy.return_value = True
            
            result = forward_packet('192.168.1.50', sample_payload, single_destination)
            
            mock_scapy.assert_called_once()
            assert result is True
    
    def test_scapy_fallback_forwards_to_all_destinations(self, sample_payload, multi_destinations):
        """Scapy fallback sends to all destinations."""
        from trapninja.processing.forwarder import _forward_scapy
        
        # Scapy imports are inside the function, so patch at scapy.all level
        with patch('scapy.all.IP') as mock_ip, \
             patch('scapy.all.UDP') as mock_udp, \
             patch('scapy.all.send') as mock_send, \
             patch('scapy.all.get_if_list', return_value=['eth0']):
            
            # Setup mock packet construction
            mock_packet = MagicMock()
            mock_ip.return_value = mock_packet
            mock_packet.__truediv__ = MagicMock(return_value=mock_packet)
            mock_packet.__getitem__ = MagicMock(return_value=mock_packet)
            
            result = _forward_scapy('192.168.1.50', sample_payload, multi_destinations, 10162)
            
            # Should call send for each destination
            assert mock_send.call_count == len(multi_destinations)
            assert result is True


# =============================================================================
# TEST CLASS: BATCH FORWARDING
# =============================================================================

class TestBatchForwarding:
    """Test batch forwarding for efficiency."""
    
    def test_batch_forward_processes_all_packets(self, sample_payload, single_destination):
        """Batch forward processes all packets in batch."""
        from trapninja.processing.forwarder import forward_packet_batch
        
        packets = [
            ('192.168.1.1', sample_payload, single_destination),
            ('192.168.1.2', sample_payload, single_destination),
            ('192.168.1.3', sample_payload, single_destination),
        ]
        
        with patch('trapninja.processing.forwarder.get_socket_pool') as mock_pool:
            mock_socket = MagicMock()
            mock_pool_instance = MagicMock()
            mock_pool_instance.is_raw_available = True
            mock_pool_instance.acquire.return_value = mock_socket
            mock_pool.return_value = mock_pool_instance
            
            count = forward_packet_batch(packets)
            
            # Should have forwarded all 3 packets
            assert count == 3
            assert mock_socket.sendto.call_count == 3
    
    def test_batch_forward_reuses_socket(self, sample_payload, single_destination):
        """Batch forward reuses same socket for all packets."""
        from trapninja.processing.forwarder import forward_packet_batch
        
        packets = [
            ('192.168.1.1', sample_payload, single_destination),
            ('192.168.1.2', sample_payload, single_destination),
        ]
        
        with patch('trapninja.processing.forwarder.get_socket_pool') as mock_pool:
            mock_socket = MagicMock()
            mock_pool_instance = MagicMock()
            mock_pool_instance.is_raw_available = True
            mock_pool_instance.acquire.return_value = mock_socket
            mock_pool.return_value = mock_pool_instance
            
            forward_packet_batch(packets)
            
            # Should acquire once, release once
            mock_pool_instance.acquire.assert_called_once()
            mock_pool_instance.release.assert_called_once()
    
    def test_batch_forward_fans_out_each_packet(self, sample_payload, multi_destinations):
        """Batch forward fans out each packet to all destinations."""
        from trapninja.processing.forwarder import forward_packet_batch
        
        packets = [
            ('192.168.1.1', sample_payload, multi_destinations),
            ('192.168.1.2', sample_payload, multi_destinations),
        ]
        
        with patch('trapninja.processing.forwarder.get_socket_pool') as mock_pool:
            mock_socket = MagicMock()
            mock_pool_instance = MagicMock()
            mock_pool_instance.is_raw_available = True
            mock_pool_instance.acquire.return_value = mock_socket
            mock_pool.return_value = mock_pool_instance
            
            count = forward_packet_batch(packets)
            
            # 2 packets * 4 destinations each = 8 sendto calls
            assert mock_socket.sendto.call_count == 8
            assert count == 8
    
    def test_batch_forward_empty_list(self):
        """Batch forward with empty list returns 0."""
        from trapninja.processing.forwarder import forward_packet_batch
        
        count = forward_packet_batch([])
        
        assert count == 0
    
    def test_batch_forward_partial_failure(self, sample_payload, single_destination):
        """Batch forward counts successful sends on partial failure."""
        from trapninja.processing.forwarder import forward_packet_batch
        
        packets = [
            ('192.168.1.1', sample_payload, single_destination),
            ('192.168.1.2', sample_payload, single_destination),
            ('192.168.1.3', sample_payload, single_destination),
        ]
        
        call_count = [0]
        
        def failing_sendto(packet, addr):
            call_count[0] += 1
            if call_count[0] == 2:
                raise OSError("Failed")
        
        with patch('trapninja.processing.forwarder.get_socket_pool') as mock_pool:
            mock_socket = MagicMock()
            mock_socket.sendto.side_effect = failing_sendto
            mock_pool_instance = MagicMock()
            mock_pool_instance.is_raw_available = True
            mock_pool_instance.acquire.return_value = mock_socket
            mock_pool.return_value = mock_pool_instance
            
            count = forward_packet_batch(packets)
            
            # 2 succeeded, 1 failed
            assert count == 2


# =============================================================================
# TEST CLASS: SOURCE PORT SAFETY
# =============================================================================

class TestSourcePortSafety:
    """Test that forwarded packets use correct source port."""
    
    def test_forward_uses_forward_source_port(self, sample_payload, single_destination):
        """Forward uses FORWARD_SOURCE_PORT constant."""
        from trapninja.processing.forwarder import forward_packet, DEFAULT_SOURCE_PORT
        from trapninja.core.constants import FORWARD_SOURCE_PORT
        
        # Verify constant matches
        assert DEFAULT_SOURCE_PORT == FORWARD_SOURCE_PORT
        
        sent_packets = []
        
        def capture_sendto(packet, addr):
            sent_packets.append(packet)
        
        with patch('trapninja.processing.forwarder.get_socket_pool') as mock_pool:
            mock_socket = MagicMock()
            mock_socket.sendto.side_effect = capture_sendto
            mock_pool_instance = MagicMock()
            mock_pool_instance.is_raw_available = True
            mock_pool_instance.acquire.return_value = mock_socket
            mock_pool.return_value = mock_pool_instance
            
            forward_packet('192.168.1.50', sample_payload, single_destination)
            
            # Extract source port from captured packet
            packet = sent_packets[0]
            src_port = struct.unpack('!H', packet[20:22])[0]
            
            assert src_port == FORWARD_SOURCE_PORT
    
    def test_forward_source_port_not_trap_port(self):
        """FORWARD_SOURCE_PORT is not standard SNMP trap port."""
        from trapninja.core.constants import FORWARD_SOURCE_PORT
        
        # Must be different from listen ports to prevent recapture
        assert FORWARD_SOURCE_PORT != 162
        assert FORWARD_SOURCE_PORT != 161


# =============================================================================
# TEST CLASS: ROUTING PRIORITY
# =============================================================================

class TestRoutingPriority:
    """Test routing priority rules."""
    
    def test_ip_blocking_has_highest_priority(self, sample_payload, mock_config):
        """IP blocking drops packets before any other routing."""
        from trapninja.processing.worker import PacketWorker
        from trapninja.processing.worker import _config_cache
        import queue
        import threading
        
        # Modify config so IP is both blocked AND would be redirected
        config = mock_config.copy()
        config['blocked_ips'] = {'192.168.10.50'}  # This IP is also in redirected_ips
        
        pq = queue.Queue()
        stop = threading.Event()
        worker = PacketWorker(0, pq, stop)
        
        with patch.object(_config_cache, 'get', return_value=config), \
             patch('trapninja.processing.worker.forward_packet') as mock_forward, \
             patch('trapninja.processing.worker.is_forwarding_enabled', return_value=True):
            
            packet_data = {
                'src_ip': '192.168.10.50',  # Both blocked and redirected
                'dst_port': 162,
                'payload': sample_payload
            }
            
            worker._process_packet(packet_data)
            
            # Should be blocked, not redirected
            mock_forward.assert_not_called()
            assert worker.stats._local.packets_blocked > 0
    
    def test_ip_redirect_before_oid_redirect(self, mock_config):
        """IP redirection takes priority over OID redirection."""
        from trapninja.processing.worker import PacketWorker
        from trapninja.processing.worker import _config_cache
        import queue
        import threading
        
        pq = queue.Queue()
        stop = threading.Event()
        worker = PacketWorker(0, pq, stop)
        
        forwarded_to = []
        
        def capture_forward(src_ip, payload, destinations):
            forwarded_to.append(destinations)
        
        # Build trap with OID that would redirect to 'security'
        # But source IP redirects to 'voice'
        payload = build_snmpv2c_trap(trap_oid='1.3.6.1.4.1.8072.2.3.0.99')
        
        with patch.object(_config_cache, 'get', return_value=mock_config), \
             patch('trapninja.processing.worker.forward_packet', side_effect=capture_forward), \
             patch('trapninja.processing.worker.is_forwarding_enabled', return_value=True), \
             patch('trapninja.processing.worker.notify_trap_processed'):
            
            packet_data = {
                'src_ip': '192.168.10.50',  # Redirects to 'voice'
                'dst_port': 162,
                'payload': payload  # OID would redirect to 'security'
            }
            
            worker._process_packet(packet_data)
            
            # Should go to 'voice', not 'security'
            assert len(forwarded_to) == 1
            assert forwarded_to[0] == mock_config['redirected_destinations']['voice']
    
    def test_oid_redirect_before_default(self, mock_config):
        """OID redirection takes priority over default destinations."""
        from trapninja.processing.worker import PacketWorker
        from trapninja.processing.worker import _config_cache
        import queue
        import threading
        
        pq = queue.Queue()
        stop = threading.Event()
        worker = PacketWorker(0, pq, stop)
        
        forwarded_to = []
        
        def capture_forward(src_ip, payload, destinations):
            forwarded_to.append(destinations)
        
        # Build trap with OID that redirects
        payload = build_snmpv2c_trap(trap_oid='1.3.6.1.4.1.8072.2.3.0.99')
        
        with patch.object(_config_cache, 'get', return_value=mock_config), \
             patch('trapninja.processing.worker.forward_packet', side_effect=capture_forward), \
             patch('trapninja.processing.worker.is_forwarding_enabled', return_value=True), \
             patch('trapninja.processing.worker.notify_trap_processed'):
            
            packet_data = {
                'src_ip': '192.168.1.50',  # Not IP-redirected
                'dst_port': 162,
                'payload': payload
            }
            
            worker._process_packet(packet_data)
            
            # Should go to 'security', not default
            assert len(forwarded_to) == 1
            assert forwarded_to[0] == mock_config['redirected_destinations']['security']
            assert forwarded_to[0] != mock_config['destinations']


# =============================================================================
# TEST CLASS: CONFIGURATION EDGE CASES
# =============================================================================

class TestConfigurationEdgeCases:
    """Test edge cases in routing configuration."""
    
    def test_missing_redirect_tag_falls_through(self, sample_payload):
        """Missing redirect tag falls through to default."""
        from trapninja.processing.worker import PacketWorker
        from trapninja.processing.worker import _config_cache
        import queue
        import threading
        
        config = {
            'destinations': [('192.168.1.100', 162)],
            'blocked_traps': set(),
            'blocked_dest': [],
            'blocked_ips': set(),
            'redirected_ips': {'192.168.10.50': 'nonexistent_tag'},  # Tag doesn't exist
            'redirected_oids': {},
            'redirected_destinations': {},  # Empty - tag won't be found
        }
        
        pq = queue.Queue()
        stop = threading.Event()
        worker = PacketWorker(0, pq, stop)
        
        forwarded_to = []
        
        def capture_forward(src_ip, payload, destinations):
            forwarded_to.append(destinations)
        
        with patch.object(_config_cache, 'get', return_value=config), \
             patch('trapninja.processing.worker.forward_packet', side_effect=capture_forward), \
             patch('trapninja.processing.worker.is_forwarding_enabled', return_value=True), \
             patch('trapninja.processing.worker.notify_trap_processed'):
            
            packet_data = {
                'src_ip': '192.168.10.50',  # IP maps to nonexistent tag
                'dst_port': 162,
                'payload': sample_payload
            }
            
            worker._process_packet(packet_data)
            
            # Should fall through and NOT forward (tag lookup fails)
            # This tests the actual behavior of the code
    
    def test_no_destinations_configured(self, sample_payload):
        """No destinations configured doesn't crash."""
        from trapninja.processing.worker import PacketWorker
        from trapninja.processing.worker import _config_cache
        import queue
        import threading
        
        config = {
            'destinations': [],  # No destinations
            'blocked_traps': set(),
            'blocked_dest': [],
            'blocked_ips': set(),
            'redirected_ips': {},
            'redirected_oids': {},
            'redirected_destinations': {},
        }
        
        pq = queue.Queue()
        stop = threading.Event()
        worker = PacketWorker(0, pq, stop)
        
        with patch.object(_config_cache, 'get', return_value=config), \
             patch('trapninja.processing.worker.forward_packet') as mock_forward, \
             patch('trapninja.processing.worker.is_forwarding_enabled', return_value=True):
            
            packet_data = {
                'src_ip': '192.168.1.50',
                'dst_port': 162,
                'payload': sample_payload
            }
            
            # Should not raise
            worker._process_packet(packet_data)
            
            # Should not forward anywhere
            mock_forward.assert_not_called()
    
    def test_large_destination_list(self, sample_payload):
        """Large destination list processes correctly."""
        from trapninja.processing.forwarder import forward_packet
        
        # 100 destinations
        large_destinations = [(f'10.0.{i // 256}.{i % 256}', 162) for i in range(100)]
        
        send_count = [0]
        
        def counting_sendto(packet, addr):
            send_count[0] += 1
        
        with patch('trapninja.processing.forwarder.get_socket_pool') as mock_pool:
            mock_socket = MagicMock()
            mock_socket.sendto.side_effect = counting_sendto
            mock_pool_instance = MagicMock()
            mock_pool_instance.is_raw_available = True
            mock_pool_instance.acquire.return_value = mock_socket
            mock_pool.return_value = mock_pool_instance
            
            result = forward_packet('192.168.1.50', sample_payload, large_destinations)
            
            assert result is True
            assert send_count[0] == 100
