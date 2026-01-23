#!/usr/bin/env python3
"""
TrapNinja Implementation Tests - Phase 10A: Trap Lifecycle

Validates complete trap lifecycle workflows with real components.
Tests the full flow from packet reception to forwarding.

ASSUMPTIONS:
- The processing pipeline uses ConfigCache with 30s TTL
- Fast path is attempted first for all packets, then version detection
- SNMPv3 is detected at byte level before Scapy parsing is attempted
- HA state check happens at processing time, not capture time
- Blocked IPs are checked before any OID extraction
- IP redirection takes priority over OID redirection
- Traps are cached even when HA blocks forwarding
- Queue drops are recorded when capacity exceeded
- Worker batch size is 50 packets with 0.5s timeout
- FORWARD_SOURCE_PORT (61162) is used to prevent capture loops
- StatsCollector uses _local.packets_* for accessing individual counters
- StatsCollector provides ha_blocked_count property

Author: TrapNinja Team
"""

import os
import sys
import time
import queue
import struct
import threading
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch, call
from typing import Dict, List, Any

# Shared fixtures and utilities are automatically available from conftest.py
# Actual implementations live in fixtures/ directory

# Import packet builders and sample data for direct use in tests
from fixtures import (
    build_snmpv2c_trap,
    build_snmpv1_trap,
    build_snmpv3_packet,
    SampleOIDs,
    SampleIPs,
    create_config,
    create_packet_data,
)


# =============================================================================
# FIXTURES (supplement conftest.py with test-specific fixtures)
# =============================================================================

@pytest.fixture
def packet_queue():
    """Create a fresh packet queue for testing."""
    return queue.Queue(maxsize=1000)


@pytest.fixture
def stop_event():
    """Create a stop event for worker control."""
    return threading.Event()


@pytest.fixture
def sample_packet_data():
    """Create sample packet data."""
    return {
        'src_ip': SampleIPs.NORMAL_1,
        'dst_port': 162,
        'payload': build_snmpv2c_trap()
    }


# =============================================================================
# TEST CLASS: VERSION DETECTION
# =============================================================================

class TestVersionDetection:
    """Test SNMP version detection accuracy."""
    
    def test_snmpv2c_detected_correctly(self):
        """SNMPv2c packets are identified as v2c."""
        from trapninja.processing.parser import is_snmpv2c, is_snmpv1, is_snmpv3
        
        payload = build_snmpv2c_trap()
        
        assert is_snmpv2c(payload) is True
        assert is_snmpv1(payload) is False
        assert is_snmpv3(payload) is False
    
    def test_snmpv1_detected_correctly(self):
        """SNMPv1 packets are identified as v1."""
        from trapninja.processing.parser import is_snmpv2c, is_snmpv1, is_snmpv3
        
        payload = build_snmpv1_trap()
        
        assert is_snmpv1(payload) is True
        assert is_snmpv2c(payload) is False
        assert is_snmpv3(payload) is False
    
    def test_snmpv3_detected_correctly(self):
        """SNMPv3 packets are identified as v3."""
        from trapninja.processing.parser import is_snmpv2c, is_snmpv1, is_snmpv3
        
        payload = build_snmpv3_packet()
        
        assert is_snmpv3(payload) is True
        assert is_snmpv2c(payload) is False
        assert is_snmpv1(payload) is False
    
    def test_empty_payload_rejected(self):
        """Empty payloads are rejected by all detectors."""
        from trapninja.processing.parser import is_snmpv2c, is_snmpv1, is_snmpv3
        
        assert is_snmpv2c(b'') is False
        assert is_snmpv1(b'') is False
        assert is_snmpv3(b'') is False
    
    def test_short_payload_rejected(self):
        """Payloads shorter than minimum are rejected."""
        from trapninja.processing.parser import is_snmpv2c, is_snmpv1, is_snmpv3
        
        short = bytes([0x30, 0x02, 0x02, 0x01])  # Truncated
        
        assert is_snmpv2c(short) is False
        assert is_snmpv1(short) is False
        assert is_snmpv3(short) is False
    
    def test_non_sequence_rejected(self):
        """Payloads not starting with SEQUENCE are rejected."""
        from trapninja.processing.parser import is_snmpv2c, is_snmpv1, is_snmpv3
        
        invalid = bytes([0x02, 0x01, 0x01, 0x04, 0x06]) + b'public'
        
        assert is_snmpv2c(invalid) is False
        assert is_snmpv1(invalid) is False
        assert is_snmpv3(invalid) is False
    
    @pytest.mark.parametrize("community", ["public", "private", "test123", "a" * 50])
    def test_various_community_strings_detected(self, community):
        """SNMPv2c detection works with various community strings."""
        from trapninja.processing.parser import is_snmpv2c
        
        payload = build_snmpv2c_trap(community=community)
        assert is_snmpv2c(payload) is True


# =============================================================================
# TEST CLASS: OID EXTRACTION
# =============================================================================

class TestOIDExtraction:
    """Test trap OID extraction accuracy."""
    
    def test_fast_path_extracts_standard_oid(self):
        """Fast path correctly extracts standard enterprise OID."""
        from trapninja.processing.parser import extract_trap_oid_fast
        
        trap_oid = "1.3.6.1.4.1.8072.2.3.0.1"
        payload = build_snmpv2c_trap(trap_oid=trap_oid)
        
        extracted = extract_trap_oid_fast(payload)
        assert extracted == trap_oid
    
    def test_fast_path_extracts_cisco_oid(self):
        """Fast path correctly extracts Cisco-style OID."""
        from trapninja.processing.parser import extract_trap_oid_fast
        
        trap_oid = "1.3.6.1.4.1.9.9.117.2.0.1"
        payload = build_snmpv2c_trap(trap_oid=trap_oid)
        
        extracted = extract_trap_oid_fast(payload)
        assert extracted == trap_oid
    
    def test_fast_path_extracts_long_oid(self):
        """Fast path handles OIDs with many components."""
        from trapninja.processing.parser import extract_trap_oid_fast
        
        trap_oid = "1.3.6.1.4.1.8072.2.3.0.1.2.3.4.5.6.7.8.9.10"
        payload = build_snmpv2c_trap(trap_oid=trap_oid)
        
        extracted = extract_trap_oid_fast(payload)
        assert extracted == trap_oid
    
    def test_fast_path_extracts_oid_with_large_components(self):
        """Fast path handles OIDs with large numeric components."""
        from trapninja.processing.parser import extract_trap_oid_fast
        
        # OID with component > 127 (requires multi-byte encoding)
        trap_oid = "1.3.6.1.4.1.8072.9999.0.1"
        payload = build_snmpv2c_trap(trap_oid=trap_oid)
        
        extracted = extract_trap_oid_fast(payload)
        assert extracted == trap_oid
    
    def test_fast_path_returns_none_for_snmpv1(self):
        """Fast path returns None for SNMPv1 (no snmpTrapOID varbind)."""
        from trapninja.processing.parser import extract_trap_oid_fast
        
        payload = build_snmpv1_trap()
        
        extracted = extract_trap_oid_fast(payload)
        assert extracted is None
    
    def test_fast_path_returns_none_for_truncated_packet(self):
        """Fast path returns None for truncated packets."""
        from trapninja.processing.parser import extract_trap_oid_fast
        
        payload = build_snmpv2c_trap()
        truncated = payload[:20]  # Cut off most of packet
        
        extracted = extract_trap_oid_fast(truncated)
        assert extracted is None
    
    def test_oid_decode_encode_roundtrip(self):
        """OID encoding and decoding are inverses."""
        from trapninja.processing.parser import decode_oid, encode_oid
        
        test_oids = [
            "1.3.6.1.4.1.8072.2.3.0.1",
            "1.3.6.1.2.1.1.3.0",
            "1.3.6.1.4.1.9.9.117.2.0.1",
            "2.16.840.1.113883.3.26",  # OID starting with 2
        ]
        
        for oid in test_oids:
            encoded = encode_oid(oid)
            decoded = decode_oid(encoded)
            assert decoded == oid


# =============================================================================
# TEST CLASS: FAST PATH VS SLOW PATH SELECTION
# =============================================================================

class TestPathSelection:
    """Test that packets are routed to correct processing path."""
    
    def test_snmpv2c_uses_fast_path(self, packet_queue, stop_event, mock_config):
        """SNMPv2c packets with extractable OID use fast path."""
        from trapninja.processing.worker import PacketWorker
        from trapninja.processing.worker import _config_cache
        
        worker = PacketWorker(0, packet_queue, stop_event)
        
        with patch.object(_config_cache, 'get', return_value=mock_config), \
             patch('trapninja.processing.worker.forward_packet') as mock_forward, \
             patch('trapninja.processing.worker.is_forwarding_enabled', return_value=True), \
             patch('trapninja.processing.worker.notify_trap_processed'):
            
            packet_data = {
                'src_ip': '192.168.1.50',
                'dst_port': 162,
                'payload': build_snmpv2c_trap()
            }
            
            worker._process_packet(packet_data)
            
            # Check fast path was recorded
            assert worker.stats._local.fast_path_hits > 0
            assert worker.stats._local.slow_path_hits == 0
    
    def test_snmpv1_uses_slow_path(self, packet_queue, stop_event, mock_config):
        """SNMPv1 packets use slow path."""
        from trapninja.processing.worker import PacketWorker
        from trapninja.processing.worker import _config_cache
        
        worker = PacketWorker(0, packet_queue, stop_event)
        
        # parse_snmp_packet is imported at top of worker, so patch at worker level
        # get_enterprise_oid is imported inside function, so patch at parser level
        with patch.object(_config_cache, 'get', return_value=mock_config), \
             patch('trapninja.processing.worker.forward_packet') as mock_forward, \
             patch('trapninja.processing.worker.is_forwarding_enabled', return_value=True), \
             patch('trapninja.processing.worker.notify_trap_processed'), \
             patch('trapninja.processing.worker.parse_snmp_packet', return_value=(MagicMock(), "v1")), \
             patch('trapninja.processing.parser.get_enterprise_oid', return_value="1.3.6.1.4.1.9.0.1"):
            
            packet_data = {
                'src_ip': '192.168.1.50',
                'dst_port': 162,
                'payload': build_snmpv1_trap()
            }
            
            worker._process_packet(packet_data)
            
            # Check slow path was used
            assert worker.stats._local.slow_path_hits > 0
    
    def test_snmpv3_detected_before_scapy_parsing(self, packet_queue, stop_event, mock_config):
        """SNMPv3 packets are detected at byte level, not via Scapy."""
        from trapninja.processing.worker import PacketWorker
        from trapninja.processing.worker import _config_cache
        
        worker = PacketWorker(0, packet_queue, stop_event)
        
        with patch.object(_config_cache, 'get', return_value=mock_config), \
             patch('trapninja.processing.worker.forward_packet') as mock_forward, \
             patch('trapninja.processing.worker.is_forwarding_enabled', return_value=True), \
             patch('trapninja.processing.worker.notify_trap_processed'), \
             patch.object(worker, '_process_snmpv3') as mock_v3_handler:
            
            packet_data = {
                'src_ip': '192.168.1.50',
                'dst_port': 162,
                'payload': build_snmpv3_packet()
            }
            
            worker._process_packet(packet_data)
            
            # SNMPv3 handler should be called directly
            mock_v3_handler.assert_called_once()


# =============================================================================
# TEST CLASS: BLOCKING CHAIN
# =============================================================================

class TestBlockingChain:
    """Test IP and OID blocking behavior."""
    
    def test_blocked_ip_drops_packet_early(self, packet_queue, stop_event, mock_config):
        """Packets from blocked IPs are dropped before OID extraction."""
        from trapninja.processing.worker import PacketWorker
        from trapninja.processing.worker import _config_cache
        
        worker = PacketWorker(0, packet_queue, stop_event)
        
        with patch.object(_config_cache, 'get', return_value=mock_config), \
             patch('trapninja.processing.worker.forward_packet') as mock_forward, \
             patch('trapninja.processing.worker.is_forwarding_enabled', return_value=True):
            
            packet_data = {
                'src_ip': '10.0.0.99',  # Blocked IP
                'dst_port': 162,
                'payload': build_snmpv2c_trap()
            }
            
            worker._process_packet(packet_data)
            
            # Should NOT forward
            mock_forward.assert_not_called()
            # Should record as blocked
            assert worker.stats._local.packets_blocked > 0
    
    def test_blocked_oid_drops_packet(self, packet_queue, stop_event, mock_config):
        """Packets with blocked OID are dropped."""
        from trapninja.processing.worker import PacketWorker
        from trapninja.processing.worker import _config_cache
        
        worker = PacketWorker(0, packet_queue, stop_event)
        
        with patch.object(_config_cache, 'get', return_value=mock_config), \
             patch('trapninja.processing.worker.forward_packet') as mock_forward, \
             patch('trapninja.processing.worker.is_forwarding_enabled', return_value=True):
            
            packet_data = {
                'src_ip': '192.168.1.50',
                'dst_port': 162,
                'payload': build_snmpv2c_trap(trap_oid='1.3.6.1.4.1.9999.1')  # Blocked OID
            }
            
            worker._process_packet(packet_data)
            
            # Should NOT forward to normal destinations
            for call_args in mock_forward.call_args_list:
                dest = call_args[0][2]  # destinations argument
                assert dest != mock_config['destinations']
            
            # Should record as blocked
            assert worker.stats._local.packets_blocked > 0
    
    def test_blocked_oid_forwards_to_blocked_dest(self, packet_queue, stop_event):
        """Blocked OID packets forward to blocked_dest if configured."""
        from trapninja.processing.worker import PacketWorker
        from trapninja.processing.worker import _config_cache
        
        config = {
            'destinations': [('192.168.1.100', 162)],
            'blocked_traps': {'1.3.6.1.4.1.9999.1'},
            'blocked_dest': [('10.99.99.1', 162)],  # Blocked destination
            'blocked_ips': set(),
            'redirected_ips': {},
            'redirected_oids': {},
            'redirected_destinations': {}
        }
        
        worker = PacketWorker(0, packet_queue, stop_event)
        
        with patch.object(_config_cache, 'get', return_value=config), \
             patch('trapninja.processing.worker.forward_packet') as mock_forward, \
             patch('trapninja.processing.worker.is_forwarding_enabled', return_value=True):
            
            packet_data = {
                'src_ip': '192.168.1.50',
                'dst_port': 162,
                'payload': build_snmpv2c_trap(trap_oid='1.3.6.1.4.1.9999.1')
            }
            
            worker._process_packet(packet_data)
            
            # Should forward to blocked_dest
            mock_forward.assert_called_once()
            assert mock_forward.call_args[0][2] == config['blocked_dest']
    
    def test_ip_blocking_checked_before_oid_extraction(self, packet_queue, stop_event, mock_config):
        """IP blocking happens before expensive OID extraction."""
        from trapninja.processing.worker import PacketWorker
        from trapninja.processing.worker import _config_cache
        
        worker = PacketWorker(0, packet_queue, stop_event)
        
        with patch.object(_config_cache, 'get', return_value=mock_config), \
             patch('trapninja.processing.worker.forward_packet') as mock_forward, \
             patch('trapninja.processing.worker.is_forwarding_enabled', return_value=True), \
             patch('trapninja.processing.parser.extract_trap_oid_fast') as mock_extract:
            
            packet_data = {
                'src_ip': '10.0.0.99',  # Blocked IP
                'dst_port': 162,
                'payload': build_snmpv2c_trap()
            }
            
            worker._process_packet(packet_data)
            
            # OID extraction should NOT be called for blocked IP
            mock_extract.assert_not_called()


# =============================================================================
# TEST CLASS: REDIRECTION CHAIN
# =============================================================================

class TestRedirectionChain:
    """Test IP and OID redirection behavior."""
    
    def test_ip_redirection_works(self, packet_queue, stop_event, mock_config):
        """Packets from redirected IPs go to correct destination."""
        from trapninja.processing.worker import PacketWorker
        from trapninja.processing.worker import _config_cache
        
        worker = PacketWorker(0, packet_queue, stop_event)
        
        with patch.object(_config_cache, 'get', return_value=mock_config), \
             patch('trapninja.processing.worker.forward_packet') as mock_forward, \
             patch('trapninja.processing.worker.is_forwarding_enabled', return_value=True), \
             patch('trapninja.processing.worker.notify_trap_processed'):
            
            packet_data = {
                'src_ip': '192.168.10.50',  # Redirected to 'security'
                'dst_port': 162,
                'payload': build_snmpv2c_trap()
            }
            
            worker._process_packet(packet_data)
            
            # Should forward to security destination
            mock_forward.assert_called_once()
            assert mock_forward.call_args[0][2] == mock_config['redirected_destinations']['security']
            
            # Should record as redirected
            assert worker.stats._local.packets_redirected > 0
    
    def test_oid_redirection_works(self, packet_queue, stop_event, mock_config):
        """Packets with redirected OID go to correct destination."""
        from trapninja.processing.worker import PacketWorker
        from trapninja.processing.worker import _config_cache
        
        worker = PacketWorker(0, packet_queue, stop_event)
        
        with patch.object(_config_cache, 'get', return_value=mock_config), \
             patch('trapninja.processing.worker.forward_packet') as mock_forward, \
             patch('trapninja.processing.worker.is_forwarding_enabled', return_value=True), \
             patch('trapninja.processing.worker.notify_trap_processed'):
            
            packet_data = {
                'src_ip': '192.168.1.50',  # Not redirected by IP
                'dst_port': 162,
                'payload': build_snmpv2c_trap(trap_oid='1.3.6.1.4.1.8072.2.3.0.99')  # Redirected OID
            }
            
            worker._process_packet(packet_data)
            
            # Should forward to voice destination
            mock_forward.assert_called_once()
            assert mock_forward.call_args[0][2] == mock_config['redirected_destinations']['voice']
    
    def test_ip_redirection_takes_priority_over_oid(self, packet_queue, stop_event):
        """IP redirection is checked before OID redirection."""
        config = {
            'destinations': [('192.168.1.100', 162)],
            'blocked_traps': set(),
            'blocked_dest': [],
            'blocked_ips': set(),
            'redirected_ips': {'192.168.10.50': 'security'},  # IP redirect
            'redirected_oids': {'1.3.6.1.4.1.8072.2.3.0.99': 'voice'},  # OID redirect
            'redirected_destinations': {
                'security': [('10.10.10.1', 162)],
                'voice': [('10.10.10.2', 162)]
            }
        }
        
        from trapninja.processing.worker import PacketWorker
        from trapninja.processing.worker import _config_cache
        
        worker = PacketWorker(0, packet_queue, stop_event)
        
        with patch.object(_config_cache, 'get', return_value=config), \
             patch('trapninja.processing.worker.forward_packet') as mock_forward, \
             patch('trapninja.processing.worker.is_forwarding_enabled', return_value=True), \
             patch('trapninja.processing.worker.notify_trap_processed'):
            
            # Packet matches BOTH IP and OID redirection
            packet_data = {
                'src_ip': '192.168.10.50',  # Redirected to 'security'
                'dst_port': 162,
                'payload': build_snmpv2c_trap(trap_oid='1.3.6.1.4.1.8072.2.3.0.99')  # Would redirect to 'voice'
            }
            
            worker._process_packet(packet_data)
            
            # IP redirection should win
            mock_forward.assert_called_once()
            assert mock_forward.call_args[0][2] == config['redirected_destinations']['security']
    
    def test_normal_forwarding_when_no_redirection(self, packet_queue, stop_event, mock_config):
        """Non-redirected packets go to normal destinations."""
        from trapninja.processing.worker import PacketWorker
        from trapninja.processing.worker import _config_cache
        
        worker = PacketWorker(0, packet_queue, stop_event)
        
        with patch.object(_config_cache, 'get', return_value=mock_config), \
             patch('trapninja.processing.worker.forward_packet') as mock_forward, \
             patch('trapninja.processing.worker.is_forwarding_enabled', return_value=True), \
             patch('trapninja.processing.worker.notify_trap_processed'):
            
            packet_data = {
                'src_ip': '192.168.1.50',  # Not redirected
                'dst_port': 162,
                'payload': build_snmpv2c_trap(trap_oid='1.3.6.1.4.1.8072.2.3.0.1')  # Not redirected
            }
            
            worker._process_packet(packet_data)
            
            # Should forward to normal destinations
            mock_forward.assert_called_once()
            assert mock_forward.call_args[0][2] == mock_config['destinations']


# =============================================================================
# TEST CLASS: HA STATE INTEGRATION
# =============================================================================

class TestHAStateIntegration:
    """Test HA state affects forwarding correctly."""
    
    def test_primary_node_forwards(self, packet_queue, stop_event, mock_config):
        """Primary node (forwarding enabled) forwards packets."""
        from trapninja.processing.worker import PacketWorker
        from trapninja.processing.worker import _config_cache
        
        worker = PacketWorker(0, packet_queue, stop_event)
        
        with patch.object(_config_cache, 'get', return_value=mock_config), \
             patch('trapninja.processing.worker.forward_packet') as mock_forward, \
             patch('trapninja.processing.worker.is_forwarding_enabled', return_value=True), \
             patch('trapninja.processing.worker.notify_trap_processed'):
            
            packet_data = {
                'src_ip': '192.168.1.50',
                'dst_port': 162,
                'payload': build_snmpv2c_trap()
            }
            
            worker._process_packet(packet_data)
            
            # Should forward
            mock_forward.assert_called_once()
    
    def test_secondary_node_blocks_forwarding(self, packet_queue, stop_event, mock_config):
        """Secondary node (forwarding disabled) does not forward."""
        from trapninja.processing.worker import PacketWorker
        from trapninja.processing.worker import _config_cache
        
        worker = PacketWorker(0, packet_queue, stop_event)
        
        with patch.object(_config_cache, 'get', return_value=mock_config), \
             patch('trapninja.processing.worker.forward_packet') as mock_forward, \
             patch('trapninja.processing.worker.is_forwarding_enabled', return_value=False):
            
            packet_data = {
                'src_ip': '192.168.1.50',
                'dst_port': 162,
                'payload': build_snmpv2c_trap()
            }
            
            worker._process_packet(packet_data)
            
            # Should NOT forward
            mock_forward.assert_not_called()
            
            # Should record as HA blocked (use ha_blocked_count property)
            assert worker.stats.ha_blocked_count > 0
    
    def test_secondary_node_still_caches_traps(self, packet_queue, stop_event, mock_config):
        """Secondary node caches traps even when not forwarding."""
        from trapninja.processing.worker import PacketWorker
        from trapninja.processing.worker import _config_cache
        
        worker = PacketWorker(0, packet_queue, stop_event)
        
        with patch.object(_config_cache, 'get', return_value=mock_config), \
             patch('trapninja.processing.worker.forward_packet') as mock_forward, \
             patch('trapninja.processing.worker.is_forwarding_enabled', return_value=False), \
             patch.object(worker, '_store_trap_in_cache') as mock_cache_store:
            
            packet_data = {
                'src_ip': '192.168.1.50',
                'dst_port': 162,
                'payload': build_snmpv2c_trap()
            }
            
            worker._process_packet(packet_data)
            
            # Should cache even though not forwarding
            mock_cache_store.assert_called_once()
    
    def test_ha_check_happens_before_config_fetch(self, packet_queue, stop_event, mock_config):
        """HA state is checked before config is fetched."""
        from trapninja.processing.worker import PacketWorker
        from trapninja.processing.worker import _config_cache
        
        worker = PacketWorker(0, packet_queue, stop_event)
        
        with patch.object(_config_cache, 'get', return_value=mock_config) as mock_cfg, \
             patch('trapninja.processing.worker.forward_packet') as mock_forward, \
             patch('trapninja.processing.worker.is_forwarding_enabled', return_value=False) as mock_ha:
            
            packet_data = {
                'src_ip': '192.168.1.50',
                'dst_port': 162,
                'payload': build_snmpv2c_trap()
            }
            
            worker._process_packet(packet_data)
            
            # HA check should be called
            mock_ha.assert_called_once()
            # Config should NOT be fetched (early return for HA blocked)
            mock_cfg.assert_not_called()


# =============================================================================
# TEST CLASS: QUEUE BEHAVIOR
# =============================================================================

class TestQueueBehavior:
    """Test packet queue behavior and statistics."""
    
    def test_queue_has_configurable_max_size(self):
        """Queue has a maximum size from constants."""
        from trapninja.network import QUEUE_MAX_SIZE
        
        assert QUEUE_MAX_SIZE > 0
        assert QUEUE_MAX_SIZE >= 10000  # At least 10K for telco scale
    
    def test_queue_stats_track_queued_count(self):
        """Queue statistics track total queued packets."""
        from trapninja.network import QueueStats
        
        stats = QueueStats()
        
        for _ in range(100):
            stats.record_queued()
        
        result = stats.get_stats()
        assert result['total_queued'] == 100
    
    def test_queue_stats_track_dropped_count(self):
        """Queue statistics track dropped packets."""
        from trapninja.network import QueueStats
        
        stats = QueueStats()
        
        for _ in range(10):
            stats.record_dropped()
        
        result = stats.get_stats()
        assert result['total_dropped'] == 10
        assert result['full_events'] == 10
    
    def test_queue_stats_track_max_depth(self):
        """Queue statistics track maximum depth observed."""
        from trapninja.network import QueueStats
        
        stats = QueueStats()
        
        stats.update_depth(50)
        stats.update_depth(100)
        stats.update_depth(75)  # Less than max
        
        result = stats.get_stats()
        assert result['max_depth'] >= 100
    
    def test_queue_stats_calculate_utilization(self):
        """Queue utilization is calculated as depth/capacity."""
        from trapninja.network import QueueStats, QUEUE_MAX_SIZE, packet_queue
        
        stats = QueueStats()
        
        # Utilization depends on current queue depth
        result = stats.get_stats()
        expected_utilization = packet_queue.qsize() / QUEUE_MAX_SIZE
        assert result['utilization'] == expected_utilization
        assert result['queue_capacity'] == QUEUE_MAX_SIZE


# =============================================================================
# TEST CLASS: WORKER BATCH PROCESSING
# =============================================================================

class TestWorkerBatchProcessing:
    """Test worker batch processing behavior."""
    
    def test_worker_processes_packets_from_queue(self, stop_event, mock_config):
        """Worker processes packets placed in queue."""
        pq = queue.Queue(maxsize=100)
        from trapninja.processing.worker import PacketWorker
        
        worker = PacketWorker(0, pq, stop_event, batch_size=10, timeout=0.1)
        
        processed_count = 0
        
        def counting_process(packet):
            nonlocal processed_count
            processed_count += 1
        
        with patch.object(worker, '_process_packet', counting_process):
            # Add packets
            for i in range(5):
                pq.put({
                    'src_ip': f'192.168.1.{i}',
                    'dst_port': 162,
                    'payload': build_snmpv2c_trap()
                })
            
            # Process one batch manually
            batch = []
            while not pq.empty() and len(batch) < 10:
                batch.append(pq.get_nowait())
            
            worker._process_batch(batch)
            
            assert processed_count == 5
    
    def test_worker_batch_size_limit(self, packet_queue, stop_event):
        """Worker respects batch size limit."""
        from trapninja.processing.worker import PacketWorker
        
        worker = PacketWorker(0, packet_queue, stop_event, batch_size=5, timeout=0.1)
        
        assert worker.batch_size == 5
    
    def test_worker_timeout_configuration(self, packet_queue, stop_event):
        """Worker respects timeout configuration."""
        from trapninja.processing.worker import PacketWorker
        
        worker = PacketWorker(0, packet_queue, stop_event, timeout=0.25)
        
        assert worker.timeout == 0.25
    
    def test_multiple_workers_can_run_concurrently(self, stop_event, mock_config):
        """Multiple workers can process packets concurrently."""
        pq = queue.Queue(maxsize=1000)
        
        from trapninja.processing.worker import start_workers, _config_cache
        
        with patch.object(_config_cache, 'get', return_value=mock_config), \
             patch('trapninja.processing.worker.forward_packet'), \
             patch('trapninja.processing.worker.is_forwarding_enabled', return_value=True), \
             patch('trapninja.processing.worker.notify_trap_processed'):
            
            # Start workers
            workers = start_workers(pq, stop_event, num_workers=4)
            
            assert len(workers) == 4
            
            # All workers should be alive
            for w in workers:
                assert w.is_alive()
            
            # Stop workers
            stop_event.set()
            for w in workers:
                w.join(timeout=1)


# =============================================================================
# TEST CLASS: STATISTICS RECORDING
# =============================================================================

class TestStatisticsRecording:
    """Test that statistics are recorded correctly during processing."""
    
    def test_forwarded_count_incremented(self, packet_queue, stop_event, mock_config):
        """Forwarding a packet increments forwarded count."""
        from trapninja.processing.worker import PacketWorker
        from trapninja.processing.worker import _config_cache
        
        worker = PacketWorker(0, packet_queue, stop_event)
        
        with patch.object(_config_cache, 'get', return_value=mock_config), \
             patch('trapninja.processing.worker.forward_packet'), \
             patch('trapninja.processing.worker.is_forwarding_enabled', return_value=True), \
             patch('trapninja.processing.worker.notify_trap_processed'):
            
            packet_data = {
                'src_ip': '192.168.1.50',
                'dst_port': 162,
                'payload': build_snmpv2c_trap()
            }
            
            worker._process_packet(packet_data)
            
            assert worker.stats._local.packets_forwarded > 0
    
    def test_blocked_count_incremented_for_ip(self, packet_queue, stop_event, mock_config):
        """Blocking by IP increments blocked count."""
        from trapninja.processing.worker import PacketWorker
        from trapninja.processing.worker import _config_cache
        
        worker = PacketWorker(0, packet_queue, stop_event)
        
        with patch.object(_config_cache, 'get', return_value=mock_config), \
             patch('trapninja.processing.worker.is_forwarding_enabled', return_value=True):
            
            packet_data = {
                'src_ip': '10.0.0.99',  # Blocked
                'dst_port': 162,
                'payload': build_snmpv2c_trap()
            }
            
            worker._process_packet(packet_data)
            
            assert worker.stats._local.packets_blocked > 0
    
    def test_redirected_count_incremented(self, packet_queue, stop_event, mock_config):
        """Redirecting a packet increments redirected count."""
        from trapninja.processing.worker import PacketWorker
        from trapninja.processing.worker import _config_cache
        
        worker = PacketWorker(0, packet_queue, stop_event)
        
        with patch.object(_config_cache, 'get', return_value=mock_config), \
             patch('trapninja.processing.worker.forward_packet'), \
             patch('trapninja.processing.worker.is_forwarding_enabled', return_value=True), \
             patch('trapninja.processing.worker.notify_trap_processed'):
            
            packet_data = {
                'src_ip': '192.168.10.50',  # Redirected
                'dst_port': 162,
                'payload': build_snmpv2c_trap()
            }
            
            worker._process_packet(packet_data)
            
            assert worker.stats._local.packets_redirected > 0
    
    def test_fast_path_count_incremented(self, packet_queue, stop_event, mock_config):
        """Using fast path increments fast path count."""
        from trapninja.processing.worker import PacketWorker
        from trapninja.processing.worker import _config_cache
        
        worker = PacketWorker(0, packet_queue, stop_event)
        
        with patch.object(_config_cache, 'get', return_value=mock_config), \
             patch('trapninja.processing.worker.forward_packet'), \
             patch('trapninja.processing.worker.is_forwarding_enabled', return_value=True), \
             patch('trapninja.processing.worker.notify_trap_processed'):
            
            packet_data = {
                'src_ip': '192.168.1.50',
                'dst_port': 162,
                'payload': build_snmpv2c_trap()
            }
            
            worker._process_packet(packet_data)
            
            assert worker.stats._local.fast_path_hits > 0


# =============================================================================
# TEST CLASS: END-TO-END LIFECYCLE
# =============================================================================

class TestEndToEndLifecycle:
    """Test complete trap lifecycle scenarios."""
    
    def test_normal_trap_lifecycle(self, packet_queue, stop_event, mock_config):
        """Normal trap flows through entire pipeline."""
        from trapninja.processing.worker import PacketWorker
        from trapninja.processing.worker import _config_cache
        
        worker = PacketWorker(0, packet_queue, stop_event)
        
        forward_calls = []
        
        def capture_forward(src_ip, payload, destinations):
            forward_calls.append({
                'src_ip': src_ip,
                'payload': payload,
                'destinations': destinations
            })
        
        with patch.object(_config_cache, 'get', return_value=mock_config), \
             patch('trapninja.processing.worker.forward_packet', side_effect=capture_forward), \
             patch('trapninja.processing.worker.is_forwarding_enabled', return_value=True), \
             patch('trapninja.processing.worker.notify_trap_processed'):
            
            trap_oid = "1.3.6.1.4.1.8072.2.3.0.1"
            payload = build_snmpv2c_trap(trap_oid=trap_oid)
            
            packet_data = {
                'src_ip': '192.168.1.50',
                'dst_port': 162,
                'payload': payload
            }
            
            worker._process_packet(packet_data)
            
            # Verify forward was called correctly
            assert len(forward_calls) == 1
            assert forward_calls[0]['src_ip'] == '192.168.1.50'
            assert forward_calls[0]['payload'] == payload
            assert forward_calls[0]['destinations'] == mock_config['destinations']
    
    def test_blocked_trap_lifecycle(self, packet_queue, stop_event, mock_config):
        """Blocked trap is dropped and recorded."""
        from trapninja.processing.worker import PacketWorker
        from trapninja.processing.worker import _config_cache
        
        worker = PacketWorker(0, packet_queue, stop_event)
        
        mock_config_copy = mock_config.copy()
        mock_config_copy['blocked_dest'] = []  # No blocked destination
        
        with patch.object(_config_cache, 'get', return_value=mock_config_copy), \
             patch('trapninja.processing.worker.forward_packet') as mock_forward, \
             patch('trapninja.processing.worker.is_forwarding_enabled', return_value=True):
            
            packet_data = {
                'src_ip': '10.0.0.99',  # Blocked IP
                'dst_port': 162,
                'payload': build_snmpv2c_trap()
            }
            
            worker._process_packet(packet_data)
            
            # Should NOT forward anywhere
            mock_forward.assert_not_called()
            
            # Should record as blocked
            assert worker.stats._local.packets_blocked > 0
    
    def test_redirected_trap_lifecycle(self, packet_queue, stop_event, mock_config):
        """Redirected trap goes to correct destination."""
        from trapninja.processing.worker import PacketWorker
        from trapninja.processing.worker import _config_cache
        
        worker = PacketWorker(0, packet_queue, stop_event)
        
        forward_calls = []
        
        def capture_forward(src_ip, payload, destinations):
            forward_calls.append({
                'src_ip': src_ip,
                'destinations': destinations
            })
        
        with patch.object(_config_cache, 'get', return_value=mock_config), \
             patch('trapninja.processing.worker.forward_packet', side_effect=capture_forward), \
             patch('trapninja.processing.worker.is_forwarding_enabled', return_value=True), \
             patch('trapninja.processing.worker.notify_trap_processed'):
            
            packet_data = {
                'src_ip': '192.168.10.50',  # Redirected to 'security'
                'dst_port': 162,
                'payload': build_snmpv2c_trap()
            }
            
            worker._process_packet(packet_data)
            
            # Should forward to security destination only
            assert len(forward_calls) == 1
            assert forward_calls[0]['destinations'] == mock_config['redirected_destinations']['security']
            
            # Should record as redirected
            assert worker.stats._local.packets_redirected > 0
    
    def test_ha_blocked_trap_lifecycle(self, packet_queue, stop_event, mock_config):
        """HA-blocked trap is cached but not forwarded."""
        from trapninja.processing.worker import PacketWorker
        from trapninja.processing.worker import _config_cache
        
        worker = PacketWorker(0, packet_queue, stop_event)
        
        cache_calls = []
        
        def capture_cache(*args, **kwargs):
            cache_calls.append(args)
        
        with patch.object(_config_cache, 'get', return_value=mock_config), \
             patch('trapninja.processing.worker.forward_packet') as mock_forward, \
             patch('trapninja.processing.worker.is_forwarding_enabled', return_value=False), \
             patch.object(worker, '_store_trap_in_cache', side_effect=capture_cache):
            
            packet_data = {
                'src_ip': '192.168.1.50',
                'dst_port': 162,
                'payload': build_snmpv2c_trap()
            }
            
            worker._process_packet(packet_data)
            
            # Should NOT forward
            mock_forward.assert_not_called()
            
            # Should cache
            assert len(cache_calls) == 1
            
            # Should record as HA blocked
            assert worker.stats.ha_blocked_count > 0


# =============================================================================
# TEST CLASS: FORWARD SOURCE PORT SAFETY
# =============================================================================

class TestForwardSourcePortSafety:
    """Test that forwarded packets use correct source port."""
    
    def test_forward_source_port_constant_defined(self):
        """FORWARD_SOURCE_PORT constant is defined."""
        from trapninja.core.constants import FORWARD_SOURCE_PORT
        
        assert FORWARD_SOURCE_PORT is not None
        assert FORWARD_SOURCE_PORT != 162  # Must be different from listen port
    
    def test_forward_source_port_not_standard_snmp(self):
        """FORWARD_SOURCE_PORT is not a standard SNMP port."""
        from trapninja.core.constants import FORWARD_SOURCE_PORT
        
        standard_ports = {161, 162, 1161, 1162}
        assert FORWARD_SOURCE_PORT not in standard_ports
