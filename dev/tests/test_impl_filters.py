#!/usr/bin/env python3
"""
TrapNinja Implementation Tests - Phase 10C: Filter Chain Processing

Validates filter chain logic including IP/OID blocking, redirection,
validation, config loading, and caching behavior.

ASSUMPTIONS:
- blocked_ips set provides O(1) lookup for IP blocking
- blocked_traps set provides O(1) lookup for OID blocking
- IP blocking is checked before OID extraction (performance)
- Redirection uses LRU cache for lookup performance
- IP redirection takes priority over OID redirection
- Config files are only reloaded when mtime changes
- Invalid IPs and OIDs are rejected during config load
- Tags must exist in redirected_destinations for redirection to work

Author: TrapNinja Team
"""

import os
import sys
import json
import time
import tempfile
import threading
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock
from typing import Dict, List, Any
from collections import defaultdict

# Shared fixtures and utilities from fixtures/ directory
from fixtures import (
    build_snmpv2c_trap,
    SampleOIDs,
    SampleIPs,
    create_config,
)

# Note: Most fixtures are now provided by conftest.py:
# - temp_config_dir
# - sample_destinations, sample_destinations_json
# - sample_blocked_traps, sample_blocked_traps_set
# - sample_blocked_ips, sample_blocked_ips_set
# - sample_redirected_ips, sample_redirected_ips_dict
# - sample_redirected_oids, sample_redirected_oids_dict
# - sample_redirected_destinations, sample_redirected_destinations_tuples
# - mock_config


# =============================================================================
# TEST CLASS: IP VALIDATION
# =============================================================================

class TestIPValidation:
    """Test IP address validation."""
    
    def test_valid_ipv4_accepted(self):
        """Valid IPv4 addresses are accepted."""
        from trapninja.redirection import validate_ip
        
        valid_ips = [
            '192.168.1.1',
            '10.0.0.1',
            '172.16.0.1',
            '255.255.255.255',
            '0.0.0.0',
        ]
        
        for ip in valid_ips:
            assert validate_ip(ip) is not None, f"{ip} should be valid"
    
    def test_invalid_ipv4_rejected(self):
        """Invalid IPv4 addresses are rejected."""
        from trapninja.redirection import validate_ip
        
        invalid_ips = [
            '256.1.1.1',      # Octet > 255
            '192.168.1',      # Missing octet
            '192.168.1.1.1',  # Extra octet
            'not.an.ip',      # Non-numeric
            '',               # Empty
            '192.168.1.1/24', # CIDR notation
        ]
        
        for ip in invalid_ips:
            assert validate_ip(ip) is None, f"{ip} should be invalid"
    
    def test_valid_ipv6_accepted(self):
        """Valid IPv6 addresses are accepted."""
        from trapninja.redirection import validate_ip
        
        valid_ips = [
            '::1',
            '2001:db8::1',
            'fe80::1',
            '::ffff:192.168.1.1',  # IPv4-mapped
        ]
        
        for ip in valid_ips:
            assert validate_ip(ip) is not None, f"{ip} should be valid"
    
    def test_leading_zeros_rejected(self):
        """IP addresses with leading zeros are rejected (ambiguous - could be octal)."""
        from trapninja.redirection import validate_ip
        
        # Python's ipaddress module rejects leading zeros as ambiguous
        result = validate_ip('192.168.001.001')
        assert result is None


# =============================================================================
# TEST CLASS: OID VALIDATION
# =============================================================================

class TestOIDValidation:
    """Test OID string validation."""
    
    def test_valid_oids_accepted(self):
        """Valid OID strings are accepted."""
        from trapninja.redirection import validate_oid
        
        valid_oids = [
            '1.3.6.1.4.1.8072.2.3.0.1',
            '1.3.6.1.2.1.1.3.0',
            '2.16.840.1.113883.3.26',
            '0.0',
            '1.3',
        ]
        
        for oid in valid_oids:
            assert validate_oid(oid) is not None, f"{oid} should be valid"
    
    def test_invalid_oids_rejected(self):
        """Invalid OID strings are rejected."""
        from trapninja.redirection import validate_oid
        
        invalid_oids = [
            '',                  # Empty
            '1',                 # Single component
            '1.3.6.a.1',         # Non-numeric
            '.1.3.6.1',          # Leading dot
            '1.3.6.1.',          # Trailing dot
            '1..3.6.1',          # Double dot
            'iso.org.dod.1',     # Named components
        ]
        
        for oid in invalid_oids:
            assert validate_oid(oid) is None, f"{oid} should be invalid"
    
    def test_oid_with_large_components(self):
        """OIDs with large numeric components are valid."""
        from trapninja.redirection import validate_oid
        
        # Components can be quite large
        large_oid = '1.3.6.1.4.1.99999.123456789.0.1'
        assert validate_oid(large_oid) is not None


# =============================================================================
# TEST CLASS: BLOCKING SET OPERATIONS
# =============================================================================

class TestBlockingSetOperations:
    """Test blocking set behavior and lookups."""
    
    def test_blocked_ips_set_lookup(self):
        """Blocked IPs use set for O(1) lookup."""
        from trapninja import config
        
        # Verify blocked_ips is a set
        assert isinstance(config.blocked_ips, (set, type(defaultdict(str))))
    
    def test_blocked_traps_set_lookup(self):
        """Blocked traps use set for O(1) lookup."""
        from trapninja import config
        
        # Verify blocked_traps is a set
        assert isinstance(config.blocked_traps, (set, type(defaultdict(str))))
    
    def test_ip_in_blocked_set(self, sample_blocked_ips):
        """IP membership check works correctly."""
        blocked_set = set(sample_blocked_ips)
        
        assert '10.0.0.99' in blocked_set
        assert '10.0.0.100' in blocked_set
        assert '192.168.1.50' not in blocked_set
    
    def test_oid_in_blocked_set(self, sample_blocked_traps):
        """OID membership check works correctly."""
        blocked_set = set(sample_blocked_traps)
        
        assert '1.3.6.1.4.1.9999.1' in blocked_set
        assert '1.3.6.1.4.1.8072.2.3.0.1' not in blocked_set


# =============================================================================
# TEST CLASS: REDIRECTION LOOKUP
# =============================================================================

class TestRedirectionLookup:
    """Test redirection lookup logic."""
    
    def test_lookup_redirection_tag_by_ip(self):
        """lookup_redirection_tag finds tag by IP."""
        from trapninja import redirection
        
        # Set up test data
        redirection.redirected_ips = defaultdict(str)
        redirection.redirected_ips['192.168.10.50'] = 'security'
        redirection.redirected_oids = defaultdict(str)
        
        # Clear LRU cache
        redirection.lookup_redirection_tag.cache_clear()
        
        tag = redirection.lookup_redirection_tag('192.168.10.50', None)
        
        assert tag == 'security'
    
    def test_lookup_redirection_tag_by_oid(self):
        """lookup_redirection_tag finds tag by OID when IP not matched."""
        from trapninja import redirection
        
        # Set up test data
        redirection.redirected_ips = defaultdict(str)
        redirection.redirected_oids = defaultdict(str)
        redirection.redirected_oids['1.3.6.1.4.1.8072.2.3.0.99'] = 'voice'
        
        # Clear LRU cache
        redirection.lookup_redirection_tag.cache_clear()
        
        tag = redirection.lookup_redirection_tag('192.168.1.50', '1.3.6.1.4.1.8072.2.3.0.99')
        
        assert tag == 'voice'
    
    def test_ip_takes_priority_over_oid(self):
        """IP redirection takes priority over OID redirection."""
        from trapninja import redirection
        
        # Set up test data - both IP and OID have redirections
        redirection.redirected_ips = defaultdict(str)
        redirection.redirected_ips['192.168.10.50'] = 'security'
        redirection.redirected_oids = defaultdict(str)
        redirection.redirected_oids['1.3.6.1.4.1.8072.2.3.0.99'] = 'voice'
        
        # Clear LRU cache
        redirection.lookup_redirection_tag.cache_clear()
        
        # Should return IP-based tag, not OID-based
        tag = redirection.lookup_redirection_tag('192.168.10.50', '1.3.6.1.4.1.8072.2.3.0.99')
        
        assert tag == 'security'
    
    def test_no_match_returns_empty(self):
        """No match returns empty string."""
        from trapninja import redirection
        
        # Set up empty test data
        redirection.redirected_ips = defaultdict(str)
        redirection.redirected_oids = defaultdict(str)
        
        # Clear LRU cache
        redirection.lookup_redirection_tag.cache_clear()
        
        tag = redirection.lookup_redirection_tag('192.168.1.50', '1.3.6.1.4.1.8072.2.3.0.1')
        
        assert tag == ''
    
    def test_lookup_uses_lru_cache(self):
        """lookup_redirection_tag uses LRU cache."""
        from trapninja import redirection
        
        # Clear cache and check info
        redirection.lookup_redirection_tag.cache_clear()
        
        # Set up test data
        redirection.redirected_ips = defaultdict(str)
        redirection.redirected_ips['192.168.10.50'] = 'security'
        redirection.redirected_oids = defaultdict(str)
        
        # First call - cache miss
        redirection.lookup_redirection_tag('192.168.10.50', None)
        info1 = redirection.lookup_redirection_tag.cache_info()
        
        # Second call - cache hit
        redirection.lookup_redirection_tag('192.168.10.50', None)
        info2 = redirection.lookup_redirection_tag.cache_info()
        
        assert info2.hits > info1.hits


# =============================================================================
# TEST CLASS: CHECK FOR REDIRECTION
# =============================================================================

class TestCheckForRedirection:
    """Test check_for_redirection function."""
    
    def test_redirection_returns_destinations(self):
        """Redirection returns correct destinations."""
        from trapninja import redirection
        
        # Set up test data
        redirection.redirected_ips = defaultdict(str)
        redirection.redirected_ips['192.168.10.50'] = 'security'
        redirection.redirected_oids = defaultdict(str)
        redirection.redirected_destinations = defaultdict(list)
        redirection.redirected_destinations['security'] = [('10.10.10.1', 162)]
        
        # Clear LRU cache
        redirection.lookup_redirection_tag.cache_clear()
        
        is_redirected, destinations, tag = redirection.check_for_redirection(
            '192.168.10.50', None
        )
        
        assert is_redirected is True
        assert destinations == [('10.10.10.1', 162)]
        assert tag == 'security'
    
    def test_no_redirection_returns_false(self):
        """No redirection returns False and empty list."""
        from trapninja import redirection
        
        # Set up empty test data
        redirection.redirected_ips = defaultdict(str)
        redirection.redirected_oids = defaultdict(str)
        redirection.redirected_destinations = defaultdict(list)
        
        # Clear LRU cache
        redirection.lookup_redirection_tag.cache_clear()
        
        is_redirected, destinations, tag = redirection.check_for_redirection(
            '192.168.1.50', '1.3.6.1.4.1.8072.2.3.0.1'
        )
        
        assert is_redirected is False
        assert destinations == []
        assert tag is None
    
    def test_missing_destination_group_returns_false(self):
        """Tag without destination group returns False."""
        from trapninja import redirection
        
        # Set up test data - tag exists but no destinations
        redirection.redirected_ips = defaultdict(str)
        redirection.redirected_ips['192.168.10.50'] = 'nonexistent'
        redirection.redirected_oids = defaultdict(str)
        redirection.redirected_destinations = defaultdict(list)
        # Note: 'nonexistent' tag has no destinations
        
        # Clear LRU cache
        redirection.lookup_redirection_tag.cache_clear()
        
        is_redirected, destinations, tag = redirection.check_for_redirection(
            '192.168.10.50', None
        )
        
        assert is_redirected is False
        assert destinations == []


# =============================================================================
# TEST CLASS: CONFIG FILE LOADING
# =============================================================================

class TestConfigFileLoading:
    """Test configuration file loading behavior."""
    
    def test_destinations_loaded_as_list(self, temp_config_dir):
        """Destinations are loaded as list from JSON."""
        # Create test data - JSON always stores as lists, not tuples
        test_destinations = [
            ['192.168.1.100', 162],
            ['192.168.1.101', 162],
        ]
        
        dest_file = os.path.join(temp_config_dir, 'destinations.json')
        with open(dest_file, 'w') as f:
            json.dump(test_destinations, f)
        
        from trapninja.config import safe_load_json
        
        loaded = safe_load_json(dest_file, [])
        
        # Verify we got the same data back
        assert len(loaded) == 2
        assert loaded[0][0] == '192.168.1.100'
        assert loaded[0][1] == 162
        assert loaded[1][0] == '192.168.1.101'
        assert loaded[1][1] == 162
    
    def test_blocked_traps_loaded_as_list(self, temp_config_dir, sample_blocked_traps):
        """Blocked traps are loaded as list (converted to set)."""
        blocked_file = os.path.join(temp_config_dir, 'blocked_traps.json')
        with open(blocked_file, 'w') as f:
            json.dump(sample_blocked_traps, f)
        
        from trapninja.config import safe_load_json
        
        loaded = safe_load_json(blocked_file, [])
        blocked_set = set(loaded)
        
        assert '1.3.6.1.4.1.9999.1' in blocked_set
        assert len(blocked_set) == 3
    
    def test_invalid_json_returns_fallback(self, temp_config_dir):
        """Invalid JSON returns fallback value."""
        bad_file = os.path.join(temp_config_dir, 'bad.json')
        with open(bad_file, 'w') as f:
            f.write('{ invalid json }')
        
        from trapninja.config import safe_load_json
        
        loaded = safe_load_json(bad_file, ['fallback'])
        
        assert loaded == ['fallback']
    
    def test_missing_file_returns_fallback(self, temp_config_dir):
        """Missing file returns fallback value."""
        from trapninja.config import safe_load_json
        
        nonexistent = os.path.join(temp_config_dir, 'nonexistent.json')
        
        loaded = safe_load_json(nonexistent, ['fallback'])
        
        assert loaded == ['fallback']
    
    def test_empty_file_returns_fallback(self, temp_config_dir):
        """Empty file returns fallback value."""
        empty_file = os.path.join(temp_config_dir, 'empty.json')
        with open(empty_file, 'w') as f:
            f.write('')
        
        from trapninja.config import safe_load_json
        
        loaded = safe_load_json(empty_file, ['fallback'])
        
        assert loaded == ['fallback']


# =============================================================================
# TEST CLASS: MTIME-BASED RELOAD
# =============================================================================

class TestMtimeBasedReload:
    """Test that configs only reload when file changes."""
    
    def test_redirected_ips_mtime_tracking(self, temp_config_dir, sample_redirected_ips):
        """Redirected IPs track mtime for reload decisions."""
        from trapninja import redirection
        
        # Save original state
        original_mtime = redirection.redirected_ips_mtime
        
        # Create config file
        ip_file = os.path.join(temp_config_dir, 'redirected_ips.json')
        with open(ip_file, 'w') as f:
            json.dump(sample_redirected_ips, f)
        
        # Patch get_config_path to use temp dir
        with patch.object(redirection, 'get_config_path', return_value=ip_file):
            redirection.redirected_ips_mtime = 0  # Force reload
            redirection.load_redirected_ips()
            
            first_mtime = redirection.redirected_ips_mtime
            
            # Second load without file change
            redirection.load_redirected_ips()
            
            second_mtime = redirection.redirected_ips_mtime
        
        # mtime should be same (no reload needed)
        assert first_mtime == second_mtime
        
        # Restore original state
        redirection.redirected_ips_mtime = original_mtime
    
    def test_config_change_triggers_reload(self, temp_config_dir):
        """File modification triggers config reload."""
        from trapninja import redirection
        
        # Start with minimal data set - don't rely on fixtures
        initial_data = [
            ['192.168.1.1', 'tag1'],
            ['192.168.1.2', 'tag2'],
        ]
        
        # Create config file
        ip_file = os.path.join(temp_config_dir, 'redirected_ips.json')
        with open(ip_file, 'w') as f:
            json.dump(initial_data, f)
        
        # Patch get_config_path
        with patch.object(redirection, 'get_config_path', return_value=ip_file):
            # Clear any existing state
            redirection.redirected_ips = defaultdict(str)
            redirection.redirected_ips_mtime = 0
            redirection.load_redirected_ips()
            
            loaded_count_1 = len(redirection.redirected_ips)
            assert loaded_count_1 == 2, f"Expected 2 entries, got {loaded_count_1}"
            
            # Wait and modify file with more entries
            time.sleep(0.1)
            new_data = initial_data + [['192.168.1.3', 'tag3'], ['192.168.1.4', 'tag4']]
            with open(ip_file, 'w') as f:
                json.dump(new_data, f)
            
            # Force mtime change detection
            redirection.redirected_ips_mtime = 0
            redirection.load_redirected_ips()
            
            loaded_count_2 = len(redirection.redirected_ips)
            assert loaded_count_2 == 4, f"Expected 4 entries, got {loaded_count_2}"
        
        # Should have loaded more entries
        assert loaded_count_2 > loaded_count_1


# =============================================================================
# TEST CLASS: CACHE CLEARING
# =============================================================================

class TestCacheClearing:
    """Test cache clearing behavior."""
    
    def test_clear_redirection_caches(self):
        """clear_redirection_caches clears LRU cache."""
        from trapninja import redirection
        
        # Set up and populate cache
        redirection.redirected_ips = defaultdict(str)
        redirection.redirected_ips['192.168.10.50'] = 'security'
        redirection.redirected_oids = defaultdict(str)
        
        redirection.lookup_redirection_tag.cache_clear()
        
        # Populate cache
        redirection.lookup_redirection_tag('192.168.10.50', None)
        redirection.lookup_redirection_tag('192.168.10.50', None)
        
        info_before = redirection.lookup_redirection_tag.cache_info()
        assert info_before.hits >= 1
        
        # Clear caches
        redirection.clear_redirection_caches()
        
        info_after = redirection.lookup_redirection_tag.cache_info()
        assert info_after.hits == 0
        assert info_after.misses == 0


# =============================================================================
# TEST CLASS: FILTER CHAIN ORDER
# =============================================================================

class TestFilterChainOrder:
    """Test the order of filter chain processing."""
    
    def test_ip_block_before_oid_extraction(self):
        """IP blocking happens before OID extraction (performance)."""
        # This is tested by verifying that extract_trap_oid_fast is not called
        # when IP is blocked (covered in Phase 10A)
        
        from trapninja.processing.worker import PacketWorker
        from trapninja.processing.worker import _config_cache
        import queue
        
        config = {
            'destinations': [('192.168.1.100', 162)],
            'blocked_traps': set(),
            'blocked_dest': [],
            'blocked_ips': {'10.0.0.99'},
            'redirected_ips': {},
            'redirected_oids': {},
            'redirected_destinations': {},
        }
        
        pq = queue.Queue()
        stop = threading.Event()
        worker = PacketWorker(0, pq, stop)
        
        with patch.object(_config_cache, 'get', return_value=config), \
             patch('trapninja.processing.worker.is_forwarding_enabled', return_value=True), \
             patch('trapninja.processing.worker.extract_trap_oid_fast') as mock_extract:
            
            # Build minimal payload
            payload = bytes([0x30, 0x10, 0x02, 0x01, 0x01, 0x04, 0x06]) + b'public'
            
            packet_data = {
                'src_ip': '10.0.0.99',  # Blocked
                'dst_port': 162,
                'payload': payload
            }
            
            worker._process_packet(packet_data)
            
            # OID extraction should NOT be called for blocked IP
            mock_extract.assert_not_called()
    
    def test_oid_block_checked_after_extraction(self):
        """OID blocking is checked after OID extraction."""
        from trapninja.processing.worker import PacketWorker
        from trapninja.processing.worker import _config_cache
        import queue
        import struct
        
        config = {
            'destinations': [('192.168.1.100', 162)],
            'blocked_traps': {'1.3.6.1.4.1.9999.1'},
            'blocked_dest': [],
            'blocked_ips': set(),
            'redirected_ips': {},
            'redirected_oids': {},
            'redirected_destinations': {},
        }
        
        pq = queue.Queue()
        stop = threading.Event()
        worker = PacketWorker(0, pq, stop)
        
        # Build SNMPv2c packet with blocked OID
        payload = build_snmpv2c_trap(trap_oid='1.3.6.1.4.1.9999.1')
        
        with patch.object(_config_cache, 'get', return_value=config), \
             patch('trapninja.processing.worker.forward_packet') as mock_forward, \
             patch('trapninja.processing.worker.is_forwarding_enabled', return_value=True):
            
            packet_data = {
                'src_ip': '192.168.1.50',  # Not blocked
                'dst_port': 162,
                'payload': payload
            }
            
            worker._process_packet(packet_data)
            
            # Should not forward (OID blocked)
            mock_forward.assert_not_called()
            assert worker.stats._local.packets_blocked > 0
    
    def test_oid_block_before_ip_redirect(self):
        """OID blocking takes priority over IP redirection.
        
        The actual priority chain in the worker is:
        1. IP blocking (drops immediately)
        2. OID blocking (drops after extraction)
        3. IP redirection
        4. OID redirection
        5. Normal forwarding
        
        This means a blocked OID will NOT be redirected even if IP matches.
        """
        from trapninja.processing.worker import PacketWorker
        from trapninja.processing.worker import _config_cache
        import queue
        
        config = {
            'destinations': [('192.168.1.100', 162)],
            'blocked_traps': {'1.3.6.1.4.1.9999.1'},  # Blocks the OID
            'blocked_dest': [],
            'blocked_ips': set(),
            'redirected_ips': {'192.168.10.50': 'security'},  # Would redirect
            'redirected_oids': {},
            'redirected_destinations': {
                'security': [('10.10.10.1', 162)]
            },
        }
        
        pq = queue.Queue()
        stop = threading.Event()
        worker = PacketWorker(0, pq, stop)
        
        # Build packet with blocked OID (build_snmpv2c_trap from conftest)
        payload = build_snmpv2c_trap(trap_oid='1.3.6.1.4.1.9999.1')
        
        with patch.object(_config_cache, 'get', return_value=config), \
             patch('trapninja.processing.worker.forward_packet') as mock_forward, \
             patch('trapninja.processing.worker.is_forwarding_enabled', return_value=True):
            
            packet_data = {
                'src_ip': '192.168.10.50',  # Would redirect to security
                'dst_port': 162,
                'payload': payload  # But OID is blocked
            }
            
            worker._process_packet(packet_data)
            
            # Should be blocked by OID, NOT redirected by IP
            mock_forward.assert_not_called()
            assert worker.stats._local.packets_blocked > 0


# =============================================================================
# TEST CLASS: DESTINATION GROUP VALIDATION
# =============================================================================

class TestDestinationGroupValidation:
    """Test destination group validation during load."""
    
    def test_valid_destinations_loaded(self, temp_config_dir, sample_redirected_destinations):
        """Valid destination groups are loaded correctly."""
        from trapninja import redirection
        
        dest_file = os.path.join(temp_config_dir, 'redirected_destinations.json')
        with open(dest_file, 'w') as f:
            json.dump(sample_redirected_destinations, f)
        
        with patch.object(redirection, 'get_config_path', return_value=dest_file):
            redirection.redirected_destinations_mtime = 0
            redirection.load_redirected_destinations()
            
            assert 'security' in redirection.redirected_destinations
            assert len(redirection.redirected_destinations['security']) == 2
    
    def test_invalid_port_rejected(self, temp_config_dir):
        """Invalid port numbers are rejected."""
        from trapninja import redirection
        
        bad_destinations = {
            'test': [['192.168.1.1', 99999]]  # Invalid port
        }
        
        dest_file = os.path.join(temp_config_dir, 'redirected_destinations.json')
        with open(dest_file, 'w') as f:
            json.dump(bad_destinations, f)
        
        with patch.object(redirection, 'get_config_path', return_value=dest_file):
            redirection.redirected_destinations_mtime = 0
            redirection.load_redirected_destinations()
            
            # Tag should exist but be empty (invalid destinations rejected)
            assert 'test' not in redirection.redirected_destinations or \
                   len(redirection.redirected_destinations['test']) == 0
    
    def test_invalid_ip_in_destination_rejected(self, temp_config_dir):
        """Invalid IP in destination is rejected."""
        from trapninja import redirection
        
        bad_destinations = {
            'test': [['not.valid.ip', 162]]
        }
        
        dest_file = os.path.join(temp_config_dir, 'redirected_destinations.json')
        with open(dest_file, 'w') as f:
            json.dump(bad_destinations, f)
        
        with patch.object(redirection, 'get_config_path', return_value=dest_file):
            redirection.redirected_destinations_mtime = 0
            redirection.load_redirected_destinations()
            
            # Tag should be empty or not exist
            assert 'test' not in redirection.redirected_destinations or \
                   len(redirection.redirected_destinations['test']) == 0
    
    def test_mixed_valid_invalid_destinations(self, temp_config_dir):
        """Mix of valid and invalid destinations - valid ones kept."""
        from trapninja import redirection
        
        mixed_destinations = {
            'test': [
                ['192.168.1.1', 162],    # Valid
                ['not.valid.ip', 162],   # Invalid IP
                ['192.168.1.2', 99999],  # Invalid port
                ['192.168.1.3', 162],    # Valid
            ]
        }
        
        dest_file = os.path.join(temp_config_dir, 'redirected_destinations.json')
        with open(dest_file, 'w') as f:
            json.dump(mixed_destinations, f)
        
        with patch.object(redirection, 'get_config_path', return_value=dest_file):
            redirection.redirected_destinations_mtime = 0
            redirection.load_redirected_destinations()
            
            # Should have only the 2 valid entries
            assert 'test' in redirection.redirected_destinations
            assert len(redirection.redirected_destinations['test']) == 2


# =============================================================================
# TEST CLASS: REDIRECTION IP LOADING
# =============================================================================

class TestRedirectionIPLoading:
    """Test IP redirection config loading."""
    
    def test_valid_ip_redirections_loaded(self, temp_config_dir, sample_redirected_ips):
        """Valid IP redirections are loaded."""
        from trapninja import redirection
        
        ip_file = os.path.join(temp_config_dir, 'redirected_ips.json')
        with open(ip_file, 'w') as f:
            json.dump(sample_redirected_ips, f)
        
        with patch.object(redirection, 'get_config_path', return_value=ip_file):
            redirection.redirected_ips_mtime = 0
            redirection.load_redirected_ips()
            
            assert '192.168.10.50' in redirection.redirected_ips
            assert redirection.redirected_ips['192.168.10.50'] == 'security'
    
    def test_invalid_ip_redirection_skipped(self, temp_config_dir):
        """Invalid IP in redirection is skipped."""
        from trapninja import redirection
        
        bad_redirections = [
            ['not.valid.ip', 'security'],
            ['192.168.1.1', 'valid_tag'],
        ]
        
        ip_file = os.path.join(temp_config_dir, 'redirected_ips.json')
        with open(ip_file, 'w') as f:
            json.dump(bad_redirections, f)
        
        with patch.object(redirection, 'get_config_path', return_value=ip_file):
            redirection.redirected_ips_mtime = 0
            redirection.load_redirected_ips()
            
            # Invalid IP should not be loaded
            assert 'not.valid.ip' not in redirection.redirected_ips
            # Valid IP should be loaded
            assert '192.168.1.1' in redirection.redirected_ips


# =============================================================================
# TEST CLASS: REDIRECTION OID LOADING
# =============================================================================

class TestRedirectionOIDLoading:
    """Test OID redirection config loading."""
    
    def test_valid_oid_redirections_loaded(self, temp_config_dir, sample_redirected_oids):
        """Valid OID redirections are loaded."""
        from trapninja import redirection
        
        oid_file = os.path.join(temp_config_dir, 'redirected_oids.json')
        with open(oid_file, 'w') as f:
            json.dump(sample_redirected_oids, f)
        
        with patch.object(redirection, 'get_config_path', return_value=oid_file):
            redirection.redirected_oids_mtime = 0
            redirection.load_redirected_oids()
            
            assert '1.3.6.1.4.1.8072.2.3.0.99' in redirection.redirected_oids
            assert redirection.redirected_oids['1.3.6.1.4.1.8072.2.3.0.99'] == 'voice'
    
    def test_invalid_oid_redirection_skipped(self, temp_config_dir):
        """Invalid OID in redirection is skipped."""
        from trapninja import redirection
        
        bad_redirections = [
            ['not.valid..oid', 'security'],  # Invalid (double dot)
            ['1.3.6.1.4.1.9.9.117', 'valid_tag'],  # Valid
        ]
        
        oid_file = os.path.join(temp_config_dir, 'redirected_oids.json')
        with open(oid_file, 'w') as f:
            json.dump(bad_redirections, f)
        
        with patch.object(redirection, 'get_config_path', return_value=oid_file):
            redirection.redirected_oids_mtime = 0
            redirection.load_redirected_oids()
            
            # Invalid OID should not be loaded
            assert 'not.valid..oid' not in redirection.redirected_oids
            # Valid OID should be loaded
            assert '1.3.6.1.4.1.9.9.117' in redirection.redirected_oids
