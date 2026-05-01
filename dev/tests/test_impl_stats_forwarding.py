#!/usr/bin/env python3
"""
TrapNinja Implementation Tests - Phase 11A: Stats + Forwarding

Validates that statistics are accurately tracked during the forwarding process.

ASSUMPTIONS:
- ProcessingStats tracks packets_processed, forwarded, blocked, redirected
- StatsCollector provides thread-local stats with periodic flush to global
- GranularStatsCollector tracks per-IP and per-OID statistics
- RateTracker uses time-bucketed counting for accurate rates
- Fast path (SNMPv2c) vs slow path tracking is accurate
- HA-blocked packets are tracked separately
- Stats remain consistent across multiple worker threads

Author: TrapNinja Team
"""

import os
import sys
import time
import queue
import threading
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock
from typing import Dict, List, Any
from dataclasses import dataclass

# Shared fixtures and utilities from fixtures/ directory
from fixtures import (
    build_snmpv2c_trap,
    build_snmpv1_trap,
    SampleOIDs,
    SampleIPs,
    create_config,
    create_packet_data,
)


# =============================================================================
# TEST CLASS: PROCESSING STATS ACCURACY
# =============================================================================

class TestProcessingStatsAccuracy:
    """Test that ProcessingStats counters are accurate."""
    
    def test_increment_processed_counts_correctly(self):
        """increment_processed increases counter by 1."""
        from trapninja.processing.stats import ProcessingStats
        
        stats = ProcessingStats()
        assert stats.packets_processed == 0
        
        stats.increment_processed()
        assert stats.packets_processed == 1
        
        stats.increment_processed()
        stats.increment_processed()
        assert stats.packets_processed == 3
    
    def test_increment_forwarded_counts_correctly(self):
        """increment_forwarded increases counter by 1."""
        from trapninja.processing.stats import ProcessingStats
        
        stats = ProcessingStats()
        assert stats.packets_forwarded == 0
        
        for _ in range(10):
            stats.increment_forwarded()
        
        assert stats.packets_forwarded == 10
    
    def test_increment_blocked_counts_correctly(self):
        """increment_blocked increases counter by 1."""
        from trapninja.processing.stats import ProcessingStats
        
        stats = ProcessingStats()
        
        stats.increment_blocked()
        stats.increment_blocked()
        
        assert stats.packets_blocked == 2
    
    def test_increment_redirected_counts_correctly(self):
        """increment_redirected increases counter by 1."""
        from trapninja.processing.stats import ProcessingStats
        
        stats = ProcessingStats()
        
        stats.increment_redirected()
        
        assert stats.packets_redirected == 1
    
    def test_increment_dropped_increments_both_counters(self):
        """increment_dropped increases both dropped and queue_full_events."""
        from trapninja.processing.stats import ProcessingStats
        
        stats = ProcessingStats()
        
        stats.increment_dropped()
        
        assert stats.packets_dropped == 1
        assert stats.queue_full_events == 1
    
    def test_increment_error_counts_correctly(self):
        """increment_error increases counter by 1."""
        from trapninja.processing.stats import ProcessingStats
        
        stats = ProcessingStats()
        
        stats.increment_error()
        stats.increment_error()
        stats.increment_error()
        
        assert stats.processing_errors == 3
    
    def test_increment_ha_blocked_counts_correctly(self):
        """increment_ha_blocked increases counter by 1."""
        from trapninja.processing.stats import ProcessingStats
        
        stats = ProcessingStats()
        
        stats.increment_ha_blocked()
        
        assert stats.ha_blocked == 1
        assert stats.ha_blocked_count == 1
    
    def test_fast_path_tracking(self):
        """record_fast_path increments fast_path_hits."""
        from trapninja.processing.stats import ProcessingStats
        
        stats = ProcessingStats()
        
        stats.record_fast_path()
        stats.record_fast_path()
        
        assert stats.fast_path_hits == 2
    
    def test_slow_path_tracking(self):
        """record_slow_path increments slow_path_hits."""
        from trapninja.processing.stats import ProcessingStats
        
        stats = ProcessingStats()
        
        stats.record_slow_path()
        
        assert stats.slow_path_hits == 1
    
    def test_fast_path_ratio_calculation(self):
        """fast_path_ratio calculates percentage correctly."""
        from trapninja.processing.stats import ProcessingStats
        
        stats = ProcessingStats()
        
        # 3 fast, 1 slow = 75%
        stats.record_fast_path()
        stats.record_fast_path()
        stats.record_fast_path()
        stats.record_slow_path()
        
        assert stats.fast_path_ratio == 75.0
    
    def test_fast_path_ratio_zero_packets(self):
        """fast_path_ratio returns 0 when no packets processed."""
        from trapninja.processing.stats import ProcessingStats
        
        stats = ProcessingStats()
        
        assert stats.fast_path_ratio == 0.0
    
    def test_max_queue_depth_tracking(self):
        """update_max_queue_depth only updates when higher."""
        from trapninja.processing.stats import ProcessingStats
        
        stats = ProcessingStats()
        
        stats.update_max_queue_depth(100)
        assert stats.max_queue_depth == 100
        
        stats.update_max_queue_depth(50)  # Lower, should not update
        assert stats.max_queue_depth == 100
        
        stats.update_max_queue_depth(150)  # Higher
        assert stats.max_queue_depth == 150
    
    def test_processing_rate_calculation(self):
        """processing_rate calculates packets per second."""
        from trapninja.processing.stats import ProcessingStats
        
        stats = ProcessingStats()
        
        # Process packets and check rate
        for _ in range(100):
            stats.increment_processed()
        
        # Rate should be positive
        assert stats.processing_rate > 0
    
    def test_uptime_tracking(self):
        """uptime returns seconds since start."""
        from trapninja.processing.stats import ProcessingStats
        
        stats = ProcessingStats()
        
        time.sleep(0.1)
        
        assert stats.uptime >= 0.1
    
    def test_reset_clears_all_counters(self):
        """reset clears all counters to zero."""
        from trapninja.processing.stats import ProcessingStats
        
        stats = ProcessingStats()
        
        # Set various counters
        stats.increment_processed()
        stats.increment_forwarded()
        stats.increment_blocked()
        stats.increment_redirected()
        stats.increment_dropped()
        stats.increment_error()
        stats.increment_ha_blocked()
        stats.record_fast_path()
        stats.record_slow_path()
        stats.update_max_queue_depth(100)
        
        stats.reset()
        
        assert stats.packets_processed == 0
        assert stats.packets_forwarded == 0
        assert stats.packets_blocked == 0
        assert stats.packets_redirected == 0
        assert stats.packets_dropped == 0
        assert stats.processing_errors == 0
        assert stats.ha_blocked == 0
        assert stats.fast_path_hits == 0
        assert stats.slow_path_hits == 0
        assert stats.max_queue_depth == 0
    
    def test_to_dict_contains_all_fields(self):
        """to_dict returns all expected fields."""
        from trapninja.processing.stats import ProcessingStats
        
        stats = ProcessingStats()
        stats.increment_processed()
        stats.increment_forwarded()
        
        result = stats.to_dict()
        
        expected_keys = [
            'packets_processed', 'packets_forwarded', 'packets_blocked',
            'packets_redirected', 'packets_dropped', 'processing_errors',
            'ha_blocked', 'fast_path_hits', 'slow_path_hits', 'fast_path_ratio',
            'queue_full_events', 'max_queue_depth', 'uptime_seconds', 'processing_rate'
        ]
        
        for key in expected_keys:
            assert key in result


# =============================================================================
# TEST CLASS: STATS COLLECTOR THREAD-LOCAL BEHAVIOR
# =============================================================================

class TestStatsCollectorThreadLocal:
    """Test StatsCollector thread-local accumulation and flush."""
    
    def test_collector_accumulates_locally(self):
        """StatsCollector accumulates stats locally before flush."""
        from trapninja.processing.stats import StatsCollector
        
        collector = StatsCollector(flush_interval=100)
        
        collector.increment_processed()
        collector.increment_forwarded()
        
        # Local stats should be updated
        assert collector._local.packets_processed == 1
        assert collector._local.packets_forwarded == 1
    
    def test_collector_flushes_at_interval(self):
        """StatsCollector flushes to global at flush_interval."""
        from trapninja.processing.stats import StatsCollector, get_global_stats, reset_global_stats
        
        reset_global_stats()
        collector = StatsCollector(flush_interval=5)
        
        # Process 5 packets to trigger flush
        for _ in range(5):
            collector.increment_processed()
        
        # Should have flushed to global
        global_stats = get_global_stats()
        assert global_stats.packets_processed >= 5
    
    def test_collector_manual_flush(self):
        """StatsCollector.flush() pushes local to global."""
        from trapninja.processing.stats import StatsCollector, get_global_stats, reset_global_stats
        
        reset_global_stats()
        collector = StatsCollector(flush_interval=1000)  # High interval
        
        collector.increment_processed()
        collector.increment_processed()
        collector.increment_processed()
        
        # Not yet flushed
        assert collector._local.packets_processed == 3
        
        collector.flush()
        
        # Local should be reset
        assert collector._local.packets_processed == 0
        
        # Global should have the counts
        global_stats = get_global_stats()
        assert global_stats.packets_processed >= 3
    
    def test_collector_tracks_all_stat_types(self):
        """StatsCollector tracks all statistic types."""
        from trapninja.processing.stats import StatsCollector
        
        collector = StatsCollector(flush_interval=1000)
        
        collector.increment_processed()
        collector.increment_forwarded()
        collector.increment_blocked()
        collector.increment_redirected()
        collector.increment_dropped()
        collector.increment_error()
        collector.increment_ha_blocked()
        collector.record_fast_path()
        collector.record_slow_path()
        
        assert collector._local.packets_processed == 1
        assert collector._local.packets_forwarded == 1
        assert collector._local.packets_blocked == 1
        assert collector._local.packets_redirected == 1
        assert collector._local.packets_dropped == 1
        assert collector._local.processing_errors == 1
        assert collector._local.ha_blocked == 1
        assert collector._local.fast_path_hits == 1
        assert collector._local.slow_path_hits == 1
    
    def test_ha_blocked_count_property(self):
        """ha_blocked_count property returns local count."""
        from trapninja.processing.stats import StatsCollector
        
        collector = StatsCollector()
        
        collector.increment_ha_blocked()
        collector.increment_ha_blocked()
        
        assert collector.ha_blocked_count == 2


# =============================================================================
# TEST CLASS: GLOBAL STATS MANAGEMENT
# =============================================================================

class TestGlobalStatsManagement:
    """Test global stats instance management."""
    
    def test_get_global_stats_returns_singleton(self):
        """get_global_stats returns same instance."""
        from trapninja.processing.stats import get_global_stats
        
        stats1 = get_global_stats()
        stats2 = get_global_stats()
        
        assert stats1 is stats2
    
    def test_reset_global_stats_clears_counters(self):
        """reset_global_stats clears all counters."""
        from trapninja.processing.stats import get_global_stats, reset_global_stats
        
        stats = get_global_stats()
        stats.increment_processed()
        
        reset_global_stats()
        
        stats = get_global_stats()
        assert stats.packets_processed == 0


# =============================================================================
# TEST CLASS: MULTI-THREAD STATS CONSISTENCY
# =============================================================================

class TestMultiThreadStatsConsistency:
    """Test stats consistency across multiple threads."""
    
    def test_concurrent_increments_are_consistent(self):
        """Concurrent increments from multiple threads are consistent."""
        from trapninja.processing.stats import get_global_stats, reset_global_stats
        
        reset_global_stats()
        stats = get_global_stats()
        
        num_threads = 10
        increments_per_thread = 100
        
        def worker():
            for _ in range(increments_per_thread):
                stats.increment_processed()
        
        threads = [threading.Thread(target=worker) for _ in range(num_threads)]
        
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        expected = num_threads * increments_per_thread
        assert stats.packets_processed == expected
    
    def test_multiple_collectors_flush_correctly(self):
        """Multiple StatsCollectors flush to same global correctly."""
        from trapninja.processing.stats import StatsCollector, get_global_stats, reset_global_stats
        
        reset_global_stats()
        
        num_collectors = 5
        increments_per_collector = 50
        
        def worker():
            collector = StatsCollector(flush_interval=10)
            for _ in range(increments_per_collector):
                collector.increment_processed()
            collector.flush()
        
        threads = [threading.Thread(target=worker) for _ in range(num_collectors)]
        
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        global_stats = get_global_stats()
        expected = num_collectors * increments_per_collector
        assert global_stats.packets_processed == expected


# =============================================================================
# TEST CLASS: RATE TRACKER ACCURACY
# =============================================================================

class TestRateTrackerAccuracy:
    """Test RateTracker provides accurate rate calculations."""
    
    def test_record_creates_bucket(self):
        """record() creates time bucket for event."""
        from trapninja.stats.models import RateTracker
        
        tracker = RateTracker(window_seconds=60)
        
        tracker.record()
        
        assert tracker.get_count(60) == 1
    
    def test_get_count_within_window(self):
        """get_count returns events within time window."""
        from trapninja.stats.models import RateTracker
        
        tracker = RateTracker(window_seconds=60)
        
        now = time.time()
        
        # Record 5 events
        for _ in range(5):
            tracker.record(now)
        
        assert tracker.get_count(60) == 5
    
    def test_get_rate_calculates_per_second(self):
        """get_rate returns events per second."""
        from trapninja.stats.models import RateTracker
        
        tracker = RateTracker(window_seconds=60)
        
        now = time.time()
        
        # Record 60 events
        for _ in range(60):
            tracker.record(now)
        
        # 60 events over 60 seconds = 1 per second
        rate = tracker.get_rate(60)
        assert rate == 1.0
    
    def test_rate_tracker_cleans_old_buckets(self):
        """RateTracker cleans up buckets older than 2x window."""
        from trapninja.stats.models import RateTracker
        
        tracker = RateTracker(window_seconds=10)
        
        # Record in far past (should be cleaned)
        old_time = time.time() - 100
        tracker.record(old_time)
        
        # Record now (triggers cleanup)
        tracker.record()
        
        # Old bucket should be cleaned, only recent should count
        assert tracker.get_count(10) == 1
    
    def test_peak_rate_tracking(self):
        """RateTracker tracks peak rate."""
        from trapninja.stats.models import RateTracker
        
        tracker = RateTracker(window_seconds=60)
        
        # Record many events to create a peak
        now = time.time()
        for _ in range(100):
            tracker.record(now)
        
        # Force peak check
        tracker._check_peak_rate(now)
        
        peak = tracker.get_peak_rate()
        assert peak >= 100


# =============================================================================
# TEST CLASS: WORKER STATS INTEGRATION
# =============================================================================

class TestWorkerStatsIntegration:
    """Test that PacketWorker correctly updates stats."""
    
    def test_worker_increments_processed_on_packet(self):
        """Worker increments packets_processed for each packet."""
        from trapninja.processing.worker import PacketWorker
        from trapninja.processing.worker import _config_cache
        
        config = {
            'destinations': [('192.168.1.100', 162)],
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
        
        payload = build_snmpv2c_trap()
        packet_data = create_packet_data(SampleIPs.NORMAL_1, payload)
        
        with patch.object(_config_cache, 'get', return_value=config), \
             patch('trapninja.processing.packet_handler.forward_packet', return_value=True), \
             patch('trapninja.processing.packet_handler.modules.ha.is_forwarding_enabled', return_value=True):
            
            worker._process_packet(packet_data)
        
        # Check local stats were updated
        assert worker.stats._local.packets_processed >= 1
    
    def test_worker_increments_forwarded_on_success(self):
        """Worker increments packets_forwarded on successful forward."""
        from trapninja.processing.worker import PacketWorker
        from trapninja.processing.worker import _config_cache
        
        config = {
            'destinations': [('192.168.1.100', 162)],
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
        
        payload = build_snmpv2c_trap()
        packet_data = create_packet_data(SampleIPs.NORMAL_1, payload)
        
        with patch.object(_config_cache, 'get', return_value=config), \
             patch('trapninja.processing.packet_handler.forward_packet', return_value=True), \
             patch('trapninja.processing.packet_handler.modules.ha.is_forwarding_enabled', return_value=True):
            
            worker._process_packet(packet_data)
        
        assert worker.stats._local.packets_forwarded >= 1
    
    def test_worker_increments_blocked_on_ip_block(self):
        """Worker increments packets_blocked when IP is blocked."""
        from trapninja.processing.worker import PacketWorker
        from trapninja.processing.worker import _config_cache
        
        config = {
            'destinations': [('192.168.1.100', 162)],
            'blocked_traps': set(),
            'blocked_dest': [],
            'blocked_ips': {SampleIPs.BLOCKED_1},
            'redirected_ips': {},
            'redirected_oids': {},
            'redirected_destinations': {},
        }
        
        pq = queue.Queue()
        stop = threading.Event()
        worker = PacketWorker(0, pq, stop)
        
        payload = build_snmpv2c_trap()
        packet_data = create_packet_data(SampleIPs.BLOCKED_1, payload)
        
        with patch.object(_config_cache, 'get', return_value=config), \
             patch('trapninja.processing.packet_handler.modules.ha.is_forwarding_enabled', return_value=True):
            
            worker._process_packet(packet_data)
        
        assert worker.stats._local.packets_blocked >= 1
    
    def test_worker_increments_blocked_on_oid_block(self):
        """Worker increments packets_blocked when OID is blocked."""
        from trapninja.processing.worker import PacketWorker
        from trapninja.processing.worker import _config_cache
        
        config = {
            'destinations': [('192.168.1.100', 162)],
            'blocked_traps': {SampleOIDs.BLOCKED_1},
            'blocked_dest': [],
            'blocked_ips': set(),
            'redirected_ips': {},
            'redirected_oids': {},
            'redirected_destinations': {},
        }
        
        pq = queue.Queue()
        stop = threading.Event()
        worker = PacketWorker(0, pq, stop)
        
        payload = build_snmpv2c_trap(trap_oid=SampleOIDs.BLOCKED_1)
        packet_data = create_packet_data(SampleIPs.NORMAL_1, payload)
        
        with patch.object(_config_cache, 'get', return_value=config), \
             patch('trapninja.processing.packet_handler.modules.ha.is_forwarding_enabled', return_value=True):
            
            worker._process_packet(packet_data)
        
        assert worker.stats._local.packets_blocked >= 1
    
    def test_worker_increments_redirected_on_redirect(self):
        """Worker increments packets_redirected when packet is redirected."""
        from trapninja.processing.worker import PacketWorker
        from trapninja.processing.worker import _config_cache
        
        config = {
            'destinations': [('192.168.1.100', 162)],
            'blocked_traps': set(),
            'blocked_dest': [],
            'blocked_ips': set(),
            'redirected_ips': {SampleIPs.REDIRECT_VOICE: 'voice'},
            'redirected_oids': {},
            'redirected_destinations': {
                'voice': [('10.10.10.1', 162)]
            },
        }
        
        pq = queue.Queue()
        stop = threading.Event()
        worker = PacketWorker(0, pq, stop)
        
        payload = build_snmpv2c_trap()
        packet_data = create_packet_data(SampleIPs.REDIRECT_VOICE, payload)
        
        with patch.object(_config_cache, 'get', return_value=config), \
             patch('trapninja.processing.packet_handler.forward_packet', return_value=True), \
             patch('trapninja.processing.packet_handler.modules.ha.is_forwarding_enabled', return_value=True):
            
            worker._process_packet(packet_data)
        
        assert worker.stats._local.packets_redirected >= 1
    
    def test_worker_increments_ha_blocked_on_secondary(self):
        """Worker increments ha_blocked when HA blocks forwarding."""
        from trapninja.processing.worker import PacketWorker
        from trapninja.processing.worker import _config_cache
        
        config = {
            'destinations': [('192.168.1.100', 162)],
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
        
        payload = build_snmpv2c_trap()
        packet_data = create_packet_data(SampleIPs.NORMAL_1, payload)
        
        with patch.object(_config_cache, 'get', return_value=config), \
             patch('trapninja.processing.packet_handler.modules.ha.is_forwarding_enabled', return_value=False):
            
            worker._process_packet(packet_data)
        
        assert worker.stats._local.ha_blocked >= 1
    
    def test_worker_records_fast_path_for_v2c(self):
        """Worker records fast_path for SNMPv2c packets."""
        from trapninja.processing.worker import PacketWorker
        from trapninja.processing.worker import _config_cache
        
        config = {
            'destinations': [('192.168.1.100', 162)],
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
        
        payload = build_snmpv2c_trap()
        packet_data = create_packet_data(SampleIPs.NORMAL_1, payload)
        
        with patch.object(_config_cache, 'get', return_value=config), \
             patch('trapninja.processing.packet_handler.forward_packet', return_value=True), \
             patch('trapninja.processing.packet_handler.modules.ha.is_forwarding_enabled', return_value=True):
            
            worker._process_packet(packet_data)
        
        # SNMPv2c should use fast path
        assert worker.stats._local.fast_path_hits >= 1


# =============================================================================
# TEST CLASS: GRANULAR STATS COLLECTION
# =============================================================================

class TestGranularStatsCollection:
    """Test granular per-IP and per-OID statistics collection."""
    
    def test_granular_collector_available(self):
        """Check if granular stats collector module is available."""
        try:
            from trapninja.stats import get_stats_collector
            assert callable(get_stats_collector)
        except ImportError:
            pytest.skip("Granular stats module not available")
    
    def test_ip_stats_tracking(self):
        """IP statistics are tracked per source IP using record_trap."""
        from trapninja.stats.models import IPStats
        
        stats = IPStats(ip_address="192.168.1.50")
        
        # Use record_trap to update counters
        for _ in range(8):
            stats.record_trap(action='forwarded')
        for _ in range(2):
            stats.record_trap(action='blocked')
        
        assert stats.total_traps == 10
        assert stats.forwarded == 8
        assert stats.blocked == 2
    
    def test_oid_stats_tracking(self):
        """OID statistics are tracked per trap OID using record_trap."""
        from trapninja.stats.models import OIDStats
        
        stats = OIDStats(oid=SampleOIDs.COLD_START)
        
        # Use record_trap to increment counts
        for _ in range(5):
            stats.record_trap(source_ip="192.168.1.1")
        
        assert stats.total_traps == 5
        assert stats.oid == SampleOIDs.COLD_START
    
    def test_lru_dict_eviction(self):
        """LRUDict evicts oldest entries when full."""
        from trapninja.stats.collector import LRUDict
        
        lru = LRUDict(max_size=3)
        
        lru['a'] = 1
        lru['b'] = 2
        lru['c'] = 3
        lru['d'] = 4  # Should evict 'a'
        
        assert 'a' not in lru
        assert 'd' in lru
        assert len(lru) == 3
    
    def test_lru_dict_get_or_create_updates_order(self):
        """LRUDict.get_or_create moves accessed item to end (most recent)."""
        from trapninja.stats.collector import LRUDict
        
        lru = LRUDict(max_size=3)
        
        lru['a'] = 1
        lru['b'] = 2
        lru['c'] = 3
        
        # Use get_or_create to access 'a' - this moves it to end
        lru.get_or_create('a', lambda: 999)
        
        # Add new item, should evict 'b' (now oldest)
        lru['d'] = 4
        
        assert 'a' in lru
        assert 'b' not in lru
    
    def test_lru_dict_get_or_create(self):
        """LRUDict.get_or_create creates new entry if missing."""
        from trapninja.stats.collector import LRUDict
        
        lru = LRUDict(max_size=10)
        
        result = lru.get_or_create('new_key', lambda: {'value': 42})
        
        assert result == {'value': 42}
        assert 'new_key' in lru
    
    def test_lru_dict_get_or_create_returns_existing(self):
        """LRUDict.get_or_create returns existing entry if present."""
        from trapninja.stats.collector import LRUDict
        
        lru = LRUDict(max_size=10)
        lru['existing'] = {'value': 100}
        
        result = lru.get_or_create('existing', lambda: {'value': 999})
        
        assert result == {'value': 100}


# =============================================================================
# TEST CLASS: STATS SUMMARY AND LOGGING
# =============================================================================

class TestStatsSummaryAndLogging:
    """Test stats summary generation and logging behavior."""
    
    def test_should_log_summary_respects_interval(self):
        """should_log_summary returns True only after interval elapsed."""
        from trapninja.processing.stats import ProcessingStats
        
        stats = ProcessingStats()
        
        # Backdate _last_summary_time to simulate time passing
        stats._last_summary_time = time.time() - 0.2
        
        # Now should_log_summary should return True (interval elapsed)
        assert stats.should_log_summary(interval=0.1) is True
        
        # Immediate second call should return False (interval reset)
        assert stats.should_log_summary(interval=0.1) is False
        
        # After interval, should return True again
        time.sleep(0.15)
        assert stats.should_log_summary(interval=0.1) is True
    
    def test_stats_dict_contains_computed_values(self):
        """to_dict includes computed values like rate and ratio."""
        from trapninja.processing.stats import ProcessingStats
        
        stats = ProcessingStats()
        stats.increment_processed()
        stats.record_fast_path()
        
        result = stats.to_dict()
        
        assert 'processing_rate' in result
        assert 'fast_path_ratio' in result
        assert 'uptime_seconds' in result


# =============================================================================
# TEST CLASS: STATS DURING BATCH PROCESSING
# =============================================================================

class TestStatsDuringBatchProcessing:
    """Test stats accuracy during batch packet processing."""
    
    def test_batch_processing_stats_accuracy(self):
        """Stats are accurate after processing a batch of packets."""
        from trapninja.processing.worker import PacketWorker
        from trapninja.processing.worker import _config_cache
        
        config = {
            'destinations': [('192.168.1.100', 162)],
            'blocked_traps': {SampleOIDs.BLOCKED_1},
            'blocked_dest': [],
            'blocked_ips': {SampleIPs.BLOCKED_1, SampleIPs.BLOCKED_2},  # Both IPs blocked
            'redirected_ips': {},
            'redirected_oids': {},
            'redirected_destinations': {},
        }
        
        pq = queue.Queue()
        stop = threading.Event()
        worker = PacketWorker(0, pq, stop)
        
        # Create batch of packets: 3 normal, 2 blocked by IP, 1 blocked by OID
        packets = [
            create_packet_data(SampleIPs.NORMAL_1, build_snmpv2c_trap()),
            create_packet_data(SampleIPs.NORMAL_2, build_snmpv2c_trap()),
            create_packet_data(SampleIPs.NORMAL_3, build_snmpv2c_trap()),
            create_packet_data(SampleIPs.BLOCKED_1, build_snmpv2c_trap()),
            create_packet_data(SampleIPs.BLOCKED_2, build_snmpv2c_trap()),
            create_packet_data(SampleIPs.NORMAL_1, build_snmpv2c_trap(trap_oid=SampleOIDs.BLOCKED_1)),
        ]
        
        with patch.object(_config_cache, 'get', return_value=config), \
             patch('trapninja.processing.packet_handler.forward_packet', return_value=True), \
             patch('trapninja.processing.packet_handler.modules.ha.is_forwarding_enabled', return_value=True):
            
            for packet in packets:
                worker._process_packet(packet)
        
        # Check stats
        assert worker.stats._local.packets_processed == 6
        assert worker.stats._local.packets_forwarded == 3  # 3 normal
        assert worker.stats._local.packets_blocked == 3  # 2 IP + 1 OID


# =============================================================================
# TEST CLASS: DESTINATION STATS
# =============================================================================

class TestDestinationStats:
    """Test per-destination statistics tracking."""
    
    def test_destination_stats_model(self):
        """DestinationStats tracks packets sent to destination using record_forward."""
        from trapninja.stats.models import DestinationStats
        
        stats = DestinationStats(
            destination="192.168.1.100:162"
        )
        
        # Use record_forward to update counters
        for _ in range(10):
            stats.record_forward(source_ip="10.0.0.1", success=True)
        for _ in range(2):
            stats.record_forward(source_ip="10.0.0.2", success=False)
        
        assert stats.total_forwarded == 12
        assert stats.successful == 10
        assert stats.failed == 2
    
    def test_multiple_destinations_tracked_separately(self):
        """Each destination has separate statistics."""
        from trapninja.stats.models import DestinationStats
        
        dest1 = DestinationStats(destination="192.168.1.100:162")
        dest2 = DestinationStats(destination="192.168.1.101:162")
        
        for _ in range(5):
            dest1.record_forward(source_ip="10.0.0.1")
        for _ in range(10):
            dest2.record_forward(source_ip="10.0.0.2")
        
        assert dest1.total_forwarded == 5
        assert dest2.total_forwarded == 10


# =============================================================================
# TEST CLASS: STATS SNAPSHOT
# =============================================================================

class TestStatsSnapshot:
    """Test StatsSnapshot for point-in-time statistics capture."""
    
    def test_stats_snapshot_captures_timestamp(self):
        """StatsSnapshot includes capture timestamp."""
        from trapninja.stats.models import StatsSnapshot
        
        before = time.time()
        snapshot = StatsSnapshot(
            total_traps=100,
            overall_rate_per_minute=600.0,
        )
        after = time.time()
        
        assert before <= snapshot.timestamp <= after
    
    def test_stats_snapshot_contains_top_lists(self):
        """StatsSnapshot contains top IPs and OIDs."""
        from trapninja.stats.models import StatsSnapshot
        
        snapshot = StatsSnapshot(
            total_traps=100,
            overall_rate_per_minute=600.0,
            top_ips=[{'ip': '192.168.1.1', 'count': 50}, {'ip': '192.168.1.2', 'count': 30}],
            top_oids=[{'oid': '1.3.6.1.6.3.1.1.5.1', 'count': 40}]
        )
        
        assert len(snapshot.top_ips) == 2
        assert len(snapshot.top_oids) == 1
    
    def test_stats_snapshot_to_dict(self):
        """StatsSnapshot can be serialized to dict."""
        from trapninja.stats.models import StatsSnapshot
        
        snapshot = StatsSnapshot(
            total_traps=100,
            total_forwarded=95,
            total_blocked=5,
        )
        
        result = snapshot.to_dict()
        
        assert 'summary' in result
        assert result['summary']['total_traps'] == 100
        assert result['summary']['total_forwarded'] == 95
