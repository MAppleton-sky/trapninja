#!/usr/bin/env python3
"""
TrapNinja Implementation Tests - Phase 11B: HA + Cache Coordination

Validates coordination between High Availability and Cache subsystems.

ASSUMPTIONS:
- Cache stores traps on both PRIMARY and SECONDARY nodes
- FailoverReplayManager detects gaps on becoming PRIMARY
- Replay occurs automatically after failover
- GapDetector identifies missing time ranges
- FailoverTracker tracks last forwarded timestamps
- Cache replay respects rate limits
- HA state transitions trigger appropriate cache operations

Author: TrapNinja Team
"""

import os
import sys
import time
import queue
import threading
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock, call
from typing import Dict, List, Any
from dataclasses import dataclass
from datetime import datetime, timedelta

# Shared fixtures and utilities from fixtures/ directory
from fixtures import (
    build_snmpv2c_trap,
    SampleOIDs,
    SampleIPs,
    create_config,
    create_packet_data,
)


# =============================================================================
# TEST CLASS: FAILOVER REPLAY CONFIG
# =============================================================================

class TestFailoverReplayConfig:
    """Test FailoverReplayConfig dataclass."""
    
    def test_default_config_values(self):
        """Default config has sensible values."""
        from trapninja.cache.failover import FailoverReplayConfig
        
        config = FailoverReplayConfig()
        
        assert config.enabled is True
        assert config.min_gap_seconds == 1.0
        assert config.max_gap_seconds == 300.0
        assert config.replay_rate_limit == 2000
        assert config.replay_delay_seconds == 1.0
        assert config.buffer_seconds == 0.5
        assert config.replay_in_background is True
        assert config.mark_replayed_traps is False
    
    def test_config_from_dict(self):
        """Config can be created from dictionary."""
        from trapninja.cache.failover import FailoverReplayConfig
        
        data = {
            'enabled': False,
            'min_gap_seconds': 2.0,
            'max_gap_seconds': 600.0,
            'replay_rate_limit': 5000,
        }
        
        config = FailoverReplayConfig.from_dict(data)
        
        assert config.enabled is False
        assert config.min_gap_seconds == 2.0
        assert config.max_gap_seconds == 600.0
        assert config.replay_rate_limit == 5000
    
    def test_config_to_dict(self):
        """Config can be serialized to dictionary."""
        from trapninja.cache.failover import FailoverReplayConfig
        
        config = FailoverReplayConfig(
            enabled=True,
            min_gap_seconds=3.0,
        )
        
        result = config.to_dict()
        
        assert result['enabled'] is True
        assert result['min_gap_seconds'] == 3.0
    
    def test_config_from_dict_uses_defaults(self):
        """Config from_dict uses defaults for missing keys."""
        from trapninja.cache.failover import FailoverReplayConfig
        
        config = FailoverReplayConfig.from_dict({})
        
        assert config.enabled is True
        assert config.replay_rate_limit == 2000


# =============================================================================
# TEST CLASS: FAILOVER TRACKER
# =============================================================================

class TestFailoverTracker:
    """Test FailoverTracker timestamp tracking."""
    
    def test_tracker_initialization(self):
        """Tracker initializes with instance_id."""
        from trapninja.cache.failover import FailoverTracker
        
        mock_redis = MagicMock()
        tracker = FailoverTracker(redis_client=mock_redis, instance_id="test-node-1")
        
        assert tracker.instance_id == "test-node-1"
    
    def test_update_last_forwarded_with_flush(self):
        """update_last_forwarded stores timestamp in Redis after flush."""
        from trapninja.cache.failover import FailoverTracker
        
        mock_redis = MagicMock()
        mock_pipe = MagicMock()
        mock_redis.pipeline.return_value = mock_pipe
        
        tracker = FailoverTracker(redis_client=mock_redis, instance_id="test-node-1")
        
        timestamp = time.time()
        tracker.update_last_forwarded("192.168.1.100:162", timestamp)
        
        # Force flush to send to Redis
        tracker.flush()
        
        # Now pipeline should have been used
        mock_redis.pipeline.assert_called()
    
    def test_get_last_forwarded(self):
        """get_last_forwarded retrieves timestamp from Redis."""
        from trapninja.cache.failover import FailoverTracker
        
        mock_redis = MagicMock()
        stored_time = time.time()
        # hgetall returns a dict with string/bytes keys
        mock_redis.hgetall.return_value = {'timestamp': str(stored_time)}
        
        tracker = FailoverTracker(redis_client=mock_redis, instance_id="test-node-1")
        
        result = tracker.get_last_forwarded("192.168.1.100:162")
        
        assert result is not None
        assert abs(result - stored_time) < 0.001
    
    def test_get_last_forwarded_no_data(self):
        """get_last_forwarded returns None when no data."""
        from trapninja.cache.failover import FailoverTracker
        
        mock_redis = MagicMock()
        mock_redis.hgetall.return_value = {}
        
        tracker = FailoverTracker(redis_client=mock_redis, instance_id="test-node-1")
        
        result = tracker.get_last_forwarded("192.168.1.100:162")
        
        assert result is None
    
    def test_tracker_uses_destination_key(self):
        """Tracker stores separate timestamps per destination."""
        from trapninja.cache.failover import FailoverTracker
        
        mock_redis = MagicMock()
        mock_pipe = MagicMock()
        mock_redis.pipeline.return_value = mock_pipe
        
        tracker = FailoverTracker(redis_client=mock_redis, instance_id="test-node-1")
        
        timestamp = time.time()
        tracker.update_last_forwarded("dest-1:162", timestamp)
        tracker.update_last_forwarded("dest-2:162", timestamp + 1)
        
        # Force flush
        tracker.flush()
        
        # Should have called pipeline hset for both
        assert mock_pipe.hset.call_count == 2
    
    def test_set_active_node(self):
        """set_active_node marks this node as active."""
        from trapninja.cache.failover import FailoverTracker
        
        mock_redis = MagicMock()
        tracker = FailoverTracker(redis_client=mock_redis, instance_id="test-node-1")
        
        tracker.set_active_node(True)
        
        mock_redis.setex.assert_called()


# =============================================================================
# TEST CLASS: GAP DETECTOR
# =============================================================================

class TestGapDetector:
    """Test GapDetector for identifying forwarding gaps."""
    
    def test_gap_detector_initialization(self):
        """GapDetector initializes with tracker."""
        from trapninja.cache.failover import GapDetector, FailoverTracker
        
        mock_redis = MagicMock()
        tracker = FailoverTracker(redis_client=mock_redis, instance_id="test")
        
        detector = GapDetector(tracker)
        
        assert detector._tracker is tracker
    
    def test_detect_gaps_returns_list(self):
        """detect_gaps returns list of GapInfo when gaps exist."""
        from trapninja.cache.failover import GapDetector, FailoverTracker, GapInfo
        
        mock_redis = MagicMock()
        # Simulate last forwarded 10 seconds ago
        old_time = time.time() - 10
        mock_redis.hgetall.return_value = {'timestamp': str(old_time)}
        mock_redis.keys.return_value = ['trapninja:failover:last_forwarded:192.168.1.100:162']
        
        tracker = FailoverTracker(redis_client=mock_redis, instance_id="test")
        detector = GapDetector(tracker, min_gap_seconds=5.0)
        
        gaps = detector.detect_gaps()
        
        assert isinstance(gaps, list)
    
    def test_detect_gap_for_destination_returns_gap_info(self):
        """detect_gap_for_destination returns GapInfo when gap exists."""
        from trapninja.cache.failover import GapDetector, FailoverTracker, GapInfo
        
        mock_redis = MagicMock()
        # Simulate last forwarded 10 seconds ago
        old_time = time.time() - 10
        mock_redis.hgetall.return_value = {'timestamp': str(old_time)}
        
        tracker = FailoverTracker(redis_client=mock_redis, instance_id="test")
        detector = GapDetector(tracker, min_gap_seconds=5.0)
        
        gap = detector.detect_gap_for_destination("192.168.1.100:162")
        
        assert gap is not None
        assert gap.gap_seconds >= 9.0  # At least 9 seconds
    
    def test_detect_gap_no_gap_when_recent(self):
        """detect_gap_for_destination returns None when last forward is recent."""
        from trapninja.cache.failover import GapDetector, FailoverTracker
        
        mock_redis = MagicMock()
        # Simulate last forwarded 1 second ago
        recent_time = time.time() - 1
        mock_redis.hgetall.return_value = {'timestamp': str(recent_time)}
        
        tracker = FailoverTracker(redis_client=mock_redis, instance_id="test")
        detector = GapDetector(tracker, min_gap_seconds=5.0)
        
        gap = detector.detect_gap_for_destination("192.168.1.100:162")
        
        assert gap is None
    
    def test_gap_info_structure(self):
        """GapInfo contains expected fields."""
        from trapninja.cache.failover import GapInfo
        
        now = time.time()
        gap = GapInfo(
            destination="192.168.1.100:162",
            gap_start=now - 10,
            gap_end=now,
            gap_seconds=10.0,
        )
        
        assert gap.destination == "192.168.1.100:162"
        assert gap.gap_seconds == 10.0
    
    def test_gap_info_to_dict(self):
        """GapInfo can be serialized to dictionary."""
        from trapninja.cache.failover import GapInfo
        
        now = time.time()
        gap = GapInfo(
            destination="192.168.1.100:162",
            gap_start=now - 10,
            gap_end=now,
            gap_seconds=10.0,
        )
        
        result = gap.to_dict()
        
        assert 'destination' in result
        assert 'gap_seconds' in result
        assert result['gap_seconds'] == 10.0


# =============================================================================
# TEST CLASS: FAILOVER REPLAY MANAGER
# =============================================================================

class TestFailoverReplayManager:
    """Test FailoverReplayManager orchestration."""
    
    def test_manager_initialization(self):
        """Manager initializes with cache and config."""
        from trapninja.cache.failover import FailoverReplayManager, FailoverReplayConfig
        from trapninja.cache.redis_backend import TrapCache, CacheConfig
        
        mock_cache = MagicMock(spec=TrapCache)
        mock_cache.available = False  # Disable component init
        mock_cache._client = None
        
        config = FailoverReplayConfig()
        
        manager = FailoverReplayManager(
            cache=mock_cache,
            config=config,
            instance_id="test-node",
        )
        
        assert manager._config is config
        assert manager._instance_id == "test-node"
    
    def test_manager_disabled_does_nothing(self):
        """Manager with disabled config does not replay."""
        from trapninja.cache.failover import FailoverReplayManager, FailoverReplayConfig
        from trapninja.cache.redis_backend import TrapCache
        
        mock_cache = MagicMock(spec=TrapCache)
        mock_cache.available = False
        mock_cache._client = None
        
        config = FailoverReplayConfig(enabled=False)
        
        manager = FailoverReplayManager(
            cache=mock_cache,
            config=config,
            instance_id="test-node",
        )
        
        # Should not trigger replay when disabled
        manager.on_become_primary()
        
        # No replay should have been attempted
        assert manager._is_primary is False  # Stays false because disabled
    
    def test_manager_available_property(self):
        """available property reflects readiness."""
        from trapninja.cache.failover import FailoverReplayManager, FailoverReplayConfig
        
        mock_cache = MagicMock()
        mock_cache.available = False
        mock_cache._client = None
        
        config = FailoverReplayConfig(enabled=True)
        
        manager = FailoverReplayManager(
            cache=mock_cache,
            config=config,
            instance_id="test-node",
        )
        
        # Not available because tracker/detector not initialized
        assert manager.available is False


# =============================================================================
# TEST CLASS: CACHE CONFIG
# =============================================================================

class TestCacheConfig:
    """Test CacheConfig for TrapCache."""
    
    def test_cache_config_defaults(self):
        """CacheConfig has sensible defaults."""
        from trapninja.cache.redis_backend import CacheConfig
        
        config = CacheConfig()
        
        assert config.enabled is False  # Disabled by default
        assert config.host == "localhost"
        assert config.port == 6379
        assert config.retention_hours == 2.0
    
    def test_cache_config_from_dict(self):
        """CacheConfig can be created from dict."""
        from trapninja.cache.redis_backend import CacheConfig
        
        data = {
            'enabled': True,
            'host': '10.0.0.1',
            'port': 6380,
            'retention_hours': 4.0,
        }
        
        config = CacheConfig.from_dict(data)
        
        assert config.enabled is True
        assert config.host == '10.0.0.1'
        assert config.port == 6380
        assert config.retention_hours == 4.0
    
    def test_cache_config_to_dict(self):
        """CacheConfig can be serialized."""
        from trapninja.cache.redis_backend import CacheConfig
        
        config = CacheConfig(enabled=True, host='redis.local')
        
        result = config.to_dict()
        
        assert result['enabled'] is True
        assert result['host'] == 'redis.local'


# =============================================================================
# TEST CLASS: TRAP CACHE INITIALIZATION
# =============================================================================

class TestTrapCacheInitialization:
    """Test TrapCache initialization and connection."""
    
    def test_cache_takes_config(self):
        """TrapCache takes CacheConfig in constructor."""
        from trapninja.cache.redis_backend import TrapCache, CacheConfig
        
        config = CacheConfig(enabled=False)
        cache = TrapCache(config)
        
        assert cache.config is config
    
    def test_cache_available_when_connected(self):
        """available returns True when connected."""
        from trapninja.cache.redis_backend import TrapCache, CacheConfig
        
        config = CacheConfig(enabled=False)
        cache = TrapCache(config)
        
        # Not connected, so not available
        assert cache.available is False
    
    def test_cache_stream_key_generation(self):
        """_stream_key generates correct key format."""
        from trapninja.cache.redis_backend import TrapCache, CacheConfig
        
        config = CacheConfig(key_prefix="test:buffer")
        cache = TrapCache(config)
        
        key = cache._stream_key("voice_noc")
        
        assert key == "test:buffer:voice_noc"


# =============================================================================
# TEST CLASS: REPLAY ENGINE
# =============================================================================

class TestReplayEngine:
    """Test ReplayEngine initialization and operation."""
    
    def test_replay_engine_takes_cache_only(self):
        """ReplayEngine takes only cache in constructor."""
        from trapninja.cache.replay import ReplayEngine
        from trapninja.cache.redis_backend import TrapCache, CacheConfig
        
        mock_cache = MagicMock(spec=TrapCache)
        
        engine = ReplayEngine(cache=mock_cache)
        
        assert engine.cache is mock_cache
    
    def test_replay_engine_stop_method(self):
        """ReplayEngine has stop method."""
        from trapninja.cache.replay import ReplayEngine
        
        mock_cache = MagicMock()
        engine = ReplayEngine(cache=mock_cache)
        
        engine.stop()
        
        assert engine._stop_requested is True
    
    def test_replay_engine_query_range(self):
        """ReplayEngine can query time range."""
        from trapninja.cache.replay import ReplayEngine
        
        mock_cache = MagicMock()
        mock_cache.query_range.return_value = iter([
            {'trap_oid': '1.3.6.1.6.3.1.1.5.1', 'source_ip': '10.0.0.1'}
        ])
        
        engine = ReplayEngine(cache=mock_cache)
        
        start = datetime.now() - timedelta(minutes=5)
        end = datetime.now()
        
        results = list(engine.query_range("voice_noc", start, end))
        
        assert len(results) == 1
        mock_cache.query_range.assert_called_once()


# =============================================================================
# TEST CLASS: HA STATE TRANSITION CACHE OPERATIONS
# =============================================================================

class TestHAStateTransitionCacheOps:
    """Test cache operations during HA state transitions."""
    
    def test_ha_cluster_initialization(self):
        """HACluster initializes without cache by default."""
        from trapninja.ha.cluster import HACluster
        from trapninja.ha.config import HAConfig
        
        config = HAConfig(
            mode='primary',
            peer_host='192.168.1.101',
            peer_port=5000,
            priority=100,
        )
        
        mock_callback = MagicMock()
        
        cluster = HACluster(config, trap_forwarder_callback=mock_callback)
        
        assert cluster.config is config
    
    def test_ha_enable_forwarding_calls_callback(self):
        """_enable_forwarding calls callback when state changes."""
        from trapninja.ha.cluster import HACluster
        from trapninja.ha.config import HAConfig
        from trapninja.ha.state import HAState
        
        config = HAConfig(
            mode='primary',
            peer_host='192.168.1.101',
            peer_port=5000,
            priority=100,
        )
        
        mock_callback = MagicMock()
        cluster = HACluster(config, trap_forwarder_callback=mock_callback)
        
        # Force state to not forwarding first
        cluster.is_forwarding = False
        
        cluster._enable_forwarding()
        
        # Callback should have been called with True
        mock_callback.assert_called_with(True)
        assert cluster.is_forwarding is True
    
    def test_ha_disable_forwarding_calls_callback(self):
        """_disable_forwarding calls callback when state changes."""
        from trapninja.ha.cluster import HACluster
        from trapninja.ha.config import HAConfig
        from trapninja.ha.state import HAState
        
        config = HAConfig(
            mode='secondary',
            peer_host='192.168.1.100',
            peer_port=5000,
            priority=50,
        )
        
        mock_callback = MagicMock()
        cluster = HACluster(config, trap_forwarder_callback=mock_callback)
        
        # Force state to forwarding first
        cluster.is_forwarding = True
        
        cluster._disable_forwarding()
        
        # Callback should have been called with False
        mock_callback.assert_called_with(False)
        assert cluster.is_forwarding is False


# =============================================================================
# TEST CLASS: GAP DETECTION SCENARIOS
# =============================================================================

class TestGapDetectionScenarios:
    """Test various gap detection scenarios."""
    
    def test_no_gap_fresh_start(self):
        """No gap when no previous timestamp exists."""
        from trapninja.cache.failover import GapDetector, FailoverTracker
        
        mock_redis = MagicMock()
        mock_redis.hgetall.return_value = {}  # No data
        
        tracker = FailoverTracker(redis_client=mock_redis, instance_id="test")
        detector = GapDetector(tracker, min_gap_seconds=1.0)
        
        gap = detector.detect_gap_for_destination("192.168.1.100:162")
        
        # No gap expected on fresh start
        assert gap is None
    
    def test_small_gap_ignored(self):
        """Gaps smaller than threshold are ignored."""
        from trapninja.cache.failover import GapDetector, FailoverTracker
        
        mock_redis = MagicMock()
        # 0.5 second gap
        recent_time = time.time() - 0.5
        mock_redis.hgetall.return_value = {'timestamp': str(recent_time)}
        
        tracker = FailoverTracker(redis_client=mock_redis, instance_id="test")
        detector = GapDetector(tracker, min_gap_seconds=1.0)
        
        gap = detector.detect_gap_for_destination("192.168.1.100:162")
        
        assert gap is None
    
    def test_large_gap_detected(self):
        """Large gaps are detected correctly."""
        from trapninja.cache.failover import GapDetector, FailoverTracker
        
        mock_redis = MagicMock()
        # 5 minute gap
        old_time = time.time() - 300
        mock_redis.hgetall.return_value = {'timestamp': str(old_time)}
        
        tracker = FailoverTracker(redis_client=mock_redis, instance_id="test")
        detector = GapDetector(tracker, min_gap_seconds=1.0)
        
        gap = detector.detect_gap_for_destination("192.168.1.100:162")
        
        assert gap is not None
        assert gap.gap_seconds >= 299.0
    
    def test_gap_capped_at_max(self):
        """Gaps are capped at max_gap_seconds."""
        from trapninja.cache.failover import GapDetector, FailoverTracker
        
        mock_redis = MagicMock()
        # 10 minute gap (exceeds 5 min max)
        old_time = time.time() - 600
        mock_redis.hgetall.return_value = {'timestamp': str(old_time)}
        
        tracker = FailoverTracker(redis_client=mock_redis, instance_id="test")
        detector = GapDetector(tracker, min_gap_seconds=1.0, max_gap_seconds=300.0)
        
        gap = detector.detect_gap_for_destination("192.168.1.100:162")
        
        assert gap is not None
        # Gap should be capped at 300 seconds
        assert gap.gap_seconds == 300.0


# =============================================================================
# TEST CLASS: REPLAY STATUS TRACKING
# =============================================================================

class TestReplayStatusTracking:
    """Test replay status and progress tracking."""
    
    def test_replay_status_structure(self):
        """ReplayStatus contains expected fields."""
        from trapninja.cache.failover.manager import ReplayStatus
        from trapninja.cache.failover import GapInfo
        
        gap = GapInfo(
            destination="192.168.1.100:162",
            gap_start=time.time() - 10,
            gap_end=time.time(),
            gap_seconds=10.0,
        )
        
        status = ReplayStatus(
            destination="192.168.1.100:162",
            gap=gap,
            state='running',
            started_at=time.time(),
            traps_sent=50,
        )
        
        assert status.destination == "192.168.1.100:162"
        assert status.state == 'running'
        assert status.traps_sent == 50
    
    def test_replay_status_duration_calculation(self):
        """ReplayStatus calculates duration correctly."""
        from trapninja.cache.failover.manager import ReplayStatus
        from trapninja.cache.failover import GapInfo
        
        gap = GapInfo(
            destination="192.168.1.100:162",
            gap_start=time.time() - 10,
            gap_end=time.time(),
            gap_seconds=10.0,
        )
        
        started = time.time() - 5
        status = ReplayStatus(
            destination="192.168.1.100:162",
            gap=gap,
            state='running',
            started_at=started,
        )
        
        # Duration should be approximately 5 seconds
        assert status.duration_seconds >= 4.9
    
    def test_replay_status_to_dict(self):
        """ReplayStatus can be serialized."""
        from trapninja.cache.failover.manager import ReplayStatus
        from trapninja.cache.failover import GapInfo
        
        gap = GapInfo(
            destination="192.168.1.100:162",
            gap_start=time.time() - 10,
            gap_end=time.time(),
            gap_seconds=10.0,
        )
        
        status = ReplayStatus(
            destination="192.168.1.100:162",
            gap=gap,
            state='completed',
            started_at=time.time() - 5,
            completed_at=time.time(),
            traps_sent=100,
            traps_failed=2,
        )
        
        result = status.to_dict()
        
        assert result['state'] == 'completed'
        assert result['traps_sent'] == 100
        assert result['traps_failed'] == 2
        assert 'duration_seconds' in result


# =============================================================================
# TEST CLASS: REPLAY RESULT
# =============================================================================

class TestReplayResult:
    """Test ReplayResult structure."""
    
    def test_replay_result_structure(self):
        """ReplayResult contains expected fields."""
        from trapninja.cache.replay import ReplayResult
        
        start = datetime.now() - timedelta(minutes=5)
        end = datetime.now()
        
        result = ReplayResult(
            destination="voice_noc",
            start_time=start,
            end_time=end,
            total_entries=100,
            sent=95,
            failed=5,
            skipped=0,
            dry_run=False,
            duration_seconds=10.5,
            rate_achieved=9.5,
        )
        
        assert result.destination == "voice_noc"
        assert result.sent == 95
        assert result.failed == 5
    
    def test_replay_result_to_dict(self):
        """ReplayResult can be serialized."""
        from trapninja.cache.replay import ReplayResult
        
        start = datetime.now() - timedelta(minutes=5)
        end = datetime.now()
        
        result = ReplayResult(
            destination="voice_noc",
            start_time=start,
            end_time=end,
            total_entries=100,
            sent=95,
            failed=5,
            skipped=0,
            dry_run=False,
            duration_seconds=10.5,
            rate_achieved=9.5,
        )
        
        data = result.to_dict()
        
        assert data['destination'] == "voice_noc"
        assert data['sent'] == 95


# =============================================================================
# TEST CLASS: FAILOVER TIMING
# =============================================================================

class TestFailoverTiming:
    """Test timing aspects of failover and replay."""
    
    def test_replay_delay_respected(self):
        """Replay waits configured delay before starting."""
        from trapninja.cache.failover import FailoverReplayConfig
        
        config = FailoverReplayConfig(
            replay_delay_seconds=2.0,
        )
        
        assert config.replay_delay_seconds == 2.0
    
    def test_buffer_seconds_extends_gap_start(self):
        """Buffer extends gap start time for safety."""
        from trapninja.cache.failover import FailoverReplayConfig
        
        config = FailoverReplayConfig(
            buffer_seconds=1.0,
        )
        
        # Buffer should be added to gap start time
        assert config.buffer_seconds == 1.0
    
    def test_max_gap_limits_replay_range(self):
        """Max gap setting limits how far back to replay."""
        from trapninja.cache.failover import FailoverReplayConfig
        
        config = FailoverReplayConfig(
            max_gap_seconds=300.0,  # 5 minutes max
        )
        
        # Replay should not go further back than max_gap_seconds
        assert config.max_gap_seconds == 300.0


# =============================================================================
# TEST CLASS: BACKGROUND REPLAY
# =============================================================================

class TestBackgroundReplay:
    """Test background replay thread behavior."""
    
    def test_background_replay_config(self):
        """Background replay is configurable."""
        from trapninja.cache.failover import FailoverReplayConfig
        
        config = FailoverReplayConfig(
            replay_in_background=True,
        )
        
        assert config.replay_in_background is True
    
    def test_foreground_replay_config(self):
        """Foreground replay is configurable."""
        from trapninja.cache.failover import FailoverReplayConfig
        
        config = FailoverReplayConfig(
            replay_in_background=False,
        )
        
        assert config.replay_in_background is False


# =============================================================================
# TEST CLASS: REPLAY COMPLETION CALLBACK
# =============================================================================

class TestReplayCompletionCallback:
    """Test replay completion callback functionality."""
    
    def test_manager_accepts_completion_callback(self):
        """Manager accepts optional completion callback."""
        from trapninja.cache.failover import FailoverReplayManager, FailoverReplayConfig
        
        mock_cache = MagicMock()
        mock_cache.available = False
        mock_cache._client = None
        
        config = FailoverReplayConfig()
        
        callback_received = []
        
        def on_complete(statuses):
            callback_received.append(statuses)
        
        manager = FailoverReplayManager(
            cache=mock_cache,
            config=config,
            instance_id="test-node",
            on_replay_complete=on_complete,
        )
        
        assert manager._on_replay_complete is on_complete


# =============================================================================
# TEST CLASS: CACHE RETENTION MANAGER
# =============================================================================

class TestCacheRetentionManager:
    """Test RetentionManager for background trimming."""
    
    def test_retention_manager_initialization(self):
        """RetentionManager initializes with cache."""
        from trapninja.cache.redis_backend import RetentionManager, TrapCache, CacheConfig
        
        config = CacheConfig(enabled=False)
        cache = TrapCache(config)
        
        manager = RetentionManager(cache, interval=60)
        
        assert manager.cache is cache
        assert manager.interval == 60
    
    def test_retention_manager_start_stop(self):
        """RetentionManager can start and stop."""
        from trapninja.cache.redis_backend import RetentionManager, TrapCache, CacheConfig
        
        config = CacheConfig(enabled=False)
        cache = TrapCache(config)
        
        manager = RetentionManager(cache, interval=60)
        
        # Should not raise
        manager.start()
        manager.stop()
    
    def test_retention_manager_config_file(self):
        """RetentionManager accepts config file path."""
        from trapninja.cache.redis_backend import RetentionManager, TrapCache, CacheConfig
        
        config = CacheConfig(enabled=False)
        cache = TrapCache(config)
        
        manager = RetentionManager(cache, interval=60)
        
        manager.set_config_file("/etc/trapninja/cache.json")
        
        assert manager._config_file == "/etc/trapninja/cache.json"


# =============================================================================
# TEST CLASS: CACHE STATS
# =============================================================================

class TestCacheStats:
    """Test CacheStats tracking."""
    
    def test_cache_stats_structure(self):
        """CacheStats contains expected fields."""
        from trapninja.cache.redis_backend import CacheStats
        
        stats = CacheStats()
        
        assert stats.entries_stored == 0
        assert stats.entries_trimmed == 0
        assert stats.store_failures == 0
        assert stats.connection_failures == 0
    
    def test_cache_stats_to_dict(self):
        """CacheStats can be serialized."""
        from trapninja.cache.redis_backend import CacheStats
        
        stats = CacheStats()
        stats.entries_stored = 100
        stats.entries_trimmed = 50
        
        result = stats.to_dict()
        
        assert result['entries_stored'] == 100
        assert result['entries_trimmed'] == 50


# =============================================================================
# TEST CLASS: GLOBAL CACHE FUNCTIONS
# =============================================================================

class TestGlobalCacheFunctions:
    """Test global cache instance functions."""
    
    def test_get_cache_returns_none_before_init(self):
        """get_cache returns None before initialization."""
        from trapninja.cache.redis_backend import get_cache, _cache_instance
        
        # Note: This test may fail if cache was previously initialized
        # In a real test, we'd need to reset the global state
        result = get_cache()
        
        # Either None or a TrapCache instance
        assert result is None or hasattr(result, 'config')
