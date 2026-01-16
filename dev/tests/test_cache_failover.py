#!/usr/bin/env python3
"""
TrapNinja Test Suite - Cache Failover Tests

Tests for trapninja.cache.failover module - failover replay management.

Author: TrapNinja Team
"""

import time
import threading
import pytest
from unittest.mock import patch, MagicMock, PropertyMock
from datetime import datetime, timedelta


# =============================================================================
# Tests for FailoverTracker
# =============================================================================

class TestFailoverTrackerInit:
    """Tests for FailoverTracker initialization."""

    def test_initialization(self):
        """Test FailoverTracker initialization."""
        from trapninja.cache.failover.tracker import FailoverTracker
        
        mock_redis = MagicMock()
        tracker = FailoverTracker(mock_redis, "instance-123")
        
        assert tracker.instance_id == "instance-123"

    def test_instance_id_property(self):
        """Test instance_id property."""
        from trapninja.cache.failover.tracker import FailoverTracker
        
        mock_redis = MagicMock()
        tracker = FailoverTracker(mock_redis, "test-id")
        
        assert tracker.instance_id == "test-id"


class TestFailoverTrackerTimestamp:
    """Tests for FailoverTracker timestamp operations."""

    def test_update_last_forwarded(self):
        """Test update_last_forwarded batches or flushes updates."""
        from trapninja.cache.failover.tracker import FailoverTracker
        
        mock_redis = MagicMock()
        mock_pipe = MagicMock()
        mock_redis.pipeline.return_value = mock_pipe
        
        tracker = FailoverTracker(mock_redis, "instance-123")
        
        # Set last batch time to now so it won't flush immediately
        tracker._last_batch_time = time.time()
        
        # Update should be batched (not flushed yet)
        tracker.update_last_forwarded("dest1", 1000.0)
        
        # Check it's in the buffer
        assert "dest1" in tracker._batch_buffer

    def test_flush_writes_to_redis(self):
        """Test flush writes batched updates to Redis."""
        from trapninja.cache.failover.tracker import FailoverTracker
        
        mock_redis = MagicMock()
        mock_pipe = MagicMock()
        mock_redis.pipeline.return_value = mock_pipe
        
        tracker = FailoverTracker(mock_redis, "instance-123")
        tracker._batch_buffer["dest1"] = 1000.0
        
        tracker.flush()
        
        mock_redis.pipeline.assert_called()
        mock_pipe.execute.assert_called()
        assert len(tracker._batch_buffer) == 0

    def test_get_last_forwarded(self):
        """Test get_last_forwarded returns timestamp."""
        from trapninja.cache.failover.tracker import FailoverTracker
        
        mock_redis = MagicMock()
        mock_redis.hgetall.return_value = {'timestamp': '1000.5'}
        
        tracker = FailoverTracker(mock_redis, "instance-123")
        
        result = tracker.get_last_forwarded("dest1")
        
        assert result == 1000.5

    def test_get_last_forwarded_not_found(self):
        """Test get_last_forwarded returns None when not found."""
        from trapninja.cache.failover.tracker import FailoverTracker
        
        mock_redis = MagicMock()
        mock_redis.hgetall.return_value = {}
        
        tracker = FailoverTracker(mock_redis, "instance-123")
        
        result = tracker.get_last_forwarded("unknown")
        
        assert result is None

    def test_get_all_last_forwarded(self):
        """Test get_all_last_forwarded returns dict."""
        from trapninja.cache.failover.tracker import FailoverTracker
        
        mock_redis = MagicMock()
        mock_redis.keys.return_value = [
            "trapninja:failover:last_forwarded:dest1",
            "trapninja:failover:last_forwarded:dest2"
        ]
        mock_pipe = MagicMock()
        mock_pipe.execute.return_value = [
            {'timestamp': '1000.0'},
            {'timestamp': '2000.0'}
        ]
        mock_redis.pipeline.return_value = mock_pipe
        
        tracker = FailoverTracker(mock_redis, "instance-123")
        
        result = tracker.get_all_last_forwarded()
        
        assert len(result) == 2


class TestFailoverTrackerActiveNode:
    """Tests for FailoverTracker active node management."""

    def test_set_active_node_true(self):
        """Test setting active node to true."""
        from trapninja.cache.failover.tracker import FailoverTracker
        
        mock_redis = MagicMock()
        tracker = FailoverTracker(mock_redis, "instance-123")
        
        tracker.set_active_node(True)
        
        mock_redis.setex.assert_called()

    def test_set_active_node_false(self):
        """Test clearing active node."""
        from trapninja.cache.failover.tracker import FailoverTracker
        
        mock_redis = MagicMock()
        mock_redis.get.return_value = "instance-123"
        tracker = FailoverTracker(mock_redis, "instance-123")
        
        tracker.set_active_node(False)
        
        mock_redis.delete.assert_called()

    def test_get_active_node(self):
        """Test getting active node."""
        from trapninja.cache.failover.tracker import FailoverTracker
        
        mock_redis = MagicMock()
        mock_redis.get.return_value = "active-instance"
        tracker = FailoverTracker(mock_redis, "instance-123")
        
        result = tracker.get_active_node()
        
        assert result == "active-instance"


class TestFailoverTrackerStats:
    """Tests for FailoverTracker statistics."""

    def test_record_forwarding_stat(self):
        """Test recording forwarding statistics."""
        from trapninja.cache.failover.tracker import FailoverTracker
        
        mock_redis = MagicMock()
        mock_pipe = MagicMock()
        mock_redis.pipeline.return_value = mock_pipe
        
        tracker = FailoverTracker(mock_redis, "instance-123")
        
        tracker.record_forwarding_stat("dest1", 10)
        
        mock_redis.pipeline.assert_called()

    def test_get_forwarding_rate(self):
        """Test getting forwarding rate."""
        from trapninja.cache.failover.tracker import FailoverTracker
        
        mock_redis = MagicMock()
        mock_redis.get.return_value = "100"
        
        tracker = FailoverTracker(mock_redis, "instance-123")
        
        rate = tracker.get_forwarding_rate("dest1", window_seconds=60)
        
        assert rate >= 0

    def test_get_status(self):
        """Test get_status returns status dict."""
        from trapninja.cache.failover.tracker import FailoverTracker
        
        mock_redis = MagicMock()
        mock_redis.keys.return_value = []
        mock_redis.get.return_value = None
        
        tracker = FailoverTracker(mock_redis, "instance-123")
        
        status = tracker.get_status()
        
        assert 'instance_id' in status
        assert status['instance_id'] == "instance-123"


# =============================================================================
# Tests for GapInfo
# =============================================================================

class TestGapInfo:
    """Tests for GapInfo dataclass."""

    def test_initialization(self):
        """Test GapInfo initialization."""
        from trapninja.cache.failover.detector import GapInfo
        
        gap = GapInfo(
            destination="voice_noc",
            gap_start=1000.0,
            gap_end=1005.0,
            gap_seconds=5.0
        )
        
        assert gap.destination == "voice_noc"
        assert gap.gap_seconds == 5.0

    def test_start_datetime(self):
        """Test start_datetime property."""
        from trapninja.cache.failover.detector import GapInfo
        
        ts = datetime(2024, 1, 1, 12, 0, 0).timestamp()
        gap = GapInfo(
            destination="test",
            gap_start=ts,
            gap_end=ts + 5,
            gap_seconds=5.0
        )
        
        result = gap.start_datetime
        
        assert isinstance(result, datetime)

    def test_to_dict(self):
        """Test GapInfo to_dict serialization."""
        from trapninja.cache.failover.detector import GapInfo
        
        gap = GapInfo(
            destination="test",
            gap_start=1000.0,
            gap_end=1005.0,
            gap_seconds=5.0,
            estimated_traps=100
        )
        
        result = gap.to_dict()
        
        assert result['destination'] == "test"
        assert result['gap_seconds'] == 5.0
        assert result['estimated_traps'] == 100

    def test_str(self):
        """Test GapInfo string representation."""
        from trapninja.cache.failover.detector import GapInfo
        
        gap = GapInfo(
            destination="test",
            gap_start=1000.0,
            gap_end=1005.0,
            gap_seconds=5.0
        )
        
        result = str(gap)
        
        assert "test" in result
        assert "5.0s" in result


# =============================================================================
# Tests for GapDetector
# =============================================================================

class TestGapDetectorInit:
    """Tests for GapDetector initialization."""

    def test_initialization(self):
        """Test GapDetector initialization."""
        from trapninja.cache.failover.detector import GapDetector
        
        mock_tracker = MagicMock()
        
        detector = GapDetector(
            mock_tracker,
            min_gap_seconds=2.0,
            max_gap_seconds=600.0
        )
        
        assert detector.min_gap_seconds == 2.0
        assert detector.max_gap_seconds == 600.0


class TestGapDetectorDetection:
    """Tests for GapDetector gap detection."""

    def test_detect_gaps_no_timestamps(self):
        """Test detect_gaps with no timestamps returns empty list."""
        from trapninja.cache.failover.detector import GapDetector
        
        mock_tracker = MagicMock()
        mock_tracker.get_all_last_forwarded.return_value = {}
        
        detector = GapDetector(mock_tracker)
        
        gaps = detector.detect_gaps()
        
        assert gaps == []

    def test_detect_gaps_below_threshold(self):
        """Test detect_gaps ignores gaps below threshold."""
        from trapninja.cache.failover.detector import GapDetector
        
        mock_tracker = MagicMock()
        # Gap of 0.5 seconds (below default 1.0s threshold)
        mock_tracker.get_all_last_forwarded.return_value = {
            'dest1': time.time() - 0.5
        }
        mock_tracker.get_forwarding_info.return_value = None
        
        detector = GapDetector(mock_tracker, min_gap_seconds=1.0)
        
        gaps = detector.detect_gaps()
        
        assert len(gaps) == 0

    def test_detect_gaps_valid_gap(self):
        """Test detect_gaps finds valid gap."""
        from trapninja.cache.failover.detector import GapDetector
        
        mock_tracker = MagicMock()
        # Gap of 5 seconds
        mock_tracker.get_all_last_forwarded.return_value = {
            'dest1': time.time() - 5.0
        }
        mock_tracker.get_forwarding_info.return_value = {'node_id': 'node1'}
        
        detector = GapDetector(mock_tracker, min_gap_seconds=1.0)
        
        gaps = detector.detect_gaps()
        
        assert len(gaps) == 1
        assert gaps[0].destination == 'dest1'
        assert gaps[0].gap_seconds >= 4.0  # Allow for timing

    def test_detect_gaps_capped_at_max(self):
        """Test detect_gaps caps gap at maximum."""
        from trapninja.cache.failover.detector import GapDetector
        
        mock_tracker = MagicMock()
        # Gap of 600 seconds (exceeds 300s max)
        mock_tracker.get_all_last_forwarded.return_value = {
            'dest1': time.time() - 600.0
        }
        mock_tracker.get_forwarding_info.return_value = None
        
        detector = GapDetector(mock_tracker, max_gap_seconds=300.0)
        
        gaps = detector.detect_gaps()
        
        assert len(gaps) == 1
        assert gaps[0].gap_seconds == 300.0  # Capped

    def test_detect_gap_for_destination(self):
        """Test detect_gap_for_destination."""
        from trapninja.cache.failover.detector import GapDetector
        
        mock_tracker = MagicMock()
        mock_tracker.get_last_forwarded.return_value = time.time() - 10.0
        mock_tracker.get_forwarding_info.return_value = None
        
        detector = GapDetector(mock_tracker)
        
        gap = detector.detect_gap_for_destination("dest1")
        
        assert gap is not None
        assert gap.destination == "dest1"


class TestGapDetectorGlobalGap:
    """Tests for GapDetector get_global_gap method."""

    def test_get_global_gap(self):
        """Test get_global_gap returns global gap."""
        from trapninja.cache.failover.detector import GapDetector
        
        mock_tracker = MagicMock()
        now = time.time()
        mock_tracker.get_all_last_forwarded.return_value = {
            'dest1': now - 10.0,
            'dest2': now - 5.0
        }
        
        detector = GapDetector(mock_tracker)
        
        gap = detector.get_global_gap()
        
        assert gap is not None
        assert gap.destination == "*"

    def test_get_global_gap_no_timestamps(self):
        """Test get_global_gap with no timestamps."""
        from trapninja.cache.failover.detector import GapDetector
        
        mock_tracker = MagicMock()
        mock_tracker.get_all_last_forwarded.return_value = {}
        
        detector = GapDetector(mock_tracker)
        
        gap = detector.get_global_gap()
        
        assert gap is None


class TestGapDetectorReplayEstimate:
    """Tests for GapDetector estimate_replay_time method."""

    def test_estimate_replay_time(self):
        """Test estimate_replay_time calculation."""
        from trapninja.cache.failover.detector import GapDetector, GapInfo
        
        mock_tracker = MagicMock()
        detector = GapDetector(mock_tracker)
        
        gaps = [
            GapInfo("dest1", 1000, 1005, 5.0, estimated_traps=500),
            GapInfo("dest2", 1000, 1005, 5.0, estimated_traps=500),
        ]
        
        estimate = detector.estimate_replay_time(gaps, rate_limit=1000)
        
        # 1000 traps at 1000/s = 1.0 second
        assert estimate == 1.0

    def test_estimate_replay_time_zero_rate(self):
        """Test estimate_replay_time with zero rate limit."""
        from trapninja.cache.failover.detector import GapDetector, GapInfo
        
        mock_tracker = MagicMock()
        detector = GapDetector(mock_tracker)
        
        gaps = [GapInfo("dest1", 1000, 1005, 5.0, estimated_traps=100)]
        
        estimate = detector.estimate_replay_time(gaps, rate_limit=0)
        
        assert estimate == 0.0


# =============================================================================
# Tests for FailoverReplayConfig
# =============================================================================

class TestFailoverReplayConfig:
    """Tests for FailoverReplayConfig dataclass."""

    def test_default_values(self):
        """Test default configuration values."""
        from trapninja.cache.failover.manager import FailoverReplayConfig
        
        config = FailoverReplayConfig()
        
        assert config.enabled is True
        assert config.min_gap_seconds == 1.0
        assert config.max_gap_seconds == 300.0
        assert config.replay_rate_limit == 2000

    def test_from_dict(self):
        """Test from_dict creates config."""
        from trapninja.cache.failover.manager import FailoverReplayConfig
        
        data = {
            'enabled': False,
            'min_gap_seconds': 2.0,
            'replay_rate_limit': 1000
        }
        
        config = FailoverReplayConfig.from_dict(data)
        
        assert config.enabled is False
        assert config.min_gap_seconds == 2.0
        assert config.replay_rate_limit == 1000

    def test_to_dict(self):
        """Test to_dict serialization."""
        from trapninja.cache.failover.manager import FailoverReplayConfig
        
        config = FailoverReplayConfig(enabled=True, min_gap_seconds=3.0)
        
        result = config.to_dict()
        
        assert result['enabled'] is True
        assert result['min_gap_seconds'] == 3.0


# =============================================================================
# Tests for ReplayStatus
# =============================================================================

class TestReplayStatus:
    """Tests for ReplayStatus dataclass."""

    def test_initialization(self):
        """Test ReplayStatus initialization."""
        from trapninja.cache.failover.manager import ReplayStatus
        from trapninja.cache.failover.detector import GapInfo
        
        gap = GapInfo("dest", 1000, 1005, 5.0)
        status = ReplayStatus(
            destination="dest",
            gap=gap,
            state="completed",
            traps_sent=100
        )
        
        assert status.destination == "dest"
        assert status.state == "completed"
        assert status.traps_sent == 100

    def test_duration_seconds(self):
        """Test duration_seconds property."""
        from trapninja.cache.failover.manager import ReplayStatus
        from trapninja.cache.failover.detector import GapInfo
        
        gap = GapInfo("dest", 1000, 1005, 5.0)
        status = ReplayStatus(
            destination="dest",
            gap=gap,
            state="completed",
            started_at=time.time() - 10.0,
            completed_at=time.time()
        )
        
        assert 9.5 <= status.duration_seconds <= 10.5

    def test_to_dict(self):
        """Test to_dict serialization."""
        from trapninja.cache.failover.manager import ReplayStatus
        from trapninja.cache.failover.detector import GapInfo
        
        gap = GapInfo("dest", 1000, 1005, 5.0)
        status = ReplayStatus(
            destination="dest",
            gap=gap,
            state="completed",
            traps_sent=50,
            traps_failed=5
        )
        
        result = status.to_dict()
        
        assert result['destination'] == "dest"
        assert result['state'] == "completed"
        assert result['traps_sent'] == 50


# =============================================================================
# Tests for FailoverReplayManager
# =============================================================================

class TestFailoverReplayManagerInit:
    """Tests for FailoverReplayManager initialization."""

    def test_initialization(self):
        """Test FailoverReplayManager initialization."""
        from trapninja.cache.failover.manager import FailoverReplayManager
        
        mock_cache = MagicMock()
        mock_cache.available = False
        
        manager = FailoverReplayManager(mock_cache)
        
        assert manager._cache == mock_cache
        assert manager._is_primary is False

    def test_available_when_disabled(self):
        """Test available is False when disabled."""
        from trapninja.cache.failover.manager import (
            FailoverReplayManager, FailoverReplayConfig
        )
        
        mock_cache = MagicMock()
        mock_cache.available = True
        
        config = FailoverReplayConfig(enabled=False)
        manager = FailoverReplayManager(mock_cache, config)
        
        # Even with components, disabled = not available
        assert manager.available is False


class TestFailoverReplayManagerOperations:
    """Tests for FailoverReplayManager operations."""

    def test_update_last_forwarded_when_not_primary(self):
        """Test update_last_forwarded is no-op when not primary."""
        from trapninja.cache.failover.manager import FailoverReplayManager
        
        mock_cache = MagicMock()
        mock_cache.available = False
        
        manager = FailoverReplayManager(mock_cache)
        
        # Should not raise
        manager.update_last_forwarded("dest1")

    def test_on_become_secondary(self):
        """Test on_become_secondary clears primary flag."""
        from trapninja.cache.failover.manager import FailoverReplayManager
        
        mock_cache = MagicMock()
        mock_cache.available = False
        
        manager = FailoverReplayManager(mock_cache)
        manager._is_primary = True
        
        manager.on_become_secondary()
        
        assert manager._is_primary is False

    def test_get_status(self):
        """Test get_status returns status dict."""
        from trapninja.cache.failover.manager import FailoverReplayManager
        
        mock_cache = MagicMock()
        mock_cache.available = False
        
        manager = FailoverReplayManager(mock_cache, instance_id="test-id")
        
        status = manager.get_status()
        
        assert 'enabled' in status
        assert 'available' in status
        assert status['instance_id'] == "test-id"

    def test_shutdown(self):
        """Test shutdown cleans up resources."""
        from trapninja.cache.failover.manager import FailoverReplayManager
        
        mock_cache = MagicMock()
        mock_cache.available = False
        
        manager = FailoverReplayManager(mock_cache)
        
        # Should not raise
        manager.shutdown()
        
        assert manager._stop_event.is_set()
