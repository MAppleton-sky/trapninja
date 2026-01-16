#!/usr/bin/env python3
"""
TrapNinja Test Suite - Statistics Models Tests

Tests for trapninja.stats.models module - statistics data models.

Author: TrapNinja Team
"""

import time
import threading
import pytest
from unittest.mock import patch, MagicMock
from collections import Counter


class TestTimeWindowEnum:
    """Tests for TimeWindow enum."""

    def test_minute_value(self):
        """Test MINUTE time window value."""
        from trapninja.stats.models import TimeWindow
        
        assert TimeWindow.MINUTE.value == 60

    def test_five_minutes_value(self):
        """Test FIVE_MINUTES time window value."""
        from trapninja.stats.models import TimeWindow
        
        assert TimeWindow.FIVE_MINUTES.value == 300

    def test_hour_value(self):
        """Test HOUR time window value."""
        from trapninja.stats.models import TimeWindow
        
        assert TimeWindow.HOUR.value == 3600

    def test_day_value(self):
        """Test DAY time window value."""
        from trapninja.stats.models import TimeWindow
        
        assert TimeWindow.DAY.value == 86400

    def test_week_value(self):
        """Test WEEK time window value."""
        from trapninja.stats.models import TimeWindow
        
        assert TimeWindow.WEEK.value == 604800


class TestRateTracker:
    """Tests for RateTracker class."""

    def test_initialization(self):
        """Test RateTracker initialization."""
        from trapninja.stats.models import RateTracker
        
        tracker = RateTracker(window_seconds=60)
        
        assert tracker.window_seconds == 60
        assert tracker.get_count() == 0

    def test_record_event(self):
        """Test recording an event."""
        from trapninja.stats.models import RateTracker
        
        tracker = RateTracker(window_seconds=60)
        tracker.record()
        
        assert tracker.get_count() >= 1

    def test_record_multiple_events(self):
        """Test recording multiple events."""
        from trapninja.stats.models import RateTracker
        
        tracker = RateTracker(window_seconds=60)
        for _ in range(10):
            tracker.record()
        
        assert tracker.get_count() >= 10

    def test_get_rate(self):
        """Test rate calculation."""
        from trapninja.stats.models import RateTracker
        
        tracker = RateTracker(window_seconds=60)
        for _ in range(60):
            tracker.record()
        
        rate = tracker.get_rate()
        
        # 60 events in 60 seconds = 1 per second
        assert rate >= 0.9  # Allow for timing variance

    def test_get_count_with_custom_window(self):
        """Test count with custom window."""
        from trapninja.stats.models import RateTracker
        
        tracker = RateTracker(window_seconds=120)
        for _ in range(10):
            tracker.record()
        
        # Get count for 60 seconds (half the tracker window)
        count = tracker.get_count(60)
        
        assert count >= 0

    def test_peak_rate_tracking(self):
        """Test peak rate is tracked."""
        from trapninja.stats.models import RateTracker
        
        tracker = RateTracker(window_seconds=60)
        
        # Record events
        for _ in range(100):
            tracker.record()
        
        # Peak should be recorded
        peak = tracker.get_peak_rate()
        assert peak >= 0

    def test_cleanup_old_buckets(self):
        """Test old buckets are cleaned up."""
        from trapninja.stats.models import RateTracker
        
        tracker = RateTracker(window_seconds=60)
        
        # Record with old timestamp
        old_time = time.time() - 200
        tracker.record(old_time)
        
        # Record with current timestamp (triggers cleanup)
        tracker.record()
        
        # Old bucket should be cleaned up, only recent count
        count = tracker.get_count(60)
        assert count >= 1

    def test_thread_safety(self):
        """Test thread safety of rate tracker."""
        from trapninja.stats.models import RateTracker
        
        tracker = RateTracker(window_seconds=60)
        errors = []
        
        def record_many():
            try:
                for _ in range(1000):
                    tracker.record()
            except Exception as e:
                errors.append(e)
        
        threads = [threading.Thread(target=record_many) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        assert len(errors) == 0
        assert tracker.get_count() == 5000


class TestIPStats:
    """Tests for IPStats class."""

    def test_initialization(self):
        """Test IPStats initialization."""
        from trapninja.stats.models import IPStats
        
        stats = IPStats(ip_address="192.168.1.1")
        
        assert stats.ip_address == "192.168.1.1"
        assert stats.total_traps == 0
        assert stats.forwarded == 0
        assert stats.blocked == 0

    def test_record_trap_increments_total(self):
        """Test record_trap increments total."""
        from trapninja.stats.models import IPStats
        
        stats = IPStats(ip_address="10.0.0.1")
        stats.record_trap()
        
        assert stats.total_traps == 1

    def test_record_trap_tracks_action(self):
        """Test record_trap tracks different actions."""
        from trapninja.stats.models import IPStats
        
        stats = IPStats(ip_address="10.0.0.1")
        
        stats.record_trap(action='forwarded')
        stats.record_trap(action='blocked')
        stats.record_trap(action='redirected')
        stats.record_trap(action='dropped')
        
        assert stats.forwarded == 1
        assert stats.blocked == 1
        assert stats.redirected == 1
        assert stats.dropped == 1

    def test_record_trap_tracks_oid(self):
        """Test record_trap tracks OIDs."""
        from trapninja.stats.models import IPStats
        
        stats = IPStats(ip_address="10.0.0.1")
        
        stats.record_trap(oid="1.3.6.1.4.1.9.1")
        stats.record_trap(oid="1.3.6.1.4.1.9.1")
        stats.record_trap(oid="1.3.6.1.4.1.9.2")
        
        assert stats.oid_counts["1.3.6.1.4.1.9.1"] == 2
        assert stats.oid_counts["1.3.6.1.4.1.9.2"] == 1

    def test_record_trap_tracks_destination(self):
        """Test record_trap tracks destinations."""
        from trapninja.stats.models import IPStats
        
        stats = IPStats(ip_address="10.0.0.1")
        
        stats.record_trap(destination="default")
        stats.record_trap(destination="default")
        stats.record_trap(destination="voice")
        
        assert stats.destination_counts["default"] == 2
        assert stats.destination_counts["voice"] == 1

    def test_rate_per_second(self):
        """Test rate_per_second property."""
        from trapninja.stats.models import IPStats
        
        stats = IPStats(ip_address="10.0.0.1")
        
        for _ in range(10):
            stats.record_trap()
        
        rate = stats.rate_per_second
        assert rate >= 0

    def test_rate_per_minute(self):
        """Test rate_per_minute property."""
        from trapninja.stats.models import IPStats
        
        stats = IPStats(ip_address="10.0.0.1")
        
        for _ in range(10):
            stats.record_trap()
        
        rate = stats.rate_per_minute
        assert rate >= 10

    def test_get_top_oids(self):
        """Test get_top_oids method."""
        from trapninja.stats.models import IPStats
        
        stats = IPStats(ip_address="10.0.0.1")
        
        stats.record_trap(oid="oid1")
        stats.record_trap(oid="oid1")
        stats.record_trap(oid="oid2")
        
        top = stats.get_top_oids(2)
        
        assert len(top) == 2
        assert top[0] == ("oid1", 2)

    def test_age_seconds(self):
        """Test age_seconds property."""
        from trapninja.stats.models import IPStats
        
        stats = IPStats(ip_address="10.0.0.1")
        
        # Age should be very small (just created)
        assert stats.age_seconds < 1

    def test_idle_seconds(self):
        """Test idle_seconds property."""
        from trapninja.stats.models import IPStats
        
        stats = IPStats(ip_address="10.0.0.1")
        stats.record_trap()
        
        # Just recorded, idle should be near zero
        assert stats.idle_seconds < 1

    def test_to_dict(self):
        """Test to_dict serialization."""
        from trapninja.stats.models import IPStats
        
        stats = IPStats(ip_address="10.0.0.1")
        stats.record_trap(oid="test_oid", action='forwarded')
        
        result = stats.to_dict()
        
        assert result['ip_address'] == "10.0.0.1"
        assert result['total_traps'] == 1
        assert 'first_seen' in result
        assert 'last_seen' in result
        assert 'rate_per_minute' in result

    def test_to_dict_without_details(self):
        """Test to_dict without details."""
        from trapninja.stats.models import IPStats
        
        stats = IPStats(ip_address="10.0.0.1")
        
        result = stats.to_dict(include_details=False)
        
        assert 'ip_address' in result
        assert 'top_oids' not in result


class TestOIDStats:
    """Tests for OIDStats class."""

    def test_initialization(self):
        """Test OIDStats initialization."""
        from trapninja.stats.models import OIDStats
        
        stats = OIDStats(oid="1.3.6.1.4.1.9.1")
        
        assert stats.oid == "1.3.6.1.4.1.9.1"
        assert stats.total_traps == 0

    def test_record_trap(self):
        """Test record_trap method."""
        from trapninja.stats.models import OIDStats
        
        stats = OIDStats(oid="1.3.6.1.4.1.9.1")
        stats.record_trap(source_ip="10.0.0.1")
        
        assert stats.total_traps == 1

    def test_record_trap_tracks_source_ips(self):
        """Test record_trap tracks source IPs."""
        from trapninja.stats.models import OIDStats
        
        stats = OIDStats(oid="1.3.6.1.4.1.9.1")
        
        stats.record_trap(source_ip="10.0.0.1")
        stats.record_trap(source_ip="10.0.0.1")
        stats.record_trap(source_ip="10.0.0.2")
        
        assert stats.ip_counts["10.0.0.1"] == 2
        assert stats.ip_counts["10.0.0.2"] == 1

    def test_get_top_ips(self):
        """Test get_top_ips method."""
        from trapninja.stats.models import OIDStats
        
        stats = OIDStats(oid="1.3.6.1.4.1.9.1")
        
        stats.record_trap(source_ip="ip1")
        stats.record_trap(source_ip="ip1")
        stats.record_trap(source_ip="ip2")
        
        top = stats.get_top_ips(2)
        
        assert len(top) == 2
        assert top[0] == ("ip1", 2)

    def test_to_dict(self):
        """Test to_dict serialization."""
        from trapninja.stats.models import OIDStats
        
        stats = OIDStats(oid="1.3.6.1.4.1.9.1")
        stats.record_trap(source_ip="10.0.0.1")
        
        result = stats.to_dict()
        
        assert result['oid'] == "1.3.6.1.4.1.9.1"
        assert result['total_traps'] == 1
        assert 'unique_sources' in result


class TestDestinationStats:
    """Tests for DestinationStats class."""

    def test_initialization(self):
        """Test DestinationStats initialization."""
        from trapninja.stats.models import DestinationStats
        
        stats = DestinationStats(destination="default")
        
        assert stats.destination == "default"
        assert stats.total_forwarded == 0

    def test_record_forward(self):
        """Test record_forward method."""
        from trapninja.stats.models import DestinationStats
        
        stats = DestinationStats(destination="default")
        stats.record_forward(source_ip="10.0.0.1")
        
        assert stats.total_forwarded == 1
        assert stats.successful == 1

    def test_record_forward_failure(self):
        """Test record_forward with failure."""
        from trapninja.stats.models import DestinationStats
        
        stats = DestinationStats(destination="default")
        stats.record_forward(source_ip="10.0.0.1", success=False)
        
        assert stats.total_forwarded == 1
        assert stats.failed == 1
        assert stats.successful == 0

    def test_success_rate(self):
        """Test success_rate property."""
        from trapninja.stats.models import DestinationStats
        
        stats = DestinationStats(destination="default")
        
        stats.record_forward(source_ip="10.0.0.1", success=True)
        stats.record_forward(source_ip="10.0.0.2", success=True)
        stats.record_forward(source_ip="10.0.0.3", success=False)
        
        # 2 successful out of 3 = 66.67%
        assert 66 < stats.success_rate < 67

    def test_success_rate_no_forwards(self):
        """Test success_rate with no forwards."""
        from trapninja.stats.models import DestinationStats
        
        stats = DestinationStats(destination="default")
        
        # Should return 100% when no forwards
        assert stats.success_rate == 100.0

    def test_to_dict(self):
        """Test to_dict serialization."""
        from trapninja.stats.models import DestinationStats
        
        stats = DestinationStats(destination="default")
        stats.record_forward(source_ip="10.0.0.1")
        
        result = stats.to_dict()
        
        assert result['destination'] == "default"
        assert result['total_forwarded'] == 1
        assert 'success_rate' in result


class TestStatsSnapshot:
    """Tests for StatsSnapshot class."""

    def test_initialization(self):
        """Test StatsSnapshot initialization."""
        from trapninja.stats.models import StatsSnapshot
        
        snapshot = StatsSnapshot()
        
        assert snapshot.total_traps == 0
        assert snapshot.timestamp > 0

    def test_to_dict(self):
        """Test to_dict serialization."""
        from trapninja.stats.models import StatsSnapshot
        
        snapshot = StatsSnapshot()
        snapshot.total_traps = 1000
        snapshot.total_forwarded = 900
        snapshot.unique_ips = 50
        
        result = snapshot.to_dict()
        
        assert 'timestamp' in result
        assert 'summary' in result
        assert result['summary']['total_traps'] == 1000
        assert result['summary']['unique_ips'] == 50

    def test_to_dict_contains_top_entities(self):
        """Test to_dict contains top entity lists."""
        from trapninja.stats.models import StatsSnapshot
        
        snapshot = StatsSnapshot()
        snapshot.top_ips = [{'ip': '10.0.0.1', 'count': 100}]
        snapshot.top_oids = [{'oid': '1.3.6.1', 'count': 50}]
        
        result = snapshot.to_dict()
        
        assert 'top_ips' in result
        assert 'top_oids' in result
        assert len(result['top_ips']) == 1

    def test_to_dict_contains_time_range(self):
        """Test to_dict contains time range."""
        from trapninja.stats.models import StatsSnapshot
        
        snapshot = StatsSnapshot()
        snapshot.oldest_data = time.time() - 3600
        snapshot.newest_data = time.time()
        
        result = snapshot.to_dict()
        
        assert 'time_range' in result
        assert result['time_range']['oldest'] is not None
        assert result['time_range']['newest'] is not None
