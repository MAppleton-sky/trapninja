#!/usr/bin/env python3
"""
Tests for TrapNinja Sliding Window Metrics

Covers:
  - SlidingWindowCounter basic behaviour and thread safety
  - ProcessingStats sliding window properties and reset
  - Prometheus exporter output contains the four new 60-second gauge metrics

Author: TrapNinja Team
"""

import time
import threading
from datetime import datetime
from unittest.mock import patch, MagicMock

import pytest

from trapninja.processing.stats import SlidingWindowCounter, ProcessingStats


# =============================================================================
# TEST GROUP 1: SlidingWindowCounter basic behaviour
# =============================================================================

class TestSlidingWindowCounter:
    """Tests for the SlidingWindowCounter public interface."""

    def test_sliding_window_starts_at_zero(self):
        counter = SlidingWindowCounter()
        assert counter.get_value() == 0

    def test_sliding_window_increment_single(self):
        counter = SlidingWindowCounter()
        counter.increment()
        assert counter.get_value() == 1

    def test_sliding_window_increment_multiple(self):
        counter = SlidingWindowCounter()
        for _ in range(5):
            counter.increment()
        assert counter.get_value() == 5

    def test_sliding_window_increment_by_count(self):
        counter = SlidingWindowCounter()
        counter.increment(count=10)
        assert counter.get_value() == 10

    @pytest.mark.slow
    def test_sliding_window_excludes_old_events(self):
        """Events older than window_seconds must not appear in get_value()."""
        # Use a 1-second window with 2 buckets so we only need to sleep 1.1s.
        counter = SlidingWindowCounter(window_seconds=1, num_buckets=2)
        counter.increment()
        assert counter.get_value() >= 1
        time.sleep(1.1)
        assert counter.get_value() == 0

    def test_sliding_window_thread_safety(self):
        """Concurrent increments from multiple threads must not lose counts."""
        counter = SlidingWindowCounter()

        def _increment_100():
            for _ in range(100):
                counter.increment()

        threads = [threading.Thread(target=_increment_100) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert counter.get_value() == 1000


# =============================================================================
# TEST GROUP 2: ProcessingStats window properties
# =============================================================================

class TestProcessingStatsWindowProperties:
    """Tests for the sliding window properties and to_dict() output."""

    def test_processing_stats_window_properties_start_at_zero(self):
        stats = ProcessingStats()
        assert stats.received_last_60s == 0
        assert stats.forwarded_last_60s == 0
        assert stats.dropped_last_60s == 0
        assert stats.errors_last_60s == 0

    def test_processing_stats_received_window_increments(self):
        stats = ProcessingStats()
        stats.increment_processed()
        stats.increment_processed()
        assert stats.received_last_60s == 2

    def test_processing_stats_forwarded_window_increments(self):
        stats = ProcessingStats()
        stats.increment_forwarded()
        assert stats.forwarded_last_60s == 1

    def test_processing_stats_dropped_window_increments(self):
        stats = ProcessingStats()
        stats.increment_dropped()
        assert stats.dropped_last_60s == 1

    def test_processing_stats_errors_window_increments(self):
        stats = ProcessingStats()
        stats.increment_error()
        assert stats.errors_last_60s == 1

    def test_processing_stats_to_dict_includes_window_60s(self):
        stats = ProcessingStats()
        stats.increment_processed()
        stats.increment_forwarded()
        d = stats.to_dict()

        assert 'window_60s' in d
        assert 'received' in d['window_60s']
        assert 'forwarded' in d['window_60s']
        assert 'dropped' in d['window_60s']
        assert 'errors' in d['window_60s']
        assert d['window_60s']['received'] == 1
        assert d['window_60s']['forwarded'] == 1

    def test_processing_stats_reset_clears_window(self):
        stats = ProcessingStats()
        stats.increment_processed()
        stats.increment_forwarded()
        stats.reset()
        assert stats.received_last_60s == 0
        assert stats.forwarded_last_60s == 0


# =============================================================================
# TEST GROUP 3: Prometheus output contains new gauge metrics
# =============================================================================

def _build_minimal_metrics_summary() -> dict:
    """
    Build a complete metrics_summary dict that satisfies every key lookup
    in export_metrics(), allowing it to run without calling get_metrics_summary().
    """
    return {
        "timestamp": datetime.now().isoformat(),
        "uptime_seconds": 123.4,
        "interval_seconds": 60,
        "metrics_config": {"directory": "/tmp", "global_labels": {}},
        # Core trap counters
        "total_traps_received":  1000,
        "total_traps_forwarded": 900,
        "total_traps_blocked":   50,
        "total_traps_redirected": 10,
        "total_traps_dropped":   2,
        "processing_errors":     3,
        # Sliding window counts — the values under test
        "window_60s_received":   42,
        "window_60s_forwarded":  38,
        "window_60s_dropped":    1,
        "window_60s_errors":     0,
        # HA
        "ha_blocked": 0,
        "ha": {"enabled": False},
        # Cache
        "traps_cached":    0,
        "cache_failures":  0,
        "cache": {"enabled": False, "available": False},
        # Performance
        "fast_path_hits":   800,
        "slow_path_hits":   200,
        "fast_path_ratio":  80.0,
        "processing_rate":  15.2,
        # Queue
        "queue_current_depth": 5,
        "queue_max_depth":     100,
        "queue_capacity":      200000,
        "queue_utilization":   0.0025,
        "queue_full_events":   0,
        # IP/OID detail (empty)
        "blocked_ips":     {},
        "blocked_oids":    {},
        "redirected_ips":  {},
        "redirected_oids": {},
    }


class TestExportMetrics60sGauges:
    """Integration test: the Prometheus exporter emits the four 60-second gauges."""

    def test_export_metrics_contains_60s_gauges(self, tmp_path):
        """
        Calls export_metrics() with a pre-built summary and a mock config
        pointing to tmp_path, then asserts the written .prom file contains
        all four sliding window gauge metrics with correct types and values.
        """
        from trapninja.metrics.exporter import export_metrics

        metrics_summary = _build_minimal_metrics_summary()

        # Build a mock config that directs file output to tmp_path.
        # json_enabled=False avoids the second write path.
        mock_config = MagicMock()
        mock_config.global_labels = {}
        mock_config.directory = str(tmp_path)
        mock_config.prometheus_path = str(tmp_path / "trapninja.prom")
        mock_config.json_enabled = False
        mock_config.export_interval_seconds = 60

        # get_current_config is imported inside export_metrics at call time,
        # so patching the attribute on the collector module is the right target.
        with patch(
            "trapninja.metrics.collector.get_current_config",
            return_value=mock_config,
        ):
            result = export_metrics(metrics_summary=metrics_summary)

        assert result is True, "export_metrics() should return True on success"

        prom_content = (tmp_path / "trapninja.prom").read_text()

        # All four metric names must be present
        assert "trapninja_traps_received_60s" in prom_content
        assert "trapninja_traps_forwarded_60s" in prom_content
        assert "trapninja_traps_dropped_60s" in prom_content
        assert "trapninja_processing_errors_60s" in prom_content

        # Each must be declared as a gauge, not a counter
        assert "# TYPE trapninja_traps_received_60s gauge" in prom_content
        assert "# TYPE trapninja_traps_forwarded_60s gauge" in prom_content
        assert "# TYPE trapninja_traps_dropped_60s gauge" in prom_content
        assert "# TYPE trapninja_processing_errors_60s gauge" in prom_content

        # Spot-check the value 42 is associated with received_60s
        assert "trapninja_traps_received_60s 42" in prom_content
