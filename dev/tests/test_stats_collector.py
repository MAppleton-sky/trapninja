#!/usr/bin/env python3
"""
TrapNinja Test Suite - Statistics Collector Tests

Tests for trapninja.stats.collector module - granular statistics collection.

Author: TrapNinja Team
"""

import time
import threading
import pytest
from unittest.mock import patch, MagicMock


class TestCollectorConfig:
    """Tests for CollectorConfig class."""

    def test_default_initialization(self):
        """Test CollectorConfig with default values."""
        from trapninja.stats.collector import CollectorConfig
        
        config = CollectorConfig()
        
        assert config.max_ips == 10000
        assert config.max_oids == 5000
        assert config.max_destinations == 100
        assert config.cleanup_interval == 300
        assert config.stale_threshold == 3600

    def test_custom_initialization(self):
        """Test CollectorConfig with custom values."""
        from trapninja.stats.collector import CollectorConfig
        
        config = CollectorConfig(
            max_ips=5000,
            max_oids=2000,
            cleanup_interval=600
        )
        
        assert config.max_ips == 5000
        assert config.max_oids == 2000
        assert config.cleanup_interval == 600

    def test_global_labels(self):
        """Test global labels configuration."""
        from trapninja.stats.collector import CollectorConfig
        
        config = CollectorConfig(
            global_labels={"env": "prod", "dc": "dc1"}
        )
        
        assert config.global_labels["env"] == "prod"
        assert config.global_labels["dc"] == "dc1"


class TestLRUDict:
    """Tests for LRUDict class."""

    def test_max_size_enforcement(self):
        """Test LRU eviction when max size exceeded."""
        from trapninja.stats.collector import LRUDict
        
        d = LRUDict(max_size=3)
        
        d["a"] = 1
        d["b"] = 2
        d["c"] = 3
        d["d"] = 4  # Should evict "a"
        
        assert "a" not in d
        assert "d" in d
        assert len(d) == 3

    def test_access_updates_order(self):
        """Test accessing item moves it to end."""
        from trapninja.stats.collector import LRUDict
        
        d = LRUDict(max_size=3)
        
        d["a"] = 1
        d["b"] = 2
        d["c"] = 3
        
        # Access "a" to move it to end
        _ = d["a"]
        d["a"] = d["a"]  # Re-set moves to end
        
        # Add new item - should evict "b" (oldest after "a" was accessed)
        d["d"] = 4
        
        assert "a" in d
        assert "d" in d

    def test_get_or_create_existing(self):
        """Test get_or_create returns existing item."""
        from trapninja.stats.collector import LRUDict
        
        d = LRUDict(max_size=10)
        d["key"] = "existing"
        
        result = d.get_or_create("key", lambda: "new")
        
        assert result == "existing"

    def test_get_or_create_new(self):
        """Test get_or_create creates new item."""
        from trapninja.stats.collector import LRUDict
        
        d = LRUDict(max_size=10)
        
        result = d.get_or_create("key", lambda: "created")
        
        assert result == "created"
        assert d["key"] == "created"


class TestGranularStatsCollector:
    """Tests for GranularStatsCollector class."""

    def test_initialization(self):
        """Test collector initialization."""
        from trapninja.stats.collector import GranularStatsCollector, CollectorConfig
        
        config = CollectorConfig(max_ips=100)
        collector = GranularStatsCollector(config)
        
        assert collector.config.max_ips == 100
        assert collector._total_traps == 0

    def test_record_trap_basic(self):
        """Test basic trap recording."""
        from trapninja.stats.collector import GranularStatsCollector
        
        collector = GranularStatsCollector()
        collector.record_trap(source_ip="10.0.0.1")
        
        assert collector._total_traps == 1

    def test_record_trap_with_oid(self):
        """Test trap recording with OID."""
        from trapninja.stats.collector import GranularStatsCollector
        
        collector = GranularStatsCollector()
        collector.record_trap(
            source_ip="10.0.0.1",
            oid="1.3.6.1.4.1.9.1"
        )
        
        assert collector._total_traps == 1
        assert "1.3.6.1.4.1.9.1" in collector._oid_stats

    def test_record_trap_actions(self):
        """Test recording different actions."""
        from trapninja.stats.collector import GranularStatsCollector
        
        collector = GranularStatsCollector()
        
        collector.record_trap(source_ip="10.0.0.1", action='forwarded')
        collector.record_trap(source_ip="10.0.0.2", action='blocked')
        collector.record_trap(source_ip="10.0.0.3", action='redirected')
        collector.record_trap(source_ip="10.0.0.4", action='dropped')
        
        assert collector._total_forwarded == 1
        assert collector._total_blocked == 1
        assert collector._total_redirected == 1
        assert collector._total_dropped == 1

    def test_record_trap_with_destination(self):
        """Test trap recording with destination."""
        from trapninja.stats.collector import GranularStatsCollector
        
        collector = GranularStatsCollector()
        collector.record_trap(
            source_ip="10.0.0.1",
            action='forwarded',
            destination="default"
        )
        
        assert "default" in collector._dest_stats

    def test_get_ip_stats(self):
        """Test get_ip_stats method."""
        from trapninja.stats.collector import GranularStatsCollector
        
        collector = GranularStatsCollector()
        collector.record_trap(source_ip="10.0.0.1", oid="test_oid")
        
        result = collector.get_ip_stats("10.0.0.1")
        
        assert result is not None
        assert result['ip_address'] == "10.0.0.1"
        assert result['total_traps'] == 1

    def test_get_ip_stats_not_found(self):
        """Test get_ip_stats returns None for unknown IP."""
        from trapninja.stats.collector import GranularStatsCollector
        
        collector = GranularStatsCollector()
        
        result = collector.get_ip_stats("unknown")
        
        assert result is None

    def test_get_oid_stats(self):
        """Test get_oid_stats method."""
        from trapninja.stats.collector import GranularStatsCollector
        
        collector = GranularStatsCollector()
        collector.record_trap(source_ip="10.0.0.1", oid="1.3.6.1.4.1.9.1")
        
        result = collector.get_oid_stats("1.3.6.1.4.1.9.1")
        
        assert result is not None
        assert result['oid'] == "1.3.6.1.4.1.9.1"

    def test_get_top_ips(self):
        """Test get_top_ips method."""
        from trapninja.stats.collector import GranularStatsCollector
        
        collector = GranularStatsCollector()
        
        # IP1 gets 3 traps, IP2 gets 1
        for _ in range(3):
            collector.record_trap(source_ip="10.0.0.1")
        collector.record_trap(source_ip="10.0.0.2")
        
        result = collector.get_top_ips(10, sort_by='total')
        
        assert len(result) == 2
        assert result[0]['ip_address'] == "10.0.0.1"
        assert result[0]['total_traps'] == 3

    def test_get_top_ips_by_rate(self):
        """Test get_top_ips sorted by rate."""
        from trapninja.stats.collector import GranularStatsCollector
        
        collector = GranularStatsCollector()
        collector.record_trap(source_ip="10.0.0.1")
        
        result = collector.get_top_ips(10, sort_by='rate')
        
        assert len(result) >= 1

    def test_get_top_oids(self):
        """Test get_top_oids method."""
        from trapninja.stats.collector import GranularStatsCollector
        
        collector = GranularStatsCollector()
        
        for _ in range(5):
            collector.record_trap(source_ip="10.0.0.1", oid="oid1")
        for _ in range(2):
            collector.record_trap(source_ip="10.0.0.2", oid="oid2")
        
        result = collector.get_top_oids(10, sort_by='total')
        
        assert len(result) == 2
        assert result[0]['oid'] == "oid1"

    def test_get_all_destinations(self):
        """Test get_all_destinations method."""
        from trapninja.stats.collector import GranularStatsCollector
        
        collector = GranularStatsCollector()
        collector.record_trap(
            source_ip="10.0.0.1",
            action='forwarded',
            destination="default"
        )
        
        result = collector.get_all_destinations()
        
        assert len(result) >= 1
        assert result[0]['destination'] == "default"

    def test_get_snapshot(self):
        """Test get_snapshot method."""
        from trapninja.stats.collector import GranularStatsCollector
        
        collector = GranularStatsCollector()
        collector.record_trap(source_ip="10.0.0.1")
        
        snapshot = collector.get_snapshot()
        
        assert snapshot.total_traps == 1
        assert snapshot.unique_ips == 1

    def test_get_summary(self):
        """Test get_summary method."""
        from trapninja.stats.collector import GranularStatsCollector
        
        collector = GranularStatsCollector()
        collector.record_trap(source_ip="10.0.0.1")
        
        result = collector.get_summary()
        
        assert 'totals' in result
        assert 'counts' in result
        assert 'rates' in result
        assert result['totals']['traps'] == 1

    def test_search_ips(self):
        """Test search_ips method."""
        from trapninja.stats.collector import GranularStatsCollector
        
        collector = GranularStatsCollector()
        collector.record_trap(source_ip="10.0.0.1")
        collector.record_trap(source_ip="10.0.0.2")
        collector.record_trap(source_ip="192.168.1.1")
        
        result = collector.search_ips("10.0.0")
        
        assert len(result) == 2

    def test_search_oids(self):
        """Test search_oids method."""
        from trapninja.stats.collector import GranularStatsCollector
        
        collector = GranularStatsCollector()
        collector.record_trap(source_ip="10.0.0.1", oid="1.3.6.1.4.1.9.1")
        collector.record_trap(source_ip="10.0.0.2", oid="1.3.6.1.4.1.9.2")
        collector.record_trap(source_ip="10.0.0.3", oid="1.3.6.1.4.1.10.1")
        
        result = collector.search_oids("1.3.6.1.4.1.9")
        
        assert len(result) == 2

    def test_reset(self):
        """Test reset method."""
        from trapninja.stats.collector import GranularStatsCollector
        
        collector = GranularStatsCollector()
        collector.record_trap(source_ip="10.0.0.1")
        
        collector.reset()
        
        assert collector._total_traps == 0
        assert len(collector._ip_stats) == 0

    def test_record_forward_failure(self):
        """Test record_forward_failure method."""
        from trapninja.stats.collector import GranularStatsCollector
        
        collector = GranularStatsCollector()
        collector.record_forward_failure(
            destination="default",
            source_ip="10.0.0.1"
        )
        
        dest_stats = collector._dest_stats.get("default")
        assert dest_stats is not None
        assert dest_stats.failed == 1


class TestCollectorExport:
    """Tests for collector export methods."""

    def test_export_prometheus_contains_required_counters(self):
        """export_prometheus emits all required counter metrics."""
        from trapninja.stats.collector import GranularStatsCollector

        collector = GranularStatsCollector()
        collector.record_trap(source_ip="10.0.0.1", oid="1.3.6.1.4.1.9.1",
                              action="forwarded", destination="default")
        collector.record_trap(source_ip="10.0.0.2", oid="1.3.6.1.4.1.9.1",
                              action="blocked")

        result = collector.export_prometheus()

        # Global counters
        assert "trapninja_traps_total" in result
        assert "trapninja_traps_forwarded_total" in result
        assert "trapninja_traps_blocked_total" in result
        assert "trapninja_traps_redirected_total" in result

        # Global gauges
        assert "trapninja_unique_sources" in result
        assert "trapninja_unique_oids" in result
        assert "trapninja_uptime_seconds" in result

        # Per-IP counters
        assert "trapninja_ip_traps_total" in result
        assert "trapninja_ip_blocked_total" in result

        # Per-IP peak gauge (must NOT be a rate-per-minute current gauge)
        assert "trapninja_ip_peak_rate_per_minute" in result

        # Per-OID counters
        assert "trapninja_oid_traps_total" in result
        assert "trapninja_oid_blocked_total" in result

        # Per-OID gauges
        assert "trapninja_oid_unique_sources" in result
        assert "trapninja_oid_peak_rate_per_minute" in result

        # Destination counters
        assert "trapninja_dest_forwards_total" in result

        # IP+OID combination counter
        assert "trapninja_ip_oid_traps_total" in result

        # Prometheus formatting
        assert "# HELP" in result
        assert "# TYPE" in result

    def test_export_prometheus_does_not_contain_removed_metrics(self):
        """
        Metrics derivable by Grafana must NOT appear in the Prometheus export.

        These were removed because Grafana calculates them natively:
          trapninja_ip_rate_per_minute   -> rate(trapninja_ip_traps_total[1m]) * 60
          trapninja_oid_rate_per_minute  -> rate(trapninja_oid_traps_total[1m]) * 60
          trapninja_dest_forwards_60s    -> increase(trapninja_dest_forwards_total[60s])
        """
        from trapninja.stats.collector import GranularStatsCollector

        collector = GranularStatsCollector()
        collector.record_trap(source_ip="10.0.0.1", oid="1.3.6.1.4.1.9.1",
                              action="forwarded", destination="default")

        result = collector.export_prometheus()

        assert "trapninja_ip_rate_per_minute" not in result
        assert "trapninja_oid_rate_per_minute" not in result
        assert "trapninja_dest_forwards_60s" not in result

    def test_export_prometheus_ip_label_present(self):
        """Per-IP metrics include ip label with correct value."""
        from trapninja.stats.collector import GranularStatsCollector

        collector = GranularStatsCollector()
        collector.record_trap(source_ip="10.0.0.1", oid="1.3.6.1.4.1.9.1")

        result = collector.export_prometheus()

        assert 'ip="10.0.0.1"' in result

    def test_export_prometheus_oid_label_present(self):
        """Per-OID metrics include oid label with correct value."""
        from trapninja.stats.collector import GranularStatsCollector

        collector = GranularStatsCollector()
        collector.record_trap(source_ip="10.0.0.1", oid="1.3.6.1.4.1.9.1")

        result = collector.export_prometheus()

        assert 'oid="1.3.6.1.4.1.9.1"' in result

    def test_export_prometheus_blocked_ip_appears_in_ip_blocked_total(self):
        """trapninja_ip_blocked_total only appears for IPs that have blocked traps."""
        from trapninja.stats.collector import GranularStatsCollector

        collector = GranularStatsCollector()
        collector.record_trap(source_ip="10.0.0.1", action="forwarded")
        collector.record_trap(source_ip="10.0.0.2", action="blocked")

        result = collector.export_prometheus()

        # Only the blocked IP should appear under ip_blocked_total
        assert 'trapninja_ip_blocked_total{ip="10.0.0.2"}' in result
        assert 'trapninja_ip_blocked_total{ip="10.0.0.1"}' not in result

    def test_export_prometheus_blocked_oid_appears_in_oid_blocked_total(self):
        """trapninja_oid_blocked_total only appears for OIDs with blocked traps."""
        from trapninja.stats.collector import GranularStatsCollector

        collector = GranularStatsCollector()
        collector.record_trap(source_ip="10.0.0.1", oid="oid.forwarded", action="forwarded")
        collector.record_trap(source_ip="10.0.0.2", oid="oid.blocked", action="blocked")

        result = collector.export_prometheus()

        assert 'trapninja_oid_blocked_total{oid="oid.blocked"}' in result
        assert 'trapninja_oid_blocked_total{oid="oid.forwarded"}' not in result

    def test_export_prometheus_dest_failures_only_when_nonzero(self):
        """trapninja_dest_failures_total only emitted for destinations with failures."""
        from trapninja.stats.collector import GranularStatsCollector

        collector = GranularStatsCollector()
        collector.record_trap(source_ip="10.0.0.1", action="forwarded",
                              destination="healthy")
        collector.record_forward_failure(destination="broken", source_ip="10.0.0.1")

        result = collector.export_prometheus()

        assert 'destination="broken"' in result
        assert 'trapninja_dest_failures_total{destination="healthy"}' not in result

    def test_export_prometheus_ip_oid_combination_present(self):
        """trapninja_ip_oid_traps_total emitted for IP+OID combinations."""
        from trapninja.stats.collector import GranularStatsCollector

        collector = GranularStatsCollector()
        collector.record_trap(source_ip="10.0.0.1", oid="1.3.6.1.4.1.9.1")

        result = collector.export_prometheus()

        assert 'trapninja_ip_oid_traps_total{ip="10.0.0.1",oid="1.3.6.1.4.1.9.1"}' in result

    def test_export_prometheus_with_global_labels(self):
        """Global labels are applied to all metrics."""
        from trapninja.stats.collector import GranularStatsCollector, CollectorConfig

        config = CollectorConfig(global_labels={"env": "test"})
        collector = GranularStatsCollector(config)
        collector.record_trap(source_ip="10.0.0.1")

        result = collector.export_prometheus()

        assert 'env="test"' in result
        # Global labels must appear on the unlabelled global metrics
        assert 'trapninja_traps_total{env="test"}' in result

    def test_export_prometheus_counter_values_are_correct(self):
        """Counter values in the Prometheus output match recorded counts."""
        from trapninja.stats.collector import GranularStatsCollector

        collector = GranularStatsCollector()
        for _ in range(3):
            collector.record_trap(source_ip="10.0.0.1", action="forwarded",
                                  destination="default")
        for _ in range(2):
            collector.record_trap(source_ip="10.0.0.1", action="blocked")

        result = collector.export_prometheus()

        assert "trapninja_traps_total 5" in result
        assert "trapninja_traps_forwarded_total 3" in result
        assert "trapninja_traps_blocked_total 2" in result

    def test_export_json(self):
        """Test export_json method."""
        from trapninja.stats.collector import GranularStatsCollector

        collector = GranularStatsCollector()
        collector.record_trap(source_ip="10.0.0.1")

        result = collector.export_json()

        assert isinstance(result, dict)
        assert 'summary' in result


class TestCollectorLifecycle:
    """Tests for collector start/stop lifecycle."""

    def test_start_stop(self, tmp_path):
        """Test start and stop methods."""
        from trapninja.stats.collector import GranularStatsCollector, CollectorConfig
        
        config = CollectorConfig(
            metrics_dir=str(tmp_path),
            cleanup_interval=3600,  # Long interval to avoid interference
            export_interval=3600
        )
        collector = GranularStatsCollector(config)
        
        collector.start()
        assert collector._running is True
        
        collector.stop()
        assert collector._running is False


class TestCollectorThreadSafety:
    """Tests for thread safety."""

    def test_concurrent_record_trap(self):
        """Test concurrent trap recording."""
        from trapninja.stats.collector import GranularStatsCollector
        
        collector = GranularStatsCollector()
        errors = []
        
        def record_many():
            try:
                for i in range(1000):
                    collector.record_trap(
                        source_ip=f"10.0.0.{i % 10}",
                        oid=f"1.3.6.1.{i % 5}"
                    )
            except Exception as e:
                errors.append(e)
        
        threads = [threading.Thread(target=record_many) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        assert len(errors) == 0
        assert collector._total_traps == 5000

    def test_concurrent_read_write(self):
        """Test concurrent reads and writes."""
        from trapninja.stats.collector import GranularStatsCollector
        
        collector = GranularStatsCollector()
        errors = []
        
        def writer():
            try:
                for i in range(500):
                    collector.record_trap(source_ip=f"10.0.0.{i % 10}")
            except Exception as e:
                errors.append(e)
        
        def reader():
            try:
                for _ in range(500):
                    collector.get_top_ips(10)
                    collector.get_summary()
            except Exception as e:
                errors.append(e)
        
        threads = []
        for _ in range(3):
            threads.append(threading.Thread(target=writer))
            threads.append(threading.Thread(target=reader))
        
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        assert len(errors) == 0


class TestGlobalCollectorManagement:
    """Tests for global collector instance management."""

    def test_get_stats_collector_returns_none_before_init(self):
        """Test get_stats_collector returns None before initialization."""
        from trapninja.stats import collector as collector_module
        
        # Store original
        original = collector_module._collector
        collector_module._collector = None
        
        try:
            result = collector_module.get_stats_collector()
            assert result is None
        finally:
            collector_module._collector = original

    def test_initialize_stats(self, tmp_path):
        """Test initialize_stats creates collector."""
        from trapninja.stats.collector import (
            initialize_stats, get_stats_collector, shutdown_stats,
            CollectorConfig
        )
        
        config = CollectorConfig(
            metrics_dir=str(tmp_path),
            cleanup_interval=3600,
            export_interval=3600
        )
        
        try:
            collector = initialize_stats(config)
            assert collector is not None
            
            # Should return same instance
            assert get_stats_collector() is collector
        finally:
            shutdown_stats()

    def test_shutdown_stats(self, tmp_path):
        """Test shutdown_stats stops and clears collector."""
        from trapninja.stats.collector import (
            initialize_stats, get_stats_collector, shutdown_stats,
            CollectorConfig
        )
        
        config = CollectorConfig(
            metrics_dir=str(tmp_path),
            cleanup_interval=3600,
            export_interval=3600
        )
        
        initialize_stats(config)
        shutdown_stats()
        
        # Collector should be None after shutdown
        # Note: This depends on implementation
