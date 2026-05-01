#!/usr/bin/env python3
"""
TrapNinja Implementation Tests - Phase 11D: Metrics Consistency

Validates that metrics accurately reflect actual system behavior.

ASSUMPTIONS:
- Metrics summary aggregates from ProcessingStats, queue stats, HA stats
- Counter increments are reflected in exported metrics
- Prometheus format includes global labels
- JSON export matches Prometheus values
- Reset operations save snapshot before clearing
- Blocked/redirected tracking by IP/OID is accurate
- Fast/slow path ratio is calculated correctly
- Uptime and processing rate are computed accurately

Author: TrapNinja Team
"""

import os
import sys
import time
import json
import tempfile
import threading
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock, call
from typing import Dict, List, Any
from datetime import datetime

# Shared fixtures and utilities from fixtures/ directory
from fixtures import (
    build_snmpv2c_trap,
    SampleOIDs,
    SampleIPs,
    create_config,
    create_packet_data,
)


# =============================================================================
# TEST CLASS: PROCESSING STATS TO METRICS
# =============================================================================

class TestProcessingStatsToMetrics:
    """Test that ProcessingStats are correctly reflected in metrics.

    Trap total counters (received/forwarded/blocked/redirected/dropped) are now
    tracked exclusively by GranularStatsCollector.  ProcessingStats only tracks
    performance metadata: errors, path hits, queue events.
    """

    def test_total_counters_absent_from_processing_stats_dict(self):
        """ProcessingStats.to_dict() no longer contains buffered total counters.

        These moved to GranularStatsCollector which increments them directly on
        every trap, eliminating the flush lag that caused Grafana dips.
        """
        from trapninja.processing.stats import ProcessingStats

        stats = ProcessingStats()
        result = stats.to_dict()

        assert 'packets_processed' not in result
        assert 'packets_forwarded' not in result
        assert 'packets_blocked' not in result
        assert 'packets_redirected' not in result
        assert 'packets_dropped' not in result

    def test_granular_collector_tracks_total_traps(self):
        """GranularStatsCollector._total_traps increments on record_trap()."""
        from trapninja.stats.collector import GranularStatsCollector

        collector = GranularStatsCollector()
        assert collector._total_traps == 0

        collector.record_trap(source_ip='10.0.0.1', action='forwarded')
        assert collector._total_traps == 1

    def test_granular_collector_tracks_forwarded(self):
        """GranularStatsCollector._total_forwarded increments correctly."""
        from trapninja.stats.collector import GranularStatsCollector

        collector = GranularStatsCollector()
        collector.record_trap(source_ip='10.0.0.1', action='forwarded')
        assert collector._total_forwarded == 1
        assert collector._total_blocked == 0

    def test_granular_collector_tracks_blocked(self):
        """GranularStatsCollector._total_blocked increments correctly."""
        from trapninja.stats.collector import GranularStatsCollector

        collector = GranularStatsCollector()
        collector.record_trap(source_ip='10.0.0.1', action='blocked')
        assert collector._total_blocked == 1
        assert collector._total_forwarded == 0

    def test_granular_collector_tracks_redirected(self):
        """GranularStatsCollector._total_redirected increments correctly."""
        from trapninja.stats.collector import GranularStatsCollector

        collector = GranularStatsCollector()
        collector.record_trap(source_ip='10.0.0.1', action='redirected')
        assert collector._total_redirected == 1

    def test_granular_collector_tracks_dropped(self):
        """GranularStatsCollector._total_dropped increments correctly."""
        from trapninja.stats.collector import GranularStatsCollector

        collector = GranularStatsCollector()
        collector.record_trap(source_ip='10.0.0.1', action='dropped')
        assert collector._total_dropped == 1

    def test_ha_blocked_count_in_metrics_summary(self):
        """ha_blocked appears in ProcessingStats.to_dict() (still tracked here)."""
        from trapninja.processing.stats import ProcessingStats

        stats = ProcessingStats()
        stats.ha_blocked = 20

        result = stats.to_dict()

        assert result['ha_blocked'] == 20


# =============================================================================
# TEST CLASS: FAST/SLOW PATH METRICS
# =============================================================================

class TestFastSlowPathMetrics:
    """Test fast/slow path ratio calculation."""
    
    def test_fast_path_ratio_calculated_correctly(self):
        """Fast path ratio is (fast / total) * 100."""
        from trapninja.processing.stats import ProcessingStats
        
        stats = ProcessingStats()
        stats.fast_path_hits = 80
        stats.slow_path_hits = 20
        
        # Should be 80%
        assert stats.fast_path_ratio == 80.0
    
    def test_fast_path_ratio_zero_when_no_packets(self):
        """Fast path ratio is 0 when no packets processed."""
        from trapninja.processing.stats import ProcessingStats
        
        stats = ProcessingStats()
        stats.fast_path_hits = 0
        stats.slow_path_hits = 0
        
        assert stats.fast_path_ratio == 0.0
    
    def test_fast_path_100_percent(self):
        """Fast path ratio is 100% when all fast path."""
        from trapninja.processing.stats import ProcessingStats
        
        stats = ProcessingStats()
        stats.fast_path_hits = 100
        stats.slow_path_hits = 0
        
        assert stats.fast_path_ratio == 100.0
    
    def test_slow_path_100_percent(self):
        """Fast path ratio is 0% when all slow path."""
        from trapninja.processing.stats import ProcessingStats
        
        stats = ProcessingStats()
        stats.fast_path_hits = 0
        stats.slow_path_hits = 100
        
        assert stats.fast_path_ratio == 0.0
    
    def test_fast_path_ratio_in_to_dict(self):
        """fast_path_ratio appears in to_dict output."""
        from trapninja.processing.stats import ProcessingStats
        
        stats = ProcessingStats()
        stats.fast_path_hits = 75
        stats.slow_path_hits = 25
        
        result = stats.to_dict()
        
        assert 'fast_path_ratio' in result
        assert result['fast_path_ratio'] == 75.0


# =============================================================================
# TEST CLASS: PROCESSING RATE METRICS
# =============================================================================

class TestProcessingRateMetrics:
    """Test that processing_rate has been removed from ProcessingStats.

    processing_rate was packets_processed / uptime — it was removed along with
    packets_processed because totals moved to GranularStatsCollector.  Rate
    calculations in Grafana use rate(trapninja_traps_received_total[1m]) instead.
    """

    def test_processing_rate_absent_from_processing_stats(self):
        """ProcessingStats no longer has a processing_rate property."""
        from trapninja.processing.stats import ProcessingStats

        stats = ProcessingStats()
        assert not hasattr(stats, 'processing_rate')

    def test_processing_rate_absent_from_to_dict(self):
        """ProcessingStats.to_dict() does not include processing_rate."""
        from trapninja.processing.stats import ProcessingStats

        stats = ProcessingStats()
        result = stats.to_dict()

        assert 'processing_rate' not in result

    def test_processing_rate_absent_from_metrics_summary(self):
        """get_metrics_summary() does not include processing_rate."""
        from trapninja.metrics.collector import get_metrics_summary
        from unittest.mock import patch

        with patch('trapninja.metrics.collector._get_processor_stats', return_value={}):
            with patch('trapninja.metrics.collector._get_granular_totals', return_value={
                'total_traps': 0, 'total_forwarded': 0, 'total_blocked': 0,
                'total_redirected': 0, 'total_dropped': 0,
            }):
                with patch('trapninja.metrics.collector._get_queue_stats', return_value={}):
                    with patch('trapninja.metrics.collector._get_ha_stats', return_value={}):
                        with patch('trapninja.metrics.collector._get_cache_stats', return_value={}):
                            summary = get_metrics_summary()

        assert 'processing_rate' not in summary


# =============================================================================
# TEST CLASS: UPTIME METRICS
# =============================================================================

class TestUptimeMetrics:
    """Test uptime calculation."""
    
    def test_uptime_increases_over_time(self):
        """Uptime increases as time passes."""
        from trapninja.processing.stats import ProcessingStats
        
        stats = ProcessingStats()
        
        uptime1 = stats.uptime
        time.sleep(0.1)
        uptime2 = stats.uptime
        
        assert uptime2 > uptime1
    
    def test_uptime_resets_with_stats(self):
        """Uptime resets when stats are reset."""
        from trapninja.processing.stats import ProcessingStats
        
        stats = ProcessingStats()
        time.sleep(0.1)
        
        old_uptime = stats.uptime
        stats.reset()
        new_uptime = stats.uptime
        
        assert new_uptime < old_uptime
    
    def test_uptime_in_to_dict(self):
        """uptime_seconds appears in to_dict output."""
        from trapninja.processing.stats import ProcessingStats
        
        stats = ProcessingStats()
        
        result = stats.to_dict()
        
        assert 'uptime_seconds' in result
        assert result['uptime_seconds'] >= 0


# =============================================================================
# TEST CLASS: PROMETHEUS FORMAT OUTPUT
# =============================================================================

class TestPrometheusFormatOutput:
    """Test Prometheus format metric output."""
    
    def test_format_prometheus_basic(self):
        """format_prometheus creates valid output."""
        from trapninja.metrics.exporter import format_prometheus
        
        result = format_prometheus("test_metric", 42)
        
        assert "test_metric 42" in result
    
    def test_format_prometheus_with_labels(self):
        """format_prometheus includes labels correctly."""
        from trapninja.metrics.exporter import format_prometheus
        
        result = format_prometheus(
            "test_metric",
            100,
            labels={"type": "v2c", "source": "test"}
        )
        
        assert "test_metric{" in result
        assert 'type="v2c"' in result
        assert 'source="test"' in result
        assert "100" in result
    
    def test_format_prometheus_with_global_labels(self):
        """format_prometheus includes global labels."""
        from trapninja.metrics.exporter import format_prometheus
        
        result = format_prometheus(
            "test_metric",
            50,
            global_labels={"on_prem": "1", "env": "prod"}
        )
        
        assert 'on_prem="1"' in result
        assert 'env="prod"' in result
    
    def test_format_prometheus_global_and_local_labels(self):
        """Global labels are merged with local labels."""
        from trapninja.metrics.exporter import format_prometheus
        
        result = format_prometheus(
            "test_metric",
            75,
            labels={"local": "value"},
            global_labels={"global": "value"}
        )
        
        assert 'global="value"' in result
        assert 'local="value"' in result
    
    def test_format_prometheus_with_help_text(self):
        """format_prometheus includes HELP comment."""
        from trapninja.metrics.exporter import format_prometheus
        
        result = format_prometheus(
            "test_metric",
            100,
            help_text="This is a test metric"
        )
        
        assert "# HELP test_metric This is a test metric" in result
    
    def test_format_prometheus_with_type(self):
        """format_prometheus includes TYPE comment."""
        from trapninja.metrics.exporter import format_prometheus
        
        result = format_prometheus(
            "test_metric",
            100,
            help_text="Test",
            metric_type="counter"
        )
        
        assert "# TYPE test_metric counter" in result
    
    def test_labels_sorted_for_consistency(self):
        """Labels are sorted alphabetically for consistent output."""
        from trapninja.metrics.exporter import format_prometheus
        
        result = format_prometheus(
            "test_metric",
            100,
            labels={"zebra": "z", "alpha": "a", "beta": "b"}
        )
        
        # Extract label string
        label_start = result.find("{")
        label_end = result.find("}")
        labels_str = result[label_start+1:label_end]
        
        # Should be sorted: alpha, beta, zebra
        assert labels_str.index("alpha") < labels_str.index("beta")
        assert labels_str.index("beta") < labels_str.index("zebra")


# =============================================================================
# TEST CLASS: METRICS SUMMARY STRUCTURE
# =============================================================================

class TestMetricsSummaryStructure:
    """Test metrics summary contains expected fields."""
    
    def test_summary_contains_timestamp(self):
        """Metrics summary contains timestamp."""
        from trapninja.metrics.collector import get_metrics_summary
        
        with patch('trapninja.metrics.collector._get_processor_stats', return_value={}):
            with patch('trapninja.metrics.collector._get_queue_stats', return_value={}):
                with patch('trapninja.metrics.collector._get_ha_stats', return_value={}):
                    with patch('trapninja.metrics.collector._get_cache_stats', return_value={}):
                        summary = get_metrics_summary()
        
        assert 'timestamp' in summary
    
    def test_summary_contains_uptime(self):
        """Metrics summary contains uptime_seconds."""
        from trapninja.metrics.collector import get_metrics_summary
        
        with patch('trapninja.metrics.collector._get_processor_stats', return_value={}):
            with patch('trapninja.metrics.collector._get_queue_stats', return_value={}):
                with patch('trapninja.metrics.collector._get_ha_stats', return_value={}):
                    with patch('trapninja.metrics.collector._get_cache_stats', return_value={}):
                        summary = get_metrics_summary()
        
        assert 'uptime_seconds' in summary
        assert summary['uptime_seconds'] >= 0
    
    def test_summary_contains_trap_counts(self):
        """Metrics summary contains all trap count fields, sourced from GranularStatsCollector."""
        from trapninja.metrics.collector import get_metrics_summary

        granular = {
            'total_traps': 100,
            'total_forwarded': 90,
            'total_blocked': 5,
            'total_redirected': 3,
            'total_dropped': 2,
        }

        with patch('trapninja.metrics.collector._get_processor_stats', return_value={}):
            with patch('trapninja.metrics.collector._get_granular_totals', return_value=granular):
                with patch('trapninja.metrics.collector._get_queue_stats', return_value={}):
                    with patch('trapninja.metrics.collector._get_ha_stats', return_value={}):
                        with patch('trapninja.metrics.collector._get_cache_stats', return_value={}):
                            summary = get_metrics_summary()

        assert 'total_traps_received' in summary
        assert 'total_traps_forwarded' in summary
        assert 'total_traps_blocked' in summary
        assert 'total_traps_redirected' in summary
        assert 'total_traps_dropped' in summary
        # Verify values come from the granular collector, not processor stats
        assert summary['total_traps_received'] == 100
        assert summary['total_traps_forwarded'] == 90
        assert summary['total_traps_blocked'] == 5
    
    def test_summary_contains_queue_metrics(self):
        """Metrics summary contains queue metrics."""
        from trapninja.metrics.collector import get_metrics_summary
        
        with patch('trapninja.metrics.collector._get_processor_stats', return_value={}):
            with patch('trapninja.metrics.collector._get_queue_stats', return_value={
                'current_depth': 50,
                'max_depth': 100,
            }):
                with patch('trapninja.metrics.collector._get_ha_stats', return_value={}):
                    with patch('trapninja.metrics.collector._get_cache_stats', return_value={}):
                        summary = get_metrics_summary()
        
        assert 'queue_current_depth' in summary
        assert 'queue_max_depth' in summary
    
    def test_summary_contains_ha_section(self):
        """Metrics summary contains HA section."""
        from trapninja.metrics.collector import get_metrics_summary
        
        with patch('trapninja.metrics.collector._get_processor_stats', return_value={}):
            with patch('trapninja.metrics.collector._get_queue_stats', return_value={}):
                with patch('trapninja.metrics.collector._get_ha_stats', return_value={'enabled': False}):
                    with patch('trapninja.metrics.collector._get_cache_stats', return_value={}):
                        summary = get_metrics_summary()
        
        assert 'ha' in summary
    
    def test_summary_contains_cache_section(self):
        """Metrics summary contains cache section."""
        from trapninja.metrics.collector import get_metrics_summary
        
        with patch('trapninja.metrics.collector._get_processor_stats', return_value={}):
            with patch('trapninja.metrics.collector._get_queue_stats', return_value={}):
                with patch('trapninja.metrics.collector._get_ha_stats', return_value={}):
                    with patch('trapninja.metrics.collector._get_cache_stats', return_value={'enabled': False}):
                        summary = get_metrics_summary()
        
        assert 'cache' in summary


# =============================================================================
# TEST CLASS: BLOCKED IP/OID TRACKING
# =============================================================================

class TestBlockedIPOIDTracking:
    """Test detailed IP/OID blocking metrics."""
    
    def test_increment_blocked_ip(self):
        """increment_blocked_ip tracks specific IPs."""
        from trapninja.metrics import collector
        
        # Clear any existing data
        collector._blocked_ip_counter.clear()
        
        collector.increment_blocked_ip("10.0.0.1")
        collector.increment_blocked_ip("10.0.0.1")
        collector.increment_blocked_ip("10.0.0.2")
        
        assert collector._blocked_ip_counter["10.0.0.1"] == 2
        assert collector._blocked_ip_counter["10.0.0.2"] == 1
    
    def test_increment_blocked_oid(self):
        """increment_blocked_oid tracks specific OIDs."""
        from trapninja.metrics import collector
        
        collector._blocked_oid_counter.clear()
        
        collector.increment_blocked_oid("1.3.6.1.6.3.1.1.5.1")
        collector.increment_blocked_oid("1.3.6.1.6.3.1.1.5.1")
        collector.increment_blocked_oid("1.3.6.1.4.1.9.9.43.2.0.1")
        
        assert collector._blocked_oid_counter["1.3.6.1.6.3.1.1.5.1"] == 2
        assert collector._blocked_oid_counter["1.3.6.1.4.1.9.9.43.2.0.1"] == 1
    
    def test_blocked_ips_in_summary(self):
        """Blocked IPs appear in metrics summary."""
        from trapninja.metrics import collector
        
        collector._blocked_ip_counter.clear()
        collector.increment_blocked_ip("10.0.0.1")
        
        with patch('trapninja.metrics.collector._get_processor_stats', return_value={}):
            with patch('trapninja.metrics.collector._get_queue_stats', return_value={}):
                with patch('trapninja.metrics.collector._get_ha_stats', return_value={}):
                    with patch('trapninja.metrics.collector._get_cache_stats', return_value={}):
                        summary = collector.get_metrics_summary()
        
        assert 'blocked_ips' in summary
        assert summary['blocked_ips'].get("10.0.0.1") == 1
    
    def test_blocked_oids_in_summary(self):
        """Blocked OIDs appear in metrics summary."""
        from trapninja.metrics import collector
        
        collector._blocked_oid_counter.clear()
        collector.increment_blocked_oid("1.3.6.1.6.3.1.1.5.1")
        
        with patch('trapninja.metrics.collector._get_processor_stats', return_value={}):
            with patch('trapninja.metrics.collector._get_queue_stats', return_value={}):
                with patch('trapninja.metrics.collector._get_ha_stats', return_value={}):
                    with patch('trapninja.metrics.collector._get_cache_stats', return_value={}):
                        summary = collector.get_metrics_summary()
        
        assert 'blocked_oids' in summary
        assert summary['blocked_oids'].get("1.3.6.1.6.3.1.1.5.1") == 1


# =============================================================================
# TEST CLASS: REDIRECTED IP/OID TRACKING
# =============================================================================

class TestRedirectedIPOIDTracking:
    """Test detailed IP/OID redirection metrics."""
    
    def test_increment_redirected_ip(self):
        """increment_redirected_ip tracks IPs by tag."""
        from trapninja.metrics import collector
        
        collector._redirected_ip_counter.clear()
        
        collector.increment_redirected_ip("10.0.0.1", "security")
        collector.increment_redirected_ip("10.0.0.2", "security")
        collector.increment_redirected_ip("10.0.0.3", "voice")
        
        assert collector._redirected_ip_counter["security"]["10.0.0.1"] == 1
        assert collector._redirected_ip_counter["security"]["10.0.0.2"] == 1
        assert collector._redirected_ip_counter["voice"]["10.0.0.3"] == 1
    
    def test_increment_redirected_oid(self):
        """increment_redirected_oid tracks OIDs by tag."""
        from trapninja.metrics import collector
        
        collector._redirected_oid_counter.clear()
        
        collector.increment_redirected_oid("1.3.6.1.6.3.1.1.5.1", "security")
        collector.increment_redirected_oid("1.3.6.1.4.1.9.9.43.2.0.1", "voice")
        
        assert collector._redirected_oid_counter["security"]["1.3.6.1.6.3.1.1.5.1"] == 1
        assert collector._redirected_oid_counter["voice"]["1.3.6.1.4.1.9.9.43.2.0.1"] == 1
    
    def test_redirected_ips_in_summary(self):
        """Redirected IPs appear in metrics summary with tags."""
        from trapninja.metrics import collector
        
        collector._redirected_ip_counter.clear()
        collector.increment_redirected_ip("10.0.0.1", "security")
        
        with patch('trapninja.metrics.collector._get_processor_stats', return_value={}):
            with patch('trapninja.metrics.collector._get_queue_stats', return_value={}):
                with patch('trapninja.metrics.collector._get_ha_stats', return_value={}):
                    with patch('trapninja.metrics.collector._get_cache_stats', return_value={}):
                        summary = collector.get_metrics_summary()
        
        assert 'redirected_ips' in summary
        assert 'security' in summary['redirected_ips']


# =============================================================================
# TEST CLASS: METRICS RESET
# =============================================================================

class TestMetricsReset:
    """Test metrics reset functionality."""
    
    def test_reset_clears_blocked_counters(self):
        """reset_metrics clears blocked IP/OID counters."""
        from trapninja.metrics import collector
        
        collector._blocked_ip_counter["10.0.0.1"] = 10
        collector._blocked_oid_counter["1.3.6.1.6.3.1.1.5.1"] = 5
        
        with patch('trapninja.metrics.collector.get_current_config') as mock_config:
            mock_config.return_value.directory = tempfile.gettempdir()
            with patch('trapninja.metrics.collector.get_metrics_summary', return_value={}):
                collector.reset_metrics()
        
        assert len(collector._blocked_ip_counter) == 0
        assert len(collector._blocked_oid_counter) == 0
    
    def test_reset_clears_redirected_counters(self):
        """reset_metrics clears redirected IP/OID counters."""
        from trapninja.metrics import collector
        
        collector._redirected_ip_counter["security"]["10.0.0.1"] = 10
        collector._redirected_oid_counter["voice"]["1.3.6.1"] = 5
        
        with patch('trapninja.metrics.collector.get_current_config') as mock_config:
            mock_config.return_value.directory = tempfile.gettempdir()
            with patch('trapninja.metrics.collector.get_metrics_summary', return_value={}):
                collector.reset_metrics()
        
        assert len(collector._redirected_ip_counter) == 0
        assert len(collector._redirected_oid_counter) == 0
    
    def test_processing_stats_reset(self):
        """ProcessingStats reset clears all remaining counters."""
        from trapninja.processing.stats import ProcessingStats

        stats = ProcessingStats()
        stats.processing_errors = 100
        stats.fast_path_hits = 95
        stats.queue_full_events = 5

        stats.reset()

        assert stats.processing_errors == 0
        assert stats.fast_path_hits == 0
        assert stats.queue_full_events == 0


# =============================================================================
# TEST CLASS: GLOBAL STATS SINGLETON
# =============================================================================

class TestGlobalStatsSingleton:
    """Test global stats singleton behavior."""
    
    def test_get_global_stats_returns_same_instance(self):
        """get_global_stats returns the same instance."""
        from trapninja.processing.stats import get_global_stats
        
        stats1 = get_global_stats()
        stats2 = get_global_stats()
        
        assert stats1 is stats2
    
    def test_global_stats_increments_persist(self):
        """Increments on global stats persist across get_global_stats() calls."""
        from trapninja.processing.stats import get_global_stats, reset_global_stats

        reset_global_stats()

        stats = get_global_stats()
        stats.increment_error()
        stats.increment_error()

        stats2 = get_global_stats()
        assert stats2.processing_errors == 2

    def test_reset_global_stats(self):
        """reset_global_stats clears all counters."""
        from trapninja.processing.stats import get_global_stats, reset_global_stats

        stats = get_global_stats()
        stats.processing_errors = 100

        reset_global_stats()

        stats2 = get_global_stats()
        assert stats2.processing_errors == 0


# =============================================================================
# TEST CLASS: METRICS CONFIG
# =============================================================================

class TestMetricsConfig:
    """Test metrics configuration."""
    
    def test_metrics_config_defaults(self):
        """MetricsConfig has sensible defaults."""
        from trapninja.metrics.config import MetricsConfig
        
        config = MetricsConfig()
        
        assert config.directory is not None
        assert config.export_interval_seconds > 0
        assert isinstance(config.global_labels, dict)
    
    def test_metrics_config_from_dict(self):
        """MetricsConfig can be created from dict."""
        from trapninja.metrics.config import MetricsConfig
        
        data = {
            'directory': '/custom/metrics',
            'export_interval_seconds': 30,
            'global_labels': {'env': 'test'},
        }
        
        config = MetricsConfig.from_dict(data)
        
        assert config.directory == '/custom/metrics'
        assert config.export_interval_seconds == 30
        assert config.global_labels == {'env': 'test'}
    
    def test_metrics_config_to_dict(self):
        """MetricsConfig can be serialized to dict."""
        from trapninja.metrics.config import MetricsConfig
        
        config = MetricsConfig(
            directory='/test',
            export_interval_seconds=45,
        )
        
        result = config.to_dict()
        
        assert result['directory'] == '/test'
        assert result['export_interval_seconds'] == 45


# =============================================================================
# TEST CLASS: EXPORT METRICS
# =============================================================================

class TestExportMetrics:
    """Test metrics export functionality."""
    
    def test_export_metrics_returns_bool(self):
        """export_metrics returns True on success."""
        from trapninja.metrics.exporter import export_metrics
        from trapninja.metrics.config import MetricsConfig
        
        with tempfile.TemporaryDirectory() as temp_dir:
            config = MetricsConfig(directory=temp_dir)
            
            # Patch at collector module where it's defined
            with patch('trapninja.metrics.collector.get_metrics_summary', return_value={
                'timestamp': datetime.now().isoformat(),
                'uptime_seconds': 100,
                'total_traps_received': 0,
                'total_traps_forwarded': 0,
                'total_traps_blocked': 0,
                'total_traps_redirected': 0,
                'total_traps_dropped': 0,
                'processing_errors': 0,
                'ha_blocked': 0,
                'traps_cached': 0,
                'cache_failures': 0,
                'fast_path_hits': 0,
                'slow_path_hits': 0,
                'fast_path_ratio': 0.0,
                'processing_rate': 0.0,
                'queue_current_depth': 0,
                'queue_max_depth': 0,
                'queue_capacity': 200000,
                'queue_utilization': 0.0,
                'queue_full_events': 0,
                'blocked_ips': {},
                'blocked_oids': {},
                'redirected_ips': {},
                'redirected_oids': {},
                'ha': {'enabled': False},
                'cache': {'enabled': False},
            }):
                with patch('trapninja.metrics.collector.get_current_config', return_value=config):
                    result = export_metrics()
            
            assert result is True
    
    def test_export_creates_prom_file(self):
        """export_metrics creates .prom file."""
        from trapninja.metrics.exporter import export_metrics
        from trapninja.metrics.config import MetricsConfig
        
        with tempfile.TemporaryDirectory() as temp_dir:
            config = MetricsConfig(directory=temp_dir)
            
            # Patch at collector module where it's defined
            with patch('trapninja.metrics.collector.get_metrics_summary', return_value={
                'timestamp': datetime.now().isoformat(),
                'uptime_seconds': 100,
                'total_traps_received': 50,
                'total_traps_forwarded': 45,
                'total_traps_blocked': 3,
                'total_traps_redirected': 2,
                'total_traps_dropped': 0,
                'processing_errors': 0,
                'ha_blocked': 0,
                'traps_cached': 0,
                'cache_failures': 0,
                'fast_path_hits': 40,
                'slow_path_hits': 10,
                'fast_path_ratio': 80.0,
                'processing_rate': 10.0,
                'queue_current_depth': 5,
                'queue_max_depth': 50,
                'queue_capacity': 200000,
                'queue_utilization': 0.00025,
                'queue_full_events': 0,
                'blocked_ips': {},
                'blocked_oids': {},
                'redirected_ips': {},
                'redirected_oids': {},
                'ha': {'enabled': False},
                'cache': {'enabled': False},
            }):
                with patch('trapninja.metrics.collector.get_current_config', return_value=config):
                    export_metrics()
            
            prom_file = config.prometheus_path
            assert os.path.exists(prom_file)
    
    def test_export_handles_error_gracefully(self):
        """export_metrics returns False on error."""
        from trapninja.metrics.exporter import export_metrics
        
        # Patch at collector module where it's defined
        with patch('trapninja.metrics.collector.get_metrics_summary', side_effect=Exception("test")):
            result = export_metrics()
        
        assert result is False


# =============================================================================
# TEST CLASS: HA METRICS INTEGRATION
# =============================================================================

class TestHAMetricsIntegration:
    """Test HA metrics in metrics summary."""
    
    def test_ha_enabled_in_metrics(self):
        """HA enabled status appears in metrics."""
        from trapninja.metrics.collector import _get_ha_stats
        
        with patch('trapninja.ha.get_ha_cluster') as mock_get:
            mock_cluster = MagicMock()
            mock_cluster.get_status.return_value = {
                'enabled': True,
                'state': 'PRIMARY',
                'is_forwarding': True,
                'peer_connected': True,
            }
            mock_get.return_value = mock_cluster
            
            stats = _get_ha_stats()
        
        assert stats['enabled'] is True
        assert stats['is_primary'] is True
    
    def test_ha_disabled_returns_enabled_false(self):
        """When HA not available, enabled is False."""
        from trapninja.metrics.collector import _get_ha_stats
        
        with patch('trapninja.ha.get_ha_cluster', return_value=None):
            stats = _get_ha_stats()
        
        assert stats['enabled'] is False


# =============================================================================
# TEST CLASS: CACHE METRICS INTEGRATION
# =============================================================================

class TestCacheMetricsIntegration:
    """Test cache metrics in metrics summary."""
    
    def test_cache_available_in_metrics(self):
        """Cache availability appears in metrics."""
        from trapninja.metrics.collector import _get_cache_stats
        
        with patch('trapninja.cache.get_cache') as mock_get:
            mock_cache = MagicMock()
            mock_cache.available = True
            mock_cache.get_stats.return_value = {'entries': 100}
            mock_get.return_value = mock_cache
            
            stats = _get_cache_stats()
        
        assert stats['enabled'] is True
        assert stats['available'] is True
    
    def test_cache_unavailable_returns_false(self):
        """When cache not available, returns enabled False."""
        from trapninja.metrics.collector import _get_cache_stats
        
        with patch('trapninja.cache.get_cache', return_value=None):
            stats = _get_cache_stats()
        
        assert stats['enabled'] is False
        assert stats['available'] is False


# =============================================================================
# TEST CLASS: QUEUE METRICS INTEGRATION
# =============================================================================

class TestQueueMetricsIntegration:
    """Test queue metrics in metrics summary."""
    
    def test_queue_stats_in_summary(self):
        """Queue stats appear in metrics summary."""
        from trapninja.metrics.collector import get_metrics_summary
        
        with patch('trapninja.metrics.collector._get_processor_stats', return_value={}):
            with patch('trapninja.metrics.collector._get_queue_stats', return_value={
                'current_depth': 25,
                'max_depth': 100,
                'queue_capacity': 200000,
                'utilization': 0.0005,
            }):
                with patch('trapninja.metrics.collector._get_ha_stats', return_value={}):
                    with patch('trapninja.metrics.collector._get_cache_stats', return_value={}):
                        summary = get_metrics_summary()
        
        assert summary['queue_current_depth'] == 25
        assert summary['queue_max_depth'] == 100


# =============================================================================
# TEST CLASS: LEGACY COMPATIBILITY
# =============================================================================

class TestLegacyCompatibility:
    """Test legacy function compatibility."""
    
    def test_increment_trap_received_exists(self):
        """Legacy increment_trap_received function exists."""
        from trapninja.metrics import increment_trap_received
        
        # Should not raise
        increment_trap_received()
    
    def test_increment_trap_forwarded_exists(self):
        """Legacy increment_trap_forwarded function exists."""
        from trapninja.metrics import increment_trap_forwarded
        
        # Should not raise
        increment_trap_forwarded()
    
    def test_reset_interval_counters_exists(self):
        """Legacy reset_interval_counters function exists."""
        from trapninja.metrics import reset_interval_counters
        
        # Should not raise
        reset_interval_counters()


# =============================================================================
# TEST CLASS: THREAD SAFETY
# =============================================================================

class TestMetricsThreadSafety:
    """Test thread safety of metrics operations."""
    
    def test_concurrent_blocked_ip_increments(self):
        """Concurrent blocked IP increments are thread-safe."""
        from trapninja.metrics import collector
        
        collector._blocked_ip_counter.clear()
        
        def increment_many():
            for _ in range(100):
                collector.increment_blocked_ip("10.0.0.1")
        
        threads = [threading.Thread(target=increment_many) for _ in range(10)]
        
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        # Should have 1000 total
        assert collector._blocked_ip_counter["10.0.0.1"] == 1000
    
    def test_processing_stats_atomic_increments(self):
        """ProcessingStats error increments are atomic under GIL."""
        from trapninja.processing.stats import ProcessingStats

        stats = ProcessingStats()

        def increment_many():
            for _ in range(100):
                stats.increment_error()

        threads = [threading.Thread(target=increment_many) for _ in range(10)]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Should have 1000 total
        assert stats.processing_errors == 1000
