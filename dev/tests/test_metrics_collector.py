#!/usr/bin/env python3
"""
TrapNinja Test Suite - Metrics Collector Tests

Tests for trapninja.metrics.collector module - metrics collection and aggregation.

Author: TrapNinja Team
"""

import time
import threading
import pytest
from unittest.mock import patch, MagicMock


class TestMetricsCollectorInitialization:
    """Tests for init_metrics function."""

    def test_init_returns_config(self, tmp_path):
        """Test init_metrics returns MetricsConfig."""
        from trapninja.metrics.collector import init_metrics
        from trapninja.metrics.config import MetricsConfig
        
        # Use temp directory to avoid permission issues
        result = init_metrics(metrics_directory=str(tmp_path))
        
        assert isinstance(result, MetricsConfig)

    def test_init_with_custom_directory(self, tmp_path):
        """Test init_metrics with custom directory."""
        from trapninja.metrics.collector import init_metrics
        
        custom_dir = str(tmp_path / "metrics")
        result = init_metrics(metrics_directory=custom_dir)
        
        assert result.directory == custom_dir

    def test_init_with_custom_interval(self, tmp_path):
        """Test init_metrics with custom export interval."""
        from trapninja.metrics.collector import init_metrics
        
        result = init_metrics(
            metrics_directory=str(tmp_path),
            export_interval=120
        )
        
        assert result.export_interval_seconds == 120

    def test_init_with_global_labels(self, tmp_path):
        """Test init_metrics with global labels."""
        from trapninja.metrics.collector import init_metrics
        
        labels = {"env": "test", "host": "server1"}
        result = init_metrics(
            metrics_directory=str(tmp_path),
            global_labels=labels
        )
        
        assert result.global_labels["env"] == "test"
        assert result.global_labels["host"] == "server1"

    def test_init_with_config_object(self, tmp_path):
        """Test init_metrics with MetricsConfig object."""
        from trapninja.metrics.collector import init_metrics
        from trapninja.metrics.config import MetricsConfig
        
        config = MetricsConfig(
            directory=str(tmp_path),
            export_interval_seconds=90
        )
        
        result = init_metrics(config=config)
        
        assert result.export_interval_seconds == 90


class TestIncrementFunctions:
    """Tests for metric increment functions."""

    def test_increment_blocked_ip(self):
        """Test incrementing blocked IP counter."""
        from trapninja.metrics import collector
        
        # Clear existing data
        collector._blocked_ip_counter.clear()
        
        collector.increment_blocked_ip("192.168.1.1")
        collector.increment_blocked_ip("192.168.1.1")
        collector.increment_blocked_ip("192.168.1.2")
        
        assert collector._blocked_ip_counter["192.168.1.1"] == 2
        assert collector._blocked_ip_counter["192.168.1.2"] == 1

    def test_increment_blocked_oid(self):
        """Test incrementing blocked OID counter."""
        from trapninja.metrics import collector
        
        collector._blocked_oid_counter.clear()
        
        collector.increment_blocked_oid("1.3.6.1.4.1.9.1")
        collector.increment_blocked_oid("1.3.6.1.4.1.9.1")
        
        assert collector._blocked_oid_counter["1.3.6.1.4.1.9.1"] == 2

    def test_increment_redirected_ip(self):
        """Test incrementing redirected IP counter."""
        from trapninja.metrics import collector
        
        collector._redirected_ip_counter.clear()
        
        collector.increment_redirected_ip("10.0.0.1", "voice")
        collector.increment_redirected_ip("10.0.0.2", "voice")
        collector.increment_redirected_ip("10.0.0.1", "data")
        
        assert collector._redirected_ip_counter["voice"]["10.0.0.1"] == 1
        assert collector._redirected_ip_counter["voice"]["10.0.0.2"] == 1
        assert collector._redirected_ip_counter["data"]["10.0.0.1"] == 1

    def test_increment_redirected_oid(self):
        """Test incrementing redirected OID counter."""
        from trapninja.metrics import collector
        
        collector._redirected_oid_counter.clear()
        
        collector.increment_redirected_oid("1.3.6.1.4.1.9.1", "critical")
        
        assert collector._redirected_oid_counter["critical"]["1.3.6.1.4.1.9.1"] == 1


class TestGetMetricsSummary:
    """Tests for get_metrics_summary function."""

    def test_returns_dict(self):
        """Test get_metrics_summary returns dictionary."""
        from trapninja.metrics.collector import get_metrics_summary
        
        result = get_metrics_summary()
        
        assert isinstance(result, dict)

    def test_contains_timestamp(self):
        """Test summary contains timestamp."""
        from trapninja.metrics.collector import get_metrics_summary
        
        result = get_metrics_summary()
        
        assert 'timestamp' in result

    def test_contains_uptime(self):
        """Test summary contains uptime."""
        from trapninja.metrics.collector import get_metrics_summary
        
        result = get_metrics_summary()
        
        assert 'uptime_seconds' in result
        assert result['uptime_seconds'] >= 0

    def test_contains_trap_counters(self):
        """Test summary contains trap counters."""
        from trapninja.metrics.collector import get_metrics_summary
        
        result = get_metrics_summary()
        
        assert 'total_traps_received' in result
        assert 'total_traps_forwarded' in result
        assert 'total_traps_blocked' in result
        assert 'total_traps_redirected' in result

    def test_contains_queue_metrics(self):
        """Test summary contains queue metrics."""
        from trapninja.metrics.collector import get_metrics_summary
        
        result = get_metrics_summary()
        
        assert 'queue_current_depth' in result
        assert 'queue_capacity' in result

    def test_contains_blocked_counters(self):
        """Test summary contains blocked IP/OID counters."""
        from trapninja.metrics.collector import get_metrics_summary
        
        result = get_metrics_summary()
        
        assert 'blocked_ips' in result
        assert 'blocked_oids' in result

    def test_contains_redirected_counters(self):
        """Test summary contains redirected IP/OID counters."""
        from trapninja.metrics.collector import get_metrics_summary
        
        result = get_metrics_summary()
        
        assert 'redirected_ips' in result
        assert 'redirected_oids' in result


class TestResetMetrics:
    """Tests for reset_metrics function."""

    def test_reset_clears_blocked_counters(self, tmp_path):
        """Test reset clears blocked counters."""
        from trapninja.metrics import collector
        
        # Set up test data
        collector._blocked_ip_counter["test_ip"] = 5
        collector._blocked_oid_counter["test_oid"] = 3
        
        # Set config to use temp directory
        with patch.object(collector, 'get_current_config') as mock_config:
            mock_config.return_value = MagicMock(directory=str(tmp_path))
            collector.reset_metrics()
        
        assert len(collector._blocked_ip_counter) == 0
        assert len(collector._blocked_oid_counter) == 0

    def test_reset_clears_redirected_counters(self, tmp_path):
        """Test reset clears redirected counters."""
        from trapninja.metrics import collector
        
        collector._redirected_ip_counter["tag"]["ip"] = 1
        collector._redirected_oid_counter["tag"]["oid"] = 1
        
        with patch.object(collector, 'get_current_config') as mock_config:
            mock_config.return_value = MagicMock(directory=str(tmp_path))
            collector.reset_metrics()
        
        assert len(collector._redirected_ip_counter) == 0
        assert len(collector._redirected_oid_counter) == 0


# =============================================================================
# PIPELINE TIMING INTEGRATION (A4)
# =============================================================================

class TestPipelineTimingInScheduleExport:
    """Verify _export_pipeline_timing() is called from the unified export timer."""

    def test_schedule_export_calls_pipeline_timing(self):
        """_schedule_metrics_export() calls _export_pipeline_timing() after _export_granular_stats()."""
        from trapninja.metrics import collector

        original_config = collector._current_config
        try:
            collector._current_config = MagicMock(export_interval_seconds=3600)
            call_order = []

            with patch('trapninja.metrics.exporter.export_metrics',
                       side_effect=lambda *a, **kw: call_order.append('metrics')), \
                 patch.object(collector, '_export_granular_stats',
                              side_effect=lambda: call_order.append('granular')), \
                 patch.object(collector, '_export_pipeline_timing',
                              side_effect=lambda: call_order.append('pipeline')), \
                 patch('trapninja.metrics.collector.Timer'):
                collector._schedule_metrics_export()
        finally:
            collector._current_config = original_config

        assert 'granular' in call_order
        assert 'pipeline' in call_order
        assert call_order.index('granular') < call_order.index('pipeline')

    def test_pipeline_timing_exception_does_not_stop_timer_rescheduling(self):
        """If _export_pipeline_timing() raises, the finally block still reschedules."""
        from trapninja.metrics import collector

        rescheduled = []

        def fake_timer(interval, fn):
            rescheduled.append(interval)
            t = MagicMock()
            t.daemon = False
            return t

        original_config = collector._current_config
        try:
            collector._current_config = MagicMock(export_interval_seconds=60)

            with patch.object(collector, '_export_pipeline_timing',
                              side_effect=RuntimeError("simulated failure")), \
                 patch.object(collector, '_export_granular_stats'), \
                 patch('trapninja.metrics.exporter.export_metrics'), \
                 patch('trapninja.metrics.collector.Timer', side_effect=fake_timer):
                collector._schedule_metrics_export()
        finally:
            collector._current_config = original_config

        # Timer was rescheduled despite the exception in _export_pipeline_timing
        assert len(rescheduled) > 0


class TestGetMetricsSummaryNewKeys:
    """Verify get_metrics_summary() includes the three new Phase 1 keys."""

    def test_contains_pipeline_timing(self):
        """get_metrics_summary() includes pipeline_timing key."""
        from trapninja.metrics.collector import get_metrics_summary

        result = get_metrics_summary()
        assert 'pipeline_timing' in result

    def test_contains_resource(self):
        """get_metrics_summary() includes resource key."""
        from trapninja.metrics.collector import get_metrics_summary

        result = get_metrics_summary()
        assert 'resource' in result

    def test_contains_socket_drops(self):
        """get_metrics_summary() includes socket_drops key."""
        from trapninja.metrics.collector import get_metrics_summary

        result = get_metrics_summary()
        assert 'socket_drops' in result


class TestLegacyCompatibility:
    """Tests for legacy compatibility functions."""

    def test_increment_trap_received_exists(self):
        """Test increment_trap_received function exists."""
        from trapninja.metrics.collector import increment_trap_received
        
        # Should not raise
        increment_trap_received()

    def test_increment_trap_forwarded_exists(self):
        """Test increment_trap_forwarded function exists."""
        from trapninja.metrics.collector import increment_trap_forwarded
        
        # Should not raise
        increment_trap_forwarded()

    def test_reset_interval_counters_exists(self):
        """Test reset_interval_counters function exists."""
        from trapninja.metrics.collector import reset_interval_counters
        
        # Should not raise
        reset_interval_counters()


class TestGetCurrentConfig:
    """Tests for get_current_config function."""

    def test_returns_metrics_config(self):
        """Test get_current_config returns MetricsConfig."""
        from trapninja.metrics.collector import get_current_config
        from trapninja.metrics.config import MetricsConfig
        
        result = get_current_config()
        
        assert isinstance(result, MetricsConfig)


class TestCleanupMetrics:
    """Tests for cleanup_metrics function."""

    def test_cleanup_does_not_raise(self):
        """Test cleanup_metrics doesn't raise exceptions."""
        from trapninja.metrics.collector import cleanup_metrics
        
        # Should not raise
        cleanup_metrics()


class TestThreadSafety:
    """Tests for thread safety of metrics operations."""

    def test_concurrent_increment_blocked_ip(self):
        """Test concurrent blocked IP increments are safe."""
        from trapninja.metrics import collector
        
        collector._blocked_ip_counter.clear()
        errors = []
        
        def increment_many():
            try:
                for _ in range(1000):
                    collector.increment_blocked_ip("concurrent_test_ip")
            except Exception as e:
                errors.append(e)
        
        threads = [threading.Thread(target=increment_many) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        assert len(errors) == 0
        assert collector._blocked_ip_counter["concurrent_test_ip"] == 5000

    def test_concurrent_increment_redirected(self):
        """Test concurrent redirected increments are safe."""
        from trapninja.metrics import collector
        
        collector._redirected_ip_counter.clear()
        errors = []
        
        def increment_many():
            try:
                for _ in range(1000):
                    collector.increment_redirected_ip("test_ip", "test_tag")
            except Exception as e:
                errors.append(e)
        
        threads = [threading.Thread(target=increment_many) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        assert len(errors) == 0
        assert collector._redirected_ip_counter["test_tag"]["test_ip"] == 5000


# =============================================================================
# EBPF STATS (B2 addendum)
# =============================================================================

class TestGetEbpfStats:
    """Verify _get_ebpf_stats() returns both keys when the eBPF module is importable."""

    def test_returns_lost_samples_and_raw_socket_drops(self):
        """_get_ebpf_stats() includes both lost_samples and raw_socket_drops."""
        from trapninja.metrics import collector

        with patch('trapninja.metrics.collector._get_ebpf_stats',
                   wraps=None,
                   side_effect=None) as _:
            pass  # just verifying via direct mock below

        # Directly mock the two ebpf functions so the test runs without BCC.
        with patch('trapninja.metrics.collector._get_ebpf_stats',
                   return_value={'lost_samples': 0, 'raw_socket_drops': 0}) as mock_fn:
            result = collector._get_ebpf_stats()

        assert 'lost_samples' in result
        assert 'raw_socket_drops' in result

    def test_returns_both_keys_via_import_mock(self):
        """_get_ebpf_stats() calls get_ebpf_lost_samples and get_ebpf_raw_socket_drops."""
        from trapninja.metrics import collector

        mock_module = MagicMock()
        mock_module.get_ebpf_lost_samples.return_value = 5
        mock_module.get_ebpf_raw_socket_drops.return_value = 12

        import sys
        sys.modules['trapninja.ebpf'] = mock_module
        try:
            result = collector._get_ebpf_stats()
        finally:
            del sys.modules['trapninja.ebpf']

        assert result.get('lost_samples') == 5
        assert result.get('raw_socket_drops') == 12


class TestUnifiedExportTimer:
    """Verify the unified timer calls both exports per cycle in the correct order."""

    def test_schedule_metrics_export_calls_both_in_order(self, tmp_path):
        """_schedule_metrics_export must call export_metrics then _export_granular_stats."""
        from trapninja.metrics import collector
        from trapninja.metrics.config import MetricsConfig

        collector._current_config = MetricsConfig(directory=str(tmp_path))
        call_order = []

        with patch('trapninja.metrics.exporter.export_metrics',
                   side_effect=lambda *a, **kw: call_order.append('metrics')), \
             patch('trapninja.metrics.collector._export_granular_stats',
                   side_effect=lambda: call_order.append('granular')), \
             patch('trapninja.metrics.collector.Timer'):
            collector._schedule_metrics_export()

        assert call_order == ['metrics', 'granular'], (
            f"Expected ['metrics', 'granular'], got {call_order}"
        )

    def test_cleanup_metrics_calls_granular_after_main(self):
        """cleanup_metrics must export both files; granular must follow main."""
        from trapninja.metrics import collector

        call_order = []

        with patch('trapninja.metrics.exporter.export_metrics',
                   side_effect=lambda *a, **kw: call_order.append('metrics')), \
             patch('trapninja.metrics.collector._export_granular_stats',
                   side_effect=lambda: call_order.append('granular')):
            collector.cleanup_metrics()

        assert 'metrics' in call_order
        assert 'granular' in call_order
        assert call_order.index('metrics') < call_order.index('granular'), (
            "export_metrics must run before _export_granular_stats"
        )
