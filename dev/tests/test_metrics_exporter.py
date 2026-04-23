#!/usr/bin/env python3
"""
TrapNinja Test Suite - Metrics Exporter Tests

Tests for trapninja.metrics.exporter module - Prometheus format export.

Author: TrapNinja Team
"""

import os
import json
import pytest
from unittest.mock import patch, MagicMock


class TestEmitCounter:
    """Tests for _emit_counter helper function."""

    def test_includes_help_and_type(self):
        """Test _emit_counter emits HELP/TYPE comments."""
        from trapninja.metrics.exporter import _emit_counter

        result = _emit_counter(
            "trapninja_traps_received_total",
            100,
            1718000000.123,
            help_text="Total traps received",
        )

        assert "# HELP trapninja_traps_received_total Total traps received" in result
        assert "# TYPE trapninja_traps_received_total counter" in result

    def test_emits_value_line(self):
        """Test _emit_counter emits the value line."""
        from trapninja.metrics.exporter import _emit_counter

        result = _emit_counter("my_counter_total", 42, 1718000000.0)

        assert "my_counter_total 42" in result

    def test_emits_created_line(self):
        """Test _emit_counter emits a _created line with the given timestamp."""
        from trapninja.metrics.exporter import _emit_counter

        result = _emit_counter("my_counter_total", 42, 1718000000.123)

        assert "my_counter_total_created 1718000000.123" in result

    def test_created_timestamp_format(self):
        """Test _created timestamp is formatted to 3 decimal places."""
        from trapninja.metrics.exporter import _emit_counter

        result = _emit_counter("my_counter_total", 0, 1700000000.0)

        assert "my_counter_total_created 1700000000.000" in result

    def test_with_global_labels(self):
        """Test labels are applied to both value and _created lines."""
        from trapninja.metrics.exporter import _emit_counter

        result = _emit_counter(
            "my_counter_total",
            10,
            1718000000.0,
            global_labels={"env": "prod"},
        )

        assert 'my_counter_total{env="prod"} 10' in result
        assert 'my_counter_total_created{env="prod"} 1718000000.000' in result

    def test_created_line_has_no_help_or_type(self):
        """Test _created line is not preceded by its own HELP/TYPE."""
        from trapninja.metrics.exporter import _emit_counter

        result = _emit_counter(
            "my_counter_total",
            5,
            1718000000.0,
            help_text="A counter",
        )

        lines = result.split("\n")
        created_idx = next(i for i, l in enumerate(lines) if "_created" in l)
        # The line immediately before _created must be the value line, not a comment
        assert not lines[created_idx - 1].startswith("#")

    def test_returns_single_string(self):
        """Test _emit_counter returns a single joined string."""
        from trapninja.metrics.exporter import _emit_counter

        result = _emit_counter("c_total", 1, 1718000000.0, help_text="x")

        assert isinstance(result, str)
        assert "\n" in result


class TestFormatPrometheus:
    """Tests for format_prometheus function."""

    def test_basic_metric(self):
        """Test formatting basic metric without labels."""
        from trapninja.metrics.exporter import format_prometheus
        
        result = format_prometheus("test_metric", 42)
        
        assert "test_metric 42" in result

    def test_metric_with_help(self):
        """Test metric includes HELP comment."""
        from trapninja.metrics.exporter import format_prometheus
        
        result = format_prometheus(
            "test_metric", 
            42, 
            help_text="This is a test metric"
        )
        
        assert "# HELP test_metric This is a test metric" in result

    def test_metric_with_type(self):
        """Test metric includes TYPE comment."""
        from trapninja.metrics.exporter import format_prometheus
        
        result = format_prometheus(
            "test_metric",
            42,
            help_text="Test",
            metric_type="counter"
        )
        
        assert "# TYPE test_metric counter" in result

    def test_metric_with_labels(self):
        """Test metric with labels."""
        from trapninja.metrics.exporter import format_prometheus
        
        result = format_prometheus(
            "test_metric",
            42,
            labels={"env": "prod", "host": "server1"}
        )
        
        assert 'env="prod"' in result
        assert 'host="server1"' in result

    def test_metric_with_global_labels(self):
        """Test metric with global labels."""
        from trapninja.metrics.exporter import format_prometheus
        
        result = format_prometheus(
            "test_metric",
            42,
            global_labels={"datacenter": "dc1"}
        )
        
        assert 'datacenter="dc1"' in result

    def test_global_labels_merged_with_metric_labels(self):
        """Test global labels are merged with metric-specific labels."""
        from trapninja.metrics.exporter import format_prometheus
        
        result = format_prometheus(
            "test_metric",
            42,
            labels={"type": "foo"},
            global_labels={"env": "prod"}
        )
        
        assert 'env="prod"' in result
        assert 'type="foo"' in result

    def test_labels_sorted_alphabetically(self):
        """Test labels are sorted for consistent output."""
        from trapninja.metrics.exporter import format_prometheus
        
        result = format_prometheus(
            "test_metric",
            42,
            labels={"zebra": "z", "alpha": "a"}
        )
        
        # alpha should appear before zebra
        alpha_pos = result.find('alpha=')
        zebra_pos = result.find('zebra=')
        assert alpha_pos < zebra_pos

    def test_gauge_metric_type(self):
        """Test gauge metric type."""
        from trapninja.metrics.exporter import format_prometheus
        
        result = format_prometheus(
            "current_value",
            100,
            help_text="Current value",
            metric_type="gauge"
        )
        
        assert "# TYPE current_value gauge" in result

    def test_counter_metric_type(self):
        """Test counter metric type."""
        from trapninja.metrics.exporter import format_prometheus
        
        result = format_prometheus(
            "total_count",
            500,
            help_text="Total count",
            metric_type="counter"
        )
        
        assert "# TYPE total_count counter" in result


class TestFormatLabeledMetrics:
    """Tests for _format_labeled_metrics function."""

    def test_empty_counter_data(self):
        """Test with empty counter data."""
        from trapninja.metrics.exporter import _format_labeled_metrics
        
        result = _format_labeled_metrics(
            "test_metric",
            "label_name",
            {},
        )
        
        assert result == []

    def test_single_counter(self):
        """Test with single counter entry."""
        from trapninja.metrics.exporter import _format_labeled_metrics
        
        result = _format_labeled_metrics(
            "blocked_count",
            "ip",
            {"192.168.1.1": 10},
            help_text="Blocked by IP"
        )
        
        assert len(result) > 0
        assert 'ip="192.168.1.1"' in "\n".join(result)
        assert "10" in "\n".join(result)

    def test_multiple_counters(self):
        """Test with multiple counter entries."""
        from trapninja.metrics.exporter import _format_labeled_metrics
        
        result = _format_labeled_metrics(
            "blocked_count",
            "ip",
            {
                "192.168.1.1": 10,
                "192.168.1.2": 20
            }
        )
        
        output = "\n".join(result)
        assert '192.168.1.1' in output
        assert '192.168.1.2' in output

    def test_with_global_labels(self):
        """Test global labels are included."""
        from trapninja.metrics.exporter import _format_labeled_metrics
        
        result = _format_labeled_metrics(
            "blocked_count",
            "ip",
            {"192.168.1.1": 5},
            global_labels={"env": "prod"}
        )
        
        output = "\n".join(result)
        assert 'env="prod"' in output

    def test_includes_help_and_type(self):
        """Test HELP and TYPE comments are included."""
        from trapninja.metrics.exporter import _format_labeled_metrics
        
        result = _format_labeled_metrics(
            "test_metric",
            "label",
            {"value": 1},
            help_text="Test help",
            metric_type="counter"
        )
        
        output = "\n".join(result)
        assert "# HELP test_metric Test help" in output
        assert "# TYPE test_metric counter" in output


class TestExportMetrics:
    """Tests for export_metrics function."""

    def test_export_creates_files(self, tmp_path):
        """Test export_metrics creates output files."""
        from trapninja.metrics.exporter import export_metrics
        from trapninja.metrics.config import MetricsConfig
        
        config = MetricsConfig(directory=str(tmp_path))
        
        with patch('trapninja.metrics.collector.get_current_config', return_value=config):
            with patch('trapninja.metrics.collector.get_metrics_summary') as mock_summary:
                mock_summary.return_value = {
                    'timestamp': '2024-01-01T00:00:00',
                    'uptime_seconds': 100,
                    'total_traps_received': 1000,
                    'total_traps_forwarded': 900,
                    'total_traps_blocked': 50,
                    'total_traps_redirected': 30,
                    'total_traps_dropped': 10,
                    'processing_errors': 5,
                    'ha_blocked': 0,
                    'ha': {'enabled': False},
                    'traps_cached': 0,
                    'cache_failures': 0,
                    'cache': {'available': False},
                    'fast_path_hits': 800,
                    'slow_path_hits': 100,
                    'fast_path_ratio': 80.0,
                    'processing_rate': 10.5,
                    'queue_current_depth': 50,
                    'queue_max_depth': 200,
                    'queue_capacity': 200000,
                    'queue_utilization': 0.001,
                    'queue_full_events': 0,
                    'blocked_ips': {},
                    'blocked_oids': {},
                    'redirected_ips': {},
                    'redirected_oids': {},
                }
                
                result = export_metrics()
        
        assert result is True
        assert (tmp_path / config.prometheus_file).exists()

    def test_export_prometheus_format(self, tmp_path):
        """Test exported file is in Prometheus format with _created lines for counters."""
        from trapninja.metrics.exporter import export_metrics
        from trapninja.metrics.config import MetricsConfig

        config = MetricsConfig(directory=str(tmp_path))

        with patch('trapninja.metrics.collector.get_current_config', return_value=config):
            with patch('trapninja.metrics.collector.get_metrics_summary') as mock_summary:
                mock_summary.return_value = {
                    'timestamp': '2024-01-01T00:00:00',
                    'uptime_seconds': 100,
                    'metrics_start_time': 1718000000.0,
                    'total_traps_received': 1000,
                    'total_traps_forwarded': 900,
                    'total_traps_blocked': 50,
                    'total_traps_redirected': 30,
                    'total_traps_dropped': 10,
                    'processing_errors': 5,
                    'ha_blocked': 0,
                    'ha': {'enabled': False},
                    'traps_cached': 0,
                    'cache_failures': 0,
                    'cache': {'available': False},
                    'fast_path_hits': 800,
                    'slow_path_hits': 100,
                    'fast_path_ratio': 80.0,
                    'processing_rate': 10.5,
                    'queue_current_depth': 50,
                    'queue_max_depth': 200,
                    'queue_capacity': 200000,
                    'queue_utilization': 0.001,
                    'queue_full_events': 0,
                    'blocked_ips': {},
                    'blocked_oids': {},
                    'redirected_ips': {},
                    'redirected_oids': {},
                }

                export_metrics()

        content = (tmp_path / config.prometheus_file).read_text()
        assert "trapninja_traps_received_total" in content
        assert "# HELP" in content
        assert "# TYPE" in content
        # Every counter must have a _created companion line
        assert "trapninja_traps_received_total_created" in content
        assert "trapninja_traps_forwarded_total_created" in content
        assert "trapninja_traps_dropped_total_created" in content
        # processing_rate is a lifetime average and must not appear in .prom output
        assert "trapninja_processing_rate" not in content

    def test_export_includes_global_labels(self, tmp_path):
        """Test global labels are included in export."""
        from trapninja.metrics.exporter import export_metrics
        from trapninja.metrics.config import MetricsConfig
        
        config = MetricsConfig(
            directory=str(tmp_path),
            global_labels={"env": "test", "dc": "dc1"}
        )
        
        with patch('trapninja.metrics.collector.get_current_config', return_value=config):
            with patch('trapninja.metrics.collector.get_metrics_summary') as mock_summary:
                mock_summary.return_value = {
                    'timestamp': '2024-01-01T00:00:00',
                    'uptime_seconds': 100,
                    'total_traps_received': 1000,
                    'total_traps_forwarded': 900,
                    'total_traps_blocked': 50,
                    'total_traps_redirected': 30,
                    'total_traps_dropped': 10,
                    'processing_errors': 5,
                    'ha_blocked': 0,
                    'ha': {'enabled': False},
                    'traps_cached': 0,
                    'cache_failures': 0,
                    'cache': {'available': False},
                    'fast_path_hits': 800,
                    'slow_path_hits': 100,
                    'fast_path_ratio': 80.0,
                    'processing_rate': 10.5,
                    'queue_current_depth': 50,
                    'queue_max_depth': 200,
                    'queue_capacity': 200000,
                    'queue_utilization': 0.001,
                    'queue_full_events': 0,
                    'blocked_ips': {},
                    'blocked_oids': {},
                    'redirected_ips': {},
                    'redirected_oids': {},
                }
                
                export_metrics()
        
        content = (tmp_path / config.prometheus_file).read_text()
        assert 'env="test"' in content
        assert 'dc="dc1"' in content

    def test_export_json_when_enabled(self, tmp_path):
        """Test JSON export when enabled."""
        from trapninja.metrics.exporter import export_metrics
        from trapninja.metrics.config import MetricsConfig
        
        config = MetricsConfig(
            directory=str(tmp_path),
            json_enabled=True
        )
        
        with patch('trapninja.metrics.collector.get_current_config', return_value=config):
            with patch('trapninja.metrics.collector.get_metrics_summary') as mock_summary:
                mock_summary.return_value = {
                    'timestamp': '2024-01-01T00:00:00',
                    'uptime_seconds': 100,
                    'total_traps_received': 1000,
                    'total_traps_forwarded': 900,
                    'total_traps_blocked': 50,
                    'total_traps_redirected': 30,
                    'total_traps_dropped': 10,
                    'processing_errors': 5,
                    'ha_blocked': 0,
                    'ha': {'enabled': False},
                    'traps_cached': 0,
                    'cache_failures': 0,
                    'cache': {'available': False},
                    'fast_path_hits': 800,
                    'slow_path_hits': 100,
                    'fast_path_ratio': 80.0,
                    'processing_rate': 10.5,
                    'queue_current_depth': 50,
                    'queue_max_depth': 200,
                    'queue_capacity': 200000,
                    'queue_utilization': 0.001,
                    'queue_full_events': 0,
                    'blocked_ips': {},
                    'blocked_oids': {},
                    'redirected_ips': {},
                    'redirected_oids': {},
                }
                
                export_metrics()
        
        json_file = tmp_path / config.json_file
        assert json_file.exists()
        
        # Should be valid JSON
        data = json.loads(json_file.read_text())
        assert 'total_traps_received' in data

    def test_export_returns_false_on_error(self, tmp_path):
        """Test export returns False on error."""
        from trapninja.metrics.exporter import export_metrics
        
        with patch('trapninja.metrics.collector.get_metrics_summary', side_effect=Exception("Test error")):
            result = export_metrics()
        
        assert result is False

    def test_export_creates_directory(self, tmp_path):
        """Test export creates metrics directory if missing."""
        from trapninja.metrics.exporter import export_metrics
        from trapninja.metrics.config import MetricsConfig
        
        metrics_dir = tmp_path / "new_dir" / "metrics"
        config = MetricsConfig(directory=str(metrics_dir))
        
        with patch('trapninja.metrics.collector.get_current_config', return_value=config):
            with patch('trapninja.metrics.collector.get_metrics_summary') as mock_summary:
                mock_summary.return_value = {
                    'timestamp': '2024-01-01T00:00:00',
                    'uptime_seconds': 100,
                    'total_traps_received': 0,
                    'total_traps_forwarded': 0,
                    'total_traps_blocked': 0,
                    'total_traps_redirected': 0,
                    'total_traps_dropped': 0,
                    'processing_errors': 0,
                    'ha_blocked': 0,
                    'ha': {'enabled': False},
                    'traps_cached': 0,
                    'cache_failures': 0,
                    'cache': {'available': False},
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
                }
                
                result = export_metrics()
        
        assert result is True
        assert metrics_dir.exists()


class TestPrometheusMetricNames:
    """Tests for correct Prometheus metric names in export."""

    def test_contains_traps_received(self, tmp_path):
        """Test export contains all required metrics including _created lines."""
        from trapninja.metrics.exporter import export_metrics
        from trapninja.metrics.config import MetricsConfig

        config = MetricsConfig(directory=str(tmp_path))
        mock_summary = {
            'timestamp': '2024-01-01T00:00:00',
            'uptime_seconds': 100,
            'metrics_start_time': 1718000000.0,
            'total_traps_received': 1000,
            'total_traps_forwarded': 900,
            'total_traps_blocked': 50,
            'total_traps_redirected': 30,
            'total_traps_dropped': 10,
            'processing_errors': 5,
            'ha_blocked': 0,
            'ha': {'enabled': False},
            'traps_cached': 0,
            'cache_failures': 0,
            'cache': {'available': False},
            'fast_path_hits': 800,
            'slow_path_hits': 100,
            'fast_path_ratio': 80.0,
            'processing_rate': 10.5,
            'queue_current_depth': 50,
            'queue_max_depth': 200,
            'queue_capacity': 200000,
            'queue_utilization': 0.001,
            'queue_full_events': 0,
            'blocked_ips': {},
            'blocked_oids': {},
            'redirected_ips': {},
            'redirected_oids': {},
        }

        with patch('trapninja.metrics.collector.get_current_config', return_value=config):
            with patch('trapninja.metrics.collector.get_metrics_summary', return_value=mock_summary):
                export_metrics()

        content = (tmp_path / config.prometheus_file).read_text()

        # Core metrics
        assert "trapninja_traps_received_total" in content
        assert "trapninja_traps_forwarded_total" in content
        assert "trapninja_traps_blocked_total" in content
        assert "trapninja_traps_redirected_total" in content
        assert "trapninja_traps_dropped_total" in content

        # Performance metrics
        assert "trapninja_fast_path_hits_total" in content
        assert "trapninja_slow_path_hits_total" in content

        # Queue metrics
        assert "trapninja_queue_depth" in content
        assert "trapninja_queue_capacity" in content

        # Every counter must have a _created companion for Prometheus reset detection
        assert "trapninja_traps_received_total_created" in content
        assert "trapninja_traps_forwarded_total_created" in content
        assert "trapninja_traps_blocked_total_created" in content
        assert "trapninja_traps_redirected_total_created" in content
        assert "trapninja_traps_dropped_total_created" in content
        assert "trapninja_processing_errors_total_created" in content
        assert "trapninja_ha_blocked_total_created" in content
        assert "trapninja_traps_cached_total_created" in content
        assert "trapninja_cache_failures_total_created" in content
        assert "trapninja_fast_path_hits_total_created" in content
        assert "trapninja_slow_path_hits_total_created" in content
        assert "trapninja_queue_full_events_total_created" in content

        # _created timestamp value must be the one from metrics_start_time
        assert "1718000000.000" in content

        # processing_rate is a lifetime average — must not appear in .prom output
        assert "trapninja_processing_rate" not in content


class TestPrometheusFormatCompliance:
    """Tests for Prometheus format compliance."""

    def test_trailing_newline(self, tmp_path):
        """Test export file ends with newline."""
        from trapninja.metrics.exporter import export_metrics
        from trapninja.metrics.config import MetricsConfig
        
        config = MetricsConfig(directory=str(tmp_path))
        mock_summary = {
            'timestamp': '2024-01-01T00:00:00',
            'uptime_seconds': 100,
            'total_traps_received': 0,
            'total_traps_forwarded': 0,
            'total_traps_blocked': 0,
            'total_traps_redirected': 0,
            'total_traps_dropped': 0,
            'processing_errors': 0,
            'ha_blocked': 0,
            'ha': {'enabled': False},
            'traps_cached': 0,
            'cache_failures': 0,
            'cache': {'available': False},
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
        }
        
        with patch('trapninja.metrics.collector.get_current_config', return_value=config):
            with patch('trapninja.metrics.collector.get_metrics_summary', return_value=mock_summary):
                export_metrics()
        
        content = (tmp_path / config.prometheus_file).read_text()
        assert content.endswith("\n")

    def test_no_blank_label_values(self, tmp_path):
        """Test no blank label values are exported."""
        from trapninja.metrics.exporter import export_metrics
        from trapninja.metrics.config import MetricsConfig
        
        config = MetricsConfig(
            directory=str(tmp_path),
            global_labels={"env": "prod"}
        )
        mock_summary = {
            'timestamp': '2024-01-01T00:00:00',
            'uptime_seconds': 100,
            'total_traps_received': 0,
            'total_traps_forwarded': 0,
            'total_traps_blocked': 0,
            'total_traps_redirected': 0,
            'total_traps_dropped': 0,
            'processing_errors': 0,
            'ha_blocked': 0,
            'ha': {'enabled': False},
            'traps_cached': 0,
            'cache_failures': 0,
            'cache': {'available': False},
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
        }
        
        with patch('trapninja.metrics.collector.get_current_config', return_value=config):
            with patch('trapninja.metrics.collector.get_metrics_summary', return_value=mock_summary):
                export_metrics()
        
        content = (tmp_path / config.prometheus_file).read_text()
        
        # Should not have empty label values like label=""
        assert '=""' not in content
