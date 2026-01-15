#!/usr/bin/env python3
"""
TrapNinja Metrics Package

Provides unified metrics collection and export for Prometheus integration.
Supports configurable:
- Output directory for metrics files
- Custom labels/tags for all metrics
- Export intervals
- Multiple export formats (Prometheus text, JSON)

Usage:
    from trapninja.metrics import init_metrics, get_metrics_summary, export_metrics

    # Initialize with custom configuration
    init_metrics(
        metrics_directory="/opt/metrics",
        export_interval=60,
        global_labels={"on_prem": "1", "environment": "production"}
    )
"""

from .config import (
    MetricsConfig,
    load_metrics_config,
    save_metrics_config,
    get_metrics_config,
    get_config_file_path,
)

from .collector import (
    init_metrics,
    get_metrics_summary,
    reset_metrics,
    cleanup_metrics,
    increment_blocked_ip,
    increment_blocked_oid,
    increment_redirected_ip,
    increment_redirected_oid,
    # Legacy compatibility functions
    increment_trap_received,
    increment_trap_forwarded,
    reset_interval_counters,
)

from .exporter import (
    export_metrics,
    format_prometheus,
)

__all__ = [
    # Configuration
    'MetricsConfig',
    'load_metrics_config',
    'save_metrics_config',
    'get_metrics_config',
    'get_config_file_path',
    # Collector
    'init_metrics',
    'get_metrics_summary',
    'reset_metrics',
    'cleanup_metrics',
    'increment_blocked_ip',
    'increment_blocked_oid',
    'increment_redirected_ip',
    'increment_redirected_oid',
    # Legacy compatibility
    'increment_trap_received',
    'increment_trap_forwarded',
    'reset_interval_counters',
    # Exporter
    'export_metrics',
    'format_prometheus',
]
