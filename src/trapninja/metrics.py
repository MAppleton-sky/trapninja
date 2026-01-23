#!/usr/bin/env python3
"""
TrapNinja Metrics Module - Backward Compatibility Layer

This module provides backward compatibility for code that imports from
trapninja.metrics directly. All functionality has been moved to the
trapninja.metrics package (metrics/__init__.py).

Usage remains the same:
    from trapninja.metrics import init_metrics, get_metrics_summary
    
New features available:
    - Configurable metrics directory
    - Global labels/tags for all Prometheus metrics
    - Configuration via metrics_config.json

See metrics/config.py for configuration options.
"""

# Re-export everything from the new package location
# This ensures backward compatibility with existing imports

try:
    from .metrics import (
        # Configuration
        MetricsConfig,
        load_metrics_config,
        save_metrics_config,
        get_metrics_config,
        get_config_file_path,
        # Collector
        init_metrics,
        get_metrics_summary,
        reset_metrics,
        cleanup_metrics,
        increment_blocked_ip,
        increment_blocked_oid,
        increment_redirected_ip,
        increment_redirected_oid,
        # Exporter
        export_metrics,
        format_prometheus,
    )
except ImportError:
    # Fallback for when the package isn't properly installed
    # This shouldn't happen in normal operation
    import logging
    logging.getLogger("trapninja").warning(
        "Failed to import from metrics package, using legacy definitions"
    )
    
    # Provide minimal stub implementations
    def init_metrics(*args, **kwargs):
        pass
    
    def get_metrics_summary():
        return {}
    
    def reset_metrics():
        pass
    
    def cleanup_metrics():
        pass
    
    def export_metrics():
        pass
    
    def format_prometheus(*args, **kwargs):
        return ""
    
    def increment_blocked_ip(ip):
        pass
    
    def increment_blocked_oid(oid):
        pass
    
    def increment_redirected_ip(ip, tag):
        pass
    
    def increment_redirected_oid(oid, tag):
        pass


__all__ = [
    'MetricsConfig',
    'load_metrics_config',
    'save_metrics_config',
    'get_metrics_config',
    'get_config_file_path',
    'init_metrics',
    'get_metrics_summary',
    'reset_metrics',
    'cleanup_metrics',
    'increment_blocked_ip',
    'increment_blocked_oid',
    'increment_redirected_ip',
    'increment_redirected_oid',
    'export_metrics',
    'format_prometheus',
]
