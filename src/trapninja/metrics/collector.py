#!/usr/bin/env python3
"""
TrapNinja Metrics Collector Module

Handles collection and aggregation of metrics from all processing components.
Integrates with:
- packet_processor.py (AtomicStats)
- processing/stats.py (ProcessingStats)
- network.py (QueueStats)
- HA cluster (if enabled)
- Cache system (if enabled)

This module provides the data collection layer, while exporter.py
handles the output formatting.
"""

import os
import time
import logging
from collections import Counter, defaultdict
from datetime import datetime
from threading import Lock, Timer
from typing import Dict, Any, Optional

from .config import (
    MetricsConfig,
    load_metrics_config,
    get_metrics_config,
    DEFAULT_METRICS_DIR,
    DEFAULT_EXPORT_INTERVAL,
)

logger = logging.getLogger("trapninja")

# Thread-safe lock for metrics operations
_metrics_lock = Lock()

# Detailed counters for filtering/redirection tracking
_blocked_ip_counter = Counter()
_blocked_oid_counter = Counter()
_redirected_ip_counter = defaultdict(Counter)  # Maps tag -> Counter of IPs
_redirected_oid_counter = defaultdict(Counter)  # Maps tag -> Counter of OIDs

# Timing information
_start_time = time.time()
_last_reset_time = time.time()

# Export timer reference
_export_timer: Optional[Timer] = None
_initialized = False

# Current configuration
_current_config: Optional[MetricsConfig] = None


def init_metrics(
    metrics_directory: str = None,
    export_interval: int = None,
    global_labels: Dict[str, str] = None,
    config: MetricsConfig = None
) -> MetricsConfig:
    """
    Initialize the metrics module.
    
    Can be called with individual parameters or a MetricsConfig object.
    If config is provided, it takes precedence over individual parameters.
    If no parameters are provided, loads configuration from file.

    Args:
        metrics_directory: Directory to store metrics files
        export_interval: Interval in seconds between metrics exports
        global_labels: Labels to apply to all metrics
        config: Complete MetricsConfig object (overrides other params)
        
    Returns:
        The active MetricsConfig instance
    """
    global _initialized, _start_time, _current_config

    # Determine configuration source
    if config is not None:
        _current_config = config
    else:
        # Try to load from file first
        _current_config = load_metrics_config()
        
        # Override with explicit parameters if provided
        if metrics_directory is not None:
            _current_config.directory = metrics_directory
        if export_interval is not None:
            _current_config.export_interval_seconds = export_interval
        if global_labels is not None:
            _current_config.global_labels.update(global_labels)

    # Create metrics directory if it doesn't exist
    try:
        if not os.path.exists(_current_config.directory):
            os.makedirs(_current_config.directory, exist_ok=True)
            logger.info(f"Created metrics directory: {_current_config.directory}")
    except Exception as e:
        logger.error(f"Failed to create metrics directory: {e}")

    _start_time = time.time()
    _initialized = True

    # Log configuration
    logger.info(
        f"Metrics module initialized: "
        f"interval={_current_config.export_interval_seconds}s, "
        f"dir={_current_config.directory}"
    )
    
    if _current_config.global_labels:
        labels_str = ", ".join(
            f"{k}={v}" for k, v in _current_config.global_labels.items()
        )
        logger.info(f"Global metrics labels: {labels_str}")

    # Start the export timer
    _schedule_metrics_export()
    
    return _current_config


def _schedule_metrics_export():
    """Schedule periodic export of metrics."""
    global _export_timer

    try:
        from ..config import stop_event
    except ImportError:
        class DummyEvent:
            def is_set(self):
                return False
        stop_event = DummyEvent()

    # Cancel any existing timer
    if _export_timer is not None:
        try:
            _export_timer.cancel()
        except Exception:
            pass

    # Export metrics
    from .exporter import export_metrics
    export_metrics()

    # Schedule next export if not stopping
    config = get_current_config()
    if not stop_event.is_set():
        _export_timer = Timer(
            config.export_interval_seconds,
            _schedule_metrics_export
        )
        _export_timer.daemon = True
        _export_timer.start()


def get_current_config() -> MetricsConfig:
    """
    Get the current metrics configuration.
    
    Returns:
        Current MetricsConfig, or default if not initialized
    """
    global _current_config
    
    if _current_config is None:
        _current_config = get_metrics_config()
    
    return _current_config


# =============================================================================
# DETAILED TRACKING FUNCTIONS (for IP/OID specific metrics)
# =============================================================================

def increment_blocked_ip(ip_address: str):
    """
    Track a blocked IP address for detailed metrics.

    Args:
        ip_address: Blocked IP address
    """
    with _metrics_lock:
        _blocked_ip_counter[ip_address] += 1


def increment_blocked_oid(trap_oid: str):
    """
    Track a blocked OID for detailed metrics.

    Args:
        trap_oid: Blocked trap OID
    """
    with _metrics_lock:
        _blocked_oid_counter[trap_oid] += 1


def increment_redirected_ip(ip_address: str, tag: str):
    """
    Track a redirected IP address for detailed metrics.

    Args:
        ip_address: Redirected IP address
        tag: Redirection tag/destination group
    """
    with _metrics_lock:
        _redirected_ip_counter[tag][ip_address] += 1


def increment_redirected_oid(trap_oid: str, tag: str):
    """
    Track a redirected OID for detailed metrics.

    Args:
        trap_oid: Redirected trap OID
        tag: Redirection tag/destination group
    """
    with _metrics_lock:
        _redirected_oid_counter[tag][trap_oid] += 1


# =============================================================================
# UNIFIED METRICS COLLECTION
# =============================================================================

def _get_processor_stats() -> Dict[str, Any]:
    """
    Get statistics from the packet processor module.
    
    Returns:
        Dictionary with processor statistics or empty dict if unavailable
    """
    try:
        from ..processing.stats import get_global_stats
        stats = get_global_stats()
        return stats.to_dict()
    except ImportError:
        pass
    
    return {}


def _get_queue_stats() -> Dict[str, Any]:
    """
    Get queue statistics from the network module.
    
    Returns:
        Dictionary with queue statistics or empty dict if unavailable
    """
    try:
        from ..network import get_queue_stats
        return get_queue_stats()
    except ImportError:
        return {}


def _get_ha_stats() -> Dict[str, Any]:
    """
    Get HA cluster statistics.
    
    Returns:
        Dictionary with HA statistics or empty dict if unavailable
    """
    try:
        from ..ha import get_ha_cluster
        cluster = get_ha_cluster()
        if cluster:
            status = cluster.get_status()
            return {
                'enabled': status.get('enabled', False),
                'state': status.get('state', 'unknown'),
                'is_primary': status.get('state') == 'PRIMARY',
                'is_forwarding': status.get('is_forwarding', False),
                'peer_connected': status.get('peer_connected', False),
                'failover_count': status.get('failover_count', 0),
            }
    except ImportError:
        pass
    
    return {'enabled': False}


def _get_cache_stats() -> Dict[str, Any]:
    """
    Get cache statistics.
    
    Returns:
        Dictionary with cache statistics or empty dict if unavailable
    """
    try:
        from ..cache import get_cache
        cache = get_cache()
        if cache and cache.available:
            return {
                'enabled': True,
                'available': True,
                'stats': cache.get_stats() if hasattr(cache, 'get_stats') else {}
            }
    except ImportError:
        pass
    
    return {'enabled': False, 'available': False}


def _get_granular_totals() -> Dict[str, Any]:
    """
    Get trap total counters from GranularStatsCollector.

    GranularStatsCollector is the single source of truth for trap totals.
    Counters update directly on every trap with no buffering, ensuring
    metrics/collector.py always reads current values.

    Returns:
        Dict with keys: total_traps, total_forwarded, total_blocked,
        total_redirected, total_dropped. Returns zeros if collector
        is not yet initialised.
    """
    try:
        from ..stats.collector import get_stats_collector
        collector = get_stats_collector()
        if collector:
            return {
                'total_traps':      collector._total_traps,
                'total_forwarded':  collector._total_forwarded,
                'total_blocked':    collector._total_blocked,
                'total_redirected': collector._total_redirected,
                'total_dropped':    collector._total_dropped,
            }
    except Exception:
        pass
    return {
        'total_traps': 0, 'total_forwarded': 0, 'total_blocked': 0,
        'total_redirected': 0, 'total_dropped': 0,
    }


def get_metrics_summary() -> Dict[str, Any]:
    """
    Get a comprehensive summary of all metrics from all sources.

    Returns:
        dict: Dictionary with complete metrics summary
    """
    # Get processor stats (performance metadata: path hits, errors, queue depth)
    processor_stats = _get_processor_stats()

    # Get trap totals from GranularStatsCollector (single source of truth)
    granular_totals = _get_granular_totals()

    # Get queue stats
    queue_stats = _get_queue_stats()

    # Get HA stats
    ha_stats = _get_ha_stats()

    # Get cache stats
    cache_stats = _get_cache_stats()

    # Calculate uptime
    uptime = time.time() - _start_time

    # Get current configuration
    config = get_current_config()

    # Build summary from processor stats
    window_60s = processor_stats.get('window_60s', {})

    summary = {
        "timestamp": datetime.now().isoformat(),
        "uptime_seconds": round(uptime, 1),
        "metrics_start_time": _start_time,
        "interval_seconds": config.export_interval_seconds,

        # Configuration info (for reference)
        "metrics_config": {
            "directory": config.directory,
            "global_labels": config.global_labels,
        },

        # Core trap processing metrics — sourced from GranularStatsCollector.
        # These are unbuffered: each trap increments the counter directly,
        # so values here are always current (no flush lag).
        "total_traps_received":   granular_totals['total_traps'],
        "total_traps_forwarded":  granular_totals['total_forwarded'],
        "total_traps_blocked":    granular_totals['total_blocked'],
        "total_traps_redirected": granular_totals['total_redirected'],
        "total_traps_dropped":    granular_totals['total_dropped'],
        "processing_errors": processor_stats.get('processing_errors', 0),

        # Sliding 60-second window counts
        "window_60s_received":  window_60s.get('received',  0),
        "window_60s_forwarded": window_60s.get('forwarded', 0),
        "window_60s_dropped":   window_60s.get('dropped',   0),
        "window_60s_errors":    window_60s.get('errors',    0),

        # HA-specific metrics
        "ha_blocked": processor_stats.get('ha_blocked', 0),

        # Cache metrics
        "traps_cached": processor_stats.get('cached', 0),
        "cache_failures": processor_stats.get('cache_failures', 0),

        # Performance metrics
        "fast_path_hits": processor_stats.get('fast_path_hits', 0),
        "slow_path_hits": processor_stats.get('slow_path_hits', 0),
        "fast_path_ratio": processor_stats.get('fast_path_ratio', 0.0),

        # Queue metrics
        "queue_current_depth": queue_stats.get('current_depth', 0),
        "queue_max_depth": max(
            queue_stats.get('max_depth', 0),
            processor_stats.get('max_queue_depth', 0)
        ),
        "queue_capacity": queue_stats.get('queue_capacity', 200000),
        "queue_utilization": queue_stats.get('utilization', 0.0),
        "queue_total_queued": queue_stats.get('total_queued', 0),
        "queue_total_dropped": queue_stats.get('total_dropped', 0),
        "queue_full_events": max(
            queue_stats.get('full_events', 0),
            processor_stats.get('queue_full_events', 0)
        ),
        
        # Detailed tracking (for specific IPs/OIDs)
        "blocked_ips": dict(_blocked_ip_counter),
        "blocked_oids": dict(_blocked_oid_counter),
        "redirected_ips": {
            tag: dict(counter) 
            for tag, counter in _redirected_ip_counter.items()
        },
        "redirected_oids": {
            tag: dict(counter) 
            for tag, counter in _redirected_oid_counter.items()
        },
        
        # HA status
        "ha": ha_stats,
        
        # Cache status
        "cache": cache_stats,
    }
    
    return summary


def reset_metrics():
    """Reset all metrics counters and save a snapshot first."""
    global _last_reset_time
    
    with _metrics_lock:
        # Save current metrics to a timestamped file before resetting
        try:
            import json
            config = get_current_config()
            current_metrics = get_metrics_summary()
            reset_file = os.path.join(
                config.directory,
                f"trapninja_metrics_{int(time.time())}.json"
            )
            with open(reset_file, 'w') as f:
                json.dump(current_metrics, f, indent=2)
            logger.info(f"Saved metrics snapshot to {reset_file} before reset")
        except Exception as e:
            logger.error(f"Failed to save metrics snapshot: {e}")
        
        # Reset detailed counters
        _blocked_ip_counter.clear()
        _blocked_oid_counter.clear()
        _redirected_ip_counter.clear()
        _redirected_oid_counter.clear()
        
        # Reset processor stats if available
        try:
            from ..processing.stats import reset_global_stats
            reset_global_stats()
        except ImportError:
            pass
        
        _last_reset_time = time.time()
        logger.info("All metrics have been reset")


def cleanup_metrics():
    """
    Clean up resources used by the metrics module.
    Should be called when shutting down.
    """
    global _export_timer

    # Cancel any pending export timer
    if _export_timer is not None:
        try:
            _export_timer.cancel()
        except Exception:
            pass
        _export_timer = None

    # Do a final export
    try:
        from .exporter import export_metrics
        export_metrics()
        logger.info("Final metrics export completed")
    except Exception as e:
        logger.error(f"Error during final metrics export: {e}")


# =============================================================================
# LEGACY COMPATIBILITY (for existing code that calls these)
# =============================================================================

def increment_trap_received():
    """Legacy function - stats now tracked in packet processor."""
    pass


def increment_trap_forwarded():
    """Legacy function - stats now tracked in packet processor."""
    pass


def reset_interval_counters():
    """Legacy function - not needed with unified metrics."""
    pass
