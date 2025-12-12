#!/usr/bin/env python3
"""
TrapNinja Metrics Module - Unified Metrics Collection

Collects metrics from all processing components and exports in Prometheus format.
Integrates with:
- packet_processor.py (AtomicStats)
- processing/stats.py (ProcessingStats)
- network.py (QueueStats)
- HA cluster (if enabled)
- Cache system (if enabled)

Exports metrics to /var/log/trapninja/metrics/ in both Prometheus (.prom)
and JSON formats for monitoring system integration.

Author: TrapNinja Team
Version: 2.1.0
"""
import os
import time
import logging
import threading
import json
from collections import Counter, defaultdict
from datetime import datetime
from threading import Lock, Timer
from typing import Dict, Any, Optional

# Get logger instance
logger = logging.getLogger("trapninja")

# Global variables for metrics configuration
metrics_lock = Lock()
metrics_dir = "/var/log/trapninja/metrics"
metrics_file = "trapninja_metrics.prom"
metrics_interval = 60  # Export metrics every 60 seconds

# Detailed counters for filtering/redirection tracking
# These track specific IPs and OIDs that are blocked/redirected
blocked_ip_counter = Counter()
blocked_oid_counter = Counter()
redirected_ip_counter = defaultdict(Counter)  # Maps tag -> Counter of IPs
redirected_oid_counter = defaultdict(Counter)  # Maps tag -> Counter of OIDs

# Last reset timestamp
last_reset_time = time.time()
_start_time = time.time()

# Export timer reference
_export_timer = None
_initialized = False


def init_metrics(metrics_directory: str = None, export_interval: int = None):
    """
    Initialize the metrics module.

    Args:
        metrics_directory: Directory to store metrics files
        export_interval: Interval in seconds between metrics exports
    """
    global metrics_dir, metrics_interval, _initialized, _start_time

    if metrics_directory:
        metrics_dir = metrics_directory

    if export_interval:
        metrics_interval = export_interval

    # Create metrics directory if it doesn't exist
    try:
        if not os.path.exists(metrics_dir):
            os.makedirs(metrics_dir, exist_ok=True)
            logger.info(f"Created metrics directory: {metrics_dir}")
    except Exception as e:
        logger.error(f"Failed to create metrics directory: {e}")

    _start_time = time.time()
    _initialized = True

    logger.info(f"Metrics module initialized with export interval of {metrics_interval}s")
    logger.info(f"Metrics will be exported to {os.path.join(metrics_dir, metrics_file)}")

    # Start the export timer
    schedule_metrics_export()


def schedule_metrics_export():
    """Schedule periodic export of metrics."""
    global _export_timer

    try:
        from .config import stop_event
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
    export_metrics()

    # Schedule next export if not stopping
    if not stop_event.is_set():
        _export_timer = Timer(metrics_interval, schedule_metrics_export)
        _export_timer.daemon = True
        _export_timer.start()


# =============================================================================
# DETAILED TRACKING FUNCTIONS (for IP/OID specific metrics)
# =============================================================================

def increment_blocked_ip(ip_address: str):
    """
    Track a blocked IP address for detailed metrics.

    Args:
        ip_address: Blocked IP address
    """
    with metrics_lock:
        blocked_ip_counter[ip_address] += 1


def increment_blocked_oid(trap_oid: str):
    """
    Track a blocked OID for detailed metrics.

    Args:
        trap_oid: Blocked trap OID
    """
    with metrics_lock:
        blocked_oid_counter[trap_oid] += 1


def increment_redirected_ip(ip_address: str, tag: str):
    """
    Track a redirected IP address for detailed metrics.

    Args:
        ip_address: Redirected IP address
        tag: Redirection tag/destination group
    """
    with metrics_lock:
        redirected_ip_counter[tag][ip_address] += 1


def increment_redirected_oid(trap_oid: str, tag: str):
    """
    Track a redirected OID for detailed metrics.

    Args:
        trap_oid: Redirected trap OID
        tag: Redirection tag/destination group
    """
    with metrics_lock:
        redirected_oid_counter[tag][trap_oid] += 1


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
        from .packet_processor import get_processor_stats
        return get_processor_stats()
    except ImportError:
        pass
    
    # Try the processing module as fallback
    try:
        from .processing.stats import get_global_stats
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
        from .network import get_queue_stats
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
        from .ha import get_ha_cluster
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
        from .cache import get_cache
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


def get_metrics_summary() -> Dict[str, Any]:
    """
    Get a comprehensive summary of all metrics from all sources.

    Returns:
        dict: Dictionary with complete metrics summary
    """
    # Get processor stats (main source of trap counts)
    processor_stats = _get_processor_stats()
    
    # Get queue stats
    queue_stats = _get_queue_stats()
    
    # Get HA stats
    ha_stats = _get_ha_stats()
    
    # Get cache stats
    cache_stats = _get_cache_stats()
    
    # Calculate uptime
    uptime = time.time() - _start_time
    
    # Build summary from processor stats
    summary = {
        "timestamp": datetime.now().isoformat(),
        "uptime_seconds": round(uptime, 1),
        "interval_seconds": metrics_interval,
        
        # Core trap processing metrics (from packet processor)
        "total_traps_received": processor_stats.get('processed', 0),
        "total_traps_forwarded": processor_stats.get('forwarded', 0),
        "total_traps_blocked": processor_stats.get('blocked', 0),
        "total_traps_redirected": processor_stats.get('redirected', 0),
        "total_traps_dropped": processor_stats.get('dropped', 0),
        "processing_errors": processor_stats.get('errors', 0),
        
        # HA-specific metrics
        "ha_blocked": processor_stats.get('ha_blocked', 0),
        
        # Cache metrics
        "traps_cached": processor_stats.get('cached', 0),
        "cache_failures": processor_stats.get('cache_failures', 0),
        
        # Performance metrics
        "fast_path_hits": processor_stats.get('fast_path_hits', 0),
        "slow_path_hits": processor_stats.get('slow_path_hits', 0),
        "fast_path_ratio": processor_stats.get('fast_path_ratio', 0.0),
        "processing_rate": processor_stats.get('processing_rate', 0.0),
        
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
        "blocked_ips": dict(blocked_ip_counter),
        "blocked_oids": dict(blocked_oid_counter),
        "redirected_ips": {tag: dict(counter) for tag, counter in redirected_ip_counter.items()},
        "redirected_oids": {tag: dict(counter) for tag, counter in redirected_oid_counter.items()},
        
        # HA status
        "ha": ha_stats,
        
        # Cache status
        "cache": cache_stats,
    }
    
    return summary


def reset_metrics():
    """Reset all metrics counters and save a snapshot first."""
    with metrics_lock:
        global last_reset_time
        
        # Save current metrics to a timestamped file before resetting
        try:
            current_metrics = get_metrics_summary()
            reset_file = os.path.join(metrics_dir, f"trapninja_metrics_{int(time.time())}.json")
            with open(reset_file, 'w') as f:
                json.dump(current_metrics, f, indent=2)
            logger.info(f"Saved metrics snapshot to {reset_file} before reset")
        except Exception as e:
            logger.error(f"Failed to save metrics snapshot: {e}")
        
        # Reset detailed counters
        blocked_ip_counter.clear()
        blocked_oid_counter.clear()
        redirected_ip_counter.clear()
        redirected_oid_counter.clear()
        
        # Reset processor stats if available
        try:
            from .packet_processor import reset_processor_stats
            reset_processor_stats()
        except ImportError:
            pass
        
        try:
            from .processing.stats import reset_global_stats
            reset_global_stats()
        except ImportError:
            pass
        
        last_reset_time = time.time()
        logger.info("All metrics have been reset")


def format_prometheus(name: str, value: Any, labels: Dict[str, str] = None,
                      help_text: str = None, metric_type: str = "gauge") -> str:
    """
    Format a metric in Prometheus format.

    Args:
        name: Name of the metric
        value: Value of the metric
        labels: Optional labels for the metric
        help_text: Optional help text
        metric_type: Type of metric ('gauge', 'counter', etc.)

    Returns:
        str: Metric in Prometheus format
    """
    lines = []

    if help_text:
        lines.append(f"# HELP {name} {help_text}")
        lines.append(f"# TYPE {name} {metric_type}")

    if labels:
        label_str = ",".join([f'{k}="{v}"' for k, v in labels.items()])
        lines.append(f"{name}{{{label_str}}} {value}")
    else:
        lines.append(f"{name} {value}")

    return "\n".join(lines)


def export_metrics():
    """
    Export metrics in Prometheus format.
    
    Collects metrics from all sources and writes to both
    Prometheus (.prom) and JSON formats.
    """
    try:
        metrics = get_metrics_summary()
        lines = []

        # Header comments
        lines.append(f"# TrapNinja Metrics Export")
        lines.append(f"# Timestamp: {metrics['timestamp']}")
        lines.append(f"# Uptime: {metrics['uptime_seconds']}s")
        lines.append("")

        # =================================================================
        # CORE TRAP PROCESSING METRICS
        # =================================================================
        
        lines.append(format_prometheus(
            "trapninja_traps_received_total",
            metrics["total_traps_received"],
            help_text="Total number of SNMP traps received",
            metric_type="counter"
        ))
        
        lines.append(format_prometheus(
            "trapninja_traps_forwarded_total",
            metrics["total_traps_forwarded"],
            help_text="Total number of SNMP traps forwarded to destinations",
            metric_type="counter"
        ))
        
        lines.append(format_prometheus(
            "trapninja_traps_blocked_total",
            metrics["total_traps_blocked"],
            help_text="Total number of SNMP traps blocked by IP or OID filters",
            metric_type="counter"
        ))
        
        lines.append(format_prometheus(
            "trapninja_traps_redirected_total",
            metrics["total_traps_redirected"],
            help_text="Total number of SNMP traps redirected to alternate destinations",
            metric_type="counter"
        ))
        
        lines.append(format_prometheus(
            "trapninja_traps_dropped_total",
            metrics["total_traps_dropped"],
            help_text="Total number of SNMP traps dropped due to queue full",
            metric_type="counter"
        ))
        
        lines.append(format_prometheus(
            "trapninja_processing_errors_total",
            metrics["processing_errors"],
            help_text="Total number of packet processing errors",
            metric_type="counter"
        ))

        # =================================================================
        # HA METRICS
        # =================================================================
        
        lines.append(format_prometheus(
            "trapninja_ha_blocked_total",
            metrics["ha_blocked"],
            help_text="Total traps not forwarded because node is in secondary mode",
            metric_type="counter"
        ))
        
        ha_info = metrics.get("ha", {})
        lines.append(format_prometheus(
            "trapninja_ha_enabled",
            1 if ha_info.get('enabled', False) else 0,
            help_text="Whether HA clustering is enabled",
            metric_type="gauge"
        ))
        
        if ha_info.get('enabled', False):
            lines.append(format_prometheus(
                "trapninja_ha_is_primary",
                1 if ha_info.get('is_primary', False) else 0,
                help_text="Whether this node is the primary (1) or secondary (0)",
                metric_type="gauge"
            ))
            
            lines.append(format_prometheus(
                "trapninja_ha_is_forwarding",
                1 if ha_info.get('is_forwarding', False) else 0,
                help_text="Whether this node is actively forwarding traps",
                metric_type="gauge"
            ))
            
            lines.append(format_prometheus(
                "trapninja_ha_peer_connected",
                1 if ha_info.get('peer_connected', False) else 0,
                help_text="Whether the HA peer is connected",
                metric_type="gauge"
            ))
            
            lines.append(format_prometheus(
                "trapninja_ha_failover_count",
                ha_info.get('failover_count', 0),
                help_text="Number of HA failover events",
                metric_type="counter"
            ))

        # =================================================================
        # CACHE METRICS
        # =================================================================
        
        lines.append(format_prometheus(
            "trapninja_traps_cached_total",
            metrics["traps_cached"],
            help_text="Total traps stored in cache for replay",
            metric_type="counter"
        ))
        
        lines.append(format_prometheus(
            "trapninja_cache_failures_total",
            metrics["cache_failures"],
            help_text="Total cache storage failures",
            metric_type="counter"
        ))
        
        cache_info = metrics.get("cache", {})
        lines.append(format_prometheus(
            "trapninja_cache_available",
            1 if cache_info.get('available', False) else 0,
            help_text="Whether cache backend (Redis) is available",
            metric_type="gauge"
        ))

        # =================================================================
        # PERFORMANCE METRICS
        # =================================================================
        
        lines.append(format_prometheus(
            "trapninja_fast_path_hits_total",
            metrics["fast_path_hits"],
            help_text="Packets processed via optimized SNMPv2c fast path",
            metric_type="counter"
        ))
        
        lines.append(format_prometheus(
            "trapninja_slow_path_hits_total",
            metrics["slow_path_hits"],
            help_text="Packets processed via full SNMP parsing",
            metric_type="counter"
        ))
        
        lines.append(format_prometheus(
            "trapninja_fast_path_ratio",
            round(metrics["fast_path_ratio"], 2),
            help_text="Percentage of packets using fast path processing",
            metric_type="gauge"
        ))
        
        lines.append(format_prometheus(
            "trapninja_processing_rate",
            round(metrics["processing_rate"], 2),
            help_text="Current packet processing rate (packets/second)",
            metric_type="gauge"
        ))

        # =================================================================
        # QUEUE METRICS
        # =================================================================
        
        lines.append(format_prometheus(
            "trapninja_queue_depth",
            metrics["queue_current_depth"],
            help_text="Current number of packets in processing queue",
            metric_type="gauge"
        ))
        
        lines.append(format_prometheus(
            "trapninja_queue_max_depth",
            metrics["queue_max_depth"],
            help_text="Maximum queue depth observed",
            metric_type="gauge"
        ))
        
        lines.append(format_prometheus(
            "trapninja_queue_capacity",
            metrics["queue_capacity"],
            help_text="Maximum queue capacity",
            metric_type="gauge"
        ))
        
        lines.append(format_prometheus(
            "trapninja_queue_utilization",
            round(metrics["queue_utilization"], 4),
            help_text="Queue utilization ratio (0.0 to 1.0)",
            metric_type="gauge"
        ))
        
        lines.append(format_prometheus(
            "trapninja_queue_full_events_total",
            metrics["queue_full_events"],
            help_text="Number of times queue reached capacity",
            metric_type="counter"
        ))

        # =================================================================
        # DETAILED IP/OID METRICS (if any tracked)
        # =================================================================
        
        # Blocked IP metrics
        if metrics["blocked_ips"]:
            lines.append("# HELP trapninja_blocked_ip_count Traps blocked from specific IP")
            lines.append("# TYPE trapninja_blocked_ip_count counter")
            for ip, count in metrics["blocked_ips"].items():
                lines.append(f'trapninja_blocked_ip_count{{ip="{ip}"}} {count}')

        # Blocked OID metrics
        if metrics["blocked_oids"]:
            lines.append("# HELP trapninja_blocked_oid_count Traps blocked with specific OID")
            lines.append("# TYPE trapninja_blocked_oid_count counter")
            for oid, count in metrics["blocked_oids"].items():
                lines.append(f'trapninja_blocked_oid_count{{oid="{oid}"}} {count}')

        # Redirected IP metrics
        if metrics["redirected_ips"]:
            lines.append("# HELP trapninja_redirected_ip_count Traps redirected from specific IP")
            lines.append("# TYPE trapninja_redirected_ip_count counter")
            for tag, ip_counts in metrics["redirected_ips"].items():
                for ip, count in ip_counts.items():
                    lines.append(f'trapninja_redirected_ip_count{{ip="{ip}",tag="{tag}"}} {count}')

        # Redirected OID metrics
        if metrics["redirected_oids"]:
            lines.append("# HELP trapninja_redirected_oid_count Traps redirected with specific OID")
            lines.append("# TYPE trapninja_redirected_oid_count counter")
            for tag, oid_counts in metrics["redirected_oids"].items():
                for oid, count in oid_counts.items():
                    lines.append(f'trapninja_redirected_oid_count{{oid="{oid}",tag="{tag}"}} {count}')

        # =================================================================
        # UPTIME METRIC
        # =================================================================
        
        lines.append(format_prometheus(
            "trapninja_uptime_seconds",
            round(metrics["uptime_seconds"], 1),
            help_text="Time in seconds since service started",
            metric_type="counter"
        ))

        # Write Prometheus format file
        metrics_path = os.path.join(metrics_dir, metrics_file)
        temp_path = f"{metrics_path}.tmp"
        
        with open(temp_path, 'w') as f:
            f.write("\n".join(lines))
        
        os.rename(temp_path, metrics_path)
        logger.debug(f"Metrics exported to {metrics_path}")

        # Write JSON format file
        json_path = os.path.join(metrics_dir, "trapninja_metrics.json")
        with open(json_path, 'w') as f:
            json.dump(metrics, f, indent=2)
        
        logger.debug(f"Metrics exported to JSON: {json_path}")

    except Exception as e:
        logger.error(f"Failed to export metrics: {e}")
        import traceback
        logger.debug(traceback.format_exc())


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
