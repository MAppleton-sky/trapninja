#!/usr/bin/env python3
"""
TrapNinja Metrics Exporter Module

Handles exporting collected metrics in various formats:
- Prometheus text format (.prom)
- JSON format (.json)

Supports global labels that are applied to all Prometheus metrics,
allowing for easy integration with multi-tenant monitoring systems.

Example output with global labels:
    trapninja_traps_received_total{on_prem="1",environment="production"} 12345
"""

import os
import json
import time
import logging
from typing import Dict, Any, Optional, List

logger = logging.getLogger("trapninja")


def format_prometheus(
    name: str,
    value: Any,
    labels: Dict[str, str] = None,
    global_labels: Dict[str, str] = None,
    help_text: str = None,
    metric_type: str = "gauge"
) -> str:
    """
    Format a metric in Prometheus format with support for global labels.

    Args:
        name: Name of the metric (should follow Prometheus naming conventions)
        value: Value of the metric (numeric)
        labels: Optional metric-specific labels
        global_labels: Optional global labels to prepend to all metrics
        help_text: Optional help text describing the metric
        metric_type: Type of metric ('gauge', 'counter', 'histogram', 'summary')

    Returns:
        str: Metric in Prometheus exposition format

    Example:
        >>> format_prometheus(
        ...     "trapninja_traps_total",
        ...     100,
        ...     labels={"type": "v2c"},
        ...     global_labels={"on_prem": "1"},
        ...     help_text="Total traps received",
        ...     metric_type="counter"
        ... )
        '# HELP trapninja_traps_total Total traps received\\n# TYPE trapninja_traps_total counter\\ntrapninja_traps_total{on_prem="1",type="v2c"} 100'
    """
    lines = []

    # Add HELP and TYPE comments
    if help_text:
        lines.append(f"# HELP {name} {help_text}")
        lines.append(f"# TYPE {name} {metric_type}")

    # Merge global labels with metric-specific labels
    # Global labels come first for consistent ordering
    all_labels = {}
    if global_labels:
        all_labels.update(global_labels)
    if labels:
        all_labels.update(labels)

    # Format the metric line
    if all_labels:
        # Sort labels for consistent output
        sorted_labels = sorted(all_labels.items())
        label_str = ",".join([f'{k}="{v}"' for k, v in sorted_labels])
        lines.append(f"{name}{{{label_str}}} {value}")
    else:
        lines.append(f"{name} {value}")

    return "\n".join(lines)


def _emit_counter(
    name: str,
    value: Any,
    created_ts: float,
    labels: Dict[str, str] = None,
    global_labels: Dict[str, str] = None,
    help_text: str = None,
) -> str:
    """
    Format a counter metric with its accompanying _created timestamp.

    The _created line anchors the counter's start time so Prometheus can
    detect resets and avoid producing false rate spikes after a restart.

    Args:
        name: Metric name (must end with _total by convention)
        value: Current counter value
        created_ts: Unix timestamp when the counter was last reset (process start)
        labels: Optional metric-specific labels
        global_labels: Optional global labels
        help_text: Optional help text

    Returns:
        str: HELP + TYPE + value line + _created line, joined with newlines
    """
    result_lines = []

    if help_text:
        result_lines.append(f"# HELP {name} {help_text}")
        result_lines.append(f"# TYPE {name} counter")

    all_labels = {}
    if global_labels:
        all_labels.update(global_labels)
    if labels:
        all_labels.update(labels)

    if all_labels:
        sorted_labels = sorted(all_labels.items())
        label_str = ",".join([f'{k}="{v}"' for k, v in sorted_labels])
        result_lines.append(f"{name}{{{label_str}}} {value}")
        result_lines.append(f"{name}_created{{{label_str}}} {created_ts:.3f}")
    else:
        result_lines.append(f"{name} {value}")
        result_lines.append(f"{name}_created {created_ts:.3f}")

    return "\n".join(result_lines)


def _format_labeled_metrics(
    base_name: str,
    label_name: str,
    counter_data: Dict[str, int],
    global_labels: Dict[str, str] = None,
    help_text: str = None,
    metric_type: str = "counter",
    additional_labels: Dict[str, str] = None
) -> List[str]:
    """
    Format a series of metrics with a common label dimension.

    Args:
        base_name: Base metric name
        label_name: Name of the varying label (e.g., "ip", "oid")
        counter_data: Dict mapping label values to counts
        global_labels: Global labels to apply
        help_text: Help text for the metric
        metric_type: Prometheus metric type
        additional_labels: Extra labels to add to all metrics

    Returns:
        List of formatted metric lines
    """
    if not counter_data:
        return []

    lines = []

    # Add HELP and TYPE once
    if help_text:
        lines.append(f"# HELP {base_name} {help_text}")
        lines.append(f"# TYPE {base_name} {metric_type}")

    # Format each metric
    for label_value, count in counter_data.items():
        # Build labels dict
        labels = {label_name: label_value}
        if additional_labels:
            labels.update(additional_labels)

        # Merge with global labels
        all_labels = {}
        if global_labels:
            all_labels.update(global_labels)
        all_labels.update(labels)

        # Sort for consistent output
        sorted_labels = sorted(all_labels.items())
        label_str = ",".join([f'{k}="{v}"' for k, v in sorted_labels])
        lines.append(f"{base_name}{{{label_str}}} {count}")

    return lines


def export_metrics(metrics_summary: Dict[str, Any] = None) -> bool:
    """
    Export metrics in Prometheus format with global labels.

    Collects metrics from all sources and writes to both
    Prometheus (.prom) and JSON formats.

    Args:
        metrics_summary: Optional pre-computed metrics. If not provided,
                        will collect current metrics.

    Returns:
        True if export succeeded, False otherwise
    """
    from .collector import get_metrics_summary, get_current_config

    try:
        # Get metrics if not provided
        if metrics_summary is None:
            metrics_summary = get_metrics_summary()

        # Get configuration
        config = get_current_config()
        global_labels = config.global_labels

        # The _created timestamp anchors all counters to process start time,
        # preventing Prometheus from computing false rate spikes on restart.
        metrics_start_time = metrics_summary.get("metrics_start_time", time.time())

        lines = []

        # Header comments
        lines.append(f"# TrapNinja Metrics Export")
        lines.append(f"# Timestamp: {metrics_summary['timestamp']}")
        lines.append(f"# Uptime: {metrics_summary['uptime_seconds']}s")

        if global_labels:
            labels_str = ", ".join(f"{k}={v}" for k, v in global_labels.items())
            lines.append(f"# Global Labels: {labels_str}")

        lines.append("")

        # =================================================================
        # CORE TRAP PROCESSING METRICS
        # =================================================================

        lines.append(_emit_counter(
            "trapninja_traps_received_total",
            metrics_summary["total_traps_received"],
            metrics_start_time,
            global_labels=global_labels,
            help_text="Total number of SNMP traps received",
        ))

        lines.append(_emit_counter(
            "trapninja_traps_forwarded_total",
            metrics_summary["total_traps_forwarded"],
            metrics_start_time,
            global_labels=global_labels,
            help_text="Total number of SNMP traps forwarded to destinations",
        ))

        lines.append(_emit_counter(
            "trapninja_traps_blocked_total",
            metrics_summary["total_traps_blocked"],
            metrics_start_time,
            global_labels=global_labels,
            help_text="Total number of SNMP traps blocked by IP or OID filters",
        ))

        lines.append(_emit_counter(
            "trapninja_traps_redirected_total",
            metrics_summary["total_traps_redirected"],
            metrics_start_time,
            global_labels=global_labels,
            help_text="Total number of SNMP traps redirected to alternate destinations",
        ))

        lines.append(_emit_counter(
            "trapninja_traps_dropped_total",
            metrics_summary["total_traps_dropped"],
            metrics_start_time,
            global_labels=global_labels,
            help_text="Total number of SNMP traps dropped due to queue full",
        ))

        lines.append(_emit_counter(
            "trapninja_processing_errors_total",
            metrics_summary["processing_errors"],
            metrics_start_time,
            global_labels=global_labels,
            help_text="Total number of packet processing errors",
        ))

        # =================================================================
        # SLIDING WINDOW METRICS (last 60 seconds) — Grafana-friendly gauges
        # =================================================================
        #
        # These are gauges representing trap counts over a rolling 60-second
        # window. Unlike the _total counters above, these give instant visibility
        # into current activity without requiring rate() calculations in Grafana.

        lines.append(format_prometheus(
            "trapninja_traps_received_60s",
            metrics_summary.get("window_60s_received", 0),
            global_labels=global_labels,
            help_text="Traps received in the last 60 seconds",
            metric_type="gauge"
        ))

        lines.append(format_prometheus(
            "trapninja_traps_forwarded_60s",
            metrics_summary.get("window_60s_forwarded", 0),
            global_labels=global_labels,
            help_text="Traps successfully forwarded in the last 60 seconds",
            metric_type="gauge"
        ))

        lines.append(format_prometheus(
            "trapninja_traps_dropped_60s",
            metrics_summary.get("window_60s_dropped", 0),
            global_labels=global_labels,
            help_text="Traps dropped (queue full) in the last 60 seconds",
            metric_type="gauge"
        ))

        lines.append(format_prometheus(
            "trapninja_processing_errors_60s",
            metrics_summary.get("window_60s_errors", 0),
            global_labels=global_labels,
            help_text="Processing errors in the last 60 seconds",
            metric_type="gauge"
        ))

        # =================================================================
        # HA METRICS
        # =================================================================

        lines.append(_emit_counter(
            "trapninja_ha_blocked_total",
            metrics_summary["ha_blocked"],
            metrics_start_time,
            global_labels=global_labels,
            help_text="Total traps not forwarded because node is in secondary mode",
        ))

        ha_info = metrics_summary.get("ha", {})
        lines.append(format_prometheus(
            "trapninja_ha_enabled",
            1 if ha_info.get('enabled', False) else 0,
            global_labels=global_labels,
            help_text="Whether HA clustering is enabled",
            metric_type="gauge"
        ))

        if ha_info.get('enabled', False):
            lines.append(format_prometheus(
                "trapninja_ha_is_primary",
                1 if ha_info.get('is_primary', False) else 0,
                global_labels=global_labels,
                help_text="Whether this node is the primary (1) or secondary (0)",
                metric_type="gauge"
            ))

            lines.append(format_prometheus(
                "trapninja_ha_is_forwarding",
                1 if ha_info.get('is_forwarding', False) else 0,
                global_labels=global_labels,
                help_text="Whether this node is actively forwarding traps",
                metric_type="gauge"
            ))

            lines.append(format_prometheus(
                "trapninja_ha_peer_connected",
                1 if ha_info.get('peer_connected', False) else 0,
                global_labels=global_labels,
                help_text="Whether the HA peer is connected",
                metric_type="gauge"
            ))

            lines.append(_emit_counter(
                "trapninja_ha_failover_count",
                ha_info.get('failover_count', 0),
                metrics_start_time,
                global_labels=global_labels,
                help_text="Number of HA failover events",
            ))

        # =================================================================
        # CACHE METRICS
        # =================================================================

        lines.append(_emit_counter(
            "trapninja_traps_cached_total",
            metrics_summary["traps_cached"],
            metrics_start_time,
            global_labels=global_labels,
            help_text="Total traps stored in cache for replay",
        ))

        lines.append(_emit_counter(
            "trapninja_cache_failures_total",
            metrics_summary["cache_failures"],
            metrics_start_time,
            global_labels=global_labels,
            help_text="Total cache storage failures",
        ))

        cache_info = metrics_summary.get("cache", {})
        lines.append(format_prometheus(
            "trapninja_cache_available",
            1 if cache_info.get('available', False) else 0,
            global_labels=global_labels,
            help_text="Whether cache backend (Redis) is available",
            metric_type="gauge"
        ))

        # =================================================================
        # PERFORMANCE METRICS
        # =================================================================

        lines.append(_emit_counter(
            "trapninja_fast_path_hits_total",
            metrics_summary["fast_path_hits"],
            metrics_start_time,
            global_labels=global_labels,
            help_text="Packets processed via optimized SNMPv2c fast path",
        ))

        lines.append(_emit_counter(
            "trapninja_slow_path_hits_total",
            metrics_summary["slow_path_hits"],
            metrics_start_time,
            global_labels=global_labels,
            help_text="Packets processed via full SNMP parsing",
        ))

        lines.append(format_prometheus(
            "trapninja_fast_path_ratio",
            round(metrics_summary["fast_path_ratio"], 2),
            global_labels=global_labels,
            help_text="Percentage of packets using fast path processing",
            metric_type="gauge"
        ))

        # =================================================================
        # QUEUE METRICS
        # =================================================================

        lines.append(format_prometheus(
            "trapninja_queue_depth",
            metrics_summary["queue_current_depth"],
            global_labels=global_labels,
            help_text="Current number of packets in processing queue",
            metric_type="gauge"
        ))

        lines.append(format_prometheus(
            "trapninja_queue_max_depth",
            metrics_summary["queue_max_depth"],
            global_labels=global_labels,
            help_text="Maximum queue depth observed",
            metric_type="gauge"
        ))

        lines.append(format_prometheus(
            "trapninja_queue_capacity",
            metrics_summary["queue_capacity"],
            global_labels=global_labels,
            help_text="Maximum queue capacity",
            metric_type="gauge"
        ))

        lines.append(format_prometheus(
            "trapninja_queue_utilization",
            round(metrics_summary["queue_utilization"], 4),
            global_labels=global_labels,
            help_text="Queue utilization ratio (0.0 to 1.0)",
            metric_type="gauge"
        ))

        lines.append(_emit_counter(
            "trapninja_queue_full_events_total",
            metrics_summary["queue_full_events"],
            metrics_start_time,
            global_labels=global_labels,
            help_text="Number of times queue reached capacity",
        ))

        # =================================================================
        # DETAILED IP/OID METRICS (if any tracked)
        # =================================================================

        # Blocked IP metrics
        blocked_ip_lines = _format_labeled_metrics(
            "trapninja_blocked_ip_count",
            "ip",
            metrics_summary.get("blocked_ips", {}),
            global_labels=global_labels,
            help_text="Traps blocked from specific IP",
            metric_type="counter"
        )
        lines.extend(blocked_ip_lines)

        # Blocked OID metrics
        blocked_oid_lines = _format_labeled_metrics(
            "trapninja_blocked_oid_count",
            "oid",
            metrics_summary.get("blocked_oids", {}),
            global_labels=global_labels,
            help_text="Traps blocked with specific OID",
            metric_type="counter"
        )
        lines.extend(blocked_oid_lines)

        # Redirected IP metrics (with tag dimension)
        redirected_ips = metrics_summary.get("redirected_ips", {})
        if redirected_ips:
            lines.append("# HELP trapninja_redirected_ip_count Traps redirected from specific IP")
            lines.append("# TYPE trapninja_redirected_ip_count counter")
            for tag, ip_counts in redirected_ips.items():
                for ip, count in ip_counts.items():
                    labels = {"ip": ip, "tag": tag}
                    all_labels = {}
                    if global_labels:
                        all_labels.update(global_labels)
                    all_labels.update(labels)
                    sorted_labels = sorted(all_labels.items())
                    label_str = ",".join([f'{k}="{v}"' for k, v in sorted_labels])
                    lines.append(f"trapninja_redirected_ip_count{{{label_str}}} {count}")

        # Redirected OID metrics (with tag dimension)
        redirected_oids = metrics_summary.get("redirected_oids", {})
        if redirected_oids:
            lines.append("# HELP trapninja_redirected_oid_count Traps redirected with specific OID")
            lines.append("# TYPE trapninja_redirected_oid_count counter")
            for tag, oid_counts in redirected_oids.items():
                for oid, count in oid_counts.items():
                    labels = {"oid": oid, "tag": tag}
                    all_labels = {}
                    if global_labels:
                        all_labels.update(global_labels)
                    all_labels.update(labels)
                    sorted_labels = sorted(all_labels.items())
                    label_str = ",".join([f'{k}="{v}"' for k, v in sorted_labels])
                    lines.append(f"trapninja_redirected_oid_count{{{label_str}}} {count}")

        # =================================================================
        # UPTIME METRIC
        # =================================================================

        lines.append(_emit_counter(
            "trapninja_uptime_seconds",
            round(metrics_summary["uptime_seconds"], 1),
            metrics_start_time,
            global_labels=global_labels,
            help_text="Time in seconds since service started",
        ))

        # =================================================================
        # WRITE OUTPUT FILES
        # =================================================================

        # Ensure metrics directory exists
        if not os.path.exists(config.directory):
            os.makedirs(config.directory, exist_ok=True)

        # Write Prometheus format file (atomic write)
        prom_path = config.prometheus_path
        temp_path = f"{prom_path}.tmp"

        with open(temp_path, 'w') as f:
            # Prometheus textfile format requires the file to end with a
            # blank line (two consecutive newlines after the last sample).
            # A single trailing \n only terminates the last line; node_exporter
            # requires \n\n to correctly close the final metric family.
            f.write("\n".join(lines))
            f.write("\n\n")

        os.rename(temp_path, prom_path)
        logger.debug(f"Metrics exported to {prom_path}")

        # Write JSON format file (if enabled)
        if config.json_enabled:
            json_path = config.json_path
            with open(json_path, 'w') as f:
                json.dump(metrics_summary, f, indent=2)

            logger.debug(f"Metrics exported to JSON: {json_path}")

        return True

    except Exception as e:
        logger.error(f"Failed to export metrics: {e}")
        import traceback
        logger.debug(traceback.format_exc())
        return False
