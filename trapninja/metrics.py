#!/usr/bin/env python3
"""
TrapNinja Metrics Module

Handles collection and export of metrics in Prometheus format for monitoring
blocked and redirected IPs and OIDs. Resets counters after each interval
to report rates rather than cumulative counts.
"""
import os
import time
import logging
import threading
import json
from collections import Counter, defaultdict
from datetime import datetime
from threading import Lock, Timer

# Get logger instance
logger = logging.getLogger("trapninja")

# Global variables for metrics
metrics_lock = Lock()
metrics_dir = "/var/log/trapninja/metrics"
metrics_file = "trapninja_metrics.prom"
metrics_interval = 60  # Export metrics every 60 seconds

# Counters for different metrics - these will be reset each interval
blocked_ip_counter = Counter()
blocked_oid_counter = Counter()
redirected_ip_counter = defaultdict(Counter)  # Maps tag -> Counter of IPs
redirected_oid_counter = defaultdict(Counter)  # Maps tag -> Counter of OIDs
total_traps_received = 0
total_traps_forwarded = 0
total_traps_blocked = 0
total_traps_redirected = 0

# Last reset timestamp
last_reset_time = time.time()

# Export timer reference
_export_timer = None


def init_metrics(metrics_directory=None, export_interval=None):
    """
    Initialize the metrics module

    Args:
        metrics_directory (str, optional): Directory to store metrics files
        export_interval (int, optional): Interval in seconds between metrics exports
    """
    global metrics_dir, metrics_interval

    # Update metrics directory if provided
    if metrics_directory:
        metrics_dir = metrics_directory

    # Update export interval if provided
    if export_interval:
        metrics_interval = export_interval

    # Create metrics directory if it doesn't exist
    try:
        if not os.path.exists(metrics_dir):
            os.makedirs(metrics_dir, exist_ok=True)
            logger.info(f"Created metrics directory: {metrics_dir}")
    except Exception as e:
        logger.error(f"Failed to create metrics directory: {e}")

    # Log initialization
    logger.info(f"Metrics module initialized with export interval of {metrics_interval} seconds")
    logger.info(f"Metrics will be exported to {os.path.join(metrics_dir, metrics_file)}")

    # Start the export timer
    schedule_metrics_export()


def schedule_metrics_export():
    """
    Schedule periodic export of metrics
    """
    global _export_timer

    try:
        from .config import stop_event
    except ImportError:
        # Create a dummy stop_event if not available
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


def increment_blocked_ip(ip_address):
    """
    Increment counter for a blocked IP address

    Args:
        ip_address (str): Blocked IP address
    """
    with metrics_lock:
        blocked_ip_counter[ip_address] += 1
        global total_traps_blocked
        total_traps_blocked += 1


def increment_blocked_oid(trap_oid):
    """
    Increment counter for a blocked OID

    Args:
        trap_oid (str): Blocked trap OID
    """
    with metrics_lock:
        blocked_oid_counter[trap_oid] += 1
        global total_traps_blocked
        total_traps_blocked += 1


def increment_redirected_ip(ip_address, tag):
    """
    Increment counter for a redirected IP address

    Args:
        ip_address (str): Redirected IP address
        tag (str): Redirection tag
    """
    with metrics_lock:
        redirected_ip_counter[tag][ip_address] += 1
        global total_traps_redirected
        total_traps_redirected += 1


def increment_redirected_oid(trap_oid, tag):
    """
    Increment counter for a redirected OID

    Args:
        trap_oid (str): Redirected trap OID
        tag (str): Redirection tag
    """
    with metrics_lock:
        redirected_oid_counter[tag][trap_oid] += 1
        global total_traps_redirected
        total_traps_redirected += 1


def increment_trap_received():
    """
    Increment counter for total traps received
    """
    with metrics_lock:
        global total_traps_received
        total_traps_received += 1


def increment_trap_forwarded():
    """
    Increment counter for total traps forwarded
    """
    with metrics_lock:
        global total_traps_forwarded
        total_traps_forwarded += 1


def get_metrics_summary():
    """
    Get a summary of current metrics

    Returns:
        dict: Dictionary with metrics summary
    """
    with metrics_lock:
        summary = {
            "timestamp": datetime.now().isoformat(),
            "total_traps_received": total_traps_received,
            "total_traps_forwarded": total_traps_forwarded,
            "total_traps_blocked": total_traps_blocked,
            "total_traps_redirected": total_traps_redirected,
            "blocked_ips": dict(blocked_ip_counter),
            "blocked_oids": dict(blocked_oid_counter),
            "redirected_ips": {tag: dict(counter) for tag, counter in redirected_ip_counter.items()},
            "redirected_oids": {tag: dict(counter) for tag, counter in redirected_oid_counter.items()},
            "interval_seconds": metrics_interval
        }
        return summary


def reset_metrics():
    """
    Reset all metrics counters
    """
    with metrics_lock:
        global total_traps_received, total_traps_forwarded, total_traps_blocked, total_traps_redirected
        global blocked_ip_counter, blocked_oid_counter, redirected_ip_counter, redirected_oid_counter
        global last_reset_time

        # Save current metrics to a timestamped file before resetting
        current_metrics = get_metrics_summary()
        try:
            reset_file = os.path.join(metrics_dir, f"trapninja_metrics_{int(time.time())}.json")
            with open(reset_file, 'w') as f:
                json.dump(current_metrics, f, indent=2)
            logger.info(f"Saved metrics snapshot to {reset_file} before reset")
        except Exception as e:
            logger.error(f"Failed to save metrics snapshot: {e}")

        # Reset counters
        blocked_ip_counter.clear()
        blocked_oid_counter.clear()
        redirected_ip_counter.clear()
        redirected_oid_counter.clear()
        total_traps_received = 0
        total_traps_forwarded = 0
        total_traps_blocked = 0
        total_traps_redirected = 0
        last_reset_time = time.time()

        logger.info("All metrics have been reset")


def format_prometheus(name, value, labels=None, help_text=None, metric_type="gauge"):
    """
    Format a metric in Prometheus format

    Args:
        name (str): Name of the metric
        value (int/float): Value of the metric
        labels (dict, optional): Labels for the metric
        help_text (str, optional): Help text for the metric
        metric_type (str): Type of metric ('gauge', 'counter', etc.)

    Returns:
        str: Metric in Prometheus format
    """
    lines = []

    # Add help text if provided
    if help_text:
        lines.append(f"# HELP {name} {help_text}")
        lines.append(f"# TYPE {name} {metric_type}")

    # Format the metric
    if labels:
        label_str = ",".join([f'{k}="{v}"' for k, v in labels.items()])
        lines.append(f"{name}{{{label_str}}} {value}")
    else:
        lines.append(f"{name} {value}")

    return "\n".join(lines)


def export_metrics():
    """
    Export metrics in Prometheus format and reset counters

    This function exports current metrics to Prometheus format file and
    also creates a JSON version for easier parsing. After exporting, it
    resets the counters for the next interval to ensure we're measuring
    rates rather than cumulative values.
    """
    try:
        # Get current metrics
        metrics = get_metrics_summary()

        # Prepare Prometheus formatted output
        lines = []

        # Add timestamp as a comment
        lines.append(f"# Timestamp: {metrics['timestamp']}")
        lines.append(f"# Export time: {datetime.now().isoformat()}")
        lines.append(f"# Interval: {metrics_interval} seconds")

        # Add global counters for the current interval (gauge metrics)
        lines.append(format_prometheus(
            "trapninja_traps_received",
            metrics["total_traps_received"],
            help_text=f"Number of SNMP traps received in the last {metrics_interval} seconds",
            metric_type="gauge"
        ))
        lines.append(format_prometheus(
            "trapninja_traps_forwarded",
            metrics["total_traps_forwarded"],
            help_text=f"Number of SNMP traps forwarded in the last {metrics_interval} seconds",
            metric_type="gauge"
        ))
        lines.append(format_prometheus(
            "trapninja_traps_blocked",
            metrics["total_traps_blocked"],
            help_text=f"Number of SNMP traps blocked in the last {metrics_interval} seconds",
            metric_type="gauge"
        ))
        lines.append(format_prometheus(
            "trapninja_traps_redirected",
            metrics["total_traps_redirected"],
            help_text=f"Number of SNMP traps redirected in the last {metrics_interval} seconds",
            metric_type="gauge"
        ))

        # Add blocked IP metrics (gauge - current interval)
        lines.append(
            "# HELP trapninja_blocked_ip Number of traps blocked from specific IP addresses in the last interval")
        lines.append("# TYPE trapninja_blocked_ip gauge")
        for ip, count in metrics["blocked_ips"].items():
            lines.append(format_prometheus(
                "trapninja_blocked_ip",
                count,
                labels={"ip": ip},
                metric_type="gauge"
            ))

        # Add blocked OID metrics (gauge - current interval)
        lines.append("# HELP trapninja_blocked_oid Number of traps blocked with specific OIDs in the last interval")
        lines.append("# TYPE trapninja_blocked_oid gauge")
        for oid, count in metrics["blocked_oids"].items():
            lines.append(format_prometheus(
                "trapninja_blocked_oid",
                count,
                labels={"oid": oid},
                metric_type="gauge"
            ))

        # Add redirected IP metrics (gauge - current interval)
        lines.append(
            "# HELP trapninja_redirected_ip Number of traps redirected from specific IP addresses in the last interval")
        lines.append("# TYPE trapninja_redirected_ip gauge")
        for tag, ip_counts in metrics["redirected_ips"].items():
            for ip, count in ip_counts.items():
                lines.append(format_prometheus(
                    "trapninja_redirected_ip",
                    count,
                    labels={"ip": ip, "tag": tag},
                    metric_type="gauge"
                ))

        # Add redirected OID metrics (gauge - current interval)
        lines.append(
            "# HELP trapninja_redirected_oid Number of traps redirected with specific OIDs in the last interval")
        lines.append("# TYPE trapninja_redirected_oid gauge")
        for tag, oid_counts in metrics["redirected_oids"].items():
            for oid, count in oid_counts.items():
                lines.append(format_prometheus(
                    "trapninja_redirected_oid",
                    count,
                    labels={"oid": oid, "tag": tag},
                    metric_type="gauge"
                ))

        # Add uptime and interval metrics
        uptime = time.time() - last_reset_time
        lines.append(format_prometheus(
            "trapninja_metrics_uptime_seconds",
            uptime,
            help_text="Time in seconds since metrics were last reset",
            metric_type="counter"
        ))
        lines.append(format_prometheus(
            "trapninja_metrics_interval_seconds",
            metrics_interval,
            help_text="Interval in seconds between metrics exports",
            metric_type="gauge"
        ))

        # Write to file
        metrics_path = os.path.join(metrics_dir, metrics_file)

        # Write to a temporary file first, then rename to ensure atomic update
        temp_path = f"{metrics_path}.tmp"
        with open(temp_path, 'w') as f:
            f.write("\n".join(lines))

        # Rename to the final file (atomic operation)
        os.rename(temp_path, metrics_path)

        logger.debug(f"Metrics exported to {metrics_path}")

        # Also write a JSON version for easier parsing
        json_path = os.path.join(metrics_dir, "trapninja_metrics.json")
        with open(json_path, 'w') as f:
            json.dump(metrics, f, indent=2)

        logger.debug(f"Metrics exported to JSON: {json_path}")

        # Reset counters for the next interval
        reset_interval_counters()

    except Exception as e:
        logger.error(f"Failed to export metrics: {e}")


def reset_interval_counters():
    """
    Reset counters for the next interval
    """
    with metrics_lock:
        global total_traps_received, total_traps_forwarded, total_traps_blocked, total_traps_redirected
        global blocked_ip_counter, blocked_oid_counter, redirected_ip_counter, redirected_oid_counter

        # Reset interval counters
        blocked_ip_counter.clear()
        blocked_oid_counter.clear()
        redirected_ip_counter.clear()
        redirected_oid_counter.clear()
        total_traps_received = 0
        total_traps_forwarded = 0
        total_traps_blocked = 0
        total_traps_redirected = 0

        logger.debug("Interval counters reset for next metrics period")


def cleanup_metrics():
    """
    Clean up resources used by the metrics module
    Should be called when shutting down
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
    except Exception as e:
        logger.error(f"Error during final metrics export: {e}")