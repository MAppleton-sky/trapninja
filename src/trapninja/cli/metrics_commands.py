#!/usr/bin/env python3
"""
TrapNinja Metrics Commands Module

Handles CLI commands for managing metrics configuration:
- View current configuration
- Set metrics output directory
- Add/remove global labels
- Set export interval

Usage:
    python trapninja.py --metrics-config
    python trapninja.py --metrics-set-dir /opt/metrics
    python trapninja.py --metrics-add-label --label-name on_prem --label-value 1
    python trapninja.py --metrics-remove-label on_prem
    python trapninja.py --metrics-set-interval 30
"""

import os
import sys
import json
from typing import Optional


def show_metrics_config(json_output: bool = False) -> int:
    """
    Show current metrics configuration.
    
    Args:
        json_output: If True, output as JSON
        
    Returns:
        Exit code (0 for success)
    """
    from ..metrics import load_metrics_config, get_config_file_path
    
    config = load_metrics_config()
    config_file = get_config_file_path()
    file_exists = os.path.exists(config_file)
    
    if json_output:
        output = {
            'config_file': config_file,
            'file_exists': file_exists,
            **config.to_dict()
        }
        print(json.dumps(output, indent=2))
    else:
        print("\nTrapNinja Metrics Configuration")
        print("=" * 50)
        print(f"\nConfig File: {config_file}")
        print(f"File Exists: {'Yes' if file_exists else 'No (using defaults)'}")
        print(f"\nEnabled: {'Yes' if config.enabled else 'No'}")
        print(f"Output Directory: {config.directory}")
        print(f"Export Interval: {config.export_interval_seconds} seconds")
        print(f"\nPrometheus File: {config.prometheus_file}")
        print(f"  Full Path: {config.prometheus_path}")
        print(f"\nJSON File: {config.json_file}")
        print(f"  Full Path: {config.json_path}")
        
        print(f"\nGlobal Labels:")
        if config.global_labels:
            for name, value in sorted(config.global_labels.items()):
                print(f"  {name}: {value}")
        else:
            print("  (none configured)")
        
        print()
        
    return 0


def set_metrics_directory(directory: str) -> int:
    """
    Set the metrics output directory.
    
    Args:
        directory: Path to the metrics directory
        
    Returns:
        Exit code (0 for success, non-zero for failure)
    """
    from ..metrics import load_metrics_config, save_metrics_config, get_config_file_path
    
    # Validate directory path
    if not directory:
        print("Error: Directory path cannot be empty")
        return 1
    
    # Normalize the path
    directory = os.path.abspath(directory)
    
    # Load current config
    config = load_metrics_config()
    old_directory = config.directory
    
    # Update directory
    config.directory = directory
    
    # Try to create the directory if it doesn't exist
    if not os.path.exists(directory):
        try:
            os.makedirs(directory, exist_ok=True)
            print(f"Created directory: {directory}")
        except PermissionError:
            print(f"Warning: Cannot create directory {directory}")
            print("  You may need to create it manually with appropriate permissions.")
        except Exception as e:
            print(f"Warning: Failed to create directory: {e}")
    
    # Save configuration
    if save_metrics_config(config):
        print(f"\nMetrics directory updated:")
        print(f"  Old: {old_directory}")
        print(f"  New: {config.directory}")
        print(f"\nConfiguration saved to: {get_config_file_path()}")
        print("\nNote: Restart TrapNinja for changes to take effect.")
        return 0
    else:
        print("Error: Failed to save configuration")
        return 1


def add_metrics_label(label_name: str, label_value: str) -> int:
    """
    Add a global label to metrics.
    
    Args:
        label_name: Name of the label
        label_value: Value of the label
        
    Returns:
        Exit code (0 for success, non-zero for failure)
    """
    from ..metrics import load_metrics_config, save_metrics_config, get_config_file_path
    
    if not label_name:
        print("Error: --label-name is required")
        return 1
    
    if label_value is None:
        print("Error: --label-value is required")
        return 1
    
    # Load current config
    config = load_metrics_config()
    
    # Check if label already exists
    old_value = config.global_labels.get(label_name)
    
    # Add/update the label (sanitization happens in MetricsConfig)
    config.global_labels[label_name] = str(label_value)
    
    # Trigger re-validation via __post_init__
    from ..metrics import MetricsConfig
    config = MetricsConfig.from_dict(config.to_dict())
    
    # Save configuration
    if save_metrics_config(config):
        # Find the sanitized name
        sanitized_name = label_name
        for key in config.global_labels:
            if config.global_labels[key] == str(label_value):
                sanitized_name = key
                break
        
        if old_value is not None:
            print(f"\nLabel '{sanitized_name}' updated:")
            print(f"  Old value: {old_value}")
            print(f"  New value: {label_value}")
        else:
            print(f"\nLabel added: {sanitized_name}={label_value}")
        
        if sanitized_name != label_name:
            print(f"\nNote: Label name sanitized from '{label_name}' to '{sanitized_name}'")
        
        print(f"\nAll global labels:")
        for name, value in sorted(config.global_labels.items()):
            print(f"  {name}: {value}")
        
        print(f"\nConfiguration saved to: {get_config_file_path()}")
        print("Note: Restart TrapNinja for changes to take effect.")
        return 0
    else:
        print("Error: Failed to save configuration")
        return 1


def remove_metrics_label(label_name: str) -> int:
    """
    Remove a global label from metrics.
    
    Args:
        label_name: Name of the label to remove
        
    Returns:
        Exit code (0 for success, non-zero for failure)
    """
    from ..metrics import load_metrics_config, save_metrics_config, get_config_file_path
    
    if not label_name:
        print("Error: Label name cannot be empty")
        return 1
    
    # Load current config
    config = load_metrics_config()
    
    # Check if label exists
    if label_name not in config.global_labels:
        print(f"Error: Label '{label_name}' not found")
        print(f"\nCurrent labels:")
        if config.global_labels:
            for name, value in sorted(config.global_labels.items()):
                print(f"  {name}: {value}")
        else:
            print("  (none configured)")
        return 1
    
    # Remove the label
    old_value = config.global_labels.pop(label_name)
    
    # Save configuration
    if save_metrics_config(config):
        print(f"\nLabel removed: {label_name} (was: {old_value})")
        
        print(f"\nRemaining global labels:")
        if config.global_labels:
            for name, value in sorted(config.global_labels.items()):
                print(f"  {name}: {value}")
        else:
            print("  (none configured)")
        
        print(f"\nConfiguration saved to: {get_config_file_path()}")
        print("Note: Restart TrapNinja for changes to take effect.")
        return 0
    else:
        print("Error: Failed to save configuration")
        return 1


def set_export_interval(seconds: int) -> int:
    """
    Set the metrics export interval.
    
    Args:
        seconds: Export interval in seconds
        
    Returns:
        Exit code (0 for success, non-zero for failure)
    """
    from ..metrics import load_metrics_config, save_metrics_config, get_config_file_path
    
    if seconds < 1:
        print("Error: Export interval must be at least 1 second")
        return 1
    
    if seconds > 3600:
        print(f"Warning: Export interval of {seconds}s is very long")
        print("  Consider using a shorter interval for timely monitoring.")
    
    # Load current config
    config = load_metrics_config()
    old_interval = config.export_interval_seconds
    
    # Update interval
    config.export_interval_seconds = seconds
    
    # Save configuration
    if save_metrics_config(config):
        print(f"\nExport interval updated:")
        print(f"  Old: {old_interval} seconds")
        print(f"  New: {config.export_interval_seconds} seconds")
        print(f"\nConfiguration saved to: {get_config_file_path()}")
        print("Note: Restart TrapNinja for changes to take effect.")
        return 0
    else:
        print("Error: Failed to save configuration")
        return 1


def _get_metrics_from_file() -> Optional[dict]:
    """
    Read the live metrics summary from trapninja_metrics.json.

    Fallback path used when the daemon's control socket isn't reachable —
    mirrors the same daemon-then-file pattern stats_commands.py already
    uses for the granular stats file, applied to the main metrics file
    instead.
    """
    try:
        from ..metrics import load_metrics_config
        config = load_metrics_config()
        if not os.path.exists(config.json_path):
            return None
        with open(config.json_path) as f:
            return json.load(f)
    except Exception as e:
        print(f"Error reading metrics file: {e}")
        return None


def show_metrics_live(json_output: bool = False, pretty: bool = False) -> int:
    """
    Show live metrics, including the Phase 1 load-test diagnostics
    (pipeline latency percentiles, resource telemetry, capture-mode drop
    visibility) that exist in trapninja_metrics.json/.prom but have no
    other CLI surface.

    Tries the running daemon first via the control socket's existing
    service_status command (which already wraps get_metrics_summary()),
    falling back to reading trapninja_metrics.json directly if the daemon
    isn't reachable.

    Args:
        json_output: If True, print the raw metrics dict as JSON instead
            of the formatted summary
        pretty: If True and json_output, pretty-print the JSON

    Returns:
        Exit code (0 for success, 1 if no data could be retrieved)
    """
    from ..control import ControlSocket

    metrics = None

    try:
        response = ControlSocket.send_command('service_status')
        if response.get('status') == ControlSocket.SUCCESS:
            metrics = response.get('data', {}).get('metrics')
    except (ConnectionRefusedError, TimeoutError, OSError):
        pass
    except Exception:
        pass

    if metrics is None:
        metrics = _get_metrics_from_file()

    if not metrics:
        print("Error: Could not retrieve metrics.")
        print("Make sure TrapNinja is running, or check the metrics file at:")
        try:
            from ..metrics import load_metrics_config
            print(f"  {load_metrics_config().json_path}")
        except Exception:
            print("  (metrics directory not configured)")
        return 1

    if json_output:
        if pretty:
            print(json.dumps(metrics, indent=2, default=str))
        else:
            print(json.dumps(metrics, default=str))
        return 0

    _print_metrics_summary(metrics)
    return 0


def _print_metrics_summary(metrics: dict):
    """Pretty-print a metrics summary, with emphasis on the Phase 1 fields."""
    print("\n" + "=" * 70)
    print("  TrapNinja Live Metrics")
    print("=" * 70)
    ts = metrics.get('timestamp')
    if ts:
        print(f"  Snapshot: {ts}")
    print(f"  Uptime:   {metrics.get('uptime_seconds', 0):.0f}s\n")

    print("TRAP TOTALS:")
    print(f"  Received:    {metrics.get('total_traps_received', 0):>12,}")
    print(f"  Forwarded:   {metrics.get('total_traps_forwarded', 0):>12,}")
    print(f"  Blocked:     {metrics.get('total_traps_blocked', 0):>12,}")
    print(f"  Redirected:  {metrics.get('total_traps_redirected', 0):>12,}")
    print(f"  Dropped:     {metrics.get('total_traps_dropped', 0):>12,}")

    print("\nQUEUE:")
    print(f"  Current Depth:  {metrics.get('queue_current_depth', 0):>10,}")
    print(f"  Max Depth:      {metrics.get('queue_max_depth', 0):>10,}")
    print(f"  Capacity:       {metrics.get('queue_capacity', 0):>10,}")
    print(f"  Utilization:    {metrics.get('queue_utilization', 0):>10.1%}")

    pt = metrics.get('pipeline_timing') or {}
    qw = pt.get('queue_wait_seconds', {})
    pd = pt.get('processing_duration_seconds', {})
    print("\nPIPELINE LATENCY (load-test diagnostics):")
    if qw.get('samples', 0) > 0 or pd.get('samples', 0) > 0:
        print(f"  Queue Wait:        p50={qw.get('p50', 0) * 1000:.2f}ms  "
              f"p95={qw.get('p95', 0) * 1000:.2f}ms  "
              f"p99={qw.get('p99', 0) * 1000:.2f}ms  "
              f"max={qw.get('max', 0) * 1000:.2f}ms  "
              f"(n={qw.get('samples', 0)})")
        print(f"  Processing Time:   p50={pd.get('p50', 0) * 1000:.2f}ms  "
              f"p95={pd.get('p95', 0) * 1000:.2f}ms  "
              f"p99={pd.get('p99', 0) * 1000:.2f}ms  "
              f"max={pd.get('max', 0) * 1000:.2f}ms  "
              f"(n={pd.get('samples', 0)})")
    else:
        print("  No samples yet (instrumentation disabled, or no traps processed)")

    res = metrics.get('resource') or {}
    print("\nRESOURCE:")
    if 'rss_bytes' in res:
        print(f"  RSS:             {res['rss_bytes'] / (1024 * 1024):>10.1f} MB")
    if 'open_fds' in res:
        print(f"  Open FDs:        {res['open_fds']:>10,}")
    if 'gc_collections' in res:
        gc_str = ", ".join(
            f"gen{g}={c}" for g, c in sorted(res['gc_collections'].items())
        )
        print(f"  GC Collections:  {gc_str}")
    if not res:
        print("  (not available)")

    sd = metrics.get('socket_drops') or {}
    ebpf = metrics.get('ebpf') or {}
    print("\nCAPTURE-MODE DROP VISIBILITY:")
    if sd:
        print("  Socket mode — kernel-level UDP receive buffer drops (/proc/net/udp):")
        for port, drops in sorted(sd.items()):
            print(f"    Port {port}: {drops:,} drops")
    if ebpf:
        print("  eBPF/raw-capture mode:")
        if 'raw_socket_drops' in ebpf:
            print(f"    AF_PACKET raw socket drops (actual data-path loss): "
                  f"{ebpf['raw_socket_drops']:,}")
        if 'lost_samples' in ebpf:
            print(f"    Perf-buffer lost notifications (side channel, NOT "
                  f"trap loss): {ebpf['lost_samples']:,}")
    if not sd and not ebpf:
        print("  (no drop data — capture mode may not be active yet)")

    print()


def show_metrics_help() -> int:
    """
    Show comprehensive metrics configuration help.
    
    Returns:
        Exit code (0)
    """
    print("""
TrapNinja Metrics Configuration Help
=====================================

The metrics system exports statistics in Prometheus format with support for:
- Configurable output directory
- Global labels applied to ALL metrics
- Configurable export intervals

CONFIGURATION FILE
------------------
Location: /etc/trapninja/metrics_config.json (or your config directory)

Example configuration:
{
  "enabled": true,
  "directory": "/opt/metrics",
  "export_interval_seconds": 60,
  "prometheus_file": "trapninja_metrics.prom",
  "json_file": "trapninja_metrics.json",
  "global_labels": {
    "on_prem": "1",
    "environment": "production"
  }
}

CLI COMMANDS
------------

View current configuration:
  python trapninja.py --metrics-config
  python trapninja.py --metrics-config --json

Set output directory:
  python trapninja.py --metrics-set-dir /opt/metrics
  python trapninja.py --metrics-set-dir /var/lib/prometheus/textfile

Add global labels:
  python trapninja.py --metrics-add-label --label-name on_prem --label-value 1
  python trapninja.py --metrics-add-label --label-name environment --label-value production
  python trapninja.py --metrics-add-label --label-name datacenter --label-value dc1

Remove global labels:
  python trapninja.py --metrics-remove-label on_prem
  python trapninja.py --metrics-remove-label environment

Set export interval:
  python trapninja.py --metrics-set-interval 30   # Export every 30 seconds
  python trapninja.py --metrics-set-interval 120  # Export every 2 minutes

GLOBAL LABELS
-------------
Global labels are applied to EVERY Prometheus metric, enabling:
- Multi-tenant monitoring (distinguish on-prem vs cloud)
- Environment tagging (dev/staging/production)
- Datacenter or region identification
- Custom organizational tags

Example output WITH labels:
  trapninja_traps_received_total{environment="production",on_prem="1"} 12345

Example output WITHOUT labels:
  trapninja_traps_received_total 12345

Label naming rules:
- Must start with letter or underscore
- Can contain only letters, numbers, and underscores
- Invalid characters are automatically replaced with underscores

PROMETHEUS INTEGRATION
----------------------
Use the Node Exporter textfile collector to scrape metrics:

1. Configure Node Exporter:
   node_exporter --collector.textfile.directory=/opt/metrics

2. Add to prometheus.yml:
   scrape_configs:
     - job_name: 'trapninja'
       static_configs:
         - targets: ['trapninja-server:9100']

3. Query with labels in Prometheus/Grafana:
   trapninja_traps_received_total{on_prem="1"}
   sum by (environment) (rate(trapninja_traps_forwarded_total[5m]))

DIRECTORY PERMISSIONS
---------------------
Ensure the metrics directory is writable by TrapNinja:
  sudo mkdir -p /opt/metrics
  sudo chown trapninja:trapninja /opt/metrics
  sudo chmod 755 /opt/metrics

For more information, see the METRICS.md documentation.
""")
    return 0
