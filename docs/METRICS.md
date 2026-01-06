# TrapNinja Metrics System

## Overview

TrapNinja provides comprehensive metrics collection and export in Prometheus format for monitoring system integration. The metrics system collects data from all processing components and exports it in both Prometheus (`.prom`) and JSON formats.

**Key Features:**
- Configurable output directory for metrics files
- Global labels/tags applied to all Prometheus metrics
- Configurable export intervals
- Integration with Prometheus via Node Exporter textfile collector

## Architecture

The unified metrics system integrates with multiple data sources:

```
┌─────────────────────────────────────────────────────────────────┐
│                     Metrics Package                             │
│            (trapninja/metrics/__init__.py)                      │
│                                                                 │
│  ┌───────────────┐ ┌───────────────┐ ┌───────────────────────┐  │
│  │ config.py     │ │ collector.py  │ │ exporter.py           │  │
│  │ Configuration │ │ Data          │ │ Prometheus/JSON       │  │
│  │ Management    │ │ Aggregation   │ │ Output                │  │
│  └───────────────┘ └───────────────┘ └───────────────────────┘  │
│           │                │                    │                │
│           ▼                ▼                    ▼                │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ Data Sources:                                              │  │
│  │ • Packet Processor (AtomicStats)                          │  │
│  │ • Network Module (QueueStats)                             │  │
│  │ • HA Cluster (if enabled)                                 │  │
│  │ • Cache System (if enabled)                               │  │
│  │ • Detailed IP/OID Tracking                                │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
              ┌───────────────────────────────────┐
              │  Configurable Output Directory    │
              │  (default: /var/log/trapninja/metrics)│
              │                                   │
              │  trapninja_metrics.prom           │
              │  trapninja_metrics.json           │
              └───────────────────────────────────┘
```

## Configuration

The metrics system is configured via `metrics_config.json` in your TrapNinja configuration directory.

### Configuration File Location

The configuration file should be placed alongside other TrapNinja config files:
- `/etc/trapninja/metrics_config.json` (production)
- `config/metrics_config.json` (development)

### Configuration Options

```json
{
  "enabled": true,
  "directory": "/opt/metrics",
  "export_interval_seconds": 60,
  "prometheus_file": "trapninja_metrics.prom",
  "json_file": "trapninja_metrics.json",
  "global_labels": {
    "on_prem": "1",
    "environment": "production",
    "datacenter": "dc1"
  }
}
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | boolean | `true` | Enable/disable metrics collection |
| `directory` | string | `/var/log/trapninja/metrics` | Directory for metrics files |
| `export_interval_seconds` | integer | `60` | How often to export metrics (seconds) |
| `prometheus_file` | string | `trapninja_metrics.prom` | Prometheus metrics filename |
| `json_file` | string | `trapninja_metrics.json` | JSON metrics filename |
| `global_labels` | object | `{}` | Labels applied to ALL metrics |

### Global Labels

Global labels are applied to **every** Prometheus metric, making it easy to:
- Distinguish between on-prem and cloud deployments
- Identify environment (dev/staging/production)
- Tag by datacenter, region, or cluster
- Support multi-tenant monitoring

**Example output with global labels:**
```
# HELP trapninja_traps_received_total Total number of SNMP traps received
# TYPE trapninja_traps_received_total counter
trapninja_traps_received_total{environment="production",on_prem="1"} 12345
```

**Important notes on global labels:**
- Label names must be Prometheus-compliant (start with letter/underscore, contain only alphanumeric/underscore)
- Invalid characters are automatically converted to underscores
- Values are always strings

### Example Configurations

**On-Premises Production:**
```json
{
  "enabled": true,
  "directory": "/opt/metrics",
  "export_interval_seconds": 60,
  "global_labels": {
    "on_prem": "1",
    "environment": "production",
    "site": "datacenter-east"
  }
}
```

**Cloud/Test Environment:**
```json
{
  "enabled": true,
  "directory": "/var/log/trapninja/metrics",
  "export_interval_seconds": 30,
  "global_labels": {
    "on_prem": "0",
    "environment": "staging",
    "cloud_provider": "aws",
    "region": "us-east-1"
  }
}
```

**High-Frequency Export (for debugging):**
```json
{
  "enabled": true,
  "directory": "/tmp/trapninja-metrics",
  "export_interval_seconds": 10,
  "global_labels": {
    "debug": "1"
  }
}
```

## Available Metrics

All metrics include any configured global labels.

### Core Packet Processing Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `trapninja_traps_received_total` | counter | Total SNMP traps received |
| `trapninja_traps_forwarded_total` | counter | Total traps forwarded to destinations |
| `trapninja_traps_blocked_total` | counter | Total traps blocked by IP or OID filters |
| `trapninja_traps_redirected_total` | counter | Total traps redirected to alternate destinations |
| `trapninja_traps_dropped_total` | counter | Total traps dropped due to queue full |
| `trapninja_processing_errors_total` | counter | Total packet processing errors |

### High Availability Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `trapninja_ha_blocked_total` | counter | Traps not forwarded because node is secondary |
| `trapninja_ha_enabled` | gauge | Whether HA clustering is enabled (1/0) |
| `trapninja_ha_is_primary` | gauge | Whether this node is primary (1/0) |
| `trapninja_ha_is_forwarding` | gauge | Whether actively forwarding traps (1/0) |
| `trapninja_ha_peer_connected` | gauge | Whether HA peer is connected (1/0) |
| `trapninja_ha_failover_count` | counter | Number of HA failover events |

### Cache Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `trapninja_traps_cached_total` | counter | Total traps stored in cache for replay |
| `trapninja_cache_failures_total` | counter | Total cache storage failures |
| `trapninja_cache_available` | gauge | Whether Redis cache is available (1/0) |

### Performance Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `trapninja_fast_path_hits_total` | counter | Packets using optimized SNMPv2c fast path |
| `trapninja_slow_path_hits_total` | counter | Packets requiring full SNMP parsing |
| `trapninja_fast_path_ratio` | gauge | Percentage of packets using fast path |
| `trapninja_processing_rate` | gauge | Current processing rate (packets/second) |

### Queue Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `trapninja_queue_depth` | gauge | Current packets in processing queue |
| `trapninja_queue_max_depth` | gauge | Maximum queue depth observed |
| `trapninja_queue_capacity` | gauge | Maximum queue capacity |
| `trapninja_queue_utilization` | gauge | Queue utilization ratio (0.0-1.0) |
| `trapninja_queue_full_events_total` | counter | Times queue reached capacity |

### Detailed Tracking Metrics

These metrics include both global labels AND metric-specific labels:

| Metric | Labels | Description |
|--------|--------|-------------|
| `trapninja_blocked_ip_count` | `ip` + global | Traps blocked from specific IP |
| `trapninja_blocked_oid_count` | `oid` + global | Traps blocked with specific OID |
| `trapninja_redirected_ip_count` | `ip`, `tag` + global | Traps redirected from specific IP |
| `trapninja_redirected_oid_count` | `oid`, `tag` + global | Traps redirected with specific OID |

**Example with global labels:**
```
trapninja_blocked_ip_count{environment="production",ip="10.0.0.100",on_prem="1"} 50
```

### Uptime Metric

| Metric | Type | Description |
|--------|------|-------------|
| `trapninja_uptime_seconds` | counter | Time since service started |

## Prometheus Integration

### Using Node Exporter Textfile Collector

The recommended approach for Prometheus integration is using the Node Exporter textfile collector.

1. **Configure Node Exporter** with your metrics directory:
   ```bash
   # If using default directory
   node_exporter --collector.textfile.directory=/var/log/trapninja/metrics
   
   # If using custom directory (e.g., /opt/metrics)
   node_exporter --collector.textfile.directory=/opt/metrics
   ```

2. **Add to Prometheus config** (`prometheus.yml`):
   ```yaml
   scrape_configs:
     - job_name: 'trapninja'
       static_configs:
         - targets: ['trapninja-server:9100']
       metric_relabel_configs:
         - source_labels: [__name__]
           regex: 'trapninja_.*'
           action: keep
   ```

### Filtering by Global Labels

With global labels configured, you can easily filter and aggregate metrics:

```promql
# Get metrics only from on-prem deployments
trapninja_traps_received_total{on_prem="1"}

# Filter by environment
sum(trapninja_traps_forwarded_total{environment="production"})

# Compare across datacenters
sum by (datacenter) (rate(trapninja_traps_received_total[5m]))
```

### Example Grafana Dashboard Queries

**Processing Rate by Environment:**
```promql
sum by (environment) (rate(trapninja_traps_received_total[5m]))
```

**Fast Path Efficiency:**
```promql
trapninja_fast_path_ratio{on_prem="1"}
```

**Queue Utilization Across Sites:**
```promql
trapninja_queue_utilization * 100
```

**HA Status Dashboard:**
```promql
# Show which servers are primary
trapninja_ha_is_primary == 1
```

**Blocked Traps by IP (Top 10):**
```promql
topk(10, trapninja_blocked_ip_count)
```

## Programmatic Configuration

You can also configure metrics programmatically:

```python
from trapninja.metrics import init_metrics, MetricsConfig

# Using MetricsConfig object
config = MetricsConfig(
    enabled=True,
    directory="/opt/metrics",
    export_interval_seconds=60,
    global_labels={
        "on_prem": "1",
        "environment": "production"
    }
)
init_metrics(config=config)

# Or using individual parameters
init_metrics(
    metrics_directory="/opt/metrics",
    export_interval=60,
    global_labels={"on_prem": "1"}
)
```

## JSON Format

The JSON export includes all metrics plus configuration metadata:

```json
{
  "timestamp": "2025-06-15T10:30:00.000000",
  "uptime_seconds": 3600.5,
  "interval_seconds": 60,
  "metrics_config": {
    "directory": "/opt/metrics",
    "global_labels": {
      "on_prem": "1",
      "environment": "production"
    }
  },
  "total_traps_received": 15000,
  "total_traps_forwarded": 14500,
  "total_traps_blocked": 250,
  "total_traps_redirected": 150,
  "total_traps_dropped": 5,
  "processing_errors": 2,
  "ha_blocked": 0,
  "traps_cached": 14500,
  "cache_failures": 0,
  "fast_path_hits": 14000,
  "slow_path_hits": 1000,
  "fast_path_ratio": 93.3,
  "processing_rate": 250.5,
  "queue_current_depth": 10,
  "queue_max_depth": 500,
  "queue_capacity": 200000,
  "queue_utilization": 0.00005,
  "queue_total_queued": 15000,
  "queue_total_dropped": 5,
  "queue_full_events": 0,
  "ha": {
    "enabled": true,
    "state": "PRIMARY",
    "is_primary": true,
    "is_forwarding": true,
    "peer_connected": true,
    "failover_count": 0
  },
  "cache": {
    "enabled": true,
    "available": true
  },
  "blocked_ips": {
    "10.0.0.100": 50,
    "192.168.1.5": 25
  },
  "blocked_oids": {},
  "redirected_ips": {},
  "redirected_oids": {}
}
```

## Directory Permissions

Ensure the metrics directory is writable by the TrapNinja service:

```bash
# Create custom metrics directory
sudo mkdir -p /opt/metrics

# Set ownership (if running as trapninja user)
sudo chown trapninja:trapninja /opt/metrics

# Set permissions
sudo chmod 755 /opt/metrics
```

## Troubleshooting

### Metrics Directory Not Created

If metrics files aren't appearing:

1. Check directory permissions
2. Verify configuration file syntax
3. Check service logs for errors:
   ```bash
   tail -f /var/log/trapninja/trapninja.log | grep -i metric
   ```

### Global Labels Not Appearing

1. Verify JSON syntax in `metrics_config.json`
2. Check for invalid label names (must be Prometheus-compliant)
3. Restart TrapNinja after configuration changes

### All Metrics Show Zero

1. Check if service is running and processing packets
2. Verify packet flow with tcpdump:
   ```bash
   tcpdump -i eth0 udp port 162
   ```
3. Check metrics file timestamps

### Metrics Not Updating

1. Check export interval configuration
2. View service logs for export errors
3. Verify disk space in metrics directory

### Queue Utilization High

If `trapninja_queue_utilization` is consistently above 0.8:

1. Consider increasing worker count
2. Check for slow destinations
3. Monitor network latency to forwarding targets

## Testing

Verify the metrics system is working:

```bash
# Check configuration is loaded
python3 -c "from trapninja.metrics import load_metrics_config; print(load_metrics_config())"

# View current metrics
cat /opt/metrics/trapninja_metrics.prom

# View JSON output
cat /opt/metrics/trapninja_metrics.json | python3 -m json.tool
```
