# TrapNinja Metrics System

## Overview

TrapNinja provides comprehensive metrics collection and export in Prometheus format for monitoring system integration. The metrics system collects data from all processing components and exports it in both Prometheus (`.prom`) and JSON formats.

## Architecture

The unified metrics system integrates with multiple data sources:

```
┌─────────────────────────────────────────────────────────────────┐
│                     Metrics Exporter                            │
│                    (metrics.py)                                 │
│                                                                 │
│  ┌───────────────┐ ┌───────────────┐ ┌───────────────────────┐  │
│  │ Packet        │ │ Network       │ │ HA Cluster            │  │
│  │ Processor     │ │ Module        │ │ (if enabled)          │  │
│  │ (AtomicStats) │ │ (QueueStats)  │ │                       │  │
│  └───────────────┘ └───────────────┘ └───────────────────────┘  │
│                                                                 │
│  ┌───────────────┐ ┌───────────────────────────────────────────┐│
│  │ Cache System  │ │ Detailed Tracking (per IP/OID counters)  ││
│  │ (if enabled)  │ │                                           ││
│  └───────────────┘ └───────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
              ┌───────────────────────────────┐
              │  /var/log/trapninja/metrics/  │
              │                               │
              │  trapninja_metrics.prom       │
              │  trapninja_metrics.json       │
              └───────────────────────────────┘
```

## Metrics Output Location

Metrics are exported to:
- **Prometheus format**: `/var/log/trapninja/metrics/trapninja_metrics.prom`
- **JSON format**: `/var/log/trapninja/metrics/trapninja_metrics.json`

## Available Metrics

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

These metrics include labels for specific IPs/OIDs:

| Metric | Labels | Description |
|--------|--------|-------------|
| `trapninja_blocked_ip_count` | `ip` | Traps blocked from specific IP |
| `trapninja_blocked_oid_count` | `oid` | Traps blocked with specific OID |
| `trapninja_redirected_ip_count` | `ip`, `tag` | Traps redirected from specific IP |
| `trapninja_redirected_oid_count` | `oid`, `tag` | Traps redirected with specific OID |

### Uptime Metric

| Metric | Type | Description |
|--------|------|-------------|
| `trapninja_uptime_seconds` | counter | Time since service started |

## Export Interval

Metrics are exported every 60 seconds by default. This can be configured when initializing the metrics module:

```python
from trapninja.metrics import init_metrics

init_metrics(
    metrics_directory="/var/log/trapninja/metrics",
    export_interval=30  # Export every 30 seconds
)
```

## Prometheus Integration

To scrape TrapNinja metrics with Prometheus, configure a file-based service discovery or use the Node Exporter textfile collector.

### Using Node Exporter Textfile Collector

1. Configure Node Exporter with `--collector.textfile.directory=/var/log/trapninja/metrics`

2. Add to Prometheus config:
```yaml
scrape_configs:
  - job_name: 'trapninja'
    static_configs:
      - targets: ['localhost:9100']
    metric_relabel_configs:
      - source_labels: [__name__]
        regex: 'trapninja_.*'
        action: keep
```

### Example Grafana Dashboard Queries

**Processing Rate:**
```promql
rate(trapninja_traps_received_total[5m])
```

**Fast Path Efficiency:**
```promql
trapninja_fast_path_ratio
```

**Queue Utilization:**
```promql
trapninja_queue_utilization * 100
```

**HA Status:**
```promql
trapninja_ha_is_primary
```

## JSON Format

The JSON export includes all metrics plus additional metadata:

```json
{
  "timestamp": "2025-06-15T10:30:00.000000",
  "uptime_seconds": 3600.5,
  "interval_seconds": 60,
  "total_traps_received": 15000,
  "total_traps_forwarded": 14500,
  "total_traps_blocked": 250,
  "total_traps_redirected": 150,
  ...
  "ha": {
    "enabled": true,
    "state": "PRIMARY",
    "is_primary": true,
    "is_forwarding": true,
    "peer_connected": true
  },
  "cache": {
    "enabled": true,
    "available": true
  },
  "blocked_ips": {
    "10.0.0.100": 50,
    "192.168.1.5": 25
  }
}
```

## Troubleshooting

### All Metrics Show Zero

If all metrics show 0:

1. **Check if service is running**: Metrics are only collected while the service is actively processing packets.

2. **Verify packet flow**: Use `tcpdump` to confirm traps are arriving:
   ```bash
   tcpdump -i eth0 udp port 162
   ```

3. **Check metrics file timestamps**:
   ```bash
   ls -la /var/log/trapninja/metrics/
   ```

4. **View raw metrics file**:
   ```bash
   cat /var/log/trapninja/metrics/trapninja_metrics.prom
   ```

### Metrics Not Updating

1. **Check export timer**: Metrics are exported every 60 seconds by default.

2. **View service logs** for errors:
   ```bash
   tail -f /var/log/trapninja/trapninja.log
   ```

### Queue Utilization High

If `trapninja_queue_utilization` is consistently above 0.8:

1. Consider increasing worker count
2. Check for slow destinations
3. Monitor network latency to forwarding targets

## Testing

Run the metrics test to verify the system is working:

```bash
cd /path/to/trapninja
python3 tests/metrics-test.py --all
```

This will verify that:
- Metrics module imports correctly
- Packet processor statistics are captured
- Metrics are exported to files
- All values are correctly aggregated
