# TrapNinja Granular Statistics Guide

This document covers TrapNinja's granular statistics system for tracking per-IP, per-OID, and per-destination trap metrics.

## Overview

The granular statistics system provides detailed tracking beyond the aggregate metrics:

| Metric Type | What It Tracks | Use Case |
|-------------|----------------|----------|
| **Per-IP** | Volume, rate, OIDs, destinations | Identify noisy sources, troubleshoot devices |
| **Per-OID** | Volume, rate, source IPs | Understand alarm types, spot patterns |
| **Per-Destination** | Forwards, success rate, sources | Monitor forwarding health |

## Architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│                        Packet Processing Pipeline                         │
├──────────────────────────────────────────────────────────────────────────┤
│  Packet Received                                                          │
│       │                                                                   │
│       ▼                                                                   │
│  ┌─────────────────┐                                                      │
│  │ Extract Source  │ ──────────────────────┐                              │
│  │ IP and OID      │                       │                              │
│  └─────────────────┘                       │                              │
│       │                                    │                              │
│       ▼                                    ▼                              │
│  ┌─────────────────┐            ┌─────────────────────┐                   │
│  │ Filtering       │            │ GranularStatsCollector                  │
│  │ & Forwarding    │            │  ├─ IPStats (LRU)   │                   │
│  └─────────────────┘            │  ├─ OIDStats (LRU)  │                   │
│       │                         │  └─ DestStats       │                   │
│       ▼                         └─────────────────────┘                   │
│  Forward to                            │                                  │
│  Destinations                          ▼                                  │
│                                 ┌─────────────────────┐                   │
│                                 │  File Export        │                   │
│                                 │  .prom / .json      │                   │
│                                 └─────────────────────┘                   │
└──────────────────────────────────────────────────────────────────────────┘
```

## Enabling Granular Statistics

Granular statistics are **automatically enabled** when TrapNinja starts (v0.7.0+).

## CLI Commands

### Summary

```bash
# Overall statistics summary
trapninja stats summary

# JSON output
trapninja stats summary --json --pretty
```

Example output:
```
=== TrapNinja Statistics Summary ===

TOTALS:
  Traps Received:   1,234,567
  Forwarded:        1,200,000
  Blocked:          30,000
  Redirected:       4,567

RATES:
  Current (1 min):  245.3/min
  Average:          4.1/sec

TRACKING:
  Unique IPs:       3,456
  Unique OIDs:      892
  Destinations:     5
```

### Top Source IPs

```bash
# Top 10 by volume (default)
trapninja stats top-ips

# Top 20 by current rate
trapninja stats top-ips -n 20 -s rate

# Top 10 most blocked
trapninja stats top-ips -s blocked

# JSON output
trapninja stats top-ips --json
```

**Sort Options:**
- `total` - Total trap count (default)
- `rate` - Current traps/minute
- `blocked` - Number blocked
- `recent` - Most recently active

Example output:
```
=== Top 20 Source IPs (sorted by total) ===

  #  IP Address           Total      Fwd      Blk   Rate/min   Last Seen
----------------------------------------------------------------------------------
  1  10.100.1.15          45,231    44,950     281     125.50   2025-01-15 14:30:45
  2  10.100.2.22          38,445    38,445       0      89.20   2025-01-15 14:30:44
  3  10.100.3.8           21,087    20,100     987      45.30   2025-01-15 14:30:43
```

### Top OIDs

```bash
# Top 10 OIDs by volume
trapninja stats top-oids

# Top 50 by rate
trapninja stats top-oids -n 50 -s rate
```

### IP Details

```bash
# Detailed stats for specific IP
trapninja stats ip 10.0.0.1
```

Shows comprehensive details:
- All counters (total, forwarded, blocked, redirected, dropped)
- Timing (first/last seen, age, idle time)
- Current rates
- Top 10 OIDs sent from this IP
- Destination breakdown

### OID Details

```bash
# Detailed stats for specific OID
trapninja stats oid 1.3.6.1.4.1.9.9.41.2.0.1
```

Shows comprehensive details:
- All counters
- Timing
- Current rates
- Top 10 source IPs for this OID
- Destination breakdown

### Destination Statistics

```bash
trapninja stats destinations
```

Shows statistics for each forwarding destination:
- Total forwards, success/failure counts
- Success rate percentage
- Current rate
- Top source IPs per destination

### Dashboard Export

```bash
# Full dashboard data as JSON
trapninja stats dashboard --pretty
```

### Export to File

```bash
# Export as JSON
trapninja stats export -f json -o /tmp/stats.json

# Export as Prometheus format
trapninja stats export -f prometheus -o /tmp/stats.prom
```

### Reset Statistics

```bash
trapninja stats reset --yes
```

Resets all granular statistics. Requires `--yes` confirmation.

## Metrics Files

Statistics are automatically exported every 60 seconds:

### JSON Format
**Location:** `/var/log/trapninja/metrics/trapninja_granular.json`

### Prometheus Format
**Location:** `/var/log/trapninja/metrics/trapninja_granular.prom`

```prometheus
# Per-IP metrics (top 50 by volume)
trapninja_ip_traps_total{ip="10.0.0.1"} 45678
trapninja_ip_rate_per_minute{ip="10.0.0.1"} 125.50

# Per-OID metrics (top 50 by volume)
trapninja_oid_traps_total{oid="1.3.6.1.4.1.9.9.41.2.0.1"} 123456

# Per-destination metrics
trapninja_dest_forwards_total{destination="default"} 1234567

# Summary
trapninja_granular_unique_ips 3456
trapninja_granular_unique_oids 892
```

## Configuration

### stats_config.json

```json
{
    "enabled": true,
    "max_ips": 10000,
    "max_oids": 5000,
    "max_destinations": 100,
    "cleanup_interval": 300,
    "stale_threshold": 3600,
    "rate_window": 60,
    "export_interval": 60,
    "persistence": {
        "enabled": false,
        "redis_key_prefix": "trapninja:stats:"
    }
}
```

### Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `max_ips` | 10000 | Maximum IPs to track (LRU eviction) |
| `max_oids` | 5000 | Maximum OIDs to track |
| `max_destinations` | 100 | Maximum destinations to track |
| `cleanup_interval` | 300 | Seconds between cleanup runs |
| `stale_threshold` | 3600 | Seconds of inactivity before entry is stale |
| `rate_window` | 60 | Seconds for rate calculation window |
| `export_interval` | 60 | Seconds between file exports |

## Memory Usage

Approximate memory usage per tracked entity:

| Entity | Memory | At Max Default |
|--------|--------|----------------|
| Per IP | ~2KB | 20MB (10,000 IPs) |
| Per OID | ~1.5KB | 7.5MB (5,000 OIDs) |
| Per Destination | ~1KB | 100KB (100 destinations) |

**Total estimated maximum: ~30MB**

The LRU eviction ensures memory stays bounded even under heavy traffic.

## Grafana Integration

**Prometheus scrape config (file-based):**
```yaml
scrape_configs:
  - job_name: 'trapninja-granular'
    file_sd_configs:
      - files:
        - '/var/log/trapninja/metrics/trapninja_granular.prom'
```

**Sample queries:**
- Top sources: `topk(10, trapninja_ip_traps_total)`
- Rate over time: `rate(trapninja_ip_traps_total[5m])`
- OID distribution: `topk(10, trapninja_oid_traps_total)`

## Performance Impact

- **Non-blocking** - Stats recording never blocks packet processing
- **Fire-and-forget** - Failures don't affect forwarding
- **Efficient counters** - Uses Python's GIL for atomic operations
- **Background cleanup** - Stale entries removed asynchronously
- **Measured overhead: <1% CPU increase at 10,000 traps/second**

## Troubleshooting

### Statistics Not Updating

1. Check service is running: `trapninja --status`
2. Check for errors: `journalctl -u trapninja | grep -i granular`
3. Verify metrics directory: `ls -la /var/log/trapninja/metrics/`

### High Memory Usage

1. Check limits: `trapninja stats summary`
2. Reduce max_ips/max_oids in stats_config.json
3. Decrease stale_threshold for faster cleanup

### Missing IPs/OIDs

Entries are removed after `stale_threshold` seconds of inactivity. Increase this value for longer retention.

## See Also

- [METRICS.md](METRICS.md) - Aggregate metrics documentation
- [CLI.md](CLI.md) - Full CLI reference
- [ARCHITECTURE.md](ARCHITECTURE.md) - System architecture overview
