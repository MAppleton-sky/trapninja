# TrapNinja Granular Statistics Guide

This document covers TrapNinja's granular statistics system for tracking per-IP, per-OID, and per-destination trap metrics.

## Overview

The granular statistics system provides detailed tracking beyond the aggregate metrics:

| Metric Type | What It Tracks | Use Case |
|-------------|----------------|----------|
| **Per-IP** | Volume, rate, OIDs, destinations | Identify noisy sources, troubleshoot devices |
| **Per-OID** | Volume, rate, source IPs | Understand alarm types, spot patterns |
| **Per-Destination** | Forwards, success rate, sources | Monitor forwarding health |

### SNMPv3 Support

As of v0.7.15, decrypted SNMPv3 traps are **routed through the standard v2c processing pipeline**. When an SNMPv3 trap is successfully decrypted and converted to v2c format:

1. The converted v2c payload is processed exactly like a native v2c trap
2. OID-based blocking rules are applied (same as v2c)
3. OID-based redirection rules are applied (same as v2c)
4. IP-based redirection rules are applied (same as v2c)
5. The OID is extracted and recorded in granular statistics

This unified processing ensures consistent behavior - blocking/redirection rules work identically for both native v2c and decrypted v3 traps.

**Example:** If you block OID `1.3.6.1.4.1.9.9.41.2.0.1`, it will be blocked whether it arrives as v2c or encrypted v3.

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
============================================================
  TrapNinja Granular Statistics Summary
============================================================

TOTALS:
  Total Traps:        1,234,567
  Forwarded:          1,200,000
  Blocked:               30,000
  Redirected:             4,567
  Dropped:                    0

COUNTS:
  Unique IPs:             3,456
  Unique OIDs:              892
  Destinations:               5

RATES:
  Per Second:            166.67
  Per Minute:          10000.00
  Per Hour:           600000.00

MEMORY USAGE:
  IP Tracking:       3456/10000
  OID Tracking:        892/5000

Last Updated: 2025-01-15 14:30:45
```

**Rate Values:**
- `Per Second` - Current rate based on the last 60-second window
- `Per Minute` - Projected rate (per_second × 60)
- `Per Hour` - Projected rate (per_second × 3600)

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

**Sort Options (`-s, --sort`):**
- `total` - Total trap count (default)
- `rate` - Current traps/minute
- `peak` - Highest peak rate ever observed
- `blocked` - Number blocked
- `recent` - Most recently active

**Detail Options:**
- `--sources N` - Number of top source IPs for OID details (default: 10, max: 500)
- `--oids N` - Number of top OIDs for IP details (default: 10, max: 500)

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
# Detailed stats for specific IP (shows top 10 OIDs by default)
trapninja stats ip 10.0.0.1

# Show top 50 OIDs from this IP
trapninja stats ip 10.0.0.1 --oids 50

# Export as JSON for further analysis
trapninja stats ip 10.0.0.1 --oids 100 --json --pretty
```

Shows comprehensive details:
- All counters (total, forwarded, blocked, redirected, dropped)
- Timing (first/last seen, age, idle time)
- Current and peak rates
- Top N OIDs sent from this IP (configurable with `--oids`, default 10, max 500)
- Destination breakdown

### OID Details

> **Note:** The OID query searches **all tracked OIDs** (up to 5,000), not just the top 100 shown by `stats top-oids`. If an OID has been seen but isn't in the top list, it can still be queried directly.

```bash
# Detailed stats for specific OID (shows top 10 sources by default)
trapninja stats oid 1.3.6.1.4.1.9.9.41.2.0.1

# Show top 30 source IPs for this OID
trapninja stats oid 1.3.6.1.4.1.9.9.41.2.0.1 --sources 30

# Export as JSON for further analysis
trapninja stats oid 1.3.6.1.4.1.9.9.41.2.0.1 --sources 100 --json --pretty
```

Shows comprehensive details:
- All counters
- Timing
- Current and peak rates
- Top N source IPs for this OID (configurable with `--sources`, default 10, max 500)
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

1. Check service is running: `trapninja daemon status`
2. Check for errors: `journalctl -u trapninja | grep -i granular`
3. Verify metrics directory: `ls -la /var/log/trapninja/metrics/`

### High Memory Usage

1. Check limits: `trapninja stats summary`
2. Reduce max_ips/max_oids in stats_config.json
3. Decrease stale_threshold for faster cleanup

### Missing IPs/OIDs

Entries are removed after `stale_threshold` seconds of inactivity. Increase this value for longer retention.

### SNMPv3 OIDs Not Appearing

If decrypted SNMPv3 traps aren't showing in OID statistics:

1. **Check decryption is working:** Look for "SNMPv3 decrypted" in logs:
   ```bash
   journalctl -u trapninja | grep "SNMPv3 decrypted"
   ```

2. **Verify varbind extraction:** Enable debug logging to see OID extraction:
   ```bash
   journalctl -u trapninja | grep "Extracted trap OID"
   ```

3. **Restart after upgrade:** If you upgraded TrapNinja, restart to load new worker code:
   ```bash
   systemctl restart trapninja
   ```

## See Also

- [METRICS.md](METRICS.md) - Aggregate metrics documentation
- [CLI.md](CLI.md) - Full CLI reference
- [ARCHITECTURE.md](ARCHITECTURE.md) - System architecture overview
