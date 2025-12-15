# TrapNinja Cache System

The TrapNinja cache system provides Redis-based trap buffering with rolling retention, enabling trap replay during monitoring system outages.

## Overview

The cache system acts as a rolling buffer that captures all forwarded SNMP traps in Redis Streams. When a monitoring system outage occurs, operators can replay the cached traps for a specific time window to backfill any data loss.

```
Normal Operation:
┌─────────────┐     ┌───────────────┐     ┌─────────────┐
│   Network   │────▶│   TrapNinja   │────▶│   NOC/NMS   │
│   Elements  │     │               │     │   Systems   │
└─────────────┘     └───────┬───────┘     └─────────────┘
                            │
                            ▼
                    ┌───────────────┐
                    │  Redis Cache  │
                    │ (2hr rolling) │
                    └───────────────┘

Replay Operation:
                    ┌───────────────┐
                    │  Redis Cache  │
                    │  Query Time   │
                    │    Window     │
                    └───────┬───────┘
                            │
                            ▼
┌─────────────┐     ┌───────────────┐     ┌─────────────┐
│   Replay    │────▶│   TrapNinja   │────▶│   NOC/NMS   │
│   Engine    │     │  (rate-limit) │     │   Systems   │
└─────────────┘     └───────────────┘     └─────────────┘
```

## Prerequisites

### Redis Installation (RHEL 8)

```bash
# Install Redis from EPEL
sudo dnf install epel-release -y
sudo dnf install redis -y

# Configure Redis
sudo vi /etc/redis.conf
```

Recommended Redis settings:

```conf
# Network - localhost only for security
bind 127.0.0.1
port 6379

# Memory management
maxmemory 4gb
maxmemory-policy noeviction

# Persistence - recover cache after restart
appendonly yes
appendfsync everysec
```

Start Redis:

```bash
sudo systemctl enable --now redis
redis-cli ping  # Should return PONG
```

### Python Redis Package

```bash
pip install redis --break-system-packages
```

## Configuration

Create `/opt/trapninja/config/cache_config.json`:

```json
{
  "enabled": true,
  "host": "localhost",
  "port": 6379,
  "password": null,
  "db": 0,
  "retention_hours": 2.0,
  "trim_interval_seconds": 60
}
```

### Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `enabled` | `false` | Enable/disable caching |
| `host` | `localhost` | Redis server hostname |
| `port` | `6379` | Redis server port |
| `password` | `null` | Redis password (if required) |
| `db` | `0` | Redis database number |
| `retention_hours` | `2.0` | Rolling retention window |
| `trim_interval_seconds` | `60` | How often to trim expired entries |
| `key_prefix` | `trapninja:buffer` | Redis key prefix |
| `max_entries_per_stream` | `1000000` | Safety cap per destination |

## CLI Commands

### View Cache Status

```bash
trapninja --cache-status
```

Output:
```
Cache Status
======================================================================
Redis: localhost:6379
Retention: 2.0 hours
Status: Connected

Operations:
  Entries stored: 45,230
  Entries trimmed: 12,500
  Store failures: 0
  Connection failures: 0

Destination          Entries       Oldest       Newest         Size
----------------------------------------------------------------------
default               32,450     14:32:15     16:32:10      42.3 MB
voice_noc             8,432     14:33:01     16:32:09      11.2 MB
broadband_noc         4,348     14:35:22     16:32:11       5.8 MB
----------------------------------------------------------------------
Total                45,230                                 59.3 MB
```

### Query Cache (Preview)

```bash
# Query with time range
trapninja --cache-query --destination voice_noc --from "14:30" --to "15:45"

# Query with relative time
trapninja --cache-query --destination default --from "-2h" --to "-1h"
```

Output:
```
Cache Query: voice_noc
Time window: 2025-01-15 14:30:00 to 2025-01-15 15:45:00
Entries found: 12,847

Top OIDs:
  1.3.6.1.4.1.9.9.41.2.0.1: 4,521
  1.3.6.1.4.1.9.9.41.2.0.2: 4,203
  1.3.6.1.4.1.2636.4.1.1: 2,847

Sample entries (first 20):
Timestamp                Source IP        OID
----------------------------------------------------------------------
2025-01-15T14:30:01.123  10.1.2.3         1.3.6.1.4.1.9.9.41.2.0.1
2025-01-15T14:30:01.456  10.1.2.4         1.3.6.1.4.1.9.9.41.2.0.2
...
```

### Replay Cache

```bash
# Dry run (preview without sending)
trapninja --cache-replay --destination voice_noc \
    --from "14:30" --to "15:45" --dry-run

# Actual replay with rate limiting
trapninja --cache-replay --destination voice_noc \
    --from "14:30" --to "15:45" --rate-limit 1000

# Replay all destinations
trapninja --cache-replay --destination all \
    --from "-2h" --to "-1h"

# Replay with OID filter
trapninja --cache-replay --destination voice_noc \
    --from "14:30" --to "15:45" \
    --oid-filter "1.3.6.1.4.1.9"

# Skip confirmation prompt
trapninja --cache-replay --destination voice_noc \
    --from "14:30" --to "15:45" -y
```

### Clear Cache

```bash
# Clear specific destination
trapninja --cache-clear --destination voice_noc

# Clear all cached entries
trapninja --cache-clear

# Skip confirmation
trapninja --cache-clear -y
```

### Cache Help

```bash
trapninja --cache-help
```

## Time Format Reference

The cache commands support multiple time formats:

| Format | Example | Description |
|--------|---------|-------------|
| Relative hours | `-2h` | 2 hours ago |
| Relative minutes | `-30m` | 30 minutes ago |
| Relative days | `-1d` | 1 day ago |
| Time only | `14:30` | Today at 14:30 |
| Yesterday | `yesterday 14:30` | Yesterday at 14:30 |
| Full datetime | `2025-01-15 14:30` | Specific date and time |

## Memory Sizing Guide

Estimate Redis memory requirements based on your trap volume:

| Trap Rate | Buffer Duration | Estimated Memory |
|-----------|-----------------|------------------|
| 10/sec | 2 hours | 150-250 MB |
| 50/sec | 2 hours | 750 MB - 1.2 GB |
| 100/sec | 2 hours | 1.5 - 2.5 GB |
| 100/sec | 4 hours | 3 - 5 GB |

Formula:
```
Memory_MB = (traps_per_second × retention_seconds × avg_trap_bytes × 1.7) / 1,048,576
```

Where:
- `avg_trap_bytes` is typically 1,200-2,000 bytes for telecom traps
- 1.7 is the Redis overhead factor

## Architecture

### Per-Destination Streams

Traps are stored in separate Redis Streams per destination:

```
trapninja:buffer:default        # Default destination traps
trapninja:buffer:voice_noc      # Voice NOC redirected traps
trapninja:buffer:broadband_noc  # Broadband NOC redirected traps
```

This enables:
- Isolated replay per destination
- Independent retention if needed
- Targeted queries

### Entry Structure

Each cached trap contains:

```json
{
  "ts": "2025-01-15T14:32:15.123456",
  "src": "10.1.2.3",
  "oid": "1.3.6.1.4.1.9.9.41.2.0.1",
  "pdu": "<base64 encoded PDU>"
}
```

### Retention Management

A background thread runs every `trim_interval_seconds` to remove entries older than `retention_hours`. This ensures the cache doesn't grow unbounded.

## Integration with HA

The cache system works seamlessly with TrapNinja's HA configuration:

- **Both nodes cache**: Primary and secondary both cache traps they process
- **Replay from either**: Replay can be triggered from either node
- **Shared Redis**: Both nodes can share a single Redis instance
- **Independent Redis**: Each node can have its own Redis (no cross-node replay)

Recommended HA setup with shared Redis:

```
┌─────────────────┐     ┌─────────────────┐
│ TrapNinja       │     │ TrapNinja       │
│ Primary         │     │ Secondary       │
└────────┬────────┘     └────────┬────────┘
         │                       │
         └───────────┬───────────┘
                     │
              ┌──────┴──────┐
              │    Redis    │
              │   (shared)  │
              └─────────────┘
```

## Troubleshooting

### Cache Not Connecting

```bash
# Check Redis is running
systemctl status redis
redis-cli ping

# Check TrapNinja logs
tail -f /var/log/trapninja/trapninja.log | grep -i cache

# Verify configuration
cat /opt/trapninja/config/cache_config.json
```

### High Memory Usage

```bash
# Check Redis memory
redis-cli INFO memory | grep used_memory_human

# Check per-stream sizes
redis-cli --scan --pattern 'trapninja:buffer:*' | while read key; do
  echo "$key: $(redis-cli MEMORY USAGE $key) bytes"
done

# Manual trim if needed
redis-cli XTRIM trapninja:buffer:default MINID $(date -d '2 hours ago' +%s)000
```

### Slow Replay Performance

- Increase `--rate-limit` if destination can handle it
- Check network latency to destination
- Verify Redis performance with `redis-cli --latency`

## Best Practices

1. **Size Redis appropriately**: Use the sizing guide above
2. **Monitor Redis memory**: Set alerts at 80% of maxmemory
3. **Test replay before outages**: Verify replay works with `--dry-run`
4. **Document outage procedures**: Include cache replay in runbooks
5. **Regular cache status checks**: Include `--cache-status` in monitoring
