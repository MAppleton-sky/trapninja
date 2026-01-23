# TrapNinja Failover Replay System

The Failover Replay system ensures **zero trap loss** during HA failovers by automatically detecting gaps in trap forwarding and replaying any missed traps from the cache.

## Overview

During an HA failover, there's typically a 2-5 second window where traps may not be forwarded:

```
Timeline:
  T=0:00:00  Primary forwarding normally
  T=0:00:05  Primary fails
  T=0:00:05  Heartbeat timeout begins
  T=0:00:08  Secondary detects failure (3 second timeout)
  T=0:00:09  Secondary completes promotion to Primary
  T=0:00:09  Secondary starts forwarding
  
  GAP: 0:00:05 to 0:00:09 (4 seconds of potential trap loss)
```

The Failover Replay system solves this by:

1. **Tracking**: Recording the timestamp of the last forwarded trap in Redis
2. **Detecting**: On failover, detecting the gap between last forwarded and now
3. **Replaying**: Automatically replaying traps from the cache for the gap window

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        FAILOVER REPLAY ARCHITECTURE                          │
│                                                                              │
│   Primary Node                              Secondary Node                   │
│   ┌─────────────────────────┐              ┌─────────────────────────┐      │
│   │  1. Forward trap        │              │                         │      │
│   │  2. Update timestamp    │─────────────►│  Redis Cache            │      │
│   │     in Redis            │              │  ├─ Trap Streams        │      │
│   │  3. Store in cache      │              │  └─ Last Forwarded TS   │      │
│   └─────────────────────────┘              └─────────────────────────┘      │
│                                                        │                     │
│                 Primary Fails ──────────────────────────                    │
│                                                        ▼                     │
│                                            ┌─────────────────────────┐      │
│                                            │  On Become PRIMARY:     │      │
│                                            │  1. Read last_forwarded │      │
│                                            │  2. Detect gap          │      │
│                                            │  3. Query cache         │      │
│                                            │  4. Replay traps        │      │
│                                            └─────────────────────────┘      │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Configuration

Add the `failover_replay` section to your cache configuration:

**File: `/opt/trapninja/config/cache_config.json`**

```json
{
  "enabled": true,
  "host": "localhost",
  "port": 6379,
  "retention_hours": 2.0,
  "trim_interval_seconds": 60,
  
  "failover_replay": {
    "enabled": true,
    "min_gap_seconds": 1.0,
    "max_gap_seconds": 300.0,
    "replay_rate_limit": 2000,
    "replay_delay_seconds": 1.0,
    "buffer_seconds": 0.5,
    "replay_in_background": true,
    "mark_replayed_traps": false
  }
}
```

### Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `enabled` | `true` | Enable automatic failover replay |
| `min_gap_seconds` | `1.0` | Minimum gap to trigger replay (ignore smaller gaps) |
| `max_gap_seconds` | `300.0` | Maximum gap to replay (caps the window at 5 minutes) |
| `replay_rate_limit` | `2000` | Traps per second during replay |
| `replay_delay_seconds` | `1.0` | Delay after becoming PRIMARY before checking gaps |
| `buffer_seconds` | `0.5` | Extra time added to gap start (safety margin) |
| `replay_in_background` | `true` | Run replay in background thread |
| `mark_replayed_traps` | `false` | Add marker to replayed traps (for debugging) |

## CLI Commands

### View Status

```bash
# Show failover replay status
trapninja failover status
```

Output:
```
Failover Replay Status
======================================================================
Enabled: True
Available: True
Instance ID: a1b2c3d4...
Is Primary: True

Configuration:
  Min gap threshold: 1.0s
  Max gap duration: 300.0s
  Replay rate limit: 2000/sec
  Replay delay: 1.0s

Tracking Status:
  Active node: a1b2c3d4...
  Pending updates: 0

  Last Forwarded per Destination:
  Destination                       Age     Timestamp
  ------------------------------------------------------------
  default                       0.3 seconds     14:32:15
  voice_noc                     0.5 seconds     14:32:15
  broadband_noc                 1.2 seconds     14:32:14

Recent Replay History:
  Destination          State             Sent     Failed     Duration
  ----------------------------------------------------------------------
  default              completed       1,234          0        12.3s
```

### Detect Gaps

Preview what would be replayed if a failover happened now:

```bash
# Detect current forwarding gaps
trapninja failover detect
```

Output:
```
Gap Detection Analysis
======================================================================
Current time: 2025-01-15 14:35:22

No gaps detected - all destinations up to date

Last Forwarded Timestamps:
  Destination                       Age     Timestamp
  ------------------------------------------------------------
  default                       0.5 seconds     14:35:21
  voice_noc                     0.8 seconds     14:35:21
```

Or if gaps are detected:

```
Detected 2 gap(s):

Gap: voice_noc
  Time range: 14:32:15 to 14:35:22
  Duration: 187.0 seconds
  Estimated traps: 4,532
  Last active node: a1b2c3d4...

Gap: default
  Time range: 14:33:01 to 14:35:22
  Duration: 141.0 seconds
  Estimated traps: 2,847

Summary:
  Total gaps: 2
  Total gap duration: 328.0s
  Estimated traps to replay: 7,379
  Estimated replay time: 3.7 seconds

To replay these gaps, use: trapninja failover replay
```

### Manual Replay

Trigger a manual replay for detected gaps or a specific time window:

```bash
# Auto-detect and replay gaps
trapninja failover replay --destination detect

# Replay specific destination and time window
trapninja failover replay --destination default \
    --from "-5m" --to "now" --rate-limit 2000

# Dry run to preview
trapninja failover replay --destination detect --dry-run

# Skip confirmation
trapninja failover replay --destination detect -y
```

### Show Help

```bash
trapninja failover help
```

## How It Works

### 1. Timestamp Tracking

Every time a trap is forwarded, the timestamp is recorded:

```python
# In the forwarder, after successful forward:
failover_manager.update_last_forwarded("default", time.time())
```

Timestamps are:
- Stored per destination in Redis
- Batched for performance (500ms intervals)
- Accessible from both HA nodes

### 2. Gap Detection

When a node becomes PRIMARY, the manager:

1. Reads `last_forwarded` timestamps from Redis
2. Compares against current time
3. Calculates gap duration for each destination
4. Filters by min/max thresholds

```
Gap Detection Logic:
  last_forwarded = Redis.get("trapninja:failover:last_forwarded:default")
  gap = current_time - last_forwarded
  
  if gap < min_gap_seconds:
    # Too small, ignore
  elif gap > max_gap_seconds:
    # Cap to prevent runaway replays
    gap = max_gap_seconds
  else:
    # Valid gap, trigger replay
```

### 3. Automatic Replay

For each detected gap:

1. Query the cache for traps in the gap window
2. Replay at configured rate limit
3. Track progress and report results

```
Replay Process:
  for gap in detected_gaps:
    entries = cache.query_range(gap.destination, gap.start, gap.end)
    for entry in entries:
      forward(entry.payload, destinations)
      rate_limit()
```

## Integration with HA

The failover replay integrates automatically with the HA cluster:

```python
# In HACluster._complete_failover():
if self.failover_manager:
    self.failover_manager.on_become_primary()
```

Sequence of events:

1. **Normal Operation**: Primary node forwards traps, updating timestamps
2. **Failure Detection**: Secondary detects Primary failure via heartbeat timeout
3. **Failover Initiated**: Secondary starts promotion to PRIMARY
4. **Failover Complete**: Secondary becomes PRIMARY, forwarding enabled
5. **Gap Check**: Failover replay manager checks for gaps
6. **Auto Replay**: If gaps detected, replay runs in background
7. **Resume Normal**: New PRIMARY continues forwarding while replay completes

## Requirements

For failover replay to work:

1. **Redis Caching Enabled**: Both nodes must have caching configured
2. **Shared Redis**: Both HA nodes must use the same Redis instance
3. **Sufficient Retention**: Cache retention >= expected failover duration

### Shared Redis Configuration

Both HA nodes should point to the same Redis server:

**Primary Node (`cache_config.json`):**
```json
{
  "enabled": true,
  "host": "redis.internal.example.com",
  "port": 6379
}
```

**Secondary Node (`cache_config.json`):**
```json
{
  "enabled": true,
  "host": "redis.internal.example.com",
  "port": 6379
}
```

### Redis Memory Sizing

Failover replay adds minimal Redis overhead:

| Data Type | Size per Destination |
|-----------|---------------------|
| Last forwarded timestamp | ~100 bytes |
| Node heartbeat | ~50 bytes |
| Statistics | ~500 bytes |

Total additional overhead: < 1KB per destination

## Troubleshooting

### No Timestamps Found

```
No forwarding timestamps found in Redis
```

**Causes:**
- Failover tracking not enabled on the PRIMARY
- No traps have been forwarded yet
- Redis connection issues

**Solutions:**
1. Check `failover_replay.enabled` is `true`
2. Verify Redis connectivity: `redis-cli ping`
3. Check logs for tracking updates

### Gap Too Large

```
Gap for default (450.0s) exceeds maximum (300.0s) - capping replay window
```

**Causes:**
- Prolonged outage exceeding max_gap_seconds
- System was down longer than expected

**Solutions:**
1. Use manual replay for larger windows:
   ```bash
   trapninja cache replay --destination default --from "-10m" --to "now"
   ```
2. Increase `max_gap_seconds` if appropriate

### Replay Too Slow

**Symptoms:**
- Replay taking longer than expected
- Destination being overwhelmed

**Solutions:**
1. Reduce `replay_rate_limit`
2. Check Redis latency
3. Verify network to destinations

### Redis Keys

Failover replay uses these Redis keys:

| Key Pattern | Purpose |
|-------------|---------|
| `trapninja:failover:last_forwarded:{dest}` | Last forwarded timestamp per destination |
| `trapninja:failover:node:{instance_id}` | Node heartbeat |
| `trapninja:failover:active_node` | Currently active node |
| `trapninja:failover:stats:{dest}:{bucket}` | Forwarding rate statistics |

To inspect:
```bash
redis-cli keys "trapninja:failover:*"
redis-cli hgetall "trapninja:failover:last_forwarded:default"
```

## Best Practices

1. **Use Shared Redis**: Both HA nodes should use the same Redis for cache and tracking
2. **Set Appropriate Thresholds**: 
   - `min_gap_seconds`: 1-2 seconds (ignore tiny gaps)
   - `max_gap_seconds`: 5 minutes (prevent runaway replays)
3. **Match Rate Limits**: `replay_rate_limit` should match or be slightly higher than your typical trap rate
4. **Test Before Production**: Use `trapninja failover detect` and `--dry-run` to validate
5. **Monitor Replay History**: Check `trapninja failover status` regularly

## Metrics

The following metrics are available for monitoring:

| Metric | Type | Description |
|--------|------|-------------|
| `trapninja_failover_replay_total` | Counter | Total replay operations |
| `trapninja_failover_replay_traps_sent` | Counter | Traps sent during replay |
| `trapninja_failover_replay_traps_failed` | Counter | Traps failed during replay |
| `trapninja_failover_gap_seconds` | Gauge | Last detected gap duration |
| `trapninja_failover_last_forwarded_age` | Gauge | Age of last forwarded timestamp |

---

**Last Updated**: 2025-01-09
