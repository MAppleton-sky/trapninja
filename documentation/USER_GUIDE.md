# TrapNinja User Guide

**Version 0.7.0 (Beta)**

A high-performance SNMP trap forwarder for telecommunications environments.

---

## Command Syntax

Throughout this guide, TrapNinja is invoked using:

```bash
python3.9 -O trapninja.py <options>
```

The `-O` flag enables Python optimizations for better performance.

---

## Quick Start

### Starting the Service

```bash
# Start as daemon
python3.9 -O trapninja.py --start

# Check status
python3.9 -O trapninja.py --status

# Stop service
python3.9 -O trapninja.py --stop
```

### Verify Operation

```bash
# Send a test trap
snmptrap -v 2c -c public localhost:162 "" .1.3.6.1.6.3.1.1.5.1

# Check it was processed
python3.9 -O trapninja.py --status | grep received
```

---

## Service Management

### Commands

| Command | Description |
|---------|-------------|
| `--start` | Start as background daemon |
| `--stop` | Stop the daemon |
| `--restart` | Stop then start |
| `--status` | Show service status and statistics |
| `--foreground` | Run in foreground (for debugging) |
| `--foreground --debug` | Run with verbose debug logging |

### Service Status

```bash
python3.9 -O trapninja.py --status
```

Key values to check:
- **Running**: Process is active
- **Traps received/forwarded**: Processing statistics
- **HA State**: PRIMARY (forwarding) or SECONDARY (standby)
- **Queue depth**: Current backlog (should be near 0 normally)

### Log Files

| Log | Location | Purpose |
|-----|----------|---------|
| Main log | `/var/log/trapninja.log` | Operations and errors |
| Metrics | `/var/log/trapninja/metrics/` | Prometheus/JSON metrics |

View recent logs:
```bash
tail -f /var/log/trapninja.log
```

---

## Filtering Traps

### Block by IP Address

Block traps from a noisy or unwanted source:

```bash
# Block an IP
python3.9 -O trapninja.py --block-ip 10.0.1.50

# Verify
python3.9 -O trapninja.py --list-blocked-ips

# Remove block
python3.9 -O trapninja.py --unblock-ip 10.0.1.50
```

### Block by OID

Block specific trap types (e.g., temperature warnings):

```bash
# Block specific OID
python3.9 -O trapninja.py --block-oid 1.3.6.1.4.1.8072.2.3.0.1

# Block OID prefix (blocks all matching)
python3.9 -O trapninja.py --block-oid 1.3.6.1.4.1.8072

# List blocked OIDs
python3.9 -O trapninja.py --list-blocked-oids

# Remove block
python3.9 -O trapninja.py --unblock-oid 1.3.6.1.4.1.8072.2.3.0.1
```

### Changes Apply Immediately

Filtering changes take effect immediately without restart.

---

## High Availability

TrapNinja supports Primary/Secondary clustering for 99.999% availability.

### HA Status

```bash
python3.9 -O trapninja.py --ha-status
```

Output shows:
- **Configured Role**: What this node is configured as (primary/secondary)
- **Acting Role**: What it's currently doing (PRIMARY forwards, SECONDARY standby)
- **Peer Status**: Connection to partner node
- **Forwarding**: Whether actively forwarding traps

### Planned Maintenance (Controlled Failover)

To perform maintenance on the PRIMARY node:

**On the SECONDARY node:**
```bash
python3.9 -O trapninja.py --promote
```

**On the PRIMARY node:**
```bash
python3.9 -O trapninja.py --demote
```

Verify both nodes show expected states:
```bash
python3.9 -O trapninja.py --ha-status
```

### Return to Normal After Maintenance

When maintenance is complete, reverse the process:

**On the original PRIMARY:**
```bash
python3.9 -O trapninja.py --promote
```

**On the original SECONDARY:**
```bash
python3.9 -O trapninja.py --demote
```

### Emergency Failover

If PRIMARY fails unexpectedly, SECONDARY auto-promotes within 3-5 seconds.

To force immediate failover:
```bash
python3.9 -O trapninja.py --force-failover
```

### HA Quick Reference

| Scenario | Action |
|----------|--------|
| Check status | `--ha-status` |
| Planned maintenance | `--promote` on secondary, then `--demote` on primary |
| Force failover | `--force-failover` |
| Both nodes confused | `--demote` on one node to break tie |

See [HA.md](HA.md) for detailed configuration.

---

## Statistics & Monitoring

### Quick Statistics Summary

```bash
python3.9 -O trapninja.py --stats-summary
```

### Top Trap Sources

```bash
# Top 10 by volume (default)
python3.9 -O trapninja.py --stats-top-ips

# Top 20 by current rate
python3.9 -O trapninja.py --stats-top-ips -n 20 -s rate

# Top blocked sources
python3.9 -O trapninja.py --stats-top-ips -s blocked
```

### Top OIDs (Trap Types)

```bash
# Top 10 by volume
python3.9 -O trapninja.py --stats-top-oids

# By current rate
python3.9 -O trapninja.py --stats-top-oids -s rate
```

### Investigate Specific Source

```bash
python3.9 -O trapninja.py --stats-ip --ip 10.0.0.1
```

Shows:
- Total/forwarded/blocked counts
- Top OIDs from this source
- Rate information
- First/last seen times

### Investigate Specific OID

```bash
python3.9 -O trapninja.py --stats-oid --oid 1.3.6.1.4.1.9.9.41.2.0.1
```

Shows:
- Total/forwarded/blocked counts
- Top source IPs for this OID
- Rate information

### Destination Statistics

```bash
python3.9 -O trapninja.py --stats-destinations
```

### Export Statistics

```bash
# JSON export
python3.9 -O trapninja.py --stats-export -f json --output /tmp/stats.json

# Prometheus format
python3.9 -O trapninja.py --stats-export -f prometheus --output /tmp/stats.prom
```

### Statistics Options Reference

| Option | Description |
|--------|-------------|
| `-n`, `--count` | Number of items to show (default: 10) |
| `-s`, `--sort` | Sort by: `total`, `rate`, `blocked`, `recent` |
| `-f`, `--format` | Export format: `json`, `prometheus` |
| `--json` | Output as JSON |
| `--pretty` | Pretty print JSON |

See [GRANULAR_STATS.md](GRANULAR_STATS.md) for all options.

---

## Trap Caching & Replay

TrapNinja caches traps in Redis for replay during monitoring outages.

### Check Cache Status

```bash
python3.9 -O trapninja.py --cache-status
```

Shows:
- Redis connection status
- Number of cached entries per destination
- Cache time range

### Preview Cached Traps

```bash
# Query default destination, last 2 hours
python3.9 -O trapninja.py --cache-query --destination default

# Specific time window
python3.9 -O trapninja.py --cache-query --destination default --from "14:30" --to "15:45"

# Relative time
python3.9 -O trapninja.py --cache-query --destination default --from "-2h" --to "-1h"
```

### Replay Traps

After a monitoring system outage, replay missed traps:

```bash
# Preview first (dry run)
python3.9 -O trapninja.py --cache-replay --destination default \
    --from "14:30" --to "15:45" --dry-run

# Actual replay with rate limiting
python3.9 -O trapninja.py --cache-replay --destination default \
    --from "14:30" --to "15:45" --rate-limit 1000

# Skip confirmation prompt
python3.9 -O trapninja.py --cache-replay --destination default \
    --from "14:30" --to "15:45" -y
```

### Clear Cache

```bash
# Clear specific destination
python3.9 -O trapninja.py --cache-clear --destination default

# Clear all
python3.9 -O trapninja.py --cache-clear -y
```

See [CACHE.md](CACHE.md) for Redis setup and configuration.

---

## SNMPv3 Decryption

TrapNinja can decrypt SNMPv3 traps and forward them as SNMPv2c.

### Check SNMPv3 Status

```bash
python3.9 -O trapninja.py --snmpv3-status
```

### Add SNMPv3 User

```bash
python3.9 -O trapninja.py --snmpv3-add-user \
    --username myuser \
    --engine-id 80001f888056565656565656 \
    --auth-protocol SHA \
    --priv-protocol AES128
```

You'll be prompted for auth and priv passwords.

### List Configured Users

```bash
python3.9 -O trapninja.py --snmpv3-list-users
```

### Remove User

```bash
python3.9 -O trapninja.py --snmpv3-remove-user --username myuser
```

---

## Configuration Files

All configuration files are in the `config/` directory.

| File | Purpose |
|------|---------|
| `destinations.json` | Forwarding destinations |
| `listen_ports.json` | UDP ports to listen on |
| `blocked_ips.json` | IPs to block (managed via CLI) |
| `blocked_traps.json` | OIDs to block (managed via CLI) |
| `ha_config.json` | High Availability settings |
| `cache_config.json` | Redis cache settings |
| `stats_config.json` | Granular statistics settings |

### Destinations

Edit `config/destinations.json`:
```json
[
  ["10.234.33.20", 162],
  ["10.234.33.21", 162]
]
```

Format: `["ip_address", port]`

Restart required after editing.

### Listen Ports

Edit `config/listen_ports.json`:
```json
[162, 6667]
```

Restart required after editing.

---

## Troubleshooting

### Service Won't Start

```bash
# Check if port is in use
netstat -ulnp | grep 162

# Run in foreground for errors
python3.9 -O trapninja.py --foreground --debug
```

### No Traps Received

```bash
# Verify traps are arriving
tcpdump -i any udp port 162 -c 5

# Check firewall
firewall-cmd --list-ports | grep 162
```

### No Traps Forwarded

```bash
# Check HA state (must be PRIMARY to forward)
python3.9 -O trapninja.py --ha-status | grep Forwarding

# Check destinations configured
cat config/destinations.json

# Check if source is blocked
python3.9 -O trapninja.py --list-blocked-ips
```

### High CPU Usage

```bash
# Check capture mode
python3.9 -O trapninja.py --status | grep -i capture

# Enable eBPF (requires root and BCC)
sudo python3.9 -O trapninja.py --start
```

### HA Issues

```bash
# Check peer connectivity
nc -vzu <peer_ip> 5000

# Check HA logs
grep "HA:" /var/log/trapninja.log | tail -20
```

See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for comprehensive diagnostics.

---

## Quick Reference Card

### Daily Operations

```bash
# Start/stop
python3.9 -O trapninja.py --start
python3.9 -O trapninja.py --stop
python3.9 -O trapninja.py --restart
python3.9 -O trapninja.py --status

# HA management
python3.9 -O trapninja.py --ha-status
python3.9 -O trapninja.py --promote
python3.9 -O trapninja.py --demote

# Statistics
python3.9 -O trapninja.py --stats-summary
python3.9 -O trapninja.py --stats-top-ips
python3.9 -O trapninja.py --stats-top-oids
python3.9 -O trapninja.py --stats-destinations
```

### Filtering

```bash
# Block/unblock IPs
python3.9 -O trapninja.py --block-ip <ip>
python3.9 -O trapninja.py --unblock-ip <ip>
python3.9 -O trapninja.py --list-blocked-ips

# Block/unblock OIDs
python3.9 -O trapninja.py --block-oid <oid>
python3.9 -O trapninja.py --unblock-oid <oid>
python3.9 -O trapninja.py --list-blocked-oids
```

### Cache Operations

```bash
python3.9 -O trapninja.py --cache-status
python3.9 -O trapninja.py --cache-query --destination <dest> --from <time> --to <time>
python3.9 -O trapninja.py --cache-replay --destination <dest> --from <time> --to <time>
```

### Help

```bash
python3.9 -O trapninja.py --help
python3.9 -O trapninja.py --ha-help
python3.9 -O trapninja.py --cache-help
python3.9 -O trapninja.py --stats-help
```

---

## Getting Help

- **CLI Help**: `python3.9 -O trapninja.py --help`
- **HA Help**: `python3.9 -O trapninja.py --ha-help`
- **Cache Help**: `python3.9 -O trapninja.py --cache-help`
- **Stats Help**: `python3.9 -O trapninja.py --stats-help`
- **Detailed docs**: See other files in the `documentation/` directory

### Related Documentation

| Document | Contents |
|----------|----------|
| [CLI.md](CLI.md) | Full CLI reference |
| [HA.md](HA.md) | HA configuration and deployment |
| [CACHE.md](CACHE.md) | Redis cache setup |
| [METRICS.md](METRICS.md) | Prometheus metrics reference |
| [GRANULAR_STATS.md](GRANULAR_STATS.md) | Statistics system details |
| [TROUBLESHOOTING.md](TROUBLESHOOTING.md) | Problem diagnosis |
| [ARCHITECTURE.md](ARCHITECTURE.md) | System internals |

---

*TrapNinja v0.7.0 (Beta) - Target production release: Q2 2025*
