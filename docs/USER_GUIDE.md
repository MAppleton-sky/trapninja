# TrapNinja User Guide

**Version 0.8.0**

A high-performance SNMP trap forwarder for telecommunications environments.

---

## Command Syntax

Throughout this guide, TrapNinja is invoked using:

```bash
python3.9 -O trapninja.py <subcommand> [options]
```

The `-O` flag enables Python optimizations for better performance.

**CLI v3.0.0 Note:** TrapNinja now uses a modern subcommand-based interface (e.g., `daemon start` instead of `--start`). Legacy flat-style arguments are still supported for backward compatibility.

---

## Quick Start

### Starting the Service

```bash
# Start as daemon
trapninja daemon start

# Check status
trapninja daemon status

# Stop service
trapninja daemon stop
```

### Verify Operation

```bash
# Send a test trap
snmptrap -v 2c -c public localhost:162 "" .1.3.6.1.6.3.1.1.5.1

# Check it was processed
trapninja daemon status | grep received
```

---

## Service Management

### Commands

| Command | Description |
|---------|-------------|
| `daemon start` | Start as background daemon |
| `daemon stop` | Stop the daemon |
| `daemon restart` | Stop then start |
| `daemon status` | Show service status and statistics |
| `daemon foreground` | Run in foreground (for debugging) |
| `daemon foreground --debug` | Run with verbose debug logging |

### Shadow/Parallel Mode (Testing)

Run TrapNinja alongside an existing trap receiver for testing:

| Option | Description |
|--------|-------------|
| `--shadow-mode` | Observe traps without forwarding (safe testing) |
| `--mirror-mode` | Capture and forward in parallel (duplicates) |
| `--parallel` | Force sniff capture for coexistence |

```bash
# Start daemon in shadow mode (observe only)
trapninja daemon start --shadow-mode

# Start daemon in mirror mode
trapninja daemon start --mirror-mode

# Foreground testing with debug output
trapninja daemon foreground --shadow-mode --debug
```

See [SHADOW_MODE.md](SHADOW_MODE.md) for detailed documentation.

### Service Status

```bash
trapninja daemon status
```

Key values to check:
- **Running**: Process is active
- **Traps received/forwarded**: Processing statistics
- **HA State**: PRIMARY (forwarding) or SECONDARY (standby)
- **Queue depth**: Current backlog (should be near 0 normally)

### Log Files

| Log      | Location                           | Purpose                 |
|----------|------------------------------------|-------------------------|
| Main log | `/var/log/trapninja/trapninja.log` | Operations and errors   |
| Metrics  | `/opt/metrics/`                    | Prometheus/JSON metrics |

View recent logs:
```bash
tail -f /var/log/trapninja/trapninja.log
```

---

## Filtering Traps

### Block by IP Address

Block traps from a noisy or unwanted source:

```bash
# Block an IP
trapninja filter block-ip 10.0.1.50

# Verify
trapninja filter list-blocked-ips

# Remove block
trapninja filter unblock-ip 10.0.1.50
```

### Block by OID

Block specific trap types (e.g., temperature warnings):

```bash
# Block specific OID
trapninja filter block-oid 1.3.6.1.4.1.8072.2.3.0.1

# Block OID prefix (blocks all matching)
trapninja filter block-oid 1.3.6.1.4.1.8072

# List blocked OIDs
trapninja filter list-blocked-oids

# Remove block
trapninja filter unblock-oid 1.3.6.1.4.1.8072.2.3.0.1
```

### Changes Apply Immediately

Filtering changes take effect immediately without restart.

---

## Trap Redirection

Redirection allows you to route specific traps to different destinations based on source IP or trap OID. This is useful for:

- Sending security-related traps to a Security Operations Center (SOC)
- Routing configuration change traps to a separate monitoring system
- Directing vendor-specific traps to specialized NOC teams

### How Redirection Works

```
┌─────────────┐     ┌──────────────────┐     ┌─────────────────────┐
│ Incoming    │     │ Check Redirect   │     │ Forward to:         │
│ Trap        │────▶│ Rules            │────▶│ - Default dest OR   │
│             │     │ (IP then OID)    │     │ - Redirect dest     │
└─────────────┘     └──────────────────┘     └─────────────────────┘
```

1. TrapNinja checks if the source IP matches a redirection rule
2. If no IP match, checks if the trap OID matches a redirection rule
3. If a match is found, the trap is sent to the redirect destination(s) instead of the default
4. If no match, the trap goes to the normal destination(s)

**Note:** Redirected traps are sent *instead of* the default destination, not in addition to it.

### Configuration Files

Redirection uses three configuration files in the `config/` directory:

| File | Purpose |
|------|--------|
| `redirected_ips.json` | Map source IPs to destination tags |
| `redirected_oids.json` | Map trap OIDs to destination tags |
| `redirected_destinations.json` | Define destination groups by tag |

### Step 1: Define Destination Groups

Edit `config/redirected_destinations.json` to define where redirected traps should go:

```json
{
  "security": [
    ["10.234.50.10", 162],
    ["10.234.50.11", 162]
  ],
  "config-changes": [
    ["10.234.60.20", 162]
  ],
  "voice-noc": [
    ["10.234.70.30", 162],
    ["10.234.70.31", 162]
  ]
}
```

Each tag (e.g., "security") maps to a list of `["ip", port]` destinations.

### Step 2: Create IP-Based Redirections

Edit `config/redirected_ips.json` to redirect all traps from specific IPs:

```json
[
  ["10.100.1.50", "security"],
  ["10.100.1.51", "security"],
  ["10.200.5.100", "voice-noc"]
]
```

Format: `["source_ip", "destination_tag"]`

**Use case:** All traps from firewall 10.100.1.50 go to the security team.

### Step 3: Create OID-Based Redirections

Edit `config/redirected_oids.json` to redirect specific trap types:

```json
[
  ["1.3.6.1.4.1.9.9.43.2.0.1", "config-changes"],
  ["1.3.6.1.4.1.9.9.43.2.0.2", "config-changes"],
  ["1.3.6.1.6.3.1.1.5.5", "security"]
]
```

Format: `["trap_oid", "destination_tag"]`

**Common OIDs to redirect:**

| OID | Description | Suggested Tag |
|-----|-------------|---------------|
| `1.3.6.1.6.3.1.1.5.5` | Authentication Failure | security |
| `1.3.6.1.4.1.9.9.43.2.0.1` | Cisco Config Change | config-changes |
| `1.3.6.1.4.1.2636.4.1.1` | Juniper Chassis Alarm | critical |

### Priority: IP vs OID

If both an IP rule and OID rule could match:
- **IP rules are checked first**
- If the source IP matches a rule, that redirection is used
- OID rules are only checked if no IP rule matches

### Example: Complete Setup

**Scenario:** Route security traps to SOC, config changes to change management.

`config/redirected_destinations.json`:
```json
{
  "soc": [
    ["10.50.1.100", 162]
  ],
  "change-mgmt": [
    ["10.50.2.100", 162]
  ]
}
```

`config/redirected_ips.json`:
```json
[
  ["10.1.1.1", "soc"],
  ["10.1.1.2", "soc"]
]
```

`config/redirected_oids.json`:
```json
[
  ["1.3.6.1.6.3.1.1.5.5", "soc"],
  ["1.3.6.1.4.1.9.9.43.2.0.1", "change-mgmt"],
  ["1.3.6.1.4.1.9.9.43.2.0.2", "change-mgmt"]
]
```

### Verify Redirection

After editing config files, verify with statistics:

```bash
# Check overall redirected count
trapninja stats summary

# Look for "Redirected" in output
```

You can also check the log file:
```bash
grep -i redirect /var/log/trapninja/trapninja.log | tail -10
```

### Configuration Reload

Redirection configuration is checked periodically (every 60 seconds by default). Changes will take effect automatically without restart.

To force an immediate reload, restart the service:
```bash
trapninja daemon restart
```

### Troubleshooting Redirection

**Traps not being redirected:**
1. Verify JSON syntax is valid: `python3 -m json.tool config/redirected_ips.json`
2. Check that the destination tag exists in `redirected_destinations.json`
3. Verify IP/OID format is correct (no typos)
4. Check logs: `grep -i redirect /var/log/trapninja/trapninja.log`

**Traps going to wrong destination:**
1. Remember IP rules take priority over OID rules
2. Check for overlapping rules
3. Verify the tag names match exactly (case-sensitive)

---

## High Availability

TrapNinja supports Primary/Secondary clustering for 99.999% availability.

### HA Status

```bash
trapninja ha status
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
trapninja ha promote
```

**On the PRIMARY node:**
```bash
trapninja ha demote
```

Verify both nodes show expected states:
```bash
trapninja ha status
```

### Return to Normal After Maintenance

When maintenance is complete, reverse the process:

**On the original PRIMARY:**
```bash
trapninja ha promote
```

**On the original SECONDARY:**
```bash
trapninja ha demote
```

### Emergency Failover

If PRIMARY fails unexpectedly, SECONDARY auto-promotes within 3-5 seconds.

To force immediate failover:
```bash
trapninja ha force-failover
```

### HA Quick Reference

| Scenario | Action |
|----------|--------|
| Check status | `trapninja ha status` |
| Planned maintenance | `trapninja ha promote` on secondary, then `trapninja ha demote` on primary |
| Force failover | `trapninja ha force-failover` |
| Both nodes confused | `trapninja ha demote` on one node to break tie |

See [HA.md](HA.md) for detailed configuration.

---

## Statistics & Monitoring

### Quick Statistics Summary

```bash
trapninja stats summary
```

### Top Trap Sources

```bash
# Top 10 by volume (default)
trapninja stats top-ips

# Top 20 by current rate
trapninja stats top-ips --count 20 --sort rate

# Top blocked sources
trapninja stats top-ips --sort blocked
```

### Top OIDs (Trap Types)

```bash
# Top 10 by volume
trapninja stats top-oids

# By current rate
trapninja stats top-oids --sort rate
```

### Investigate Specific Source

```bash
trapninja stats ip-details --ip 10.0.0.1
```

Shows:
- Total/forwarded/blocked counts
- Top OIDs from this source
- Rate information
- First/last seen times

### Investigate Specific OID

```bash
trapninja stats oid-details --oid 1.3.6.1.4.1.9.9.41.2.0.1
```

Shows:
- Total/forwarded/blocked counts
- Top source IPs for this OID
- Rate information

### Destination Statistics

```bash
trapninja stats destinations
```

### Export Statistics

```bash
# JSON export
trapninja stats export --format json --output /tmp/stats.json

# Prometheus format
trapninja stats export --format prometheus --output /tmp/stats.prom
```

### Statistics Options Reference

| Option | Description |
|--------|-------------|
| `--count N` | Number of items to show (default: 10) |
| `--sort TYPE` | Sort by: `total`, `rate`, `blocked`, `recent` |
| `--format FMT` | Export format: `json`, `prometheus` |
| `--json` | Output as JSON |
| `--pretty` | Pretty print JSON |

See [GRANULAR_STATS.md](GRANULAR_STATS.md) for all options.

---

## Trap Caching & Replay

TrapNinja caches traps in Redis for replay during monitoring outages.

### Check Cache Status

```bash
trapninja cache status
```

Shows:
- Redis connection status
- Number of cached entries per destination
- Cache time range

### Preview Cached Traps

```bash
# Query default destination, last 2 hours
trapninja cache query --destination default

# Specific time window
trapninja cache query --destination default --from "14:30" --to "15:45"

# Relative time
trapninja cache query --destination default --from "-2h" --to "-1h"
```

### Replay Traps

After a monitoring system outage, replay missed traps:

```bash
# Preview first (dry run)
trapninja cache replay --destination default \
    --from "14:30" --to "15:45" --dry-run

# Actual replay with rate limiting
trapninja cache replay --destination default \
    --from "14:30" --to "15:45" --rate-limit 1000

# Skip confirmation prompt
trapninja cache replay --destination default \
    --from "14:30" --to "15:45" -y
```

### Clear Cache

```bash
# Clear specific destination
trapninja cache clear --destination default

# Clear all
trapninja cache clear -y
```

See [CACHE.md](CACHE.md) for Redis setup and configuration.

---

## SNMPv3 Decryption

TrapNinja can decrypt SNMPv3 traps and forward them as SNMPv2c.

### Check SNMPv3 Status

```bash
trapninja snmpv3 status
```

### Add SNMPv3 User

Interactive mode (recommended - passwords not shown on screen):

```bash
trapninja snmpv3 add-user \
    --username myuser \
    --engine-id 80001f888056565656565656 \
    --auth-protocol SHA \
    --priv-protocol AES128
```

You'll be prompted to enter and confirm both passphrases:

```
Authentication passphrase for myuser: 
Confirm authentication passphrase: 
Privacy passphrase for myuser: 
Confirm privacy passphrase: 
✓ Added user myuser for engine 80001f888056565656565656
```

For scripted deployments, passphrases can be provided directly:

```bash
trapninja snmpv3 add-user \
    --username myuser \
    --engine-id 80001f888056565656565656 \
    --auth-protocol SHA \
    --auth-passphrase "MyAuthPassword123" \
    --priv-protocol AES128 \
    --priv-passphrase "MyPrivPassword456"
```

**Note:** Passphrases must be at least 8 characters.

### List Configured Users

```bash
trapninja snmpv3 list-users
```

### Remove User

```bash
trapninja snmpv3 remove-user \
    --engine-id 80001f888056565656565656 \
    --username myuser
```

See [SNMPV3_CREDENTIALS.md](SNMPV3_CREDENTIALS.md) for complete documentation including supported protocols, Engine ID formats, vendor-specific examples, and troubleshooting.

---

## Configuration Files

All configuration files are in the `config/` directory.

| File | Purpose |
|------|---------|
| `trapninja.json` | Main config (interface, bind_address, capture mode) |
| `destinations.json` | Default forwarding destinations |
| `listen_ports.json` | UDP ports to listen on |
| `blocked_ips.json` | IPs to block (managed via CLI) |
| `blocked_traps.json` | OIDs to block (managed via CLI) |
| `redirected_ips.json` | IPs to redirect (edit manually) |
| `redirected_oids.json` | OIDs to redirect (edit manually) |
| `redirected_destinations.json` | Redirect destination groups |
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
trapninja daemon foreground --debug
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
trapninja ha status | grep Forwarding

# Check destinations configured
cat config/destinations.json

# Check if source is blocked
trapninja filter list-blocked-ips
```

### High CPU Usage

```bash
# Check capture mode
trapninja daemon status | grep -i capture

# Enable eBPF (requires root and BCC)
sudo trapninja daemon start
```

### HA Issues

```bash
# Check peer connectivity
nc -vzu <peer_ip> 5000

# Check HA logs
grep "HA:" /var/log/trapninja/trapninja.log | tail -20
```

See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for comprehensive diagnostics.

---

## Quick Reference Card

### Daily Operations

```bash
# Start/stop
trapninja daemon start
trapninja daemon stop
trapninja daemon restart
trapninja daemon status

# HA management
trapninja ha status
trapninja ha promote
trapninja ha demote

# Statistics
trapninja stats summary
trapninja stats top-ips
trapninja stats top-oids
trapninja stats destinations
```

### Filtering

```bash
# Block/unblock IPs
trapninja filter block-ip <ip>
trapninja filter unblock-ip <ip>
trapninja filter list-blocked-ips

# Block/unblock OIDs
trapninja filter block-oid <oid>
trapninja filter unblock-oid <oid>
trapninja filter list-blocked-oids
```

### Cache Operations

```bash
trapninja cache status
trapninja cache query --destination <dest> --from <time> --to <time>
trapninja cache replay --destination <dest> --from <time> --to <time>
```

### Help

```bash
trapninja --help
trapninja daemon --help
trapninja ha --help
trapninja cache --help
trapninja stats --help
trapninja filter --help
```

---

## Getting Help

- **Main Help**: `trapninja --help`
- **Category Help**: `trapninja <category> --help`
  - `trapninja daemon --help`
  - `trapninja ha --help`
  - `trapninja cache --help`
  - `trapninja stats --help`
  - `trapninja filter --help`
  - `trapninja snmpv3 --help`
- **Detailed docs**: See other files in the `docs/` directory

### Related Documentation

| Document | Contents |
|----------|----------|
| [CLI.md](CLI.md) | Full CLI reference with all subcommands |
| [HA.md](HA.md) | HA configuration and deployment |
| [CACHE.md](CACHE.md) | Redis cache setup |
| [METRICS.md](METRICS.md) | Prometheus metrics reference |
| [GRANULAR_STATS.md](GRANULAR_STATS.md) | Statistics system details |
| [SNMPV3_CREDENTIALS.md](SNMPV3_CREDENTIALS.md) | SNMPv3 user credentials and decryption |
| [TROUBLESHOOTING.md](TROUBLESHOOTING.md) | Problem diagnosis |
| [ARCHITECTURE.md](ARCHITECTURE.md) | System internals |

---

*TrapNinja v0.8.0*
