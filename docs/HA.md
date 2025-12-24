# TrapNinja High Availability Guide

## Overview

TrapNinja supports High Availability (HA) clustering with automatic failover for environments requiring 99.999% uptime. The HA system uses a Primary/Secondary model where only the PRIMARY node forwards traps.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                      HA CLUSTER                                      │
│                                                                      │
│   Primary Node                        Secondary Node                 │
│   ┌─────────────────┐                ┌─────────────────┐            │
│   │    TrapNinja    │◄──Heartbeat───►│    TrapNinja    │            │
│   │                 │    (1s UDP)    │                 │            │
│   │  State: PRIMARY │                │  State: SECONDARY│            │
│   │  Forwarding: ON │                │  Forwarding: OFF│            │
│   └────────┬────────┘                └────────┬────────┘            │
│            │                                  │                      │
│            ▼                                  ▼                      │
│      Forwards Traps                    Drops Traps                   │
│     to Destinations                  (monitors only)                 │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

## Quick Setup

### Primary Node

```bash
# Configure as primary
python trapninja.py --configure-ha \
    --ha-mode primary \
    --ha-peer-host 192.168.1.102 \
    --ha-priority 150

# Start service
python trapninja.py --start
```

### Secondary Node

```bash
# Configure as secondary
python trapninja.py --configure-ha \
    --ha-mode secondary \
    --ha-peer-host 192.168.1.101 \
    --ha-priority 100

# Start service
python trapninja.py --start
```

### Verify HA Status

```bash
# Check status on both nodes
python trapninja.py --ha-status
```

Expected output on PRIMARY:
```
HA Status: primary
Forwarding: True
Peer: 192.168.1.102:5000
Peer Status: CONNECTED
Last Heartbeat: 1s ago
```

Expected output on SECONDARY:
```
HA Status: secondary
Forwarding: False
Peer: 192.168.1.101:5000
Peer Status: CONNECTED
Last Heartbeat: 1s ago
```

## Configuration

### Configuration File

Location: `config/ha_config.json`

```json
{
    "enabled": true,
    "mode": "primary",
    "peer_host": "192.168.1.102",
    "peer_port": 5000,
    "local_port": 5000,
    "priority": 150,
    "heartbeat_interval": 1.0,
    "heartbeat_timeout": 3.0,
    "failover_delay": 2.0,
    "shared_secret": "your-secret-key",
    "auto_failback": false
}
```

### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | false | Enable HA functionality |
| `mode` | string | "standalone" | Role: "primary", "secondary", or "standalone" |
| `peer_host` | string | - | IP address of peer node |
| `peer_port` | int | 5000 | UDP port for HA communication |
| `local_port` | int | 5000 | Local UDP port for HA |
| `priority` | int | 100 | Election priority (higher wins) |
| `heartbeat_interval` | float | 1.0 | Seconds between heartbeats |
| `heartbeat_timeout` | float | 3.0 | Seconds before peer is considered dead |
| `failover_delay` | float | 2.0 | Delay before assuming PRIMARY role |
| `shared_secret` | string | - | Authentication key for HA messages |
| `auto_failback` | bool | false | Automatically return to SECONDARY when original PRIMARY returns |

## HA States

| State | Forwarding | Description |
|-------|------------|-------------|
| PRIMARY | Yes | Active node, forwards all traps |
| SECONDARY | No | Standby node, drops traps |
| STANDALONE | Yes | No HA configured, forwards all traps |
| INITIALIZING | No | Starting up, determining role |
| FAILOVER | No | Transitioning between states |
| SPLIT_BRAIN | No | Both nodes detected as primary |
| ERROR | No | Error condition, manual intervention needed |

## Failover Scenarios

### Automatic Failover

When the PRIMARY node fails:

1. SECONDARY detects missed heartbeats (3+ seconds)
2. SECONDARY waits `failover_delay` (2 seconds)
3. SECONDARY promotes itself to PRIMARY
4. SECONDARY begins forwarding traps
5. Total failover time: <5 seconds (typically 3-4 seconds)

### Manual Failover (Maintenance)

For planned maintenance on the PRIMARY:

```bash
# On PRIMARY - demote to secondary
python trapninja.py --demote

# On SECONDARY - promote to primary
python trapninja.py --promote
```

Or use force failover:

```bash
# Trigger immediate failover
python trapninja.py --force-failover
```

### Failback

When the original PRIMARY returns:

**With `auto_failback: false` (default, recommended):**
- Original PRIMARY stays as SECONDARY
- Manual intervention required to restore original roles
- Prevents "ping-pong" scenarios

**With `auto_failback: true`:**
- Original PRIMARY automatically resumes PRIMARY role
- Current PRIMARY demotes to SECONDARY
- Brief interruption during transition

### Split-Brain Handling

If both nodes believe they are PRIMARY:

1. Split-brain detected via heartbeat messages
2. Both nodes enter SPLIT_BRAIN state (forwarding disabled)
3. Priority-based election determines winner
4. Lower priority node demotes to SECONDARY
5. Higher priority node becomes PRIMARY

## Firewall Requirements

| Port | Protocol | Direction | Purpose |
|------|----------|-----------|---------|
| 5000 | UDP | Bidirectional | HA heartbeat and state sync |
| 162 | UDP | Inbound | SNMP trap reception |

```bash
# Example firewall rules (firewalld)
firewall-cmd --permanent --add-port=5000/udp
firewall-cmd --permanent --add-port=162/udp
firewall-cmd --reload
```

## Monitoring

### Prometheus Metrics

HA-related metrics exported on the metrics endpoint:

| Metric | Type | Description |
|--------|------|-------------|
| `trapninja_ha_state` | Gauge | Current HA state (1=PRIMARY, 2=SECONDARY, etc.) |
| `trapninja_ha_forwarding` | Gauge | Forwarding enabled (1=yes, 0=no) |
| `trapninja_ha_peer_connected` | Gauge | Peer connection status |
| `trapninja_ha_last_heartbeat_seconds` | Gauge | Time since last heartbeat |
| `trapninja_ha_failovers_total` | Counter | Total failover events |
| `trapninja_traps_ha_blocked_total` | Counter | Traps dropped due to HA state |

### Log Messages

Key HA log messages to monitor:

```
INFO  - HA: Trap forwarding ENABLED - this instance is active
INFO  - HA: Trap forwarding DISABLED - this instance is standby
INFO  - HA: Peer heartbeat timeout, initiating failover
INFO  - HA: Promoted to PRIMARY
INFO  - HA: Demoted to SECONDARY
WARN  - HA: Split-brain detected, resolving...
ERROR - HA: Failed to connect to peer
```

## CLI Commands

```bash
# Configure HA
python trapninja.py --configure-ha \
    --ha-mode <primary|secondary> \
    --ha-peer-host <ip> \
    --ha-priority <number>

# Show HA status
python trapninja.py --ha-status

# Manual promotion
python trapninja.py --promote

# Manual demotion
python trapninja.py --demote

# Force failover
python trapninja.py --force-failover

# Disable HA
python trapninja.py --disable-ha

# Show HA help
python trapninja.py --ha-help
```

## Troubleshooting

### Secondary Forwarding When It Shouldn't

**Symptom**: Secondary node forwards traps despite showing SECONDARY state.

**Cause**: HA check not being executed at packet processing time.

**Verification**:
```bash
# Check ha_blocked counter - should increment on SECONDARY
python trapninja.py --status | grep ha_blocked
```

**Solution**: Ensure using TrapNinja 0.5.0+ which includes the HA forwarding fix.

### Heartbeat Failures

**Symptom**: Frequent failovers, peer shown as disconnected.

**Checks**:
1. Firewall allowing UDP port 5000
2. Network connectivity between nodes
3. Correct peer IP in configuration

```bash
# Test connectivity
nc -vzu <peer_ip> 5000

# Check firewall
firewall-cmd --list-ports
```

### Split-Brain Condition

**Symptom**: Both nodes in SPLIT_BRAIN state, no forwarding.

**Cause**: Network partition or heartbeat issues.

**Resolution**:
1. Check network connectivity
2. Manually demote one node: `python trapninja.py --demote`
3. Verify only one PRIMARY exists

### HA State Not Persisting

**Symptom**: Node reverts to wrong state after restart.

**Checks**:
1. Configuration file permissions
2. Disk space for config directory
3. Check config file after restart

```bash
cat config/ha_config.json | python -m json.tool
```

### High ha_blocked Counter on Primary

**Symptom**: PRIMARY node shows high ha_blocked count.

**Cause**: May indicate brief periods where HA thought it was SECONDARY.

**Investigation**:
```bash
# Check logs for state transitions
grep "HA:" /var/log/trapninja.log | tail -50
```

## Configuration Synchronization

TrapNinja HA includes automatic configuration synchronization between Primary and Secondary nodes. This feature keeps shared configurations (destinations, block lists, redirection rules) in sync without requiring Redis.

### How It Works

1. **Heartbeat Checksums**: Each heartbeat includes a checksum of shared configurations
2. **Automatic Detection**: If checksums differ for 3+ heartbeats, sync is triggered
3. **Push on Change**: Config changes on Primary are automatically pushed to Secondary
4. **Primary-Authoritative**: Primary is the single source of truth

### Synchronized Configurations

- `destinations.json` - Trap forwarding destinations
- `blocked_ips.json` - Blocked source IPs
- `blocked_traps.json` - Blocked trap OIDs
- `redirected_ips.json` - IP-based redirection rules
- `redirected_oids.json` - OID-based redirection rules
- `redirected_destinations.json` - Redirection destination groups

### NOT Synchronized (Server-Specific)

- `ha_config.json` - Different on each node (mode, peer, priority)
- `listen_ports.json` - May differ for testing
- `cache_config.json` - Cache may not be on all servers

### Config Sync Commands

```bash
# Show sync status
python trapninja.py --config-sync-status

# Trigger manual sync
python trapninja.py --config-sync

# Force sync (ignore checksums)
python trapninja.py --config-sync --force
```

### Making Config Changes

1. **Always modify on Primary**: Changes should be made on the Primary server
2. **Automatic propagation**: Changes are automatically pushed to Secondary
3. **Verify sync**: Use `--config-sync-status` to confirm propagation

For detailed config sync documentation, see [CONFIG_SYNC.md](CONFIG_SYNC.md).

## Rolling Upgrades and Version Compatibility

TrapNinja HA supports mixed-version operation during rolling upgrades.

### Version Compatibility (0.7.9+)

Starting with version 0.7.9, TrapNinja HA uses backward-compatible message
serialization that allows nodes running different versions to communicate
without checksum failures.

**How it works:**
- Newer optional fields (like `config_checksum`) are excluded from checksum
  calculation when null
- Older versions that don't have these fields will produce matching checksums
- This enables zero-downtime upgrades in HA clusters

### Rolling Upgrade Procedure

1. **Upgrade Secondary First**:
   ```bash
   # On Secondary
   python trapninja.py --stop
   # Deploy new version
   python trapninja.py --start
   ```

2. **Verify Secondary Health**:
   ```bash
   python trapninja.py --ha-status
   # Confirm SECONDARY state, peer connected
   ```

3. **Failover to Secondary**:
   ```bash
   # On Primary
   python trapninja.py --demote
   ```

4. **Upgrade Original Primary**:
   ```bash
   python trapninja.py --stop
   # Deploy new version
   python trapninja.py --start
   ```

5. **Optional: Restore Original Roles**:
   ```bash
   # If you want original primary back as primary
   python trapninja.py --promote
   ```

### Troubleshooting Version Mismatches

If you see "HA message checksum failed" in logs:

1. **Check Versions**: Ensure both nodes are running 0.7.9 or later
2. **View Debug Logs**: Check debug output for checksum details
3. **Upgrade Both Nodes**: If running pre-0.7.9 on either node, upgrade both

```bash
# Enable debug logging temporarily
export TRAPNINJA_LOG_LEVEL=DEBUG
python trapninja.py --start
```

---

## Best Practices

### Deployment

1. **Use identical configurations** on both nodes (except mode and priority)
2. **Set distinct priorities** - PRIMARY should have higher priority
3. **Use shared secret** for production deployments
4. **Test failover** before production deployment
5. **Monitor ha_blocked metric** to verify SECONDARY isn't leaking traps

### Network

1. **Dedicated HA network** - Use separate VLAN if possible
2. **Low latency** - Keep nodes in same datacenter or low-latency link
3. **Redundant network paths** - Avoid single point of failure

### Operations

1. **Use manual failover** for planned maintenance
2. **Disable auto_failback** to prevent ping-pong scenarios
3. **Monitor both nodes** with alerting on state changes
4. **Test failover regularly** as part of DR testing

## Example Configurations

### Primary Node (`ha_config.json`)

```json
{
    "enabled": true,
    "mode": "primary",
    "peer_host": "192.168.1.102",
    "peer_port": 5000,
    "local_port": 5000,
    "priority": 150,
    "heartbeat_interval": 1.0,
    "heartbeat_timeout": 3.0,
    "failover_delay": 2.0,
    "shared_secret": "trapninja-ha-secret-2025",
    "auto_failback": false
}
```

### Secondary Node (`ha_config.json`)

```json
{
    "enabled": true,
    "mode": "secondary",
    "peer_host": "192.168.1.101",
    "peer_port": 5000,
    "local_port": 5000,
    "priority": 100,
    "heartbeat_interval": 1.0,
    "heartbeat_timeout": 3.0,
    "failover_delay": 2.0,
    "shared_secret": "trapninja-ha-secret-2025",
    "auto_failback": false
}
```

---

## Configuration Synchronization

TrapNinja supports automatic synchronization of shared configurations between HA nodes. This ensures both nodes have identical trap handling rules.

### Enable Config Sync

```bash
# Enable on both nodes
python trapninja.py --enable-sync

# Check status
python trapninja.py --sync-status

# Show differences
python trapninja.py --sync-diff
```

### Synced vs Local Configs

**Synced** (identical on both nodes):
- `destinations.json`
- `blocked_ips.json`, `blocked_traps.json`
- `redirected_*.json`

**Local** (node-specific):
- `ha_config.json`
- `cache_config.json`
- `listen_ports.json`

See [CONFIG_SYNC.md](CONFIG_SYNC.md) for detailed documentation.

---

**Last Updated**: 2025-12-24
