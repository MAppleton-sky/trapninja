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

**Last Updated**: 2025-01-10
