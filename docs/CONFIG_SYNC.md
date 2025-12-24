# TrapNinja HA Configuration Synchronization

## Overview

Configuration synchronization keeps shared configurations synchronized between HA cluster nodes. The PRIMARY node is the authoritative source and pushes changes to SECONDARY nodes automatically.

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                    CONFIG SYNC ARCHITECTURE                           │
│                                                                       │
│   PRIMARY Node                           SECONDARY Node               │
│   ┌─────────────────────┐               ┌─────────────────────┐      │
│   │  Config Files       │               │  Config Files       │      │
│   │  ┌───────────────┐  │               │  ┌───────────────┐  │      │
│   │  │destinations   │──┼───Push────────┼─►│destinations   │  │      │
│   │  │blocked_ips    │──┼───────────────┼─►│blocked_ips    │  │      │
│   │  │blocked_traps  │──┼───────────────┼─►│blocked_traps  │  │      │
│   │  │redirected_*   │──┼───────────────┼─►│redirected_*   │  │      │
│   │  └───────────────┘  │               │  └───────────────┘  │      │
│   │                     │               │                     │      │
│   │  Local Only:        │               │  Local Only:        │      │
│   │  ┌───────────────┐  │               │  ┌───────────────┐  │      │
│   │  │ha_config      │  │   (NOT        │  │ha_config      │  │      │
│   │  │cache_config   │  │   SYNCED)     │  │cache_config   │  │      │
│   │  │listen_ports   │  │               │  │listen_ports   │  │      │
│   │  └───────────────┘  │               │  └───────────────┘  │      │
│   └─────────────────────┘               └─────────────────────┘      │
│              │                                    ▲                   │
│              │          HA TCP Channel            │                   │
│              └──────────────────────────────────►─┘                   │
│                   (Uses existing HA sockets)                          │
└──────────────────────────────────────────────────────────────────────┘
```

## Synchronized vs Local Configurations

### Synchronized Configurations (Shared Between Nodes)

These configurations define trap handling behavior and should be identical across all HA nodes:

| File | Description |
|------|-------------|
| `destinations.json` | Forward destinations for traps |
| `blocked_ips.json` | Blocked source IP addresses |
| `blocked_traps.json` | Blocked trap OIDs |
| `redirected_ips.json` | IP-based redirection rules |
| `redirected_oids.json` | OID-based redirection rules |
| `redirected_destinations.json` | Redirection target destinations |

### Local-Only Configurations (Node-Specific)

These configurations are specific to each node and should NOT be synchronized:

| File | Description |
|------|-------------|
| `ha_config.json` | HA mode, priority, peer address |
| `cache_config.json` | Redis cache settings |
| `listen_ports.json` | Listening ports |
| `capture_config.json` | Packet capture settings |
| `shadow_config.json` | Shadow mode settings |
| `stats_config.json` | Statistics settings |
| `sync_config.json` | Config sync settings |

## Quick Start

### Enable Config Sync on Both Nodes

```bash
# On PRIMARY
python trapninja.py --enable-sync

# On SECONDARY  
python trapninja.py --enable-sync

# Restart services
python trapninja.py --restart
```

### Verify Sync Status

```bash
python trapninja.py --sync-status
```

Expected output:
```
======================================================================
Config Sync Status
======================================================================

Configuration:
  Enabled: True
  Sync on startup: True
  Sync on promotion: True
  Push on file change: True
  Version check interval: 30s
  Primary authority: True

Runtime Status:
  HA State: primary
  Instance: 8f7e3a2b...

Statistics:
  Pushes sent: 12
  Pushes received: 0
  Conflicts: 0
  Errors: 0
  Last sync: 5.2s ago

Config Versions:
  Config                         Local        Peer         Status
  ------------------------------ ------------ ------------ ----------
  destinations                   a3f82b1c     a3f82b1c     ✓ In sync
  blocked_ips                    92e7d4f0     92e7d4f0     ✓ In sync
  blocked_traps                  -            -            -
  redirected_ips                 f1c83e9a     f1c83e9a     ✓ In sync
  redirected_oids                8b2e4c7d     8b2e4c7d     ✓ In sync
  redirected_destinations        c9f1a2b3     c9f1a2b3     ✓ In sync
======================================================================
```

## Configuration

### sync_config.json

```json
{
  "enabled": true,
  "sync_on_startup": true,
  "sync_on_promotion": true,
  "push_on_file_change": true,
  "version_check_interval": 30,
  "primary_authority": true,
  "sync_timeout": 10.0
}
```

### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | false | Enable config synchronization |
| `sync_on_startup` | bool | true | Sync configs when service starts |
| `sync_on_promotion` | bool | true | Push configs when becoming PRIMARY |
| `push_on_file_change` | bool | true | Auto-push when local configs change |
| `version_check_interval` | int | 30 | Seconds between version checks (SECONDARY) |
| `primary_authority` | bool | true | Only PRIMARY can push changes |
| `sync_timeout` | float | 10.0 | Timeout for sync operations |

## How It Works

### Automatic Sync Flow

1. **Startup Sync**: When service starts, SECONDARY requests configs from PRIMARY
2. **File Monitoring**: PRIMARY monitors config files for changes
3. **Auto Push**: When a synced config changes on PRIMARY, it's pushed to SECONDARY
4. **Version Checking**: SECONDARY periodically checks version checksums with PRIMARY
5. **Pull on Mismatch**: If versions differ, SECONDARY pulls updated configs

### Failover Behavior

When failover occurs:

1. **New PRIMARY** (was SECONDARY): Pushes its configs to the peer
2. **New SECONDARY** (was PRIMARY): Pulls configs from new PRIMARY

This ensures the new PRIMARY's configuration becomes authoritative.

### Version Tracking

Each config file has version metadata:

- **Checksum**: MD5 hash of config content
- **Modification time**: File mtime
- **Size**: File size in bytes

Version mismatches trigger synchronization.

## CLI Commands

### Status Commands

```bash
# Show sync status
python trapninja.py --sync-status

# Show config differences between nodes
python trapninja.py --sync-diff

# Show sync help
python trapninja.py --sync-help
```

### Configuration Commands

```bash
# Enable sync
python trapninja.py --enable-sync

# Disable sync
python trapninja.py --disable-sync

# Configure sync settings
python trapninja.py --configure-sync \
  --sync-on-startup \
  --push-on-file-change \
  --version-check-interval 60
```

### Manual Sync Commands

```bash
# Push all configs to peer (PRIMARY only)
python trapninja.py --sync-push

# Push specific config
python trapninja.py --sync-push --config destinations

# Pull all configs from peer (SECONDARY)
python trapninja.py --sync-pull

# Force push (bypass authority check)
python trapninja.py --sync-push --force
```

## Integration with HA

Config sync uses the existing HA TCP socket communication:

```
┌─────────────┐                      ┌─────────────┐
│   PRIMARY   │                      │  SECONDARY  │
│             │                      │             │
│  HA Cluster │◄────Heartbeat───────►│  HA Cluster │
│             │                      │             │
│  Config     │─────Config Push────►│  Config     │
│  Sync Mgr   │◄────Version Req─────│  Sync Mgr   │
│             │─────Version Resp───►│             │
└─────────────┘                      └─────────────┘
```

### Message Types

| Message | Direction | Description |
|---------|-----------|-------------|
| `config_version_request` | SECONDARY → PRIMARY | Request version checksums |
| `config_version_response` | PRIMARY → SECONDARY | Return version checksums |
| `config_request` | SECONDARY → PRIMARY | Request full config data |
| `config_response` | PRIMARY → SECONDARY | Return full config data |
| `config_push` | PRIMARY → SECONDARY | Push updated config |
| `config_ack` | SECONDARY → PRIMARY | Acknowledge config received |

## Conflict Resolution

### Primary Authority Mode (Default)

When `primary_authority: true`:

- Only PRIMARY can push configs
- SECONDARY rejects push attempts with error
- Ensures single source of truth

### Split-Brain Handling

During split-brain:

- Config sync is effectively paused
- Both nodes may have different configs
- After resolution, winning PRIMARY pushes configs

### Manual Override

Use `--force` flag to bypass authority checks:

```bash
# Force push from SECONDARY (emergency use)
python trapninja.py --sync-push --force
```

## Troubleshooting

### Sync Not Working

1. Check sync is enabled:
   ```bash
   python trapninja.py --sync-status
   ```

2. Verify HA connectivity:
   ```bash
   python trapninja.py --ha-status
   ```

3. Check logs:
   ```bash
   grep "Config sync" /var/log/trapninja/trapninja.log
   ```

### Version Mismatch Persists

1. Check for local file permissions:
   ```bash
   ls -la /opt/trapninja/config/
   ```

2. Force a full sync:
   ```bash
   # On SECONDARY
   python trapninja.py --sync-pull --force
   ```

### Push Rejected

If PRIMARY's push is rejected:

1. Check peer is SECONDARY:
   ```bash
   ssh peer "python trapninja.py --ha-status"
   ```

2. Check for split-brain condition

3. Verify `primary_authority` setting

## Best Practices

### Configuration Changes

1. **Always make changes on PRIMARY**: Edit configs on the PRIMARY node
2. **Verify sync**: Check `--sync-status` after changes
3. **Document changes**: Use version control for config files

### Failover Procedures

1. Before planned failover:
   - Verify configs are in sync: `--sync-diff`
   
2. After failover:
   - Check new PRIMARY's configs are pushed
   - Verify SECONDARY received updates

### Monitoring

1. Monitor sync statistics via Prometheus metrics:
   ```
   trapninja_sync_pushes_total
   trapninja_sync_pulls_total
   trapninja_sync_conflicts_total
   trapninja_sync_errors_total
   ```

2. Alert on:
   - Persistent version mismatches
   - Sync errors
   - Conflicts

## Example Scenarios

### Scenario 1: Add New Destination on PRIMARY

```bash
# On PRIMARY - edit config
vi /opt/trapninja/config/destinations.json
# Add new destination

# Config is auto-pushed to SECONDARY (if push_on_file_change=true)
# Or manually push:
python trapninja.py --sync-push --config destinations

# Verify on SECONDARY
ssh secondary "python trapninja.py --sync-status"
```

### Scenario 2: Initial Setup with Existing Configs

```bash
# Configure sync on both nodes
# On PRIMARY:
python trapninja.py --configure-sync --enabled

# On SECONDARY:
python trapninja.py --configure-sync --enabled

# Start PRIMARY first
python trapninja.py --start

# Start SECONDARY - will pull configs automatically
python trapninja.py --start
```

### Scenario 3: Recover from Split-Brain

```bash
# After split-brain is resolved, check configs
python trapninja.py --sync-diff

# If configs differ, force sync from authoritative node
# On PRIMARY:
python trapninja.py --sync-push

# Or on SECONDARY if PRIMARY had wrong config:
python trapninja.py --sync-push --force
```

---

**Last Updated**: 2025-01-15
