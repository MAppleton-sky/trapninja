# TrapNinja Configuration Guide

## Overview

TrapNinja uses JSON configuration files stored in the configuration directory. The configuration directory is determined in the following priority order:

1. `TRAPNINJA_CONFIG` environment variable
2. `/etc/trapninja` (standard system location)
3. `./config` (relative to source directory, for development)
4. `/opt/trapninja/config` (default installation location)

## Configuration Files

| File | Purpose |
|------|---------|
| `trapninja.json` | Main configuration (interface, bind address, capture mode) |
| `destinations.json` | Forward destinations |
| `listen_ports.json` | UDP ports to listen on |
| `blocked_ips.json` | Source IPs to block |
| `blocked_traps.json` | Trap OIDs to block |
| `redirected_ips.json` | IP-based redirection rules |
| `redirected_oids.json` | OID-based redirection rules |
| `redirected_destinations.json` | Redirection destination groups |
| `ha_config.json` | High availability settings |
| `cache_config.json` | Redis cache settings |

---

## Main Configuration (trapninja.json)

The main configuration file controls core TrapNinja settings.

### Example

```json
{
  "interface": "eth0",
  "bind_address": "10.1.2.3",
  "capture_mode": "auto",
  "config_check_interval": 60
}
```

### Settings

#### interface

The network interface to capture SNMP traps on.

| Value | Description |
|-------|-------------|
| `"eth0"`, `"ens192"`, etc. | Specific interface name |
| `null` or omitted | Auto-detect (recommended) |

**Auto-detection priority:**
1. First non-loopback interface with an IP address
2. Common interface names (eth0, ens192, ens160, enp0s3, etc.)
3. First available non-loopback interface
4. Falls back to `eth0` if detection fails

**Environment variable override:** `TRAPNINJA_INTERFACE`

#### bind_address

The IP address to bind the SNMP trap listener to. This is a security setting (CWE-284) that restricts which network interface accepts incoming traps.

| Value | Description |
|-------|-------------|
| `"10.1.2.3"` | Specific IP address to bind to |
| `null` or omitted | Auto-detect from configured interface |

**Auto-detection behavior:**
1. If `bind_address` is set explicitly, use that IP
2. Otherwise, try to get the IP address of the configured `interface`
3. Fall back to `0.0.0.0` (all interfaces) with a warning if detection fails

**Security recommendation:** Always set an explicit `bind_address` in production environments to prevent trap reception on unintended network interfaces.

#### capture_mode

Packet capture method.

| Value | Description |
|-------|-------------|
| `"auto"` | Use eBPF if available, fall back to sniff (recommended) |
| `"sniff"` | Use Scapy sniff() with libpcap |
| `"socket"` | Use UDP socket listeners |

**Warning:** Never run both socket and sniff modes simultaneously - it causes packet duplication.

#### config_check_interval

How often (in seconds) to check for configuration file changes. Default: 60

---

## Deployment Examples

### Server with eth0 (default Linux)

```json
{
  "interface": "eth0",
  "bind_address": "10.1.2.3",
  "capture_mode": "auto"
}
```

### Server with ens192 (VMware)

```json
{
  "interface": "ens192",
  "bind_address": "192.168.1.100",
  "capture_mode": "auto"
}
```

### Auto-detect interface (recommended for portability)

```json
{
  "interface": null,
  "bind_address": null,
  "capture_mode": "auto"
}
```

Or simply omit the file entirely - TrapNinja will auto-detect.

### Using environment variable

```bash
# In systemd service file or shell
export TRAPNINJA_INTERFACE=ens192
```

---

## Destinations Configuration (destinations.json)

Defines where to forward SNMP traps.

### Format

```json
[
  ["192.168.1.100", 162],
  ["10.0.0.50", 1162],
  {"host": "snmp-collector.example.com", "port": 162}
]
```

Each destination can be:
- Array: `[host, port]`
- Object: `{"host": "...", "port": 162}`

---

## Listen Ports Configuration (listen_ports.json)

UDP ports to listen for incoming traps.

### Format

```json
[162, 1162, 10162]
```

Default: `[162]`

**Note:** Ports below 1024 require root privileges.

---

## Blocked IPs Configuration (blocked_ips.json)

Source IP addresses to silently drop.

### Format

```json
[
  "10.0.0.1",
  "192.168.100.50",
  "172.16.0.0"
]
```

---

## Blocked Traps Configuration (blocked_traps.json)

Trap OIDs to silently drop.

### Format

```json
[
  "1.3.6.1.4.1.9.9.41.2.0.1",
  "1.3.6.1.6.3.1.1.5.3"
]
```

---

## Redirection Configuration

### redirected_ips.json

Map source IPs to destination tags.

```json
[
  ["10.0.1.100", "voice-team"],
  ["10.0.2.0/24", "core-network"]
]
```

### redirected_oids.json

Map trap OIDs to destination tags.

```json
[
  ["1.3.6.1.4.1.9.9.41.2.0.1", "security-team"],
  ["1.3.6.1.6.3.1.1.5", "operations"]
]
```

### redirected_destinations.json

Define destination groups for redirection tags.

```json
{
  "voice-team": [
    ["10.100.1.50", 162],
    ["10.100.1.51", 162]
  ],
  "security-team": [
    ["10.100.2.100", 1162]
  ],
  "core-network": [
    ["10.100.3.200", 162]
  ]
}
```

---

## CLI Configuration Commands

### Show current configuration

```bash
trapninja daemon config
trapninja daemon config --json
```

### Validate configuration

```bash
trapninja daemon config --validate
```

---

## Best Practices

1. **Set explicit bind_address for security** - Always configure `bind_address` in production to restrict which interface accepts traps (CWE-284 mitigation).

2. **Use auto-detection for portability** - Set `"interface": null` to allow deployment across different server types without configuration changes.

3. **Use environment variables for deployment** - Set `TRAPNINJA_CONFIG` and `TRAPNINJA_INTERFACE` in your systemd service file for environment-specific settings.

4. **Validate before deploying** - Always run `--validate-config` after making changes.

5. **Keep HA nodes in sync** - Use config sync or shared configuration management (Ansible, etc.) to keep Primary and Secondary configurations aligned.
