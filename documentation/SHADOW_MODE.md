git # TrapNinja Shadow/Parallel Mode Guide

## Overview

Shadow and parallel modes allow TrapNinja to run **alongside an existing SNMP trap receiver** for testing, comparison, and validation purposes. This is essential for migration scenarios where you want to verify TrapNinja's behavior before replacing your current solution.

## How It Works

Traditional SNMP trap receivers bind to UDP port 162, preventing other applications from receiving traps on the same port. TrapNinja's shadow/parallel modes use **libpcap-based packet capture** (via Scapy's `sniff()` function) which captures packets at the network layer without binding to the port.

| Capture Mode | Port Binding | Parallel Operation | Method |
|--------------|--------------|-------------------|--------|
| `socket`     | YES (exclusive) | ❌ No | UDP socket.bind() |
| `sniff`      | NO | ✅ Yes | libpcap raw capture |
| `ebpf`       | NO | ✅ Yes | Kernel eBPF program |

## Operating Modes

### Shadow Mode (Observe Only)

Shadow mode captures and processes traps but **does NOT forward** them. Perfect for validating routing rules, counting traps, and testing your configuration before deployment.

```bash
# Run in shadow mode (observe only, no forwarding)
sudo python3 trapninja.py --foreground --shadow-mode --debug
```

**Characteristics:**
- Uses sniff capture (libpcap)
- Can run alongside existing trap receivers
- Traps are counted and processed but NOT forwarded
- Full statistics collection
- Useful for testing routing rules

### Mirror Mode (Parallel Forwarding)

Mirror mode captures traps using sniff mode AND forwards them, running in parallel with your existing receiver. Both systems will receive and forward the same traps.

```bash
# Run in mirror mode (parallel capture and forward)
sudo python3 trapninja.py --foreground --mirror-mode --debug
```

**Characteristics:**
- Uses sniff capture (libpcap)
- Can run alongside existing trap receivers  
- Both TrapNinja AND existing receiver forward traps
- Use for comparison testing
- **WARNING:** Destinations will receive duplicate traps!

### Parallel Capture Mode

Simply forces sniff capture mode without changing forwarding behavior. Use when you need TrapNinja to coexist with another receiver but still forward traps.

```bash
# Enable parallel capture
sudo python3 trapninja.py --foreground --parallel
```

## Command Line Options

| Option | Description |
|--------|-------------|
| `--shadow-mode` | Enable shadow mode (observe only, no forwarding) |
| `--mirror-mode` | Enable mirror mode (parallel capture and forward) |
| `--parallel` | Force sniff capture for coexistence |
| `--capture-mode MODE` | Force capture mode: `auto`, `sniff`, or `socket` |
| `--log-traps FILE` | Log all observed traps to file |

## Configuration Files

### Capture Configuration

Location: `/opt/trapninja/config/capture_config.json`

```json
{
  "mode": "sniff",
  "allow_parallel": true,
  "buffer_size_mb": 64,
  "batch_size": 100,
  "worker_count": 0
}
```

**Options:**
- `mode`: `"auto"`, `"sniff"`, or `"socket"`
  - `auto`: Try eBPF first, fall back to sniff (default)
  - `sniff`: Always use libpcap sniffing (parallel-safe)
  - `socket`: Use UDP socket binding (exclusive access)
- `allow_parallel`: Force sniff mode for parallel operation
- `buffer_size_mb`: Capture buffer size (default: 64MB)
- `worker_count`: Number of processing workers (0 = auto-detect)

### Shadow Configuration

Location: `/opt/trapninja/config/shadow_config.json`

```json
{
  "enabled": true,
  "observe_only": true,
  "log_all_traps": false,
  "log_file": "/var/log/trapninja/shadow_traps.log",
  "collect_detailed_stats": true,
  "stats_export_interval": 60
}
```

## Common Use Cases

### 1. Testing Before Production Deployment

Run TrapNinja in shadow mode to verify it receives all expected traps and makes correct routing decisions:

```bash
# Terminal 1: Existing trap receiver (e.g., snmptrapd) is running

# Terminal 2: Run TrapNinja in shadow mode
sudo python3 trapninja.py --foreground --shadow-mode --debug

# Watch the output to verify:
# - All expected sources are sending traps
# - OIDs are correctly identified  
# - Routing rules match expectations
# - No packets are being dropped
```

### 2. Comparing Statistics

Use shadow mode to collect parallel statistics:

```bash
# Run for a period to collect stats
sudo python3 trapninja.py --foreground --shadow-mode --log-traps /tmp/trapninja_test.log

# After testing, compare:
# - Total trap counts
# - Per-source counts
# - Per-OID counts
```

### 3. Validating Routing Rules

Test your routing configuration without affecting production:

```bash
# Configure routing rules in config files
# Then run in shadow mode to verify
sudo python3 trapninja.py --foreground --shadow-mode --debug 2>&1 | grep -E "(FORWARD|BLOCK|REDIRECT)"
```

### 4. Performance Testing

Compare TrapNinja's performance with your current solution:

```bash
# Run in mirror mode
sudo python3 trapninja.py --foreground --mirror-mode --debug

# Both systems forward traps - compare:
# - Processing latency
# - CPU usage
# - Memory usage
# - Packet loss (if any)
```

## CLI Commands

### Check Shadow Status

```bash
python3 trapninja.py --shadow-status
```

### Export Shadow Statistics

```bash
python3 trapninja.py --shadow-export
```

## Requirements

Shadow and parallel modes require:
- Root/sudo privileges (for raw packet capture)
- libpcap installed on the system
- Python Scapy library
- Network interface access

## Notes

1. **Root Privileges Required**: Raw packet capture requires root privileges or appropriate capabilities.

2. **Interface Selection**: Make sure TrapNinja is configured to listen on the correct network interface.

3. **BPF Filters**: TrapNinja automatically creates BPF filters to capture only SNMP trap traffic.

4. **No Interference**: Shadow mode will NOT interfere with your existing trap receiver - they operate completely independently.

5. **Statistics**: All standard TrapNinja statistics (per-IP, per-OID, etc.) work in shadow mode.

6. **Duplicate Traps**: In mirror mode, destinations will receive duplicate traps. Plan accordingly.

## Troubleshooting

### "Permission denied" errors

Run with sudo or configure appropriate capabilities:
```bash
sudo python3 trapninja.py --foreground --shadow-mode
```

### No traps received

1. Verify interface name: `ip addr show`
2. Check BPF filter: Look for "BPF filter:" in debug output
3. Verify traffic exists: `tcpdump -i eth0 udp port 162`

### High CPU usage

Increase buffer size or reduce worker count:
```json
{
  "buffer_size_mb": 128,
  "worker_count": 4
}
```

## Example Session

```bash
$ sudo python3 trapninja.py --foreground --shadow-mode --debug
Running TrapNinja in foreground with HA support...
Shadow mode: ENABLED (observe only, no forwarding)
Using sniff capture to run alongside existing trap receivers
Debug mode enabled

[2024-01-15 10:30:00] [INFO] ============================================================
[2024-01-15 10:30:00] [INFO] SHADOW MODE ENABLED
[2024-01-15 10:30:00] [INFO]   - Using sniff capture (can run alongside other receivers)
[2024-01-15 10:30:00] [INFO]   - Forwarding DISABLED - observe only
[2024-01-15 10:30:00] [INFO]   - All traps will be counted but NOT forwarded
[2024-01-15 10:30:00] [INFO] ============================================================
[2024-01-15 10:30:00] [INFO] Starting TrapNinja service with HA support (PID: 12345)...
[2024-01-15 10:30:00] [INFO] Capture mode forced to SNIFF for parallel operation
[2024-01-15 10:30:00] [INFO] Starting packet capture with Scapy sniff (sniff mode)
[2024-01-15 10:30:00] [INFO] Listening on interface 'eth0', UDP ports [162]
[2024-01-15 10:30:00] [INFO] BPF filter: (udp dst port 162 and not udp src port 10162)

# Traps are now being captured and counted...
# Use Ctrl+C to stop

^C
[2024-01-15 10:35:00] [INFO] Final metrics summary:
[2024-01-15 10:35:00] [INFO] Total traps received: 1,234
[2024-01-15 10:35:00] [INFO] Total traps forwarded: 0  # Shadow mode - none forwarded
[2024-01-15 10:35:00] [INFO] Total traps blocked: 56
```
