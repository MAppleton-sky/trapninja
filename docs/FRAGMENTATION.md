# TrapNinja IP Fragment Reassembly

## Overview

TrapNinja supports IP fragment reassembly for SNMP traps that exceed the network MTU (Maximum Transmission Unit). This is essential for handling large traps in sniff mode, where the kernel doesn't automatically reassemble fragmented packets.

## When Fragmentation Occurs

IP fragmentation happens when an SNMP trap exceeds the network MTU (typically 1500 bytes for Ethernet):

- **MTU** = 1500 bytes (standard Ethernet)
- **IP Header** = 20 bytes (minimum)
- **UDP Header** = 8 bytes
- **Max UDP Payload** = 1472 bytes without fragmentation

If an SNMP trap's PDU exceeds ~1472 bytes, it will be fragmented into multiple IP packets.

### Common Causes of Large Traps

- Traps with many varbinds (alarm details, configuration data)
- Traps containing large OCTET STRING values
- Bulk notifications from network equipment
- Vendor-specific extended information

## The Problem

When a packet is fragmented, the fragments look like this:

```
Fragment 1: [IP Header (offset=0, MF=1)] [UDP Header] [Data part 1]
Fragment 2: [IP Header (offset>0)]       [NO UDP HDR] [Data part 2]
Fragment 3: [IP Header (offset>0, MF=0)] [NO UDP HDR] [Data part 3]
```

**Key issue**: Only the first fragment contains the UDP header with port information.

### Capture Mode Comparison

| Mode | Fragments Handled | How |
|------|------------------|-----|
| **Socket** | ✅ Automatic | Kernel reassembles before delivery |
| **Sniff** (standard) | ❌ Broken | BPF filter drops non-first fragments |
| **Sniff** (with reassembly) | ✅ Works | TrapNinja reassembles fragments |
| **eBPF** | ❌ Broken | Sees fragments separately |

## Configuration

### Enabling Fragment Reassembly

Create or edit `config/capture_config.json`:

```json
{
  "mode": "sniff",
  "fragment_reassembly": {
    "enabled": true,
    "timeout_seconds": 5.0,
    "max_buffer_mb": 100.0,
    "max_datagrams": 10000
  }
}
```

### Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `enabled` | `false` | Enable fragment reassembly |
| `timeout_seconds` | `5.0` | Time to wait for all fragments |
| `max_buffer_mb` | `100.0` | Maximum memory for fragment buffer |
| `max_datagrams` | `10000` | Maximum concurrent incomplete datagrams |

### Recommended Settings by Environment

**Low-Latency LAN (< 10ms RTT)**
```json
{
  "fragment_reassembly": {
    "enabled": true,
    "timeout_seconds": 2.0,
    "max_buffer_mb": 50.0,
    "max_datagrams": 5000
  }
}
```

**Standard Network (10-100ms RTT)**
```json
{
  "fragment_reassembly": {
    "enabled": true,
    "timeout_seconds": 5.0,
    "max_buffer_mb": 100.0,
    "max_datagrams": 10000
  }
}
```

**High-Latency WAN (> 100ms RTT)**
```json
{
  "fragment_reassembly": {
    "enabled": true,
    "timeout_seconds": 10.0,
    "max_buffer_mb": 200.0,
    "max_datagrams": 20000
  }
}
```

## How It Works

### Fragment-Aware BPF Filter

When enabled, TrapNinja uses an enhanced BPF filter:

```
((udp dst port 162) and not (udp src port 10162)) or ((ip[6:2] & 0x1fff) != 0 and ip proto 17)
```

This captures:
1. Complete UDP packets destined to port 162 (standard traps)
2. First fragments with UDP header visible
3. Non-first UDP fragments (offset > 0) regardless of port

### Reassembly Process

1. **Parse IP Header**: Extract fragment metadata (src/dst IP, protocol, ID, offset, MF flag)
2. **Create Key**: `(src_ip, dst_ip, protocol, ip_id)` uniquely identifies a datagram
3. **Buffer Fragment**: Store fragment data indexed by byte offset
4. **Check Completeness**: When MF=0 fragment arrives, check for gaps
5. **Reassemble**: Concatenate fragments in offset order
6. **Deliver**: Pass complete datagram to processing pipeline

### Memory Management

The reassembly buffer enforces limits to prevent resource exhaustion:

- **Count limit**: Maximum concurrent incomplete datagrams
- **Size limit**: Maximum total buffer memory
- **Timeout**: Automatic cleanup of stale fragments
- **LRU eviction**: Oldest entries removed when limits exceeded

## Monitoring

### Service Status

Fragment statistics are included in service status:

```bash
trapninja --status
```

Output includes:
```
fragment_reassembly:
  fragments_received: 1234
  datagrams_completed: 456
  datagrams_timeout: 12
  datagrams_evicted: 0
  bytes_reassembled: 789012
  current_datagrams: 3
  current_bytes: 4567
```

### Log Messages

```
# Startup
Fragment reassembly ENABLED
  Timeout: 5.0s, Buffer: 100.0MB, Max datagrams: 10000
Using fragment-aware BPF filter
BPF filter: ((udp dst port 162) and not (udp src port 10162)) or ((ip[6:2] & 0x1fff) != 0 and ip proto 17)

# Debug level (when traps are reassembled)
Reassembled fragmented trap from 10.1.2.3, payload size: 2048 bytes

# Shutdown
Fragment stats: completed=456, timeout=12, evicted=0
```

## Troubleshooting

### Detecting Fragmented Traffic

```bash
# Check for fragmented UDP packets
tcpdump -i eth0 -nn 'ip[6:2] & 0x3fff != 0 and ip proto 17' -c 10

# Count fragmented packets to port 162
tcpdump -i eth0 -nn 'udp dst port 162' -v 2>&1 | grep -c 'frag'

# Watch for large UDP packets (potential fragmentation)
tcpdump -i eth0 -nn 'udp dst port 162' -v | grep -E 'length [0-9]{4,}'
```

### Common Issues

**Fragments Not Being Captured**

Check the BPF filter in logs:
```bash
grep "BPF filter" /var/log/trapninja/trapninja.log
```

Should show the fragment-aware filter if enabled.

**High Timeout Rate**

If `datagrams_timeout` is high:
- Increase `timeout_seconds` 
- Check network path for packet loss
- Verify all fragments are reaching the server

**Memory Pressure**

If `datagrams_evicted` is high:
- Increase `max_buffer_mb`
- Decrease `timeout_seconds`
- Check for fragment storm (DoS attack)

**Incomplete Traps**

If traps arrive incomplete:
1. Verify fragment reassembly is enabled
2. Check BPF filter includes fragment capture
3. Look for packet loss on the network path

### Verification Script

```bash
#!/bin/bash
# verify_fragments.sh - Verify fragment handling

echo "=== TrapNinja Fragment Verification ==="

# Check if fragment reassembly is configured
CONFIG="/opt/trapninja/config/capture_config.json"
if [ -f "$CONFIG" ]; then
    if grep -q '"enabled": true' "$CONFIG" 2>/dev/null; then
        echo "✓ Fragment reassembly enabled in config"
    else
        echo "✗ Fragment reassembly NOT enabled"
    fi
else
    echo "✗ No capture_config.json found"
fi

# Check running filter
echo ""
echo "Current BPF filter in use:"
grep "BPF filter:" /var/log/trapninja/trapninja.log | tail -1

# Check for recent fragment activity
echo ""
echo "Recent fragment statistics:"
trapninja --status 2>/dev/null | grep -A10 "fragment_reassembly" || echo "No fragment stats available"

# Check for fragmented packets on wire
echo ""
echo "Checking for fragmented UDP traffic (5 seconds)..."
timeout 5 tcpdump -i eth0 -nn 'ip[6:2] & 0x3fff != 0 and ip proto 17' -c 5 2>/dev/null || echo "No fragments captured"
```

## Best Practices

### Production Recommendations

1. **Use Socket Mode When Possible**
   - Socket mode handles fragments automatically via kernel
   - Only use sniff mode when coexistence with other receivers is required

2. **Monitor Fragment Statistics**
   - Set up alerts for high timeout/eviction rates
   - Track `datagrams_completed` as a health indicator

3. **Size Buffer Appropriately**
   ```
   buffer_size = expected_concurrent_fragmented_traps × avg_trap_size × 2
   ```

4. **Set Timeout Based on Network**
   - LAN: 2-5 seconds
   - WAN: 5-10 seconds
   - High-latency: 10-15 seconds

### Shadow/Mirror Mode

When running in shadow or mirror mode alongside another trap receiver:

```json
{
  "mode": "sniff",
  "allow_parallel": true,
  "fragment_reassembly": {
    "enabled": true,
    "timeout_seconds": 5.0
  }
}
```

This ensures fragmented traps are properly captured even when TrapNinja isn't the exclusive receiver.

## Technical Details

### BPF Filter Breakdown

```
((udp dst port 162) and not (udp src port 10162))
    ^                           ^
    |                           |
    Incoming traps              Exclude our forwarded packets
    
or 

((ip[6:2] & 0x1fff) != 0 and ip proto 17)
    ^                ^          ^
    |                |          |
    Flags/offset     Offset>0   UDP protocol
    field            (not first 
                     fragment)
```

### Fragment Key Structure

Each datagram is uniquely identified by:
- Source IP address
- Destination IP address  
- IP Protocol (17 for UDP)
- IP Identification field (16-bit)

This combination ensures fragments from different sources or datagrams are tracked separately.

### Thread Safety

The reassembly buffer is fully thread-safe:
- RLock protects all operations
- Multiple capture threads can add fragments concurrently
- Background cleanup thread runs independently
- Statistics access is atomic

## See Also

- [Shadow Mode](SHADOW_MODE.md) - Parallel capture operation
- [Troubleshooting](TROUBLESHOOTING.md) - General troubleshooting guide
- [Configuration](CONFIG.md) - Configuration reference
