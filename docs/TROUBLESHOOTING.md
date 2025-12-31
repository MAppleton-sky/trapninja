# TrapNinja Troubleshooting Guide

## Overview

This guide covers common issues encountered with TrapNinja and their solutions. Issues are organized by symptom for easy navigation.

## Quick Diagnostics

```bash
# Check service status
python trapninja.py --status

# Run in foreground with debug logging
python trapninja.py --foreground --debug

# Check log file
tail -f /var/log/trapninja.log

# Monitor metrics
curl http://localhost:8080/metrics | grep trapninja
```

---

## Daemon Startup Issues

### Symptom: Daemon Crashes Immediately After Restart (Fixed in v0.7.12)

**Example Output**:
```
python3.9 -O trapninja.py --restart
...
Starting TrapNinja daemon...
Daemon process spawned with PID 3543057
Verifying daemon startup...
  Warning: Control socket not responding, but process 3543057 is running
✓ TrapNinja daemon started successfully with PID 3543057

# Then immediately:
python3.9 -O trapninja.py --status
TrapNinja is not running (stale PID file)
```

**Root Cause**: The `--restart` argument was being passed to the daemon subprocess
along with `--foreground`. Since these are in a mutually exclusive argument group,
the subprocess crashed during argument parsing, but error output was hidden (sent
to /dev/null).

**Solution**: Fixed in v0.7.12:
- Changed to use hidden `--foreground-daemon` argument for daemon spawning
- Added comprehensive filtering of ALL daemon control arguments
- Better startup verification with crash diagnostics

**Workaround for older versions**:
```bash
# Instead of --restart, do stop then start separately:
python trapninja.py --stop
sleep 2
python trapninja.py --start
```

### Symptom: Daemon Starts But Control Socket Doesn't Respond

**Causes**:

1. **Complex initialization still in progress**:
   - HA cluster initialization
   - Redis cache connection
   - SNMPv3 credential loading
   
   The default timeout was increased to 15 seconds in v0.7.12.

2. **Permission issues on socket file**:
   ```bash
   ls -la /tmp/trapninja_control.sock
   # Should show owner as the user running the daemon
   ```

3. **Old socket file lingering**:
   ```bash
   # Remove stale socket
   rm -f /tmp/trapninja_control.sock
   python trapninja.py --start
   ```

**Diagnostics**:
```bash
# Check log file for startup errors
tail -50 /var/log/trapninja.log

# Run in foreground to see all output
python trapninja.py --foreground --debug
```

### Symptom: "stale PID file" on Status Check

**The daemon stopped unexpectedly and left behind a PID file.**

**Solutions**:

1. TrapNinja automatically removes stale PID files
2. Check logs for crash reason:
   ```bash
   tail -100 /var/log/trapninja.log | grep -i "error\|exception\|crash"
   ```

3. Common causes:
   - Out of memory
   - Unhandled exception during packet processing
   - Signal from external source (OOM killer, user, etc.)

---

## Packet Duplication Issues

### Symptom: More Packets Forwarded Than Received

**Example**: Trap tracker shows 10x more forwarded than received:
```
Incoming:  339
Forwarded: 3353
Ratio:     ~10x (should be ~2x with 2 destinations)
```

### Cause 1: Packet Re-Capture Loop (Fixed in v0.5.1)

**Root Cause**: Forwarded packets being re-captured by the sniff filter.

The original BPF filter `udp port 162` matched both:
- Incoming traps (dport=162) ✓
- Our forwarded traps (dport=162) ✗ Also matched!

**Solution**: TrapNinja 0.5.1+ uses a distinct source port (10162) and excludes it in the BPF filter:

```
BPF Filter: "udp dst port 162 and not udp src port 10162"
```

**Verification**:
```bash
# Check the constant is set correctly
grep -r "FORWARD_SOURCE_PORT" trapninja/core/constants.py
# Should show: FORWARD_SOURCE_PORT = 10162
```

### Cause 2: Socket + Sniff Running Simultaneously (Fixed in v0.5.2)

**Root Cause**: Both UDP socket listeners AND Scapy sniff() running at the same time.

This happened when `load_config()` auto-started UDP listeners before capture mode was determined.

**Solution**: TrapNinja 0.5.2+ only starts ONE capture method:
- Socket mode: Only UDP socket listeners
- Sniff mode: Only Scapy sniff (sockets explicitly cleaned up)
- eBPF mode: Only eBPF capture

**Verification**:
```bash
# In foreground mode, check logs for:
# "NOTE: UDP socket listeners are DISABLED in sniff mode"
python trapninja.py --foreground --debug 2>&1 | grep -i "listener\|sniff\|capture"
```

### Verification After Fix

Use the trap tracker to verify correct ratio:

```bash
./snmp_trap_tracker.sh -l <server_ip> -f <destination_ip>

# Send test traps
snmptrap -v 2c -c public <server_ip>:162 "" .1.3.6.1.6.3.1.1.5.1

# Expected with 2 destinations:
# Incoming: 100
# Forwarded: 200 (exactly 2x)
```

---

## HA Issues

### Symptom: Secondary Node Forwarding Traps

**Expected**: Only PRIMARY should forward traps. SECONDARY should drop them.

**Verification**:
```bash
# On SECONDARY, check ha_blocked counter
python trapninja.py --status | grep ha_blocked
# Should increment when traps arrive
```

**Causes and Solutions**:

1. **HA check not at processing time** (Fixed in v0.5.0)
   - Solution: Update to v0.5.0+

2. **Guard condition in _disable_forwarding()** (Fixed in v0.5.0)
   - Old code had `if self.is_forwarding:` guard that prevented the callback
   - Solution: Update to v0.5.0+

3. **Import issues with HA module**
   - Check logs for: `"WARNING: Failed to import HA module"`
   - If present, HA protection is disabled

**Expected Logs on SECONDARY**:
```
INFO  - HA: Trap forwarding DISABLED - this instance is standby
DEBUG - Packet received but forwarding disabled by HA (secondary mode)
```

### Symptom: Frequent Failovers

**Cause**: Network issues or misconfiguration.

**Checks**:
```bash
# Test UDP connectivity to peer
nc -vzu <peer_ip> 5000

# Check firewall
firewall-cmd --list-ports | grep 5000

# Check heartbeat timeout isn't too aggressive
cat config/ha_config.json | grep timeout
# Recommended: heartbeat_timeout >= 3.0
```

**Solution**: Increase `heartbeat_timeout` if network has occasional latency spikes.

### Symptom: Split-Brain Condition

**Both nodes show PRIMARY or both in SPLIT_BRAIN state.**

**Resolution**:
1. Check network connectivity between nodes
2. Manually demote one node:
   ```bash
   python trapninja.py --demote
   ```
3. Wait for state to stabilize
4. Verify with `--ha-status` on both nodes

### Symptom: HA State Not Persisting

**Node reverts to wrong state after restart.**

**Checks**:
```bash
# Verify config file is writable
ls -la config/ha_config.json

# Check config after restart
cat config/ha_config.json | python -m json.tool

# Look for write errors in logs
grep -i "error.*config\|permission" /var/log/trapninja.log
```

---

## Performance Issues

### Symptom: High CPU Usage

**Expected**: <30% with eBPF, <60% with socket capture.

**Diagnostics**:
```bash
# Check which capture mode is active
python trapninja.py --status | grep -i capture

# Monitor CPU per process
top -p $(pgrep -f trapninja)
```

**Solutions**:

1. **Enable eBPF acceleration** (reduces CPU by ~70%):
   ```bash
   # Install dependencies
   yum install bcc bcc-tools python3-bcc  # RHEL
   apt install bpfcc-tools python3-bpfcc  # Ubuntu
   
   # Run as root for eBPF
   sudo python trapninja.py --start
   ```

2. **Reduce worker count** if CPU-bound:
   - Edit worker count in config (default: 2× CPU cores)

3. **Optimize filtering**:
   - Block high-volume noise sources at IP level
   - Use specific OID patterns instead of broad wildcards

### Symptom: Queue Overflow

**Traps being dropped during alarm floods.**

**Diagnostics**:
```bash
# Check queue metrics
curl -s http://localhost:8080/metrics | grep queue
```

**Solutions**:

1. **Increase queue capacity** (default: 200,000):
   - Edit `QUEUE_CAPACITY` in core/constants.py

2. **Add more workers**:
   - Workers process queue faster

3. **Use eBPF**:
   - Kernel-space filtering reduces queue pressure

### Symptom: High Latency

**Traps taking too long to forward.**

**Diagnostics**:
```bash
# Check processing histogram
curl -s http://localhost:8080/metrics | grep processing_seconds
```

**Solutions**:

1. **Disable slow path parsing**:
   - Slow path is fallback for malformed traps
   - Most traps should use fast path

2. **Check destination health**:
   - Slow destinations back up the workers
   - Use multiple workers to parallelize

---

## Network Issues

### Symptom: No Traps Being Received

**Diagnostics**:
```bash
# Check port binding
netstat -ulnp | grep 162

# Capture traffic manually
tcpdump -i any udp port 162 -c 10

# Check firewall
firewall-cmd --list-all
```

**Common Causes**:

1. **Port already in use**:
   ```bash
   # Find process using port
   lsof -i :162
   ```

2. **Firewall blocking**:
   ```bash
   # Allow trap port
   firewall-cmd --permanent --add-port=162/udp
   firewall-cmd --reload
   ```

3. **SELinux blocking**:
   ```bash
   # Check for denials
   ausearch -m avc -ts recent
   
   # Allow if needed
   setsebool -P nis_enabled 1
   ```

### Symptom: No Traps Being Forwarded

**Receiving traps but not forwarding.**

**Diagnostics**:
```bash
# Check if forwarding is enabled
python trapninja.py --ha-status | grep Forwarding

# Check destinations configuration
cat config/destinations.json

# Check blocked lists
python trapninja.py --list-blocked-ips
python trapninja.py --list-blocked-oids
```

**Common Causes**:

1. **HA in SECONDARY mode**:
   - Check with `--ha-status`
   - Promote if needed: `--promote`

2. **All destinations filtered**:
   - Check `blocked_ips.json` and `blocked_traps.json`

3. **Empty destinations list**:
   - Verify `destinations.json` has entries

### Symptom: Destination Unreachable

**Forwarding attempted but failing.**

**Diagnostics**:
```bash
# Test destination connectivity
nc -vzu <dest_ip> 162

# Check for errors in logs
grep -i "error.*forward\|destination" /var/log/trapninja.log

# Check metrics for failures
curl -s http://localhost:8080/metrics | grep forward_errors
```

---

## SNMPv3 Issues

### Symptom: SNMPv3 Decryption Failing

**Diagnostics**:
```bash
# Check SNMPv3 status
python trapninja.py --snmpv3-status

# List configured users
python trapninja.py --snmpv3-list-users

# Check for decryption errors
grep -i "snmpv3\|decrypt" /var/log/trapninja.log
```

**Common Causes**:

1. **Missing credentials**:
   ```bash
   # Add user
   python trapninja.py --snmpv3-add-user \
       --username <user> \
       --engine-id <id> \
       --auth-protocol SHA \
       --priv-protocol AES128
   ```

2. **Wrong engine ID**:
   - Engine ID must match the source device
   - Use hex format: `80001f888056565656565656`

3. **Protocol mismatch**:
   - Auth and privacy protocols must match device config

---

## Configuration Issues

### Symptom: Configuration Not Loading

**Diagnostics**:
```bash
# Validate JSON syntax
python -m json.tool < config/destinations.json

# Check file permissions
ls -la config/

# Look for parse errors
grep -i "error.*config\|json" /var/log/trapninja.log
```

### Symptom: Changes Not Taking Effect

**Configuration changes not reflected.**

**Solutions**:

1. **Restart service**:
   ```bash
   python trapninja.py --restart
   ```

2. **Clear cache** (for runtime changes):
   ```python
   from trapninja.cli.filtering_commands import config_manager
   config_manager.invalidate_cache()
   ```

3. **Check for backup files**:
   - Old `.bak` or `.old` files might be confusing

---

## Diagnostic Commands

### Service Status

```bash
# Full status
python trapninja.py --status

# HA status
python trapninja.py --ha-status

# SNMPv3 status
python trapninja.py --snmpv3-status
```

### Log Analysis

```bash
# Recent errors
grep -i error /var/log/trapninja.log | tail -20

# HA state changes
grep "HA:" /var/log/trapninja.log | tail -20

# Packet processing
grep -i "forward\|process\|drop" /var/log/trapninja.log | tail -20
```

### Metrics

```bash
# All metrics
curl -s http://localhost:8080/metrics

# Specific metrics
curl -s http://localhost:8080/metrics | grep -E "received|forwarded|dropped|ha_blocked"
```

### Network Diagnostics

```bash
# Check listening ports
netstat -ulnp | grep trapninja

# Capture incoming traps
tcpdump -i any udp port 162 -c 10 -nn

# Check forwarded packets
tcpdump -i any "udp src port 10162" -c 10 -nn
```

---

## Getting Help

If issues persist:

1. **Collect diagnostics**:
   ```bash
   python trapninja.py --status > diag.txt
   tail -100 /var/log/trapninja.log >> diag.txt
   ```

2. **Enable debug logging**:
   ```bash
   python trapninja.py --foreground --debug 2>&1 | tee debug.log
   ```

3. **Check version**:
   ```bash
   python trapninja.py --version
   cat VERSION
   ```

---

## Packet Drops

### Symptom: Non-Zero "Dropped" Count in Stats Summary

**Understanding Drops**:

The "Dropped" counter in TrapNinja indicates **queue overflow events** - packets that arrived when the processing queue was full. This typically occurs during burst traffic scenarios (e.g., fiber cuts, device reboots causing alarm floods).

**Example**:
```
Dropped:                    629
```

With 629 drops out of 2.8M traps, the drop rate is ~0.02% which is excellent for telco-scale traffic.

### Diagnosing Drops

**1. Check Queue Statistics**:
```bash
# View queue metrics in real-time
watch -n 5 'cat /var/log/trapninja/metrics/trapninja_granular.prom | grep -E "queue|dropped"'

# Or check the JSON stats
cat /var/log/trapninja/metrics/trapninja_granular.json | python -m json.tool | grep -A5 queue
```

**2. Check Processing Logs for Queue Full Warnings**:
```bash
# Look for queue full events (logged with rate limiting)
grep -i "queue full" /var/log/trapninja.log

# Example output:
# WARNING - Queue full: 15 packets dropped
```

**3. Identify Burst Traffic Periods**:
```bash
# Check peak rates - high peaks indicate burst traffic
python trapninja.py --stats-top-ips --sort peak -n 20
python trapninja.py --stats-top-oids --sort peak -n 20

# Look for IPs with very high peak vs current rate
# Peak/min >> Current/min indicates burst traffic occurred
```

**4. Correlate Drops with Traffic Patterns**:
```bash
# Check when drops occurred by looking at log timestamps
grep "Queue full" /var/log/trapninja.log | head -20

# Cross-reference with network events (fiber cuts, maintenance, etc.)
```

### Understanding Queue Metrics

| Metric | Description |
|--------|-------------|
| `current_depth` | Current packets waiting in queue |
| `max_depth` | Highest queue depth observed |
| `total_queued` | Total packets successfully queued |
| `total_dropped` | Packets dropped due to full queue |
| `full_events` | Number of times queue was full |
| `queue_capacity` | Maximum queue size (default: 200,000) |
| `utilization` | current_depth / queue_capacity |

### Solutions for Reducing Drops

**1. Enable eBPF Acceleration** (Recommended):
```bash
# eBPF filtering happens in kernel, reducing queue pressure
sudo yum install bcc bcc-tools python3-bcc  # RHEL
sudo python trapninja.py --start
```

**2. Block High-Volume Noise Sources**:
```bash
# Identify sources generating excessive traps
python trapninja.py --stats-top-ips --sort peak -n 10

# Block noisy sources if appropriate
python trapninja.py --add-blocked-ip 10.x.x.x
```

**3. Block Noisy OIDs**:
```bash
# Identify OIDs causing floods
python trapninja.py --stats-top-oids --sort peak -n 10

# Block non-critical OIDs
python trapninja.py --add-blocked-oid 1.3.6.1.4.1.xxxx
```

**4. Increase Processing Capacity**:

Edit `packet_processor.py` to increase workers:
```python
# In start_workers(), change:
num_workers = min(cpu_count * 2, 32)  # Default
num_workers = min(cpu_count * 4, 64)  # More aggressive
```

**5. Increase Queue Capacity** (Last Resort):

Edit `network.py`:
```python
QUEUE_MAX_SIZE = 200000  # Default
QUEUE_MAX_SIZE = 500000  # Increase for extreme scenarios
```

**Note**: Increasing queue size uses more memory (~500 bytes per slot).

### Acceptable Drop Rates

| Drop Rate | Assessment |
|-----------|------------|
| < 0.01% | Excellent - no action needed |
| 0.01-0.1% | Good - acceptable for most environments |
| 0.1-1% | Monitor - may indicate capacity issues |
| > 1% | Investigate - likely needs optimization |

### Drop Rate Calculation

```
Drop Rate = (Dropped / Total Traps) × 100

Example: 629 / 2,845,859 × 100 = 0.022%
```

---

## Metrics Issues

### Symptom: All Metrics Show Zero

**Root Cause (Fixed in v0.6.0)**: Prior to v0.6.0, the metrics module was not integrated with the packet processor. The `metrics.py` module had its own counters that were never incremented because packet processing happened in `packet_processor.py` with separate statistics.

**Solution**: Update to TrapNinja v0.6.0+ which has unified metrics collection.

**Verification**:
```bash
# Check metrics file
cat /var/log/trapninja/metrics/trapninja_metrics.prom | head -30

# Run metrics test
cd /path/to/trapninja
python3 tests/metrics-test.py --all
```

### Symptom: Metrics Not Updating

**Causes and Solutions**:

1. **No traffic**: Verify traps are arriving:
   ```bash
   tcpdump -i eth0 udp port 162 -c 5
   ```

2. **Export timer issue**: Metrics export every 60s by default
   ```bash
   # Force immediate export
   python -c "from trapninja.metrics import export_metrics; export_metrics()"
   ```

3. **Directory permissions**:
   ```bash
   ls -la /var/log/trapninja/metrics/
   # Should be writable by trapninja user
   ```

### Symptom: Fast Path Ratio Is 0%

**Expected**: Most SNMPv2c traps should use fast path (85%+ typical).

**Causes**:

1. **All SNMPv3 traffic**: SNMPv3 uses slow path for decryption
2. **Malformed traps**: Traps that fail fast path validation

**Diagnostics**:
```bash
# Check trap type breakdown in logs
grep -E "fast_path|slow_path" /var/log/trapninja.log | tail -20

# Check metrics
cat /var/log/trapninja/metrics/trapninja_metrics.prom | grep fast_path
```

### Viewing Metrics

**Prometheus format**:
```bash
cat /var/log/trapninja/metrics/trapninja_metrics.prom
```

**JSON format**:
```bash
cat /var/log/trapninja/metrics/trapninja_metrics.json | python -m json.tool
```

**Real-time monitoring**:
```bash
watch -n 5 'cat /var/log/trapninja/metrics/trapninja_metrics.prom | grep -E "received|forwarded|blocked|rate"'
```

See `documentation/METRICS.md` for full metrics reference.

---

**Last Updated**: 2025-12-31
