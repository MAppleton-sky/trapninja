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

**Last Updated**: 2025-06-15
