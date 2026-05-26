# TrapNinja Capture File Replay

## Overview

The capture file replay feature allows you to replay packets from pcap/pcapng capture files through the TrapNinja processing pipeline. Packets are injected as if they arrived from the network, passing through parsing, filtering, routing, and forwarding.

**Intended audience:** Developers, QA engineers, NOC test environments

**IMPORTANT:** This is a development and testing tool. It is NOT intended for use on live production systems.

---

## ⚠ Production Safety Warning

**Replay injects packets into the same pipeline as live traps.**

When you replay a capture file:
- Injected packets ARE processed by filtering, routing, and forwarding
- On a system with live destinations configured, injected packets WILL be forwarded to real NMS/OSS systems
- SNMPv3 packets will go through the same decryption path as live traps

### Production Safety Gate

TrapNinja includes a safety gate that blocks replay on systems where a live daemon is running:

1. The safety gate checks for the presence of `/var/run/trapninja.pid`
2. If the PID file exists and contains a live process, replay is blocked
3. A warning banner is displayed with instructions to override

### Overriding the Safety Gate

If you understand the risks and need to replay on a system with a running daemon, use ONE of:

**CLI flag:**
```bash
trapninja replay run /path/to/traps.pcap --i-know-this-is-not-production
```

**Environment variable:**
```bash
TRAPNINJA_REPLAY_ALLOW=1 trapninja replay run /path/to/traps.pcap
```

---

## Capturing a Suitable Replay File

Use `tcpdump` to capture SNMP trap traffic:

```bash
# Capture all SNMP traps on port 162
sudo tcpdump -i eth0 -w /tmp/traps.pcap udp port 162

# Capture from a specific source
sudo tcpdump -i eth0 -w /tmp/traps.pcap udp port 162 and src host 10.0.0.1

# Capture on multiple ports
sudo tcpdump -i eth0 -w /tmp/traps.pcap udp port 162 or udp port 1162
```

**Notes:**
- Requires root or `CAP_NET_RAW` capability
- Both pcap and pcapng formats are supported
- Large captures may be several gigabytes — replay handles them efficiently via streaming

---

## Usage

### Basic replay (as-fast-as-possible)

Replay all packets from a capture file at maximum speed:

```bash
trapninja replay run /path/to/traps.pcap
```

### Replay honouring original timing

Replay packets with inter-packet delays matching the original capture:

```bash
trapninja replay run /path/to/traps.pcap --replay-realtime
```

**Note:** Delays are capped at 5 seconds to avoid stalls on large gaps in the capture.

### Replay multiple passes (load testing)

Replay the file 3 times in succession:

```bash
trapninja replay run /path/to/traps.pcap --replay-count 3
```

### Loop indefinitely (load testing)

Replay continuously until Ctrl-C:

```bash
trapninja replay run /path/to/traps.pcap --replay-count 0
```

### Dry run (parse and count, do not inject)

Parse the capture and show statistics without injecting packets:

```bash
trapninja replay run /path/to/traps.pcap --replay-dry-run
```

### Filter to a single source IP

Only replay packets from a specific source:

```bash
trapninja replay run /path/to/traps.pcap --replay-filter-src 10.0.0.1
```

### Write summary to JSON

Save replay statistics to a JSON file:

```bash
trapninja replay run /path/to/traps.pcap --replay-summary-json /tmp/summary.json
```

### Override production safety gate

```bash
trapninja replay run /path/to/traps.pcap --i-know-this-is-not-production
```

---

## CLI Reference

| Option | Description | Default |
|--------|-------------|---------|
| `<capture-file>` | Path to pcap/pcapng capture file (required) | — |
| `--replay-realtime` | Honour inter-packet timestamps | Off |
| `--replay-count N` | Number of replay passes (0 = loop forever) | 1 |
| `--replay-filter-src IP` | Only replay packets from this source IP | None (all) |
| `--replay-dry-run` | Parse and count but do NOT inject | Off |
| `--replay-summary-json PATH` | Write summary to JSON file | None |
| `--i-know-this-is-not-production` | Bypass production safety gate | Off |

---

## Replay Metrics

During replay, metrics are written to an ephemeral Prometheus file:

**Location:** `/var/log/trapninja/metrics/trapninja_replay.prom`

**Lifecycle:**
- Created when replay starts
- Updated every 10 seconds during replay
- **Deleted** when replay ends or the process exits

**Metrics:**
- `trapninja_replay_packets_read` — Total packets read from capture file
- `trapninja_replay_packets_injected` — Packets injected into pipeline
- `trapninja_replay_packets_skipped` — Packets skipped (non-SNMP port, filtered)
- `trapninja_replay_packets_failed` — Packets failed (queue full, etc.)

**Important:** These metrics are completely isolated from production counters. They will NOT appear in normal Prometheus scrapes after replay completes.

---

## SNMP Version Support

The replay engine supports all SNMP versions:
- **v1** — Replayed transparently
- **v2c** — Replayed transparently
- **v3** — Replayed and processed through the existing SNMPv3 decryption path

Version detection is heuristic (BER/ASN.1 byte parsing) and used for the version counters in the summary. The actual SNMP processing uses the full pysnmp parser.

---

## Troubleshooting

### "Queue full" warnings during replay

The packet queue is full and some packets are being dropped.

**Solutions:**
- Use `--replay-realtime` to slow down injection
- Check that the TrapNinja daemon is processing packets efficiently
- Consider running replay against a non-production instance

### "Safety gate blocked" with no daemon running

A stale PID file may exist from a previous daemon run.

**Solution:** Remove the stale PID file:
```bash
sudo rm /var/run/trapninja.pid
```

### Packets counted as "skipped"

Packets are skipped if they:
- Don't have IP + UDP layers (e.g., ARP, ICMP)
- Have a destination port not in `LISTEN_PORTS` (default: 162)
- Don't match the `--replay-filter-src` IP (if specified)

**Solution:** Verify the capture file contains UDP port 162 traffic:
```bash
tcpdump -r /path/to/traps.pcap -n 'udp port 162' | head
```

### "Scapy not available" error

The scapy library is required for reading pcap files.

**Solution:** Install scapy:
```bash
pip install scapy
```

---

## Architecture Notes

### Injection Point

Replay uses the same injection point as live capture methods:

```python
from .network import packet_queue

packet_queue.put_nowait({
    'src_ip': src_ip,        # str, e.g. '10.0.0.1'
    'dst_port': dst_port,    # int, e.g. 162
    'payload': payload,      # bytes, UDP payload only
})
```

This ensures replayed packets go through the exact same processing pipeline as live traffic.

### Metric Isolation

Replay metrics are held in the `ReplayMetrics` dataclass and are NEVER merged with:
- `network._queue_stats`
- The shared stats module
- Production Prometheus `.prom` files

This ensures replay activity cannot contaminate production monitoring.

### Memory Efficiency

The replay engine uses Scapy's `PcapReader` for streaming iteration, so even multi-gigabyte capture files are processed with constant memory usage.
