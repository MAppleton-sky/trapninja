# TrapNinja Metrics System

## Overview

TrapNinja provides comprehensive metrics collection and export in Prometheus
format for monitoring system integration. The metrics system collects data
from all processing components and exports it in both Prometheus (`.prom`)
and JSON formats.

**Key Features:**
- Configurable output directory for metrics files
- Global labels/tags applied to all Prometheus metrics
- Configurable export intervals
- Integration with Prometheus via Node Exporter textfile collector
- `_created` timestamps on all counters for accurate Grafana rate calculation

## Architecture

### Counter Source of Truth (v0.8.1+)

As of v0.8.1, trap total counters (received, forwarded, blocked, redirected,
dropped) are owned exclusively by `GranularStatsCollector`. This is the
**single source of truth** for all trap counts. Counters increment directly
on every trap with no buffering, ensuring values are always current at export
time.

`ProcessingStats` retains responsibility for: sliding-window gauges (60s),
fast/slow path hit counts, queue metrics, HA-blocked counts, and processing
errors.

### Unified Export Timer (v0.8.1+)

Both `.prom` files are written by a **single coordinated timer** owned by
`metrics/collector.py`. `GranularStatsCollector` no longer runs its own
export timer — instead its `export_now()` method is called synchronously
by the unified timer immediately after `export_metrics()`. This guarantees
both files always reflect the same point-in-time snapshot.

```
┌──────────────────────────────────────────────────────────────────────────┐
│                          Packet Processing                               │
│                                                                          │
│  Every trap calls _record_granular_stats()                               │
│       │                                                                  │
│       ▼                                                                  │
│  GranularStatsCollector (single source of truth for totals)              │
│  ├── _total_traps          (unbuffered, always current)                  │
│  ├── _total_forwarded                                                    │
│  ├── _total_blocked                                                      │
│  ├── _total_redirected                                                   │
│  └── _total_dropped                                                      │
│                                                                          │
│  ProcessingStats (windows, performance, queue)                           │
│  ├── _window_received      (60s sliding window)                          │
│  ├── _window_forwarded                                                   │
│  ├── _window_dropped                                                     │
│  ├── _window_errors                                                      │
│  ├── fast_path_hits / slow_path_hits                                     │
│  ├── ha_blocked                                                          │
│  └── queue_full_events / max_queue_depth                                 │
└──────────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
       metrics/collector.py  _schedule_metrics_export()  ← single unified timer
       │
       ├─ 1. export_metrics()        → trapninja_metrics.prom + .json
       │     reads totals from GranularStatsCollector,
       │     windows/performance/queue from ProcessingStats
       │
       └─ 2. collector.export_now()  → trapninja_granular.prom + .json
             reads per-IP/OID/destination from GranularStatsCollector

       Both files written in the same callback — always consistent.
```

This architecture eliminates two classes of divergence that existed in earlier
versions:
- **Flush-lag divergence**: total counters were buffered per-worker and could
  lag behind granular per-IP stats during load changes (fixed in v0.8.1 by
  making GranularStatsCollector the counter source of truth)
- **Timer-drift divergence**: two independent timers wrote files at different
  moments, producing different snapshots for the same Prometheus scrape
  (fixed in v0.8.1 by the unified export timer)

### Relationship to Granular Statistics

TrapNinja writes two `.prom` files. They are designed to complement each
other without overlap:

| File | Contents |
|---|---|
| `trapninja_metrics.prom` | Global trap totals, HA, cache, queue, performance, uptime |
| `trapninja_granular.prom` | Per-IP, per-OID, per-destination, IP×OID combinations, unique source/OID gauges |

The global trap totals (`trapninja_traps_received_total` etc.) appear **only**
in `trapninja_metrics.prom`. They were removed from `trapninja_granular.prom`
in v0.8.1 to prevent Prometheus from double-counting when node_exporter picks
up both files. Both files read from the same `GranularStatsCollector` counters,
so the values are always identical.

### Counter Reset Protection (`_created` timestamps)

Every counter metric includes a `_created` timestamp line. This tells
Prometheus exactly when the counter was last reset (i.e. process start time),
preventing false rate spikes in Grafana after a TrapNinja restart:

```
trapninja_traps_received_total 87432
trapninja_traps_received_total_created 1718042400.000
```

When Prometheus sees the `_created` value change between scrapes it knows a
new process lifetime has started and anchors its rate calculation correctly
rather than treating the counter drop as a spike. See `GRANULAR_STATS.md` for
the same pattern applied to per-IP and per-OID counters.

## Configuration

The metrics system is configured via `metrics_config.json` in your TrapNinja
configuration directory.

### Configuration File Location

- `/etc/trapninja/metrics_config.json` (production)
- `config/metrics_config.json` (development)

### Configuration Options

```json
{
  "enabled": true,
  "directory": "/opt/metrics",
  "export_interval_seconds": 60,
  "prometheus_file": "trapninja_metrics.prom",
  "json_file": "trapninja_metrics.json",
  "json_enabled": true,
  "global_labels": {
    "on_prem": "1",
    "environment": "production",
    "datacenter": "dc1"
  }
}
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | boolean | `true` | Enable/disable metrics collection |
| `directory` | string | `/var/log/trapninja/metrics` | Directory for metrics files |
| `export_interval_seconds` | integer | `60` | How often to export metrics (seconds) |
| `prometheus_file` | string | `trapninja_metrics.prom` | Prometheus metrics filename |
| `json_file` | string | `trapninja_metrics.json` | JSON metrics filename |
| `json_enabled` | boolean | `true` | Enable/disable JSON format output |
| `global_labels` | object | `{}` | Labels applied to ALL metrics |

### Global Labels

Global labels are applied to **every** Prometheus metric in
`trapninja_metrics.prom`, making it easy to distinguish deployments,
environments, and datacenters:

```
trapninja_traps_received_total{environment="production",on_prem="1"} 12345
trapninja_traps_received_total_created{environment="production",on_prem="1"} 1718042400.000
```

Global labels configured here are independent of any global labels configured
in `stats_config.json` (which apply to `trapninja_granular.prom`). Configure
both consistently for a unified Prometheus label set.

**Label name rules:** Must start with a letter or underscore; contain only
alphanumeric characters and underscores. Invalid characters are automatically
converted to underscores.

### Example Configurations

**On-Premises Production:**
```json
{
  "enabled": true,
  "directory": "/opt/metrics",
  "export_interval_seconds": 60,
  "global_labels": {
    "on_prem": "1",
    "environment": "production",
    "site": "datacenter-east"
  }
}
```

**High-Frequency Export (for debugging):**
```json
{
  "enabled": true,
  "directory": "/tmp/trapninja-metrics",
  "export_interval_seconds": 10,
  "global_labels": {
    "debug": "1"
  }
}
```

## Available Metrics

All metrics include any configured global labels.

### Core Trap Processing Counters

These counters are sourced from `GranularStatsCollector` and are always
current — no flush buffer between trap processing and metric export.

| Metric | Type | Description |
|--------|------|-------------|
| `trapninja_traps_received_total` | counter | Total SNMP traps received |
| `trapninja_traps_forwarded_total` | counter | Total traps forwarded to destinations |
| `trapninja_traps_blocked_total` | counter | Total traps blocked by IP or OID filters |
| `trapninja_traps_redirected_total` | counter | Total traps redirected to alternate destinations |
| `trapninja_traps_dropped_total` | counter | Total traps dropped due to queue full |
| `trapninja_processing_errors_total` | counter | Total packet processing errors |

Each counter is accompanied by a `_created` line (e.g.
`trapninja_traps_received_total_created`) containing the Unix timestamp of
the last process start. Do not use these `_created` lines directly in Grafana
panels — they are consumed automatically by Prometheus for accurate
`rate()` calculation.

### Sliding Window Gauges (60-second)

These gauges report trap counts observed in the last 60 seconds. They update
directly from the hot path with no buffering, making them suitable for
current-activity panels in Grafana without requiring `rate()` calculation.

| Metric | Type | Description |
|--------|------|-------------|
| `trapninja_traps_received_60s` | gauge | Traps received in the last 60 seconds |
| `trapninja_traps_forwarded_60s` | gauge | Traps forwarded in the last 60 seconds |
| `trapninja_traps_dropped_60s` | gauge | Traps dropped in the last 60 seconds |
| `trapninja_processing_errors_60s` | gauge | Processing errors in the last 60 seconds |

### High Availability Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `trapninja_ha_blocked_total` | counter | Traps not forwarded because node is secondary |
| `trapninja_ha_enabled` | gauge | Whether HA clustering is enabled (1/0) |
| `trapninja_ha_is_primary` | gauge | Whether this node is primary (1/0) |
| `trapninja_ha_is_forwarding` | gauge | Whether actively forwarding traps (1/0) |
| `trapninja_ha_peer_connected` | gauge | Whether HA peer is connected (1/0) |
| `trapninja_ha_failover_count` | counter | Number of HA failover events |

### Cache Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `trapninja_traps_cached_total` | counter | Total traps stored in cache for replay |
| `trapninja_cache_failures_total` | counter | Total cache storage failures |
| `trapninja_cache_available` | gauge | Whether Redis cache is available (1/0) |

### Performance Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `trapninja_fast_path_hits_total` | counter | Packets using optimized SNMPv2c fast path |
| `trapninja_slow_path_hits_total` | counter | Packets requiring full SNMP parsing |
| `trapninja_fast_path_ratio` | gauge | Percentage of packets using fast path |

Note: `trapninja_processing_rate` (lifetime average packets/second) was
removed from the Prometheus export in v0.8.0 as it is not a meaningful
instantaneous rate metric. Use `rate(trapninja_traps_received_total[2m])`
in Grafana instead.

### Queue Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `trapninja_queue_depth` | gauge | Current packets in processing queue |
| `trapninja_queue_max_depth` | gauge | Maximum queue depth observed |
| `trapninja_queue_capacity` | gauge | Maximum queue capacity |
| `trapninja_queue_utilization` | gauge | Queue utilization ratio (0.0–1.0) |
| `trapninja_queue_full_events_total` | counter | Times queue reached capacity |

### Detailed Tracking Metrics

These metrics carry both global labels and metric-specific labels:

| Metric | Labels | Description |
|--------|--------|-------------|
| `trapninja_blocked_ip_count` | `ip` + global | Traps blocked from specific IP |
| `trapninja_blocked_oid_count` | `oid` + global | Traps blocked with specific OID |
| `trapninja_redirected_ip_count` | `ip`, `tag` + global | Traps redirected from specific IP |
| `trapninja_redirected_oid_count` | `oid`, `tag` + global | Traps redirected with specific OID |

### Uptime

| Metric | Type | Description |
|--------|------|-------------|
| `trapninja_uptime_seconds` | counter | Time since service started |

### Pipeline Timing Metrics (Phase 1 load-test instrumentation)

Per-stage latency percentiles computed from lock-free per-worker ring
buffers (4096 samples per worker by default, configurable via
`diagnostics_config.json`). Percentiles are computed once per unified
export cycle. Metrics are **absent** when timing is disabled or before
the first export cycle.

| Metric | Type | Description |
|--------|------|-------------|
| `trapninja_queue_wait_seconds_p50` | gauge | Median time a packet spends waiting in the queue (capture → dequeue) |
| `trapninja_queue_wait_seconds_p95` | gauge | 95th-percentile queue wait time |
| `trapninja_queue_wait_seconds_p99` | gauge | 99th-percentile queue wait time |
| `trapninja_queue_wait_seconds_max` | gauge | Maximum queue wait time in the current ring buffer window |
| `trapninja_queue_wait_seconds_samples` | gauge | Number of samples in the ring buffer used for queue wait computation |
| `trapninja_processing_duration_seconds_p50` | gauge | Median time spent processing a single packet (dequeue → forward complete) |
| `trapninja_processing_duration_seconds_p95` | gauge | 95th-percentile processing duration |
| `trapninja_processing_duration_seconds_p99` | gauge | 99th-percentile processing duration |
| `trapninja_processing_duration_seconds_max` | gauge | Maximum processing duration in the current ring buffer window |
| `trapninja_processing_duration_seconds_samples` | gauge | Number of samples in the ring buffer used for processing duration computation |

**Notes:**
- Queue wait is only recorded for live traps. Replay packets (injected via
  `--replay`) do not carry a `_capture_ts` and are excluded from queue wait
  calculations, though their processing duration is still recorded.
- Both metrics aggregate across all worker threads; p99 reflects the
  worst worker in that export cycle.
- These are gauges (not histograms) because they are computed from a
  fixed-size rolling window, not a cumulative distribution.

**Configuration (`diagnostics_config.json`):**
```json
{
  "pipeline_timing": {
    "enabled": true,
    "ring_buffer_size": 4096,
    "percentiles": [50, 95, 99]
  }
}
```

See `config.example/diagnostics_config.json` for the full annotated example.

### Resource Telemetry Metrics (Phase 1 load-test instrumentation)

Process-level resource snapshot sampled once per export cycle. Useful for
correlating memory growth or FD leaks with trap load during load tests.

| Metric | Type | Description |
|--------|------|-------------|
| `trapninja_process_rss_bytes` | gauge | Resident set size (RSS) of the TrapNinja process in bytes |
| `trapninja_process_open_fds` | gauge | Number of open file descriptors (Linux only; absent on other platforms) |
| `trapninja_gc_collections_total{generation="0"}` | counter | CPython GC collection count for generation 0 (youngest objects) |
| `trapninja_gc_collections_total{generation="1"}` | counter | CPython GC collection count for generation 1 |
| `trapninja_gc_collections_total{generation="2"}` | counter | CPython GC collection count for generation 2 (oldest objects — most expensive) |

**Notes:**
- `trapninja_gc_collections_total` does **not** include a `_created`
  timestamp. These are kernel/runtime counters reset by the OS/interpreter,
  not by TrapNinja's process lifetime, so a `_created` line would be
  misleading. Use `increase()` rather than `rate()` for GC collection trends.
- `trapninja_process_open_fds` reads `/proc/<pid>/fd` and is silently
  omitted on platforms where that path is unavailable (e.g., Windows dev
  environments). On RHEL production it is always present.

### Socket Drop Metrics (Phase 1 load-test instrumentation)

Kernel-level UDP receive-buffer drops, read from `/proc/net/udp` once per
export cycle. Only active in **socket capture mode** (eBPF disabled). In
eBPF/raw-capture mode, see `trapninja_ebpf_raw_socket_drops_total` instead.

| Metric | Type | Description |
|--------|------|-------------|
| `trapninja_socket_drops_total{port="162"}` | counter | Cumulative kernel UDP receive-buffer drops on the given listen port |

**Notes:**
- One label series per configured listen port (typically just `port="162"`).
- This metric does **not** include a `_created` timestamp. The kernel's drop
  counter is not owned by TrapNinja and may have non-zero values before
  TrapNinja starts. Use `increase()` rather than `rate()` in Grafana.
- A non-zero and growing value here means traps are arriving faster than the
  kernel socket buffer can absorb them — consider increasing the socket
  receive buffer (`SO_RCVBUF`) or reducing burst load.

### eBPF Capture Metrics (Phase 1 load-test instrumentation)

Only present when eBPF/raw-capture mode is active. Both metrics are absent
when TrapNinja is running in socket capture mode.

| Metric | Type | Description |
|--------|------|-------------|
| `trapninja_ebpf_lost_samples_total` | counter | Lost notifications on the eBPF perf-buffer side channel |
| `trapninja_ebpf_raw_socket_drops_total` | counter | Cumulative AF_PACKET-level drops on the raw capture socket |

**Important distinction:**

`trapninja_ebpf_lost_samples_total` counts dropped *notifications* on the
eBPF perf buffer, which is a filtering/counting side channel — **not** the
path packets take into the processing queue. A lost notification does not
necessarily mean the corresponding trap was lost. This metric is a stress
signal (perf-buffer overrun under extreme kernel load), not a direct
trap-loss count.

`trapninja_ebpf_raw_socket_drops_total` is the actual data-path drop counter.
It reads `getsockopt(SOL_PACKET, PACKET_STATISTICS)` on the AF_PACKET raw
socket that `_raw_capture_loop()` reads from. A drop here means the kernel
discarded a packet before TrapNinja could read it — a genuine trap loss.

**Neither metric includes a `_created` timestamp.** `PACKET_STATISTICS` resets
the kernel's internal counter on every read; TrapNinja accumulates the deltas
into a monotonically-increasing running total, which means the counter behaves
correctly with `rate()` and `increase()` in Grafana, but a `_created` line
would misrepresent when the accumulation started.

## Prometheus Integration

### Node Exporter Textfile Collector

```bash
# Start node_exporter pointing at the metrics directory
node_exporter --collector.textfile.directory=/var/log/trapninja/metrics
```

Node_exporter will pick up both `trapninja_metrics.prom` and
`trapninja_granular.prom`. The files are designed to contain no overlapping
metric names, so Prometheus will not double-count any values.

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'trapninja'
    static_configs:
      - targets: ['trapninja-server:9100']
    metric_relabel_configs:
      - source_labels: [__name__]
        regex: 'trapninja_.*'
        action: keep
```

### Recommended Grafana Queries

**Current trap rate (traps/second):**
```promql
rate(trapninja_traps_received_total[2m])
```

Use a `[2m]` range window rather than `[1m]` to ensure the calculation spans
at least two scrape intervals, avoiding single-point artefacts.

**Current trap rate (traps/minute) — alternative using 60s gauge:**
```promql
trapninja_traps_received_60s
```

This gauge is updated directly on the hot path with no buffering, making it
slightly more responsive than `rate()` for current-activity panels.

**Forwarding efficiency:**
```promql
rate(trapninja_traps_forwarded_total[2m]) / rate(trapninja_traps_received_total[2m])
```

**Queue utilisation:**
```promql
trapninja_queue_utilization * 100
```

**Fast path ratio:**
```promql
trapninja_fast_path_ratio
```

**HA primary/secondary status:**
```promql
trapninja_ha_is_primary
```

**Top 10 blocked IPs:**
```promql
topk(10, trapninja_blocked_ip_count)
```

**Processing pipeline p99 latency:**
```promql
trapninja_processing_duration_seconds_p99
```

**Queue wait p95 (time packets spend waiting before a worker picks them up):**
```promql
trapninja_queue_wait_seconds_p95
```

**RSS memory trend:**
```promql
trapninja_process_rss_bytes / 1024 / 1024
```

**GC gen-2 collection rate (high values indicate memory pressure):**
```promql
increase(trapninja_gc_collections_total{generation="2"}[5m])
```

**AF_PACKET raw socket drop rate (eBPF mode only):**
```promql
rate(trapninja_ebpf_raw_socket_drops_total[2m])
```

**UDP socket drop rate (socket capture mode only):**
```promql
rate(trapninja_socket_drops_total[2m])
```

For per-IP and per-OID rate queries, use the granular metrics in
`trapninja_granular.prom` — see `GRANULAR_STATS.md`.

## JSON Format

The JSON export mirrors the Prometheus content and includes configuration
metadata. Trap totals are sourced from the same `GranularStatsCollector`
counters as the `.prom` file.

```json
{
  "timestamp": "2025-06-15T10:30:00.000000",
  "uptime_seconds": 3600.5,
  "metrics_start_time": 1718042400.0,
  "interval_seconds": 60,
  "metrics_config": {
    "directory": "/opt/metrics",
    "global_labels": {
      "on_prem": "1",
      "environment": "production"
    }
  },
  "total_traps_received": 15000,
  "total_traps_forwarded": 14500,
  "total_traps_blocked": 250,
  "total_traps_redirected": 150,
  "total_traps_dropped": 5,
  "processing_errors": 2,
  "ha_blocked": 0,
  "traps_cached": 14500,
  "cache_failures": 0,
  "fast_path_hits": 14000,
  "slow_path_hits": 1000,
  "fast_path_ratio": 93.3,
  "window_60s_received": 250,
  "window_60s_forwarded": 242,
  "window_60s_dropped": 0,
  "window_60s_errors": 0,
  "queue_current_depth": 10,
  "queue_max_depth": 500,
  "queue_capacity": 200000,
  "queue_utilization": 0.00005,
  "queue_full_events": 0,
  "ha": {
    "enabled": true,
    "state": "PRIMARY",
    "is_primary": true,
    "is_forwarding": true,
    "peer_connected": true,
    "failover_count": 0
  },
  "cache": {
    "enabled": true,
    "available": true
  },
  "blocked_ips": {
    "10.0.0.100": 50
  },
  "blocked_oids": {},
  "redirected_ips": {},
  "redirected_oids": {}
}
```

Note: `processing_rate` (lifetime average) is present in the JSON export for
CLI and diagnostic tooling but is intentionally absent from the `.prom` file.

## Directory Permissions

```bash
sudo mkdir -p /opt/metrics
sudo chown trapninja:trapninja /opt/metrics
sudo chmod 755 /opt/metrics
```

## Troubleshooting

### Metrics Show Zero After Upgrade to v0.8.1

If you are upgrading from a version prior to v0.8.1, ensure the granular
statistics collector is initialised before the metrics export timer fires.
The startup sequence initialises the granular collector first, but if metrics
are exported before the first trap is processed, `_get_granular_totals()` will
return zeros until the collector is ready. This self-corrects within the first
export interval.

### Rate Spikes in Grafana After Restart

TrapNinja emits `_created` timestamps on all counters to prevent this. If you
are still seeing spikes, verify the running version is v0.8.0+ and that the
`.prom` file contains `_created` lines:

```bash
grep "_created" /var/log/trapninja/metrics/trapninja_metrics.prom | head -5
```

If no `_created` lines are present, the running process is stale — restart
TrapNinja to pick up the updated code.

### `trapninja_traps_received_total` Dips Not Seen in Other Metrics

Prior to v0.8.1 this had two root causes, both now resolved:

1. **Flush-lag** — `trapninja_traps_received_total` was sourced from a
   per-worker buffered counter (flushed every 1,000 operations) while the
   granular per-IP totals were sourced from an unbuffered direct counter.
   Fixed by making `GranularStatsCollector` the single counter source.

2. **Timer-drift** — two independent 60-second export timers started at
   different times and drifted apart, writing the two `.prom` files at
   different moments from different snapshots. During periods of I/O or
   CPU pressure one timer could lag significantly behind the other,
   producing Grafana dips that did not reflect actual trap volume changes.
   Fixed by the unified export timer: both files are now written in the
   same callback, always from a consistent snapshot.

If you are still seeing this on v0.8.1+, confirm both fixes are deployed
and that the running process has been restarted after deployment.

### Double-Counted Metrics in Prometheus

If Prometheus shows values twice the expected amount, check that node_exporter
is not scraping a directory containing both old and new `.prom` files with
overlapping metric names. In v0.8.1 the global trap totals were removed from
`trapninja_granular.prom` — if you have an older `trapninja_granular.prom`
file on disk alongside a new `trapninja_metrics.prom`, delete the old granular
file and restart TrapNinja to regenerate it cleanly.

### Node Exporter Not Reading Metrics File

1. **Missing trailing newline** — fixed in v0.5.1+. Check the file ends with
   a blank line: `tail -c 2 /opt/metrics/trapninja_metrics.prom | xxd`
2. **File permissions** — `ls -la /opt/metrics/trapninja_metrics.prom`
3. **Syntax errors** — `promtool check metrics < /opt/metrics/trapninja_metrics.prom`
4. **Directory not configured** — `ps aux | grep node_exporter | grep textfile`

### All Metrics Show Zero

1. Check the service is running and processing packets
2. Verify packet flow: `tcpdump -i eth0 udp port 162`
3. Check logs: `tail -f /var/log/trapninja/trapninja.log | grep -i metric`

### Queue Utilisation Consistently High

If `trapninja_queue_utilization` is above 0.8:
1. Consider increasing worker count
2. Check for slow destinations causing back-pressure
3. Monitor network latency to forwarding targets

## Programmatic Configuration

```python
from trapninja.metrics import init_metrics, MetricsConfig

config = MetricsConfig(
    enabled=True,
    directory="/opt/metrics",
    export_interval_seconds=60,
    global_labels={"on_prem": "1", "environment": "production"}
)
init_metrics(config=config)
```

## See Also

- [GRANULAR_STATS.md](GRANULAR_STATS.md) — Per-IP, per-OID, per-destination metrics
- [ARCHITECTURE.md](ARCHITECTURE.md) — System architecture overview
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md) — General troubleshooting guide
