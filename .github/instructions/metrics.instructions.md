---
applyTo: "src/trapninja/metrics/**,src/trapninja/stats/**"
---

# Metrics and Stats — Rules

## Prometheus Metric Naming

All per-source-IP metrics use the `trapninja_src_ip_*` prefix. **Not** `trapninja_ip_*` — this was renamed in v0.8.0 for directional clarity. Any regression to the old prefix will break existing Grafana dashboards and Prometheus alerting rules.

Standard metric families:
- `trapninja_traps_received_total` — cumulative counter
- `trapninja_traps_forwarded_total` — cumulative counter
- `trapninja_traps_dropped_total` — cumulative counter (alert if > 0 sustained)
- `trapninja_traps_failed_total` — cumulative counter (alert if rising)
- `trapninja_src_ip_received_total` — per-source-IP counter
- `trapninja_ha_role` — gauge (1 = ACTIVE, 0 = STANDBY)
- `trapninja_queue_depth` — gauge
- `trapninja_cache_size` — gauge

## Atomic File Writes — Mandatory

All `.prom` file writes must be atomic. Never write directly to the final filename:

```python
# CORRECT — atomic write
import os
import tempfile

tmp_path = prom_path + '.tmp'
with open(tmp_path, 'w') as f:
    f.write(content)
os.rename(tmp_path, prom_path)  # atomic on Linux

# WRONG — node_exporter may read a partial file
with open(prom_path, 'w') as f:
    f.write(content)
```

## No Empty Metric Families

Never write a metric family with `# HELP` and `# TYPE` headers but no sample lines. node_exporter rejects the entire file silently if empty families are present.

```python
# CORRECT — filter before writing
families_to_write = [f for f in all_families if f.samples]
for family in families_to_write:
    write_family(f, family)

# WRONG — writes empty families that break node_exporter
for family in all_families:
    write_family(f, family)
```

Always append `\n\n` after each metric family block (required separator).

## Stats Must Never Block Forwarding

Statistics collection follows a strict two-tier model:

**Tier 1 (hot path — forwarding thread):**
```python
with self._lock:
    self._counters[key] += 1  # only this, nothing else
```

**Tier 2 (background timer thread):**
- Aggregation (sum, average, percentile)
- Rolling window calculations
- Prometheus file write
- Redis metric updates
- Baseline persistence

If a stats operation cannot be expressed as a single lock + single add, it belongs in Tier 2.

## Sliding Window Counters (Designed, Not Yet Implemented)

The `SlidingWindowCounter` architecture uses a ring buffer per metric with 1-second buckets over a 60-second window. When implementing:
- Ring buffer is pre-allocated at init time — no dynamic allocation on the hot path
- Background thread aggregates by summing the ring buffer — never on the forwarding thread
- LRU eviction applies to (source_ip, oid) pair tracking — the tracked set is bounded
- Window size must be configurable, not hardcoded

## Baseline Files

Baselines are stored at `/etc/trapninja/baselines/` as JSON files, named by the operator-supplied identifier. They are **node-local** — never synced to Redis, never compared across nodes.
