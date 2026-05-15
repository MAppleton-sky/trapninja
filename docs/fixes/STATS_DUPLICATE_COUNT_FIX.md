# Stats Duplicate Count & Imbalance Fix

> **Status:** Proposed — not yet implemented  
> **Date identified:** 2026-05-15  
> **Affected files:**
> - `src/trapninja/stats/collector.py`
> - `src/trapninja/stats/models.py`
> - `src/trapninja/metrics/collector.py`
> - `src/trapninja/metrics/exporter.py`
> - `src/trapninja/processing/packet_handler.py`

---

## Background

A code audit identified four related issues in the stats/metrics pipeline:

1. A Prometheus double-count risk caused by an implicit contract between two files
2. A counter imbalance where five action types are silently unaccounted for
3. Missing Prometheus metrics for HA-blocked and SNMPv3 error traps
4. No test validating that action-specific counters sum to the total trap count

---

## Issue 1 — Prometheus Double-Count Risk

### Location
`stats/collector.py:590–600`

### Description
`GranularStatsCollector.export_prometheus()` intentionally does **not** export global trap
counters (`trapninja_traps_total`, `_forwarded_total`, etc.) because `metrics/collector.py`
exports them via `metrics/exporter.py`. This design is correct but **implicit** — it relies
on developers knowing not to export these counters from both files. If that comment is missed,
both `.prom` files will contain identical metric names, and `node_exporter` will double-count
them when scraping.

### Root Cause
The boundary between the two collectors is undocumented as an API — it is maintained only
by a code comment.

### Proposed Fix
Add a `get_totals()` public method to `GranularStatsCollector` that returns all exportable
counters as a typed dict. Replace the direct private attribute access in
`metrics/collector.py:_get_granular_totals()` with a call to this method.

```python
# stats/collector.py — new public method
def get_totals(self) -> Dict[str, int]:
    """Single source of truth for all trap action totals for metrics export."""
    return {
        'total_traps':      self._total_traps,
        'total_forwarded':  self._total_forwarded,
        'total_blocked':    self._total_blocked,
        'total_redirected': self._total_redirected,
        'total_dropped':    self._total_dropped,
        'total_ha_blocked': self._total_ha_blocked,   # see Issue 2
        'total_v3_errors':  self._total_v3_errors,    # see Issue 2
    }

# metrics/collector.py — replace _get_granular_totals() body with:
collector = get_stats_collector()
if collector:
    return collector.get_totals()
```

**Why this matters:** Adding a new action type now forces updating `get_totals()`, which
surfaces any gap immediately rather than silently omitting it from Prometheus.

---

## Issue 2 — Counter Imbalance: Unhandled Action Types

### Location
- `stats/collector.py:196–204` — `GranularStatsCollector.record_trap()`
- `stats/models.py:197–205` — `IPStats.record_trap()`
- `processing/packet_handler.py:334, 700, 719, 731, 804`

### Description
Five action types are passed to `record_trap()` that fall through the `if/elif` chain without
incrementing any action-specific counter. `_total_traps` is still incremented, creating an
imbalance:

```
_total_traps != forwarded + blocked + redirected + dropped
```

| Action string | Caller location | Meaning |
|---|---|---|
| `ha_blocked` | `packet_handler.py:334` | Trap rejected — node is HA secondary |
| `v3_decryption_failed` | `packet_handler.py:700` | SNMPv3 key/auth failure |
| `v3_decryption_error` | `packet_handler.py:719` | SNMPv3 unexpected decryption error |
| `v3_logic_error` | `packet_handler.py:731` | BUG path — credentials present but unhandled |
| `v3_conversion_failed` | `packet_handler.py:804` | Post-decrypt PDU conversion failure |

### Proposed Fix
Add two new counters to `GranularStatsCollector` and `IPStats`. The four SNMPv3 variants
roll up into a single `v3_errors` counter — they are all decryption-path failures and
distinguishing them at the totals level adds noise without operational value.

```python
# stats/collector.py — __init__
self._total_ha_blocked: int = 0
self._total_v3_errors: int = 0

# stats/collector.py — record_trap() extend elif chain
elif action == 'ha_blocked':
    self._total_ha_blocked += 1
elif action in ('v3_decryption_failed', 'v3_decryption_error',
                'v3_logic_error', 'v3_conversion_failed'):
    self._total_v3_errors += 1
```

Apply the same pattern to `IPStats.record_trap()` in `models.py`:

```python
# stats/models.py — IPStats.__init__
self.ha_blocked: int = 0
self.v3_errors: int = 0

# stats/models.py — IPStats.record_trap() extend elif chain
elif action == 'ha_blocked':
    self.ha_blocked += 1
elif action in ('v3_decryption_failed', 'v3_decryption_error',
                'v3_logic_error', 'v3_conversion_failed'):
    self.v3_errors += 1
```

---

## Issue 3 — Missing Prometheus Metrics

### Location
`metrics/exporter.py:235–273`

### Description
The Prometheus exporter only exports five action counters. HA-blocked and SNMPv3 error
traps are never exported, making them invisible to alerting and dashboards.

### Proposed Fix
After the `trapninja_traps_dropped_total` block in `exporter.py`, add:

```python
lines.append(_emit_counter(
    "trapninja_traps_ha_blocked_total",
    metrics_summary["total_ha_blocked"],
    metrics_start_time,
    global_labels=global_labels,
    help_text="Total traps rejected because this node is HA secondary",
))

lines.append(_emit_counter(
    "trapninja_traps_v3_errors_total",
    metrics_summary["total_v3_errors"],
    metrics_start_time,
    global_labels=global_labels,
    help_text="Total SNMPv3 traps dropped due to decryption or conversion failure",
))
```

Also update `_get_granular_totals()` in `metrics/collector.py` to include the two new keys
(or replace with `get_totals()` as described in Issue 1), and ensure `get_metrics_summary()`
propagates them through to the exporter.

---

## Issue 4 — No Counter-Balance Test

### Location
`dev/tests/` — no existing test covers this

### Description
There is no test asserting that all action-specific counters sum to `_total_traps`. This
means the imbalance described in Issue 2 went undetected.

### Proposed Fix
Add a test to `dev/tests/` (suggested name: `test_impl_stats_counter_balance.py`):

```python
def test_action_counters_sum_to_total():
    """All action-specific counters must account for every recorded trap."""
    collector = GranularStatsCollector()
    # Record one trap of each action type
    for action in ('forwarded', 'blocked', 'redirected', 'dropped',
                   'ha_blocked', 'v3_decryption_failed', 'v3_decryption_error',
                   'v3_logic_error', 'v3_conversion_failed'):
        collector.record_trap('1.2.3.4', '1.3.6.1', action, None)

    totals = collector.get_totals()
    action_sum = (
        totals['total_forwarded'] + totals['total_blocked'] +
        totals['total_redirected'] + totals['total_dropped'] +
        totals['total_ha_blocked'] + totals['total_v3_errors']
    )
    assert totals['total_traps'] == action_sum, (
        f"Counter imbalance: total_traps={totals['total_traps']} "
        f"but action sum={action_sum}"
    )
```

---

## Implementation Order

1. **Issue 2** — Add counters to `stats/collector.py` and `stats/models.py`
2. **Issue 1** — Add `get_totals()` to `GranularStatsCollector`; update `metrics/collector.py`
3. **Issue 3** — Add new Prometheus metrics to `metrics/exporter.py`
4. **Issue 4** — Add counter-balance test

Issues 2 and 1 must be done together (1 depends on 2). Issues 3 and 4 can follow independently.

---

## Migration Notes

- No configuration changes required.
- The two new Prometheus metrics (`trapninja_traps_ha_blocked_total`,
  `trapninja_traps_v3_errors_total`) are additive — existing dashboards are unaffected.
- Operators may wish to add alerting rules on `trapninja_traps_v3_errors_total > 0` to
  surface SNMPv3 credential mismatches in production.
