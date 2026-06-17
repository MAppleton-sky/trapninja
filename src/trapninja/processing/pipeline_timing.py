#!/usr/bin/env python3
"""
TrapNinja Pipeline Timing Collector

Lock-free-on-write latency instrumentation for the trap processing pipeline.
Tracks two per-trap latency measurements:

  - queue_wait:   time between a packet being queued (capture) and a worker
                  dequeuing it for processing
  - processing:   time spent inside PacketHandler._process_packet() per trap
                  (parsing, filtering, forwarding, stats, cache)

Design constraints (hot path is sacred):
  - Each worker owns exactly one pair of ring buffers, written only by that
    worker's own thread. No lock is taken on the write path.
  - The background exporter (driven by the existing unified metrics timer
    in metrics/collector.py) takes a lock only to copy the *list of buffer
    references*, never during the read of buffer contents. Percentile
    computation on a buffer that is concurrently being overwritten may
    include an occasional torn read (mixed old/new value); this is
    accepted as the cost of zero hot-path locking, consistent with how
    network.QueueStats already reports an approximate current_depth value
    elsewhere in this codebase.
  - Buffers are fixed-size and overwrite the oldest sample on wraparound
    (ring sampling), so memory is bounded regardless of trap volume.

This module is purely observational. It must never raise into the hot path
and must never affect forwarding behaviour. Disabling it via config (see
_load_config) must reduce its hot-path cost to a single boolean check.

Author: TrapNinja Team
Version: 1.0.0
"""

import array
import logging
import threading
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("trapninja")

DEFAULT_RING_SIZE = 4096
DEFAULT_PERCENTILES: Tuple[int, ...] = (50, 95, 99)


# =============================================================================
# RING BUFFER
# =============================================================================

class RingBuffer:
    """
    Fixed-size float ring buffer with single-writer, multi-reader semantics.

    Intended for exactly one writer thread (the owning worker) and
    occasional reads from a background thread for percentile computation.
    No lock is used on write — see module docstring for the accepted
    torn-read tradeoff.
    """

    __slots__ = ('_data', '_size', '_index', '_count')

    def __init__(self, size: int = DEFAULT_RING_SIZE):
        self._size = size
        self._data = array.array('d', [0.0] * size)
        self._index = 0   # next write position
        self._count = 0   # number of samples written, capped at _size

    def record(self, value: float) -> None:
        """Write one sample. O(1), no lock. Call only from the owning worker thread."""
        self._data[self._index] = value
        self._index = (self._index + 1) % self._size
        if self._count < self._size:
            self._count += 1

    def snapshot(self) -> List[float]:
        """
        Copy current contents for percentile computation.

        May race with a concurrent record() call (torn read of at most one
        slot). Acceptable for approximate observability data — see module
        docstring. Order is not chronological once the buffer has wrapped;
        callers must not depend on ordering.
        """
        n = self._count
        if n == 0:
            return []
        return list(self._data[:n])


# =============================================================================
# PER-WORKER BUFFER PAIR
# =============================================================================

class WorkerTimingBuffers:
    """Per-worker pair of ring buffers: queue_wait and processing_duration."""

    __slots__ = ('worker_id', 'queue_wait', 'processing_duration')

    def __init__(self, worker_id: int, ring_size: int = DEFAULT_RING_SIZE):
        self.worker_id = worker_id
        self.queue_wait = RingBuffer(ring_size)
        self.processing_duration = RingBuffer(ring_size)


# =============================================================================
# PERCENTILE HELPER
# =============================================================================

def _percentile_summary(samples: List[float], percentiles: Tuple[int, ...]) -> Dict[str, float]:
    """
    Compute a percentile summary for a list of samples.

    Returns a dict with one key per requested percentile (e.g. 'p50'),
    plus 'max' and 'samples'. Returns all zeros (not an exception) for
    an empty input — callers must be able to export this before the
    first sample has been recorded.
    """
    result: Dict[str, float] = {f'p{p}': 0.0 for p in percentiles}
    result['max'] = 0.0
    result['samples'] = 0
    if not samples:
        return result
    ordered = sorted(samples)
    n = len(ordered)
    for p in percentiles:
        idx = min(int(round((p / 100.0) * (n - 1))), n - 1)
        result[f'p{p}'] = ordered[idx]
    result['max'] = ordered[-1]
    result['samples'] = n
    return result


# =============================================================================
# COLLECTOR
# =============================================================================

class PipelineTimingCollector:
    """
    Process-wide registry of per-worker timing buffers.

    Workers call register_worker() once at startup and unregister_worker()
    on clean shutdown. The background metrics exporter calls
    compute_percentiles() once per export interval to drain all workers'
    buffers into aggregated percentiles. This is an O(n log n) sort over
    up to (num_workers * ring_size * 2) samples — cheap at export-interval
    frequency, but expensive enough that callers should cache the result
    rather than calling this on every metrics read. See
    metrics/collector.py's _export_pipeline_timing() / _last_pipeline_timing
    for the caching point.
    """

    def __init__(self, ring_size: int = DEFAULT_RING_SIZE,
                 enabled: bool = True,
                 percentiles: Tuple[int, ...] = DEFAULT_PERCENTILES):
        self._ring_size = ring_size
        self.enabled = enabled
        self.percentiles = percentiles
        self._buffers: Dict[int, WorkerTimingBuffers] = {}
        self._registry_lock = threading.Lock()  # protects dict structure only

    def register_worker(self, worker_id: int) -> WorkerTimingBuffers:
        """
        Register a worker and return its dedicated buffer pair.

        Safe to call multiple times for the same worker_id — returns a
        fresh buffer pair each time, replacing any prior entry.
        """
        buffers = WorkerTimingBuffers(worker_id, self._ring_size)
        with self._registry_lock:
            self._buffers[worker_id] = buffers
        return buffers

    def unregister_worker(self, worker_id: int) -> None:
        """Remove a worker's buffers on clean shutdown (best effort)."""
        with self._registry_lock:
            self._buffers.pop(worker_id, None)

    def compute_percentiles(self) -> Dict[str, Dict[str, float]]:
        """
        Drain all registered workers' buffers and compute aggregate percentiles.

        Returns:
            {
                'queue_wait_seconds': {'p50': .., 'p95': .., 'p99': .., 'max': .., 'samples': N},
                'processing_duration_seconds': {'p50': .., 'p95': .., 'p99': .., 'max': .., 'samples': N},
            }
        Never raises — any internal failure is logged and a zeroed result
        is returned instead.
        """
        try:
            with self._registry_lock:
                buffer_refs = list(self._buffers.values())

            queue_wait_samples: List[float] = []
            processing_samples: List[float] = []
            for wb in buffer_refs:
                queue_wait_samples.extend(wb.queue_wait.snapshot())
                processing_samples.extend(wb.processing_duration.snapshot())

            return {
                'queue_wait_seconds': _percentile_summary(queue_wait_samples, self.percentiles),
                'processing_duration_seconds': _percentile_summary(processing_samples, self.percentiles),
            }
        except Exception as e:
            logger.error(f"PipelineTimingCollector.compute_percentiles failed: {e}")
            empty = _percentile_summary([], self.percentiles)
            return {'queue_wait_seconds': dict(empty), 'processing_duration_seconds': dict(empty)}


# =============================================================================
# MODULE SINGLETON
# =============================================================================

_collector: Optional[PipelineTimingCollector] = None
_collector_lock = threading.Lock()


def get_pipeline_timing_collector() -> PipelineTimingCollector:
    """Get or create the global PipelineTimingCollector singleton."""
    global _collector
    if _collector is None:
        with _collector_lock:
            if _collector is None:
                ring_size, enabled, percentiles = _load_config()
                _collector = PipelineTimingCollector(
                    ring_size=ring_size, enabled=enabled, percentiles=percentiles
                )
    return _collector


def _load_config() -> Tuple[int, bool, Tuple[int, ...]]:
    """
    Load pipeline_timing settings from diagnostics_config.json.

    Returns (ring_size, enabled, percentiles), falling back to module
    defaults on any error or missing config. This is read once at
    singleton creation, not hot-reloaded — toggling this diagnostic
    flag requires a restart, which is an acceptable tradeoff for a
    load-testing aid (unlike production filtering rules, which must
    hot-reload).
    """
    try:
        import json
        import os
        from ..config import CONFIG_DIR
        path = os.path.join(CONFIG_DIR, "diagnostics_config.json")
        if not os.path.exists(path):
            return DEFAULT_RING_SIZE, True, DEFAULT_PERCENTILES
        with open(path, 'r') as f:
            cfg = json.load(f)
        timing_cfg = cfg.get('pipeline_timing', {})
        ring_size = int(timing_cfg.get('ring_buffer_size', DEFAULT_RING_SIZE))
        enabled = bool(timing_cfg.get('enabled', True))
        percentiles = tuple(timing_cfg.get('percentiles', list(DEFAULT_PERCENTILES)))
        return ring_size, enabled, percentiles
    except Exception as e:
        logger.debug(f"Could not load diagnostics_config.json, using defaults: {e}")
        return DEFAULT_RING_SIZE, True, DEFAULT_PERCENTILES


def reset_pipeline_timing_collector() -> None:
    """Reset the singleton. Test-only helper — do not call from production code."""
    global _collector
    with _collector_lock:
        _collector = None
