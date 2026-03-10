#!/usr/bin/env python3
"""
TrapNinja Processing Statistics

Lock-free statistics collection for high-performance processing.

Author: TrapNinja Team
Version: 2.0.0
"""

import time
import threading
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional


SLIDING_WINDOW_SECONDS = 60
SLIDING_WINDOW_BUCKETS = 12


class SlidingWindowCounter:
    """
    Thread-safe sliding-window event counter using fixed-width time buckets.

    The 60-second window is divided into SLIDING_WINDOW_BUCKETS (12) slots of
    bucket_width seconds each (5 s by default).  Each slot is addressed by
    ``int(now / bucket_width) % num_buckets`` — a modular index that wraps
    around naturally as time advances.

    Rotation is *lazy*: no background thread is needed.  On every ``increment``
    call the slot's stored timestamp is checked; if it falls outside the
    current window the slot is silently reset before the new count is added.
    This makes ``increment`` O(1) and keeps the lock's critical section to a
    single conditional reset + integer add.

    Thread-safety guarantee
    -----------------------
    All mutations of ``_buckets`` and ``_bucket_timestamps`` are serialised
    through ``_lock``.  ``get_value`` acquires the same lock so it always
    observes a consistent snapshot.  The index computation (``time.time()``
    call + arithmetic) is done *outside* the lock because it is read-only and
    the worst case — two threads landing on the same slot simultaneously — is
    handled correctly by the in-lock timestamp comparison.
    """

    def __init__(
        self,
        window_seconds: int = SLIDING_WINDOW_SECONDS,
        num_buckets: int = SLIDING_WINDOW_BUCKETS,
    ) -> None:
        self._num_buckets: int = num_buckets
        self._window_seconds: float = float(window_seconds)
        self._bucket_width: float = self._window_seconds / self._num_buckets
        self._buckets: List[int] = [0] * self._num_buckets
        self._bucket_timestamps: List[float] = [0.0] * self._num_buckets
        self._lock = threading.Lock()

    def increment(self, count: int = 1) -> None:
        """
        Record *count* events against the current time bucket.

        O(1).  Lock hold time is a single comparison + two assignments + one
        addition — typically sub-microsecond.

        Args:
            count: Number of events to add (default 1).
        """
        now = time.time()
        idx = int(now / self._bucket_width) % self._num_buckets
        with self._lock:
            if now - self._bucket_timestamps[idx] >= self._window_seconds:
                self._buckets[idx] = 0
                self._bucket_timestamps[idx] = now
            self._buckets[idx] += count

    def get_value(self) -> int:
        """
        Return the total number of events recorded in the last 60 seconds.

        Iterates all 12 buckets under lock; only includes buckets whose
        timestamp falls within the current window.

        Returns:
            Sum of counts across all valid buckets.
        """
        now = time.time()
        cutoff = now - self._window_seconds
        total = 0
        with self._lock:
            for i in range(self._num_buckets):
                if self._bucket_timestamps[i] > cutoff:
                    total += self._buckets[i]
        return total


@dataclass
class ProcessingStats:
    """
    Lock-free processing statistics.
    
    Uses Python's GIL for atomic int operations on simple fields.
    Thread-safe for increment operations.
    
    Attributes:
        packets_processed: Total packets processed
        packets_forwarded: Successfully forwarded packets
        packets_blocked: Blocked by IP or OID filter
        packets_redirected: Redirected to alternate destinations
        packets_dropped: Dropped due to queue full
        processing_errors: Errors during processing
        fast_path_hits: Processed via fast SNMPv2c path
        slow_path_hits: Processed via full parsing
        ha_blocked: Packets blocked due to HA secondary mode
    """
    packets_processed: int = 0
    packets_forwarded: int = 0
    packets_blocked: int = 0
    packets_redirected: int = 0
    packets_dropped: int = 0
    processing_errors: int = 0
    fast_path_hits: int = 0
    slow_path_hits: int = 0
    queue_full_events: int = 0
    max_queue_depth: int = 0
    ha_blocked: int = 0  # Blocked due to HA secondary mode
    
    # Timing
    _start_time: float = field(default_factory=time.time)
    _last_summary_time: float = field(default_factory=time.time)

    # Sliding-window counters (last 60 seconds)
    _window_received: SlidingWindowCounter = field(
        default_factory=lambda: SlidingWindowCounter()
    )
    _window_forwarded: SlidingWindowCounter = field(
        default_factory=lambda: SlidingWindowCounter()
    )
    _window_dropped: SlidingWindowCounter = field(
        default_factory=lambda: SlidingWindowCounter()
    )
    _window_errors: SlidingWindowCounter = field(
        default_factory=lambda: SlidingWindowCounter()
    )

    def increment_processed(self):
        """Record a processed packet."""
        self.packets_processed += 1
        self._window_received.increment()

    def increment_forwarded(self):
        """Record a forwarded packet."""
        self.packets_forwarded += 1
        self._window_forwarded.increment()

    def increment_blocked(self):
        """Record a blocked packet."""
        self.packets_blocked += 1

    def increment_redirected(self):
        """Record a redirected packet."""
        self.packets_redirected += 1

    def increment_dropped(self):
        """Record a dropped packet."""
        self.packets_dropped += 1
        self.queue_full_events += 1
        self._window_dropped.increment()

    def increment_error(self):
        """Record a processing error."""
        self.processing_errors += 1
        self._window_errors.increment()
    
    def increment_ha_blocked(self):
        """Record a packet blocked by HA (secondary mode)."""
        self.ha_blocked += 1
    
    @property
    def ha_blocked_count(self) -> int:
        """Get count of HA-blocked packets."""
        return self.ha_blocked
    
    def record_fast_path(self):
        """Record fast path processing."""
        self.fast_path_hits += 1
    
    def record_slow_path(self):
        """Record slow path processing."""
        self.slow_path_hits += 1
    
    def update_max_queue_depth(self, depth: int):
        """Update maximum queue depth if higher."""
        if depth > self.max_queue_depth:
            self.max_queue_depth = depth
    
    @property
    def uptime(self) -> float:
        """Get seconds since start."""
        return time.time() - self._start_time
    
    @property
    def fast_path_ratio(self) -> float:
        """Calculate fast path ratio as percentage."""
        total = self.fast_path_hits + self.slow_path_hits
        if total == 0:
            return 0.0
        return (self.fast_path_hits / total) * 100
    
    @property
    def processing_rate(self) -> float:
        """Calculate packets per second."""
        elapsed = self.uptime
        if elapsed <= 0:
            return 0.0
        return self.packets_processed / elapsed

    @property
    def received_last_60s(self) -> int:
        """Count of traps received in the last 60 seconds."""
        return self._window_received.get_value()

    @property
    def forwarded_last_60s(self) -> int:
        """Count of traps forwarded in the last 60 seconds."""
        return self._window_forwarded.get_value()

    @property
    def dropped_last_60s(self) -> int:
        """Count of traps dropped in the last 60 seconds."""
        return self._window_dropped.get_value()

    @property
    def errors_last_60s(self) -> int:
        """Count of processing errors in the last 60 seconds."""
        return self._window_errors.get_value()

    def should_log_summary(self, interval: float = 30.0) -> bool:
        """
        Check if it's time to log a summary.
        
        Args:
            interval: Seconds between summaries
            
        Returns:
            True if interval has elapsed
        """
        now = time.time()
        if now - self._last_summary_time >= interval:
            self._last_summary_time = now
            return True
        return False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            'packets_processed': self.packets_processed,
            'packets_forwarded': self.packets_forwarded,
            'packets_blocked': self.packets_blocked,
            'packets_redirected': self.packets_redirected,
            'packets_dropped': self.packets_dropped,
            'processing_errors': self.processing_errors,
            'ha_blocked': self.ha_blocked,
            'fast_path_hits': self.fast_path_hits,
            'slow_path_hits': self.slow_path_hits,
            'fast_path_ratio': round(self.fast_path_ratio, 1),
            'queue_full_events': self.queue_full_events,
            'max_queue_depth': self.max_queue_depth,
            'uptime_seconds': round(self.uptime, 1),
            'processing_rate': round(self.processing_rate, 1),
            'window_60s': {
                'received':  self.received_last_60s,
                'forwarded': self.forwarded_last_60s,
                'dropped':   self.dropped_last_60s,
                'errors':    self.errors_last_60s,
            },
        }
    
    def reset(self):
        """Reset all counters."""
        self.packets_processed = 0
        self.packets_forwarded = 0
        self.packets_blocked = 0
        self.packets_redirected = 0
        self.packets_dropped = 0
        self.processing_errors = 0
        self.ha_blocked = 0
        self.fast_path_hits = 0
        self.slow_path_hits = 0
        self.queue_full_events = 0
        self.max_queue_depth = 0
        self._start_time = time.time()
        self._last_summary_time = time.time()
        self._window_received  = SlidingWindowCounter()
        self._window_forwarded = SlidingWindowCounter()
        self._window_dropped   = SlidingWindowCounter()
        self._window_errors    = SlidingWindowCounter()


# Global statistics instance
_global_stats: Optional[ProcessingStats] = None
_stats_lock = threading.Lock()


def get_global_stats() -> ProcessingStats:
    """
    Get or create global statistics instance.
    
    Returns:
        ProcessingStats instance
    """
    global _global_stats
    if _global_stats is None:
        with _stats_lock:
            if _global_stats is None:
                _global_stats = ProcessingStats()
    return _global_stats


def reset_global_stats():
    """Reset global statistics."""
    global _global_stats
    with _stats_lock:
        if _global_stats:
            _global_stats.reset()
        else:
            _global_stats = ProcessingStats()


class StatsCollector:
    """
    Thread-local statistics collector.

    Collects stats locally and periodically flushes to global.
    Reduces contention on global counters.

    Window counters bypass the local buffer to preserve accurate event timing
    for the 60-second sliding window.  All other counters are batched and
    flushed to the global instance every flush_interval operations.
    """

    def __init__(self, flush_interval: int = 1000):
        """
        Initialize collector.

        Args:
            flush_interval: Flush after this many operations
        """
        self._local = ProcessingStats()
        self._flush_interval = flush_interval
        self._ops_since_flush = 0

    def increment_processed(self):
        self._local.increment_processed()
        get_global_stats()._window_received.increment()
        self._maybe_flush()

    def increment_forwarded(self):
        self._local.increment_forwarded()
        get_global_stats()._window_forwarded.increment()
        self._maybe_flush()

    def increment_blocked(self):
        self._local.increment_blocked()
        self._maybe_flush()

    def increment_redirected(self):
        self._local.increment_redirected()
        self._maybe_flush()

    def increment_dropped(self):
        self._local.increment_dropped()
        get_global_stats()._window_dropped.increment()
        self._maybe_flush()

    def increment_error(self):
        self._local.increment_error()
        get_global_stats()._window_errors.increment()
        self._maybe_flush()
    
    def increment_ha_blocked(self):
        self._local.increment_ha_blocked()
        self._maybe_flush()
    
    @property
    def ha_blocked_count(self) -> int:
        """Get local ha_blocked count."""
        return self._local.ha_blocked
    
    def record_fast_path(self):
        self._local.record_fast_path()
    
    def record_slow_path(self):
        self._local.record_slow_path()
    
    def _maybe_flush(self):
        """Flush to global if interval reached."""
        self._ops_since_flush += 1
        if self._ops_since_flush >= self._flush_interval:
            self.flush()
    
    def flush(self):
        """Flush local stats to global."""
        global_stats = get_global_stats()
        
        global_stats.packets_processed += self._local.packets_processed
        global_stats.packets_forwarded += self._local.packets_forwarded
        global_stats.packets_blocked += self._local.packets_blocked
        global_stats.packets_redirected += self._local.packets_redirected
        global_stats.packets_dropped += self._local.packets_dropped
        global_stats.processing_errors += self._local.processing_errors
        global_stats.ha_blocked += self._local.ha_blocked
        global_stats.fast_path_hits += self._local.fast_path_hits
        global_stats.slow_path_hits += self._local.slow_path_hits
        
        self._local.reset()
        self._ops_since_flush = 0
