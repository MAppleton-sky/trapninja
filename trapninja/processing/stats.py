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
from typing import Dict, Any, Optional


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
    
    def increment_processed(self):
        """Record a processed packet."""
        self.packets_processed += 1
    
    def increment_forwarded(self):
        """Record a forwarded packet."""
        self.packets_forwarded += 1
    
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
    
    def increment_error(self):
        """Record a processing error."""
        self.processing_errors += 1
    
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
        self._maybe_flush()
    
    def increment_forwarded(self):
        self._local.increment_forwarded()
        self._maybe_flush()
    
    def increment_blocked(self):
        self._local.increment_blocked()
        self._maybe_flush()
    
    def increment_redirected(self):
        self._local.increment_redirected()
        self._maybe_flush()
    
    def increment_dropped(self):
        self._local.increment_dropped()
        self._maybe_flush()
    
    def increment_error(self):
        self._local.increment_error()
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
