#!/usr/bin/env python3
"""
TrapNinja Gap Detector

Detects gaps in trap forwarding that occur during HA failover.
Analyzes timestamps to identify time windows where traps may have been missed.

The detector considers:
- Time gap between last known forwarded trap and current time
- Minimum gap threshold (gaps smaller than this are ignored)
- Maximum gap duration (caps replay window for safety)
- Per-destination gap analysis

Author: TrapNinja Team
Version: 1.0.0
"""

import logging
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Any

logger = logging.getLogger("trapninja")


@dataclass
class GapInfo:
    """
    Information about a detected forwarding gap.
    
    Attributes:
        destination: Destination identifier
        gap_start: Unix timestamp when gap started
        gap_end: Unix timestamp when gap ended (failover completion)
        gap_seconds: Duration of gap in seconds
        last_node: Instance ID of last forwarding node
        estimated_traps: Estimated number of traps in gap (from cache count)
        detected_at: When the gap was detected
    """
    destination: str
    gap_start: float
    gap_end: float
    gap_seconds: float
    last_node: Optional[str] = None
    estimated_traps: int = 0
    detected_at: float = 0.0
    
    def __post_init__(self):
        if self.detected_at == 0.0:
            self.detected_at = time.time()
    
    @property
    def start_datetime(self) -> datetime:
        """Get gap start as datetime."""
        return datetime.fromtimestamp(self.gap_start)
    
    @property
    def end_datetime(self) -> datetime:
        """Get gap end as datetime."""
        return datetime.fromtimestamp(self.gap_end)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'destination': self.destination,
            'gap_start': self.gap_start,
            'gap_start_iso': self.start_datetime.isoformat(),
            'gap_end': self.gap_end,
            'gap_end_iso': self.end_datetime.isoformat(),
            'gap_seconds': round(self.gap_seconds, 2),
            'last_node': self.last_node,
            'estimated_traps': self.estimated_traps,
            'detected_at': self.detected_at,
        }
    
    def __str__(self) -> str:
        return (
            f"Gap[{self.destination}]: {self.gap_seconds:.1f}s "
            f"({self.start_datetime.strftime('%H:%M:%S')} - "
            f"{self.end_datetime.strftime('%H:%M:%S')})"
        )


class GapDetector:
    """
    Detects forwarding gaps during HA failover.
    
    Compares last known forwarded timestamps against current time
    to identify windows where traps may have been missed.
    
    Configuration:
        min_gap_seconds: Minimum gap to consider (default: 1.0s)
        max_gap_seconds: Maximum gap to replay (default: 300s = 5 min)
        buffer_seconds: Extra buffer added to gap start (default: 0.5s)
    """
    
    DEFAULT_MIN_GAP = 1.0      # 1 second minimum
    DEFAULT_MAX_GAP = 300.0    # 5 minutes maximum
    DEFAULT_BUFFER = 0.5      # 0.5 second buffer
    
    def __init__(self,
                 tracker: 'FailoverTracker',
                 cache: Optional['TrapCache'] = None,
                 min_gap_seconds: float = DEFAULT_MIN_GAP,
                 max_gap_seconds: float = DEFAULT_MAX_GAP,
                 buffer_seconds: float = DEFAULT_BUFFER):
        """
        Initialize gap detector.
        
        Args:
            tracker: FailoverTracker instance
            cache: TrapCache for estimating trap counts (optional)
            min_gap_seconds: Minimum gap to consider
            max_gap_seconds: Maximum gap to allow
            buffer_seconds: Extra buffer to add to gap start
        """
        self._tracker = tracker
        self._cache = cache
        self.min_gap_seconds = min_gap_seconds
        self.max_gap_seconds = max_gap_seconds
        self.buffer_seconds = buffer_seconds
    
    def detect_gaps(self, 
                   destinations: Optional[List[str]] = None,
                   failover_time: Optional[float] = None) -> List[GapInfo]:
        """
        Detect forwarding gaps for all or specific destinations.
        
        Args:
            destinations: List of destinations to check (None for all)
            failover_time: Time when failover completed (default: now)
            
        Returns:
            List of detected GapInfo objects
        """
        now = failover_time or time.time()
        gaps = []
        
        # Get all last forwarded timestamps
        if destinations:
            timestamps = {}
            for dest in destinations:
                ts = self._tracker.get_last_forwarded(dest)
                if ts:
                    timestamps[dest] = ts
        else:
            timestamps = self._tracker.get_all_last_forwarded()
        
        if not timestamps:
            logger.debug("No forwarding timestamps found - no gap detection possible")
            return gaps
        
        for dest, last_ts in timestamps.items():
            gap = self._analyze_gap(dest, last_ts, now)
            if gap:
                gaps.append(gap)
                logger.info(f"Detected {gap}")
        
        return gaps
    
    def _analyze_gap(self, 
                    destination: str,
                    last_forwarded: float,
                    current_time: float) -> Optional[GapInfo]:
        """
        Analyze a single destination for gaps.
        
        Args:
            destination: Destination identifier
            last_forwarded: Last forwarded timestamp
            current_time: Current/failover time
            
        Returns:
            GapInfo if gap detected, None otherwise
        """
        gap_seconds = current_time - last_forwarded
        
        # Check minimum threshold
        if gap_seconds < self.min_gap_seconds:
            logger.debug(
                f"Gap for {destination} ({gap_seconds:.2f}s) "
                f"below minimum threshold ({self.min_gap_seconds}s)"
            )
            return None
        
        # Cap at maximum
        if gap_seconds > self.max_gap_seconds:
            logger.warning(
                f"Gap for {destination} ({gap_seconds:.1f}s) exceeds maximum "
                f"({self.max_gap_seconds}s) - capping replay window"
            )
            # Adjust start to cap the gap
            gap_start = current_time - self.max_gap_seconds
            gap_seconds = self.max_gap_seconds
        else:
            # Add buffer to start (go back slightly further)
            gap_start = last_forwarded - self.buffer_seconds
        
        # Get additional info
        info = self._tracker.get_forwarding_info(destination)
        last_node = info.get('node_id') if info else None
        
        # Estimate trap count if cache available
        estimated_traps = 0
        if self._cache:
            try:
                from datetime import datetime
                start_dt = datetime.fromtimestamp(gap_start)
                end_dt = datetime.fromtimestamp(current_time)
                estimated_traps = self._cache.count_range(destination, start_dt, end_dt)
            except Exception as e:
                logger.debug(f"Failed to estimate trap count: {e}")
        
        return GapInfo(
            destination=destination,
            gap_start=gap_start,
            gap_end=current_time,
            gap_seconds=gap_seconds,
            last_node=last_node,
            estimated_traps=estimated_traps,
        )
    
    def detect_gap_for_destination(self,
                                   destination: str,
                                   failover_time: Optional[float] = None) -> Optional[GapInfo]:
        """
        Detect gap for a specific destination.
        
        Args:
            destination: Destination to check
            failover_time: Time when failover completed
            
        Returns:
            GapInfo if gap detected, None otherwise
        """
        now = failover_time or time.time()
        last_ts = self._tracker.get_last_forwarded(destination)
        
        if last_ts is None:
            logger.debug(f"No forwarding timestamp for {destination}")
            return None
        
        return self._analyze_gap(destination, last_ts, now)
    
    def get_global_gap(self, failover_time: Optional[float] = None) -> Optional[GapInfo]:
        """
        Get the overall gap across all destinations.
        
        Uses the oldest last_forwarded timestamp to determine the gap.
        Useful for a single replay operation covering all destinations.
        
        Args:
            failover_time: Time when failover completed
            
        Returns:
            GapInfo representing global gap, or None
        """
        now = failover_time or time.time()
        timestamps = self._tracker.get_all_last_forwarded()
        
        if not timestamps:
            return None
        
        # Find oldest timestamp (most conservative gap start)
        oldest_dest = min(timestamps.items(), key=lambda x: x[1])
        oldest_ts = oldest_dest[1]
        
        gap_seconds = now - oldest_ts
        
        if gap_seconds < self.min_gap_seconds:
            return None
        
        if gap_seconds > self.max_gap_seconds:
            gap_start = now - self.max_gap_seconds
            gap_seconds = self.max_gap_seconds
        else:
            gap_start = oldest_ts - self.buffer_seconds
        
        # Sum estimated traps across all destinations
        total_estimated = 0
        if self._cache:
            try:
                start_dt = datetime.fromtimestamp(gap_start)
                end_dt = datetime.fromtimestamp(now)
                for dest in timestamps.keys():
                    total_estimated += self._cache.count_range(dest, start_dt, end_dt)
            except Exception:
                pass
        
        return GapInfo(
            destination="*",  # All destinations
            gap_start=gap_start,
            gap_end=now,
            gap_seconds=gap_seconds,
            last_node=oldest_dest[0],
            estimated_traps=total_estimated,
        )
    
    def estimate_replay_time(self, 
                            gaps: List[GapInfo],
                            rate_limit: int = 1000) -> float:
        """
        Estimate time required to replay detected gaps.
        
        Args:
            gaps: List of detected gaps
            rate_limit: Replay rate in traps/second
            
        Returns:
            Estimated seconds for replay
        """
        total_traps = sum(gap.estimated_traps for gap in gaps)
        
        if rate_limit <= 0:
            return 0.0
        
        return total_traps / rate_limit
