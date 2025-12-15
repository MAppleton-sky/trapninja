#!/usr/bin/env python3
"""
TrapNinja Statistics Data Models

Data classes for granular statistics tracking.

Author: TrapNinja Team
Version: 1.0.0
"""

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Set
from collections import Counter, deque
from datetime import datetime, timedelta
from enum import Enum


class TimeWindow(Enum):
    """Time windows for statistics aggregation."""
    MINUTE = 60
    FIVE_MINUTES = 300
    HOUR = 3600
    DAY = 86400
    WEEK = 604800


@dataclass
class RateTracker:
    """
    Tracks event rates using a sliding window.
    
    Uses a deque of timestamps to calculate rates efficiently.
    Memory-bounded by max_samples.
    """
    window_seconds: int = 60
    max_samples: int = 10000
    _timestamps: deque = field(default_factory=lambda: deque(maxlen=10000))
    
    def __post_init__(self):
        self._timestamps = deque(maxlen=self.max_samples)
    
    def record(self, timestamp: float = None):
        """Record an event."""
        if timestamp is None:
            timestamp = time.time()
        self._timestamps.append(timestamp)
    
    def get_rate(self, window_seconds: int = None) -> float:
        """
        Get events per second over the window.
        
        Args:
            window_seconds: Window size (default: self.window_seconds)
            
        Returns:
            Events per second
        """
        if window_seconds is None:
            window_seconds = self.window_seconds
        
        if not self._timestamps:
            return 0.0
        
        cutoff = time.time() - window_seconds
        count = sum(1 for ts in self._timestamps if ts >= cutoff)
        
        return count / window_seconds if window_seconds > 0 else 0.0
    
    def get_count(self, window_seconds: int = None) -> int:
        """Get event count in window."""
        if window_seconds is None:
            window_seconds = self.window_seconds
        
        if not self._timestamps:
            return 0
        
        cutoff = time.time() - window_seconds
        return sum(1 for ts in self._timestamps if ts >= cutoff)
    
    def cleanup(self, max_age: int = None):
        """Remove old timestamps beyond max_age."""
        if max_age is None:
            max_age = self.window_seconds * 2
        
        cutoff = time.time() - max_age
        while self._timestamps and self._timestamps[0] < cutoff:
            self._timestamps.popleft()


@dataclass
class IPStats:
    """
    Statistics for a single source IP address.
    
    Tracks:
    - Total trap count
    - Forwarded/blocked/redirected counts
    - First and last seen timestamps
    - Rate tracking
    - Top OIDs from this IP
    - Action breakdown (what happened to traps)
    """
    ip_address: str
    
    # Counters
    total_traps: int = 0
    forwarded: int = 0
    blocked: int = 0
    redirected: int = 0
    dropped: int = 0
    
    # Timestamps
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    
    # Rate tracking (1-minute window)
    _rate_tracker: RateTracker = field(default_factory=lambda: RateTracker(window_seconds=60))
    
    # Top OIDs from this IP (OID -> count)
    oid_counts: Counter = field(default_factory=Counter)
    
    # Destination breakdown (destination -> count)
    destination_counts: Counter = field(default_factory=Counter)
    
    def record_trap(self, oid: str = None, action: str = 'forwarded', 
                    destination: str = None):
        """
        Record a trap from this IP.
        
        Args:
            oid: Trap OID (if extracted)
            action: What happened ('forwarded', 'blocked', 'redirected', 'dropped')
            destination: Where it was sent
        """
        now = time.time()
        
        self.total_traps += 1
        self.last_seen = now
        self._rate_tracker.record(now)
        
        # Update action counter
        if action == 'forwarded':
            self.forwarded += 1
        elif action == 'blocked':
            self.blocked += 1
        elif action == 'redirected':
            self.redirected += 1
        elif action == 'dropped':
            self.dropped += 1
        
        # Track OID if provided
        if oid:
            self.oid_counts[oid] += 1
        
        # Track destination if provided
        if destination:
            self.destination_counts[destination] += 1
    
    @property
    def rate_per_second(self) -> float:
        """Current rate (traps/second over last minute)."""
        return self._rate_tracker.get_rate(60)
    
    @property
    def rate_per_minute(self) -> float:
        """Current rate (traps/minute)."""
        return self._rate_tracker.get_count(60)
    
    @property
    def age_seconds(self) -> float:
        """Seconds since first seen."""
        return time.time() - self.first_seen
    
    @property
    def idle_seconds(self) -> float:
        """Seconds since last seen."""
        return time.time() - self.last_seen
    
    def get_top_oids(self, n: int = 10) -> List[tuple]:
        """Get top N OIDs by count."""
        return self.oid_counts.most_common(n)
    
    def to_dict(self, include_details: bool = True) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result = {
            'ip_address': self.ip_address,
            'total_traps': self.total_traps,
            'forwarded': self.forwarded,
            'blocked': self.blocked,
            'redirected': self.redirected,
            'dropped': self.dropped,
            'first_seen': datetime.fromtimestamp(self.first_seen).isoformat(),
            'last_seen': datetime.fromtimestamp(self.last_seen).isoformat(),
            'rate_per_minute': round(self.rate_per_minute, 2),
            'rate_per_second': round(self.rate_per_second, 4),
            'age_seconds': round(self.age_seconds, 1),
            'idle_seconds': round(self.idle_seconds, 1),
        }
        
        if include_details:
            result['top_oids'] = [
                {'oid': oid, 'count': count} 
                for oid, count in self.get_top_oids(10)
            ]
            result['unique_oids'] = len(self.oid_counts)
            result['destinations'] = dict(self.destination_counts)
        
        return result


@dataclass
class OIDStats:
    """
    Statistics for a single trap OID.
    
    Tracks:
    - Total trap count
    - Action breakdown
    - First and last seen timestamps
    - Rate tracking
    - Top source IPs for this OID
    """
    oid: str
    
    # Counters
    total_traps: int = 0
    forwarded: int = 0
    blocked: int = 0
    redirected: int = 0
    dropped: int = 0
    
    # Timestamps
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    
    # Rate tracking
    _rate_tracker: RateTracker = field(default_factory=lambda: RateTracker(window_seconds=60))
    
    # Top source IPs (IP -> count)
    ip_counts: Counter = field(default_factory=Counter)
    
    # Destination breakdown
    destination_counts: Counter = field(default_factory=Counter)
    
    def record_trap(self, source_ip: str, action: str = 'forwarded',
                    destination: str = None):
        """
        Record a trap with this OID.
        
        Args:
            source_ip: Source IP address
            action: What happened
            destination: Where it was sent
        """
        now = time.time()
        
        self.total_traps += 1
        self.last_seen = now
        self._rate_tracker.record(now)
        
        # Update action counter
        if action == 'forwarded':
            self.forwarded += 1
        elif action == 'blocked':
            self.blocked += 1
        elif action == 'redirected':
            self.redirected += 1
        elif action == 'dropped':
            self.dropped += 1
        
        # Track source IP
        self.ip_counts[source_ip] += 1
        
        # Track destination
        if destination:
            self.destination_counts[destination] += 1
    
    @property
    def rate_per_second(self) -> float:
        """Current rate (traps/second)."""
        return self._rate_tracker.get_rate(60)
    
    @property
    def rate_per_minute(self) -> float:
        """Current rate (traps/minute)."""
        return self._rate_tracker.get_count(60)
    
    @property
    def age_seconds(self) -> float:
        """Seconds since first seen."""
        return time.time() - self.first_seen
    
    @property
    def idle_seconds(self) -> float:
        """Seconds since last seen."""
        return time.time() - self.last_seen
    
    def get_top_ips(self, n: int = 10) -> List[tuple]:
        """Get top N source IPs by count."""
        return self.ip_counts.most_common(n)
    
    def to_dict(self, include_details: bool = True) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result = {
            'oid': self.oid,
            'total_traps': self.total_traps,
            'forwarded': self.forwarded,
            'blocked': self.blocked,
            'redirected': self.redirected,
            'dropped': self.dropped,
            'first_seen': datetime.fromtimestamp(self.first_seen).isoformat(),
            'last_seen': datetime.fromtimestamp(self.last_seen).isoformat(),
            'rate_per_minute': round(self.rate_per_minute, 2),
            'rate_per_second': round(self.rate_per_second, 4),
            'age_seconds': round(self.age_seconds, 1),
            'idle_seconds': round(self.idle_seconds, 1),
        }
        
        if include_details:
            result['top_source_ips'] = [
                {'ip': ip, 'count': count}
                for ip, count in self.get_top_ips(10)
            ]
            result['unique_sources'] = len(self.ip_counts)
            result['destinations'] = dict(self.destination_counts)
        
        return result


@dataclass
class DestinationStats:
    """
    Statistics for a forwarding destination.
    
    Tracks:
    - Forward count
    - Success/failure rates
    - Latency (if tracked)
    - Source breakdown
    """
    destination: str  # "ip:port" or tag name
    
    # Counters
    total_forwarded: int = 0
    successful: int = 0
    failed: int = 0
    
    # Timestamps
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    
    # Rate tracking
    _rate_tracker: RateTracker = field(default_factory=lambda: RateTracker(window_seconds=60))
    
    # Source IP breakdown
    source_ip_counts: Counter = field(default_factory=Counter)
    
    # OID breakdown
    oid_counts: Counter = field(default_factory=Counter)
    
    def record_forward(self, source_ip: str, oid: str = None, 
                       success: bool = True):
        """Record a forward to this destination."""
        now = time.time()
        
        self.total_forwarded += 1
        self.last_seen = now
        self._rate_tracker.record(now)
        
        if success:
            self.successful += 1
        else:
            self.failed += 1
        
        self.source_ip_counts[source_ip] += 1
        
        if oid:
            self.oid_counts[oid] += 1
    
    @property
    def rate_per_minute(self) -> float:
        """Current rate (forwards/minute)."""
        return self._rate_tracker.get_count(60)
    
    @property
    def success_rate(self) -> float:
        """Success percentage."""
        if self.total_forwarded == 0:
            return 100.0
        return (self.successful / self.total_forwarded) * 100
    
    def to_dict(self, include_details: bool = True) -> Dict[str, Any]:
        """Convert to dictionary."""
        result = {
            'destination': self.destination,
            'total_forwarded': self.total_forwarded,
            'successful': self.successful,
            'failed': self.failed,
            'success_rate': round(self.success_rate, 2),
            'first_seen': datetime.fromtimestamp(self.first_seen).isoformat(),
            'last_seen': datetime.fromtimestamp(self.last_seen).isoformat(),
            'rate_per_minute': round(self.rate_per_minute, 2),
        }
        
        if include_details:
            result['top_sources'] = [
                {'ip': ip, 'count': count}
                for ip, count in self.source_ip_counts.most_common(10)
            ]
            result['top_oids'] = [
                {'oid': oid, 'count': count}
                for oid, count in self.oid_counts.most_common(10)
            ]
        
        return result


@dataclass
class StatsSnapshot:
    """
    Point-in-time snapshot of all statistics.
    
    Used for periodic exports and API responses.
    """
    timestamp: float = field(default_factory=time.time)
    
    # Summary counters
    total_traps: int = 0
    total_forwarded: int = 0
    total_blocked: int = 0
    total_redirected: int = 0
    total_dropped: int = 0
    
    # Counts
    unique_ips: int = 0
    unique_oids: int = 0
    unique_destinations: int = 0
    
    # Rates
    overall_rate_per_minute: float = 0.0
    
    # Top entities
    top_ips: List[Dict] = field(default_factory=list)
    top_oids: List[Dict] = field(default_factory=list)
    top_destinations: List[Dict] = field(default_factory=list)
    
    # Time range
    oldest_data: float = 0.0
    newest_data: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'timestamp': datetime.fromtimestamp(self.timestamp).isoformat(),
            'summary': {
                'total_traps': self.total_traps,
                'total_forwarded': self.total_forwarded,
                'total_blocked': self.total_blocked,
                'total_redirected': self.total_redirected,
                'total_dropped': self.total_dropped,
                'unique_ips': self.unique_ips,
                'unique_oids': self.unique_oids,
                'unique_destinations': self.unique_destinations,
                'overall_rate_per_minute': round(self.overall_rate_per_minute, 2),
            },
            'top_ips': self.top_ips,
            'top_oids': self.top_oids,
            'top_destinations': self.top_destinations,
            'time_range': {
                'oldest': datetime.fromtimestamp(self.oldest_data).isoformat() if self.oldest_data else None,
                'newest': datetime.fromtimestamp(self.newest_data).isoformat() if self.newest_data else None,
            }
        }
