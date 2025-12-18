#!/usr/bin/env python3
"""
TrapNinja Granular Statistics Collector

High-performance, thread-safe statistics collection for per-IP and per-OID tracking.

Features:
- Lock-free design where possible (using Python's GIL)
- Memory-bounded with LRU eviction
- Background cleanup of stale entries
- Efficient batch updates
- Optional Redis persistence

Author: TrapNinja Team
Version: 1.0.0
"""

import time
import threading
import logging
from collections import OrderedDict
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field

from .models import IPStats, OIDStats, DestinationStats, StatsSnapshot, RateTracker

logger = logging.getLogger("trapninja")


@dataclass
class CollectorConfig:
    """Configuration for the statistics collector."""
    
    # Maximum entries to track (LRU eviction when exceeded)
    max_ips: int = 10000
    max_oids: int = 5000
    max_destinations: int = 100
    
    # Cleanup settings
    cleanup_interval: int = 300  # Cleanup every 5 minutes
    stale_threshold: int = 3600  # Consider entry stale after 1 hour idle
    
    # Rate tracking window
    rate_window: int = 60  # 1 minute window for rate calculations
    
    # Persistence settings
    persist_to_redis: bool = False
    redis_key_prefix: str = "trapninja:stats:"
    persist_interval: int = 60  # Persist every minute
    
    # Export settings
    export_interval: int = 60  # Export metrics every minute
    metrics_dir: str = "/var/log/trapninja/metrics"


class LRUDict(OrderedDict):
    """
    OrderedDict with LRU eviction and max size.
    
    Thread-safe for basic operations due to GIL, but use
    with external lock for compound operations.
    """
    
    def __init__(self, max_size: int = 10000, *args, **kwargs):
        self.max_size = max_size
        super().__init__(*args, **kwargs)
    
    def __setitem__(self, key, value):
        if key in self:
            self.move_to_end(key)
        super().__setitem__(key, value)
        
        # Evict oldest if over limit
        while len(self) > self.max_size:
            oldest = next(iter(self))
            del self[oldest]
    
    def get_or_create(self, key, factory):
        """Get existing item or create new one."""
        if key in self:
            self.move_to_end(key)
            return self[key]
        
        value = factory()
        self[key] = value
        return value


class GranularStatsCollector:
    """
    High-performance granular statistics collector.
    
    Collects per-IP, per-OID, and per-destination statistics
    with efficient memory management and thread safety.
    
    Usage:
        collector = GranularStatsCollector()
        collector.start()
        
        # Record a trap
        collector.record_trap(
            source_ip="10.0.0.1",
            oid="1.3.6.1.4.1.9.9.41.2.0.1",
            action="forwarded",
            destination="default"
        )
        
        # Query stats
        top_ips = collector.get_top_ips(10)
        ip_detail = collector.get_ip_stats("10.0.0.1")
    """
    
    def __init__(self, config: CollectorConfig = None):
        """
        Initialize the collector.
        
        Args:
            config: Configuration settings (uses defaults if None)
        """
        self.config = config or CollectorConfig()
        
        # Statistics storage with LRU eviction
        self._ip_stats: LRUDict = LRUDict(max_size=self.config.max_ips)
        self._oid_stats: LRUDict = LRUDict(max_size=self.config.max_oids)
        self._dest_stats: LRUDict = LRUDict(max_size=self.config.max_destinations)
        
        # Global rate tracker
        self._global_rate = RateTracker(window_seconds=self.config.rate_window)
        
        # Totals (for quick access without iterating)
        self._total_traps = 0
        self._total_forwarded = 0
        self._total_blocked = 0
        self._total_redirected = 0
        self._total_dropped = 0
        
        # Threading
        self._lock = threading.RLock()
        self._cleanup_timer: Optional[threading.Timer] = None
        self._export_timer: Optional[threading.Timer] = None
        self._running = False
        
        # Start time
        self._start_time = time.time()
        
        logger.info(f"GranularStatsCollector initialized: max_ips={self.config.max_ips}, "
                   f"max_oids={self.config.max_oids}")
    
    def start(self):
        """Start background threads for cleanup and export."""
        self._running = True
        self._schedule_cleanup()
        self._schedule_export()
        # Initial export so files exist immediately
        self._export_stats()
        logger.info("GranularStatsCollector started")
    
    def stop(self):
        """Stop background threads."""
        self._running = False
        
        if self._cleanup_timer:
            self._cleanup_timer.cancel()
            self._cleanup_timer = None
        
        if self._export_timer:
            self._export_timer.cancel()
            self._export_timer = None
        
        # Final export
        self._export_stats()
        
        logger.info("GranularStatsCollector stopped")
    
    # =========================================================================
    # RECORDING METHODS (Hot path - optimized for speed)
    # =========================================================================
    
    def record_trap(self, source_ip: str, oid: str = None, 
                    action: str = 'forwarded', destination: str = None):
        """
        Record a trap event.
        
        This is the main entry point called from packet processing.
        Optimized for minimal overhead.
        
        Args:
            source_ip: Source IP address
            oid: Trap OID (None if not extracted)
            action: 'forwarded', 'blocked', 'redirected', 'dropped'
            destination: Destination tag or "ip:port"
        """
        now = time.time()
        
        # Update totals (atomic due to GIL)
        self._total_traps += 1
        if action == 'forwarded':
            self._total_forwarded += 1
        elif action == 'blocked':
            self._total_blocked += 1
        elif action == 'redirected':
            self._total_redirected += 1
        elif action == 'dropped':
            self._total_dropped += 1
        
        # Global rate
        self._global_rate.record(now)
        
        # Update IP stats
        ip_stat = self._ip_stats.get_or_create(
            source_ip, 
            lambda: IPStats(ip_address=source_ip)
        )
        ip_stat.record_trap(oid=oid, action=action, destination=destination)
        
        # Update OID stats (only if OID provided)
        if oid:
            oid_stat = self._oid_stats.get_or_create(
                oid,
                lambda: OIDStats(oid=oid)
            )
            oid_stat.record_trap(source_ip=source_ip, action=action, 
                                destination=destination)
        
        # Update destination stats (only for forwarded/redirected)
        if destination and action in ('forwarded', 'redirected'):
            dest_stat = self._dest_stats.get_or_create(
                destination,
                lambda: DestinationStats(destination=destination)
            )
            dest_stat.record_forward(source_ip=source_ip, oid=oid, success=True)
    
    def record_forward_failure(self, destination: str, source_ip: str, 
                               oid: str = None):
        """Record a failed forward attempt."""
        dest_stat = self._dest_stats.get_or_create(
            destination,
            lambda: DestinationStats(destination=destination)
        )
        dest_stat.record_forward(source_ip=source_ip, oid=oid, success=False)
    
    # =========================================================================
    # QUERY METHODS
    # =========================================================================
    
    def get_ip_stats(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """
        Get detailed statistics for a specific IP.
        
        Args:
            ip_address: IP to look up
            
        Returns:
            Dictionary with IP stats or None if not found
        """
        if ip_address in self._ip_stats:
            return self._ip_stats[ip_address].to_dict(include_details=True)
        return None
    
    def get_oid_stats(self, oid: str) -> Optional[Dict[str, Any]]:
        """
        Get detailed statistics for a specific OID.
        
        Args:
            oid: OID to look up
            
        Returns:
            Dictionary with OID stats or None if not found
        """
        if oid in self._oid_stats:
            return self._oid_stats[oid].to_dict(include_details=True)
        return None
    
    def get_destination_stats(self, destination: str) -> Optional[Dict[str, Any]]:
        """Get detailed statistics for a specific destination."""
        if destination in self._dest_stats:
            return self._dest_stats[destination].to_dict(include_details=True)
        return None
    
    def get_top_ips(self, n: int = 10, 
                    sort_by: str = 'total') -> List[Dict[str, Any]]:
        """
        Get top N IPs by trap count or rate.
        
        Args:
            n: Number of IPs to return
            sort_by: 'total', 'rate', 'blocked', 'recent'
            
        Returns:
            List of IP stats dictionaries
        """
        # Snapshot under lock to avoid mutation during iteration
        with self._lock:
            ip_list = list(self._ip_stats.values())
        
        if sort_by == 'total':
            ip_list.sort(key=lambda x: x.total_traps, reverse=True)
        elif sort_by == 'rate':
            ip_list.sort(key=lambda x: x.rate_per_minute, reverse=True)
        elif sort_by == 'blocked':
            ip_list.sort(key=lambda x: x.blocked, reverse=True)
        elif sort_by == 'recent':
            ip_list.sort(key=lambda x: x.last_seen, reverse=True)
        
        return [ip.to_dict(include_details=False) for ip in ip_list[:n]]
    
    def get_top_oids(self, n: int = 10, 
                     sort_by: str = 'total') -> List[Dict[str, Any]]:
        """
        Get top N OIDs by trap count or rate.
        
        Args:
            n: Number of OIDs to return
            sort_by: 'total', 'rate', 'blocked', 'recent'
            
        Returns:
            List of OID stats dictionaries
        """
        # Snapshot under lock to avoid mutation during iteration
        with self._lock:
            oid_list = list(self._oid_stats.values())
        
        if sort_by == 'total':
            oid_list.sort(key=lambda x: x.total_traps, reverse=True)
        elif sort_by == 'rate':
            oid_list.sort(key=lambda x: x.rate_per_minute, reverse=True)
        elif sort_by == 'blocked':
            oid_list.sort(key=lambda x: x.blocked, reverse=True)
        elif sort_by == 'recent':
            oid_list.sort(key=lambda x: x.last_seen, reverse=True)
        
        return [oid.to_dict(include_details=False) for oid in oid_list[:n]]
    
    def get_all_destinations(self) -> List[Dict[str, Any]]:
        """Get stats for all destinations."""
        # Snapshot under lock to avoid mutation during iteration
        with self._lock:
            dest_list = list(self._dest_stats.values())
        return [d.to_dict(include_details=True) for d in dest_list]
    
    def get_snapshot(self, top_n: int = 50) -> StatsSnapshot:
        """
        Get a point-in-time snapshot of all statistics.
        
        Args:
            top_n: Number of top IPs/OIDs to include (default 50)
        
        Returns:
            StatsSnapshot with summary and top entities
        """
        snapshot = StatsSnapshot(timestamp=time.time())
        
        # Summary
        snapshot.total_traps = self._total_traps
        snapshot.total_forwarded = self._total_forwarded
        snapshot.total_blocked = self._total_blocked
        snapshot.total_redirected = self._total_redirected
        snapshot.total_dropped = self._total_dropped
        
        # Counts
        snapshot.unique_ips = len(self._ip_stats)
        snapshot.unique_oids = len(self._oid_stats)
        snapshot.unique_destinations = len(self._dest_stats)
        
        # Rate
        snapshot.overall_rate_per_minute = self._global_rate.get_count(60)
        
        # Top entities - include more for file export so CLI -n works
        snapshot.top_ips = self.get_top_ips(top_n, sort_by='total')
        snapshot.top_oids = self.get_top_oids(top_n, sort_by='total')
        snapshot.top_destinations = self.get_all_destinations()
        
        # Time range - snapshot under lock to avoid mutation during iteration
        with self._lock:
            ip_stats_list = list(self._ip_stats.values())
        
        if ip_stats_list:
            all_first_seen = [ip.first_seen for ip in ip_stats_list]
            all_last_seen = [ip.last_seen for ip in ip_stats_list]
            snapshot.oldest_data = min(all_first_seen) if all_first_seen else 0
            snapshot.newest_data = max(all_last_seen) if all_last_seen else 0
        
        return snapshot
    
    def search_ips(self, pattern: str, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Search for IPs matching a pattern.
        
        Args:
            pattern: IP prefix or pattern (e.g., "10.0.", "192.168.1")
            limit: Maximum results to return
            
        Returns:
            List of matching IP stats
        """
        # Snapshot under lock to avoid mutation during iteration
        with self._lock:
            ip_items = list(self._ip_stats.items())
        
        results = []
        for ip, stats in ip_items:
            if ip.startswith(pattern):
                results.append(stats.to_dict(include_details=False))
                if len(results) >= limit:
                    break
        return results
    
    def search_oids(self, pattern: str, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Search for OIDs matching a pattern.
        
        Args:
            pattern: OID prefix (e.g., "1.3.6.1.4.1.9")
            limit: Maximum results to return
            
        Returns:
            List of matching OID stats
        """
        # Snapshot under lock to avoid mutation during iteration
        with self._lock:
            oid_items = list(self._oid_stats.items())
        
        results = []
        for oid, stats in oid_items:
            if oid.startswith(pattern):
                results.append(stats.to_dict(include_details=False))
                if len(results) >= limit:
                    break
        return results
    
    def get_summary(self) -> Dict[str, Any]:
        """Get a quick summary for dashboards."""
        return {
            'timestamp': time.time(),
            'uptime_seconds': time.time() - self._start_time,
            'totals': {
                'traps': self._total_traps,
                'forwarded': self._total_forwarded,
                'blocked': self._total_blocked,
                'redirected': self._total_redirected,
                'dropped': self._total_dropped,
            },
            'counts': {
                'unique_ips': len(self._ip_stats),
                'unique_oids': len(self._oid_stats),
                'destinations': len(self._dest_stats),
            },
            'rates': {
                # Calculate rate from last minute, then project to other periods
                'per_second': round(self._global_rate.get_rate(60), 2),
                'per_minute': round(self._global_rate.get_rate(60) * 60, 2),
                'per_hour': round(self._global_rate.get_rate(60) * 3600, 2),
            },
            'limits': {
                'max_ips': self.config.max_ips,
                'max_oids': self.config.max_oids,
                'ip_usage': f"{len(self._ip_stats)}/{self.config.max_ips}",
                'oid_usage': f"{len(self._oid_stats)}/{self.config.max_oids}",
            }
        }
    
    # =========================================================================
    # EXPORT METHODS
    # =========================================================================
    
    def export_prometheus(self) -> str:
        """
        Export stats in Prometheus format with labels.
        
        Returns:
            Prometheus-formatted metrics string
        """
        # Snapshot all stats under lock to avoid mutation during iteration
        with self._lock:
            ip_stats_list = list(self._ip_stats.values())
            oid_stats_list = list(self._oid_stats.values())
            dest_stats_list = list(self._dest_stats.values())
            unique_ips = len(self._ip_stats)
            unique_oids = len(self._oid_stats)
        
        lines = []
        
        # Header
        lines.append("# TrapNinja Granular Statistics")
        lines.append(f"# Timestamp: {time.time()}")
        lines.append("")
        
        # Per-IP metrics (top 50 by volume)
        lines.append("# HELP trapninja_ip_traps_total Total traps from IP")
        lines.append("# TYPE trapninja_ip_traps_total counter")
        for ip_stat in sorted(ip_stats_list, 
                              key=lambda x: x.total_traps, reverse=True)[:50]:
            lines.append(f'trapninja_ip_traps_total{{ip="{ip_stat.ip_address}"}} {ip_stat.total_traps}')
        
        lines.append("")
        lines.append("# HELP trapninja_ip_rate_per_minute Current trap rate from IP")
        lines.append("# TYPE trapninja_ip_rate_per_minute gauge")
        for ip_stat in sorted(ip_stats_list,
                              key=lambda x: x.rate_per_minute, reverse=True)[:50]:
            if ip_stat.rate_per_minute > 0:
                lines.append(f'trapninja_ip_rate_per_minute{{ip="{ip_stat.ip_address}"}} {ip_stat.rate_per_minute:.2f}')
        
        # Per-OID metrics (top 50 by volume)
        lines.append("")
        lines.append("# HELP trapninja_oid_traps_total Total traps with OID")
        lines.append("# TYPE trapninja_oid_traps_total counter")
        for oid_stat in sorted(oid_stats_list,
                               key=lambda x: x.total_traps, reverse=True)[:50]:
            lines.append(f'trapninja_oid_traps_total{{oid="{oid_stat.oid}"}} {oid_stat.total_traps}')
        
        lines.append("")
        lines.append("# HELP trapninja_oid_rate_per_minute Current trap rate for OID")
        lines.append("# TYPE trapninja_oid_rate_per_minute gauge")
        for oid_stat in sorted(oid_stats_list,
                               key=lambda x: x.rate_per_minute, reverse=True)[:50]:
            if oid_stat.rate_per_minute > 0:
                lines.append(f'trapninja_oid_rate_per_minute{{oid="{oid_stat.oid}"}} {oid_stat.rate_per_minute:.2f}')
        
        # Per-destination metrics
        lines.append("")
        lines.append("# HELP trapninja_dest_forwards_total Total forwards to destination")
        lines.append("# TYPE trapninja_dest_forwards_total counter")
        for dest_stat in dest_stats_list:
            lines.append(f'trapninja_dest_forwards_total{{destination="{dest_stat.destination}"}} {dest_stat.total_forwarded}')
        
        # Global summary
        lines.append("")
        lines.append(f"trapninja_granular_unique_ips {unique_ips}")
        lines.append(f"trapninja_granular_unique_oids {unique_oids}")
        
        return "\n".join(lines)
    
    def export_json(self) -> Dict[str, Any]:
        """Export full stats as JSON."""
        return self.get_snapshot().to_dict()
    
    # =========================================================================
    # BACKGROUND TASKS
    # =========================================================================
    
    def _schedule_cleanup(self):
        """Schedule next cleanup."""
        if not self._running:
            return
        
        self._cleanup_timer = threading.Timer(
            self.config.cleanup_interval,
            self._cleanup_and_reschedule
        )
        self._cleanup_timer.daemon = True
        self._cleanup_timer.start()
    
    def _cleanup_and_reschedule(self):
        """Run cleanup and schedule next."""
        if not self._running:
            return
        
        self._cleanup_stale()
        self._schedule_cleanup()
    
    def _cleanup_stale(self):
        """Remove stale entries that haven't been seen recently."""
        cutoff = time.time() - self.config.stale_threshold
        
        # Identify stale entries under lock, then delete
        with self._lock:
            # Cleanup IPs
            stale_ips = [
                ip for ip, stats in self._ip_stats.items()
                if stats.last_seen < cutoff
            ]
            for ip in stale_ips:
                del self._ip_stats[ip]
            
            # Cleanup OIDs
            stale_oids = [
                oid for oid, stats in self._oid_stats.items()
                if stats.last_seen < cutoff
            ]
            for oid in stale_oids:
                del self._oid_stats[oid]
        
        if stale_ips or stale_oids:
            logger.debug(f"Cleanup: removed {len(stale_ips)} stale IPs, "
                        f"{len(stale_oids)} stale OIDs")
    
    def _schedule_export(self):
        """Schedule next export."""
        if not self._running:
            return
        
        self._export_timer = threading.Timer(
            self.config.export_interval,
            self._export_and_reschedule
        )
        self._export_timer.daemon = True
        self._export_timer.start()
    
    def _export_and_reschedule(self):
        """Run export and schedule next."""
        if not self._running:
            return
        
        self._export_stats()
        self._schedule_export()
    
    def _export_stats(self):
        """Export statistics to files."""
        import os
        import json
        
        try:
            # Ensure directory exists
            os.makedirs(self.config.metrics_dir, exist_ok=True)
            
            # Export Prometheus format
            prom_path = os.path.join(
                self.config.metrics_dir, 
                "trapninja_granular.prom"
            )
            with open(prom_path, 'w') as f:
                f.write(self.export_prometheus())
            
            # Export JSON format
            json_path = os.path.join(
                self.config.metrics_dir,
                "trapninja_granular.json"
            )
            with open(json_path, 'w') as f:
                json.dump(self.export_json(), f, indent=2)
            
            logger.debug(f"Exported granular stats to {self.config.metrics_dir}")
            
        except Exception as e:
            logger.error(f"Failed to export granular stats: {e}")
    
    def reset(self):
        """Reset all statistics."""
        with self._lock:
            self._ip_stats.clear()
            self._oid_stats.clear()
            self._dest_stats.clear()
            self._total_traps = 0
            self._total_forwarded = 0
            self._total_blocked = 0
            self._total_redirected = 0
            self._total_dropped = 0
            self._global_rate = RateTracker(window_seconds=self.config.rate_window)
            self._start_time = time.time()
        
        logger.info("Granular statistics reset")


# =============================================================================
# GLOBAL INSTANCE MANAGEMENT
# =============================================================================

_collector: Optional[GranularStatsCollector] = None
_collector_lock = threading.Lock()


def get_stats_collector() -> Optional[GranularStatsCollector]:
    """Get the global stats collector instance."""
    return _collector


def initialize_stats(config: CollectorConfig = None) -> GranularStatsCollector:
    """
    Initialize and start the global stats collector.
    
    Args:
        config: Optional configuration (uses defaults if None)
        
    Returns:
        GranularStatsCollector instance
    """
    global _collector
    
    with _collector_lock:
        if _collector is None:
            _collector = GranularStatsCollector(config)
            _collector.start()
        return _collector


def shutdown_stats():
    """Shutdown the global stats collector."""
    global _collector
    
    with _collector_lock:
        if _collector:
            _collector.stop()
            _collector = None
