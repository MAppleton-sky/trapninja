#!/usr/bin/env python3
"""
TrapNinja Shadow Mode Module

Provides "shadow mode" functionality for running TrapNinja alongside an existing
SNMP trap receiver for testing and comparison purposes.

Shadow mode:
- Uses libpcap capture (sniff mode) - does NOT bind to UDP ports
- Can run in parallel with existing trap receivers
- Optionally disables forwarding (observe-only mode)
- Collects full statistics for comparison testing
- Can log all received traps for validation

Use cases:
1. Testing TrapNinja before production deployment
2. Validating trap routing decisions
3. Comparing performance with existing solutions
4. Auditing trap flow without affecting production

Example:
    # Run in shadow mode (observe only, no forwarding)
    python trapninja.py --foreground --shadow-mode
    
    # Run in mirror mode (parallel forwarding for comparison)
    python trapninja.py --foreground --mirror-mode
"""

import os
import json
import time
import logging
from threading import Lock
from typing import Dict, Any, Optional
from collections import defaultdict
from dataclasses import dataclass, field

logger = logging.getLogger("trapninja")


@dataclass
class ShadowConfig:
    """Shadow mode configuration"""
    
    # Core shadow mode settings
    enabled: bool = False              # Enable shadow mode
    observe_only: bool = True          # Don't forward, just observe
    log_all_traps: bool = False        # Log every trap (verbose)
    log_file: Optional[str] = None     # File to log observed traps
    
    # Statistics collection
    collect_detailed_stats: bool = True
    stats_export_interval: int = 60    # Export stats every N seconds
    
    # Comparison mode settings
    compare_with_production: bool = False  # Track what production sees
    production_host: Optional[str] = None  # Host to query for comparison
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ShadowConfig':
        """Create config from dictionary"""
        return cls(
            enabled=data.get('enabled', False),
            observe_only=data.get('observe_only', True),
            log_all_traps=data.get('log_all_traps', False),
            log_file=data.get('log_file'),
            collect_detailed_stats=data.get('collect_detailed_stats', True),
            stats_export_interval=data.get('stats_export_interval', 60),
            compare_with_production=data.get('compare_with_production', False),
            production_host=data.get('production_host'),
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Export to dictionary"""
        return {
            'enabled': self.enabled,
            'observe_only': self.observe_only,
            'log_all_traps': self.log_all_traps,
            'log_file': self.log_file,
            'collect_detailed_stats': self.collect_detailed_stats,
            'stats_export_interval': self.stats_export_interval,
            'compare_with_production': self.compare_with_production,
            'production_host': self.production_host,
        }


@dataclass 
class CaptureConfig:
    """Capture mode configuration"""
    
    # Capture mode: "auto", "sniff", "socket", "ebpf"
    # - "auto": Try eBPF, fall back to sniff
    # - "sniff": Use Scapy sniff() with libpcap (can run alongside other receivers)
    # - "socket": Use UDP socket bind (requires exclusive port access)
    # - "ebpf": Use eBPF if available (can run alongside other receivers)
    mode: str = "auto"
    
    # Force sniff mode for parallel operation
    # This overrides mode to "sniff" and prevents socket binding
    allow_parallel: bool = False
    
    # Advanced tuning
    buffer_size_mb: int = 64       # Socket/capture buffer size
    batch_size: int = 100          # Packets to process in batch
    worker_count: int = 0          # 0 = auto-detect based on CPU
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'CaptureConfig':
        """Create config from dictionary"""
        return cls(
            mode=data.get('mode', 'auto'),
            allow_parallel=data.get('allow_parallel', False),
            buffer_size_mb=data.get('buffer_size_mb', 64),
            batch_size=data.get('batch_size', 100),
            worker_count=data.get('worker_count', 0),
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Export to dictionary"""
        return {
            'mode': self.mode,
            'allow_parallel': self.allow_parallel,
            'buffer_size_mb': self.buffer_size_mb,
            'batch_size': self.batch_size,
            'worker_count': self.worker_count,
        }
    
    def get_effective_mode(self) -> str:
        """Get effective capture mode considering parallel setting"""
        if self.allow_parallel:
            return "sniff"  # Force sniff mode for parallel operation
        return self.mode


class ShadowModeStats:
    """
    Statistics collector for shadow mode.
    
    Tracks detailed metrics for comparison with production systems.
    """
    
    def __init__(self):
        self._lock = Lock()
        self._start_time = time.time()
        
        # Counters
        self.total_observed = 0
        self.total_forwarded = 0
        self.total_blocked = 0
        self.total_redirected = 0
        
        # Per-source statistics
        self.source_counts: Dict[str, int] = defaultdict(int)
        self.source_last_seen: Dict[str, float] = {}
        
        # Per-OID statistics  
        self.oid_counts: Dict[str, int] = defaultdict(int)
        self.oid_last_seen: Dict[str, float] = {}
        
        # Per-destination statistics
        self.dest_counts: Dict[str, int] = defaultdict(int)
        
        # Time-series data (for rate calculation)
        self._rate_buckets: Dict[int, int] = defaultdict(int)
        self._bucket_size = 1  # 1-second buckets
    
    def record_trap(self, source_ip: str, trap_oid: str, 
                   destinations: list = None, 
                   blocked: bool = False,
                   redirected: bool = False):
        """Record an observed trap"""
        now = time.time()
        bucket = int(now) // self._bucket_size
        
        with self._lock:
            self.total_observed += 1
            
            # Source tracking
            self.source_counts[source_ip] += 1
            self.source_last_seen[source_ip] = now
            
            # OID tracking
            if trap_oid:
                self.oid_counts[trap_oid] += 1
                self.oid_last_seen[trap_oid] = now
            
            # Destination tracking
            if destinations:
                for dest_ip, dest_port in destinations:
                    key = f"{dest_ip}:{dest_port}"
                    self.dest_counts[key] += 1
            
            # Status tracking
            if blocked:
                self.total_blocked += 1
            elif redirected:
                self.total_redirected += 1
            else:
                self.total_forwarded += 1
            
            # Rate tracking
            self._rate_buckets[bucket] += 1
    
    def get_current_rate(self, window: int = 60) -> float:
        """Calculate current trap rate over window (default 60 seconds)"""
        now = int(time.time())
        current_bucket = now // self._bucket_size
        
        total = 0
        with self._lock:
            for i in range(window):
                bucket = current_bucket - i
                total += self._rate_buckets.get(bucket, 0)
        
        return total / window
    
    def get_summary(self) -> Dict[str, Any]:
        """Get statistics summary"""
        uptime = time.time() - self._start_time
        
        with self._lock:
            return {
                'uptime_seconds': uptime,
                'total_observed': self.total_observed,
                'total_forwarded': self.total_forwarded,
                'total_blocked': self.total_blocked,
                'total_redirected': self.total_redirected,
                'unique_sources': len(self.source_counts),
                'unique_oids': len(self.oid_counts),
                'unique_destinations': len(self.dest_counts),
                'current_rate_1m': self.get_current_rate(60),
                'average_rate': self.total_observed / uptime if uptime > 0 else 0,
            }
    
    def get_top_sources(self, n: int = 10) -> list:
        """Get top N sources by volume"""
        with self._lock:
            sorted_sources = sorted(
                self.source_counts.items(),
                key=lambda x: x[1],
                reverse=True
            )
            return sorted_sources[:n]
    
    def get_top_oids(self, n: int = 10) -> list:
        """Get top N OIDs by volume"""
        with self._lock:
            sorted_oids = sorted(
                self.oid_counts.items(),
                key=lambda x: x[1],
                reverse=True
            )
            return sorted_oids[:n]
    
    def export_json(self) -> str:
        """Export full statistics as JSON"""
        with self._lock:
            data = {
                'summary': self.get_summary(),
                'top_sources': self.get_top_sources(20),
                'top_oids': self.get_top_oids(20),
                'all_sources': dict(self.source_counts),
                'all_oids': dict(self.oid_counts),
                'destinations': dict(self.dest_counts),
            }
        return json.dumps(data, indent=2)


# Global shadow mode state
_shadow_config: Optional[ShadowConfig] = None
_capture_config: Optional[CaptureConfig] = None
_shadow_stats: Optional[ShadowModeStats] = None
_trap_log_file = None


def initialize_shadow_mode(shadow_config: ShadowConfig = None,
                          capture_config: CaptureConfig = None) -> bool:
    """
    Initialize shadow mode.
    
    Args:
        shadow_config: Shadow mode configuration
        capture_config: Capture mode configuration
        
    Returns:
        True if initialized successfully
    """
    global _shadow_config, _capture_config, _shadow_stats, _trap_log_file
    
    _shadow_config = shadow_config or ShadowConfig()
    _capture_config = capture_config or CaptureConfig()
    
    if _shadow_config.enabled:
        logger.info("Shadow mode enabled")
        logger.info(f"  Observe only: {_shadow_config.observe_only}")
        logger.info(f"  Log all traps: {_shadow_config.log_all_traps}")
        
        _shadow_stats = ShadowModeStats()
        
        # Open trap log file if configured
        if _shadow_config.log_all_traps and _shadow_config.log_file:
            try:
                _trap_log_file = open(_shadow_config.log_file, 'a')
                logger.info(f"  Trap log file: {_shadow_config.log_file}")
            except Exception as e:
                logger.warning(f"Failed to open trap log file: {e}")
    
    if _capture_config.allow_parallel:
        logger.info("Parallel operation mode enabled")
        logger.info("  Using sniff capture to avoid port binding")
        logger.info("  Can run alongside existing trap receivers")
    
    return True


def shutdown_shadow_mode():
    """Clean up shadow mode resources"""
    global _trap_log_file, _shadow_stats
    
    if _trap_log_file:
        try:
            _trap_log_file.close()
        except Exception:
            pass
        _trap_log_file = None
    
    # Export final stats
    if _shadow_stats and _shadow_config and _shadow_config.enabled:
        try:
            summary = _shadow_stats.get_summary()
            logger.info("Shadow mode final statistics:")
            logger.info(f"  Total observed: {summary['total_observed']:,}")
            logger.info(f"  Would forward: {summary['total_forwarded']:,}")
            logger.info(f"  Would block: {summary['total_blocked']:,}")
            logger.info(f"  Would redirect: {summary['total_redirected']:,}")
            logger.info(f"  Unique sources: {summary['unique_sources']:,}")
            logger.info(f"  Unique OIDs: {summary['unique_oids']:,}")
        except Exception as e:
            logger.debug(f"Error exporting shadow stats: {e}")


def is_shadow_mode() -> bool:
    """Check if shadow mode is enabled"""
    return _shadow_config is not None and _shadow_config.enabled


def is_observe_only() -> bool:
    """Check if we should only observe (not forward)"""
    if _shadow_config is None:
        return False
    return _shadow_config.enabled and _shadow_config.observe_only


def should_use_sniff_mode() -> bool:
    """Check if we should use sniff mode for parallel operation"""
    if _capture_config is None:
        return False
    return _capture_config.allow_parallel or _capture_config.mode == "sniff"


def get_effective_capture_mode() -> str:
    """Get the effective capture mode to use"""
    if _capture_config is None:
        return "auto"
    return _capture_config.get_effective_mode()


def record_shadow_trap(source_ip: str, trap_oid: str,
                       destinations: list = None,
                       blocked: bool = False,
                       redirected: bool = False,
                       raw_payload: bytes = None):
    """
    Record a trap observation in shadow mode.
    
    Called by the packet processor to track what would happen
    to each trap without actually forwarding.
    """
    if _shadow_stats is None:
        return
    
    _shadow_stats.record_trap(
        source_ip=source_ip,
        trap_oid=trap_oid,
        destinations=destinations,
        blocked=blocked,
        redirected=redirected
    )
    
    # Log the trap if configured
    if _trap_log_file and _shadow_config and _shadow_config.log_all_traps:
        try:
            timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
            status = "BLOCKED" if blocked else "REDIRECT" if redirected else "FORWARD"
            dest_str = ",".join([f"{d[0]}:{d[1]}" for d in (destinations or [])])
            line = f"{timestamp} | {source_ip} | {trap_oid} | {status} | {dest_str}\n"
            _trap_log_file.write(line)
            _trap_log_file.flush()
        except Exception:
            pass


def get_shadow_stats() -> Optional[ShadowModeStats]:
    """Get shadow mode statistics collector"""
    return _shadow_stats


def get_shadow_summary() -> Dict[str, Any]:
    """Get shadow mode statistics summary"""
    if _shadow_stats is None:
        return {'enabled': False}
    
    summary = _shadow_stats.get_summary()
    summary['enabled'] = True
    summary['observe_only'] = _shadow_config.observe_only if _shadow_config else True
    return summary


# Configuration file paths
SHADOW_CONFIG_FILE = "/opt/trapninja/config/shadow_config.json"
CAPTURE_CONFIG_FILE = "/opt/trapninja/config/capture_config.json"


def load_shadow_config() -> ShadowConfig:
    """Load shadow config from file"""
    if os.path.exists(SHADOW_CONFIG_FILE):
        try:
            with open(SHADOW_CONFIG_FILE, 'r') as f:
                data = json.load(f)
            return ShadowConfig.from_dict(data)
        except Exception as e:
            logger.warning(f"Failed to load shadow config: {e}")
    return ShadowConfig()


def load_capture_config() -> CaptureConfig:
    """Load capture config from file"""
    if os.path.exists(CAPTURE_CONFIG_FILE):
        try:
            with open(CAPTURE_CONFIG_FILE, 'r') as f:
                data = json.load(f)
            return CaptureConfig.from_dict(data)
        except Exception as e:
            logger.warning(f"Failed to load capture config: {e}")
    return CaptureConfig()


def save_capture_config(config: CaptureConfig) -> bool:
    """Save capture config to file"""
    try:
        config_dir = os.path.dirname(CAPTURE_CONFIG_FILE)
        if not os.path.exists(config_dir):
            os.makedirs(config_dir)
        
        with open(CAPTURE_CONFIG_FILE, 'w') as f:
            json.dump(config.to_dict(), f, indent=2)
        
        logger.info(f"Saved capture config to {CAPTURE_CONFIG_FILE}")
        return True
    except Exception as e:
        logger.error(f"Failed to save capture config: {e}")
        return False
