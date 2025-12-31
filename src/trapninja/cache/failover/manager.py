#!/usr/bin/env python3
"""
TrapNinja Failover Replay Manager

Orchestrates automatic gap detection and replay during HA failover.
Ensures zero trap loss during failover transitions.

Features:
- Automatic gap detection on becoming PRIMARY
- Configurable replay rate and thresholds
- Background replay to minimize impact on new trap processing
- Replay progress tracking and reporting
- Integration with HA state transitions

Usage:
    # Initialize with cache and config
    manager = FailoverReplayManager(cache, config)
    
    # Hook into HA state changes
    ha_cluster.state_manager.add_callback(manager.on_state_change)
    
    # Or manually trigger on failover
    manager.on_become_primary()
    
    # Update timestamp on each forwarded trap
    manager.update_last_forwarded(destination, timestamp)

Author: TrapNinja Team
Version: 1.0.0
"""

import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Dict, Any, List, Callable

from .tracker import FailoverTracker
from .detector import GapDetector, GapInfo

logger = logging.getLogger("trapninja")


@dataclass
class FailoverReplayConfig:
    """
    Configuration for failover replay.
    
    Attributes:
        enabled: Enable automatic failover replay
        min_gap_seconds: Minimum gap to trigger replay (default: 1.0s)
        max_gap_seconds: Maximum gap to replay (default: 300s = 5 min)
        replay_rate_limit: Traps/second during replay (default: 2000)
        replay_delay_seconds: Delay before starting replay (default: 1.0s)
        buffer_seconds: Extra buffer added to gap start (default: 0.5s)
        replay_in_background: Run replay in background thread (default: True)
        mark_replayed_traps: Add marker to replayed traps (default: False)
    """
    enabled: bool = True
    min_gap_seconds: float = 1.0
    max_gap_seconds: float = 300.0
    replay_rate_limit: int = 2000
    replay_delay_seconds: float = 1.0
    buffer_seconds: float = 0.5
    replay_in_background: bool = True
    mark_replayed_traps: bool = False
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'FailoverReplayConfig':
        """Create config from dictionary."""
        return cls(
            enabled=data.get('enabled', True),
            min_gap_seconds=data.get('min_gap_seconds', 1.0),
            max_gap_seconds=data.get('max_gap_seconds', 300.0),
            replay_rate_limit=data.get('replay_rate_limit', 2000),
            replay_delay_seconds=data.get('replay_delay_seconds', 1.0),
            buffer_seconds=data.get('buffer_seconds', 0.5),
            replay_in_background=data.get('replay_in_background', True),
            mark_replayed_traps=data.get('mark_replayed_traps', False),
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'enabled': self.enabled,
            'min_gap_seconds': self.min_gap_seconds,
            'max_gap_seconds': self.max_gap_seconds,
            'replay_rate_limit': self.replay_rate_limit,
            'replay_delay_seconds': self.replay_delay_seconds,
            'buffer_seconds': self.buffer_seconds,
            'replay_in_background': self.replay_in_background,
            'mark_replayed_traps': self.mark_replayed_traps,
        }


@dataclass
class ReplayStatus:
    """Status of a replay operation."""
    destination: str
    gap: GapInfo
    state: str  # 'pending', 'running', 'completed', 'failed'
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    traps_sent: int = 0
    traps_failed: int = 0
    error_message: Optional[str] = None
    
    @property
    def duration_seconds(self) -> float:
        """Get replay duration."""
        if not self.started_at:
            return 0.0
        end = self.completed_at or time.time()
        return end - self.started_at
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'destination': self.destination,
            'gap': self.gap.to_dict(),
            'state': self.state,
            'started_at': self.started_at,
            'completed_at': self.completed_at,
            'duration_seconds': round(self.duration_seconds, 2),
            'traps_sent': self.traps_sent,
            'traps_failed': self.traps_failed,
            'error_message': self.error_message,
        }


class FailoverReplayManager:
    """
    Manages automatic gap detection and replay during failover.
    
    Integrates with:
    - TrapCache for trap storage and replay
    - HA cluster for state transition callbacks
    - Forwarder for sending replayed traps
    
    Thread-safe for use with multiple worker threads.
    """
    
    def __init__(self,
                 cache: 'TrapCache',
                 config: Optional[FailoverReplayConfig] = None,
                 instance_id: Optional[str] = None,
                 on_replay_complete: Optional[Callable[[List[ReplayStatus]], None]] = None):
        """
        Initialize failover replay manager.
        
        Args:
            cache: TrapCache instance
            config: Replay configuration
            instance_id: Unique instance ID (generated if not provided)
            on_replay_complete: Callback when replay completes
        """
        self._cache = cache
        self._config = config or FailoverReplayConfig()
        self._instance_id = instance_id or self._generate_instance_id()
        self._on_replay_complete = on_replay_complete
        
        # Initialize components
        self._tracker: Optional[FailoverTracker] = None
        self._detector: Optional[GapDetector] = None
        
        # State
        self._lock = threading.Lock()
        self._is_primary = False
        self._replay_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._current_replays: Dict[str, ReplayStatus] = {}
        self._replay_history: List[ReplayStatus] = []
        self._max_history = 50
        
        # Initialize if cache is available
        if cache and cache.available:
            self._initialize_components()
    
    def _generate_instance_id(self) -> str:
        """Generate a unique instance ID."""
        import uuid
        return str(uuid.uuid4())
    
    def _initialize_components(self):
        """Initialize tracker and detector components."""
        if not self._cache or not self._cache._client:
            logger.warning("Cache not available - failover replay disabled")
            return
        
        try:
            self._tracker = FailoverTracker(
                self._cache._client,
                self._instance_id
            )
            
            self._detector = GapDetector(
                self._tracker,
                self._cache,
                min_gap_seconds=self._config.min_gap_seconds,
                max_gap_seconds=self._config.max_gap_seconds,
                buffer_seconds=self._config.buffer_seconds
            )
            
            logger.info(
                f"Failover replay manager initialized "
                f"(min_gap={self._config.min_gap_seconds}s, "
                f"max_gap={self._config.max_gap_seconds}s, "
                f"rate={self._config.replay_rate_limit}/s)"
            )
            
        except Exception as e:
            logger.error(f"Failed to initialize failover replay: {e}")
            self._tracker = None
            self._detector = None
    
    @property
    def available(self) -> bool:
        """Check if failover replay is available."""
        return (
            self._config.enabled and
            self._tracker is not None and
            self._detector is not None
        )
    
    def update_last_forwarded(self, destination: str, timestamp: Optional[float] = None):
        """
        Update last forwarded timestamp for a destination.
        
        Should be called for each forwarded trap. Batched internally
        for performance - minimal overhead on hot path.
        
        Args:
            destination: Destination identifier
            timestamp: Unix timestamp (default: current time)
        """
        if not self.available or not self._is_primary:
            return
        
        self._tracker.update_last_forwarded(destination, timestamp)
    
    def on_become_primary(self):
        """
        Called when this node becomes PRIMARY.
        
        Triggers gap detection and automatic replay if enabled.
        """
        with self._lock:
            if not self._config.enabled:
                logger.debug("Failover replay disabled by configuration")
                return
            
            if not self.available:
                logger.warning("Failover replay not available")
                return
            
            self._is_primary = True
            failover_time = time.time()
            
            # Mark as active node
            self._tracker.set_active_node(True)
            
            logger.info("Failover replay: checking for gaps...")
            
            # Detect gaps
            gaps = self._detector.detect_gaps(failover_time=failover_time)
            
            if not gaps:
                logger.info("Failover replay: no gaps detected - no replay needed")
                return
            
            # Log detected gaps
            total_traps = sum(g.estimated_traps for g in gaps)
            total_gap = sum(g.gap_seconds for g in gaps)
            
            logger.info(
                f"Failover replay: detected {len(gaps)} gap(s), "
                f"~{total_traps:,} traps, ~{total_gap:.1f}s total"
            )
            
            for gap in gaps:
                logger.info(f"  {gap}")
            
            # Start replay
            if self._config.replay_in_background:
                self._start_background_replay(gaps)
            else:
                self._perform_replay(gaps)
    
    def on_become_secondary(self):
        """Called when this node becomes SECONDARY."""
        with self._lock:
            self._is_primary = False
            
            if self._tracker:
                self._tracker.set_active_node(False)
                self._tracker.flush()
            
            # Stop any running replay
            self._stop_event.set()
    
    def on_state_change(self, old_state, new_state):
        """
        Callback for HA state transitions.
        
        Hook this into HAStateManager.add_callback().
        
        Args:
            old_state: Previous HAState
            new_state: New HAState
        """
        # Import here to avoid circular imports
        try:
            from ...ha.state import HAState
        except ImportError:
            logger.warning("Could not import HAState for failover replay callback")
            return
        
        if new_state == HAState.PRIMARY and old_state != HAState.PRIMARY:
            # Becoming PRIMARY - check for gaps
            # Delay slightly to ensure forwarding is enabled
            def delayed_check():
                time.sleep(self._config.replay_delay_seconds)
                self.on_become_primary()
            
            thread = threading.Thread(
                target=delayed_check,
                daemon=True,
                name="FailoverReplayCheck"
            )
            thread.start()
            
        elif old_state == HAState.PRIMARY and new_state != HAState.PRIMARY:
            # No longer PRIMARY
            self.on_become_secondary()
    
    def _start_background_replay(self, gaps: List[GapInfo]):
        """Start replay in background thread."""
        self._stop_event.clear()
        
        self._replay_thread = threading.Thread(
            target=self._perform_replay,
            args=(gaps,),
            daemon=True,
            name="FailoverReplay"
        )
        self._replay_thread.start()
    
    def _perform_replay(self, gaps: List[GapInfo]):
        """
        Perform the actual replay operation.
        
        Args:
            gaps: List of detected gaps to replay
        """
        try:
            from ..replay import ReplayEngine
        except ImportError as e:
            logger.error(f"Failed to import ReplayEngine: {e}")
            return
        
        engine = ReplayEngine(self._cache)
        results: List[ReplayStatus] = []
        
        for gap in gaps:
            if self._stop_event.is_set():
                logger.info("Failover replay cancelled")
                break
            
            status = ReplayStatus(
                destination=gap.destination,
                gap=gap,
                state='running',
                started_at=time.time()
            )
            
            with self._lock:
                self._current_replays[gap.destination] = status
            
            try:
                logger.info(
                    f"Failover replay: starting {gap.destination} "
                    f"({gap.estimated_traps:,} traps, {gap.gap_seconds:.1f}s gap)"
                )
                
                # Handle "all destinations" case
                if gap.destination == "*":
                    # Replay all destinations
                    dest_results = engine.replay_all(
                        start=gap.start_datetime,
                        end=gap.end_datetime,
                        rate_limit=self._config.replay_rate_limit,
                        dry_run=False
                    )
                    
                    for dest, result in dest_results.items():
                        status.traps_sent += result.sent
                        status.traps_failed += result.failed
                else:
                    # Replay single destination
                    result = engine.replay(
                        destination=gap.destination,
                        start=gap.start_datetime,
                        end=gap.end_datetime,
                        rate_limit=self._config.replay_rate_limit,
                        dry_run=False,
                        mark_as_replay=self._config.mark_replayed_traps
                    )
                    
                    status.traps_sent = result.sent
                    status.traps_failed = result.failed
                
                status.state = 'completed'
                status.completed_at = time.time()
                
                logger.info(
                    f"Failover replay: completed {gap.destination} - "
                    f"{status.traps_sent:,} sent, {status.traps_failed:,} failed "
                    f"in {status.duration_seconds:.1f}s"
                )
                
            except Exception as e:
                status.state = 'failed'
                status.error_message = str(e)
                status.completed_at = time.time()
                logger.error(f"Failover replay failed for {gap.destination}: {e}")
            
            results.append(status)
            
            with self._lock:
                del self._current_replays[gap.destination]
                self._replay_history.append(status)
                
                # Trim history
                while len(self._replay_history) > self._max_history:
                    self._replay_history.pop(0)
        
        # Summary
        total_sent = sum(r.traps_sent for r in results)
        total_failed = sum(r.traps_failed for r in results)
        total_time = sum(r.duration_seconds for r in results)
        
        logger.info(
            f"Failover replay complete: {total_sent:,} sent, "
            f"{total_failed:,} failed in {total_time:.1f}s"
        )
        
        # Callback
        if self._on_replay_complete:
            try:
                self._on_replay_complete(results)
            except Exception as e:
                logger.error(f"Replay complete callback error: {e}")
    
    def trigger_manual_replay(self,
                             destination: str,
                             start: datetime,
                             end: datetime,
                             rate_limit: Optional[int] = None) -> ReplayStatus:
        """
        Manually trigger a replay for a specific time window.
        
        Args:
            destination: Destination to replay
            start: Start of replay window
            end: End of replay window
            rate_limit: Override default rate limit
            
        Returns:
            ReplayStatus with results
        """
        try:
            from ..replay import ReplayEngine
        except ImportError as e:
            return ReplayStatus(
                destination=destination,
                gap=GapInfo(
                    destination=destination,
                    gap_start=start.timestamp(),
                    gap_end=end.timestamp(),
                    gap_seconds=(end - start).total_seconds()
                ),
                state='failed',
                error_message=f"Import error: {e}"
            )
        
        gap = GapInfo(
            destination=destination,
            gap_start=start.timestamp(),
            gap_end=end.timestamp(),
            gap_seconds=(end - start).total_seconds()
        )
        
        status = ReplayStatus(
            destination=destination,
            gap=gap,
            state='running',
            started_at=time.time()
        )
        
        engine = ReplayEngine(self._cache)
        rate = rate_limit or self._config.replay_rate_limit
        
        try:
            result = engine.replay(
                destination=destination,
                start=start,
                end=end,
                rate_limit=rate,
                dry_run=False
            )
            
            status.traps_sent = result.sent
            status.traps_failed = result.failed
            status.state = 'completed'
            
        except Exception as e:
            status.state = 'failed'
            status.error_message = str(e)
        
        status.completed_at = time.time()
        
        with self._lock:
            self._replay_history.append(status)
        
        return status
    
    def get_status(self) -> Dict[str, Any]:
        """Get manager status for monitoring."""
        with self._lock:
            return {
                'enabled': self._config.enabled,
                'available': self.available,
                'is_primary': self._is_primary,
                'instance_id': self._instance_id,
                'config': self._config.to_dict(),
                'tracker': self._tracker.get_status() if self._tracker else None,
                'current_replays': {
                    k: v.to_dict() for k, v in self._current_replays.items()
                },
                'recent_replays': [r.to_dict() for r in self._replay_history[-10:]],
            }
    
    def shutdown(self):
        """Shutdown the manager."""
        self._stop_event.set()
        
        if self._tracker:
            self._tracker.cleanup()
        
        if self._replay_thread and self._replay_thread.is_alive():
            self._replay_thread.join(timeout=5.0)
        
        logger.info("Failover replay manager shutdown complete")
