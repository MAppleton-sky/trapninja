#!/usr/bin/env python3
"""
TrapNinja Replay Engine

Provides time-window based trap replay with rate limiting.
Replays cached traps to destinations during outage recovery.

Features:
- Time-range based replay
- Configurable rate limiting
- Progress tracking with callbacks
- Dry-run mode for preview
- OID and source filtering
- Resume capability after interruption

Author: TrapNinja Team
Version: 1.0.0
"""

import base64
import logging
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Dict, Any, List, Callable, Iterator

logger = logging.getLogger("trapninja")


@dataclass
class ReplayResult:
    """Result of a replay operation."""
    destination: str
    start_time: datetime
    end_time: datetime
    total_entries: int
    sent: int
    failed: int
    skipped: int
    dry_run: bool
    duration_seconds: float
    rate_achieved: float  # traps/second
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'destination': self.destination,
            'start_time': self.start_time.isoformat(),
            'end_time': self.end_time.isoformat(),
            'total_entries': self.total_entries,
            'sent': self.sent,
            'failed': self.failed,
            'skipped': self.skipped,
            'dry_run': self.dry_run,
            'duration_seconds': round(self.duration_seconds, 2),
            'rate_achieved': round(self.rate_achieved, 1),
        }


class ReplayEngine:
    """
    Engine for replaying cached traps with rate limiting.
    
    Supports time-window based replay with filtering and
    progress tracking.
    """
    
    def __init__(self, cache: 'TrapCache'):
        """
        Initialize replay engine.
        
        Args:
            cache: TrapCache instance to replay from
        """
        self.cache = cache
        self._stop_requested = False
    
    def stop(self):
        """Request stop of current replay operation."""
        self._stop_requested = True
    
    def query_range(self, destination: str,
                    start: datetime, end: datetime,
                    oid_filter: Optional[str] = None,
                    source_filter: Optional[str] = None) -> Iterator[Dict[str, Any]]:
        """
        Query traps in time range with optional filtering.
        
        Args:
            destination: Destination to query
            start: Start of time range
            end: End of time range
            oid_filter: OID prefix to filter (e.g., "1.3.6.1.4.1.9")
            source_filter: Source IP prefix to filter (e.g., "10.1.")
            
        Yields:
            Matching trap entries
        """
        for entry in self.cache.query_range(destination, start, end):
            # Apply OID filter
            if oid_filter:
                trap_oid = entry.get('trap_oid', '')
                if not trap_oid.startswith(oid_filter):
                    continue
            
            # Apply source filter
            if source_filter:
                source_ip = entry.get('source_ip', '')
                if not source_ip.startswith(source_filter):
                    continue
            
            yield entry
    
    def count_entries(self, destination: str,
                      start: datetime, end: datetime,
                      oid_filter: Optional[str] = None,
                      source_filter: Optional[str] = None) -> int:
        """
        Count entries matching criteria.
        
        Args:
            destination: Destination to query
            start: Start of time range
            end: End of time range
            oid_filter: OID prefix filter
            source_filter: Source IP prefix filter
            
        Returns:
            Number of matching entries
        """
        if not oid_filter and not source_filter:
            # Use efficient count if no filtering
            return self.cache.count_range(destination, start, end)
        
        # Count with filtering (slower)
        count = 0
        for _ in self.query_range(destination, start, end, oid_filter, source_filter):
            count += 1
        return count
    
    def get_oid_summary(self, destination: str,
                        start: datetime, end: datetime,
                        limit: int = 10) -> Dict[str, int]:
        """
        Get summary of trap OIDs in time range.
        
        Args:
            destination: Destination to query
            start: Start of time range
            end: End of time range
            limit: Maximum OIDs to return
            
        Returns:
            Dict of {oid: count} for top OIDs
        """
        oid_counts: Dict[str, int] = {}
        
        for entry in self.cache.query_range(destination, start, end):
            oid = entry.get('trap_oid', 'unknown')
            oid_counts[oid] = oid_counts.get(oid, 0) + 1
        
        # Sort by count and limit
        sorted_oids = sorted(oid_counts.items(), key=lambda x: x[1], reverse=True)
        return dict(sorted_oids[:limit])
    
    def replay(self,
               destination: str,
               start: datetime,
               end: datetime,
               rate_limit: int = 500,
               dry_run: bool = False,
               oid_filter: Optional[str] = None,
               source_filter: Optional[str] = None,
               exclude_oids: Optional[List[str]] = None,
               progress_callback: Optional[Callable[[int, int], None]] = None,
               mark_as_replay: bool = True,
               replay_to: Optional[str] = None) -> ReplayResult:
        """
        Replay cached traps to destination.
        
        Args:
            destination: Source destination ID (which cache to replay from)
            start: Start of replay window
            end: End of replay window
            rate_limit: Maximum traps per second (default 500)
            dry_run: If True, don't actually send traps
            oid_filter: Only replay OIDs starting with this prefix
            source_filter: Only replay from sources starting with this prefix
            exclude_oids: List of OIDs to exclude from replay
            progress_callback: Called with (processed, total) periodically
            mark_as_replay: Add replay marker to forwarded traps
            replay_to: Custom destination as "host:port" (overrides default routing)
            
        Returns:
            ReplayResult with statistics
        """
        self._stop_requested = False
        replay_start_time = time.time()
        
        # Get entries to replay
        entries = list(self.query_range(destination, start, end, oid_filter, source_filter))
        total = len(entries)
        
        # Apply exclusion filter
        if exclude_oids:
            entries = [e for e in entries if e.get('trap_oid', '') not in exclude_oids]
        
        # Dry run - just return stats
        if dry_run:
            return ReplayResult(
                destination=destination,
                start_time=start,
                end_time=end,
                total_entries=total,
                sent=0,
                failed=0,
                skipped=total - len(entries),
                dry_run=True,
                duration_seconds=0,
                rate_achieved=0,
            )
        
        # Get forwarder for actual sending
        try:
            from ..packet_processor import forward_fast
            from ..config import destinations as default_destinations
            from ..config import redirected_destinations
        except ImportError as e:
            logger.error(f"Failed to import forwarding components: {e}")
            return ReplayResult(
                destination=destination,
                start_time=start,
                end_time=end,
                total_entries=total,
                sent=0,
                failed=total,
                skipped=0,
                dry_run=False,
                duration_seconds=0,
                rate_achieved=0,
            )
        
        # Determine target destinations
        if replay_to:
            # Custom destination specified - parse host:port
            try:
                if ':' in replay_to:
                    host, port_str = replay_to.rsplit(':', 1)
                    port = int(port_str)
                else:
                    host = replay_to
                    port = 162  # Default SNMP trap port
                target_list = [(host, port)]
                target_description = f"{host}:{port}"
            except ValueError as e:
                logger.error(f"Invalid replay_to format '{replay_to}': {e}")
                return ReplayResult(
                    destination=destination,
                    start_time=start,
                    end_time=end,
                    total_entries=total,
                    sent=0,
                    failed=total,
                    skipped=0,
                    dry_run=False,
                    duration_seconds=0,
                    rate_achieved=0,
                )
        elif destination in redirected_destinations:
            targets = redirected_destinations[destination]
            target_description = destination
            # Convert targets to list of tuples
            target_list = []
            for t in targets:
                if isinstance(t, (list, tuple)) and len(t) >= 2:
                    target_list.append((str(t[0]), int(t[1])))
                else:
                    logger.warning(f"Invalid target format: {t}")
        else:
            targets = default_destinations
            target_description = "default"
            # Convert targets to list of tuples
            target_list = []
            for t in targets:
                if isinstance(t, (list, tuple)) and len(t) >= 2:
                    target_list.append((str(t[0]), int(t[1])))
                else:
                    logger.warning(f"Invalid target format: {t}")
        
        if not target_list:
            logger.error("No valid targets after conversion")
            return ReplayResult(
                destination=destination,
                start_time=start,
                end_time=end,
                total_entries=total,
                sent=0,
                failed=total,
                skipped=0,
                dry_run=False,
                duration_seconds=0,
                rate_achieved=0,
            )
        
        # Replay with rate limiting
        sent = 0
        failed = 0
        skipped = total - len(entries)
        interval = 1.0 / rate_limit if rate_limit > 0 else 0
        
        logger.info(f"Starting replay from '{destination}' to {target_description}: {len(entries)} traps, rate limit {rate_limit}/s")
        
        for i, entry in enumerate(entries):
            if self._stop_requested:
                logger.info("Replay stopped by request")
                skipped += len(entries) - i
                break
            
            loop_start = time.time()
            
            try:
                # Decode PDU
                pdu_base64 = entry.get('pdu_base64', '')
                if not pdu_base64:
                    failed += 1
                    continue
                
                try:
                    payload = base64.b64decode(pdu_base64)
                except Exception:
                    failed += 1
                    continue
                
                source_ip = entry.get('source_ip', '127.0.0.1')
                
                # Forward the trap
                success = forward_fast(source_ip, payload, target_list)
                
                if success:
                    sent += 1
                else:
                    failed += 1
                    
            except Exception as e:
                logger.debug(f"Replay entry failed: {e}")
                failed += 1
            
            # Rate limiting
            elapsed = time.time() - loop_start
            if elapsed < interval:
                time.sleep(interval - elapsed)
            
            # Progress callback
            if progress_callback and (i + 1) % 100 == 0:
                progress_callback(i + 1, len(entries))
        
        # Final progress callback
        if progress_callback:
            progress_callback(len(entries), len(entries))
        
        replay_duration = time.time() - replay_start_time
        rate_achieved = sent / replay_duration if replay_duration > 0 else 0
        
        logger.info(f"Replay complete: {sent} sent, {failed} failed, {skipped} skipped "
                   f"in {replay_duration:.1f}s ({rate_achieved:.1f}/s)")
        
        return ReplayResult(
            destination=destination,
            start_time=start,
            end_time=end,
            total_entries=total,
            sent=sent,
            failed=failed,
            skipped=skipped,
            dry_run=False,
            duration_seconds=replay_duration,
            rate_achieved=rate_achieved,
        )
    
    def replay_all(self,
                   start: datetime,
                   end: datetime,
                   rate_limit: int = 500,
                   dry_run: bool = False,
                   progress_callback: Optional[Callable[[str, int, int], None]] = None
                   ) -> Dict[str, ReplayResult]:
        """
        Replay all destinations for a time window.
        
        Args:
            start: Start of replay window
            end: End of replay window
            rate_limit: Maximum traps per second per destination
            dry_run: If True, don't actually send
            progress_callback: Called with (destination, processed, total)
            
        Returns:
            Dict of {destination: ReplayResult}
        """
        results = {}
        
        destinations = self.cache.get_destinations()
        
        for dest in destinations:
            if self._stop_requested:
                break
            
            def dest_progress(processed: int, total: int):
                if progress_callback:
                    progress_callback(dest, processed, total)
            
            result = self.replay(
                destination=dest,
                start=start,
                end=end,
                rate_limit=rate_limit,
                dry_run=dry_run,
                progress_callback=dest_progress
            )
            results[dest] = result
        
        return results
