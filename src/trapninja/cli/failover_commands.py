#!/usr/bin/env python3
"""
TrapNinja Failover Replay CLI Commands

Provides command-line interface for failover replay management:
- failover-status: View failover replay status
- failover-replay: Manually trigger a gap replay
- failover-test: Test gap detection without replay

Author: TrapNinja Team
Version: 1.0.0
"""

import logging
import time
from datetime import datetime, timedelta
from typing import Optional

logger = logging.getLogger("trapninja")


def _format_duration(seconds: float) -> str:
    """Format duration in human-readable form."""
    if seconds < 60:
        return f"{seconds:.1f} seconds"
    elif seconds < 3600:
        return f"{seconds / 60:.1f} minutes"
    else:
        return f"{seconds / 3600:.1f} hours"


def _get_failover_manager():
    """
    Get the failover replay manager for CLI operations.
    
    Creates a new manager connected to the cache for CLI use.
    
    Returns:
        FailoverReplayManager or None
    """
    try:
        from ..cache import (
            get_cache, TrapCache, CacheConfig,
            FailoverReplayManager, FailoverReplayConfig
        )
        from ..config import load_cache_config, CACHE_CONFIG_FILE
        import os
    except ImportError as e:
        print(f"Required modules not available: {e}")
        return None, None
    
    # Check if failover replay is available
    if FailoverReplayManager is None:
        print("Failover replay module not available")
        return None, None
    
    # Check cache config
    if not os.path.exists(CACHE_CONFIG_FILE):
        print(f"Cache configuration file not found: {CACHE_CONFIG_FILE}")
        return None, None
    
    # Load cache config
    try:
        config = load_cache_config()
    except Exception as e:
        print(f"Failed to load cache configuration: {e}")
        return None, None
    
    if not config or not config.enabled:
        print("Cache is not enabled - failover replay requires caching")
        return None, None
    
    # Check redis
    try:
        import redis
    except ImportError:
        print("Redis Python package not installed")
        return None, None
    
    # Create cache
    cache = TrapCache(config)
    if not cache.connect():
        print(f"Failed to connect to Redis at {config.host}:{config.port}")
        return None, None
    
    # Load failover config
    failover_config = _load_failover_config()
    
    # Create manager
    manager = FailoverReplayManager(cache, failover_config)
    
    return manager, cache


def _load_failover_config():
    """Load failover replay configuration."""
    try:
        from ..cache import FailoverReplayConfig
        from ..config import CONFIG_DIR
        import os
        import json
        
        config_file = os.path.join(CONFIG_DIR, "cache_config.json")
        
        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                data = json.load(f)
            
            failover_data = data.get('failover_replay', {})
            return FailoverReplayConfig.from_dict(failover_data)
        
        return FailoverReplayConfig()
        
    except Exception:
        return None


def show_failover_status(verbose: bool = False) -> bool:
    """
    Display failover replay status.
    
    Args:
        verbose: Show additional details
        
    Returns:
        True if successful
    """
    manager, cache = _get_failover_manager()
    
    if not manager:
        return False
    
    try:
        status = manager.get_status()
        
        print("Failover Replay Status")
        print("=" * 70)
        print(f"Enabled: {status['enabled']}")
        print(f"Available: {status['available']}")
        print(f"Instance ID: {status['instance_id'][:8]}...")
        print(f"Is Primary: {status['is_primary']}")
        print()
        
        # Configuration
        config = status.get('config', {})
        print("Configuration:")
        print(f"  Min gap threshold: {config.get('min_gap_seconds', 'N/A')}s")
        print(f"  Max gap duration: {config.get('max_gap_seconds', 'N/A')}s")
        print(f"  Replay rate limit: {config.get('replay_rate_limit', 'N/A')}/sec")
        print(f"  Replay delay: {config.get('replay_delay_seconds', 'N/A')}s")
        print()
        
        # Tracker status
        tracker = status.get('tracker', {})
        if tracker:
            print("Tracking Status:")
            print(f"  Active node: {tracker.get('active_node', 'None')[:8]}..." if tracker.get('active_node') else "  Active node: None")
            print(f"  Pending updates: {tracker.get('pending_updates', 0)}")
            
            destinations = tracker.get('destinations', {})
            if destinations:
                print("\n  Last Forwarded per Destination:")
                print(f"  {'Destination':<25} {'Age':>12} {'Timestamp':>20}")
                print("  " + "-" * 60)
                
                for dest, info in destinations.items():
                    age = info.get('age_seconds', 0)
                    ts = datetime.fromtimestamp(info.get('last_forwarded', 0))
                    print(f"  {dest:<25} {_format_duration(age):>12} {ts.strftime('%Y-%m-%d %H:%M:%S'):>20}")
        print()
        
        # Current replays
        current = status.get('current_replays', {})
        if current:
            print("Currently Running Replays:")
            for dest, replay in current.items():
                print(f"  {dest}: {replay['state']} - "
                      f"{replay['traps_sent']} sent, {replay['traps_failed']} failed")
        
        # Recent replays
        recent = status.get('recent_replays', [])
        if recent:
            print("\nRecent Replay History:")
            print(f"  {'Destination':<20} {'State':<12} {'Sent':>10} {'Failed':>10} {'Duration':>12}")
            print("  " + "-" * 70)
            
            for replay in recent[-10:]:
                print(f"  {replay['destination']:<20} {replay['state']:<12} "
                      f"{replay['traps_sent']:>10,} {replay['traps_failed']:>10,} "
                      f"{replay['duration_seconds']:>10.1f}s")
        
        return True
        
    finally:
        if cache:
            cache.shutdown()


def detect_gaps(verbose: bool = False) -> bool:
    """
    Detect current forwarding gaps without triggering replay.
    
    Args:
        verbose: Show additional details
        
    Returns:
        True if successful
    """
    manager, cache = _get_failover_manager()
    
    if not manager:
        return False
    
    try:
        from ..cache.failover import GapDetector
        
        if not manager._tracker or not manager._detector:
            print("Failover tracking not initialized")
            return False
        
        print("Gap Detection Analysis")
        print("=" * 70)
        print(f"Current time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print()
        
        # Get all timestamps
        timestamps = manager._tracker.get_all_last_forwarded()
        
        if not timestamps:
            print("No forwarding timestamps found in Redis")
            print("\nThis could mean:")
            print("  - No traps have been forwarded with failover tracking enabled")
            print("  - The cache was recently cleared")
            print("  - Failover tracking is not enabled on the active node")
            return True
        
        # Detect gaps
        gaps = manager._detector.detect_gaps()
        
        if not gaps:
            print("No gaps detected - all destinations up to date")
            print()
            print("Last Forwarded Timestamps:")
            print(f"  {'Destination':<25} {'Age':>12} {'Timestamp':>20}")
            print("  " + "-" * 60)
            
            for dest, ts in timestamps.items():
                age = time.time() - ts
                dt = datetime.fromtimestamp(ts)
                print(f"  {dest:<25} {_format_duration(age):>12} {dt.strftime('%H:%M:%S'):>20}")
            
            return True
        
        # Show detected gaps
        print(f"Detected {len(gaps)} gap(s):")
        print()
        
        total_traps = 0
        for gap in gaps:
            print(f"Gap: {gap.destination}")
            print(f"  Time range: {gap.start_datetime.strftime('%H:%M:%S')} to "
                  f"{gap.end_datetime.strftime('%H:%M:%S')}")
            print(f"  Duration: {gap.gap_seconds:.1f} seconds")
            print(f"  Estimated traps: {gap.estimated_traps:,}")
            if gap.last_node:
                print(f"  Last active node: {gap.last_node[:8]}...")
            print()
            total_traps += gap.estimated_traps
        
        # Summary
        total_gap = sum(g.gap_seconds for g in gaps)
        rate = manager._config.replay_rate_limit if manager._config else 1000
        estimated_replay = total_traps / rate if rate > 0 else 0
        
        print("Summary:")
        print(f"  Total gaps: {len(gaps)}")
        print(f"  Total gap duration: {total_gap:.1f}s")
        print(f"  Estimated traps to replay: {total_traps:,}")
        print(f"  Estimated replay time: {_format_duration(estimated_replay)}")
        print()
        print("To replay these gaps, use: trapninja --failover-replay")
        
        return True
        
    finally:
        if cache:
            cache.shutdown()


def trigger_manual_replay(destination: str,
                         start_time: str,
                         end_time: str,
                         rate_limit: Optional[int] = None,
                         dry_run: bool = False,
                         yes: bool = False) -> bool:
    """
    Manually trigger a failover gap replay.
    
    Args:
        destination: Destination to replay (or "detect" to auto-detect)
        start_time: Start of replay window
        end_time: End of replay window
        rate_limit: Override rate limit
        dry_run: Preview without sending
        yes: Skip confirmation
        
    Returns:
        True if successful
    """
    manager, cache = _get_failover_manager()
    
    if not manager:
        return False
    
    try:
        # Handle "detect" mode - auto-detect gaps
        if destination.lower() == "detect":
            return _replay_detected_gaps(manager, rate_limit, dry_run, yes)
        
        # Parse times
        from .cache_commands import _parse_datetime
        
        start = _parse_datetime(start_time)
        end = _parse_datetime(end_time)
        
        if not start:
            print(f"Invalid start time: {start_time}")
            return False
        
        if not end:
            print(f"Invalid end time: {end_time}")
            return False
        
        if start >= end:
            print("Start time must be before end time")
            return False
        
        # Count traps in window
        count = cache.count_range(destination, start, end)
        duration = (end - start).total_seconds()
        rate = rate_limit or (manager._config.replay_rate_limit if manager._config else 1000)
        estimated_time = count / rate if rate > 0 else 0
        
        print("Manual Failover Replay")
        print("=" * 70)
        print(f"Destination: {destination}")
        print(f"Time window: {start.strftime('%Y-%m-%d %H:%M:%S')} to "
              f"{end.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Duration: {_format_duration(duration)}")
        print(f"Traps to replay: {count:,}")
        print(f"Rate limit: {rate}/sec")
        print(f"Estimated replay time: {_format_duration(estimated_time)}")
        print()
        
        if dry_run:
            print("[DRY RUN - No traps will be sent]")
            return True
        
        if count == 0:
            print("No traps found in the specified time window")
            return True
        
        if not yes:
            response = input("Proceed with replay? [y/N]: ")
            if response.lower() != 'y':
                print("Replay cancelled")
                return False
        
        print("\nStarting replay...")
        
        result = manager.trigger_manual_replay(
            destination=destination,
            start=start,
            end=end,
            rate_limit=rate
        )
        
        print()
        print("Replay Complete")
        print("=" * 70)
        print(f"State: {result.state}")
        print(f"Traps sent: {result.traps_sent:,}")
        print(f"Traps failed: {result.traps_failed:,}")
        print(f"Duration: {_format_duration(result.duration_seconds)}")
        
        if result.error_message:
            print(f"Error: {result.error_message}")
        
        return result.state == 'completed'
        
    finally:
        if cache:
            cache.shutdown()


def _replay_detected_gaps(manager, rate_limit: Optional[int], 
                         dry_run: bool, yes: bool) -> bool:
    """Replay automatically detected gaps."""
    if not manager._detector:
        print("Gap detection not available")
        return False
    
    gaps = manager._detector.detect_gaps()
    
    if not gaps:
        print("No gaps detected - nothing to replay")
        return True
    
    total_traps = sum(g.estimated_traps for g in gaps)
    total_duration = sum(g.gap_seconds for g in gaps)
    rate = rate_limit or (manager._config.replay_rate_limit if manager._config else 1000)
    estimated_time = total_traps / rate if rate > 0 else 0
    
    print("Detected Gaps for Replay")
    print("=" * 70)
    
    for gap in gaps:
        print(f"\n{gap.destination}:")
        print(f"  Window: {gap.start_datetime.strftime('%H:%M:%S')} - "
              f"{gap.end_datetime.strftime('%H:%M:%S')}")
        print(f"  Duration: {gap.gap_seconds:.1f}s, Traps: ~{gap.estimated_traps:,}")
    
    print()
    print(f"Total: {len(gaps)} gaps, {total_traps:,} traps, "
          f"estimated {_format_duration(estimated_time)} to replay")
    print()
    
    if dry_run:
        print("[DRY RUN - No traps will be sent]")
        return True
    
    if not yes:
        response = input("Proceed with replay? [y/N]: ")
        if response.lower() != 'y':
            print("Replay cancelled")
            return False
    
    print("\nStarting replay of detected gaps...")
    
    # Trigger on_become_primary to replay all gaps
    manager.on_become_primary()
    
    # Wait a moment for background replay to start
    import time
    time.sleep(2)
    
    print("\nReplay initiated. Use --failover-status to monitor progress.")
    
    return True


def show_failover_help() -> bool:
    """Display failover replay help."""
    help_text = """
TrapNinja Failover Replay System
================================

The failover replay system ensures zero trap loss during HA failovers by:
1. Tracking the last forwarded timestamp for each destination
2. Detecting gaps when a node becomes PRIMARY
3. Automatically replaying cached traps from the gap window

COMMANDS
--------

  --failover-status
      Show failover replay status and recent history.
      
      Example:
        trapninja --failover-status

  --failover-detect
      Detect current forwarding gaps without replaying.
      Shows what would be replayed if a failover happened now.
      
      Example:
        trapninja --failover-detect

  --failover-replay
      Manually trigger a gap replay.
      
      Options:
        --destination   Destination to replay (or "detect" for auto)
        --from          Start of replay window
        --to            End of replay window  
        --rate-limit    Override replay rate (traps/sec)
        --dry-run       Preview without sending
        -y, --yes       Skip confirmation
      
      Examples:
        # Replay detected gaps automatically
        trapninja --failover-replay --destination detect
        
        # Replay specific time window
        trapninja --failover-replay --destination default \\
            --from "-5m" --to "now" --rate-limit 2000

CONFIGURATION
-------------

Add to /opt/trapninja/config/cache_config.json:

{
  "enabled": true,
  "host": "localhost",
  "port": 6379,
  "retention_hours": 2.0,
  "failover_replay": {
    "enabled": true,
    "min_gap_seconds": 1.0,
    "max_gap_seconds": 300.0,
    "replay_rate_limit": 2000,
    "replay_delay_seconds": 1.0,
    "replay_in_background": true
  }
}

Configuration Options:

  enabled             Enable automatic failover replay (default: true)
  min_gap_seconds     Minimum gap to trigger replay (default: 1.0s)
  max_gap_seconds     Maximum gap to replay (default: 300s = 5 min)
  replay_rate_limit   Traps/second during replay (default: 2000)
  replay_delay_seconds  Delay before starting replay (default: 1.0s)
  replay_in_background  Run replay in background thread (default: true)

HOW IT WORKS
------------

1. TIMESTAMP TRACKING
   - Each forwarded trap updates a timestamp in Redis
   - Stored per destination for granular tracking
   - Batched for performance (500ms intervals)

2. GAP DETECTION
   - When a node becomes PRIMARY, it reads last_forwarded timestamps
   - Compares against current time to find gaps
   - Gaps smaller than min_gap_seconds are ignored
   - Gaps larger than max_gap_seconds are capped

3. AUTOMATIC REPLAY
   - Queries cache for traps in the gap window
   - Replays at configured rate to avoid overwhelming NMS
   - Runs in background to not block new trap processing
   - Progress tracked in --failover-status

INTEGRATION WITH HA
-------------------

The failover replay integrates automatically with HA clustering:

1. Node A (PRIMARY) forwards traps, updating timestamps
2. Node A fails - failover to Node B takes ~3 seconds
3. Node B becomes PRIMARY
4. Node B detects 3-second gap
5. Node B automatically replays ~50-500 traps from cache
6. No traps lost!

REQUIREMENTS
------------

1. Redis caching enabled and working
2. Both HA nodes using the same Redis instance
3. Retention window >= expected failover time

TROUBLESHOOTING
---------------

"No timestamps found":
  - Ensure failover tracking is enabled
  - Check that traps are being forwarded
  - Verify Redis connectivity

"Gap too large":
  - Check max_gap_seconds configuration
  - May indicate prolonged outage
  - Manual replay can be used for larger windows

"Replay too slow":
  - Increase replay_rate_limit
  - Check Redis performance
  - Check network to destinations
"""
    print(help_text)
    return True
