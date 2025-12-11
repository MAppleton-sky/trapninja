#!/usr/bin/env python3
"""
TrapNinja Cache CLI Commands

Provides command-line interface for cache management:
- cache status: View cache statistics
- cache replay: Replay traps for a time window
- cache query: Preview traps in a time window
- cache clear: Clear cached entries

Note: CLI commands connect directly to Redis using the configuration file,
independent of the running daemon.

Author: TrapNinja Team
Version: 1.0.0
"""

import sys
import logging
from datetime import datetime, timedelta
from typing import Optional

logger = logging.getLogger("trapninja")


def _format_duration(seconds: float) -> str:
    """
    Format duration in human-readable form.
    
    Args:
        seconds: Duration in seconds
        
    Returns:
        Formatted string (e.g., "45 seconds", "12.5 minutes", "2.3 hours", "1.5 days")
    """
    if seconds < 60:
        return f"{seconds:.1f} seconds"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f} minutes"
    elif seconds < 86400:
        hours = seconds / 3600
        return f"{hours:.1f} hours"
    else:
        days = seconds / 86400
        return f"{days:.1f} days"


def _format_bytes(num_bytes: int) -> str:
    """Format bytes as human-readable string."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if abs(num_bytes) < 1024:
            return f"{num_bytes:.1f} {unit}"
        num_bytes /= 1024
    return f"{num_bytes:.1f} TB"


def _format_timestamp(ts: Optional[str]) -> str:
    """Format timestamp for display."""
    if not ts:
        return "-"
    try:
        dt = datetime.fromisoformat(ts.replace('Z', '+00:00'))
        return dt.strftime("%H:%M:%S")
    except Exception:
        return ts[:19] if len(ts) > 19 else ts


def _parse_datetime(value: str) -> Optional[datetime]:
    """
    Parse datetime from various formats.
    
    Supported formats:
    - "2025-01-15 14:30"
    - "2025-01-15 14:30:00"
    - "14:30" (today)
    - "yesterday 14:30"
    - "-2h" (2 hours ago)
    - "-30m" (30 minutes ago)
    - "now"
    """
    value = value.strip().lower()
    now = datetime.now()
    
    # Handle "now"
    if value == "now":
        return now
    
    # Relative time format: -2h, -30m
    if value.startswith('-'):
        try:
            amount = value[1:-1]
            unit = value[-1].lower()
            amount = float(amount)
            
            if unit == 'h':
                return now - timedelta(hours=amount)
            elif unit == 'm':
                return now - timedelta(minutes=amount)
            elif unit == 's':
                return now - timedelta(seconds=amount)
            elif unit == 'd':
                return now - timedelta(days=amount)
        except (ValueError, IndexError):
            pass
    
    # Time only format: 14:30
    if len(value) <= 8 and ':' in value:
        try:
            time_parts = value.split(':')
            hour = int(time_parts[0])
            minute = int(time_parts[1]) if len(time_parts) > 1 else 0
            second = int(time_parts[2]) if len(time_parts) > 2 else 0
            return now.replace(hour=hour, minute=minute, second=second, microsecond=0)
        except (ValueError, IndexError):
            pass
    
    # Yesterday format
    if value.startswith('yesterday'):
        try:
            time_part = value[9:].strip()
            if time_part:
                time_parts = time_part.split(':')
                hour = int(time_parts[0])
                minute = int(time_parts[1]) if len(time_parts) > 1 else 0
            else:
                hour, minute = 0, 0
            yesterday = now - timedelta(days=1)
            return yesterday.replace(hour=hour, minute=minute, second=0, microsecond=0)
        except (ValueError, IndexError):
            pass
    
    # Full datetime formats
    formats = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M",
        "%d/%m/%Y %H:%M:%S",
        "%d/%m/%Y %H:%M",
    ]
    
    for fmt in formats:
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    
    return None


def _get_cache_for_cli():
    """
    Get a cache instance for CLI operations.
    
    Creates a new connection to Redis based on the configuration file,
    independent of the running daemon.
    
    Returns:
        TrapCache instance or None if not configured/available
    """
    try:
        from ..cache import TrapCache, CacheConfig
        from ..config import load_cache_config, CACHE_CONFIG_FILE
        import os
    except ImportError as e:
        print(f"Cache module not available: {e}")
        return None
    
    # Check if config file exists
    if not os.path.exists(CACHE_CONFIG_FILE):
        print(f"Cache configuration file not found: {CACHE_CONFIG_FILE}")
        print("\nTo enable caching, create the configuration file with:")
        print(f'  {{"enabled": true, "host": "localhost", "port": 6379}}')
        return None
    
    # Load configuration
    try:
        config = load_cache_config()
    except Exception as e:
        print(f"Failed to load cache configuration: {e}")
        return None
    
    if config is None:
        print("Failed to load cache configuration")
        return None
    
    if not config.enabled:
        print("Cache is not enabled in configuration")
        print(f"\nEdit {CACHE_CONFIG_FILE} and set \"enabled\": true")
        return None
    
    # Check if redis module is available
    try:
        import redis
    except ImportError:
        print("Redis Python package not installed")
        print("\nInstall with: pip install redis --break-system-packages")
        return None
    
    # Create cache instance and connect
    cache = TrapCache(config)
    
    if not cache.connect():
        print(f"Failed to connect to Redis at {config.host}:{config.port}")
        print("\nCheck that Redis is running:")
        print("  systemctl status redis")
        print("  redis-cli ping")
        return None
    
    return cache


def show_cache_status(verbose: bool = False) -> bool:
    """
    Display cache status for all destinations.
    
    Args:
        verbose: Show additional details
        
    Returns:
        True if successful
    """
    cache = _get_cache_for_cli()
    
    if not cache:
        return False
    
    try:
        stats = cache.get_stats()
        
        print("Cache Status")
        print("=" * 70)
        print(f"Redis: {stats['config']['host']}:{stats['config']['port']}")
        print(f"Retention: {stats['config']['retention_hours']} hours")
        print(f"Status: Connected")
        print()
        
        # Per-destination statistics
        destinations = stats.get('destinations', {})
        
        if not destinations:
            print("No cached entries")
            return True
        
        print(f"{'Destination':<20} {'Entries':>10} {'Oldest':>12} {'Newest':>12} {'Size':>12}")
        print("-" * 70)
        
        total_entries = 0
        total_size = 0
        
        for dest, info in sorted(destinations.items()):
            total_entries += info['length']
            total_size += info['memory_bytes']
            
            print(f"{dest:<20} {info['length']:>10,} "
                  f"{_format_timestamp(info['first_entry']):>12} "
                  f"{_format_timestamp(info['last_entry']):>12} "
                  f"{_format_bytes(info['memory_bytes']):>12}")
        
        print("-" * 70)
        print(f"{'Total':<20} {total_entries:>10,} {'':<12} {'':<12} {_format_bytes(total_size):>12}")
        
        # Calculate retention window
        retention_hours = stats['config']['retention_hours']
        print()
        print(f"Retention window: {retention_hours} hours (entries older than this are automatically trimmed)")
        
        return True
        
    finally:
        cache.shutdown()


def query_cache(destination: str,
                start_time: str,
                end_time: str,
                limit: int = 20,
                show_oids: bool = True) -> bool:
    """
    Query and preview cached traps for a time window.
    
    Args:
        destination: Destination to query
        start_time: Start time (various formats supported)
        end_time: End time (various formats supported)
        limit: Maximum entries to show
        show_oids: Show OID summary
        
    Returns:
        True if successful
    """
    cache = _get_cache_for_cli()
    
    if not cache:
        return False
    
    try:
        from ..cache import ReplayEngine
    except ImportError:
        print("Cache module not available")
        return False
    
    try:
        # Parse times
        start = _parse_datetime(start_time)
        end = _parse_datetime(end_time)
        
        if not start:
            print(f"Invalid start time: {start_time}")
            print("Supported formats: '14:30', '2025-01-15 14:30', '-2h' (2 hours ago), 'now'")
            return False
        
        if not end:
            print(f"Invalid end time: {end_time}")
            return False
        
        engine = ReplayEngine(cache)
        
        # Get count
        count = engine.count_entries(destination, start, end)
        
        print(f"Cache Query: {destination}")
        print(f"Time window: {start.strftime('%Y-%m-%d %H:%M:%S')} to {end.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Entries found: {count:,}")
        print()
        
        if count == 0:
            return True
        
        # Show OID summary
        if show_oids:
            oid_summary = engine.get_oid_summary(destination, start, end, limit=10)
            if oid_summary:
                print("Top OIDs:")
                for oid, cnt in oid_summary.items():
                    print(f"  {oid}: {cnt:,}")
                print()
        
        # Show sample entries
        print(f"Sample entries (first {limit}):")
        print(f"{'Timestamp':<24} {'Source IP':<16} {'OID'}")
        print("-" * 70)
        
        for i, entry in enumerate(engine.query_range(destination, start, end)):
            if i >= limit:
                break
            
            ts = entry.get('timestamp', '')[:19]
            src = entry.get('source_ip', '')
            oid = entry.get('trap_oid', '')
            
            # Truncate OID if too long
            if len(oid) > 40:
                oid = oid[:37] + "..."
            
            print(f"{ts:<24} {src:<16} {oid}")
        
        if count > limit:
            print(f"... and {count - limit:,} more entries")
        
        return True
        
    finally:
        cache.shutdown()


def replay_cache(destination: str,
                 start_time: str,
                 end_time: str,
                 rate_limit: int = 500,
                 dry_run: bool = False,
                 oid_filter: Optional[str] = None,
                 source_filter: Optional[str] = None,
                 exclude_oid: Optional[str] = None,
                 yes: bool = False,
                 replay_to: Optional[str] = None) -> bool:
    """
    Replay cached traps for a time window.
    
    Args:
        destination: Destination to replay from (or "all")
        start_time: Start of replay window
        end_time: End of replay window
        rate_limit: Maximum traps per second
        dry_run: Preview without sending
        oid_filter: Only replay OIDs starting with this
        source_filter: Only replay from sources starting with this
        exclude_oid: OID to exclude
        yes: Skip confirmation prompt
        replay_to: Custom destination as "host:port" (overrides default routing)
        
    Returns:
        True if successful
    """
    cache = _get_cache_for_cli()
    
    if not cache:
        return False
    
    try:
        from ..cache import ReplayEngine
    except ImportError:
        print("Cache module not available")
        return False
    
    try:
        # Parse times
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
        
        engine = ReplayEngine(cache)
        
        # Build exclusion list
        exclude_oids = [exclude_oid] if exclude_oid else None
        
        # Handle "all" destination
        if destination.lower() == "all":
            destinations = cache.get_destinations()
            if not destinations:
                print("No cached destinations found")
                return True
            
            total_count = 0
            for dest in destinations:
                count = engine.count_entries(dest, start, end, oid_filter, source_filter)
                total_count += count
                print(f"  {dest}: {count:,} entries")
            
            print(f"\nTotal: {total_count:,} entries across {len(destinations)} destinations")
            
            if not yes and not dry_run:
                response = input("\nProceed with replay? [y/N]: ")
                if response.lower() != 'y':
                    print("Replay cancelled")
                    return False
            
            # Replay all
            results = engine.replay_all(
                start=start,
                end=end,
                rate_limit=rate_limit,
                dry_run=dry_run,
                progress_callback=lambda d, p, t: print(f"\r{d}: {p}/{t}", end="", flush=True)
            )
            
            print("\n\nReplay Results:")
            print("-" * 50)
            for dest, result in results.items():
                status = "DRY RUN" if result.dry_run else "COMPLETE"
                print(f"{dest}: {result.sent:,} sent, {result.failed:,} failed [{status}]")
            
            return True
        
        # Single destination replay
        count = engine.count_entries(destination, start, end, oid_filter, source_filter)
        
        if count == 0:
            print(f"No entries found for {destination} in the specified time window")
            return True
        
        duration = end - start
        estimated_time = count / rate_limit if rate_limit > 0 else 0
        
        print(f"Replay Summary")
        print("=" * 50)
        print(f"Source cache: {destination}")
        if replay_to:
            print(f"Replay to: {replay_to}")
        else:
            print(f"Replay to: original destinations")
        print(f"Time window: {start.strftime('%Y-%m-%d %H:%M:%S')} to {end.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Duration: {duration}")
        print(f"Entries to replay: {count:,}")
        print(f"Rate limit: {rate_limit}/sec")
        print(f"Estimated time: {_format_duration(estimated_time)}")
        
        if oid_filter:
            print(f"OID filter: {oid_filter}")
        if source_filter:
            print(f"Source filter: {source_filter}")
        if exclude_oids:
            print(f"Excluding OIDs: {exclude_oids}")
        
        if dry_run:
            print("\n[DRY RUN - No traps will be sent]")
            
            # Show OID summary
            oid_summary = engine.get_oid_summary(destination, start, end, limit=10)
            if oid_summary:
                print("\nTop OIDs in window:")
                for oid, cnt in oid_summary.items():
                    print(f"  {oid}: {cnt:,}")
            
            return True
        
        # Confirmation
        if not yes:
            response = input("\nProceed with replay? [y/N]: ")
            if response.lower() != 'y':
                print("Replay cancelled")
                return False
        
        # Progress display
        last_percent = -1
        
        def progress_callback(processed: int, total: int):
            nonlocal last_percent
            percent = int(processed * 100 / total) if total > 0 else 0
            if percent != last_percent:
                bar_len = 40
                filled = int(bar_len * processed / total)
                bar = '█' * filled + '░' * (bar_len - filled)
                print(f"\rProgress: [{bar}] {percent}% ({processed:,}/{total:,})", end="", flush=True)
                last_percent = percent
        
        print("\nStarting replay...")
        
        result = engine.replay(
            destination=destination,
            start=start,
            end=end,
            rate_limit=rate_limit,
            dry_run=False,
            oid_filter=oid_filter,
            source_filter=source_filter,
            exclude_oids=exclude_oids,
            progress_callback=progress_callback,
            replay_to=replay_to
        )
        
        print("\n")
        print("Replay Complete")
        print("=" * 50)
        print(f"Sent: {result.sent:,}")
        print(f"Failed: {result.failed:,}")
        print(f"Skipped: {result.skipped:,}")
        print(f"Duration: {_format_duration(result.duration_seconds)}")
        print(f"Rate achieved: {result.rate_achieved:.1f}/sec")
        
        return True
        
    finally:
        cache.shutdown()


def clear_cache(destination: Optional[str] = None, yes: bool = False) -> bool:
    """
    Clear cached entries.
    
    Args:
        destination: Specific destination, or None for all
        yes: Skip confirmation prompt
        
    Returns:
        True if successful
    """
    cache = _get_cache_for_cli()
    
    if not cache:
        return False
    
    try:
        if destination:
            info = cache.get_stream_info(destination)
            if not info or info['length'] == 0:
                print(f"No cached entries for {destination}")
                return True
            
            print(f"This will clear {info['length']:,} entries for {destination}")
        else:
            destinations = cache.get_destinations()
            if not destinations:
                print("No cached entries")
                return True
            
            total = 0
            for d in destinations:
                info = cache.get_stream_info(d)
                if info:
                    total += info['length']
            print(f"This will clear {total:,} entries across {len(destinations)} destinations")
        
        if not yes:
            response = input("Are you sure? [y/N]: ")
            if response.lower() != 'y':
                print("Clear cancelled")
                return False
        
        if destination:
            success = cache.clear_destination(destination)
        else:
            success = cache.clear_all()
        
        if success:
            print("Cache cleared successfully")
        else:
            print("Failed to clear cache")
        
        return success
        
    finally:
        cache.shutdown()


def trim_cache(yes: bool = False) -> bool:
    """
    Manually trigger retention trim to remove old entries.
    
    Args:
        yes: Skip confirmation prompt
        
    Returns:
        True if successful
    """
    cache = _get_cache_for_cli()
    
    if not cache:
        return False
    
    try:
        # Show what will be trimmed
        from datetime import timedelta
        cutoff = datetime.now() - timedelta(hours=cache.config.retention_hours)
        
        print(f"Retention period: {cache.config.retention_hours} hours")
        print(f"Cutoff time: {cutoff.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Entries older than this will be removed.")
        print()
        
        # Show current state
        destinations = cache.get_destinations()
        if not destinations:
            print("No cached entries to trim")
            return True
        
        total_before = 0
        for dest in destinations:
            info = cache.get_stream_info(dest)
            if info:
                total_before += info['length']
                oldest = info.get('first_entry', 'unknown')
                print(f"  {dest}: {info['length']:,} entries (oldest: {oldest})")
        
        print(f"\nTotal entries before trim: {total_before:,}")
        
        if not yes:
            response = input("\nProceed with trim? [y/N]: ")
            if response.lower() != 'y':
                print("Trim cancelled")
                return False
        
        print("\nRunning trim...")
        results = cache.trim_old_entries()
        
        total_removed = sum(results.values())
        
        print(f"\nTrim complete:")
        for dest, removed in results.items():
            if removed > 0:
                print(f"  {dest}: {removed:,} entries removed")
        
        if total_removed == 0:
            print("  No entries were old enough to remove")
        else:
            print(f"\nTotal removed: {total_removed:,}")
        
        # Show new totals
        total_after = 0
        for dest in destinations:
            info = cache.get_stream_info(dest)
            if info:
                total_after += info['length']
        
        print(f"Entries remaining: {total_after:,}")
        
        return True
        
    finally:
        cache.shutdown()


def show_cache_help() -> bool:
    """Display comprehensive cache help."""
    help_text = """
TrapNinja Cache System
======================

The cache system provides a rolling buffer of SNMP traps in Redis,
enabling replay during monitoring system outages.

COMMANDS
--------

  --cache-status
      Show cache status and statistics for all destinations.
      
      Example:
        trapninja --cache-status

  --cache-query
      Query and preview cached traps for a time window.
      
      Options:
        --destination  Destination to query
        --from         Start time
        --to           End time
        --limit        Maximum entries to show (default: 20)
      
      Example:
        trapninja --cache-query --destination default --from "-2h" --to "now"

  --cache-replay
      Replay cached traps for a time window.
      
      Options:
        --destination   Destination to replay from (or "all")
        --from          Start of replay window
        --to            End of replay window
        --replay-to     Custom destination host:port (e.g., 10.1.2.3:162)
        --rate-limit    Max traps/sec (default: 500)
        --dry-run       Preview without sending
        --oid-filter    Only replay OIDs starting with this
        --source-filter Only replay from these sources
        --exclude-oid   OID to exclude from replay
        -y, --yes       Skip confirmation prompt
      
      Examples:
        # Preview what would be replayed
        trapninja --cache-replay --destination default --from "-2h" --to "-1h" --dry-run
        
        # Replay to original destinations
        trapninja --cache-replay --destination default --from "14:30" --to "15:45" --rate-limit 1000
        
        # Replay to a test NMS
        trapninja --cache-replay --destination default --from "-1h" --to "now" --replay-to 10.1.2.3:162
        
        # Replay to alternate port
        trapninja --cache-replay --destination default --from "-1h" --to "now" --replay-to test-nms.example.com:1162
        
        # Replay all destinations
        trapninja --cache-replay --destination all --from "-2h" --to "-1h"

  --cache-clear
      Clear cached entries.
      
      Options:
        --destination  Specific destination (omit for all)
        -y, --yes      Skip confirmation prompt
      
      Example:
        trapninja --cache-clear --destination default

TIME FORMATS
------------

The following time formats are supported for --from and --to:

  Relative:
    -2h          2 hours ago
    -30m         30 minutes ago
    -1d          1 day ago
    now          Current time
  
  Time only (today):
    14:30        Today at 14:30
    09:15:30     Today at 09:15:30
  
  Yesterday:
    yesterday 14:30
  
  Full datetime:
    2025-01-15 14:30
    2025-01-15 14:30:00

CONFIGURATION
-------------

Create /opt/trapninja/config/cache_config.json:

{
  "enabled": true,
  "host": "localhost",
  "port": 6379,
  "retention_hours": 2.0,
  "trim_interval_seconds": 60
}

REDIS SETUP
-----------

1. Install Redis:
   dnf install epel-release
   dnf install redis

2. Configure Redis (edit /etc/redis.conf):
   maxmemory 4gb
   maxmemory-policy noeviction
   appendonly yes

3. Start Redis:
   systemctl enable --now redis

4. Install Python Redis package:
   pip install redis --break-system-packages

DESTINATIONS
------------

Traps are cached per destination:
  - "default"     : Traps forwarded to normal destinations
  - "voice_noc"   : Traps redirected to voice_noc tag
  - "broadband"   : Traps redirected to broadband tag
  - etc.

The destination name matches your redirection tags.
"""
    print(help_text)
    return True
