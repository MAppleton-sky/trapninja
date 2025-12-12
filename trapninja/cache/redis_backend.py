#!/usr/bin/env python3
"""
TrapNinja Redis Cache Backend

Provides Redis Streams-based trap caching with rolling retention.
Designed for non-blocking operation - cache failures don't affect forwarding.

Features:
- Rolling 2-hour retention window (configurable)
- Per-destination streams for isolated replay
- Automatic retention trimming
- Connection pooling and reconnection handling
- Thread-safe operations

Author: TrapNinja Team
Version: 1.0.0
"""

import base64
import json
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Any, Iterator

logger = logging.getLogger("trapninja")

# Check if redis is available
try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    logger.debug("Redis package not installed - cache functionality disabled")


@dataclass
class CacheConfig:
    """Configuration for the trap cache."""
    enabled: bool = False
    host: str = "localhost"
    port: int = 6379
    password: Optional[str] = None
    db: int = 0
    retention_hours: float = 2.0
    trim_interval_seconds: int = 60
    key_prefix: str = "trapninja:buffer"
    max_entries_per_stream: int = 1000000  # Safety cap
    socket_timeout: float = 5.0
    socket_connect_timeout: float = 5.0
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'CacheConfig':
        """Create config from dictionary."""
        return cls(
            enabled=data.get('enabled', False),
            host=data.get('host', 'localhost'),
            port=data.get('port', 6379),
            password=data.get('password'),
            db=data.get('db', 0),
            retention_hours=data.get('retention_hours', 2.0),
            trim_interval_seconds=data.get('trim_interval_seconds', 60),
            key_prefix=data.get('key_prefix', 'trapninja:buffer'),
            max_entries_per_stream=data.get('max_entries_per_stream', 1000000),
            socket_timeout=data.get('socket_timeout', 5.0),
            socket_connect_timeout=data.get('socket_connect_timeout', 5.0),
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert config to dictionary."""
        return {
            'enabled': self.enabled,
            'host': self.host,
            'port': self.port,
            'password': self.password,
            'db': self.db,
            'retention_hours': self.retention_hours,
            'trim_interval_seconds': self.trim_interval_seconds,
            'key_prefix': self.key_prefix,
            'max_entries_per_stream': self.max_entries_per_stream,
            'socket_timeout': self.socket_timeout,
            'socket_connect_timeout': self.socket_connect_timeout,
        }


@dataclass
class CacheStats:
    """Statistics for cache operations."""
    entries_stored: int = 0
    entries_trimmed: int = 0
    store_failures: int = 0
    trim_failures: int = 0
    connection_failures: int = 0
    last_store_time: Optional[float] = None
    last_trim_time: Optional[float] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert stats to dictionary."""
        return {
            'entries_stored': self.entries_stored,
            'entries_trimmed': self.entries_trimmed,
            'store_failures': self.store_failures,
            'trim_failures': self.trim_failures,
            'connection_failures': self.connection_failures,
            'last_store_time': self.last_store_time,
            'last_trim_time': self.last_trim_time,
        }


class TrapCache:
    """
    Redis Streams-based trap cache with rolling retention.
    
    Stores traps in per-destination streams for efficient querying
    and replay. Non-blocking - cache failures don't affect forwarding.
    
    Thread-safe for concurrent access from multiple worker threads.
    """
    
    def __init__(self, config: CacheConfig):
        """
        Initialize the trap cache.
        
        Args:
            config: Cache configuration
        """
        self.config = config
        self._client: Optional['redis.Redis'] = None
        self._lock = threading.Lock()
        self._connected = False
        self._stats = CacheStats()
        self._last_connection_attempt = 0
        self._connection_retry_interval = 30.0  # Retry connection every 30s
    
    def connect(self) -> bool:
        """
        Establish Redis connection.
        
        Returns:
            True if connection successful, False otherwise
        """
        if not REDIS_AVAILABLE:
            logger.warning("Redis package not installed - cache disabled")
            return False
        
        if not self.config.enabled:
            logger.debug("Cache not enabled in configuration")
            return False
        
        with self._lock:
            try:
                self._client = redis.Redis(
                    host=self.config.host,
                    port=self.config.port,
                    password=self.config.password,
                    db=self.config.db,
                    socket_timeout=self.config.socket_timeout,
                    socket_connect_timeout=self.config.socket_connect_timeout,
                    decode_responses=True,
                    retry_on_timeout=True
                )
                
                # Test connection
                self._client.ping()
                self._connected = True
                logger.info(f"Connected to Redis cache at {self.config.host}:{self.config.port}")
                return True
                
            except Exception as e:
                logger.warning(f"Redis connection failed: {e} - caching disabled")
                self._client = None
                self._connected = False
                self._stats.connection_failures += 1
                return False
    
    def _ensure_connected(self) -> bool:
        """
        Ensure Redis connection is active, with rate-limited reconnection.
        
        Returns:
            True if connected, False otherwise
        """
        if self._connected and self._client:
            try:
                self._client.ping()
                return True
            except Exception:
                self._connected = False
        
        # Rate limit reconnection attempts
        now = time.time()
        if now - self._last_connection_attempt < self._connection_retry_interval:
            return False
        
        self._last_connection_attempt = now
        return self.connect()
    
    @property
    def available(self) -> bool:
        """Check if cache is available for operations."""
        return self._connected and self._client is not None
    
    def _stream_key(self, destination: str) -> str:
        """Generate stream key for destination."""
        return f"{self.config.key_prefix}:{destination}"
    
    def store(self, destination: str, trap_data: Dict[str, Any]) -> Optional[str]:
        """
        Store trap in cache. Non-blocking - failures don't affect forwarding.
        
        Args:
            destination: Destination identifier (e.g., "voice_noc")
            trap_data: Dict with trap details:
                - timestamp: ISO format timestamp
                - source_ip: Source IP address
                - trap_oid: Trap OID (optional)
                - pdu_base64: Base64 encoded PDU
                
        Returns:
            Stream entry ID if successful, None otherwise
        """
        if not self._ensure_connected():
            return None
        
        try:
            # Prepare entry data
            entry = {
                'ts': trap_data.get('timestamp', datetime.now().isoformat()),
                'src': trap_data.get('source_ip', ''),
                'oid': trap_data.get('trap_oid', ''),
                'pdu': trap_data.get('pdu_base64', ''),
            }
            
            # Add to stream with maxlen safety cap
            entry_id = self._client.xadd(
                self._stream_key(destination),
                entry,
                maxlen=self.config.max_entries_per_stream,
                approximate=True
            )
            
            self._stats.entries_stored += 1
            self._stats.last_store_time = time.time()
            
            return entry_id
            
        except Exception as e:
            logger.debug(f"Cache store failed: {e}")
            self._stats.store_failures += 1
            self._connected = False  # Mark for reconnection
            return None
    
    def query_range(self, destination: str, 
                    start: datetime, end: datetime,
                    count: Optional[int] = None) -> Iterator[Dict[str, Any]]:
        """
        Query traps in a time range.
        
        Args:
            destination: Destination to query
            start: Start of time range
            end: End of time range
            count: Maximum entries to return (None for all)
            
        Yields:
            Trap entries with id, timestamp, source_ip, trap_oid, pdu_base64
        """
        if not self._ensure_connected():
            return
        
        try:
            # Convert datetimes to Redis stream IDs (millisecond timestamps)
            start_ms = int(start.timestamp() * 1000)
            end_ms = int(end.timestamp() * 1000)
            
            # Query the stream
            if count:
                entries = self._client.xrange(
                    self._stream_key(destination),
                    min=start_ms,
                    max=end_ms,
                    count=count
                )
            else:
                entries = self._client.xrange(
                    self._stream_key(destination),
                    min=start_ms,
                    max=end_ms
                )
            
            for entry_id, fields in entries:
                yield {
                    'id': entry_id,
                    'timestamp': fields.get('ts', ''),
                    'source_ip': fields.get('src', ''),
                    'trap_oid': fields.get('oid', ''),
                    'pdu_base64': fields.get('pdu', ''),
                }
                
        except Exception as e:
            logger.warning(f"Cache query failed: {e}")
            self._connected = False
    
    def count_range(self, destination: str, 
                    start: datetime, end: datetime) -> int:
        """
        Count traps in a time range.
        
        Args:
            destination: Destination to query
            start: Start of time range
            end: End of time range
            
        Returns:
            Number of entries in range
        """
        if not self._ensure_connected():
            return 0
        
        try:
            start_ms = int(start.timestamp() * 1000)
            end_ms = int(end.timestamp() * 1000)
            
            # Use XRANGE with COUNT to efficiently count
            # For large ranges, this iterates in chunks
            count = 0
            cursor = str(start_ms)
            
            while True:
                entries = self._client.xrange(
                    self._stream_key(destination),
                    min=cursor,
                    max=end_ms,
                    count=10000
                )
                
                if not entries:
                    break
                
                count += len(entries)
                
                # Move cursor past last entry
                last_id = entries[-1][0]
                # Increment the sequence part of the ID
                parts = last_id.split('-')
                if len(parts) == 2:
                    cursor = f"{parts[0]}-{int(parts[1]) + 1}"
                else:
                    break
            
            return count
            
        except Exception as e:
            logger.warning(f"Cache count failed: {e}")
            return 0
    
    def get_destinations(self) -> List[str]:
        """
        Get all destination IDs with cached data.
        
        Returns:
            List of destination identifiers
        """
        if not self._ensure_connected():
            return []
        
        try:
            pattern = f"{self.config.key_prefix}:*"
            keys = self._client.keys(pattern)
            prefix_len = len(self.config.key_prefix) + 1
            return [k[prefix_len:] for k in keys]
            
        except Exception as e:
            logger.warning(f"Failed to get destinations: {e}")
            return []
    
    def get_stream_info(self, destination: str) -> Optional[Dict[str, Any]]:
        """
        Get information about a destination's stream.
        
        Args:
            destination: Destination to query
            
        Returns:
            Dict with length, first_entry, last_entry, memory_bytes
        """
        if not self._ensure_connected():
            return None
        
        try:
            key = self._stream_key(destination)
            
            # Get stream length
            length = self._client.xlen(key)
            
            if length == 0:
                return {
                    'length': 0,
                    'first_entry': None,
                    'last_entry': None,
                    'memory_bytes': 0,
                }
            
            # Get first and last entries
            first = self._client.xrange(key, count=1)
            last = self._client.xrevrange(key, count=1)
            
            # Get memory usage
            try:
                memory = self._client.memory_usage(key) or 0
            except Exception:
                memory = 0
            
            first_ts = None
            last_ts = None
            
            if first:
                first_ts = first[0][1].get('ts')
            if last:
                last_ts = last[0][1].get('ts')
            
            return {
                'length': length,
                'first_entry': first_ts,
                'last_entry': last_ts,
                'memory_bytes': memory,
            }
            
        except Exception as e:
            logger.warning(f"Failed to get stream info: {e}")
            return None
    
    def trim_old_entries(self, destination: Optional[str] = None) -> Dict[str, int]:
        """
        Remove entries older than retention period.
        
        Args:
            destination: Specific destination, or None for all
            
        Returns:
            Dict of {destination: entries_removed}
        """
        if not self._ensure_connected():
            return {}
        
        cutoff = datetime.now() - timedelta(hours=self.config.retention_hours)
        cutoff_ms = int(cutoff.timestamp() * 1000)
        results = {}
        
        destinations = [destination] if destination else self.get_destinations()
        
        for dest in destinations:
            try:
                key = self._stream_key(dest)
                
                # Get count before trim for reporting
                before_len = self._client.xlen(key)
                
                if before_len == 0:
                    results[dest] = 0
                    continue
                
                # Try XTRIM with MINID (Redis 6.2+ / redis-py 4.0+)
                try:
                    # Format: XTRIM key MINID ~ threshold
                    self._client.execute_command(
                        'XTRIM', key, 'MINID', '~', str(cutoff_ms)
                    )
                except Exception as e:
                    # Fallback: manually delete old entries
                    logger.debug(f"XTRIM MINID not supported, using fallback: {e}")
                    self._trim_fallback(key, cutoff_ms)
                
                after_len = self._client.xlen(key)
                removed = before_len - after_len
                
                if removed > 0:
                    logger.debug(f"Trimmed {removed} entries from {dest}")
                
                results[dest] = removed
                self._stats.entries_trimmed += removed
                
            except Exception as e:
                logger.warning(f"Trim failed for {dest}: {e}")
                self._stats.trim_failures += 1
                results[dest] = 0
        
        self._stats.last_trim_time = time.time()
        
        if sum(results.values()) > 0:
            logger.info(f"Cache retention trim: removed {sum(results.values())} expired entries")
        
        return results
    
    def _trim_fallback(self, key: str, cutoff_ms: int):
        """
        Fallback trim method for older Redis versions.
        Deletes entries older than cutoff by ID range.
        Loops until all old entries are removed.
        
        Args:
            key: Stream key
            cutoff_ms: Cutoff timestamp in milliseconds
        """
        total_deleted = 0
        batch_size = 10000
        
        while True:
            try:
                # Get batch of entries older than cutoff
                old_entries = self._client.xrange(key, min='-', max=str(cutoff_ms), count=batch_size)
                
                if not old_entries:
                    break  # No more old entries
                
                # Delete the old entries by ID
                ids_to_delete = [entry[0] for entry in old_entries]
                if ids_to_delete:
                    self._client.xdel(key, *ids_to_delete)
                    total_deleted += len(ids_to_delete)
                
                # If we got fewer than batch_size, we're done
                if len(old_entries) < batch_size:
                    break
                    
            except Exception as e:
                logger.warning(f"Fallback trim batch failed: {e}")
                break
        
        if total_deleted > 0:
            logger.debug(f"Fallback trim removed {total_deleted} entries from {key}")
    
    def clear_destination(self, destination: str) -> bool:
        """
        Clear all cached entries for a destination.
        
        Args:
            destination: Destination to clear
            
        Returns:
            True if successful
        """
        if not self._ensure_connected():
            return False
        
        try:
            self._client.delete(self._stream_key(destination))
            logger.info(f"Cleared cache for destination: {destination}")
            return True
        except Exception as e:
            logger.warning(f"Failed to clear cache for {destination}: {e}")
            return False
    
    def clear_all(self) -> bool:
        """
        Clear all cached entries.
        
        Returns:
            True if successful
        """
        if not self._ensure_connected():
            return False
        
        try:
            destinations = self.get_destinations()
            for dest in destinations:
                self._client.delete(self._stream_key(dest))
            logger.info(f"Cleared cache for all {len(destinations)} destinations")
            return True
        except Exception as e:
            logger.warning(f"Failed to clear all cache: {e}")
            return False
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get comprehensive cache statistics.
        
        Returns:
            Dict with connection status, per-destination stats, operation stats
        """
        stats = {
            'available': self.available,
            'config': {
                'host': self.config.host,
                'port': self.config.port,
                'retention_hours': self.config.retention_hours,
            },
            'operations': self._stats.to_dict(),
            'destinations': {},
        }
        
        if self.available:
            for dest in self.get_destinations():
                info = self.get_stream_info(dest)
                if info:
                    stats['destinations'][dest] = info
        
        return stats
    
    def shutdown(self):
        """Close Redis connection and clean up resources."""
        with self._lock:
            if self._client:
                try:
                    self._client.close()
                except Exception:
                    pass
                self._client = None
            self._connected = False
        logger.info("Cache connection closed")


class RetentionManager:
    """
    Background thread for periodic retention trimming.
    
    Runs at configurable intervals to remove entries older than
    the retention window. Supports hot-reload of configuration.
    """
    
    def __init__(self, cache: TrapCache, interval: int = 60):
        """
        Initialize retention manager.
        
        Args:
            cache: TrapCache instance to manage
            interval: Trim interval in seconds
        """
        self.cache = cache
        self.interval = interval
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._config_file = None
        self._config_mtime = 0
    
    def set_config_file(self, path: str):
        """Set the config file path for hot-reload monitoring."""
        self._config_file = path
        try:
            if os.path.exists(path):
                self._config_mtime = os.path.getmtime(path)
        except Exception:
            pass
    
    def _check_config_reload(self) -> bool:
        """
        Check if config file has changed and reload if needed.
        
        Returns:
            True if config was reloaded
        """
        if not self._config_file or not os.path.exists(self._config_file):
            return False
        
        try:
            current_mtime = os.path.getmtime(self._config_file)
            if current_mtime != self._config_mtime:
                # Config file changed - reload it
                with open(self._config_file, 'r') as f:
                    data = json.load(f)
                
                # Update retention hours
                old_retention = self.cache.config.retention_hours
                new_retention = data.get('retention_hours', old_retention)
                
                if new_retention != old_retention:
                    self.cache.config.retention_hours = new_retention
                    logger.info(f"Cache config reloaded: retention_hours changed from {old_retention} to {new_retention} hours")
                
                # Update trim interval
                old_interval = self.interval
                new_interval = data.get('trim_interval_seconds', old_interval)
                
                if new_interval != old_interval:
                    self.interval = new_interval
                    logger.info(f"Cache config reloaded: trim_interval changed from {old_interval} to {new_interval} seconds")
                
                self._config_mtime = current_mtime
                return True
                
        except Exception as e:
            logger.warning(f"Failed to reload cache config: {e}")
        
        return False
    
    def start(self):
        """Start the retention trimmer background thread."""
        if self._thread and self._thread.is_alive():
            return
        
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._trim_loop,
            daemon=True,
            name="CacheRetentionTrimmer"
        )
        self._thread.start()
        logger.info(f"Cache retention trimmer started (interval: {self.interval}s)")
    
    def stop(self):
        """Stop the retention trimmer."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5.0)
        logger.info("Cache retention trimmer stopped")
    
    def _trim_loop(self):
        """Background trim loop."""
        logger.info("Retention trim loop starting")
        
        while not self._stop_event.is_set():
            try:
                # Wait for interval or stop signal
                if self._stop_event.wait(timeout=self.interval):
                    break
                
                # Check for config changes before each trim
                self._check_config_reload()
                
                # Perform trim
                if self.cache.available:
                    logger.debug("Running retention trim...")
                    results = self.cache.trim_old_entries()
                    total_removed = sum(results.values())
                    if total_removed > 0:
                        logger.info(f"Retention trim: removed {total_removed} expired entries")
                    else:
                        logger.debug("Retention trim: no expired entries")
                else:
                    logger.debug("Retention trim skipped: cache not available")
                        
            except Exception as e:
                logger.warning(f"Retention trim error: {e}")


# =============================================================================
# GLOBAL CACHE INSTANCE
# =============================================================================

_cache_instance: Optional[TrapCache] = None
_retention_manager: Optional[RetentionManager] = None
_cache_lock = threading.Lock()


def get_cache() -> Optional[TrapCache]:
    """
    Get the global cache instance.
    
    Returns:
        TrapCache instance or None if not initialized
    """
    return _cache_instance


def initialize_cache(config: CacheConfig, config_file: Optional[str] = None) -> Optional[TrapCache]:
    """
    Initialize the global cache instance.
    
    Args:
        config: Cache configuration
        config_file: Path to config file for hot-reload support
        
    Returns:
        TrapCache instance if successful, None otherwise
    """
    global _cache_instance, _retention_manager
    
    with _cache_lock:
        if _cache_instance is not None:
            logger.warning("Cache already initialized")
            return _cache_instance
        
        if not config.enabled:
            logger.info("Cache not enabled in configuration")
            return None
        
        if not REDIS_AVAILABLE:
            logger.warning("Redis package not installed - cache disabled")
            logger.info("To enable caching, install: pip install redis --break-system-packages")
            return None
        
        cache = TrapCache(config)
        
        if cache.connect():
            _cache_instance = cache
            
            # Start retention trimmer
            _retention_manager = RetentionManager(
                cache,
                interval=config.trim_interval_seconds
            )
            
            # Set config file path for hot-reload
            if config_file:
                _retention_manager.set_config_file(config_file)
                logger.info(f"Cache config hot-reload enabled: {config_file}")
            
            _retention_manager.start()
            
            logger.info(f"Cache initialized with {config.retention_hours}h retention")
            return cache
        else:
            logger.warning("Failed to initialize cache - continuing without caching")
            return None


def shutdown_cache():
    """Shutdown the global cache instance and retention manager."""
    global _cache_instance, _retention_manager
    
    with _cache_lock:
        if _retention_manager:
            _retention_manager.stop()
            _retention_manager = None
        
        if _cache_instance:
            _cache_instance.shutdown()
            _cache_instance = None
    
    logger.info("Cache shutdown complete")
