#!/usr/bin/env python3
"""
TrapNinja Failover Tracker

Tracks trap forwarding timestamps in Redis for gap detection during failover.
Uses Redis for cross-node visibility and atomic operations.

The tracker stores:
- Last forwarded timestamp per destination
- Node heartbeat timestamps
- Forwarding statistics for gap analysis

Author: TrapNinja Team
Version: 1.0.0
"""

import time
import logging
import threading
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List

logger = logging.getLogger("trapninja")


class FailoverTracker:
    """
    Tracks forwarding timestamps in Redis for failover gap detection.
    
    Stores per-destination timestamps with minimal overhead on the hot path.
    Uses Redis atomic operations for cross-node consistency.
    
    Keys used:
        trapninja:failover:last_forwarded:{dest} - Last forwarded timestamp
        trapninja:failover:node:{instance_id} - Node heartbeat
        trapninja:failover:active_node - Currently active node
    """
    
    KEY_PREFIX = "trapninja:failover"
    LAST_FORWARDED_KEY = f"{KEY_PREFIX}:last_forwarded"
    NODE_HEARTBEAT_KEY = f"{KEY_PREFIX}:node"
    ACTIVE_NODE_KEY = f"{KEY_PREFIX}:active_node"
    FORWARDING_STATS_KEY = f"{KEY_PREFIX}:stats"
    
    def __init__(self, redis_client, instance_id: str):
        """
        Initialize failover tracker.
        
        Args:
            redis_client: Redis client instance
            instance_id: Unique identifier for this TrapNinja instance
        """
        self._client = redis_client
        self._instance_id = instance_id
        self._lock = threading.Lock()
        self._batch_buffer: Dict[str, float] = {}
        self._batch_interval = 0.5  # Batch updates every 500ms
        self._last_batch_time = 0.0
        self._stats_window = 60  # 1 minute stats window
        
    @property
    def instance_id(self) -> str:
        """Get instance ID."""
        return self._instance_id
    
    def update_last_forwarded(self, destination: str, timestamp: Optional[float] = None):
        """
        Update last forwarded timestamp for a destination.
        
        Batches updates for performance - actual Redis write happens 
        when batch interval expires or on explicit flush.
        
        Args:
            destination: Destination identifier
            timestamp: Unix timestamp (default: current time)
        """
        ts = timestamp or time.time()
        
        with self._lock:
            self._batch_buffer[destination] = ts
            
            # Check if we should flush
            now = time.time()
            if now - self._last_batch_time >= self._batch_interval:
                self._flush_batch()
    
    def _flush_batch(self):
        """Flush batched timestamp updates to Redis."""
        if not self._batch_buffer:
            return
        
        try:
            pipe = self._client.pipeline(transaction=False)
            
            for dest, ts in self._batch_buffer.items():
                key = f"{self.LAST_FORWARDED_KEY}:{dest}"
                # Use HSET for efficient multi-field storage
                pipe.hset(key, mapping={
                    'timestamp': ts,
                    'node_id': self._instance_id,
                    'updated_at': time.time()
                })
                # Expire after 4 hours (2x retention window)
                pipe.expire(key, 14400)
            
            pipe.execute()
            self._batch_buffer.clear()
            self._last_batch_time = time.time()
            
        except Exception as e:
            logger.debug(f"Failover tracker batch flush failed: {e}")
    
    def flush(self):
        """Force flush any pending updates."""
        with self._lock:
            self._flush_batch()
    
    def get_last_forwarded(self, destination: str) -> Optional[float]:
        """
        Get last forwarded timestamp for a destination.
        
        Args:
            destination: Destination identifier
            
        Returns:
            Unix timestamp or None if not found
        """
        try:
            key = f"{self.LAST_FORWARDED_KEY}:{destination}"
            data = self._client.hgetall(key)
            
            if data and 'timestamp' in data:
                return float(data['timestamp'])
            return None
            
        except Exception as e:
            logger.warning(f"Failed to get last forwarded timestamp: {e}")
            return None
    
    def get_all_last_forwarded(self) -> Dict[str, float]:
        """
        Get last forwarded timestamps for all destinations.
        
        Returns:
            Dict of {destination: timestamp}
        """
        try:
            # Find all destination keys
            pattern = f"{self.LAST_FORWARDED_KEY}:*"
            keys = self._client.keys(pattern)
            
            if not keys:
                return {}
            
            result = {}
            prefix_len = len(self.LAST_FORWARDED_KEY) + 1
            
            pipe = self._client.pipeline(transaction=False)
            for key in keys:
                pipe.hgetall(key)
            
            responses = pipe.execute()
            
            for key, data in zip(keys, responses):
                if data and 'timestamp' in data:
                    dest = key[prefix_len:] if isinstance(key, str) else key.decode()[prefix_len:]
                    result[dest] = float(data['timestamp'])
            
            return result
            
        except Exception as e:
            logger.warning(f"Failed to get all last forwarded timestamps: {e}")
            return {}
    
    def get_forwarding_info(self, destination: str) -> Optional[Dict[str, Any]]:
        """
        Get detailed forwarding info for a destination.
        
        Args:
            destination: Destination identifier
            
        Returns:
            Dict with timestamp, node_id, updated_at or None
        """
        try:
            key = f"{self.LAST_FORWARDED_KEY}:{destination}"
            data = self._client.hgetall(key)
            
            if not data:
                return None
            
            return {
                'timestamp': float(data.get('timestamp', 0)),
                'node_id': data.get('node_id', ''),
                'updated_at': float(data.get('updated_at', 0)),
            }
            
        except Exception as e:
            logger.warning(f"Failed to get forwarding info: {e}")
            return None
    
    def set_active_node(self, is_active: bool = True):
        """
        Mark this node as the active forwarding node.
        
        Args:
            is_active: Whether this node is actively forwarding
        """
        try:
            if is_active:
                self._client.setex(
                    self.ACTIVE_NODE_KEY,
                    300,  # 5 minute expiry
                    self._instance_id
                )
                logger.debug(f"Set active node: {self._instance_id[:8]}...")
            else:
                # Only delete if we are the active node
                current = self._client.get(self.ACTIVE_NODE_KEY)
                if current and current == self._instance_id:
                    self._client.delete(self.ACTIVE_NODE_KEY)
                    logger.debug(f"Cleared active node")
                    
        except Exception as e:
            logger.warning(f"Failed to set active node: {e}")
    
    def get_active_node(self) -> Optional[str]:
        """
        Get the currently active node ID.
        
        Returns:
            Instance ID of active node or None
        """
        try:
            return self._client.get(self.ACTIVE_NODE_KEY)
        except Exception as e:
            logger.warning(f"Failed to get active node: {e}")
            return None
    
    def record_node_heartbeat(self):
        """Record a heartbeat for this node."""
        try:
            key = f"{self.NODE_HEARTBEAT_KEY}:{self._instance_id}"
            self._client.setex(key, 60, time.time())  # 60 second expiry
        except Exception as e:
            logger.debug(f"Failed to record node heartbeat: {e}")
    
    def get_peer_last_heartbeat(self, peer_id: str) -> Optional[float]:
        """
        Get the last heartbeat timestamp for a peer node.
        
        Args:
            peer_id: Instance ID of peer node
            
        Returns:
            Unix timestamp or None
        """
        try:
            key = f"{self.NODE_HEARTBEAT_KEY}:{peer_id}"
            value = self._client.get(key)
            return float(value) if value else None
        except Exception as e:
            logger.debug(f"Failed to get peer heartbeat: {e}")
            return None
    
    def record_forwarding_stat(self, destination: str, trap_count: int = 1):
        """
        Record forwarding statistics for analysis.
        
        Uses Redis time-series-like structure with minute buckets.
        
        Args:
            destination: Destination identifier
            trap_count: Number of traps forwarded
        """
        try:
            # Bucket key based on current minute
            bucket = int(time.time() / 60) * 60
            key = f"{self.FORWARDING_STATS_KEY}:{destination}:{bucket}"
            
            pipe = self._client.pipeline(transaction=False)
            pipe.incrby(key, trap_count)
            pipe.expire(key, 3600)  # Keep for 1 hour
            pipe.execute()
            
        except Exception as e:
            logger.debug(f"Failed to record forwarding stat: {e}")
    
    def get_forwarding_rate(self, destination: str, 
                           window_seconds: int = 60) -> float:
        """
        Get average forwarding rate for a destination.
        
        Args:
            destination: Destination identifier
            window_seconds: Time window for average
            
        Returns:
            Traps per second
        """
        try:
            now = int(time.time())
            start_bucket = ((now - window_seconds) // 60) * 60
            
            total = 0
            buckets_checked = 0
            
            for bucket in range(start_bucket, now + 60, 60):
                key = f"{self.FORWARDING_STATS_KEY}:{destination}:{bucket}"
                value = self._client.get(key)
                if value:
                    total += int(value)
                buckets_checked += 1
            
            if buckets_checked == 0:
                return 0.0
            
            return total / window_seconds
            
        except Exception as e:
            logger.debug(f"Failed to get forwarding rate: {e}")
            return 0.0
    
    def get_status(self) -> Dict[str, Any]:
        """Get tracker status for monitoring."""
        try:
            all_timestamps = self.get_all_last_forwarded()
            active_node = self.get_active_node()
            
            return {
                'instance_id': self._instance_id,
                'is_active': active_node == self._instance_id,
                'active_node': active_node,
                'destinations': {
                    dest: {
                        'last_forwarded': ts,
                        'age_seconds': time.time() - ts
                    }
                    for dest, ts in all_timestamps.items()
                },
                'pending_updates': len(self._batch_buffer),
            }
            
        except Exception as e:
            return {
                'instance_id': self._instance_id,
                'error': str(e)
            }
    
    def cleanup(self):
        """Cleanup on shutdown."""
        # Flush any pending updates
        self.flush()
        
        # Clear active node if we are active
        self.set_active_node(False)
