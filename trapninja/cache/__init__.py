#!/usr/bin/env python3
"""
TrapNinja Cache Module

Provides Redis-based trap caching with rolling retention for replay
during monitoring system outages.

Components:
- TrapCache: Redis Streams-based cache with automatic retention
- ReplayEngine: Time-window based trap replay with rate limiting
- RetentionManager: Background trimmer for rolling retention window

Usage:
    from trapninja.cache import TrapCache, ReplayEngine, get_cache
    
    # Get the global cache instance
    cache = get_cache()
    
    # Store a trap
    cache.store("voice_noc", {
        "timestamp": "2025-01-15T14:32:15.123Z",
        "source_ip": "10.1.2.3",
        "trap_oid": "1.3.6.1.4.1.9.9.41.2.0.1",
        "pdu_base64": "<base64 encoded PDU>"
    })
    
    # Replay traps for a time window
    engine = ReplayEngine(cache)
    engine.replay("voice_noc", start_dt, end_dt, rate_limit=500)
"""

__all__ = [
    'TrapCache',
    'ReplayEngine',
    'RetentionManager',
    'get_cache',
    'initialize_cache',
    'shutdown_cache',
    'CacheConfig',
]

from .redis_backend import (
    TrapCache,
    RetentionManager,
    get_cache,
    initialize_cache,
    shutdown_cache,
    CacheConfig,
)

from .replay import ReplayEngine
