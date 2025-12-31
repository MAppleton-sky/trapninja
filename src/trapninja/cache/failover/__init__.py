#!/usr/bin/env python3
"""
TrapNinja Failover Replay Module

Provides automatic gap detection and replay during HA failovers to ensure
zero trap loss even during the few seconds of failover transition.

Components:
- FailoverTracker: Tracks forwarding timestamps in Redis for gap detection
- GapDetector: Detects gaps in trap forwarding after failover
- AutoReplayManager: Automatically replays missed traps during failover

Architecture:
    ┌─────────────────────────────────────────────────────────────────────┐
    │                    FAILOVER REPLAY FLOW                              │
    │                                                                      │
    │  Primary Node (failing)          Secondary Node (taking over)        │
    │  ┌─────────────────────┐        ┌─────────────────────────────┐     │
    │  │ Last trap: T=10:00:05│        │ Becomes PRIMARY at T=10:00:08│     │
    │  │ (stored in Redis)   │        │                             │     │
    │  └─────────────────────┘        │ 1. Read last_forwarded from │     │
    │            │                    │    Redis: T=10:00:05        │     │
    │            ▼                    │ 2. Current time: T=10:00:08 │     │
    │     ┌──────────────┐            │ 3. Gap detected: 3 seconds  │     │
    │     │ Redis Cache  │◄───────────│ 4. Auto-replay from cache   │     │
    │     │ (Traps from  │            │    T=10:00:05 to T=10:00:08 │     │
    │     │ both nodes)  │            └─────────────────────────────┘     │
    │     └──────────────┘                                                 │
    └─────────────────────────────────────────────────────────────────────┘

Usage:
    from trapninja.cache.failover import FailoverReplayManager
    
    # Initialize with cache
    manager = FailoverReplayManager(cache, config)
    
    # Call when becoming PRIMARY
    manager.on_become_primary()
    
    # Update on each forwarded trap (lightweight)
    manager.update_last_forwarded(timestamp)

Author: TrapNinja Team
Version: 1.0.0
"""

__all__ = [
    'FailoverReplayManager',
    'FailoverTracker',
    'GapDetector',
    'FailoverReplayConfig',
    'GapInfo',
]

from .tracker import FailoverTracker
from .detector import GapDetector, GapInfo
from .manager import FailoverReplayManager, FailoverReplayConfig
