#!/usr/bin/env python3
"""
TrapNinja Configuration Cache

Thread-safe configuration cache with TTL for hot-path packet processing.
Reduces import and dict access overhead by caching frequently-accessed
configuration values with a 30-second refresh interval.

IMPORTANT: Imports the config MODULE (not variables) to avoid stale
references when load_config() reassigns module-level variables.
"""

import time
import logging
import threading
from typing import Dict

logger = logging.getLogger("trapninja")


class ConfigCache:
    """
    Thread-safe configuration cache with TTL.

    Caches flattened configuration dict from the config module with a
    configurable time-to-live. Thread-safe via a simple lock to prevent
    multiple workers from refreshing simultaneously.

    Attributes:
        ttl: Cache time-to-live in seconds (default: 30.0)
    """

    def __init__(self, ttl: float = 30.0):
        self._ttl = ttl
        self._cache: Dict = {}
        self._last_refresh: float = 0
        self._lock = threading.Lock()

    def get(self) -> Dict:
        """
        Get cached configuration, refreshing if stale.

        Returns:
            Dict with keys: destinations, blocked_ips, blocked_traps,
            blocked_dest, redirected_ips, redirected_oids,
            redirected_destinations
        """
        now = time.time()

        if now - self._last_refresh > self._ttl or not self._cache:
            with self._lock:
                # Double-check after acquiring lock (another thread may have refreshed)
                if now - self._last_refresh > self._ttl or not self._cache:
                    self._refresh()

        return self._cache

    def _refresh(self):
        """Refresh the configuration cache from the config module."""
        try:
            from .. import config as cfg

            self._cache = {
                'destinations': getattr(cfg, 'destinations', []),
                'blocked_ips': getattr(cfg, 'blocked_ips', set()),
                'blocked_ip_ranges': getattr(cfg, 'blocked_ip_ranges', []),
                'blocked_traps': getattr(cfg, 'blocked_traps', set()),
                'blocked_dest': getattr(cfg, 'blocked_dest', None),
                'redirected_ips': getattr(cfg, 'redirected_ips', {}),
                'redirected_ip_ranges': getattr(cfg, 'redirected_ip_ranges', []),
                'redirected_oids': getattr(cfg, 'redirected_oids', {}),
                'redirected_destinations': getattr(cfg, 'redirected_destinations', {}),
            }
            self._last_refresh = time.time()

            # Safety check: warn if no destinations are configured
            # This is a critical operational signal — traps will be
            # processed but silently not forwarded anywhere
            dest_count = len(self._cache['destinations'])
            if dest_count == 0:
                logger.warning(
                    "Config cache refresh: NO destinations configured — "
                    "traps will be processed but NOT forwarded"
                )
            else:
                logger.debug(
                    f"Config cache refreshed: {dest_count} destination(s), "
                    f"{len(self._cache['blocked_ips'])} blocked IPs, "
                    f"{len(self._cache['blocked_ip_ranges'])} blocked IP ranges, "
                    f"{len(self._cache['blocked_traps'])} blocked traps"
                )

        except Exception as e:
            logger.warning(f"Config cache refresh failed: {e}")
            if not self._cache:
                # Provide safe defaults on first load failure
                self._cache = {
                    'destinations': [],
                    'blocked_ips': set(),
                    'blocked_ip_ranges': [],
                    'blocked_traps': set(),
                    'blocked_dest': None,
                    'redirected_ips': {},
                    'redirected_ip_ranges': [],
                    'redirected_oids': {},
                    'redirected_destinations': {},
                }

    def invalidate(self):
        """Force cache refresh on next access."""
        self._last_refresh = 0


# Module-level singleton used by all workers
_config_cache = ConfigCache()


def get_config_cache() -> ConfigCache:
    """Get the module-level configuration cache singleton."""
    return _config_cache
