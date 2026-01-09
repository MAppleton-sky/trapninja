# Cache Integration Fix: Traps Not Being Stored

## Issue

The `trapninja cache status` command reported 0 entries even when traps were being received and forwarded.

## Root Cause

The cache system was properly initialized in `service.py`, but traps were **never actually stored** in the cache.

The cache integration was only implemented in the legacy fallback workers (`_start_legacy_workers` in `network.py`), but the system was using the new high-performance `PacketWorker` class from `processing/worker.py`, which did not have any caching code.

### Code Flow Before Fix

1. ✅ Cache initialized in `service.py` → `initialize_cache()`
2. ✅ Workers started via `start_packet_processors()` → calls `processing.start_workers()`
3. ✅ `PacketWorker` processes traps, forwards them successfully
4. ❌ **No call to `cache.store()` anywhere in the packet processing pipeline**

### Legacy vs New Workers

| Feature | Legacy Workers (`network.py`) | New Workers (`processing/worker.py`) |
|---------|-------------------------------|--------------------------------------|
| Performance | Basic | Optimized (batch processing, config cache) |
| Caching | ✅ Implemented | ❌ **Missing** |
| Used When | Fallback only | **Always** (default) |

## Solution

Added cache integration to `processing/worker.py`:

### 1. Added Cache Imports

```python
# Import cache module for trap buffering
try:
    from ..cache import get_cache
    import base64
    from datetime import datetime
    CACHE_AVAILABLE = True
except ImportError:
    CACHE_AVAILABLE = False
    def get_cache():
        return None
```

### 2. Added Cache Method to PacketWorker

```python
def _store_trap_in_cache(self, source_ip: str, payload: bytes, 
                          trap_oid: str = None, destination: str = 'default'):
    """Store trap in Redis cache for replay capability."""
    if not CACHE_AVAILABLE:
        return
    
    # Lazy initialization of cache reference
    if not self._cache_checked:
        self._cache = get_cache()
        self._cache_checked = True
    
    if not self._cache or not self._cache.available:
        return
    
    try:
        trap_data = {
            'timestamp': datetime.now().isoformat(),
            'source_ip': source_ip,
            'trap_oid': trap_oid or '',
            'pdu_base64': base64.b64encode(payload).decode('ascii'),
        }
        self._cache.store(destination, trap_data)
    except Exception as e:
        # Non-blocking - don't let cache errors affect forwarding
        logger.debug(f"Cache store failed: {e}")
```

### 3. Added Cache Calls to All Forwarding Paths

Cache calls were added to:

- **Fast path (SNMPv2c)**: Default forwarding, IP redirection, OID redirection
- **Slow path (v1/malformed)**: All forwarding paths
- **SNMPv3 path**: Decrypted v2c forwarding, original v3 fallback forwarding
- **HA secondary mode**: Cache traps even when forwarding is disabled (for gap-fill replay)

## Verification

After the fix:

```bash
# Check cache status - should show entries
trapninja cache status

# Example output:
Cache Status
======================================================================
Redis: localhost:6379
Retention: 2.0 hours
Status: Connected

Destination          Entries      Oldest       Newest         Size
----------------------------------------------------------------------
default                1,234     14:32:15     14:45:30      2.1 MB
voice_noc                567     14:33:22     14:44:58      1.1 MB
----------------------------------------------------------------------
Total                  1,801                                3.2 MB
```

## Files Changed

- `src/trapninja/processing/worker.py` - Added cache integration
- `config.example/cache_config.json` - Added example configuration
- `docs/fixes/CACHE_INTEGRATION_FIX.md` - This documentation

## Configuration

Ensure `config/cache_config.json` exists and is enabled:

```json
{
  "enabled": true,
  "host": "localhost",
  "port": 6379,
  "retention_hours": 2.0,
  "trim_interval_seconds": 60
}
```

Ensure Redis is running:

```bash
systemctl status redis
redis-cli ping  # Should return PONG
```

## Related

- [CACHE.md](../CACHE.md) - Full cache system documentation
- [FAILOVER_REPLAY.md](../FAILOVER_REPLAY.md) - Gap-fill replay documentation
