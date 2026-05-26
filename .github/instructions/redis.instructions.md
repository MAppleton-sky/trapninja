---
applyTo: "src/trapninja/cache/**"
---

# Cache — Redis 5.0.3 Compatibility Rules

## Production Redis Version

Production runs **Redis 5.0.3 on RHEL 8**. This is a hard constraint that cannot change without a major infrastructure effort. Write all Redis code against 5.0.3 semantics.

## Stream Trimming — Critical

`XTRIM stream MINID timestamp` is **Redis 6.2+ only**. Never use it. It will raise `ResponseError` at runtime in production but may work fine in dev/test environments running newer Redis.

Always use the `XRANGE` + `XDEL` pattern:

```python
# CORRECT for Redis 5.0.3
def trim_stream(self, stream_key: str, cutoff_id: str) -> None:
    entries = self._redis.xrange(stream_key, min='-', max=cutoff_id)
    if entries:
        ids = [entry[0] for entry in entries]
        self._redis.xdel(stream_key, *ids)

# WRONG — Redis 6.2+ only, fails silently until production
self._redis.xtrim(stream_key, minid=cutoff_id)
```

Trim frequently (every 30–60 seconds) to keep the `XRANGE` result set small — this operation is O(N) where N is entries being deleted.

## Cache Write Placement

Traps are written to the Redis cache **before** forwarding confirmation. This is intentional — it ensures the cache can replay if the forwarding acknowledgement is uncertain.

## Failure Handling

Redis unavailability must **never** stop trap forwarding:

```python
try:
    self._write_to_cache(trap)
except redis.RedisError as e:
    logger.warning("Cache write failed, continuing: %s", e)
    self._stats.increment_cache_miss()
    # forwarding continues regardless
```

A background reconnect thread handles Redis reconnection with exponential backoff. The cache miss rate is exposed as a Prometheus metric.

## No Blocking on Forwarding Thread

Redis writes from the forwarding thread must use fire-and-forget or pipeline patterns. Never make a synchronous blocking Redis call on the forwarding thread. If writes must be synchronous, move them to a background worker with a bounded queue.

## Stream Key Schema

Do not change the Redis stream key schema without considering the HA failover implications. The Secondary reads from the Primary's cached stream on promotion — a key schema change breaks replay during rolling upgrades.
