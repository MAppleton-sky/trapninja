---
applyTo: "dev/tests/**"
---

# Tests — Rules and Patterns

## The Most Common Test Bug in This Project

`unittest.mock.patch` must target the **call site** (where the function is imported and used), not the **definition site** (where the function is originally defined).

```python
# Scenario: forwarder.py does: from trapninja.utils import resolve_oid

# WRONG — patches the definition; forwarder.py still calls the real function
@patch('trapninja.utils.resolve_oid')
def test_something(self, mock_resolve):
    ...  # mock_resolve is never called; real function runs

# CORRECT — patches where forwarder.py imported it
@patch('trapninja.forwarder.forwarder.resolve_oid')
def test_something(self, mock_resolve):
    ...  # mock_resolve is called correctly
```

If a mock isn't being called (`assert_called_once_with` fails unexpectedly), this is almost certainly the cause. Check it first.

## Redis and eBPF — Always Mock in Unit Tests

Never use a live Redis instance or live eBPF in unit tests:

```python
# CORRECT — mock Redis client
@patch('trapninja.cache.trap_cache.redis.Redis')
def test_cache_write(self, mock_redis):
    mock_redis.return_value.xadd.return_value = '1234-0'
    ...

# WRONG — requires live Redis
def test_cache_write(self):
    cache = TrapCache(host='localhost', port=6379)  # fails in CI
    ...
```

## Test Evolution Rule

Tests describe **current intended behaviour**. When behaviour changes intentionally:
- Update or replace the relevant tests
- Do NOT add workarounds to make old tests pass
- Do NOT resurrect removed code paths to satisfy old tests

When in doubt: the production code's current behaviour is the source of truth, not the old test.

## What Good Tests Look Like

```python
def test_dropped_trap_increments_counter_and_logs_warning(self):
    """
    When a trap cannot be forwarded after max retries,
    the failed counter must increment and a WARNING must be logged.
    Silent failure is not acceptable.
    """
    ...
```

Each test should have a docstring explaining what **behaviour** it validates, not what **code** it calls.

## Coverage Expectations

- Test-to-code ratio: ~0.95:1 (approximately one test per line of production code)
- All new code requires corresponding tests
- Critical paths (parsing, routing, filtering, retry) require multiple tests covering happy path, failure path, and edge cases
- HA state transitions require tests for all transition sequences

## Integration vs Unit Test Labelling

If a test requires external infrastructure (Redis, eBPF, network), mark it clearly:

```python
@pytest.mark.integration
def test_redis_replay_on_failover(self):
    ...
```

Integration tests are skipped in CI environments without the required infrastructure.
