# Test Suite — Scoped Rules

> Read `../../CLAUDE.md` for project-wide rules. This file adds **test-specific constraints**.

## Testing Philosophy

Tests exist to validate **current, desired behaviour** — not to preserve historical behaviour
that has been intentionally superseded. When the system changes, tests must change with it.

### Test Evolution Rules
- **Never reintroduce deprecated behaviour** solely to make old tests pass.
- When an intentional behaviour change causes a test failure:
  → Update or replace the test to reflect the new desired behaviour.
  → Explain clearly what changed and why the new test is correct.
- Tests that only enforce removed/deprecated functionality should be deleted with a clear
  commit message explaining why.

### What to Test (Priority Order)
1. **End-to-end trap pipeline** — capture → parse → filter → route → forward
2. **Failure scenarios** — Redis down, network failure, malformed packets, burst overload
3. **HA failover** — promotion, demotion, state machine transitions, split-brain
4. **Security** — credentials never leaked in logs, BER parsing of malformed input
5. **Config validation** — valid, invalid, and boundary configs
6. **Unit logic** — parsing, routing, filtering, retry behaviour

### Test Organisation
```
dev/tests/                 — Primary test suite
  test_impl_*.py           — Implementation/behaviour tests (integration-style unit tests)
  test_integration_*.py    — Full integration tests
  test_cache_*.py          — Cache-specific tests
  test_ha_*.py             — HA module tests
  test_cli_*.py            — CLI tests
  test_snmpv3_*.py         — SNMPv3 credential and decryption tests
  fixtures/                — Shared fixtures (configs, packets, sample data)

tests/unit/                — Additional unit tests
```

### Fixture Rules
- `fixtures/packets.py`: Raw packet bytes for testing — use synthetic packets only.
- `fixtures/configs.py`: Test configurations — must be clearly marked as test data.
- `fixtures/sample_data.py`: Sample trap data — no production credentials or real IPs.
- **Never commit real credentials, real IP addresses, or production config data.**

### SNMPv3 Test Constraints
- Use **synthetic throwaway credentials** in all SNMPv3 tests.
- Assertions must never print, log, or assert the value of auth/priv keys.
- Test decryption failure paths as well as success paths.
- Test passthrough (fallback) behaviour when credentials are unavailable.

### Performance / Load Tests
- Burst load tests must simulate realistic telecom spike scenarios (10k–100k traps/min).
- Stats collection must be verified to not block forwarding under load.
- Queue saturation behaviour: test what happens when the worker queue fills up.

### Mocking Strategy
- Mock Redis at the connection level — never mock internal Redis client methods.
- Mock socket operations for forwarding tests — avoid real network I/O in unit tests.
- Use real BER parsing in SNMPv3 tests — do not mock the ASN.1 parser itself.
- Use `pytest` fixtures and `conftest.py` for shared setup — avoid duplication.

### Running Tests
```bash
# Full suite
cd dev && python -m pytest tests/ -v

# Specific module
python -m pytest tests/test_impl_routing.py -v

# With coverage
python -m pytest tests/ --cov=trapninja --cov-report=term-missing
```
