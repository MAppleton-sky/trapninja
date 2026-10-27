"""Runtime-generated placeholder secrets for tests."""

from secrets import token_hex, token_urlsafe


def new_test_secret() -> str:
    """Return a disposable random value for a test secret field."""
    return token_urlsafe(32)


def new_test_username() -> str:
    """Return a disposable, valid-length identifier for credential fixtures."""
    return f"u{token_hex(8)}"
