"""Runtime-generated placeholder secrets for tests."""

from secrets import token_urlsafe


def new_test_secret() -> str:
    """Return a disposable random value for a test secret field."""
    return token_urlsafe(32)
