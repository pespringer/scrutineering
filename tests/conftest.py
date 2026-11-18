"""Shared test configuration."""

import os
from datetime import datetime, timezone

import pytest

# Production code refuses implicit database credentials. Tests explicitly opt
# into an in-memory SQLite engine before application modules are imported.
os.environ.setdefault("SCRUTINEERING_TEST_MODE", "1")


def _register_postgres_functions(dbapi_connection, _record):
    """SQLite stand-ins for the Postgres functions the schema's CHECKs and defaults use."""
    dbapi_connection.create_function("char_length", 1, lambda value: len(value) if value is not None else None)
    dbapi_connection.create_function(
        "now", 0, lambda: datetime.now(timezone.utc).replace(tzinfo=None).strftime("%Y-%m-%d %H:%M:%S.%f")
    )
    dbapi_connection.execute("PRAGMA foreign_keys=ON")


@pytest.fixture(autouse=True)
def database():
    """Give every test a fresh, real schema behind `src.db.connection.get_session`."""
    from sqlalchemy import create_engine, event
    from sqlalchemy.pool import StaticPool

    import src.db.connection as connection
    from src.db.models import Base

    engine = create_engine("sqlite+pysqlite://", poolclass=StaticPool, connect_args={"check_same_thread": False})
    event.listen(engine, "connect", _register_postgres_functions)
    Base.metadata.create_all(engine)
    previous = connection.session_factory.kw.get("bind")
    connection.session_factory.configure(bind=engine)
    try:
        yield engine
    finally:
        connection.session_factory.configure(bind=previous)
        engine.dispose()


@pytest.fixture(autouse=True)
def offline_scanning(monkeypatch):
    """Keep worker tests off the network and out of retry sleeps.

    Digest resolution behaves as if the registry were unreachable, so scans run
    by tag unless a test patches `src.scan.tasks.resolve_digest` itself.
    """

    def unreachable(*_args, **_kwargs):
        raise ConnectionError("registry unreachable in tests")

    monkeypatch.setattr("src.scan.tasks.resolve_digest", unreachable)
    monkeypatch.setenv("SCANNER_RETRY_BACKOFF_SECONDS", "0")
    for name in ("REQUIRE_IMMUTABLE_SCAN_IDENTITY", "SCANNER_RETRY_ATTEMPTS", "SCANNER_TIMEOUT"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture(autouse=True)
def discovery_status_store(monkeypatch):
    """An in-memory stand-in for the Redis key that holds the last runtime discovery result."""
    store: dict[str, str] = {}

    class FakeRedis:
        def set(self, key, value, ex=None):
            store[key] = value

        def get(self, key):
            return store.get(key)

    monkeypatch.setattr("src.scan.runtime_discovery._redis", lambda url: FakeRedis())
    return store
