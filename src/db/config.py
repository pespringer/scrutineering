"""Database URL configuration with explicit production and test modes."""

from __future__ import annotations

import os

TEST_DATABASE_URL = "sqlite+pysqlite:///:memory:"


def get_database_url(*environment_names: str) -> str:
    """Return a configured database URL or fail closed."""
    for name in environment_names:
        value = os.environ.get(name, "").strip()
        if value:
            return value

    if os.environ.get("SCRUTINEERING_TEST_MODE") == "1":
        return TEST_DATABASE_URL

    names = ", ".join(environment_names)
    raise RuntimeError(
        f"A database URL must be configured via {names}; refusing an insecure default"
    )


def get_async_database_url(sync_url: str) -> str:
    """Derive the async SQLAlchemy URL for a configured sync URL."""
    explicit = os.environ.get("ASYNC_DATABASE_URL", "").strip()
    if explicit:
        return explicit

    return (
        sync_url.replace("postgresql+psycopg2://", "postgresql+asyncpg://", 1)
        .replace("postgresql://", "postgresql+asyncpg://", 1)
        .replace("sqlite+pysqlite://", "sqlite+aiosqlite://", 1)
    )
