"""Database URLs and pool sizes, from `src/config.py`, with explicit production and test modes."""

from __future__ import annotations

from src.config import Settings, get_settings

TEST_DATABASE_URL = "sqlite+pysqlite:///:memory:"


def get_database_url(settings: Settings | None = None) -> str:
    """The configured database URL, or fail closed."""
    settings = settings or get_settings()
    value = settings.database_url.get_secret_value().strip()
    if value:
        if settings.node_env == "production" and value.startswith("sqlite"):
            raise RuntimeError("production database must not use SQLite")
        return value
    if settings.scrutineering_test_mode:
        return TEST_DATABASE_URL
    raise RuntimeError("DATABASE_URL must be configured; refusing an insecure default")


def get_async_database_url(sync_url: str, settings: Settings | None = None) -> str:
    """`ASYNC_DATABASE_URL`, or the async SQLAlchemy URL for the sync one."""
    explicit = (settings or get_settings()).async_database_url.get_secret_value().strip()
    if explicit:
        return explicit
    return (
        sync_url.replace("postgresql+psycopg2://", "postgresql+asyncpg://", 1)
        .replace("postgresql://", "postgresql+asyncpg://", 1)
        .replace("sqlite+pysqlite://", "sqlite+aiosqlite://", 1)
    )


def pool_options(settings: Settings | None = None) -> dict[str, int]:
    """`DB_POOL_SIZE` and `DB_MAX_OVERFLOW` as SQLAlchemy engine options."""
    settings = settings or get_settings()
    return {"pool_size": settings.db_pool_size, "max_overflow": settings.db_max_overflow}
