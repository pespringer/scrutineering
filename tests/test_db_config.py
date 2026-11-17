"""Fail-closed database configuration, read through src/config.py."""

import pytest

from src.config import get_settings
from src.db.config import TEST_DATABASE_URL, get_async_database_url, get_database_url, pool_options


def test_missing_database_url_fails_closed():
    with pytest.raises(RuntimeError, match="refusing an insecure default"):
        get_database_url(get_settings({}))


def test_test_mode_uses_ephemeral_database():
    assert get_database_url(get_settings({"SCRUTINEERING_TEST_MODE": "1"})) == TEST_DATABASE_URL


def test_production_refuses_sqlite():
    settings = get_settings({"DATABASE_URL": "sqlite:///x.db", "NODE_ENV": "production"})
    with pytest.raises(RuntimeError, match="must not use SQLite"):
        get_database_url(settings)


def test_async_url_is_derived_unless_set():
    url = "postgresql+psycopg2://u:p@db/scrutineering"
    assert get_async_database_url(url, get_settings({})) == "postgresql+asyncpg://u:p@db/scrutineering"
    explicit = get_settings({"ASYNC_DATABASE_URL": "postgresql+asyncpg://other/db"})
    assert get_async_database_url(url, explicit) == "postgresql+asyncpg://other/db"


def test_pool_sizes_are_read_and_bounded():
    assert pool_options(get_settings({"DB_POOL_SIZE": "4", "DB_MAX_OVERFLOW": "2"})) == {
        "pool_size": 4,
        "max_overflow": 2,
    }
    with pytest.raises(ValueError, match="DB_POOL_SIZE"):
        get_settings({"DB_POOL_SIZE": "101"})
