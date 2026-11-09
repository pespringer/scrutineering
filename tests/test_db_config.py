"""Tests for fail-closed database configuration."""

import pytest

from src.db.config import TEST_DATABASE_URL, get_database_url


def test_missing_database_url_fails_closed(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("SCAN_DATABASE_URL", raising=False)
    monkeypatch.delenv("SCRUTINEERING_TEST_MODE", raising=False)

    with pytest.raises(RuntimeError, match="refusing an insecure default"):
        get_database_url("DATABASE_URL", "SCAN_DATABASE_URL")


def test_test_mode_uses_ephemeral_database(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setenv("SCRUTINEERING_TEST_MODE", "1")

    assert get_database_url("DATABASE_URL") == TEST_DATABASE_URL
