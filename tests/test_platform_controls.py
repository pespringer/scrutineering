from datetime import datetime, timezone

import pytest

from src.platform.controls import (
    ProviderPage,
    QueueHealth,
    RetentionPolicy,
    RetryPolicy,
    backup_manifest,
    bounded_output,
    classify_validation_failure,
    guard_changed_files,
    page_bounds,
    parse_retry_after,
    verify_backup,
)


def test_retention_is_opt_in_and_cutoff_is_bounded():
    policy = RetentionPolicy(days=30)
    assert policy.cutoff(datetime(2026, 1, 31, tzinfo=timezone.utc)).day == 1
    assert not policy.can_purge()
    assert RetentionPolicy(days=30, purge_enabled=True, dry_run=False).can_purge()


def test_page_output_and_changed_file_guards():
    assert page_bounds(10, 0) == (10, 0)
    assert bounded_output("abcdef", 3) == "def"
    assert guard_changed_files(["src/b.py", "src/a.py", "src/a.py"]) == ["src/a.py", "src/b.py"]
    with pytest.raises(ValueError): page_bounds(101, 0)
    with pytest.raises(ValueError): guard_changed_files(["../secret"])


def test_execution_failure_and_retry_classification():
    assert classify_validation_failure(0) == "success"
    assert classify_validation_failure(1, "command timed out") == "timeout"
    assert classify_validation_failure(127) == "environment"
    policy = RetryPolicy(maximum_attempts=3, base_seconds=10, maximum_seconds=15)
    assert [policy.delay(i) for i in (1, 2, 3)] == [10, 15, 15]
    assert policy.terminal(3)


def test_provider_pages_retry_after_and_backup_manifest():
    assert ProviderPage(({"id": 1},), "next").bounded().next_cursor == "next"
    assert parse_retry_after("9999") == 900
    assert parse_retry_after("bad", default=7) == 7
    records = [{"id": 1}]
    value = backup_manifest(records, source="postgres")
    assert verify_backup(records, value)
    assert QueueHealth(1, 901).status() == "starved"
