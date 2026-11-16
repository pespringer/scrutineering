from datetime import datetime, timezone

import pytest

from src.remediation.limits import (
    RetentionPolicy,
    bounded_output,
    classify_validation_failure,
    guard_changed_files,
    parse_retry_after,
)


def test_retention_is_opt_in_and_cutoff_is_bounded():
    policy = RetentionPolicy(days=30)
    assert policy.cutoff(datetime(2026, 1, 31, tzinfo=timezone.utc)).day == 1
    assert not policy.can_purge()
    assert RetentionPolicy(days=30, purge_enabled=True, dry_run=False).can_purge()
    with pytest.raises(ValueError):
        RetentionPolicy(days=0).cutoff()


def test_output_is_truncated_from_the_end():
    assert bounded_output("abcdef", 3) == "def"
    with pytest.raises(ValueError):
        bounded_output("abc", 0)


@pytest.mark.parametrize("path", ["../secret", "/etc/passwd", "src/a b.py", ""])
def test_changed_file_guard_rejects_unsafe_paths(path):
    with pytest.raises(ValueError):
        guard_changed_files([path])


def test_changed_file_guard_sorts_dedupes_and_limits():
    assert guard_changed_files(["src/b.py", "src/a.py", "src/a.py"]) == ["src/a.py", "src/b.py"]
    with pytest.raises(ValueError):
        guard_changed_files([f"f{i}.py" for i in range(3)], maximum=2)


def test_validation_failure_classification():
    assert classify_validation_failure(0) == "success"
    assert classify_validation_failure(1, "command timed out") == "timeout"
    assert classify_validation_failure(127) == "environment"
    assert classify_validation_failure(2) == "validation_failed"


def test_retry_after_is_clamped():
    assert parse_retry_after("9999") == 900
    assert parse_retry_after("bad", default=7) == 7
    assert parse_retry_after(None) == 60
    assert parse_retry_after("-5") == 0
