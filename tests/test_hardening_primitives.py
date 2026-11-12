from datetime import datetime, timedelta, timezone

from src.remediation.chaos import FailurePlan
from src.remediation.concurrency import lease_available, next_version
from src.remediation.evidence_archive import manifest, verify_manifest


def test_archive_manifest_round_trip_and_tamper_detection():
    value = manifest([{"id": 1}, {"id": 2}])
    assert verify_manifest(value)
    value["records"][0]["id"] = 99
    assert not verify_manifest(value)


def test_lease_and_version_helpers_are_deterministic():
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    assert lease_available(None, now)
    assert lease_available(now - timedelta(seconds=1), now)
    assert not lease_available(now + timedelta(seconds=1), now)
    assert next_version(None) == 1 and next_version(4) == 5


def test_failure_plan_has_reproducible_outcomes():
    plan = FailurePlan(failures_before_success=2, failure_kind="rate_limited")
    assert [plan.outcome(i) for i in range(1, 4)] == ["rate_limited", "rate_limited", "success"]
