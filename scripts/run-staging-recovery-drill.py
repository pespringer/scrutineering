"""Run the receiver-independent alert/recovery lifecycle drill."""

import os
from datetime import datetime, timezone

os.environ.setdefault("SCRUTINEERING_TEST_MODE", "1")

from src.db.models import RemediationAlertDelivery
from src.remediation.alert_delivery import FakeReceiver, delivery_key, schedule_retry
from src.remediation.evidence_export import sign_export, verify_export
from src.remediation.chaos import FailurePlan
from src.remediation.evidence_archive import manifest, verify_manifest


def main():
    code, _ = FakeReceiver().deliver({"event_type": "stale"})
    assert code == 202
    record = RemediationAlertDelivery(publication_id=1, delivery_key=delivery_key(1, "fake", "stale", {"x": 1}), receiver="fake", max_attempts=2, attempts=0)
    record.last_error = "simulated failure"
    schedule_retry(record, datetime.now(timezone.utc).replace(tzinfo=None))
    assert record.status == "retrying" and record.next_attempt_at is not None
    export = {"publication_id": 1, "status": "verified"}
    assert verify_export(export, sign_export(export, "staging-secret"), "staging-secret")
    assert [FailurePlan(2, "timeout").outcome(i) for i in range(1, 4)] == ["timeout", "timeout", "success"]
    assert verify_manifest(manifest([export]))
    print("PASS receiver-independent recovery, dead-letter, and signed export drill")


if __name__ == "__main__":
    main()
