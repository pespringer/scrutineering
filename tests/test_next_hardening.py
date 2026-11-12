from datetime import datetime, timedelta

import pytest

from src.remediation.alert_governance import QueuePolicy, compatible_payload, fair_order
from src.remediation.audit_export import iter_jsonl, verify_chain
from src.remediation.concurrency import LeaseState, check_version, heartbeat, reclaim
from src.remediation.evidence_archive import compress_manifest, decompress_manifest, manifest


def test_queue_policy_priority_compatibility_and_fair_order():
    QueuePolicy(tenant_required=True).validate(priority="critical", tenant="team-a")
    assert compatible_payload({"schema_version": "alert-v1"})
    assert [item["priority"] for item in fair_order([{"id": 1, "priority": "low"}, {"id": 2, "priority": "critical"}])] == ["critical", "low"]
    with pytest.raises(ValueError): QueuePolicy(tenant_required=True).validate(priority="normal")


def test_audit_jsonl_and_chain_verification():
    records = [{"id": 1, "previous_hash": None, "record_hash": "a"}, {"id": 2, "previous_hash": "a", "record_hash": "b"}]
    assert list(iter_jsonl(records))[0].endswith("\n")
    assert verify_chain(records)


def test_archive_compression_round_trip():
    value = manifest([{"id": 1}], key_id="key-1")
    assert decompress_manifest(compress_manifest(value)) == value


def test_lease_heartbeat_reclaim_and_version_guard():
    now = datetime.now()
    state = LeaseState("worker-a", now + timedelta(seconds=10), 1)
    state = heartbeat(state, owner="worker-a", until=now + timedelta(seconds=20))
    assert state.version == 2
    with pytest.raises(ValueError): reclaim(state, now=now)
    assert reclaim(state, now=now + timedelta(seconds=21)).owner is None
    with pytest.raises(ValueError): check_version(1, 2)
