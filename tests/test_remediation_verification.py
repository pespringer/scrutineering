from types import SimpleNamespace

from src.remediation.verification_tasks import queue_remediation_verification_scan, remediation_scan_target


class _Session:
    pass


def test_verification_target_preserves_filesystem_checkout(monkeypatch):
    monkeypatch.setenv("REMEDIATION_SCAN_REPOSITORY_ROOT", "/workspace/repository")
    remediation = SimpleNamespace(image=SimpleNamespace(tag="filesystem", repo_name="local/source-fixture"))
    assert remediation_scan_target(remediation) == "fs:/workspace/repository/source-fixture"


def test_verification_scan_queue_is_idempotent(monkeypatch):
    calls = []
    events = []
    monkeypatch.setattr("src.scan.tasks.enqueue_scan", lambda *args, **kwargs: calls.append((args, kwargs)))
    monkeypatch.setattr("src.remediation.verification_tasks.RemediationRepository.list_events", lambda *_: events)
    monkeypatch.setattr("src.remediation.verification_tasks.RemediationRepository.append_event", lambda _, event: events.append(SimpleNamespace(**event)))
    remediation = SimpleNamespace(
        id=12, image=SimpleNamespace(tag="latest", repo_name="alpine", full_name="alpine:latest"),
        verification_scan_id=None, verification_status="not_requested", verification_error=None,
        finding_count=3,
    )

    first = queue_remediation_verification_scan(_Session(), remediation)
    second = queue_remediation_verification_scan(_Session(), remediation)

    assert first == second
    assert first.startswith("remediation-verify-12-")
    assert calls == [(("alpine:latest",), {"priority": "high", "scan_id": first})]
    assert remediation.verification_status == "pending"
    assert remediation.verification_findings_before == 3
