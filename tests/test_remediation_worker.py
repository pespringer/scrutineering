from types import SimpleNamespace
from unittest.mock import Mock

from src.db.models import RemediationStatus
from src.remediation.worker import _blocked, execution_enabled


def test_remediation_execution_is_disabled_by_default(monkeypatch):
    monkeypatch.delenv("REMEDIATION_EXECUTION_ENABLED", raising=False)
    assert execution_enabled() is False


def test_remediation_execution_requires_explicit_enablement(monkeypatch):
    monkeypatch.setenv("REMEDIATION_EXECUTION_ENABLED", "true")
    assert execution_enabled() is True


def test_blocked_execution_persists_terminal_failure_and_event(monkeypatch):
    session = Mock()
    remediation = SimpleNamespace(status=RemediationStatus.ANALYZING, error_message=None)
    update_status = Mock()
    monkeypatch.setattr("src.remediation.worker.RemediationRepository.get_by_id", lambda *_: remediation)
    monkeypatch.setattr("src.remediation.worker.RemediationRepository.update_status", update_status)
    monkeypatch.setattr("src.remediation.worker.RemediationRepository.list_events", lambda *_: [])

    result = _blocked(session, 7, "branch_publication_failed:403")

    assert result == {"remediation_id": 7, "status": "blocked", "reason": "branch_publication_failed:403"}
    assert remediation.status == RemediationStatus.ANALYZING
    update_status.assert_called_once_with(session, 7, RemediationStatus.FAILED, error_message="branch_publication_failed:403")
