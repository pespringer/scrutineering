from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from fastapi import HTTPException

from src.api.routes import remediations as dashboard_api
from src.db.models import RemediationStatus


def _request(*roles: str):
    return SimpleNamespace(state=SimpleNamespace(principal_roles=list(roles), principal_id="alice", auth_method="api_key"))


@pytest.fixture
def remediation_store(monkeypatch):
    remediation = SimpleNamespace(status=RemediationStatus.REQUIRES_REVIEW)
    session = Mock()
    session.get.return_value = remediation

    @contextmanager
    def fake_session():
        yield session

    update_status = Mock()
    monkeypatch.setattr(dashboard_api, "get_session", fake_session)
    monkeypatch.setattr(dashboard_api.RemediationRepository, "update_status", update_status)
    monkeypatch.setattr(dashboard_api.RemediationRepository, "get_by_id", lambda *_: remediation)
    monkeypatch.setattr(dashboard_api, "record_operator_event", Mock())
    monkeypatch.setattr(dashboard_api, "remediation_payload", lambda record: {"status": "approved"})
    return SimpleNamespace(remediation=remediation, session=session, update_status=update_status)


def test_security_operator_approves_without_a_token(remediation_store):
    assert dashboard_api.approve_remediation(7, _request("security-operator")) == {"status": "approved"}
    args, kwargs = remediation_store.update_status.call_args
    assert args[1:] == (7, RemediationStatus.ANALYZING)
    assert kwargs["approved_by"] == "alice"
    assert kwargs["approved_at"] is not None


def test_approval_requires_security_operator_role(remediation_store):
    with pytest.raises(HTTPException) as error:
        dashboard_api.approve_remediation(7, _request("operator", "remediator"))
    assert error.value.status_code == 403
    remediation_store.update_status.assert_not_called()


def test_approval_rejects_remediations_not_awaiting_review(remediation_store):
    remediation_store.remediation.status = RemediationStatus.ANALYZING
    with pytest.raises(HTTPException) as error:
        dashboard_api.approve_remediation(7, _request("security-operator"))
    assert error.value.status_code == 409


def test_approval_returns_404_for_unknown_remediation(remediation_store):
    remediation_store.session.get.return_value = None
    with pytest.raises(HTTPException) as error:
        dashboard_api.approve_remediation(7, _request("security-operator"))
    assert error.value.status_code == 404
