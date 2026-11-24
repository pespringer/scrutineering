"""The audit log's hash chain: written on every record, checked on request and daily (security-hardening.md)."""

from __future__ import annotations

import importlib.util
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from src.api.app import create_app
from src.db import audit_chain
from src.db.connection import get_session
from src.db.models import AuditEventType, AuditLog
from src.db.repositories import AuditLogRepository
from src.reports import export
from src.scan.records import get_or_create_image, scan_identity

API_KEY = "chain-key"
MIGRATION = Path("src/db/migrations/versions/0018_security_hardening.py")


def _client(monkeypatch, roles: str = "security-operator") -> TestClient:
    monkeypatch.setenv("PYTHON_API_KEY", API_KEY)
    monkeypatch.setenv("DASHBOARD_DEFAULT_ROLES", roles)
    client = TestClient(create_app())
    client.headers["x-api-key"] = API_KEY
    return client


def _record(entity_id: str, image_id: int | None = None, **detail) -> int:
    with get_session() as session:
        return AuditLogRepository.record(
            session,
            AuditEventType.CONFIG_CHANGED,
            detail=detail,
            entity_type="test",
            entity_id=entity_id,
            image_id=image_id,
            actor="alice",
            actor_kind="user",
        ).id


def _verify() -> audit_chain.Verification:
    with get_session() as session:
        return audit_chain.verify_all(session)


def test_each_record_chains_to_the_one_before():
    ids = [_record(f"r{n}", n=n) for n in range(3)]

    with get_session() as session:
        records = session.query(AuditLog).order_by(AuditLog.id).all()
        assert records[0].previous_hash == ""
        for before, after in zip(records, records[1:]):
            assert after.previous_hash == before.record_hash
        assert len({record.record_hash for record in records}) == 3
    assert _verify() == audit_chain.Verification(True, 3, None)
    assert ids == sorted(ids)


def test_an_edited_record_breaks_the_chain_at_that_record():
    _record("first")
    edited = _record("second", amount=1)
    _record("third")
    with get_session() as session:
        session.get(AuditLog, edited).detail = {"amount": 1000}

    assert _verify() == audit_chain.Verification(False, 2, edited)


def test_a_deleted_record_breaks_the_chain_at_the_next_one():
    _record("first")
    deleted = _record("second")
    following = _record("third")
    with get_session() as session:
        session.delete(session.get(AuditLog, deleted))

    result = _verify()
    assert (result.intact, result.first_broken_id) == (False, following)


def test_swapping_two_records_breaks_the_chain():
    first = _record("first")
    second = _record("second")
    with get_session() as session:
        one, two = session.get(AuditLog, first), session.get(AuditLog, second)
        one.entity_id, two.entity_id = two.entity_id, one.entity_id

    assert _verify().first_broken_id == first


def test_deleting_an_image_does_not_break_the_chain():
    with get_session() as session:
        image = get_or_create_image(session, scan_identity("registry:5000/team/app:1.0"))
        image_id = image.id
    _record("about-the-image", image_id=image_id)
    _record("later")
    with get_session() as session:
        session.query(AuditLog).filter_by(image_id=image_id).update({"image_id": None})

    assert _verify().intact


def test_the_migrations_copy_of_the_hash_matches_the_apps():
    spec = importlib.util.spec_from_file_location("migration_0018", MIGRATION)
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    row = SimpleNamespace(
        timestamp=datetime(2026, 11, 23, 3, 50, 1, 123456),
        event_type="config_changed",
        entity_type="remediation",
        entity_id="7",
        actor="alice",
        actor_kind="user",
        detail={"b": [1, 2], "a": "ü"},
    )
    fields = vars(row)

    assert migration.record_hash("abc", row) == audit_chain.record_hash("abc", **fields)
    assert migration.record_hash("", row) == audit_chain.record_hash("", **fields)


def test_verify_route_needs_audit_export_and_reports_the_chain(monkeypatch):
    _record("first")
    broken = _record("second")
    assert _client(monkeypatch, roles="operator").get("/api/dashboard/audit/verify").status_code == 403
    client = _client(monkeypatch)

    assert client.get("/api/dashboard/audit/verify").json() == {"intact": True, "records": 2, "first_broken_id": None}
    with get_session() as session:
        session.get(AuditLog, broken).actor = "mallory"
    assert client.get("/api/dashboard/audit/verify").json()["first_broken_id"] == broken


def test_exports_carry_the_chain(monkeypatch):
    _record("first")
    records = _client(monkeypatch).get("/api/dashboard/audit/export").json()["records"]

    assert records[0]["previous_hash"] == "" and len(records[0]["record_hash"]) == 64


@pytest.fixture
def saved(monkeypatch):
    statuses = {}
    monkeypatch.setattr(audit_chain, "save_status", lambda status, url: statuses.update(status))
    monkeypatch.setattr(audit_chain, "load_status", lambda url: statuses or None)
    return statuses


def test_the_daily_check_reports_a_break_in_the_system_status(monkeypatch, saved):
    _record("first")
    broken = _record("second")
    client = _client(monkeypatch, roles="dashboard")

    assert export.verify_audit_chain()["intact"] is True
    assert client.get("/api/dashboard/system-status").json()["audit_chain"]["intact"] is True
    with get_session() as session:
        session.get(AuditLog, broken).detail = {"changed": True}
    export.verify_audit_chain()

    status = client.get("/api/dashboard/system-status").json()
    assert status["audit_chain"]["first_broken_id"] == broken
    assert f"The audit log's hash chain is broken at record {broken}" in status["problems"]
