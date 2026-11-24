"""Images, the local registry catalog, findings triage and export, the audit trail and posture trend."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from src.api.app import create_app
from src.db.connection import get_session
from src.db.models import AuditLog, FindingSource, Image, ScanFinding, Severity, SeveritySnapshot
from src.scan.records import create_pending_scan, get_or_create_image, scan_identity

API_KEY = "inventory-key"


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _client(monkeypatch, roles: str = "operator,security-operator") -> TestClient:
    monkeypatch.setenv("PYTHON_API_KEY", API_KEY)
    monkeypatch.setenv("DASHBOARD_DEFAULT_ROLES", roles)
    client = TestClient(create_app())
    client.headers["x-api-key"] = API_KEY
    return client


def _image(reference: str) -> int:
    with get_session() as session:
        return get_or_create_image(session, scan_identity(reference)).id


def _finding(image_id: int, cve: str, severity: Severity = Severity.HIGH, *, resolved=False, fixed="2.0") -> int:
    with get_session() as session:
        finding = ScanFinding(
            image_id=image_id,
            fingerprint=f"fp-{image_id}-{cve}",
            vuln_key=f"{cve}:pkg",
            cve_id=cve,
            package_name="pkg",
            package_version="1.0",
            severity=severity,
            fixed_version=fixed,
            fix_available=fixed is not None,
            source=FindingSource.TRIVY,
            resolved_at=_now() if resolved else None,
        )
        session.add(finding)
        session.flush()
        return finding.id


def _audit() -> list[AuditLog]:
    with get_session() as session:
        records = session.query(AuditLog).order_by(AuditLog.id).all()
        session.expunge_all()
        return records


# Images


def test_inventory_filters_by_name_severity_and_running(monkeypatch):
    client = _client(monkeypatch)
    api = _image("registry:5000/team/api:1")
    web = _image("registry:5000/team/web:1")
    _finding(api, "CVE-1", Severity.CRITICAL)
    _finding(web, "CVE-2", Severity.LOW)
    _finding(web, "CVE-3", Severity.CRITICAL, resolved=True)
    with get_session() as session:
        session.get(Image, web).last_seen_running_at = _now()

    def ids(query: str = "") -> list[int]:
        return [item["id"] for item in client.get(f"/api/dashboard/images{query}").json()["items"]]

    assert ids() == [api, web]
    assert ids("?search=web") == [web]
    assert ids("?severity=critical") == [api]
    assert ids("?running=true") == [web]
    web_row = client.get("/api/dashboard/images?search=web").json()["items"][0]
    assert (web_row["open_findings"], web_row["resolved_findings"], web_row["containers"]) == (1, 1, 0)
    assert client.get("/api/dashboard/images?severity=urgent").status_code == 400


def test_archiving_hides_an_image_and_is_audited(monkeypatch):
    client = _client(monkeypatch)
    api = _image("registry:5000/team/api:1")
    web = _image("registry:5000/team/web:1")

    body = client.post("/api/dashboard/images/bulk-archive", json={"ids": [api, 999]}).json()

    assert body["archived"] == [api]
    assert [item["id"] for item in client.get("/api/dashboard/images").json()["items"]] == [web]
    assert [(r.entity_type, r.entity_id, r.detail["action"]) for r in _audit()] == [
        ("image", str(api), "archive_image")
    ]
    assert (
        _client(monkeypatch, roles="dashboard")
        .post("/api/dashboard/images/bulk-archive", json={"ids": [web]})
        .status_code
        == 403
    )


def test_image_detail_pages_open_findings_and_counts_resolved_ones(monkeypatch):
    client = _client(monkeypatch)
    image_id = _image("registry:5000/team/api:1")
    critical = _finding(image_id, "CVE-1", Severity.CRITICAL)
    high = _finding(image_id, "CVE-2", Severity.HIGH)
    _finding(image_id, "CVE-3", Severity.HIGH, resolved=True)

    body = client.get(f"/api/dashboard/images/{image_id}").json()
    assert [finding["id"] for finding in body["findings"]] == [critical, high]
    assert (body["image"]["open_findings"], body["image"]["resolved_findings"]) == (2, 1)
    assert (body["image"]["source"], body["image"]["sbom"]) == (None, None)

    page = client.get(f"/api/dashboard/images/{image_id}?severity=high&limit=1").json()
    assert [finding["id"] for finding in page["findings"]] == [high]
    assert page["findings_page"]["total"] == 1
    # The image's own counts cover every open finding, not just the filtered page.
    assert page["image"]["open_findings"] == 2
    assert client.get("/api/dashboard/images/999").status_code == 404


class FakeRegistry:
    """The local registry's catalog, tags and manifest HEADs."""

    def __init__(self, tags: dict[str, list[str]], broken_manifest: str | None = None):
        self.tags, self.broken_manifest = tags, broken_manifest

    def json(self, path: str) -> dict:
        if path.startswith("/v2/_catalog"):
            return {"repositories": list(self.tags)}
        repository = path.removeprefix("/v2/").removesuffix("/tags/list")
        return {"tags": self.tags[repository]}

    def manifest(self, repository: str, tag: str) -> dict:
        if f"{repository}:{tag}" == self.broken_manifest:
            raise OSError("manifest unknown")
        return {"digest": f"sha256:{repository}-{tag}", "size": 1234}


@pytest.fixture
def registry(monkeypatch):
    def install(fake: FakeRegistry) -> None:
        monkeypatch.setattr("src.api.routes.images._registry_json", fake.json)
        monkeypatch.setattr("src.api.routes.images._registry_manifest_metadata", fake.manifest)

    return install


def test_registry_inventory_joins_tags_with_scan_state(monkeypatch, registry):
    monkeypatch.setenv("LOCAL_REGISTRY_HOST", "registry:5000")
    client = _client(monkeypatch)
    registry(FakeRegistry({"team/api": ["2", "1"], "team/web": ["1"], "team/new": ["1"]}, "team/web:1"))
    api1 = _image("registry:5000/team/api:1")
    api2 = _image("registry:5000/team/api:2")
    web1 = _image("registry:5000/team/web:1")
    _finding(api1, "CVE-1", Severity.CRITICAL)
    _finding(api1, "CVE-2", Severity.HIGH, resolved=True)
    with get_session() as session:
        for reference, status in (
            ("registry:5000/team/api:1", "completed"),
            ("registry:5000/team/api:2", "completed"),
            ("registry:5000/team/web:1", "running"),
        ):
            create_pending_scan(session, reference).status = status

    body = client.get("/api/dashboard/registry/inventory").json()

    by_name = {item["image_name"]: item for item in body["tags"]}
    assert [item["tag"] for item in body["tags"] if item["repository"] == "team/api"] == ["1", "2"]
    assert by_name["registry:5000/team/api:1"]["security_status"] == "issues_found"
    assert (
        by_name["registry:5000/team/api:1"]["open_findings"],
        by_name["registry:5000/team/api:1"]["critical_count"],
    ) == (
        1,
        1,
    )
    assert by_name["registry:5000/team/api:2"]["security_status"] == "clean"
    assert by_name["registry:5000/team/web:1"]["security_status"] == "scanning"
    assert by_name["registry:5000/team/web:1"]["error"] == "manifest unknown"
    assert by_name["registry:5000/team/new:1"]["security_status"] == "not_scanned"
    assert by_name["registry:5000/team/new:1"]["image_id"] is None
    assert {by_name[f"registry:5000/team/{n}"]["image_id"] for n in ("api:1", "api:2", "web:1")} == {api1, api2, web1}
    assert body["summary"] == {
        "repositories": 3,
        "tags": 4,
        "scanned": 3,
        "not_scanned": 1,
        "scanning": 1,
        "issues_found": 1,
        "clean": 1,
    }
    assert body["registry"]["reachable"] is True


def test_registry_inventory_reports_an_unreachable_registry(monkeypatch, registry):
    client = _client(monkeypatch)

    def unreachable(path: str) -> dict:
        raise OSError("connection refused")

    monkeypatch.setattr("src.api.routes.images._registry_json", unreachable)
    response = client.get("/api/dashboard/registry/inventory")
    assert (response.status_code, response.json()["detail"]) == (503, "local_registry_unavailable")


def test_registry_inventory_marks_a_failed_scan(monkeypatch, registry):
    monkeypatch.setenv("LOCAL_REGISTRY_HOST", "registry:5000")
    client = _client(monkeypatch)
    registry(FakeRegistry({"team/api": ["1"]}))
    _image("registry:5000/team/api:1")
    with get_session() as session:
        create_pending_scan(session, "registry:5000/team/api:1").status = "failed"

    assert client.get("/api/dashboard/registry/inventory").json()["tags"][0]["security_status"] == "scan_failed"


# Findings


def test_acknowledging_skips_resolved_findings_and_is_audited(monkeypatch):
    client = _client(monkeypatch)
    image_id = _image("registry:5000/team/api:1")
    open_id = _finding(image_id, "CVE-1")
    resolved_id = _finding(image_id, "CVE-2", resolved=True)

    body = client.post("/api/dashboard/findings/bulk-acknowledge", json={"ids": [open_id, resolved_id]}).json()

    assert (body["acknowledged"], body["count"]) == ([open_id], 1)
    with get_session() as session:
        assert session.get(ScanFinding, open_id).acknowledged is True
        assert session.get(ScanFinding, resolved_id).acknowledged is False
    assert [r.detail["action"] for r in _audit()] == ["acknowledge_findings"]


def test_acknowledging_nothing_open_writes_no_audit_record(monkeypatch):
    client = _client(monkeypatch)
    resolved_id = _finding(_image("registry:5000/team/api:1"), "CVE-2", resolved=True)
    assert client.post("/api/dashboard/findings/bulk-acknowledge", json={"ids": [resolved_id]}).json()["count"] == 0
    assert _audit() == []


def test_local_mode_assigns_to_any_name(monkeypatch):
    client = _client(monkeypatch)
    finding_id = _finding(_image("registry:5000/team/api:1"), "CVE-1")
    body = client.post("/api/dashboard/findings/bulk-assign", json={"finding_ids": [finding_id], "assignee": "bob"})
    assert body.json()["assigned"] == [finding_id]
    unassign = client.post("/api/dashboard/findings/bulk-assign", json={"finding_ids": [finding_id], "assignee": None})
    assert unassign.json()["assignee"] is None
    with get_session() as session:
        assert session.get(ScanFinding, finding_id).assigned_to is None


def test_triage_needs_the_operator_role(monkeypatch):
    client = _client(monkeypatch, roles="dashboard,remediator")
    finding_id = _finding(_image("registry:5000/team/api:1"), "CVE-1")
    assert client.post("/api/dashboard/findings/bulk-acknowledge", json={"ids": [finding_id]}).status_code == 403
    assign = {"finding_ids": [finding_id], "assignee": "bob"}
    assert client.post("/api/dashboard/findings/bulk-assign", json=assign).status_code == 403


def test_findings_export_filters_and_hashes_its_records(monkeypatch):
    client = _client(monkeypatch)
    api = _image("registry:5000/team/api:1")
    web = _image("registry:5000/team/web:1")
    critical = _finding(api, "CVE-1", Severity.CRITICAL)
    _finding(api, "CVE-2", Severity.LOW)
    _finding(web, "CVE-3", Severity.CRITICAL)
    _finding(api, "CVE-4", Severity.CRITICAL, resolved=True)
    client.post("/api/dashboard/findings/bulk-acknowledge", json={"ids": [critical]})

    body = client.get(f"/api/dashboard/findings/export?severity=critical&image_id={api}").json()

    assert [record["id"] for record in body["records"]] == [critical]
    canonical = json.dumps(body["records"], sort_keys=True, separators=(",", ":")).encode()
    assert body["sha256"] == hashlib.sha256(canonical).hexdigest()
    assert body["format"] == "scrutineering-findings-v1"
    unacknowledged = client.get("/api/dashboard/findings/export?acknowledged=false").json()
    assert critical not in [record["id"] for record in unacknowledged["records"]]
    assert unacknowledged["count"] == 2


# Audit


def _event(actor: str, event_type: str, when: datetime) -> None:
    from src.db.models import AuditEventType
    from src.db.repositories import AuditLogRepository

    with get_session() as session:
        AuditLogRepository.record(
            session,
            event_type=AuditEventType(event_type),
            entity_type="scan",
            entity_id=f"{actor}-{event_type}",
            detail={},
            actor=actor,
            actor_kind="user",
        )
        session.flush()
        session.query(AuditLog).order_by(AuditLog.id.desc()).first().timestamp = when


def test_audit_trail_filters_and_pages_newest_first(monkeypatch):
    client = _client(monkeypatch, roles="dashboard")
    now = _now()
    _event("alice", "scan_started", now - timedelta(days=3))
    _event("bob", "scan_cancelled", now - timedelta(days=2))
    _event("alice", "config_changed", now - timedelta(days=1))

    def entities(query: str = "") -> list[str]:
        return [item["entity_id"] for item in client.get(f"/api/dashboard/audit{query}").json()["items"]]

    assert entities() == ["alice-config_changed", "bob-scan_cancelled", "alice-scan_started"]
    assert entities("?actor=alice") == ["alice-config_changed", "alice-scan_started"]
    assert entities("?event_type=SCAN_CANCELLED") == ["bob-scan_cancelled"]
    since = (now - timedelta(days=2, hours=1)).isoformat()
    until = (now - timedelta(hours=12)).isoformat()
    assert entities(f"?since={since}&until={until}") == ["alice-config_changed", "bob-scan_cancelled"]
    page = client.get("/api/dashboard/audit?limit=1&offset=1").json()
    assert ([item["entity_id"] for item in page["items"]], page["total"]) == (["bob-scan_cancelled"], 3)


def test_audit_export_is_oldest_first_and_hashed(monkeypatch):
    now = _now()
    _event("alice", "scan_started", now - timedelta(days=2))
    _event("bob", "scan_cancelled", now - timedelta(days=1))
    assert _client(monkeypatch, roles="operator").get("/api/dashboard/audit/export").status_code == 403

    body = _client(monkeypatch, roles="security-operator").get("/api/dashboard/audit/export?actor=bob").json()

    assert [record["entity_id"] for record in body["records"]] == ["bob-scan_cancelled"]
    canonical = json.dumps(body["records"], sort_keys=True, separators=(",", ":")).encode()
    assert (body["format"], body["sha256"]) == ("scrutineering-audit-v1", hashlib.sha256(canonical).hexdigest())
    everything = _client(monkeypatch, roles="security-operator").get("/api/dashboard/audit/export").json()
    assert [record["entity_id"] for record in everything["records"]] == ["alice-scan_started", "bob-scan_cancelled"]


# Posture


def test_trend_sums_daily_snapshots_across_images(monkeypatch):
    client = _client(monkeypatch, roles="dashboard")
    api = _image("registry:5000/team/api:1")
    web = _image("registry:5000/team/web:1")
    day = _now().replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=1)
    with get_session() as session:
        for image_id, critical in ((api, 2), (web, 3)):
            session.add(
                SeveritySnapshot(
                    image_id=image_id,
                    snapshot_date=day,
                    critical_count=critical,
                    high_count=1,
                    medium_count=0,
                    low_count=0,
                )
            )
        session.add(
            SeveritySnapshot(
                image_id=api, snapshot_date=day - timedelta(days=60), critical_count=9, high_count=9, medium_count=9
            )
        )

    assert client.get("/api/dashboard/posture/trend?days=30").json() == [
        {"date": day.date().isoformat(), "critical": 5, "high": 2, "medium": 0, "low": 0}
    ]


def test_trend_falls_back_to_completed_scans_without_snapshots(monkeypatch):
    client = _client(monkeypatch, roles="dashboard")
    yesterday = _now() - timedelta(days=1)
    with get_session() as session:
        for status, critical in (("completed", 4), ("partial", 6), ("failed", 99)):
            scan = create_pending_scan(session, "registry:5000/team/api:1")
            scan.status, scan.completed_at, scan.critical_count, scan.high_count = status, yesterday, critical, 1
        old = create_pending_scan(session, "registry:5000/team/api:1")
        old.status, old.completed_at, old.critical_count = "completed", yesterday - timedelta(days=60), 50

    assert client.get("/api/dashboard/posture/trend?days=30").json() == [
        {"date": yesterday.date().isoformat(), "critical": 6, "high": 1, "medium": 0, "low": 0}
    ]
    assert client.get("/api/dashboard/posture/trend?days=0").status_code == 422
