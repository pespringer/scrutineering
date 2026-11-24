"""Publishing a verified remediation as a GitHub pull request, and what the merge leads to.

A bare git repository stands in for github.com and a fake client for its REST API.
"""

import hashlib
import hmac
import io
import json
import subprocess
from urllib.error import HTTPError

import pytest
from fastapi.testclient import TestClient

from src.api.app import create_app
from src.api.routes import webhooks
from src.db.connection import get_session
from src.db.models import Image, Remediation, RemediationPublication, RemediationStatus, Scan, ScanFinding
from src.db.repositories import RemediationRepository
from src.remediation import publish, sources
from src.scan.records import queue_scan
from src.scan.utils.db import persist_findings

API_KEY = "publish-key"
SECRET = "hook-secret"
IMAGE = "registry:5000/team/app:1.0"
OLD_DIGEST = "sha256:" + "a" * 64
LODASH = {
    "cve_id": "CVE-2021-23337",
    "package_name": "lodash",
    "package_version": "4.17.20",
    "package_type": "npm",
    "fixed_version": "4.17.21",
    "severity": "high",
}
EXISTING = {"cve_id": "CVE-2023-0001", "package_name": "libssl3", "package_version": "3.0.7-r0", "severity": "high"}


def _git(cwd, *args) -> str:
    command = ["git", "-c", "user.name=t", "-c", "user.email=t@t", "-c", "init.defaultBranch=main", *args]
    return subprocess.run(command, cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


class FakeGitHub(publish.GitHub):
    """The real client's interface over a fake REST API; git pushes go to the stand-in repository."""

    def __init__(self):
        super().__init__("fake-token")
        self.pulls = []

    def default_branch(self, repository):
        return "main"

    def open_pull_request(self, repository, *, head, base, title, body):
        self.pulls.append({"repository": repository, "head": head, "base": base, "title": title, "body": body})
        return {"number": 7, "html_url": f"https://github.com/{repository}/pull/7"}


@pytest.fixture
def remote(tmp_path, monkeypatch):
    """`acme/app` on the stand-in GitHub, with one commit on main."""
    work = tmp_path / "work"
    work.mkdir()
    _git(work, "init", "-q")
    (work / "Dockerfile").write_text("FROM node:18.12-alpine\nCOPY . .\n")
    (work / "package.json").write_text('{\n  "dependencies": {\n    "lodash": "4.17.20"\n  }\n}\n')
    _git(work, "add", ".")
    _git(work, "commit", "-q", "-m", "init")
    bare = tmp_path / "remotes" / "acme" / "app.git"
    bare.parent.mkdir(parents=True)
    _git(tmp_path, "clone", "-q", "--bare", str(work), str(bare))
    monkeypatch.setattr(sources, "GITHUB_WEB", str(tmp_path / "remotes"))
    (work / "package.json").write_text('{\n  "dependencies": {\n    "lodash": "4.17.21"\n  }\n}\n')
    return {"bare": bare, "commit": _git(work, "rev-parse", "HEAD"), "patch": _git(work, "diff") + "\n"}


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("PYTHON_API_KEY", API_KEY)
    monkeypatch.setenv("DASHBOARD_DEFAULT_ROLES", "dashboard,remediator,security-operator")
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", SECRET)
    api = TestClient(create_app())
    api.headers["x-api-key"] = API_KEY
    return api


def _ready(client, remote, repository="https://github.com/acme/app") -> int:
    """A remediation of lodash that execution verified: `ready` with its patch."""
    scan_id = queue_scan(IMAGE, enqueue=lambda *a, **k: None)
    with get_session() as session:
        scan = session.query(Scan).filter_by(scan_id=scan_id).one()
        scan.image_digest = OLD_DIGEST
        scan.image.digest = OLD_DIGEST
        image_id = scan.image_id
    persist_findings(scan_id, image_id, [LODASH, EXISTING], "trivy", reconcile_missing=True)
    assert client.put(f"/api/dashboard/images/{image_id}/source", json={"repository": repository}).status_code == 200
    with get_session() as session:
        finding_id = session.query(ScanFinding).filter_by(package_name="lodash").one().id
    rid = client.post("/api/dashboard/remediations", json={"image_id": image_id, "finding_ids": [finding_id]}).json()[
        "id"
    ]
    with get_session() as session:
        for status in (RemediationStatus.APPROVED, RemediationStatus.BUILDING, RemediationStatus.VERIFYING):
            RemediationRepository.update_status(session, rid, status)
        RemediationRepository.update_status(
            session,
            rid,
            RemediationStatus.READY,
            patch=remote["patch"],
            source_commit=remote["commit"],
            candidate_image=f"registry:5000/team/app:scrutineering-candidate-{rid}",
            candidate_digest="sha256:" + "d" * 64,
            verification={"targeted": 1, "still_present": [], "new_critical_or_high": [], "candidate_findings": 1},
        )
    return rid


def _remediation(rid) -> Remediation:
    with get_session() as session:
        record = session.get(Remediation, rid)
        session.expunge(record)
        return record


def _publication(rid) -> RemediationPublication:
    with get_session() as session:
        record = session.query(RemediationPublication).filter_by(remediation_id=rid).one()
        session.expunge(record)
        return record


def _events(rid) -> list[str]:
    with get_session() as session:
        return [event.event_type for event in RemediationRepository.list_events(session, rid)]


def test_publishing_pushes_the_verified_patch_and_opens_a_pull_request(client, remote):
    rid = _ready(client, remote)
    github = FakeGitHub()

    result = publish.publish(rid, provider=github)

    assert result["status"] == "published"
    branch = f"scrutineering/remediation-{rid}"
    pushed = _git(remote["bare"], "rev-parse", branch)
    assert _git(remote["bare"], "rev-parse", f"{branch}^") == remote["commit"]  # one commit on the patched commit
    assert '"lodash": "4.17.21"' in _git(remote["bare"], "show", f"{branch}:package.json")
    assert _git(remote["bare"], "log", "-1", "--format=%an", branch) == "Scrutineering"
    [pull] = github.pulls
    assert pull["head"] == branch and pull["base"] == "main" and pull["repository"] == "acme/app"
    assert pull["title"] == f"Fix 1 vulnerability in team/app (Scrutineering #{rid})"
    assert "CVE-2021-23337" in pull["body"] and "| Open findings | 2 | 1 |" in pull["body"]
    assert f"scrutineering-candidate-{rid}" in pull["body"]

    record = _remediation(rid)
    assert record.status == RemediationStatus.PUBLISHED
    publication = _publication(rid)
    assert (publication.status, publication.provider_number, publication.head_commit) == ("open", 7, pushed)
    assert publication.image_digest == OLD_DIGEST and publication.base_branch == "main"
    assert _events(rid)[-1] == "published"
    payload = client.get(f"/api/dashboard/remediations/{rid}").json()
    assert payload["status_label"] == "Pull request open" and payload["publications"][0]["number"] == 7


def test_a_retried_publication_pushes_the_same_commit(client, remote):
    rid = _ready(client, remote)

    class Unavailable(FakeGitHub):
        def open_pull_request(self, *args, **kwargs):
            raise publish.PublishError("GitHub is unreachable: timed out")

    first = publish.publish(rid, provider=Unavailable())
    assert first["publication"] == "failed"
    assert _remediation(rid).status == RemediationStatus.READY  # failure leaves it publishable
    assert "unreachable" in _publication(rid).error_message
    branch = f"scrutineering/remediation-{rid}"
    first_head = _git(remote["bare"], "rev-parse", branch)

    assert publish.publish(rid, provider=FakeGitHub())["status"] == "published"
    assert _git(remote["bare"], "rev-parse", branch) == first_head
    assert _events(rid)[-2:] == ["publication_failed", "published"]


def test_publishing_never_overwrites_someone_elses_branch(client, remote, tmp_path):
    rid = _ready(client, remote)
    other = tmp_path / "other"
    _git(tmp_path, "clone", "-q", str(remote["bare"]), str(other))
    (other / "notes.txt").write_text("not ours\n")
    _git(other, "add", ".")
    _git(other, "commit", "-q", "-m", "someone else")
    _git(other, "push", "-q", "origin", f"HEAD:refs/heads/scrutineering/remediation-{rid}")

    result = publish.publish(rid, provider=FakeGitHub())

    assert result["publication"] == "failed"
    assert "already exists on GitHub with other commits" in result["reason"]
    assert _remediation(rid).status == RemediationStatus.READY


def test_the_publish_route_needs_a_token_a_github_source_and_a_ready_remediation(client, remote, monkeypatch):
    rid = _ready(client, remote)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    assert client.post(f"/api/dashboard/remediations/{rid}/publish").json()["detail"] == "publication_not_configured"

    monkeypatch.setenv("GITHUB_TOKEN", "token-value")
    queued = []
    monkeypatch.setattr(
        "src.api.routes.remediations.publish_remediation",
        type("Task", (), {"apply_async": lambda self, **kw: queued.append(kw) or type("R", (), {"id": "t1"})()})(),
    )
    response = client.post(f"/api/dashboard/remediations/{rid}/publish")
    assert response.status_code == 202 and queued == [{"args": [rid], "queue": "remediation.normal"}]
    assert client.get(f"/api/dashboard/remediations/{rid}").json()["publication_target"] == "acme/app"

    publish.publish(rid, provider=FakeGitHub())
    assert client.post(f"/api/dashboard/remediations/{rid}/publish").status_code == 409


def test_publishing_uses_the_source_the_fix_was_proposed_with(client, remote, monkeypatch):
    rid = _ready(client, remote)
    image_id = _remediation(rid).image_id
    # After approval, someone repoints the source at another project and branch.
    changed = {"repository": "https://github.com/evil/app", "ref": "attacker-branch"}
    assert client.put(f"/api/dashboard/images/{image_id}/source", json=changed).status_code == 200
    github = FakeGitHub()

    assert publish.publish(rid, provider=github)["status"] == "published"

    [pull] = github.pulls
    assert (pull["repository"], pull["base"]) == ("acme/app", "main")
    assert client.get(f"/api/dashboard/remediations/{rid}").json()["publication_target"] == "acme/app"


def test_a_source_that_is_not_on_github_cannot_be_published(client, remote, monkeypatch):
    rid = _ready(client, remote, repository="https://gitlab.example.com/acme/app")
    monkeypatch.setenv("GITHUB_TOKEN", "token-value")
    assert client.post(f"/api/dashboard/remediations/{rid}/publish").json()["detail"] == "source_not_on_github"
    assert client.get(f"/api/dashboard/remediations/{rid}").json()["publication_target"] is None


def _deliver(client, payload: dict, delivery: str, secret: str = SECRET):
    body = json.dumps(payload).encode()
    signature = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    headers = {"x-github-delivery": delivery, "x-github-event": "pull_request", "x-hub-signature-256": signature}
    return client.post("/api/dashboard/webhooks/github", content=body, headers=headers)


def _closed(merged: bool) -> dict:
    return {
        "action": "closed",
        "repository": {"full_name": "acme/app"},
        "pull_request": {"number": 7, "merged": merged, "merge_commit_sha": "c" * 40 if merged else None},
        # Fields a sender might add are ignored: the server rescans instead.
        "observed_digest": "sha256:" + "f" * 64,
        "findings_after": 0,
    }


@pytest.fixture
def published(client, remote, monkeypatch):
    rid = _ready(client, remote)
    publish.publish(rid, provider=FakeGitHub())
    rescans = []
    monkeypatch.setattr(webhooks, "queue_rescan", lambda image: rescans.append(image) or "postmerge-1")
    return rid, rescans


def test_a_merge_rescans_the_image_and_trusts_nothing_in_the_payload(client, published):
    rid, rescans = published
    response = _deliver(client, _closed(merged=True), "delivery-1")

    assert response.json()["publication"] == "merged" and rescans == [IMAGE]
    assert _publication(rid).status == "merged" and _publication(rid).merge_commit == "c" * 40
    assert _remediation(rid).status == RemediationStatus.PUBLISHED  # only a rescan completes it
    assert _deliver(client, _closed(merged=True), "delivery-1").json()["duplicate"] is True
    assert rescans == [IMAGE]


def test_closing_the_pull_request_without_merging_fails_the_remediation(client, published):
    rid, rescans = published
    _deliver(client, _closed(merged=False), "delivery-2")
    record = _remediation(rid)
    assert record.status == RemediationStatus.FAILED and "closed without merging" in record.error_message
    assert rescans == []


def test_webhooks_need_a_valid_signature_and_only_github_exists(client, published):
    assert _deliver(client, _closed(merged=True), "delivery-3", secret="wrong").status_code == 401
    assert client.post("/api/dashboard/webhooks/gitlab", content=b"{}").status_code == 404
    unmatched = {**_closed(merged=True), "repository": {"full_name": "acme/other"}}
    assert _deliver(client, unmatched, "delivery-4").json()["matched"] is False


def _rescan(digest: str, *findings) -> None:
    scan_id = queue_scan(IMAGE, enqueue=lambda *a, **k: None)
    with get_session() as session:
        scan = session.query(Scan).filter_by(scan_id=scan_id).one()
        scan.image_digest = digest
        image_id = scan.image_id
    persist_findings(scan_id, image_id, list(findings), "trivy", reconcile_missing=True)


def test_after_a_merge_only_a_rebuilt_image_decides_the_outcome(client, published):
    rid, _ = published
    _deliver(client, _closed(merged=True), "delivery-5")

    _rescan(OLD_DIGEST, LODASH, EXISTING)  # not rebuilt yet: still waiting
    assert _remediation(rid).status == RemediationStatus.PUBLISHED

    _rescan("sha256:" + "b" * 64, LODASH, EXISTING)  # rebuilt, but lodash is still there
    record = _remediation(rid)
    assert record.status == RemediationStatus.FAILED and "still has 1 of the targeted findings" in record.error_message


def test_a_rebuilt_image_without_the_targets_completes_the_remediation(client, published):
    rid, _ = published
    _deliver(client, _closed(merged=True), "delivery-6")
    _rescan("sha256:" + "b" * 64, {**LODASH, "package_version": "4.17.21", "cve_id": "CVE-2099-0001"}, EXISTING)
    assert _remediation(rid).status == RemediationStatus.COMPLETED
    assert _events(rid)[-1] == "completed"


def _response(payload, status=200):
    class Response(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    if status >= 400:
        raise HTTPError("https://api.github.com", status, "error", {}, io.BytesIO(json.dumps(payload).encode()))
    return Response(json.dumps(payload).encode())


def test_the_github_client_reuses_an_open_pull_request_and_never_echoes_the_token():
    calls = []

    def transport(request, timeout):
        calls.append((request.get_method(), request.full_url, request.headers.get("Authorization")))
        if request.get_method() == "POST":
            return _response(
                {"message": "Validation Failed", "errors": [{"message": "A pull request already exists"}]}, 422
            )
        return _response([{"number": 3, "html_url": "https://github.com/acme/app/pull/3"}])

    github = publish.GitHub("secret-token", transport=transport)
    pull = github.open_pull_request("acme/app", head="scrutineering/remediation-1", base="main", title="t", body="b")
    assert pull["number"] == 3
    assert calls[1][1].endswith("/repos/acme/app/pulls?state=open&head=acme%3Ascrutineering/remediation-1")
    assert calls[0][2] == "Bearer secret-token"

    def forbidden(request, timeout):
        return _response({"message": "Resource not accessible by integration"}, 403)

    with pytest.raises(publish.PublishError) as error:
        publish.GitHub("secret-token", transport=forbidden).default_branch("acme/app")
    assert "403" in str(error.value) and "secret-token" not in str(error.value)


def test_github_repository_is_read_only_from_github_urls():
    from src.remediation.sources import github_repository

    assert github_repository("https://github.com/acme/app.git") == "acme/app"
    assert github_repository("https://github.example.com/acme/app") is None
    assert github_repository("app") is None
    with get_session() as session:
        assert session.query(Image).count() == 0


def test_github_sources_are_cloned_with_the_token_and_others_without(tmp_path, monkeypatch, remote):
    """Execution must reach private GitHub sources; no other source ever sees the token."""
    from src.remediation import build
    from src.remediation.sources import SourceSettings

    seen = []
    real_git = build.git

    def recording_git(args, *rest, **kwargs):
        if args[0] == "clone":
            seen.append((args[-2], (kwargs.get("env") or {}).get("SCRUTINEERING_GIT_TOKEN")))
        return real_git(args, *rest, **kwargs)

    monkeypatch.setattr(build, "git", recording_git)
    monkeypatch.setenv("GITHUB_TOKEN", "token-value")
    for name in ("one", "two"):
        (tmp_path / name).mkdir()
    github = SourceSettings.validated(repository="https://github.com/acme/app")
    _, commit = build.checkout(github, tmp_path / "one")
    assert commit == remote["commit"] and seen[-1] == (str(remote["bare"]), "token-value")
    assert "token-value" not in (tmp_path / "one" / "source" / ".git" / "config").read_text()

    local = tmp_path / "sources" / "app"
    _git(tmp_path, "clone", "-q", str(remote["bare"]), str(local))
    monkeypatch.setenv("REMEDIATION_SOURCES_ROOT", str(tmp_path / "sources"))
    build.checkout(SourceSettings.validated(repository="app"), tmp_path / "two")
    assert seen[-1][1] is None


def test_an_unexpected_failure_is_recorded_against_the_sources_provider(client, remote, monkeypatch):
    rid = _ready(client, remote)

    def explode(remediation_id, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(publish, "publish", explode)
    assert publish.publish_remediation.run(rid)["publication"] == "failed"
    publication = _publication(rid)
    assert (publication.provider, publication.status) == ("github", "failed")
    assert "boom" in publication.error_message
    assert _remediation(rid).status == RemediationStatus.READY
