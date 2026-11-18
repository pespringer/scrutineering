"""Golden path: the product's core loop, end to end, without live scanners.

This test defines "working" (docs/RESET-PLAN.md, ground rule 1). It drives the
real FastAPI app over HTTP, the real worker functions, a real git checkout of
the fixture source, and a real schema. The stand-ins are external binaries on
PATH: `trivy` and `grype` replay output recorded from the fixture images
(fixtures/images/vulnerable-node, re-recorded by scripts/record-golden-fixtures.sh),
`npm` rewrites the manifest and lockfile as `npm install --package-lock-only`
would, and `buildctl` reports a digest instead of building. GitHub is a bare git
repository plus a fake REST client.

  scan the fixture -> findings -> connect its source -> propose a fix -> approve
  -> execute: patch, build the candidate, run the source's tests in it, scan it -> ready
  -> open a pull request with the patch -> published -> merge webhook queues a rescan
  -> rescan the rebuilt image -> the targeted finding resolves -> remediation completed
  (each step that needs a person, or ends the loop, sends a signed webhook notification)
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from src.api.app import create_app
from src.db.connection import get_session
from src.db.models import ScanFinding

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures"
RECORDED = FIXTURES / "scanner-output" / "vulnerable-node"
IMAGE = "registry:5000/fixtures/vulnerable-node:1.0"
TARGET_CVE, TARGET_PACKAGE = "CVE-2021-23337", "lodash"
API_KEY = "golden-path-key"


@pytest.fixture
def stage(tmp_path, monkeypatch):
    """Fake scanner binaries that replay recorded output for the current stage."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    stage_file = tmp_path / "stage"
    for scanner in ("trivy", "grype"):
        script = bin_dir / scanner
        # The SBOM step after each scan asks Trivy for CycloneDX (docs/design/sbom-evidence.md).
        sbom = f'case " $* " in *" cyclonedx "*) cat "{RECORDED}/cyclonedx.json"; exit 0 ;; esac\n'
        script.write_text(
            f'#!/bin/sh\n{sbom if scanner == "trivy" else ""}cat "{RECORDED}/$(cat "{stage_file}")-{scanner}.json"\n'
        )
        script.chmod(script.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")

    def use(name: str) -> None:
        stage_file.write_text(name)

    use("before")
    return use


FAKE_NPM = """#!PYTHON
# Stand-in for `npm install <pkg>@<version> --save --save-exact --package-lock-only`.
import json, sys
spec = next(arg for arg in sys.argv[2:] if not arg.startswith("-"))
package, version = spec.rsplit("@", 1)
manifest = json.load(open("package.json"))
manifest["dependencies"][package] = version
json.dump(manifest, open("package.json", "w"), indent=2)
lock = json.load(open("package-lock.json"))
lock["packages"][""]["dependencies"][package] = version
lock["packages"]["node_modules/" + package]["version"] = version
json.dump(lock, open("package-lock.json", "w"), indent=2)
"""

FAKE_BUILDCTL = """#!PYTHON
# Stand-in for `buildctl build`: report a digest for the pushed image. The test-stage build
# (the source's test command) succeeds when its RUN line is the expected command.
import json, os, sys
args = sys.argv
if "target=scrutineering-test" in args:
    folder = [arg.split("=", 1)[1] for arg in args if arg.startswith("dockerfile=")][0]
    sys.exit(0 if TEST_RUN in open(os.path.join(folder, "Dockerfile")).read() else 1)
json.dump({"containerimage.digest": "sha256:" + "c" * 64}, open(args[args.index("--metadata-file") + 1], "w"))
"""
# The fixture image's test: the patched lodash is the one installed in the candidate.
TEST_COMMAND = ["node", "-e", "process.exit(require('lodash/package.json').version === '4.17.21' ? 0 : 1)"]


@pytest.fixture
def source(tmp_path, monkeypatch):
    """The fixture image's source as a git repository under the worker's sources root."""
    root = tmp_path / "sources"
    repository = root / "vulnerable-node"
    shutil.copytree(FIXTURES / "images" / "vulnerable-node", repository)
    for command in (["init", "-q"], ["add", "."], ["commit", "-q", "-m", "fixture"]):
        subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", *command], cwd=repository, check=True)
    bin_dir = tmp_path / "tools"
    bin_dir.mkdir()
    for name, body in (("npm", FAKE_NPM), ("buildctl", FAKE_BUILDCTL)):
        script = bin_dir / name
        test_run = repr(f"RUN {json.dumps(TEST_COMMAND)}")
        script.write_text(body.replace("#!PYTHON", f"#!{sys.executable}").replace("TEST_RUN", test_run))
        script.chmod(script.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setenv("REMEDIATION_SOURCES_ROOT", str(root))
    return "vulnerable-node"


@pytest.fixture
def api(monkeypatch):
    """The real app, with scans run synchronously by the real worker."""
    from src.scan import tasks

    monkeypatch.setenv("PYTHON_API_KEY", API_KEY)
    monkeypatch.setenv("DASHBOARD_DEFAULT_ROLES", "dashboard,operator,remediator,security-operator")
    monkeypatch.setenv("REMEDIATION_EXECUTION_ENABLED", "true")
    monkeypatch.setattr(
        tasks,
        "enqueue_scan",
        lambda target, **kw: tasks.run_scan.run.__func__(MagicMock(), target, scan_id=kw["scan_id"]),
    )
    from src.api.routes import remediations
    from src.remediation.worker import run_remediation

    class RunNow:
        @staticmethod
        def apply_async(args, queue):
            run_remediation(*args)
            return MagicMock(id="remediation-task")

    monkeypatch.setattr(remediations, "execute_approved_remediation", RunNow)
    client = TestClient(create_app())
    client.headers["x-api-key"] = API_KEY
    return client


def _scan(api: TestClient, image: str = IMAGE) -> dict:
    response = api.post("/api/dashboard/scans", json={"image_name": image})
    assert response.status_code == 202, response.text
    scan = api.get(f"/api/dashboard/scans/{response.json()['scan_id']}").json()
    assert scan["status"] == "completed", scan
    return scan


def _target_finding(api: TestClient, scan_id: str) -> dict:
    items = api.get(f"/api/dashboard/scans/{scan_id}/findings", params={"limit": 200}).json()["items"]
    page = 0
    while len(items) == 200 * (page + 1):
        page += 1
        items += api.get(
            f"/api/dashboard/scans/{scan_id}/findings", params={"limit": 200, "offset": 200 * page}
        ).json()["items"]
    matches = [item for item in items if item["cve_id"] == TARGET_CVE and item["package_name"] == TARGET_PACKAGE]
    assert len(matches) == 1, f"expected one {TARGET_CVE} finding, got {len(matches)}"
    return matches[0]


def _recorded_count(stage: str) -> int:
    trivy = json.loads((RECORDED / f"{stage}-trivy.json").read_text())
    return sum(len(result.get("Vulnerabilities") or []) for result in trivy["Results"])


def test_scan_half_finds_the_fixture_vulnerabilities(api, stage):
    scan = _scan(api)

    assert scan["image_name"] == IMAGE
    assert scan["findings"] >= _recorded_count("before") * 0.9  # Grype adds some; dedup merges the rest
    lodash = _target_finding(api, scan["scan_id"])
    assert lodash["package_version"] == "4.17.20"
    assert lodash["fixed_version"] == "4.17.21"
    assert lodash["fix_available"] is True
    assert lodash["lifecycle_status"] == "open"
    assert lodash["severity"] == "HIGH"

    image = api.get(f"/api/dashboard/images/{scan['image_id']}").json()["image"]
    assert image["name"] == IMAGE
    assert image["open_findings"] == scan["findings"]

    # The scan's CycloneDX SBOM (docs/design/sbom-evidence.md), downloadable for the scan and the image.
    sbom = api.get(f"/api/dashboard/scans/{scan['scan_id']}/sbom")
    assert sbom.status_code == 200 and sbom.headers["content-type"].startswith("application/vnd.cyclonedx+json")
    document = sbom.json()
    assert document["bomFormat"] == "CycloneDX"
    assert {"name": TARGET_PACKAGE, "version": "4.17.20"}.items() <= next(
        component for component in document["components"] if component["name"] == TARGET_PACKAGE
    ).items()
    assert image["sbom"]["scan_id"] == scan["scan_id"]
    assert image["sbom"]["components"] == len(document["components"])
    assert image["sbom"]["sha256"] == sbom.headers["x-scrutineering-sbom-sha256"]
    assert api.get(f"/api/dashboard/images/{scan['image_id']}/sbom").content == sbom.content
    # Signed with this instance's key; anyone can check it with the served public key alone.
    from src.signing import verify

    [key] = api.get("/api/dashboard/signing-keys").json()["keys"]
    assert sbom.headers["x-scrutineering-key-id"] == key["key_id"]
    assert verify(sbom.content, sbom.headers["x-scrutineering-signature"], key["public_key_pem"])
    assert api.get("/api/dashboard/posture/summary").json()["total_findings"] == scan["findings"]


def test_saved_text_fits_its_columns(api, stage):
    """SQLite ignores VARCHAR lengths; Postgres rejects the insert. Check the limits here.

    Regression: Grype has no title field, so long descriptions became titles over
    the 1024-character column and the live scan failed to save.
    """
    import sqlalchemy as sa
    from src.db.models import FindingObservation

    _scan(api)
    with get_session() as session:
        for model in (ScanFinding, FindingObservation):
            for column in model.__table__.columns:
                limit = getattr(column.type, "length", None)
                if isinstance(column.type, sa.String) and limit:
                    longest = session.query(sa.func.max(sa.func.length(column))).scalar() or 0
                    assert longest <= limit, f"{model.__tablename__}.{column.name}: {longest} > {limit}"


def test_rescan_of_the_patched_image_resolves_the_targeted_finding(api, stage):
    """Lifecycle the remediation loop relies on: the fixed image's scan closes the finding."""
    before = _scan(api)
    stage("after")
    after = _scan(api)

    with get_session() as session:
        lodash = session.query(ScanFinding).filter_by(cve_id=TARGET_CVE, package_name=TARGET_PACKAGE).one()
        assert lodash.resolved_at is not None
    # Each scan keeps what it saw.
    assert _target_finding(api, before["scan_id"])["package_version"] == "4.17.20"
    after_items = api.get(f"/api/dashboard/scans/{after['scan_id']}/findings", params={"limit": 200}).json()
    assert TARGET_CVE not in {item["cve_id"] for item in after_items["items"]}


def _fix_to_ready(api: TestClient, stage, repository: str) -> tuple[int, dict]:
    """Scan, connect the source, propose and approve the lodash fix, and execute it to `ready`."""
    scan = _scan(api)
    lodash = _target_finding(api, scan["scan_id"])
    connected = api.put(
        f"/api/dashboard/images/{scan['image_id']}/source",
        json={"repository": repository, "test_command": TEST_COMMAND},
    )
    assert connected.status_code == 200, connected.text

    preview = api.post(
        "/api/dashboard/remediations/preview", json={"image_id": scan["image_id"], "finding_ids": [lodash["id"]]}
    ).json()
    assert preview["actionable_count"] == 1, preview
    assert [action["strategy"] for action in preview["actions"]] == ["dependency_update"]

    created = api.post(
        "/api/dashboard/remediations", json={"image_id": scan["image_id"], "finding_ids": [lodash["id"]]}
    )
    assert created.status_code == 201, created.text
    remediation_id = created.json()["id"]

    assert api.post(f"/api/dashboard/remediations/{remediation_id}/approve").status_code == 200
    stage("patched")  # what the candidate built from the patched source scans as
    assert api.post(f"/api/dashboard/remediations/{remediation_id}/execute").status_code == 202

    remediation = api.get(f"/api/dashboard/remediations/{remediation_id}").json()
    assert remediation["status"] == "ready", remediation
    assert '"lodash": "4.17.21"' in remediation["patch"]
    assert remediation["candidate_image"] == (
        "registry:5000/fixtures/vulnerable-node:scrutineering-candidate-" + str(remediation_id)
    )
    assert remediation["verification"]["still_present"] == []
    assert remediation["verification"]["new_critical_or_high"] == []
    assert remediation["resolved_finding_count"] == 0  # the running image is unchanged until it is rebuilt
    events = [
        event["event_type"]
        for event in api.get(f"/api/dashboard/remediations/{remediation_id}/events").json()["events"]
    ]
    assert "tested" in events  # the source's test command ran in the candidate
    return remediation_id, remediation


def test_remediation_half_fixes_the_dependency_and_verifies_by_rescan(api, stage, source):
    remediation_id, _ = _fix_to_ready(api, stage, source)

    _scan(api)  # the image is rebuilt from the patched source and scanned again
    remediation = api.get(f"/api/dashboard/remediations/{remediation_id}").json()
    assert remediation["status"] == "completed", remediation
    assert remediation["resolved_finding_count"] == 1


class FakeGitHub:
    """Stand-in for the GitHub REST API; the git side is a real bare repository."""

    pulls: list[dict] = []

    def __init__(self, token, transport=None):
        assert token == "golden-path-token"

    def default_branch(self, repository):
        return "main"

    def open_pull_request(self, repository, *, head, base, title, body):
        self.pulls.append({"repository": repository, "head": head, "base": base, "body": body})
        return {"number": 1, "html_url": f"https://github.com/{repository}/pull/1"}


@pytest.fixture
def github(tmp_path, monkeypatch, source):
    """The fixture source hosted on a stand-in github.com, with publication running synchronously."""
    from src.api.routes import remediations, webhooks
    from src.remediation import publish, sources

    hosted = tmp_path / "github" / "fixtures" / "vulnerable-node.git"
    hosted.parent.mkdir(parents=True)
    subprocess.run(["git", "clone", "-q", "--bare", str(tmp_path / "sources" / source), str(hosted)], check=True)
    monkeypatch.setattr(sources, "GITHUB_WEB", str(tmp_path / "github"))
    monkeypatch.setattr(publish, "GitHub", FakeGitHub)
    monkeypatch.setenv("GITHUB_TOKEN", "golden-path-token")
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", "golden-path-secret")
    FakeGitHub.pulls = []

    class PublishNow:
        @staticmethod
        def apply_async(args, queue):
            publish.publish(*args)
            return MagicMock(id="publish-task")

    monkeypatch.setattr(remediations, "publish_remediation", PublishNow)
    rescans = []
    monkeypatch.setattr(webhooks, "queue_rescan", rescans.append)
    return {"hosted": hosted, "rescans": rescans}


@pytest.fixture
def receiver(monkeypatch):
    """A webhook notification channel, with an in-process receiver standing in for the operator's."""
    import httpx

    from src.notifications import delivery, outbox

    monkeypatch.setenv("NOTIFICATION_WEBHOOK_URL", "https://hooks.example.test/scrutineering")
    monkeypatch.setenv("NOTIFICATION_WEBHOOK_SECRET", "golden-path-notify")
    monkeypatch.setattr(outbox, "enqueue_delivery", lambda: None)  # the test delivers, as the sweep would
    received = []

    def handle(request: httpx.Request) -> httpx.Response:
        received.append(request)
        return httpx.Response(204)

    monkeypatch.setattr(delivery, "transport", httpx.MockTransport(handle))
    return received


def _merge_webhook(api: TestClient, number: int) -> dict:
    import hashlib
    import hmac

    body = json.dumps(
        {
            "action": "closed",
            "repository": {"full_name": "fixtures/vulnerable-node"},
            "pull_request": {"number": number, "merged": True, "merge_commit_sha": "e" * 40},
        }
    ).encode()
    signature = "sha256=" + hmac.new(b"golden-path-secret", body, hashlib.sha256).hexdigest()
    headers = {"x-github-delivery": "merge-1", "x-github-event": "pull_request", "x-hub-signature-256": signature}
    response = api.post("/api/dashboard/webhooks/github", content=body, headers=headers)
    assert response.status_code == 200, response.text
    return response.json()


def test_remediation_is_published_as_a_pull_request_and_completes_after_merge(api, stage, github, receiver):
    remediation_id, _ = _fix_to_ready(api, stage, "https://github.com/fixtures/vulnerable-node")

    published = api.post(f"/api/dashboard/remediations/{remediation_id}/publish")
    assert published.status_code == 202, published.text
    remediation = api.get(f"/api/dashboard/remediations/{remediation_id}").json()
    assert remediation["status"] == "published", remediation
    [pull] = FakeGitHub.pulls
    branch = f"scrutineering/remediation-{remediation_id}"
    assert pull["head"] == branch and pull["base"] == "main"
    assert TARGET_CVE in pull["body"]
    package = subprocess.run(
        ["git", "show", f"{branch}:package.json"], cwd=github["hosted"], check=True, capture_output=True, text=True
    ).stdout
    assert '"lodash": "4.17.21"' in package  # the pushed branch carries the verified patch

    merged = _merge_webhook(api, remediation["publications"][0]["number"])
    assert merged["publication"] == "merged" and github["rescans"] == [IMAGE], merged
    assert api.get(f"/api/dashboard/remediations/{remediation_id}").json()["status"] == "published"

    _scan(api)  # the queued rescan, once the merged source is rebuilt into the image
    remediation = api.get(f"/api/dashboard/remediations/{remediation_id}").json()
    assert remediation["status"] == "completed", remediation
    assert remediation["resolved_finding_count"] == 1

    # Every step that needs a person, or finishes the loop, was announced, signed, in order.
    import hashlib
    import hmac

    from src.notifications.delivery import deliver

    assert deliver()["sent"] == 4
    bodies = []
    for request in receiver:
        expected = "sha256=" + hmac.new(b"golden-path-notify", request.content, hashlib.sha256).hexdigest()
        assert request.headers["x-scrutineering-signature"] == expected
        bodies.append(json.loads(request.content))
    assert [body["event"] for body in bodies] == [
        "remediation.proposed",
        "remediation.ready",
        "remediation.published",
        "remediation.completed",
    ]
    assert all(body["remediation"]["id"] == remediation_id for body in bodies)
    assert [body["remediation"]["status"] for body in bodies] == ["proposed", "ready", "published", "completed"]
    assert bodies[2]["remediation"]["pull_request_url"] == "https://github.com/fixtures/vulnerable-node/pull/1"
