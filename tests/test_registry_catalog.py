"""The bundled registry's catalog and tag details (docs/design/registry-management.md), against a fake registry."""

from __future__ import annotations

import json
from urllib.error import URLError

import pytest
from fastapi.testclient import TestClient

from src.api.app import create_app
from src.db.connection import get_session
from src.db.models import FindingSource, Remediation, RemediationStatus, ScanFinding, Severity
from src.scan.records import create_pending_scan, get_or_create_image, scan_identity
from src.scan.registry_catalog import MAX_DOCUMENT_BYTES, redact_history
from tests.fake_registry import HOST, INDEX, MANIFEST, FakeRegistry, digest_of

API_KEY = "registry-key"


@pytest.fixture
def registry(monkeypatch) -> FakeRegistry:
    fake = FakeRegistry()
    monkeypatch.setenv("LOCAL_REGISTRY_HOST", HOST)
    monkeypatch.setenv("REGISTRY_INSECURE", "true")
    monkeypatch.setattr("src.scan.registry_catalog._open", fake)
    return fake


def _client(monkeypatch, roles: str = "operator,security-operator") -> TestClient:
    monkeypatch.setenv("PYTHON_API_KEY", API_KEY)
    monkeypatch.setenv("DASHBOARD_DEFAULT_ROLES", roles)
    client = TestClient(create_app())
    client.headers["x-api-key"] = API_KEY
    return client


def _inventory(client: TestClient) -> tuple[dict, dict[str, dict]]:
    response = client.get("/api/dashboard/registry/inventory")
    assert response.status_code == 200, response.text
    body = response.json()
    return body, {f"{item['repository']}:{item['tag']}": item for item in body["tags"]}


def _detail(client: TestClient, repository: str, tag: str):
    return client.get("/api/dashboard/registry/tags/detail", params={"repository": repository, "tag": tag})


def _scanned(reference: str, status: str, findings: dict[str, Severity] | None = None) -> int:
    with get_session() as session:
        image = get_or_create_image(session, scan_identity(reference))
        create_pending_scan(session, reference).status = status
        for cve, severity in (findings or {}).items():
            session.add(
                ScanFinding(
                    image_id=image.id,
                    fingerprint=f"fp-{image.id}-{cve}",
                    vuln_key=f"{cve}:pkg",
                    cve_id=cve,
                    package_name="pkg",
                    package_version="1.0",
                    severity=severity,
                    source=FindingSource.TRIVY,
                )
            )
        return image.id


# Catalog


def test_size_is_the_layers_and_not_the_manifest(monkeypatch, registry):
    registry.tag("team/api", "1", registry.image({"base": 50_000_000, "app": 3_000_000}))
    _, tags = _inventory(_client(monkeypatch))
    assert tags["team/api:1"]["size"] == 53_000_000
    assert tags["team/api:1"]["platforms"] == [{"platform": "linux/amd64", "size": 53_000_000}]
    assert tags["team/api:1"]["error"] is None


def test_a_multi_platform_tag_lists_platforms_and_counts_attestations(monkeypatch, registry):
    amd = registry.image({"base": 10, "amd": 5})
    arm = registry.image({"base": 10, "arm": 7}, arch="arm64")
    proof = registry.image({"sbom": 3}, arch="unknown")
    digest = registry.index((amd, "linux/amd64"), (arm, "linux/arm64"), (proof, "unknown/unknown"))
    registry.tag("team/api", "1", digest)

    _, tags = _inventory(_client(monkeypatch))

    tag = tags["team/api:1"]
    assert tag["digest"] == digest
    assert tag["platforms"] == [{"platform": "linux/amd64", "size": 15}, {"platform": "linux/arm64", "size": 17}]
    assert tag["attestations"] == 1
    assert tag["size"] == 22  # the shared base layer counts once


def test_stored_bytes_count_each_blob_once(monkeypatch, registry):
    def own(digest: str) -> int:
        manifest = json.loads(registry.content[digest][1])
        return len(registry.content[digest][1]) + manifest["config"]["size"]

    one, two = registry.image({"base": 1000, "one": 10}), registry.image({"base": 1000, "two": 20})
    registry.tag("team/api", "1", one)
    registry.tag("team/api", "also-1", one)
    registry.tag("team/web", "1", two)

    body, _ = _inventory(_client(monkeypatch))

    assert body["repositories"] == [
        {"name": "team/api", "tags": 2, "stored_bytes": 1010 + own(one)},
        {"name": "team/web", "tags": 1, "stored_bytes": 1020 + own(two)},
    ]
    # The base layer is stored once for both repositories. Both images have the same config blob.
    config = json.loads(registry.content[one][1])["config"]["size"]
    assert body["summary"]["stored_bytes"] == 1030 + own(one) + own(two) - config


def test_layers_held_elsewhere_are_not_stored(monkeypatch, registry):
    config = registry.put({"os": "windows", "architecture": "amd64"})
    foreign = "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip"
    layers = [{"mediaType": foreign, "digest": digest_of(b"w"), "size": 9999}, {"digest": digest_of(b"a"), "size": 5}]
    document = {"mediaType": MANIFEST, "config": {"digest": config, "size": 1}, "layers": layers}
    registry.tag("team/win", "1", registry.put(document, MANIFEST))
    _, tags = _inventory(_client(monkeypatch))
    assert tags["team/win:1"]["size"] == 5


def test_tags_sharing_an_image_are_counted(monkeypatch, registry):
    same = registry.image({"a": 1})
    for tag in ("1", "2", "3"):
        registry.tag("team/api", tag, same)
    registry.tag("team/api", "4", registry.image({"b": 1}))
    registry.tag("team/other", "1", same)  # deleting in one repository doesn't touch another
    _, tags = _inventory(_client(monkeypatch))
    assert {name: tag["shared_count"] for name, tag in tags.items()} == {
        "team/api:1": 2,
        "team/api:2": 2,
        "team/api:3": 2,
        "team/api:4": 0,
        "team/other:1": 0,
    }


def test_listings_follow_pages_without_leaving_the_registry(monkeypatch, registry):
    registry.page_size = 2
    digest = registry.image({"a": 1})
    for number in range(5):
        registry.tag("team/api", f"t{number}", digest)
        registry.tag(f"repo{number}", "1", digest)
    body, tags = _inventory(_client(monkeypatch))
    assert body["summary"]["repositories"] == 6  # the fake's Link headers name another host
    assert len([name for name in tags if name.startswith("team/api:")]) == 5


def test_empty_repositories_are_left_out(monkeypatch, registry):
    registry.tag("team/api", "1", registry.image({"a": 1}))
    registry.tags["team/emptied"] = {}
    body, _ = _inventory(_client(monkeypatch))
    assert [item["name"] for item in body["repositories"]] == ["team/api"]
    assert body["summary"]["repositories"] == 1


def test_an_unreadable_image_doesnt_hide_the_others(monkeypatch, registry):
    registry.tag("team/api", "good", registry.image({"a": 1}))
    registry.tag("team/api", "gone", "sha256:" + "0" * 64)
    registry.tag("team/api", "huge", registry.put({"mediaType": MANIFEST, "x": "y" * MAX_DOCUMENT_BYTES}, MANIFEST))
    forged = registry.image({"b": 1})
    registry.content[forged] = (MANIFEST, b'{"layers": []}')
    registry.tag("team/api", "forged", forged)

    _, tags = _inventory(_client(monkeypatch))

    assert tags["team/api:good"]["size"] == 1
    assert tags["team/api:gone"]["error"] == "the registry answered 404"
    assert tags["team/api:huge"]["error"] == "the document is over 4 MB"
    assert tags["team/api:forged"]["error"] == "the content doesn't match its digest"
    assert tags["team/api:huge"]["size"] is None


@pytest.mark.parametrize("document", [{"layers": "x", "config": []}, {"manifests": [{}]}, {"layers": [1, {}]}])
def test_malformed_manifests_are_errors_not_crashes(monkeypatch, registry, document):
    registry.tag("team/api", "bad", registry.put(document, MANIFEST))
    _, tags = _inventory(_client(monkeypatch))
    assert tags["team/api:bad"]["error"]
    assert _detail(_client(monkeypatch), "team/api", "bad").status_code == 502


def test_a_second_load_reads_only_digests(monkeypatch, registry):
    registry.tag("team/api", "1", registry.image({"a": 1}))
    client = _client(monkeypatch)
    _, first = _inventory(client)
    registry.requests.clear()
    _, second = _inventory(client)
    assert first == second
    assert [method for method, path in registry.requests if "/manifests/" in path or "/blobs/" in path] == ["HEAD"]


def test_a_cache_failure_only_costs_requests(monkeypatch, registry):
    def down():
        raise ConnectionError("redis is down")

    monkeypatch.setattr("src.scan.registry_catalog._redis", down)
    registry.tag("team/api", "1", registry.image({"a": 1}))
    _, tags = _inventory(_client(monkeypatch))
    assert tags["team/api:1"]["size"] == 1


def test_an_unreadable_listing_is_unavailable_not_empty(monkeypatch, registry):
    registry.tag("team/api", "1", registry.image({"a": 1}))
    registry.failing.add("/v2/team/api/tags/list")
    response = _client(monkeypatch).get("/api/dashboard/registry/inventory")
    assert (response.status_code, response.json()["detail"]) == (503, "local_registry_unavailable")


def test_an_unreachable_registry_is_unavailable(monkeypatch, registry):
    def refuse(request, timeout):
        raise URLError("connection refused")

    monkeypatch.setattr("src.scan.registry_catalog._open", refuse)
    response = _client(monkeypatch).get("/api/dashboard/registry/inventory")
    assert (response.status_code, response.json()["detail"]) == (503, "local_registry_unavailable")


# Scan state


def test_tags_are_joined_with_scan_state(monkeypatch, registry):
    for name in ("api", "web", "bad", "new"):
        registry.tag(f"team/{name}", "1", registry.image({name: 1}))
    registry.tag("team/api", "2", registry.image({"two": 1}))
    api1 = _scanned(f"{HOST}/team/api:1", "completed", {"CVE-1": Severity.CRITICAL, "CVE-2": Severity.LOW})
    _scanned(f"{HOST}/team/api:2", "completed")
    _scanned(f"{HOST}/team/web:1", "running")
    _scanned(f"{HOST}/team/bad:1", "failed")

    body, tags = _inventory(_client(monkeypatch))

    assert {name: tag["security_status"] for name, tag in tags.items()} == {
        "team/api:1": "issues_found",
        "team/api:2": "clean",
        "team/web:1": "scanning",
        "team/bad:1": "scan_failed",
        "team/new:1": "not_scanned",
    }
    tag = tags["team/api:1"]
    assert (tag["image_id"], tag["open_findings"], tag["critical_count"], tag["high_count"]) == (api1, 2, 1, 0)
    assert tag["image_name"] == f"{HOST}/team/api:1"
    summary = {key: value for key, value in body["summary"].items() if key != "stored_bytes"}
    assert summary == {
        "repositories": 4,
        "tags": 5,
        "scanned": 4,
        "not_scanned": 1,
        "scanning": 1,
        "issues_found": 1,
        "clean": 1,
    }


def test_a_docker_hub_image_with_the_same_name_is_another_image(monkeypatch, registry):
    registry.tag("team/app", "1.0", registry.image({"a": 1}))
    _scanned("team/app:1.0", "completed", {"CVE-1": Severity.CRITICAL})
    _, tags = _inventory(_client(monkeypatch))
    tag = tags["team/app:1.0"]
    assert (tag["image_id"], tag["security_status"], tag["open_findings"]) == (None, "not_scanned", 0)


# Candidates


def _remediation(digest: str, status: RemediationStatus = RemediationStatus.READY) -> int:
    with get_session() as session:
        image = get_or_create_image(session, scan_identity(f"{HOST}/team/api:1"))
        row = Remediation(image_id=image.id, status=status, candidate_digest=digest)
        session.add(row)
        session.flush()
        row.candidate_image = f"{HOST}/team/api:scrutineering-candidate-{row.id}"
        return row.id


def test_a_candidate_names_its_remediation(monkeypatch, registry):
    digest = registry.image({"a": 1})
    remediation_id = _remediation(digest)
    registry.tag("team/api", f"scrutineering-candidate-{remediation_id}", digest)
    registry.tag("team/api", "1", digest)

    _, tags = _inventory(_client(monkeypatch))
    assert tags["team/api:1"]["candidate"] is None
    candidate = tags[f"team/api:scrutineering-candidate-{remediation_id}"]["candidate"]
    assert candidate == {"remediation_id": remediation_id, "status": "ready", "unmatched": False}

    _, tags = _inventory(_client(monkeypatch, roles="operator"))  # may not see remediations
    candidate = tags[f"team/api:scrutineering-candidate-{remediation_id}"]["candidate"]
    assert candidate == {"remediation_id": None, "status": None, "unmatched": False}


def test_a_reused_remediation_number_is_not_the_candidates(monkeypatch, registry):
    remediation_id = _remediation("sha256:" + "1" * 64)
    registry.tag("team/api", f"scrutineering-candidate-{remediation_id}", registry.image({"old": 1}))
    registry.tag("team/web", f"scrutineering-candidate-{remediation_id}", registry.image({"web": 1}))
    _, tags = _inventory(_client(monkeypatch))
    assert [tag["candidate"] for tag in tags.values()] == [
        {"remediation_id": None, "status": None, "unmatched": True}
    ] * 2


# Details


def test_detail_describes_the_image_without_its_environment(monkeypatch, registry):
    config = {
        "Env": ["API_TOKEN=hunter2"],
        "Labels": {"org.opencontainers.image.source": "https://git.example/api"},
        "Entrypoint": ["/app"],
        "Cmd": ["--serve"],
        "ExposedPorts": {"8080/tcp": {}},
        "User": "1000",
        "WorkingDir": "/srv",
    }
    history = [
        {"created": "2026-01-01T00:00:00Z", "created_by": "COPY . /srv # buildkit"},
        {"created_by": "ENV API_TOKEN=hunter2", "empty_layer": True},
        {"created_by": "RUN |1 API_TOKEN=hunter2 /bin/sh -c npm ci # buildkit"},
    ]
    digest = registry.image({"a": 4, "b": 6}, config=config, created="2026-01-02T00:00:00Z", history=history)
    registry.tag("team/api", "1", digest)

    response = _detail(_client(monkeypatch), "team/api", "1")

    assert response.status_code == 200, response.text
    assert "hunter2" not in response.text
    body = response.json()
    assert (body["digest"], body["attestations"], len(body["images"])) == (digest, 0, 1)
    image = body["images"][0]
    assert (image["platform"], image["size"], image["created"]) == ("linux/amd64", 10, "2026-01-02T00:00:00Z")
    assert [layer["size"] for layer in image["layers"]] == [4, 6]
    assert image["labels"] == {"org.opencontainers.image.source": "https://git.example/api"}
    assert (image["entrypoint"], image["command"]) == (["/app"], ["--serve"])
    assert (image["exposed_ports"], image["user"], image["working_dir"]) == (["8080/tcp"], "1000", "/srv")
    assert [item["command"] for item in image["history"]] == [
        "COPY . /srv # buildkit",
        "ENV API_TOKEN=…",
        "RUN |… /bin/sh -c npm ci # buildkit",
    ]


def test_detail_lists_every_platform(monkeypatch, registry):
    amd, arm = registry.image({"amd": 5}), registry.image({"arm": 7}, arch="arm64")
    proof = registry.image({"sbom": 3}, arch="unknown")
    index = registry.index((amd, "linux/amd64"), (arm, "linux/arm64"), (proof, "unknown/unknown"))
    registry.tag("team/api", "1", index)
    body = _detail(_client(monkeypatch), "team/api", "1").json()
    assert [(item["platform"], item["digest"], item["size"]) for item in body["images"]] == [
        ("linux/amd64", amd, 5),
        ("linux/arm64", arm, 7),
    ]
    assert (body["media_type"], body["attestations"]) == (INDEX, 1)


def test_detail_refuses_bad_names_and_missing_tags(monkeypatch, registry):
    registry.tag("team/api", "1", registry.image({"a": 1}))
    client = _client(monkeypatch)
    for repository, tag in (("../secrets", "1"), ("team/api", "../../_catalog"), ("Team", "1"), ("a//b", "1")):
        assert _detail(client, repository, tag).status_code == 400
    assert registry.requests == []
    assert _detail(client, "team/api", "missing").status_code == 404


def test_reading_the_registry_needs_its_permission(monkeypatch, registry):
    registry.tag("team/api", "1", registry.image({"a": 1}))
    client = _client(monkeypatch, roles="remediator")
    assert client.get("/api/dashboard/registry/inventory").status_code == 403
    assert _detail(client, "team/api", "1").status_code == 403


@pytest.mark.parametrize(
    ("command", "shown"),
    [
        ("ENV A=1 B=2", "ENV A=…"),
        ("ENV PASSWORD secret", "ENV PASSWORD=…"),
        ("/bin/sh -c #(nop)  ENV TOKEN=x", "ENV TOKEN=…"),
        ("ARG TOKEN=x", "ARG TOKEN=…"),
        ("ENV 'odd'=x", "ENV …"),
        ("|1 TOKEN=x /bin/sh -c make", "|… /bin/sh -c make"),
        ("RUN |1 TOKEN=x /bin/bash -c make", "RUN |…"),
        ("RUN /bin/sh -c make", "RUN /bin/sh -c make"),
        ("ENVOY start", "ENVOY start"),
    ],
)
def test_history_hides_environment_and_build_arguments(command, shown):
    assert redact_history(command) == shown
