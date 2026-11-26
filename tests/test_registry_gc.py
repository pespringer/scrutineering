"""`make registry-gc`: its preflight (src/scan/registry_gc.py) and the script that runs it (scripts/registry-gc.py)."""

from __future__ import annotations

import importlib.util
import json
import subprocess
from datetime import timedelta
from pathlib import Path

import pytest

from src.db.connection import get_session
from src.db.models import Deployment, Remediation, RemediationStatus
from src.scan.deployments import utcnow
from src.scan.records import create_pending_scan, get_or_create_image, scan_identity
from src.scan.registry_gc import Running, from_docker, main, preflight
from tests.fake_registry import HOST, FakeRegistry

PUBLIC = "localhost:5000"
S = RemediationStatus


@pytest.fixture
def registry(monkeypatch) -> FakeRegistry:
    fake = FakeRegistry()
    monkeypatch.setenv("LOCAL_REGISTRY_HOST", HOST)
    monkeypatch.setenv("LOCAL_REGISTRY_PUBLIC_HOST", PUBLIC)
    monkeypatch.setenv("REGISTRY_INSECURE", "true")
    monkeypatch.setattr("src.scan.registry_catalog._open", fake)
    monkeypatch.setattr("src.scan.registry_catalog._cached", lambda digests: {})
    monkeypatch.setattr("src.scan.registry_catalog._cache", lambda summaries: None)
    return fake


def _container(image_ref: str, digests: list[str], *, gone=False, seen_days_ago=0) -> None:
    seen = utcnow() - timedelta(days=seen_days_ago)
    with get_session() as session:
        image = get_or_create_image(session, scan_identity(image_ref))
        session.add(
            Deployment(
                container_id=f"c-{image_ref}",
                name="web-1",
                image_ref=image_ref,
                image_id=image.id,
                running_digests=digests,
                first_seen_at=seen,
                last_seen_at=seen,
                gone_at=seen if gone else None,
            )
        )


# Work in progress


def test_an_idle_stack_may_be_collected(registry, capsys):
    registry.tag("team/api", "1", registry.image({"a": 1}))
    assert preflight() == []
    assert main() == 0
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize("status", list(S))
def test_a_remediation_building_or_verifying_stops_it(registry, status):
    with get_session() as session:
        image = get_or_create_image(session, scan_identity(f"{HOST}/team/api:1"))
        session.add(Remediation(image_id=image.id, status=status))
    problems = preflight()
    assert bool(problems) == (status in (S.BUILDING, S.VERIFYING))


@pytest.mark.parametrize("status", ["pending", "running", "completed", "failed"])
@pytest.mark.parametrize("host", [HOST, PUBLIC])
def test_a_scan_of_a_local_image_stops_it(registry, status, host):
    with get_session() as session:
        create_pending_scan(session, f"{host}/team/api:1").status = status
    problems = preflight()
    assert bool(problems) == (status in ("pending", "running"))
    assert all("team/api:1" in problem for problem in problems)


def test_a_scan_of_another_registrys_image_doesnt(registry):
    with get_session() as session:
        create_pending_scan(session, "team/api:1")
        create_pending_scan(session, "ghcr.io/team/api:1")
    assert preflight() == []


# Running containers


@pytest.mark.parametrize("host", [HOST, PUBLIC])
def test_a_container_of_a_build_no_tag_keeps_stops_it(registry, capsys, host):
    untagged = registry.image({"old": 1})
    registry.tag("team/api", "1", registry.image({"new": 1}))
    _container(f"{host}/team/api:1", [untagged])
    (problem,) = preflight()
    assert "web-1" in problem and "no tag keeps" in problem
    assert main() == 1
    assert "web-1" in capsys.readouterr().out


@pytest.mark.parametrize("known_by", ["index", "platform", "config"])
def test_a_build_a_tag_keeps_is_fine_however_docker_names_it(registry, known_by):
    platform = registry.image({"a": 1})
    index = registry.index((platform, "linux/amd64"))
    config = json.loads(registry.content[platform][1])["config"]["digest"]
    registry.tag("team/api", "2", index)
    _container(f"{HOST}/team/api:1", [{"index": index, "platform": platform, "config": config}[known_by]])
    assert preflight() == []


def test_an_untagged_config_is_found_as_a_blob(registry):
    platform = registry.image({"old": 1}, config={"User": "old"})
    config = json.loads(registry.content[platform][1])["config"]["digest"]
    registry.tag("team/api", "1", registry.image({"new": 1}))
    _container(f"{HOST}/team/api:1", [config])
    assert len(preflight()) == 1


def test_a_build_the_registry_never_held_is_fine(registry):
    # Built and run on the host, never pushed: collection can't remove it.
    registry.tag("team/api", "1", registry.image({"a": 1}))
    _container(f"{PUBLIC}/team/api:dev", ["sha256:" + "7" * 64])
    assert preflight() == []


def test_containers_that_dont_count(registry):
    untagged = registry.image({"old": 1})
    registry.tag("team/api", "1", registry.image({"new": 1}))
    _container(f"{HOST}/team/api:gone", [untagged], gone=True)
    _container(f"{HOST}/team/api:quiet", [untagged], seen_days_ago=31)
    # Docker Hub's team/api is another image.
    _container("team/api:1", [untagged])
    assert preflight() == []


def test_unreadable_tags_are_named_when_they_may_keep_the_build(registry):
    untagged = registry.image({"old": 1})
    registry.tag("team/api", "1", untagged)
    registry.failing.add(f"/v2/team/api/manifests/{untagged}")
    _container(f"{HOST}/team/api:1", [untagged])
    registry.failing.discard(f"/v2/team/api/manifests/{untagged}")
    registry.failing.add("/v2/team/api/manifests/1")
    problems = preflight()
    assert problems[-1] == "These tags couldn't be read, and may keep it: team/api:1"


def test_a_container_discovery_didnt_record_is_found_through_docker(registry):
    # Its tag moved before discovery ran, so `docker ps` shows only an image ID.
    untagged = registry.image({"old": 1})
    registry.tag("team/api", "1", registry.image({"new": 1}))
    running = Running("dev-1", f"{PUBLIC}/team/api:1", frozenset({untagged}))
    (problem,) = preflight(docker=[running])
    assert "dev-1" in problem
    assert preflight(docker=[Running("hub-1", "team/api:1", frozenset({untagged}))]) == []


def test_a_container_both_report_is_named_once(registry):
    untagged = registry.image({"old": 1})
    registry.tag("team/api", "1", registry.image({"new": 1}))
    _container(f"{HOST}/team/api:1", [untagged])
    assert len(preflight(docker=[Running("web-1", f"{HOST}/team/api:1", frozenset({untagged}))])) == 1


def test_dockers_report_is_read_defensively(monkeypatch, registry, capsys):
    document = json.dumps(
        [
            {"name": "dev-1", "image_ref": f"{PUBLIC}/team/api:1", "digests": ["sha256:" + "a" * 64, "../x", 7]},
            "junk",
            {"name": "x" * 300, "image_ref": None, "digests": None},
        ]
    )
    first, second = from_docker(document)
    assert (first.name, first.digests) == ("dev-1", frozenset({"sha256:" + "a" * 64}))
    assert (len(second.name), second.image_ref, second.digests) == (256, "", frozenset())
    assert from_docker("") == []

    untagged = registry.image({"old": 1})
    registry.tag("team/api", "1", registry.image({"new": 1}))
    payload = json.dumps([{"name": "dev-1", "image_ref": f"{PUBLIC}/team/api:1", "digests": [untagged]}])
    monkeypatch.setattr("sys.argv", ["registry_gc", "--containers", "-"])
    monkeypatch.setattr("sys.stdin", __import__("io").StringIO(payload))
    assert main() == 1
    assert "dev-1" in capsys.readouterr().out


def test_an_unreachable_registry_stops_it(registry):
    _container(f"{HOST}/team/api:1", ["sha256:" + "7" * 64])
    registry.failing.add("/v2/_catalog")
    assert preflight() == ["The registry can't be read: the registry answered 500."]


# The script


def _script():
    path = Path(__file__).parent.parent / "scripts" / "registry-gc.py"
    spec = importlib.util.spec_from_file_location("registry_gc_script", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Docker:
    """`docker` as the script calls it: records each call, and answers as told."""

    def __init__(self, preflight=0, collected=0, healthy=True):
        self.calls: list[str] = []
        self.preflight, self.collected, self.healthy = preflight, collected, healthy
        self.stored = iter(["2048\t/var/lib/registry", "512\t/var/lib/registry"])

    def __call__(self, args, capture_output=True, text=True, check=False, input=None):
        command = " ".join(args)
        self.calls.append(command)
        code, out = 0, ""
        if command == "docker ps -q":
            out = "c1 c2 c3\n"
        elif command == "docker inspect c1 c2 c3":
            # c3 stopped meanwhile: Docker still prints the others, and fails.
            code = 1
            out = json.dumps(
                [
                    {"Name": "/dev-1", "Image": "sha256:" + "1" * 64, "Config": {"Image": "localhost:5000/a:1"}},
                    {"Name": "/old-1", "Image": "sha256:" + "3" * 64, "Config": {"Image": "localhost:5000/a:0"}},
                ]
            )
        elif command.startswith("docker image inspect") and command.endswith("1" * 64):
            out = json.dumps(["localhost:5000/a@sha256:" + "2" * 64]) + "\n"
        elif command.startswith("docker image inspect"):
            # Its tag moved, and containerd's image store no longer knows it by ID.
            code, out = 1, "\n"
        elif "src.scan.registry_gc" in command:
            self.sent = json.loads(input)
            code, out = self.preflight, "Scan s1 of x is pending or running." if self.preflight else ""
        elif "du -sk" in command:
            out = next(self.stored)
        elif "garbage-collect" in command:
            if self.collected is None:
                raise KeyboardInterrupt
            code, out = self.collected, "106 blobs marked, 218 blobs and 124 manifests eligible for deletion"
        elif command.startswith("docker inspect"):
            out = "healthy" if self.healthy else "starting"
        elif "ps -q registry" in command:
            out = "abc"
        if check and code:
            raise subprocess.CalledProcessError(code, args)
        return subprocess.CompletedProcess(args, code, out, "")

    def steps(self) -> list[str]:
        names = {"registry_gc": "preflight", " stop ": "stop", "garbage-collect": "collect", " start ": "start"}
        return [name for call in self.calls for key, name in names.items() if key in f"{call} "]


@pytest.fixture
def script(monkeypatch):
    module = _script()
    monkeypatch.setattr(module.time, "sleep", lambda seconds: None)
    monkeypatch.setattr(module, "HEALTHY_WITHIN_SECONDS", 0.05)
    return module


def _run(monkeypatch, script, docker: Docker) -> int:
    monkeypatch.setattr(script.subprocess, "run", docker)
    return script.main()


def test_it_stops_collects_and_starts_the_registry_again(monkeypatch, script, capsys):
    docker = Docker()
    assert _run(monkeypatch, script, docker) == 0
    assert docker.steps() == ["preflight", "stop", "collect", "start"]
    collect = next(call for call in docker.calls if "garbage-collect" in call)
    assert collect.endswith("--delete-untagged /etc/distribution/config.yml")
    assert "run --rm --no-deps --entrypoint registry registry" in collect
    out = capsys.readouterr().out
    assert "Removed 124 manifests and 218 blobs" in out and "1.5 MiB freed" in out


def test_the_hosts_containers_are_passed_to_the_preflight(monkeypatch, script):
    docker = Docker()
    _run(monkeypatch, script, docker)
    assert any(call.endswith("python -m src.scan.registry_gc --containers -") for call in docker.calls)
    digests = ["sha256:" + "1" * 64, "sha256:" + "2" * 64]
    assert docker.sent == [
        {"name": "dev-1", "image_ref": "localhost:5000/a:1", "digests": digests},
        {"name": "old-1", "image_ref": "localhost:5000/a:0", "digests": ["sha256:" + "3" * 64]},
    ]


def test_a_problem_found_beforehand_changes_nothing(monkeypatch, script, capsys):
    docker = Docker(preflight=1)
    assert _run(monkeypatch, script, docker) == 1
    assert docker.steps() == ["preflight"]
    assert "pending or running" in capsys.readouterr().out


def test_the_registry_is_started_again_when_collection_fails(monkeypatch, script, capsys):
    docker = Docker(collected=1)
    assert _run(monkeypatch, script, docker) == 1
    assert docker.steps()[-1] == "start"
    assert "Collection failed. The registry is running again." in capsys.readouterr().out


def test_the_registry_is_started_again_when_interrupted(monkeypatch, script):
    docker = Docker(collected=None)
    with pytest.raises(KeyboardInterrupt):
        _run(monkeypatch, script, docker)
    assert docker.steps()[-1] == "start"


def test_a_registry_that_doesnt_come_back_is_reported(monkeypatch, script, capsys):
    assert _run(monkeypatch, script, Docker(healthy=False)) == 1
    assert "isn't healthy" in capsys.readouterr().out
