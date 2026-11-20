"""Deployments: the containers runtime discovery records (docs/design/deployment-observation.md)."""

import asyncio
import json
from datetime import datetime, timedelta

import pytest

from src.config import get_settings
from src.db.connection import get_session
from src.db.models import Deployment, Image
from src.scan import deployments, runtime_discovery
from src.scan.deployments import Observed, deployment_state, observe, parse_started_at, record, running_digests
from src.scan.discovery import docker as docker_module
from src.scan.discovery._process import RuntimeUnavailable
from src.scan.runtime_discovery import Classified, run_discovery

NOW = datetime(2026, 11, 19, 12, 0, 0)
A, B, C = ("sha256:" + letter * 64 for letter in "abc")


def _observed(container_id="c1", ref="nginx:1.27", digests=(A,), started=None, name="web"):
    return Observed(container_id, name, ref, list(digests), started)


def _rows():
    with get_session() as session:
        rows = session.query(Deployment).order_by(Deployment.id).all()
        return [(row.container_id, row.image_ref, row.running_digests, row.started_at, row.gone_at) for row in rows]


# -- Pure helpers -------------------------------------------------------------------------------------


def test_running_digests_cover_both_docker_image_stores():
    # containerd store: the image ID is the registry digest.
    assert running_digests(A, [f"nginx@{A}"]) == [A]
    # Classic store: the image ID is the config digest; the registry digest comes from RepoDigests.
    assert running_digests(B, [f"nginx@{A}", f"docker.io/library/nginx@{C}"]) == [A, B, C]
    # A locally built image has no RepoDigests; junk is dropped.
    assert running_digests(A, None) == [A]
    assert running_digests("not-a-digest", ["nginx@sha256:short", ""]) == []


def test_started_at_is_parsed_to_naive_utc():
    assert parse_started_at("2026-11-19T10:00:01.123456789Z") == datetime(2026, 11, 19, 10, 0, 1, 123456)
    assert parse_started_at("2026-11-19T12:00:00+02:00") == datetime(2026, 11, 19, 10, 0, 0)
    assert parse_started_at("0001-01-01T00:00:00Z") is None
    assert parse_started_at("") is None and parse_started_at("yesterday") is None


def test_state_is_current_stale_or_unknown():
    assert deployment_state([A, B], A) == "current"
    assert deployment_state([B], A) == "stale"
    # Scanned by tag (no digest): never guessed to be stale.
    assert deployment_state([B], None) == "unknown"


# -- Observing through Docker -------------------------------------------------------------------------


def test_observe_inspects_only_containers_of_scannable_images():
    containers = [
        {"id": "c1", "image": "nginx:1.27"},
        {"id": "c2", "image": "nginx:1.27"},
        {"id": "c3", "image": "myapp:dev"},
        {"id": "", "image": "nginx:1.27"},
    ]
    asked, lookups = [], []

    async def inspect(ids):
        asked.append(ids)
        return [
            {"Id": "c1", "Name": "/web-1", "Image": B, "State.StartedAt": "2026-11-19T09:00:00Z"},
            {"Id": "c2", "Name": "/web-2", "Image": B, "State.StartedAt": "2026-11-19T09:05:00Z"},
            {"Id": "c9", "Name": "/unasked", "Image": C, "State.StartedAt": ""},
        ]

    async def repo_digests(image_id):
        lookups.append(image_id)
        return [f"nginx@{A}"]

    observed = asyncio.run(observe(containers, ["nginx:1.27"], inspect, repo_digests))
    assert asked == [["c1", "c2"]] and lookups == [B]  # one digest lookup per build
    assert [(item.container_id, item.name, item.running_digests) for item in observed] == [
        ("c1", "web-1", [A, B]),
        ("c2", "web-2", [A, B]),
    ]
    assert observed[0].started_at == datetime(2026, 11, 19, 9, 0)


def test_observe_reports_when_docker_could_not_be_inspected():
    async def inspect(ids):
        return None

    async def repo_digests(image_id):
        raise AssertionError("not reached")

    assert asyncio.run(observe([{"id": "c1", "image": "x:1"}], ["x:1"], inspect, repo_digests)) is None


def test_docker_inspect_keeps_only_the_listed_fields(monkeypatch):
    calls = []
    line = "\t".join(json.dumps(value) for value in ("c1", "/web", "nginx:1.27", A, "2026-11-19T09:00:00Z"))

    async def run_cli(cmd, timeout=15):
        calls.append(cmd)
        # c2 stopped since it was listed: Docker prints the others and exits 1.
        return 1, line + "\n", "Error: No such container: c2"

    monkeypatch.setattr(docker_module, "run_cli", run_cli)
    found = asyncio.run(docker_module.DockerRuntimeCollector().inspect_containers(["c1", "c2"]))
    assert found == [
        {
            "Id": "c1",
            "Name": "/web",
            "Config.Image": "nginx:1.27",
            "Image": A,
            "State.StartedAt": "2026-11-19T09:00:00Z",
        }
    ]
    assert "{{json .Config.Env}}" not in calls[0][4] and calls[0][-2:] == ["c1", "c2"]


def test_docker_inspect_failure_is_not_an_empty_host(monkeypatch):
    async def run_cli(cmd, timeout=15):
        return 1, "", "Cannot connect to the Docker daemon"

    monkeypatch.setattr(docker_module, "run_cli", run_cli)
    assert asyncio.run(docker_module.DockerRuntimeCollector().inspect_containers(["c1"])) is None
    assert asyncio.run(docker_module.DockerRuntimeCollector().inspect_containers([])) == []


# -- Recording ----------------------------------------------------------------------------------------


def test_a_container_is_inserted_then_updated():
    started = datetime(2026, 11, 19, 9, 0)
    assert record([_observed(started=started)], {"c1"}, now=NOW) == {"recorded": 1, "gone": 0}
    later = NOW + timedelta(minutes=15)
    # `docker restart` keeps the ID: same row, new start time.
    record([_observed(started=started + timedelta(hours=1))], {"c1"}, now=later)
    with get_session() as session:
        row = session.query(Deployment).one()
        image = session.get(Image, row.image_id)
        assert (image.repo_name, image.tag) == ("nginx", "1.27")
        assert (row.first_seen_at, row.last_seen_at, row.started_at) == (NOW, later, started + timedelta(hours=1))


def test_a_recreated_container_is_a_new_row_and_the_old_one_is_gone():
    record([_observed("old", digests=[A])], {"old"}, now=NOW)
    later = NOW + timedelta(minutes=15)
    assert record([_observed("new", digests=[B])], {"new"}, now=later) == {"recorded": 1, "gone": 1}
    assert _rows() == [
        ("old", "nginx:1.27", [A], None, later),
        ("new", "nginx:1.27", [B], None, None),
    ]


def test_a_listed_container_that_could_not_be_inspected_is_not_gone():
    record([_observed("c1")], {"c1"}, now=NOW)
    assert record([], {"c1"}, now=NOW + timedelta(minutes=15)) == {"recorded": 0, "gone": 0}
    assert _rows()[0][4] is None


def test_a_container_seen_again_is_no_longer_gone():
    record([_observed("c1")], {"c1"}, now=NOW)
    record([], set(), now=NOW + timedelta(minutes=15))
    assert _rows()[0][4] is not None
    record([_observed("c1")], {"c1"}, now=NOW + timedelta(minutes=30))
    assert _rows()[0][4] is None


def test_prune_deletes_only_rows_gone_for_over_30_days():
    record([_observed("old"), _observed("recent"), _observed("running")], {"old", "recent", "running"}, now=NOW)
    record([_observed("running")], {"running", "recent"}, now=NOW + timedelta(days=1))
    record([_observed("running")], {"running"}, now=NOW + timedelta(days=20))
    assert deployments.prune(now=NOW + timedelta(days=31, minutes=1)) == 1
    assert [row[0] for row in _rows()] == ["recent", "running"]


# -- A whole discovery run ----------------------------------------------------------------------------


@pytest.fixture
def stored(monkeypatch):
    saved = []
    monkeypatch.setattr(runtime_discovery, "save_status", lambda status, url: saved.append(status))
    return saved


def _settings():
    return get_settings({"SCAN_RUNTIME_DISCOVERY_ENABLED": "true", "SCAN_COOLDOWN_SECONDS": "3600"})


def test_a_discovery_run_records_containers_and_marks_stopped_ones_gone(stored):
    def collect(listed, observed):
        async def run():
            return [{"id": item, "image": "nginx:1.27"} for item in listed], Classified(["nginx:1.27"]), observed

        return run

    status = run_discovery(
        _settings(),
        queue=lambda image: None,
        collect=collect(["c1", "c2"], [_observed("c1"), _observed("c2")]),
        now=NOW,
    )
    assert status["deployments"] == {"recorded": 2, "gone": 0}
    later = NOW + timedelta(minutes=15)
    status = run_discovery(_settings(), queue=lambda image: None, collect=collect(["c1"], [_observed("c1")]), now=later)
    assert status["deployments"] == {"recorded": 1, "gone": 1}
    assert [(row[0], row[4]) for row in _rows()] == [("c1", None), ("c2", later)]


def test_nothing_is_marked_gone_when_the_runtime_cannot_be_listed_or_inspected(stored):
    record([_observed("c1")], {"c1"}, now=NOW)

    async def unreachable():
        raise RuntimeUnavailable("Cannot connect to the Docker daemon")

    async def uninspectable():
        return [], Classified([]), None

    for collect in (unreachable, uninspectable):
        status = run_discovery(_settings(), queue=lambda image: None, collect=collect, now=NOW + timedelta(hours=1))
        assert "deployments" not in status
    assert _rows()[0][4] is None
