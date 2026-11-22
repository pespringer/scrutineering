import asyncio

from src.scan.runtime_discovery import select_runtime_images


def test_runtime_discovery_filters_and_deduplicates_images():
    containers = [
        {"id": "one", "names": "api-1", "image": "acme/api:latest", "labels": {"scan": "yes"}},
        {"id": "two", "names": "api-2", "image": "acme/api:latest", "labels": {"scan": "yes"}},
        {"id": "three", "names": "db-1", "image": "postgres:16", "labels": {"scan": "yes"}},
    ]

    assert select_runtime_images(containers, include=["acme/*"], include_label="scan=yes") == ["acme/api:latest"]


def test_runtime_discovery_excludes_container_names_and_images():
    containers = [
        {"id": "one", "names": "api-dev", "image": "acme/api:dev"},
        {"id": "two", "names": "api-prod", "image": "acme/api:prod"},
    ]

    assert select_runtime_images(containers, exclude=["*:dev"], exclude_containers=["api-prod"]) == []


# -- A whole run: classify, record, queue only what's due, report ------------------------------------

from datetime import datetime, timedelta  # noqa: E402

import pytest  # noqa: E402

from src.config import get_settings  # noqa: E402
from src.db.connection import get_session  # noqa: E402
from src.db.models import Image, Scan, ScanStatus  # noqa: E402
from src.scan import runtime_discovery  # noqa: E402
from src.scan.discovery._process import RuntimeUnavailable  # noqa: E402
from src.scan.runtime_discovery import Classified, classify, run_discovery  # noqa: E402
from src.scan import records as runtime_discovery_records  # noqa: E402

NOW = datetime(2026, 11, 18, 12, 0, 0)


def test_the_opt_out_label_skips_a_container():
    containers = [
        {"names": "web", "image": "nginx:1.27", "labels": "scrutineering.scan=false,app=web"},
        {"names": "db", "image": "postgres:16", "labels": {"scrutineering.scan": "true"}},
    ]
    assert select_runtime_images(containers) == ["postgres:16"]


def test_images_are_sorted_into_scannable_local_only_and_id_only():
    digests = {"nginx:1.27": ["nginx@sha256:aaa"], "myapp:dev": [], "gone:1": None}

    async def repo_digests(image):
        return digests[image]

    images = ["nginx:1.27", "myapp:dev", "gone:1", "sha256:" + "a" * 64, "0123456789ab"]
    result = asyncio.run(classify(images, repo_digests))
    assert result == Classified(scannable=["nginx:1.27"], local_only=2, id_only=2)
    assert asyncio.run(classify(["redis:7", "0123456789ab"], None)) == Classified(scannable=["redis:7"], id_only=1)


@pytest.fixture
def stored(monkeypatch):
    saved = []
    monkeypatch.setattr(runtime_discovery, "save_status", lambda status, url: saved.append(status))
    return saved


def _settings(**env):
    return get_settings({"SCAN_RUNTIME_DISCOVERY_ENABLED": "true", "SCAN_COOLDOWN_SECONDS": "3600", **env})


def _collect(images, containers=None, local_only=0, id_only=0):
    async def collect():
        return containers or [{} for _ in images], Classified(list(images), local_only, id_only), None

    return collect


def test_a_run_records_running_images_and_queues_each_once(stored):
    queued = []
    status = run_discovery(_settings(), queue=queued.append, collect=_collect(["nginx:1.27", "redis:7"]), now=NOW)

    assert queued == ["nginx:1.27", "redis:7"]
    assert status == {
        "status": "ok",
        "checked_at": "2026-11-18T12:00:00Z",
        "error": None,
        "containers": 2,
        "running_images": 2,
        "local_only": 0,
        "id_only": 0,
        "queued": 2,
    }
    assert stored == [status]
    with get_session() as session:
        assert {image.full_name: image.last_seen_running_at for image in session.query(Image)} == {
            "nginx:1.27": NOW,
            "redis:7": NOW,
        }


def _scanned(name: str, at: datetime | None, scan_status: ScanStatus | None = None) -> None:
    from src.scan.records import create_pending_scan

    with get_session() as session:
        scan = create_pending_scan(session, name)
        scan.image.last_scan_at = at
        scan.status = (scan_status or ScanStatus.COMPLETED).value


def test_only_images_due_a_scan_are_queued_oldest_first(stored):
    _scanned("fresh:1", NOW - timedelta(minutes=10))  # within the cooldown
    _scanned("stale:1", NOW - timedelta(hours=5))
    _scanned("older:1", NOW - timedelta(hours=9))
    _scanned("busy:1", NOW - timedelta(hours=9), ScanStatus.RUNNING)  # a scan is already running
    queued = []
    images = ["fresh:1", "stale:1", "busy:1", "older:1", "new:1"]
    status = run_discovery(_settings(), queue=queued.append, collect=_collect(images), now=NOW)

    assert queued == ["new:1", "older:1", "stale:1"]
    assert status["running_images"] == 5 and status["queued"] == 3


def test_a_second_run_with_nothing_new_queues_nothing(stored):
    queued = []

    def queue(image):
        queued.append(image)
        _scanned(image, NOW)  # the queued scan finished

    run_discovery(_settings(), queue=queue, collect=_collect(["nginx:1.27"]), now=NOW)
    later = NOW + timedelta(minutes=15)
    status = run_discovery(_settings(), queue=queue, collect=_collect(["nginx:1.27"]), now=later)
    assert queued == ["nginx:1.27"] and status["queued"] == 0
    with get_session() as session:
        assert session.query(Image).one().last_seen_running_at == later


def test_the_queue_limit_caps_scans_not_the_images_recorded(stored):
    queued = []
    images = [f"app{index}:1" for index in range(5)]
    status = run_discovery(
        _settings(SCAN_RUNTIME_MAX_IMAGES="2"), queue=queued.append, collect=_collect(images), now=NOW
    )
    assert len(queued) == 2 and status["running_images"] == 5
    with get_session() as session:
        assert session.query(Image).filter(Image.last_seen_running_at == NOW).count() == 5


def test_an_unreachable_runtime_is_an_error_not_zero(stored):
    async def collect():
        raise RuntimeUnavailable("Cannot connect to the Docker daemon at tcp://docker-proxy:2375")

    queued = []
    status = run_discovery(_settings(), queue=queued.append, collect=collect, now=NOW)
    assert status["status"] == "error" and "docker-proxy" in status["error"]
    assert "running_images" not in status and queued == []


def test_disabled_discovery_says_so(stored):
    off = get_settings({"SCAN_RUNTIME_DISCOVERY_ENABLED": "false"})
    status = run_discovery(off, queue=lambda image: None, collect=_collect(["x:1"]), now=NOW)
    assert status["status"] == "disabled"
    with get_session() as session:
        assert session.query(Scan).count() == 0 and session.query(Image).count() == 0


def test_discovery_is_on_by_default():
    assert get_settings({}).scan_runtime_discovery_enabled is True


def test_the_images_api_says_which_images_are_running(monkeypatch):
    from fastapi.testclient import TestClient

    from src.api.app import create_app
    from src.scan.runtime_discovery import RUNNING_WINDOW

    monkeypatch.setenv("PYTHON_API_KEY", "key")
    client = TestClient(create_app())
    client.headers["x-api-key"] = "key"
    now = runtime_discovery._now()
    with get_session() as session:
        session.add_all(
            [
                Image(repo_name="seen/now", tag="1", last_seen_running_at=now),
                Image(repo_name="seen/yesterday", tag="1", last_seen_running_at=now - RUNNING_WINDOW * 48),
                Image(repo_name="never/seen", tag="1"),
            ]
        )
    everything = client.get("/api/dashboard/images").json()["items"]
    assert {item["repo_name"]: item["running"] for item in everything} == {
        "seen/now": True,
        "seen/yesterday": False,
        "never/seen": False,
    }
    running = client.get("/api/dashboard/images", params={"running": "true"}).json()
    assert [item["repo_name"] for item in running["items"]] == ["seen/now"] and running["total"] == 1


def test_the_registry_decides_when_docker_gives_local_builds_a_digest_too():
    """Docker's containerd image store reports a digest for local builds, so RepoDigests can't tell them apart."""

    async def repo_digests(image):
        return [f"{image.split(':')[0]}@sha256:{'a' * 64}"]

    answers = {"nginx:1.27": True, "scrutineering-api:latest": False, "offline.example/app:1": None}
    checked = []

    def in_registry(image):
        checked.append(image)
        return answers[image]

    result = asyncio.run(classify(list(answers), repo_digests, in_registry, known={"nginx:1.27"}))
    assert result == Classified(scannable=["nginx:1.27", "offline.example/app:1"], local_only=1)
    assert checked == ["scrutineering-api:latest", "offline.example/app:1"]  # known images skip the check


def test_in_registry_maps_the_registry_s_answers(monkeypatch):
    from urllib.error import HTTPError, URLError

    from src.scan import registry

    def answer(outcome):
        def resolve(identity, **kwargs):
            if isinstance(outcome, Exception):
                raise outcome
            return "sha256:" + "b" * 64

        monkeypatch.setattr(registry, "resolve_digest", resolve)
        return runtime_discovery.in_registry("registry.example/team/app:1")

    assert answer(None) is True
    assert answer(HTTPError("u", 404, "not found", {}, None)) is False
    assert answer(HTTPError("u", 401, "unauthorized", {}, None)) is False
    assert answer(PermissionError("registry requires credentials")) is False
    assert answer(HTTPError("u", 503, "unavailable", {}, None)) is None
    assert answer(URLError("no route")) is None


def test_only_images_with_a_successful_scan_are_known():
    _scanned("pulled:1", NOW)  # completed
    _scanned("failed:1", NOW, ScanStatus.FAILED)
    assert runtime_discovery.known_images(["pulled:1", "failed:1", "never:1"]) == {"pulled:1"}


def test_selection_skips_opted_out_and_imageless_containers_and_honours_the_limit():
    containers = [
        {"image": "", "names": "init"},
        {"image": "acme/api:1", "names": "api", "labels": {"scrutineering.scan": "FALSE"}},
        {"image": "acme/web:1", "names": "web", "labels": "tier=front,team=a"},
        {"image": "acme/web:1", "names": "web-2"},
        {"image": "acme/db:1", "names": "db"},
    ]
    assert select_runtime_images(containers) == ["acme/web:1", "acme/db:1"]
    assert select_runtime_images(containers, limit=1) == ["acme/web:1"]
    # A label filter without "key=value" matches nothing rather than everything.
    assert select_runtime_images(containers, include_label="tier") == []
    with pytest.raises(ValueError):
        select_runtime_images(containers, limit=0)


def test_known_images_are_those_with_a_usable_scan():
    with get_session() as session:
        for reference, status in (
            ("acme/done:1", "completed"),
            ("acme/partial:1", "partial"),
            ("acme/bad:1", "failed"),
        ):
            scan = runtime_discovery_records.create_pending_scan(session, reference)
            scan.status = status
    known = runtime_discovery.known_images(["acme/done:1", "acme/partial:1", "acme/bad:1", "acme/never:1", "Not A Ref"])
    assert known == {"acme/done:1", "acme/partial:1"}
