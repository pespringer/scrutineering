"""The dashboard status panel reports only what the API can verify."""

import pytest

from src.api.routes import system
from src.scan.records import queue_scan


@pytest.fixture
def workers(monkeypatch):
    def set_reply(reply):
        def ping(timeout):
            if isinstance(reply, Exception):
                raise reply
            return reply

        monkeypatch.setattr(system.celery_app.control, "ping", ping)

    return set_reply


def test_operational_when_database_and_workers_respond(workers):
    workers([{"celery@a": {"ok": "pong"}}, {"celery@b": {"ok": "pong"}}])
    queue_scan("alpine:3.20", scan_id="s1", enqueue=lambda *a, **k: None)
    status = system.system_status()
    assert status["status"] == "operational"
    assert status["workers"] == 2
    assert status["problems"] == []
    assert status["last_scan"]["scan_id"] == "s1"
    assert status["last_scan"]["status"] == "pending"


def test_degraded_when_no_worker_answers(workers):
    workers([])
    status = system.system_status()
    assert status["status"] == "degraded"
    assert status["problems"] == ["No scan workers responding"]
    assert status["last_scan"] is None


def test_degraded_when_the_broker_is_unreachable(workers):
    workers(ConnectionError("redis down"))
    status = system.system_status()
    assert (status["status"], status["queue"]) == ("degraded", "unavailable")
    assert status["problems"] == ["Scan queue unreachable"]


def test_unavailable_when_the_database_is_down(workers, monkeypatch):
    workers([{"celery@a": {"ok": "pong"}}])
    monkeypatch.setattr(system, "_database_ok", lambda: False)
    status = system.system_status()
    assert (status["status"], status["database"]) == ("unavailable", "unavailable")
    assert status["problems"] == ["Database unreachable"]
    assert status["last_scan"] is None


def test_the_last_discovery_run_is_reported(workers):
    from src.scan.runtime_discovery import save_status

    workers([{"celery@a": {"ok": "pong"}}])
    assert system.system_status()["discovery"] is None  # no run within the hour
    ok = {"status": "ok", "checked_at": "2026-11-18T12:00:00Z", "error": None, "running_images": 3, "queued": 1}
    save_status(ok, "redis://unused")
    status = system.system_status()
    assert status["discovery"] == ok and status["status"] == "operational"


def test_a_discovery_error_degrades_the_status(workers):
    from src.scan.runtime_discovery import save_status

    workers([{"celery@a": {"ok": "pong"}}])
    error = "Cannot connect to the Docker daemon at tcp://docker-proxy:2375"
    save_status({"status": "error", "checked_at": "2026-11-18T12:00:00Z", "error": error}, "redis://unused")
    status = system.system_status()
    assert status["status"] == "degraded"
    assert status["problems"] == [f"Runtime discovery can't list containers: {error}"]
