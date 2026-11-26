"""The daily candidate cleanup (docs/design/registry-management.md), against a fake registry."""

from __future__ import annotations

from datetime import timedelta

import pytest

from src.db.connection import get_session
from src.db.models import Deployment, Image, Remediation, RemediationStatus
from src.db.repositories import RemediationRepository
from src.remediation import candidates
from src.remediation.candidates import RETENTION, prune
from src.scan.celery_app import create_celery_app
from src.scan.deployments import utcnow
from src.scan.records import create_pending_scan, get_or_create_image, scan_identity
from tests.fake_registry import HOST, FakeRegistry

S = RemediationStatus
NOW = utcnow()
OLD = NOW - RETENTION - timedelta(seconds=1)
OTHER = "sha256:" + "9" * 64


@pytest.fixture
def registry(monkeypatch) -> FakeRegistry:
    fake = FakeRegistry()
    monkeypatch.setenv("LOCAL_REGISTRY_HOST", HOST)
    monkeypatch.setenv("LOCAL_REGISTRY_PUBLIC_HOST", "localhost:5000")
    monkeypatch.setenv("REGISTRY_INSECURE", "true")
    monkeypatch.setattr("src.scan.registry_catalog._open", fake)
    return fake


def _candidate(registry: FakeRegistry, status=S.COMPLETED, *, ended=OLD, push=True, **values) -> int:
    """A remediation of team/api:1 and the candidate it pushed."""
    digest = registry.image({"a": 1})
    with get_session() as session:
        image = get_or_create_image(session, scan_identity(f"{HOST}/team/api:1"))
        row = Remediation(image_id=image.id, status=status, completed_at=ended)
        session.add(row)
        session.flush()
        row.candidate_image = f"{HOST}/team/api:{_tag(row.id)}"
        row.candidate_digest = digest
        for name, value in values.items():
            setattr(row, name, value)
        remediation_id = row.id
    if push:
        registry.tag("team/api", _tag(remediation_id), digest)
    return remediation_id


def _tag(remediation_id: int) -> str:
    return f"scrutineering-candidate-{remediation_id}"


def _events(remediation_id: int) -> list[tuple[str, dict]]:
    with get_session() as session:
        rows = RemediationRepository.list_events(session, remediation_id)
        return [(row.event_type, row.detail) for row in rows]


def _kept(registry: FakeRegistry, remediation_id: int, outcome: dict) -> None:
    assert prune(NOW) == outcome
    assert _tag(remediation_id) in registry.tags["team/api"]
    assert _events(remediation_id) == []


@pytest.mark.parametrize("status", [S.COMPLETED, S.FAILED, S.CANCELLED])
def test_an_old_candidate_is_deleted_and_recorded(registry, status):
    remediation_id = _candidate(registry, status)
    name = f"{HOST}/team/api:{_tag(remediation_id)}"
    with get_session() as session:
        tracked = get_or_create_image(session, scan_identity(name)).id

    assert prune(NOW) == {"deleted": 1}

    assert registry.tags["team/api"] == {}
    ((event, detail),) = _events(remediation_id)
    assert event == "candidate_deleted"
    assert (detail["candidate"], detail["archived_image_ids"]) == (name, [tracked])
    with get_session() as session:
        row = session.get(Remediation, remediation_id)
        assert (row.status, row.candidate_image, row.candidate_digest) == (status, name, detail["digest"])
        assert session.get(Image, tracked).active is False
        assert session.get(Image, row.image_id).active is True
    assert prune(NOW) == {}


def test_only_the_candidate_goes_not_tags_sharing_its_image(registry):
    old, recent = _candidate(registry), _candidate(registry, ended=NOW)
    digest = registry.tags["team/api"][_tag(old)]
    registry.tag("team/api", "1", digest)
    assert prune(NOW) == {"deleted": 1}
    assert registry.tags["team/api"] == {_tag(recent): digest, "1": digest}


def test_it_is_kept_for_exactly_30_days(registry):
    remediation_id = _candidate(registry, ended=NOW - RETENTION)
    _kept(registry, remediation_id, {})
    assert prune(NOW + timedelta(seconds=1)) == {"deleted": 1}


@pytest.mark.parametrize("status", [s for s in S if s not in (S.COMPLETED, S.FAILED, S.CANCELLED)])
def test_a_retried_remediation_keeps_its_candidate(registry, status):
    # A retry leaves `completed_at` as it was.
    _kept(registry, _candidate(registry, status), {})


def test_one_that_never_recorded_its_end_is_kept(registry):
    _kept(registry, _candidate(registry, ended=None), {})


def test_a_different_digest_is_kept(registry):
    _kept(registry, _candidate(registry, candidate_digest=OTHER), {"tag_changed": 1})


def test_no_recorded_digest_is_kept(registry):
    # Pushed just as its remediation was cancelled.
    _kept(registry, _candidate(registry, S.CANCELLED, candidate_digest=None), {})


def test_another_recorded_reference_is_kept(registry):
    remediation_id = _candidate(registry, candidate_image=f"{HOST}/team/web:1")
    _kept(registry, remediation_id, {})


def test_another_repositorys_tag_with_the_same_number_is_kept(registry):
    remediation_id = _candidate(registry)
    registry.tag("team/web", _tag(remediation_id), registry.tags["team/api"][_tag(remediation_id)])
    assert prune(NOW) == {"deleted": 1}
    assert list(registry.tags["team/web"]) == [_tag(remediation_id)]


def test_an_id_that_doesnt_exist_is_kept(registry):
    registry.tag("team/api", _tag(999), registry.image({"a": 1}))
    assert prune(NOW) == {}
    assert registry.tags["team/api"]


def test_an_operators_tag_is_never_touched(registry):
    # Whatever the records say, only a tag named exactly as a candidate is one.
    digest = registry.image({"a": 1})
    for name in ("1", "my-{}", "{}-fixed"):
        remediation_id = _candidate(registry, push=False)
        tag = name.format(_tag(remediation_id))
        with get_session() as session:
            session.get(Remediation, remediation_id).candidate_image = f"{HOST}/team/api:{tag}"
        registry.tag("team/api", tag, digest)
    assert prune(NOW) == {}
    assert len(registry.tags["team/api"]) == 3


def test_a_running_candidate_is_kept(registry):
    remediation_id = _candidate(registry)
    with get_session() as session:
        image = get_or_create_image(session, scan_identity(f"localhost:5000/team/api:{_tag(remediation_id)}"))
        session.add(
            Deployment(
                container_id="c1",
                name="web-1",
                image_ref=f"localhost:5000/team/api:{_tag(remediation_id)}",
                image_id=image.id,
                running_digests=[],
                first_seen_at=NOW,
                last_seen_at=NOW,
            )
        )
    _kept(registry, remediation_id, {"running": 1})


def test_a_candidate_being_scanned_is_kept(registry):
    remediation_id = _candidate(registry)
    with get_session() as session:
        create_pending_scan(session, f"{HOST}/team/api:{_tag(remediation_id)}")
    _kept(registry, remediation_id, {"scan_active": 1})


@pytest.mark.parametrize(
    ("values", "code"),
    [
        # Retried, and waiting for approval.
        ({"status": S.PROPOSED}, "remediation_active"),
        # Retried, and cancelled again: its 30 days start over.
        ({"status": S.CANCELLED, "completed_at": NOW}, "not_due"),
        # Retried, rebuilt and failed, with the clock set back: the digest alone says it's another build.
        ({"candidate_digest": OTHER}, "not_due"),
    ],
)
def test_a_retry_during_the_run_keeps_the_candidate(monkeypatch, registry, values, code):
    remediation_id = _candidate(registry, S.FAILED)
    real = candidates.delete_tag

    def retried_first(session, *args, **kwargs):
        session.query(Remediation).filter(Remediation.id == remediation_id).update(values)
        return real(session, *args, **kwargs)

    monkeypatch.setattr(candidates, "delete_tag", retried_first)
    assert prune(NOW) == {code: 1}
    assert _tag(remediation_id) in registry.tags["team/api"]


@pytest.mark.parametrize(("status", "code"), [(400, "registry_delete_unsupported"), (405, "registry_delete_disabled")])
def test_a_registry_that_refuses_every_delete_ends_the_run(registry, status, code):
    for _ in range(3):
        _candidate(registry)
    registry.delete_status = status
    assert prune(NOW) == {code: 1}
    assert len(registry.tags["team/api"]) == 3


def test_one_failure_doesnt_stop_the_others(monkeypatch, registry):
    first = _candidate(registry)
    _candidate(registry)
    registry.failing.add(f"/v2/team/api/manifests/{_tag(first)}")
    assert prune(NOW) == {"registry_failed": 1, "deleted": 1}
    assert list(registry.tags["team/api"]) == [_tag(first)]
    registry.failing.clear()

    def broken(*args, **kwargs):
        raise RuntimeError("the database went away")

    monkeypatch.setattr(candidates, "delete_tag", broken)
    assert prune(NOW) == {"delete_failed": 1}


def test_a_repository_that_cant_be_listed_doesnt_stop_the_others(registry):
    registry.tag("team/aaa", "1", registry.image({"b": 1}))
    _candidate(registry)
    registry.failing.add("/v2/team/aaa/tags/list")
    assert prune(NOW) == {"deleted": 1}


def test_an_unreachable_registry_is_tried_again_the_next_day(registry):
    remediation_id = _candidate(registry)
    registry.failing.add("/v2/_catalog")
    _kept(registry, remediation_id, {})


def test_a_delete_that_cant_be_recorded_says_so(monkeypatch, registry):
    _candidate(registry)

    def broken(*args, **kwargs):
        raise RuntimeError("no events today")

    monkeypatch.setattr(RemediationRepository, "record_event", broken)
    assert prune(NOW) == {"delete_not_recorded": 1}


def test_candidates_already_deleted_cost_nothing(registry):
    for _ in range(3):
        _candidate(registry, push=False)
    assert prune(NOW) == {}
    assert [path for _, path in registry.requests] == ["/v2/_catalog"]


def test_the_task_runs_daily_where_workers_listen():
    import src.scan.tasks as tasks

    entry = create_celery_app().conf.beat_schedule["prune-candidates"]
    assert entry["task"] in tasks.app.tasks
    assert entry["options"] == {"queue": "scan.low"}
    assert (entry["schedule"].hour, entry["schedule"].minute) == ({3}, {55})


def test_a_refusal_doesnt_stop_the_others(registry):
    _candidate(registry, candidate_digest=OTHER)
    _candidate(registry)
    assert prune(NOW) == {"tag_changed": 1, "deleted": 1}
