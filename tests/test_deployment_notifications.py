"""`remediation.deployment_stale` (docs/design/deployment-observation.md, step 3)."""

from __future__ import annotations

from datetime import timedelta

import pytest

from src.db.connection import get_session
from src.db.models import Notification
from src.notifications import deployments, outbox, slack
from tests.test_deployments_api import FIXED, OLD, _completed_remediation, _container, _image

URL = "https://hooks.example.test/scrutineering"


@pytest.fixture
def configured(monkeypatch):
    monkeypatch.setenv("NOTIFICATION_WEBHOOK_URL", URL)
    monkeypatch.setenv("NOTIFICATION_WEBHOOK_SECRET", "notify-secret")
    monkeypatch.setenv("DASHBOARD_PUBLIC_URL", "https://scrutineering.home.lan/")
    monkeypatch.setattr(outbox, "enqueue_delivery", lambda: None)


def _stale_rows() -> list[Notification]:
    with get_session() as session:
        return session.query(Notification).filter_by(event=outbox.DEPLOYMENT_STALE).all()


def _fix_with_containers(*containers: tuple[str, str], reference: str = "registry:5000/team/app:1.0"):
    """A completed fix, and containers that discovery last listed 25 hours after it completed."""
    image_id = _image(reference)
    rid, _, completed = _completed_remediation(image_id)
    for name, digest in containers:
        _container(image_id, f"{name}", [digest], seen=completed + timedelta(hours=25))
    return rid, completed


def test_a_fix_still_stale_after_24_hours_is_announced_once(configured):
    rid, completed = _fix_with_containers(("web-1", FIXED), ("web-2", OLD))
    assert deployments.sweep(now=completed + timedelta(hours=23)) == 0  # too soon
    assert deployments.sweep(now=completed + timedelta(hours=25)) == 1
    assert deployments.sweep(now=completed + timedelta(hours=26)) == 0  # once
    [row] = _stale_rows()
    assert row.remediation_id == rid and row.channel == "webhook"
    assert row.payload["deployment"] == {"containers": 2, "fixed": 1, "not_fixed": ["web-2"]}
    assert row.payload["remediation"]["url"] == f"https://scrutineering.home.lan/remediations/{rid}"


def test_nothing_is_sent_when_every_container_runs_the_fix_or_none_runs(configured):
    _, completed = _fix_with_containers(("web-1", FIXED))
    assert deployments.sweep(now=completed + timedelta(hours=25)) == 0
    _, completed = _fix_with_containers(reference="registry:5000/team/other:1.0")
    assert deployments.sweep(now=completed + timedelta(hours=25)) == 0
    assert _stale_rows() == []


def test_old_fixes_are_not_announced(configured):
    """Configuring a channel later doesn't announce every fix ever completed."""
    _, completed = _fix_with_containers(("web-1", OLD))
    assert deployments.sweep(now=completed + timedelta(hours=73)) == 0


def test_it_can_be_turned_off_and_needs_a_channel(configured, monkeypatch):
    _, completed = _fix_with_containers(("web-1", OLD))
    monkeypatch.setenv("NOTIFICATION_EVENTS", "completed,failed")
    assert deployments.sweep(now=completed + timedelta(hours=25)) == 0
    monkeypatch.delenv("NOTIFICATION_EVENTS")
    monkeypatch.delenv("NOTIFICATION_WEBHOOK_URL")
    monkeypatch.delenv("NOTIFICATION_WEBHOOK_SECRET")
    assert deployments.sweep(now=completed + timedelta(hours=25)) == 0
    assert _stale_rows() == []


def test_the_slack_message_names_the_stale_containers(configured):
    _, completed = _fix_with_containers(("web-1", OLD), ("web-2", OLD))
    deployments.sweep(now=completed + timedelta(hours=25))
    message = slack.message(_stale_rows()[0].payload)
    assert message["text"].startswith("A fix isn't running yet: 2 of 2 container(s)")
    assert "`web-1`, `web-2`" in message["blocks"][1]["text"]["text"]
