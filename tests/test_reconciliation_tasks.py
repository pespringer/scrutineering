from src.remediation.reconciliation_tasks import stale_threshold_seconds
from src.scan.celery_app import create_celery_app


def test_stale_threshold_is_bounded(monkeypatch):
    monkeypatch.setenv("REMEDIATION_PUBLICATION_STALE_SECONDS", "1")
    assert stale_threshold_seconds() == 60
    monkeypatch.setenv("REMEDIATION_PUBLICATION_STALE_SECONDS", "9999999")
    assert stale_threshold_seconds() == 604800


def test_celery_beat_schedules_reconciliation_on_remediation_queue():
    app = create_celery_app()
    schedule = app.conf.beat_schedule["reconcile-stale-publications"]
    assert schedule["task"] == "src.remediation.reconciliation_tasks.reconcile_stale_publications"
    assert schedule["schedule"] == 300.0
    assert schedule["options"]["queue"] == "remediation.normal"
