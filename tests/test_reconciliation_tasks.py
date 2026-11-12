from src.remediation.reconciliation_tasks import stale_threshold_seconds
from src.scan.celery_app import create_celery_app
from src.telemetry.scan_metrics import record_reconciliation_run, scan_metrics


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


def test_reconciliation_run_metric_rejects_unknown_status():
    scan_metrics.clear()
    record_reconciliation_run("completed")
    assert 'scrutineering_reconciliation_runs_total{status="completed"} 1' in scan_metrics.render()
