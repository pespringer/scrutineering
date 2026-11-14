"""Celery app configuration for the scrutineering scan orchestrator."""

import os

from celery import Celery
from celery.schedules import crontab


def create_celery_app() -> Celery:
    """Build and return a configured Celery application."""
    broker_url = os.environ.get(
        "CELERY_BROKER_URL", "redis://localhost:6379/0"
    )
    backend_url = os.environ.get(
        "CELERY_RESULT_BACKEND", "redis://localhost:6379/1"
    )

    app = Celery("scrutineering", broker=broker_url, backend=backend_url)

    app.conf.update(
        worker_prefetch_multiplier=1,
        worker_max_tasks_per_child=100,
        task_serializer="json",
        result_serializer="json",
        accept_content=["json"],
        task_default_queue="scan.normal",
        task_routes={
            "src.scan.tasks.run_scan": {"queue": "scan.normal"},
            "src.scan.tasks.run_image_scan": {"queue": "scan.normal"},
            "src.scan.tasks.schedule_active_scans": {"queue": "scan.low"},
            "src.scan.tasks.discover_runtime_scans": {"queue": "scan.low"},
            "src.scan.retention_tasks.report_expired_scans": {"queue": "remediation.normal"},
            "src.platform.backup_tasks.report_backup_freshness": {"queue": "remediation.normal"},
            "src.platform.backup_tasks.execute_postgres_backup": {"queue": "remediation.normal"},
            "src.platform.backup_tasks.schedule_postgres_backup": {"queue": "remediation.normal"},
    "src.platform.backup_tasks.verify_postgres_restore": {"queue": "remediation.normal"},
            "src.remediation.worker.execute_approved_remediation": {"queue": "remediation.normal"},
            "src.remediation.reconciliation_tasks.reconcile_stale_publications": {"queue": "remediation.normal"},
            "src.remediation.recovery_tasks.poll_recovery_requests": {"queue": "remediation.normal"},
            "src.remediation.retention_tasks.purge_expired_evidence": {"queue": "remediation.normal"},
            "src.remediation.alert_tasks.deliver_alerts": {"queue": "remediation.normal"},
        },
        beat_schedule={
            "report-expired-scans": {
                "task": "src.scan.retention_tasks.report_expired_scans",
                "schedule": 86400.0,
                "kwargs": {"dry_run": True},
                "options": {"queue": "remediation.normal"},
            },
            "report-backup-freshness": {
                "task": "src.platform.backup_tasks.report_backup_freshness",
                "schedule": 86400.0,
                "kwargs": {"dry_run": True},
                "options": {"queue": "remediation.normal"},
            },
            "schedule-postgres-backup": {
                "task": "src.platform.backup_tasks.schedule_postgres_backup",
                "schedule": crontab(minute="0"),
                "options": {"queue": "remediation.normal"},
            },
            "schedule-active-image-scans": {
                "task": "src.scan.tasks.schedule_active_scans",
                "schedule": crontab(minute="0", hour="*/6"),
                "options": {"queue": "scan.low"},
            },
            "discover-runtime-image-scans": {
                "task": "src.scan.tasks.discover_runtime_scans",
                "schedule": crontab(minute="*/15"),
                "options": {"queue": "scan.low"},
            },
            "reconcile-stale-publications": {
                "task": "src.remediation.reconciliation_tasks.reconcile_stale_publications",
                "schedule": 300.0,
                "options": {"queue": "remediation.normal"},
            },
            "poll-publication-recoveries": {
                "task": "src.remediation.recovery_tasks.poll_recovery_requests",
                "schedule": 60.0,
                "options": {"queue": "remediation.normal"},
            },
            "purge-expired-evidence-dry-run": {
                "task": "src.remediation.retention_tasks.purge_expired_evidence",
                "schedule": 86400.0,
                "kwargs": {"dry_run": True},
                "options": {"queue": "remediation.normal"},
            },
            "deliver-local-alerts": {
                "task": "src.remediation.alert_tasks.deliver_alerts",
                "schedule": 60.0,
                "options": {"queue": "remediation.normal"},
            },
        },
        task_acks_late=True,
        task_time_limit=3600,
        task_soft_time_limit=3000,
    )

    return app
