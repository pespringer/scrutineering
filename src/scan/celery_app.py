"""Celery app configuration for the scrutineering scan orchestrator."""

import os

from celery import Celery
from celery.schedules import crontab


DEFAULT_SCAN_SCHEDULE = "0 */6 * * *"


def scan_schedule(expression: str | None = None) -> crontab:
    """Parse SCHEDULE_CRON_SCAN (five cron fields) into the beat schedule for inventory rescans."""
    value = (expression if expression is not None else os.environ.get("SCHEDULE_CRON_SCAN", "")).strip()
    fields = (value or DEFAULT_SCAN_SCHEDULE).split()
    if len(fields) != 5:
        raise ValueError(f"SCHEDULE_CRON_SCAN must have five cron fields, got {value!r}")
    minute, hour, day_of_month, month_of_year, day_of_week = fields
    return crontab(
        minute=minute, hour=hour, day_of_month=day_of_month, month_of_year=month_of_year, day_of_week=day_of_week
    )


def create_celery_app() -> Celery:
    """Build and return a configured Celery application."""
    broker_url = os.environ.get("CELERY_BROKER_URL", "redis://localhost:6379/0")
    backend_url = os.environ.get("CELERY_RESULT_BACKEND", "redis://localhost:6379/1")

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
            "src.scan.tasks.schedule_active_scans": {"queue": "scan.low"},
            "src.scan.tasks.discover_runtime_scans": {"queue": "scan.low"},
            "src.remediation.worker.execute_approved_remediation": {"queue": "remediation.normal"},
        },
        beat_schedule={
            "schedule-active-image-scans": {
                "task": "src.scan.tasks.schedule_active_scans",
                "schedule": scan_schedule(),
                "options": {"queue": "scan.low"},
            },
            "discover-runtime-image-scans": {
                "task": "src.scan.tasks.discover_runtime_scans",
                "schedule": crontab(minute="*/15"),
                "options": {"queue": "scan.low"},
            },
        },
        task_acks_late=True,
        task_time_limit=3600,
        task_soft_time_limit=3000,
    )

    return app
