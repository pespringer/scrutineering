"""Celery app configuration for the scrutineering scan orchestrator."""

import os

from celery import Celery


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
            "src.remediation.worker.execute_approved_remediation": {"queue": "remediation.normal"},
            "src.remediation.reconciliation_tasks.reconcile_stale_publications": {"queue": "remediation.normal"},
        },
        beat_schedule={
            "reconcile-stale-publications": {
                "task": "src.remediation.reconciliation_tasks.reconcile_stale_publications",
                "schedule": 300.0,
                "options": {"queue": "remediation.normal"},
            },
        },
        task_acks_late=True,
        task_time_limit=3600,
        task_soft_time_limit=3000,
    )

    return app
