"""Celery app configuration for the scrutineering scan orchestrator."""

from celery import Celery
from celery.schedules import crontab

from src.config import get_settings


def scan_schedule(expression: str | None = None) -> crontab:
    """Parse SCHEDULE_CRON_SCAN (five cron fields) into the beat schedule for inventory rescans."""
    value = (expression or get_settings().schedule_cron_scan).strip()
    fields = value.split()
    if len(fields) != 5:
        raise ValueError(f"SCHEDULE_CRON_SCAN must have five cron fields, got {value!r}")
    minute, hour, day_of_month, month_of_year, day_of_week = fields
    return crontab(
        minute=minute, hour=hour, day_of_month=day_of_month, month_of_year=month_of_year, day_of_week=day_of_week
    )


def report_schedule(expression: str | None = None) -> crontab | None:
    """REPORT_SCHEDULE_CRON as a beat schedule, or None when it's `off`."""
    value = (expression or get_settings().report_schedule_cron).strip()
    return None if value == "off" else scan_schedule(value)


def create_celery_app() -> Celery:
    """Build and return a configured Celery application."""
    settings = get_settings()
    app = Celery("scrutineering", broker=settings.celery_broker_url, backend=settings.celery_result_backend)

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
            "src.notifications.delivery.deliver_pending": {"queue": "notify"},
            "src.scan.sbom.prune_sboms": {"queue": "scan.low"},
            "src.scan.deployments.prune_deployments": {"queue": "scan.low"},
            "src.notifications.deployments.notify_stale_deployments": {"queue": "notify"},
            "src.reports.weekly.build_weekly_report": {"queue": "scan.low"},
            "src.reports.weekly.build_on_demand_report": {"queue": "scan.low"},
            "src.reports.export.build_compliance_export": {"queue": "scan.low"},
            "src.reports.export.prune_compliance_exports": {"queue": "scan.low"},
            "src.api.principals.prune_principals": {"queue": "scan.low"},
            "src.remediation.evidence.build_due_evidence": {"queue": "notify"},
        },
        beat_schedule={
            "schedule-active-image-scans": {
                "task": "src.scan.tasks.schedule_active_scans",
                "schedule": scan_schedule(),
                "options": {"queue": "scan.low"},
            },
            "build-due-evidence": {
                "task": "src.remediation.evidence.build_due_evidence",
                "schedule": 60.0,
                "options": {"queue": "notify", "expires": 55},
            },
            "prune-superseded-sboms": {
                "task": "src.scan.sbom.prune_sboms",
                "schedule": crontab(minute=30, hour=3),
                "options": {"queue": "scan.low"},
            },
            "prune-gone-deployments": {
                "task": "src.scan.deployments.prune_deployments",
                "schedule": crontab(minute=45, hour=3),
                "options": {"queue": "scan.low"},
            },
            "prune-principals": {
                "task": "src.api.principals.prune_principals",
                "schedule": crontab(hour=3, minute=40),
                "options": {"queue": "scan.low"},
            },
            "prune-compliance-exports": {
                "task": "src.reports.export.prune_compliance_exports",
                "schedule": crontab(minute=10),
                "options": {"queue": "scan.low"},
            },
            "notify-stale-deployments": {
                "task": "src.notifications.deployments.notify_stale_deployments",
                "schedule": crontab(minute="5,20,35,50"),
                "options": {"queue": "notify", "expires": 600},
            },
            "deliver-pending-notifications": {
                "task": "src.notifications.delivery.deliver_pending",
                "schedule": 60.0,
                # A sweep nobody picks up is dropped rather than piling up; the next one covers it.
                "options": {"queue": "notify", "expires": 55},
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

    weekly = report_schedule()
    if weekly is not None:
        app.conf.beat_schedule["build-weekly-report"] = {
            "task": "src.reports.weekly.build_weekly_report",
            "schedule": weekly,
            "options": {"queue": "scan.low"},
        }
    return app
