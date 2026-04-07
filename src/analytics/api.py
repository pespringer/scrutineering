"""FastAPI endpoints for security analytics and reporting."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query

router = APIRouter(prefix="/api/analytics", tags=["analytics"])

_services: dict[str, Any] = {}


def _get_posture():
    from src.analytics.posture import SecurityPostureService
    if "posture" not in _services:
        _services["posture"] = SecurityPostureService()
    return _services["posture"]


def _get_trends():
    from src.analytics.trends import TrendAnalyzer
    if "trends" not in _services:
        _services["trends"] = TrendAnalyzer()
    return _services["trends"]


def _get_compliance():
    from src.analytics.compliance import ComplianceReporter
    if "compliance" not in _services:
        _services["compliance"] = ComplianceReporter()
    return _services["compliance"]


def _get_notifications():
    from src.analytics.notifications import NotificationService
    if "notifications" not in _services:
        _services["notifications"] = NotificationService()
    return _services["notifications"]


# -- Posture ----------------------------------------------------------------

@router.get("/posture/overview")
def get_posture_overview():
    """High-level security posture summary for the dashboard header."""
    return {
        "message": "Posture overview requires database session.",
        "status": "ok",
    }


@router.get("/posture/images")
def get_container_inventory():
    """List all tracked container images with status."""
    return {
        "message": "Container inventory requires database session.",
        "status": "ok",
    }


# -- Trends -----------------------------------------------------------------

@router.get("/trends/overall")
def get_overall_trend(days: int = Query(30, ge=1, le=365)):
    """Get overall severity trend across all images."""
    return {
        "message": "Trend data requires database session.",
        "status": "ok",
        "days": days,
    }


@router.get("/trends/top-images")
def get_top_images_by_findings(limit: int = Query(10, ge=1, le=100)):
    """Get the images with the most critical/high findings."""
    return {
        "message": "Top images requires database session.",
        "status": "ok",
        "limit": limit,
    }


# -- Compliance -------------------------------------------------------------

@router.post("/compliance/generate")
def generate_compliance_report(
    framework: str,
    posture_data: dict | None = None,
    audit_data: dict | None = None,
    anomaly_data: dict | None = None,
    trend_data: dict | None = None,
    output_format: str = "json",
):
    """Generate a compliance report for the specified framework."""
    reporter = _get_compliance()
    report = reporter.generate(
        framework=framework,
        posture_data=posture_data or {},
        audit_data=audit_data or {},
        anomaly_data=anomaly_data or {},
        trend_data=trend_data or {},
    )
    if output_format == "markdown":
        return {"format": "markdown", "content": reporter.export_markdown(report)}
    return report


@router.get("/compliance/frameworks")
def list_supported_frameworks():
    """List all supported compliance frameworks."""
    from src.analytics.compliance import FRAMEWORKS
    return {
        "frameworks": [
            {"key": k, "name": v["name"]}
            for k, v in FRAMEWORKS.items()
        ],
    }


@router.get("/compliance/reports")
def list_reports(framework: str | None = None):
    """List previously generated compliance reports."""
    reporter = _get_compliance()
    return reporter.list_reports(framework=framework)


# -- Notifications ----------------------------------------------------------

@router.post("/notifications/dispatch")
def dispatch_notification(
    title: str,
    severity: str = "medium",
    body: str = "",
    container_id: str = "",
    image_name: str = "",
    alert_id: str = "",
    channels: list[str] | None = None,
):
    """Dispatch an alert notification to configured channels."""
    svc = _get_notifications()
    return svc.dispatch_from_dict({
        "title": title,
        "severity": severity,
        "body": body,
        "container_id": container_id,
        "image_name": image_name,
        "alert_id": alert_id,
    }, channels=channels)


@router.get("/notifications/stats")
def get_notification_stats():
    """Get notification channel statistics."""
    svc = _get_notifications()
    return svc.summary()


@router.post("/notifications/channel/{name}/configure")
def configure_channel(name: str, config: dict[str, Any]):
    """Add or update a notification channel."""
    svc = _get_notifications()
    from src.analytics.notifications import (
        WebhookChannel, SlackChannel, PagerDutyChannel, EmailChannel,
    )
    min_sev = config.get("min_severity", "medium")
    if name == "webhook":
        channel = WebhookChannel(
            url=config["url"],
            name=config.get("channel_name", "webhook"),
            min_severity=min_sev,
            headers=config.get("headers"),
        )
    elif name == "slack":
        channel = SlackChannel(
            webhook_url=config["webhook_url"],
            channel=config.get("channel", "#alerts"),
            username=config.get("username", "Container Sentinel"),
            min_severity=min_sev,
        )
    elif name == "pagerduty":
        channel = PagerDutyChannel(
            routing_key=config["routing_key"],
            min_severity=min_sev,
        )
    elif name == "email":
        channel = EmailChannel(
            recipients=config["recipients"],
            sender=config.get("sender", "sentinel@localhost"),
            min_severity=min_sev,
        )
    else:
        raise HTTPException(status_code=400, detail=f"Unknown channel: {name}")

    svc.add_channel(channel)
    return {"success": True, "channel": name}
