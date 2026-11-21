"""The weekly report: posture now, what changed in the period, fixes, and stale containers.

See docs/design/reports-compliance.md. Built by the worker from server records only, written as
canonical JSON (as evidence is), signed with the instance key, and kept. A weekly report covers the
7 whole UTC days before the run (Monday to Monday) and is built once per week; an on-demand report
covers this week so far and never replaces the weekly one.
"""

from __future__ import annotations

import hashlib
import logging
from collections import Counter
from datetime import datetime, timedelta

from celery import shared_task
from sqlalchemy import func

from src.db.connection import get_session
from src.db.models import (
    EvidenceBundle,
    Image,
    Remediation,
    RemediationStatus,
    Report,
    Scan,
    ScanFinding,
)
from src.remediation.evidence import canonical
from src.scan.deployments import deployment_state, latest_scan_digest, remediation_deployment, running_rows, utcnow
from src.scan.runtime_discovery import running_since

logger = logging.getLogger(__name__)

SCHEMA = "scrutineering.report/v1"
WEEKLY, ON_DEMAND = "weekly", "on_demand"
SEVERITIES = ("critical", "high", "medium", "low", "unknown")
TOP_IMAGES = 10


def _iso(value: datetime | None) -> str | None:
    return value.isoformat(timespec="seconds") + "Z" if value else None


def _value(value) -> str | None:
    return getattr(value, "value", value)


def week_start(moment: datetime) -> datetime:
    """Monday 00:00 UTC of the week holding `moment` (naive UTC)."""
    day = moment.replace(hour=0, minute=0, second=0, microsecond=0)
    return day - timedelta(days=day.weekday())


def weekly_period(now: datetime) -> tuple[datetime, datetime]:
    """The last whole week before `now`: Monday 00:00 to Monday 00:00."""
    end = week_start(now)
    return end - timedelta(days=7), end


def _by_severity(rows) -> dict[str, int]:
    counts = Counter(_value(severity) or "unknown" for (severity,) in rows)
    return {severity: counts.get(severity, 0) for severity in SEVERITIES}


def _posture(session, now: datetime) -> dict:
    open_rows = session.query(ScanFinding.severity).filter(ScanFinding.resolved_at.is_(None)).all()
    return {
        "active_images": session.query(Image).filter_by(active=True).count(),
        "running_images": session.query(Image).filter(Image.last_seen_running_at >= running_since(now)).count(),
        "open": _by_severity(open_rows),
        "fixable": session.query(ScanFinding)
        .filter(ScanFinding.resolved_at.is_(None), ScanFinding.fix_available.is_(True))
        .count(),
    }


def _changes(session, start: datetime, end: datetime) -> dict:
    def counted(column) -> dict[str, int]:
        return _by_severity(session.query(ScanFinding.severity).filter(column >= start, column < end).all())

    return {
        "new": counted(ScanFinding.first_seen),
        "resolved": counted(ScanFinding.resolved_at),
        "reopened": counted(ScanFinding.reopened_at),
    }


def _scans(session, start: datetime, end: datetime) -> dict:
    rows = (
        session.query(Scan.status, func.count(Scan.id))
        .filter(Scan.started_at >= start, Scan.started_at < end)
        .group_by(Scan.status)
        .all()
    )
    scanned = session.query(Scan.image_id).filter(Scan.started_at >= start, Scan.started_at < end)
    not_scanned = session.query(Image).filter(Image.active.is_(True), Image.id.not_in(scanned)).count()
    return {"by_status": {_value(status): count for status, count in sorted(rows)}, "images_not_scanned": not_scanned}


def _remediations(session, start: datetime, end: datetime) -> list[dict]:
    ended = (
        session.query(Remediation)
        .filter(Remediation.status.in_([RemediationStatus.COMPLETED, RemediationStatus.FAILED]))
        .filter(Remediation.completed_at.is_not(None))
        .order_by(Remediation.completed_at, Remediation.id)
        .all()
    )
    items = []
    for remediation in ended:
        if not start <= remediation.completed_at < end:  # compared in Python, as for evidence
            continue
        bundle = (
            session.query(EvidenceBundle.sha256)
            .filter(EvidenceBundle.remediation_id == remediation.id)
            .order_by(EvidenceBundle.id.desc())
            .first()
        )
        items.append(
            {
                "id": remediation.id,
                "image": remediation.image.full_name if remediation.image else None,
                "outcome": _value(remediation.status),
                "targets": remediation.finding_count,
                "completed_at": _iso(remediation.completed_at),
                "evidence_sha256": bundle[0] if bundle else None,
            }
        )
    return items


def _deployments(session, now: datetime) -> dict:
    image_ids = [image_id for (image_id,) in session.query(Image.id).filter_by(active=True).all()]
    rows = running_rows(session, image_ids, now)
    digests = {image_id: latest_scan_digest(session, image_id) for image_id in {row.image_id for row in rows}}
    names = {image.id: image.full_name for image in session.query(Image).filter(Image.id.in_(digests)).all()}
    stale = [
        {"container": row.name, "image": names.get(row.image_id)}
        for row in rows
        if deployment_state(row.running_digests or [], digests[row.image_id]) == "stale"
    ]
    fixes = []
    completed = (
        session.query(Remediation)
        .filter(Remediation.status == RemediationStatus.COMPLETED)
        .filter(Remediation.image_id.in_({row.image_id for row in rows}))
        .order_by(Remediation.id)
        .all()
    )
    for remediation in completed:
        deployment = remediation_deployment(session, remediation, now)
        if deployment and deployment["fixed"] is not None and deployment["not_fixed"]:
            fixes.append({"remediation_id": remediation.id, "image": names.get(remediation.image_id), **deployment})
    return {"containers": len(rows), "stale_containers": stale, "fixes_not_running": fixes}


def _top_images(session) -> list[dict]:
    rows = (
        session.query(ScanFinding.image_id, ScanFinding.severity)
        .join(Image, ScanFinding.image_id == Image.id)
        .filter(Image.active.is_(True), ScanFinding.resolved_at.is_(None))
        .all()
    )
    counts: dict[int, Counter] = {}
    for image_id, severity in rows:
        if _value(severity) in ("critical", "high"):
            counts.setdefault(image_id, Counter())[_value(severity)] += 1
    names = {image.id: image.full_name for image in session.query(Image).filter(Image.id.in_(counts)).all()}
    ranked = sorted(
        counts, key=lambda image_id: (-counts[image_id]["critical"], -counts[image_id]["high"], names[image_id])
    )
    return [
        {
            "image_id": image_id,
            "image": names[image_id],
            "critical": counts[image_id]["critical"],
            "high": counts[image_id]["high"],
        }
        for image_id in ranked[:TOP_IMAGES]
    ]


def build_document(session, kind: str, start: datetime, end: datetime, now: datetime) -> dict:
    """The report. `posture`, `deployments` and `top_images` describe `generated_at`; the rest, the period."""
    return {
        "schema": SCHEMA,
        "kind": kind,
        "period": {"start": _iso(start), "end": _iso(end), "generated_at": _iso(now)},
        "posture": _posture(session, now),
        "changes": _changes(session, start, end),
        "scans": _scans(session, start, end),
        "remediations": _remediations(session, start, end),
        "deployments": _deployments(session, now),
        "top_images": _top_images(session),
    }


def build(kind: str, start: datetime, end: datetime, now: datetime | None = None) -> Report | None:
    """Build, sign and store one report; None if that period's report already exists."""
    from src import signing
    from src.notifications.outbox import record_report_ready

    now = now or utcnow()
    with get_session() as session:
        exists = session.query(Report.id).filter_by(kind=kind, period_start=start, period_end=end).first()
        if exists:
            return None
        document = build_document(session, kind, start, end, now)
        data = canonical(document)
        try:
            signature = signing.sign(data)
        except Exception as exc:  # noqa: BLE001 - logged; the report is kept unsigned
            logger.error("could not sign the %s report for %s, keeping it unsigned: %s", kind, start, exc)
            signature = None
        report = Report(
            kind=kind,
            period_start=start,
            period_end=end,
            document=data.decode(),
            sha256=hashlib.sha256(data).hexdigest(),
            signature=signature.value if signature else None,
            key_id=signature.key_id if signature else None,
            created_at=now,
        )
        session.add(report)
        session.flush()
        if kind == WEEKLY:
            record_report_ready(session, report, document)
        session.expunge(report)
    logger.info("%s report for %s: %d bytes", kind, start.date(), len(data))
    return report


@shared_task(name="src.reports.weekly.build_weekly_report", acks_late=True, ignore_result=True)
def build_weekly_report() -> int | None:
    """From beat (REPORT_SCHEDULE_CRON): last week's report, once."""
    start, end = weekly_period(utcnow())
    report = build(WEEKLY, start, end)
    return report.id if report else None


@shared_task(name="src.reports.weekly.build_on_demand_report", acks_late=True, ignore_result=True)
def build_on_demand_report() -> int | None:
    """Queued by an admin from the dashboard: this week so far."""
    now = utcnow()
    report = build(ON_DEMAND, week_start(now), now, now)
    return report.id if report else None


def queue_on_demand() -> str:
    """Queue an on-demand report on the worker (the API never signs); returns the task ID."""
    return build_on_demand_report.apply_async(queue="scan.low", retry=False).id
