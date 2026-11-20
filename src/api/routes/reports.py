"""Reports (list, read, signature, an admin's on-demand build) and compliance exports.

See docs/design/reports-compliance.md. Reports are built and signed by the worker; these routes only
read them, and queue an on-demand build.
"""

from __future__ import annotations

import json
from datetime import datetime, time, timedelta

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse, Response

from src.api.routes._access import require_role
from src.api.schemas import ComplianceExportRequest
from src.api.serializers import iso
from src.db.connection import get_session
from src.db.models import ComplianceExport, Report
from src.scan.deployments import utcnow

router = APIRouter()


def _summary(report: Report) -> dict:
    return {
        "id": report.id,
        "kind": report.kind,
        "period_start": iso(report.period_start),
        "period_end": iso(report.period_end),
        "sha256": report.sha256,
        "signed": bool(report.signature),
        "key_id": report.key_id,
        "created_at": iso(report.created_at),
    }


def _get(session, report_id: int) -> Report:
    report = session.get(Report, report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="report_not_found")
    return report


@router.get("/reports")
def list_reports(limit: int = Query(default=52, ge=1, le=200)) -> dict:
    with get_session() as session:
        reports = session.query(Report).order_by(Report.period_end.desc(), Report.id.desc()).limit(limit).all()
        return {"items": [_summary(report) for report in reports]}


@router.get("/reports/{report_id:int}")
def read_report(report_id: int) -> dict:
    """The summary plus the document, parsed. Download the exact signed bytes from `/reports/{id}.json`."""
    with get_session() as session:
        report = _get(session, report_id)
        return {**_summary(report), "document": json.loads(report.document)}


@router.get("/reports/{report_id:int}.json")
def download_report(report_id: int) -> PlainTextResponse:
    """The stored bytes exactly as signed."""
    with get_session() as session:
        report = _get(session, report_id)
        name = f"scrutineering-report-{report.kind}-{report.period_start.date().isoformat()}.json"
        headers = {
            "Content-Disposition": f'attachment; filename="{name}"',
            "X-Scrutineering-Report-SHA256": report.sha256,
        }
        if report.signature:
            headers.update(
                {"X-Scrutineering-Signature": report.signature, "X-Scrutineering-Key-ID": report.key_id or ""}
            )
        return PlainTextResponse(report.document, media_type="application/json", headers=headers)


@router.get("/reports/{report_id:int}.sig")
def report_signature(report_id: int) -> PlainTextResponse:
    with get_session() as session:
        report = _get(session, report_id)
        if not report.signature:
            raise HTTPException(status_code=404, detail="report_not_signed")
        return PlainTextResponse(
            report.signature + "\n",
            headers={
                "Content-Disposition": f'attachment; filename="report-{report_id}.json.sig"',
                "X-Scrutineering-Key-ID": report.key_id or "",
            },
        )


@router.post("/reports", status_code=202)
def build_report_now(request: Request) -> dict:
    """Queue an on-demand report for this week so far. Admin only: reports are signed and kept."""
    require_role(request, "admin")
    from src.reports import weekly

    try:
        task_id = weekly.queue_on_demand()
    except Exception as exc:  # noqa: BLE001 - the broker is down
        raise HTTPException(status_code=503, detail="report_queue_unavailable") from exc
    return {"queued": True, "task_id": task_id}


# -- Compliance exports ----------------------------------------------------------------------------


def _export_summary(export: ComplianceExport) -> dict:
    return {
        "id": export.id,
        "since": iso(export.since),
        "until": iso(export.until),
        "status": export.status,
        "error": export.error,
        "files": export.files,
        "size": export.size,
        "sha256": export.sha256,
        "requested_by": export.requested_by,
        "created_at": iso(export.created_at),
        "finished_at": iso(export.finished_at),
    }


@router.post("/compliance/exports", status_code=202)
def request_export(payload: ComplianceExportRequest, request: Request) -> dict:
    """Queue a zip of the range's evidence, SBOMs, reports, findings and audit log. One at a time."""
    require_role(request, "security-operator")
    from src.reports import export as exports

    since = datetime.combine(payload.since, time.min)
    until = datetime.combine(payload.until, time.min) + timedelta(days=1)
    with get_session() as session:
        if session.query(ComplianceExport.id).filter(ComplianceExport.status.in_(exports.ACTIVE)).first():
            raise HTTPException(status_code=409, detail="export_already_running")
        export = ComplianceExport(
            requested_by=getattr(request.state, "principal_id", None),
            since=since,
            until=until,
            status="pending",
            created_at=utcnow(),
        )
        session.add(export)
        session.flush()
        export_id = export.id
    try:
        exports.queue_build(export_id)
    except Exception as exc:  # noqa: BLE001 - the broker is down
        with get_session() as session:
            failed = session.get(ComplianceExport, export_id)
            failed.status, failed.error, failed.finished_at = "failed", "could not queue the build", utcnow()
        raise HTTPException(status_code=503, detail="export_queue_unavailable") from exc
    with get_session() as session:
        return _export_summary(session.get(ComplianceExport, export_id))


@router.get("/compliance/exports")
def list_exports(request: Request) -> dict:
    """Exports of the last 24 hours, newest first (their zips are deleted after that)."""
    require_role(request, "security-operator")
    with get_session() as session:
        rows = session.query(ComplianceExport).order_by(ComplianceExport.id.desc()).limit(20).all()
        return {"items": [_export_summary(export) for export in rows]}


@router.get("/compliance/exports/{export_id:int}/download")
def download_export(export_id: int, request: Request) -> Response:
    require_role(request, "security-operator")
    with get_session() as session:
        export = session.get(ComplianceExport, export_id)
        if export is None or export.status != "ready" or export.data is None:
            raise HTTPException(status_code=404, detail="export_not_ready")
        name = f"scrutineering-export-{export.since.date()}_{(export.until - timedelta(days=1)).date()}.zip"
        return Response(
            content=export.data,
            media_type="application/zip",
            headers={
                "Content-Disposition": f'attachment; filename="{name}"',
                "X-Scrutineering-Export-SHA256": export.sha256 or "",
            },
        )
