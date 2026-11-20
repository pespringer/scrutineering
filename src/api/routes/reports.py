"""Weekly and on-demand reports: list, read, signature, and an admin's on-demand build.

See docs/design/reports-compliance.md. Reports are built and signed by the worker; these routes only
read them, and queue an on-demand build.
"""

from __future__ import annotations

import json

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse

from src.api.routes._access import require_role
from src.api.serializers import iso
from src.db.connection import get_session
from src.db.models import Report

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
