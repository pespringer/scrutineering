"""FastAPI endpoints for the forensics and incident investigation toolkit.

Provides the REST API needed by the dashboard and external tools for:
  - Forensic snapshot capture and retrieval
  - Network flow querying
  - Forensic timeline assembly
  - Root cause analysis
  - SIEM export (CEF, LEEF, JSON)
  - Incident report generation
  - Audit log queries
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/forensics", tags=["forensics"])

# Lazily-created service instances (set during app startup)
_snapshot_service = None
_network_service = None
_timeline = None
_rca = None
_report_gen = None
_audit_logger = None

from src.forensics.snapshot import ForensicSnapshotService
from src.forensics.network import NetworkCaptureService
from src.forensics.timeline import ForensicTimeline, RootCauseAnalyzer
from src.forensics.report import IncidentReportGenerator
from src.forensics.audit import AuditLogger


def _get_snapshot_service() -> ForensicSnapshotService:
    global _snapshot_service
    if _snapshot_service is None:
        _snapshot_service = ForensicSnapshotService()
    return _snapshot_service


def _get_network_service() -> NetworkCaptureService:
    global _network_service
    if _network_service is None:
        _network_service = NetworkCaptureService()
    return _network_service


def _get_timeline() -> ForensicTimeline:
    global _timeline
    if _timeline is None:
        _timeline = ForensicTimeline()
    return _timeline


def _get_rca() -> RootCauseAnalyzer:
    global _rca
    if _rca is None:
        _rca = RootCauseAnalyzer()
    return _rca


def _get_report_gen() -> IncidentReportGenerator:
    global _report_gen
    if _report_gen is None:
        _report_gen = IncidentReportGenerator()
    return _report_gen


def _get_audit_logger() -> AuditLogger:
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = AuditLogger()
    return _audit_logger


# -- Pydantic models -------------------------------------------------------- #

class SnapshotRequest(BaseModel):
    container_id: str
    include_files: bool = True
    include_processes: bool = True
    include_network: bool = True


class AnomalyInput(BaseModel):
    kind: str
    container_id: str = ""
    severity: str = "medium"
    evidence: dict[str, Any] = Field(default_factory=dict)


class RCARequest(BaseModel):
    container_id: str
    anomalies: list[AnomalyInput] = Field(default_factory=list)
    findings: list[dict[str, Any]] = Field(default_factory=list)
    network_events: list[dict[str, Any]] = Field(default_factory=list)


class ReportRequest(BaseModel):
    container_id: str
    severity: str = "medium"
    title: str = ""
    analyst: str = ""
    include_snapshot: bool = True
    include_network: bool = True
    include_timeline: bool = True
    include_rca: bool = True


class AuditLogRequest(BaseModel):
    container_id: str | None = None
    event_type: str | None = None
    min_severity: str | None = None
    since: datetime | None = None
    limit: int = Query(500, ge=1, le=5000)


class SIEMExportRequest(BaseModel):
    format: str = "json"   # json, cef, leef, syslog, elastic_bulk
    events: list[dict[str, Any]] = Field(default_factory=list)


class TimelineEventInput(BaseModel):
    source: str = ""
    event_type: str = ""
    severity: str = ""
    container_id: str = ""
    description: str = ""
    timestamp: datetime | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class AlertResponse(BaseModel):
    success: bool
    message: str = ""


# -- Snapshot endpoints ----------------------------------------------------- #

@router.post("/snapshot")
async def capture_snapshot(req: SnapshotRequest):
    """Capture a forensic snapshot of a running container."""
    import asyncio
    svc = _get_snapshot_service()

    async def _capture():
        return await svc.capture(
            req.container_id,
            include_files=req.include_files,
            include_processes=req.include_processes,
            include_network=req.include_network,
        )

    loop = asyncio.get_event_loop()
    try:
        snap = await loop.run_in_executor(None, lambda: asyncio.get_event_loop().run_until_complete(_capture()))
    except RuntimeError:
        # Sync fallback if no running loop
        snap = await svc.capture(
            req.container_id,
            include_files=req.include_files,
            include_processes=req.include_processes,
            include_network=req.include_network,
        )

    return snap.to_dict()


# -- Network endpoints ------------------------------------------------------ #

@router.get("/network/flows")
def get_network_flows(
    container_id: str | None = Query(None),
    external_only: bool = Query(False),
    limit: int = Query(100, ge=1, le=1000),
):
    """Retrieve captured network flow records."""
    svc = _get_network_service()
    return svc.get_flows(
        container_id=container_id,
        external_only=external_only,
        limit=limit,
    )


@router.get("/network/dns")
def get_dns_log(
    container_id: str | None = Query(None),
    limit: int = Query(100, ge=1, le=1000),
):
    """Retrieve captured DNS query logs."""
    svc = _get_network_service()
    return svc.get_dns_log(container_id=container_id, limit=limit)


@router.get("/network/unusual-ports/{container_id}")
def detect_unusual_ports(container_id: str):
    """Find connections to non-standard ports for a container."""
    svc = _get_network_service()
    return svc.detect_unusual_ports(container_id)


# -- Timeline endpoints ----------------------------------------------------- #

@router.get("/timeline")
def get_timeline(
    container_id: str | None = Query(None),
    source: str | None = Query(None),
    event_type: str | None = Query(None),
    min_severity: str | None = Query(None),
    since: datetime | None = Query(None),
    to: datetime | None = Query(None),
    limit: int = Query(500, ge=1, le=5000),
):
    """Query the forensic timeline with filters."""
    tl = _get_timeline()
    return tl.query(
        container_id=container_id,
        source=source,
        event_type=event_type,
        min_severity=min_severity,
        since=since,
        to=to,
        limit=limit,
    )


@router.post("/timeline/events")
def add_timeline_event(evt: TimelineEventInput):
    """Add an event to the forensic timeline."""
    from src.forensics.timeline import TimelineEvent
    tl = _get_timeline()
    ts = evt.timestamp or datetime.now(tz=datetime.now().astimezone().tzinfo)
    tl.add_event(TimelineEvent(
        timestamp=ts,
        source=evt.source,
        event_type=evt.event_type,
        severity=evt.severity,
        container_id=evt.container_id,
        description=evt.description,
        details=evt.details,
    ))
    return AlertResponse(success=True, message="Event added")


@router.get("/timeline/summary")
def timeline_summary():
    """Get summary statistics for the forensic timeline."""
    tl = _get_timeline()
    return tl.summary()


# -- Root cause analysis endpoints ------------------------------------------ #

@router.post("/rca")
def run_root_cause_analysis(req: RCARequest):
    """Run root cause analysis for a container."""
    rca = _get_rca()
    anomalies_dicts = [a.model_dump() for a in req.anomalies]
    hypotheses = rca.analyze(
        container_id=req.container_id,
        anomalies=anomalies_dicts,
        findings=req.findings,
        network_events=req.network_events,
    )
    return [h.to_dict() for h in hypotheses]


# -- Report generation endpoints -------------------------------------------- #

@router.post("/report")
def generate_report(req: ReportRequest, output_format: str = "json"):
    """Generate an incident report."""
    gen = _get_report_gen()
    # Build data from services
    snap_data = None
    if req.include_snapshot:
        snap_data = {}  # Would normally come from snapshot service

    flows = None
    if req.include_network:
        ns = _get_network_service()
        flows = ns.get_flows(container_id=req.container_id)

    events = None
    if req.include_timeline:
        tl = _get_timeline()
        events = tl.query(container_id=req.container_id, limit=200)

    hypotheses = None
    if req.include_rca:
        rca = _get_rca()
        hypotheses = [h.to_dict() for h in rca.analyze(req.container_id)]

    report = gen.generate(
        container_id=req.container_id,
        severity=req.severity,
        title=req.title,
        analyst=req.analyst,
        snapshot=snap_data or None,
        network_flows=flows,
        timeline_events=events,
        rca_hypotheses=hypotheses,
    )

    if output_format == "markdown":
        return {"format": "markdown", "content": gen.to_markdown(report)}
    return gen.to_json(report)


@router.get("/reports")
def list_reports(
    container_id: str | None = Query(None),
    min_severity: str | None = Query(None),
):
    """List previously generated reports."""
    gen = _get_report_gen()
    reports = gen.get_reports(
        container_id=container_id,
        min_severity=min_severity,
    )
    return [r.to_dict() for r in reports]


# -- SIEM export endpoints -------------------------------------------------- #

@router.post("/siem/export")
def export_siem(req: SIEMExportRequest):
    """Export forensic events in SIEM-compatible formats."""
    from src.forensics.siem import SIEMExporter

    if req.format == "cef":
        lines = SIEMExporter.export_cef_batch(req.events)
    elif req.format == "leef":
        lines = [
            SIEMExporter.to_leef(
                event_type=e.get("event_type", ""),
                severity=e.get("severity", "medium"),
                attributes=e.get("attributes"),
            )
            for e in req.events
        ]
    elif req.format == "syslog":
        lines = [
            SIEMExporter.to_syslog_rfc5424(message=e.get("description", ""))
            for e in req.events
        ]
    elif req.format == "elastic_bulk":
        body = SIEMExporter.to_elasticsearch_bulk(req.events)
        return {"format": req.format, "content": body}
    else:  # json (default)
        lines = SIEMExporter.export_json_batch(req.events)

    return {"format": req.format, "lines": lines}


# -- Audit log endpoints ---------------------------------------------------- #

@router.get("/audit")
def query_audit_log(
    container_id: str | None = Query(None),
    event_type: str | None = Query(None),
    min_severity: str | None = Query(None),
    since: datetime | None = Query(None),
    to: datetime | None = Query(None),
    limit: int = Query(500, ge=1, le=5000),
):
    """Query the audit log with filters."""
    al = _get_audit_logger()
    return al.query(
        container_id=container_id,
        event_type=event_type,
        min_severity=min_severity,
        since=since,
        to=to,
        limit=limit,
    )


@router.post("/audit/log")
def log_audit_event(
    event_type: str,
    container_id: str,
    severity: str = "info",
    actor: str = "system",
    action: str = "",
    subject: str = "",
    detail: dict[str, Any] | None = None,
):
    """Append a new audit event."""
    al = _get_audit_logger()
    rec = al.log(
        event_type=event_type,
        container_id=container_id,
        severity=severity,
        actor=actor,
        action=action or event_type,
        subject=subject,
        detail=detail,
    )
    return rec.to_dict()


@router.get("/audit/summary")
def audit_log_summary(container_id: str | None = Query(None)):
    """Get summary statistics for the audit log."""
    al = _get_audit_logger()
    return al.summary(container_id=container_id)


@router.post("/audit/lifecycle")
def log_container_lifecycle(
    container_id: str, status: str, detail: dict | None = None
):
    """Log a container lifecycle event (start/stop/restart)."""
    al = _get_audit_logger()
    rec = al.log_container_lifecycle(
        container_id, status, detail=detail)
    return rec.to_dict()


@router.post("/audit/exec")
def log_exec_command(
    container_id: str, command: str, user: str = "root"
):
    """Log an exec command inside a container."""
    al = _get_audit_logger()
    rec = al.log_exec(container_id, command, user=user)
    return rec.to_dict()


@router.get("/audit/export")
def export_audit_log():
    """Export the entire audit log as JSON."""
    al = _get_audit_logger()
    import json
    return json.loads(al.export_json())
