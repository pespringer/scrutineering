"""Live system status for the dashboard's status panel: database, scan workers, last scan."""

from __future__ import annotations

from fastapi import APIRouter
from sqlalchemy import text

from src.api.serializers import enum_value, iso
from src.config import get_settings
from src.db import audit_chain
from src.db.connection import get_session
from src.db.models import Scan
from src.scan.runtime_discovery import load_status
from src.scan.tasks import app as celery_app

router = APIRouter()

WORKER_PING_TIMEOUT_SECONDS = 1.0


def _database_ok() -> bool:
    try:
        with get_session() as session:
            session.execute(text("SELECT 1"))
        return True
    except Exception:
        return False


def _responding_workers() -> int | None:
    """Number of Celery workers that answered a ping, or None if the broker is unreachable."""
    try:
        return len(celery_app.control.ping(timeout=WORKER_PING_TIMEOUT_SECONDS) or [])
    except Exception:
        return None


@router.get("/system-status")
def system_status() -> dict:
    """Report what is actually up, so the dashboard never shows a status it cannot back."""
    database = _database_ok()
    workers = _responding_workers()
    last_scan = None
    if database:
        with get_session() as session:
            scan = session.query(Scan).order_by(Scan.started_at.desc(), Scan.id.desc()).first()
            if scan is not None:
                last_scan = {
                    "scan_id": scan.scan_id,
                    "status": enum_value(scan.status),
                    "started_at": iso(scan.started_at),
                    "completed_at": iso(scan.completed_at),
                }

    problems = []
    if not database:
        problems.append("Database unreachable")
    if workers is None:
        problems.append("Scan queue unreachable")
    elif workers == 0:
        problems.append("No scan workers responding")
    discovery = load_status(get_settings().redis_url)
    if discovery and discovery.get("status") == "error":
        problems.append(f"Runtime discovery can't list containers: {discovery.get('error')}")
    chain = audit_chain.load_status(get_settings().redis_url)
    if chain and not chain.get("intact"):
        problems.append(f"The audit log's hash chain is broken at record {chain.get('first_broken_id')}")
    status = "unavailable" if not database else "degraded" if problems else "operational"
    return {
        "status": status,
        "database": "ok" if database else "unavailable",
        "queue": "ok" if workers is not None else "unavailable",
        "workers": workers or 0,
        "last_scan": last_scan,
        # The last discovery run within the hour (docs/design/runtime-discovery.md), or None.
        "discovery": discovery,
        # The daily audit chain check's last result (docs/design/security-hardening.md), or None.
        "audit_chain": chain,
        "problems": problems,
    }
