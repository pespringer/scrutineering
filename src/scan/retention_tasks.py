"""Dry-run-first retention reporting for durable scan history."""

from __future__ import annotations

import hashlib
import json
import os

from celery import shared_task

from src.db.connection import get_session
from src.db.models import Scan, ScanFinding
from src.scan.retention import ScanRetentionPolicy


@shared_task(name="src.scan.retention_tasks.report_expired_scans", acks_late=True)
def report_expired_scans(*, dry_run: bool = True, limit: int = 500) -> dict[str, int | bool | str]:
    if limit < 1:
        raise ValueError("retention report limit must be positive")
    policy = ScanRetentionPolicy(days=int(os.environ.get("SCAN_RETENTION_DAYS", "90")), purge_enabled=os.environ.get("SCAN_PURGE_ENABLED", "false").lower() == "true", dry_run=dry_run)
    cutoff = policy.cutoff()
    with get_session() as session:
        scans = session.query(Scan).filter(Scan.completed_at.is_not(None), Scan.completed_at < cutoff).limit(limit).all()
        finding_count = session.query(ScanFinding).filter(ScanFinding.scan_id.in_([scan.scan_id for scan in scans])).count() if scans else 0
        purged = 0
        if not dry_run and policy.can_purge():
            for scan in scans:
                session.query(ScanFinding).filter(ScanFinding.scan_id == scan.scan_id).delete(synchronize_session=False)
                session.delete(scan)
            purged = len(scans)
    report = {"cutoff": cutoff.isoformat(), "dry_run": dry_run, "purge_enabled": policy.purge_enabled, "eligible": len(scans), "findings": finding_count, "purged": purged}
    report["report_sha256"] = hashlib.sha256(json.dumps(report, sort_keys=True).encode()).hexdigest()
    return report
