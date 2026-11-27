"""Persist one scan's deduplicated findings and apply the finding lifecycle."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone

from sqlalchemy import select

from src.db.models import FindingObservation, FindingSource, ScanFinding, Severity
from src.remediation.lifecycle import complete_verified_remediations


def make_fingerprint(cve_id: str, package_name: str, package_version: str) -> str:
    """Identity of one vulnerable package version on an image."""
    return hashlib.sha256(f"{cve_id or ''}:{package_name}:{package_version or ''}".encode()).hexdigest()[:64]


def make_vuln_key(cve_id: str, package_name: str) -> str:
    """Version-independent key: is this CVE still present in this package at all?"""
    return hashlib.sha256(f"{cve_id or ''}:{package_name}".encode()).hexdigest()[:64]


def _finding_source(finding: dict, default: str) -> FindingSource:
    """Map merged multi-scanner provenance to the single legacy enum column."""
    sources = finding.get("sources") or [part for part in default.split(",") if part]
    return FindingSource(sorted(sources)[0])


def _column_limit(model, name: str) -> int | None:
    return getattr(model.__table__.c[name].type, "length", None)


def _bounded(model, name: str, value):
    """Fit scanner text to its column: titles and versions are free-form and can be very long."""
    if value is None:
        return None
    text = str(value)
    limit = _column_limit(model, name)
    if limit is None or len(text) <= limit:
        return text
    return text[: limit - 1] + "…"


def _severity(value) -> Severity | None:
    if not value:
        return None
    try:
        return Severity(value)
    except ValueError:
        return Severity.UNKNOWN


def apply_finding_observation(finding: ScanFinding, *, observed: bool, observed_at: datetime) -> None:
    """Apply one scan's lifecycle observation to an existing finding."""
    if observed:
        if finding.resolved_at is not None:
            finding.reopened_at = observed_at
        finding.resolved_at = None
    elif finding.resolved_at is None:
        finding.resolved_at = observed_at


def persist_findings(
    scan_id: str,
    image_id: int,
    deduped_findings: list[dict],
    source_name: str,
    reconcile_missing: bool = False,
    session_factory=None,
) -> int:
    """Record what `scan_id` observed on `image_id`.

    Creates or updates one `ScanFinding` per fingerprint and one
    `FindingObservation` per finding seen by this scan. When the scan is
    complete (`reconcile_missing`), open findings it did not see are resolved.
    Returns the number of findings observed.
    """
    if session_factory is None:
        from src.db.connection import get_session as session_factory

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    observed: dict[str, dict] = {}
    for finding in deduped_findings:
        fingerprint = make_fingerprint(
            finding.get("cve_id") or "", finding["package_name"], finding.get("package_version") or ""
        )
        observed.setdefault(fingerprint, finding)

    with session_factory() as session:
        existing = {
            row.fingerprint: row
            for row in session.execute(select(ScanFinding).where(ScanFinding.image_id == image_id)).scalars()
        }
        # By CVE and package, not version: an upgrade that keeps the CVE isn't news (docs/design/scan-alerts.md).
        open_critical = {
            row.vuln_key for row in existing.values() if row.resolved_at is None and row.severity == Severity.CRITICAL
        }
        seen: list[ScanFinding] = []
        for fingerprint, finding in observed.items():
            severity = _severity(finding.get("severity"))
            row = existing.get(fingerprint)
            if row is None:
                row = ScanFinding(
                    image_id=image_id,
                    fingerprint=fingerprint,
                    vuln_key=make_vuln_key(finding.get("cve_id") or "", finding["package_name"]),
                    package_name=_bounded(ScanFinding, "package_name", finding["package_name"]),
                    package_version=_bounded(ScanFinding, "package_version", finding.get("package_version")),
                    package_type=_bounded(ScanFinding, "package_type", finding.get("package_type")),
                    file_path=_bounded(ScanFinding, "file_path", finding.get("file_path")),
                    cve_id=_bounded(ScanFinding, "cve_id", finding.get("cve_id")),
                    title=_bounded(ScanFinding, "title", finding.get("title", "")) or "",
                    description=finding.get("description"),
                    severity=severity,
                    source=_finding_source(finding, source_name),
                    fixed_version=_bounded(ScanFinding, "fixed_version", finding.get("fixed_version")),
                    fix_available=bool(finding.get("fixed_version")),
                    first_seen=now,
                    last_seen=now,
                )
                session.add(row)
                session.flush()
            else:
                row.last_seen = now
                apply_finding_observation(row, observed=True, observed_at=now)
                if severity:
                    row.severity = severity
                row.title = _bounded(ScanFinding, "title", finding.get("title", row.title)) or ""
                if finding.get("file_path"):
                    row.file_path = _bounded(ScanFinding, "file_path", finding["file_path"])
                if finding.get("fixed_version"):
                    row.fixed_version = _bounded(ScanFinding, "fixed_version", finding["fixed_version"])
                    row.fix_available = True
            seen.append(row)
            session.add(
                FindingObservation(
                    scan_id=scan_id,
                    finding_id=row.id,
                    severity=severity,
                    fixed_version=_bounded(FindingObservation, "fixed_version", finding.get("fixed_version")),
                    file_path=_bounded(FindingObservation, "file_path", finding.get("file_path")),
                    observed_at=now,
                )
            )

        if reconcile_missing:
            for fingerprint, row in existing.items():
                if fingerprint not in observed:
                    apply_finding_observation(row, observed=False, observed_at=now)
            session.flush()
            complete_verified_remediations(session, image_id, scan_id)

        new_critical = [row for row in seen if row.severity == Severity.CRITICAL and row.vuln_key not in open_critical]
        if new_critical:
            from src.notifications.outbox import record_new_critical

            session.flush()
            record_new_critical(session, scan_id, image_id, new_critical, complete=reconcile_missing)

    return len(observed)
