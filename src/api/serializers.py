"""JSON shapes the dashboard API returns for scans, images, findings and remediations."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone


from src.db.models import (
    FindingObservation,
    Image,
    Remediation,
    RemediationStatus,
    Scan,
    ScanFinding,
)
from src.remediation.state_machine import LABELS


def iso(value: datetime | None) -> str | None:
    """ISO 8601 in UTC with an explicit `Z`.

    The database stores naive UTC datetimes. Without a zone marker, browsers
    parse them as local time, which shifted every timestamp in the dashboard by
    the viewer's UTC offset.
    """
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def enum_value(value) -> str | None:
    return value.value if hasattr(value, "value") else value


def severity_counts(findings: list[ScanFinding]) -> dict[str, int]:
    counts = Counter((enum_value(finding.severity) or "unknown") for finding in findings)
    return {severity: counts.get(severity, 0) for severity in ("critical", "high", "medium", "low")}


def scan_payload(scan: Scan) -> dict:
    return {
        "scan_id": scan.scan_id,
        "image_id": getattr(scan, "image_id", None),
        "image_name": getattr(scan, "target", None) or (scan.image.full_name if scan.image else "unknown"),
        "target": getattr(scan, "target", None),
        "status": enum_value(scan.status),
        "phase": getattr(scan, "phase", None) or enum_value(scan.status),
        "task_id": getattr(scan, "task_id", None),
        "started_at": iso(scan.started_at),
        "completed_at": iso(scan.completed_at),
        "findings": scan.total_findings or 0,
        "critical_count": scan.critical_count or 0,
        "high_count": scan.high_count or 0,
        "medium_count": scan.medium_count or 0,
        "low_count": scan.low_count or 0,
        "archived": bool(getattr(scan, "archived", False)),
        "scanner_versions": getattr(scan, "scanner_versions", None) or {},
        "vulnerability_db_versions": getattr(scan, "vulnerability_db_versions", None) or {},
        "error_message": getattr(scan, "error_message", None),
    }


def image_payload(image: Image, findings: list[ScanFinding], resolved_count: int = 0) -> dict:
    counts = severity_counts(findings)
    return {
        "id": image.id,
        "registry": enum_value(image.registry_name),
        "name": image.full_name,
        "repo_name": image.repo_name,
        "tag": image.tag,
        "last_scan_at": iso(image.last_scan_at),
        "last_scan_id": image.last_scan_id,
        "open_findings": len(findings),
        "resolved_findings": resolved_count,
        "critical_count": counts["critical"],
        "high_count": counts["high"],
        "medium_count": counts["medium"],
        "low_count": counts["low"],
    }


def source_payload(source) -> dict | None:
    if source is None:
        return None
    return {
        "repository": source.repository,
        "ref": source.ref,
        "dockerfile_path": source.dockerfile_path,
        "build_context": source.build_context,
        "build_args": source.build_args or {},
        "test_command": source.test_command,
        "updated_by": source.updated_by,
        "updated_at": iso(source.updated_at),
    }


def finding_payload(finding: ScanFinding) -> dict:
    severity = enum_value(finding.severity)
    return {
        "id": finding.id,
        "fingerprint": finding.fingerprint,
        "cve_id": finding.cve_id,
        "package_name": finding.package_name,
        "package_version": finding.package_version,
        "package_type": finding.package_type,
        "file_path": getattr(finding, "file_path", None),
        "severity": severity.upper() if severity else "UNKNOWN",
        "title": finding.title,
        "description": finding.description,
        "fixed_version": finding.fixed_version,
        "fix_available": bool(finding.fix_available),
        "first_seen": iso(finding.first_seen),
        "last_seen": iso(finding.last_seen),
        "resolved_at": iso(getattr(finding, "resolved_at", None)),
        "reopened_at": iso(getattr(finding, "reopened_at", None)),
        "lifecycle_status": "resolved" if getattr(finding, "resolved_at", None) else "open",
        "acknowledged": bool(getattr(finding, "acknowledged", False)),
        "assigned_to": getattr(finding, "assigned_to", None),
        "remediation_id": getattr(finding, "remediation_id", None),
    }


def observation_payload(observation: FindingObservation, finding: ScanFinding) -> dict:
    """A finding as one scan saw it; lifecycle fields reflect its current state."""
    severity = enum_value(observation.severity)
    return {
        **finding_payload(finding),
        "severity": severity.upper() if severity else "UNKNOWN",
        "fixed_version": observation.fixed_version,
        "fix_available": observation.fixed_version is not None,
        "file_path": observation.file_path,
        "observed_at": iso(observation.observed_at),
    }


def paginate(items: list[dict], limit: int, offset: int, total: int) -> dict:
    return {"items": items, "limit": limit, "offset": offset, "count": len(items), "total": total}


def remediation_payload(remediation: Remediation, actions: list[dict] | None = None) -> dict:
    remediation_findings = list(getattr(remediation, "findings", []) or [])
    resolved_findings = sum(1 for finding in remediation_findings if getattr(finding, "resolved_at", None) is not None)
    status = RemediationStatus(enum_value(remediation.status))
    return {
        "id": remediation.id,
        "image_id": remediation.image_id,
        "status": status.value,
        "status_label": LABELS[status],
        "error_message": getattr(remediation, "error_message", None),
        "started_at": iso(getattr(remediation, "started_at", None)),
        "completed_at": iso(getattr(remediation, "completed_at", None)),
        "source_commit": getattr(remediation, "source_commit", None),
        "patch": getattr(remediation, "patch", None),
        "candidate_image": getattr(remediation, "candidate_image", None),
        "candidate_digest": getattr(remediation, "candidate_digest", None),
        "verification": getattr(remediation, "verification", None),
        "finding_count": remediation.finding_count,
        "open_finding_count": max(len(remediation_findings) - resolved_findings, 0),
        "resolved_finding_count": resolved_findings,
        "resolution_status": "resolved"
        if remediation_findings and resolved_findings == len(remediation_findings)
        else "open",
        "target_severities": remediation.target_severities,
        "approved_by": remediation.approved_by,
        "approved_at": iso(remediation.approved_at),
        "actions": actions
        if actions is not None
        else [
            {
                "id": action.id,
                "action_type": enum_value(action.action_type),
                "file_path": action.file_path,
                "before_value": action.before_value,
                "after_value": action.after_value,
                "success": action.success,
                "detail": action.detail,
            }
            for action in remediation.actions
        ],
        "publications": [
            {
                "id": publication.id,
                "provider": publication.provider,
                "repository": publication.repository,
                "status": publication.status,
                "url": publication.url,
                "number": publication.provider_number,
                "merged_at": iso(publication.merged_at),
                "verification_status": publication.verification_status,
                "scan_status": publication.scan_status,
                "post_merge_scan_id": publication.post_merge_scan_id,
                "verification_detail": publication.verification_detail,
                "findings_before": publication.findings_before,
                "findings_after": publication.findings_after,
                "rollback_command": publication.rollback_command,
            }
            for publication in remediation.publications
        ],
    }
