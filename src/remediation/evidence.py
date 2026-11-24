"""Signed evidence for remediations that ended `completed` or `failed` (docs/design/sbom-evidence.md).

A bundle is one canonical JSON document (sorted keys, no whitespace) built from the server's own
records only: targets, plan, patch, candidate and its verification, the pull request, the scans
before and after with their SBOM hashes, and the event timeline. It is signed and frozen: built
once per ending, never rebuilt. A remediation is due a bundle when it is `completed` or `failed`
and no bundle records its current ending (`ended_at`); a beat sweep builds what is due.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone

from celery import shared_task
from sqlalchemy import select

from src.db.connection import get_session
from src.db.models import (
    EvidenceBundle,
    FindingObservation,
    Remediation,
    RemediationStatus,
    Sbom,
    Scan,
    ScanFinding,
    ScanStatus,
)

logger = logging.getLogger(__name__)

SCHEMA = "scrutineering.evidence/v1"
ENDINGS = (RemediationStatus.COMPLETED, RemediationStatus.FAILED)
FINISHED_SCANS = (ScanStatus.COMPLETED.value, ScanStatus.PARTIAL.value)


def _iso(value: datetime | None) -> str | None:
    return value.replace(tzinfo=None).isoformat(timespec="seconds") + "Z" if value else None


def _value(value):
    return getattr(value, "value", value)


def canonical(document: dict) -> bytes:
    """The exact bytes that are stored, hashed and signed."""
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _scan_summary(session, scan: Scan | None, target_keys: set[str] | None = None) -> dict | None:
    if scan is None:
        return None
    sbom = session.execute(select(Sbom.sha256).where(Sbom.scan_id == scan.scan_id)).scalar_one_or_none()
    summary = {
        "scan_id": scan.scan_id,
        "status": _value(scan.status),
        "digest": scan.image_digest,
        "completed_at": _iso(scan.completed_at),
        "open_findings": scan.total_findings,
        "sbom_sha256": sbom,
    }
    if target_keys is not None:
        observed = set(
            session.execute(
                select(ScanFinding.vuln_key)
                .join(FindingObservation, FindingObservation.finding_id == ScanFinding.id)
                .where(FindingObservation.scan_id == scan.scan_id)
            ).scalars()
        )
        summary["targets_present"] = sorted(target_keys & observed)
    return summary


def finished_scan(session, image_id: int, *, started_by: datetime | None) -> Scan | None:
    """The last finished scan of the image that had started by `started_by`.

    By start time, not finish time: the scan that completes a remediation saves its findings, which
    completes the remediation, before the scan itself is stamped finished.
    """
    query = select(Scan).where(Scan.image_id == image_id, Scan.status.in_(FINISHED_SCANS))
    if started_by is not None:
        query = query.where(Scan.started_at <= started_by)
    return session.execute(query.order_by(Scan.started_at.desc(), Scan.id.desc()).limit(1)).scalar_one_or_none()


def build_document(session, remediation: Remediation) -> tuple[dict, str | None, str | None]:
    """The bundle, and the scan IDs it cites (their SBOMs are kept for it)."""
    image = remediation.image
    findings = list(remediation.findings)
    target_keys = {finding.vuln_key for finding in findings if finding.vuln_key}
    before = finished_scan(session, remediation.image_id, started_by=remediation.created_at)
    after = finished_scan(session, remediation.image_id, started_by=remediation.completed_at)
    if after is not None and before is not None and after.scan_id == before.scan_id:
        after = None  # it ended without a later scan
    publication = max(remediation.publications, key=lambda item: item.id) if remediation.publications else None
    patch = remediation.patch or ""
    document = {
        "schema": SCHEMA,
        "generated_at": _iso(datetime.now(timezone.utc)),
        "remediation": {
            "id": remediation.id,
            "status": _value(remediation.status),
            "image": image.full_name if image else None,
            "approved_by": remediation.approved_by,
            "approved_at": _iso(remediation.approved_at),
            "created_at": _iso(remediation.created_at),
            "ended_at": _iso(remediation.completed_at),
            "error": remediation.error_message,
        },
        "targets": sorted(
            (
                {
                    "cve_id": finding.cve_id,
                    "package": finding.package_name,
                    "version": finding.package_version,
                    "severity": _value(finding.severity),
                    "vuln_key": finding.vuln_key,
                }
                for finding in findings
            ),
            key=lambda item: (item["cve_id"] or "", item["package"] or ""),
        ),
        "plan": [
            {
                "strategy": _value(action.action_type),
                "from": action.before_value,
                "to": action.after_value,
                "detail": action.detail or {},
            }
            for action in sorted(remediation.actions, key=lambda item: item.id)
        ],
        "patch": {
            "source_commit": remediation.source_commit,
            "sha256": hashlib.sha256(patch.encode()).hexdigest() if patch else None,
            "diff": patch or None,
        },
        "candidate": {
            "image": remediation.candidate_image,
            "digest": remediation.candidate_digest,
            "test_command": (remediation.source or {}).get("test_command"),
            "verification": remediation.verification,
        },
        "publication": (
            {
                "provider": publication.provider,
                "repository": publication.repository,
                "url": publication.url,
                "status": publication.status,
                "branch": publication.branch,
                "head_commit": publication.head_commit,
                "merged_at": _iso(publication.merged_at),
                "merge_commit": publication.merge_commit,
            }
            if publication
            else None
        ),
        "scans": {
            "before": _scan_summary(session, before),
            "after": _scan_summary(session, after, target_keys),
        },
        "events": [
            {"sequence": event.sequence, "type": event.event_type, "at": _iso(event.created_at), "detail": event.detail}
            for event in sorted(remediation.events, key=lambda item: (item.sequence or 0, item.id))
        ],
    }
    return document, before.scan_id if before else None, after.scan_id if after else None


def _due(session) -> list[int]:
    """Remediations that ended and have no bundle for that ending.

    Compared as datetimes in Python: SQLite stores `func.now()` and a Python datetime as differently
    formatted text, so an SQL equality on them can miss.
    """
    ended = session.execute(
        select(Remediation.id, Remediation.completed_at).where(
            Remediation.status.in_(ENDINGS), Remediation.completed_at.is_not(None)
        )
    ).all()
    if not ended:
        return []
    recorded = set(
        session.execute(
            select(EvidenceBundle.remediation_id, EvidenceBundle.ended_at).where(
                EvidenceBundle.remediation_id.in_([remediation_id for remediation_id, _ in ended])
            )
        ).all()
    )
    return [remediation_id for remediation_id, ended_at in ended if (remediation_id, ended_at) not in recorded]


def build(remediation_id: int) -> EvidenceBundle | None:
    """Build, sign and store one bundle. An unusable key stores it unsigned, as with SBOMs."""
    from src import signing

    with get_session() as session:
        remediation = session.get(Remediation, remediation_id)
        if remediation is None or RemediationStatus(_value(remediation.status)) not in ENDINGS:
            return None
        document, before_scan_id, after_scan_id = build_document(session, remediation)
        data = canonical(document)
        try:
            signature = signing.sign(data)
        except Exception as exc:  # noqa: BLE001 - logged; the bundle is kept unsigned
            logger.error("could not sign evidence for remediation %s, keeping it unsigned: %s", remediation_id, exc)
            signature = None
        bundle = EvidenceBundle(
            remediation_id=remediation_id,
            outcome=_value(remediation.status),
            ended_at=remediation.completed_at,
            before_scan_id=before_scan_id,
            after_scan_id=after_scan_id,
            document=data.decode(),
            sha256=hashlib.sha256(data).hexdigest(),
            signature=signature.value if signature else None,
            key_id=signature.key_id if signature else None,
        )
        session.add(bundle)
        session.flush()
        session.expunge(bundle)
    logger.info("evidence for remediation %s: %s, %d bytes", remediation_id, bundle.outcome, len(data))
    return bundle


def build_due() -> int:
    """Build every bundle that is due. Returns how many were built."""
    with get_session() as session:
        due = _due(session)
    built = 0
    for remediation_id in due:
        try:
            built += build(remediation_id) is not None
        except Exception:
            logger.exception("could not build evidence for remediation %s", remediation_id)
    return built


@shared_task(name="src.remediation.evidence.build_due_evidence", acks_late=True, ignore_result=True)
def build_due_evidence() -> int:
    """Every minute, from beat."""
    return build_due()
