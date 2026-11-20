"""The compliance export: one zip for a date range, with a signed manifest.

See docs/design/reports-compliance.md. The API records a request; the worker builds the zip from
server records (it holds the signing key), stores it on the request row for 24 hours, and a sweep
deletes it after that. Files keep their own signatures; `manifest.json` lists every file with its
SHA-256 and size and is signed, so the zip as a whole can be checked with openssl and sha256sum.
"""

from __future__ import annotations

import csv
import hashlib
import io
import logging
import zipfile
from datetime import datetime, timedelta

from celery import shared_task

from src.db.connection import get_session
from src.db.models import AuditLog, ComplianceExport, EvidenceBundle, Report, Sbom, ScanFinding, SigningKey
from src.remediation.evidence import canonical
from src.scan.deployments import utcnow

logger = logging.getLogger(__name__)

SCHEMA = "scrutineering.export/v1"
MAX_RANGE = timedelta(days=366)
KEEP_FOR = timedelta(hours=24)
MAX_BYTES = 512 * 1024 * 1024
ACTIVE = ("pending", "building")
# A fixed timestamp for every zip entry: the same records give the same files (all but the signature).
ZIP_TIME = (2020, 1, 1, 0, 0, 0)
FINDING_COLUMNS = (
    "id",
    "image",
    "cve_id",
    "vuln_key",
    "package_name",
    "package_version",
    "fixed_version",
    "severity",
    "title",
    "first_seen",
    "resolved_at",
    "reopened_at",
    "acknowledged",
    "remediation_id",
)
# Spreadsheets run a cell that starts with one of these as a formula; scanner text is untrusted.
FORMULA_START = ("=", "+", "-", "@", "\t", "\r")


def _iso(value: datetime | None) -> str | None:
    return value.isoformat(timespec="seconds") + "Z" if value else None


def _value(value):
    return getattr(value, "value", value)


def _cell(value) -> str:
    text = "" if value is None else str(_value(value))
    return "'" + text if text.startswith(FORMULA_START) else text


def _fingerprint(key_id: str) -> str:
    return key_id.removeprefix("sha256:")


def _findings_csv(session, since: datetime, until: datetime) -> bytes:
    """Findings open now, plus those resolved in the range."""
    rows = (
        session.query(ScanFinding)
        .filter(
            (ScanFinding.resolved_at.is_(None))
            | ((ScanFinding.resolved_at >= since) & (ScanFinding.resolved_at < until))
        )
        .order_by(ScanFinding.id)
        .all()
    )
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(FINDING_COLUMNS)
    for finding in rows:
        image = finding.image.full_name if getattr(finding, "image", None) is not None else finding.image_id
        values = [
            finding.id,
            image,
            finding.cve_id,
            finding.vuln_key,
            finding.package_name,
            finding.package_version,
            finding.fixed_version,
            _value(finding.severity),
            finding.title,
            _iso(finding.first_seen),
            _iso(finding.resolved_at),
            _iso(finding.reopened_at),
            bool(finding.acknowledged),
            finding.remediation_id,
        ]
        writer.writerow([_cell(value) for value in values])
    return out.getvalue().encode()


def _audit_json(session, since: datetime, until: datetime) -> bytes:
    records = (
        session.query(AuditLog)
        .filter(AuditLog.timestamp >= since, AuditLog.timestamp < until)
        .order_by(AuditLog.timestamp.asc(), AuditLog.id.asc())
        .all()
    )
    items = [
        {
            "id": record.id,
            "timestamp": _iso(record.timestamp),
            "event_type": _value(record.event_type),
            "entity_type": record.entity_type,
            "entity_id": record.entity_id,
            "detail": record.detail,
            "actor": record.actor,
            "actor_kind": record.actor_kind,
            "record_hash": record.record_hash,
            "previous_hash": record.previous_hash,
        }
        for record in records
    ]
    return canonical({"format": "scrutineering-audit-v1", "records": items})


def collect(session, since: datetime, until: datetime) -> dict[str, bytes]:
    """Every file of the export except the manifest and its signature, by path."""
    files: dict[str, bytes] = {}
    key_ids: set[str] = set()

    def signed(path: str, document: str, signature: str | None, key_id: str | None) -> None:
        files[path] = document.encode()
        if signature:
            files[f"{path}.sig"] = (signature + "\n").encode()
            key_ids.add(key_id or "")

    bundles = session.query(EvidenceBundle).order_by(EvidenceBundle.id).all()
    cited: set[str] = set()
    for bundle in bundles:
        if not since <= bundle.ended_at < until:  # compared in Python, as for evidence
            continue
        signed(f"evidence/{bundle.remediation_id}-{bundle.id}.json", bundle.document, bundle.signature, bundle.key_id)
        cited.update(scan_id for scan_id in (bundle.before_scan_id, bundle.after_scan_id) if scan_id)
    for sbom in session.query(Sbom).filter(Sbom.scan_id.in_(cited)).order_by(Sbom.scan_id).all():
        signed(f"sboms/{sbom.scan_id}.cdx.json", sbom.document, sbom.signature, sbom.key_id)
    reports = session.query(Report).order_by(Report.period_start, Report.id).all()
    for report in reports:
        if since <= report.period_start < until:
            name = f"reports/{report.kind}-{report.period_start.date().isoformat()}-{report.id}.json"
            signed(name, report.document, report.signature, report.key_id)
    files["findings.csv"] = _findings_csv(session, since, until)
    files["audit.json"] = _audit_json(session, since, until)
    key_ids.discard("")
    for key in session.query(SigningKey).filter(SigningKey.key_id.in_(key_ids)).all():
        files[f"keys/{_fingerprint(key.key_id)}.pem"] = key.public_key_pem.encode()
    return files


def manifest(files: dict[str, bytes], since: datetime, until: datetime, now: datetime, key_id: str) -> bytes:
    return canonical(
        {
            "schema": SCHEMA,
            "range": {"since": _iso(since), "until": _iso(until)},
            "generated_at": _iso(now),
            "key_id": key_id,
            "files": [
                {"path": path, "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
                for path, data in sorted(files.items())
            ],
        }
    )


def build_zip(since: datetime, until: datetime, now: datetime) -> tuple[bytes, int]:
    """The zip and how many files it holds. Raises if the key can't sign: an unsigned export proves nothing."""
    from src import signing

    key_id = signing.current_key_id()
    with get_session() as session:
        files = collect(session, since, until)
        pem = session.query(SigningKey.public_key_pem).filter_by(key_id=key_id).scalar()
    files[f"keys/{_fingerprint(key_id)}.pem"] = pem.encode()
    manifest_bytes = manifest(files, since, until, now, key_id)
    signature = signing.sign(manifest_bytes)
    files["manifest.json"] = manifest_bytes
    files["manifest.json.sig"] = (signature.value + "\n").encode()
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in [
            "manifest.json",
            "manifest.json.sig",
            *sorted(set(files) - {"manifest.json", "manifest.json.sig"}),
        ]:
            info = zipfile.ZipInfo(path, date_time=ZIP_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            archive.writestr(info, files[path])
    return buffer.getvalue(), len(files)


def build(export_id: int) -> str:
    """Build one requested export; returns its final status."""
    with get_session() as session:
        export = session.get(ComplianceExport, export_id)
        if export is None or export.status != "pending":
            return export.status if export else "missing"
        export.status = "building"
        since, until = export.since, export.until
    try:
        data, count = build_zip(since, until, utcnow())
        if len(data) > MAX_BYTES:
            raise ValueError(
                f"the export is {len(data) // (1024 * 1024)} MB, over the {MAX_BYTES // (1024 * 1024)} MB limit"
            )
    except Exception as exc:  # noqa: BLE001 - recorded on the request, shown on the page
        logger.exception("compliance export %s failed", export_id)
        with get_session() as session:
            export = session.get(ComplianceExport, export_id)
            export.status, export.error, export.finished_at = "failed", str(exc)[:500], utcnow()
        return "failed"
    with get_session() as session:
        export = session.get(ComplianceExport, export_id)
        export.status, export.data, export.files = "ready", data, count
        export.size, export.sha256, export.finished_at = len(data), hashlib.sha256(data).hexdigest(), utcnow()
    logger.info("compliance export %s: %d files, %d bytes", export_id, count, len(data))
    return "ready"


def prune(now: datetime | None = None) -> int:
    """Delete exports older than KEEP_FOR, and fail requests a worker never finished."""
    now = now or utcnow()
    with get_session() as session:
        old = session.query(ComplianceExport).filter(ComplianceExport.created_at < now - KEEP_FOR).all()
        for export in old:
            session.delete(export)
        stuck = (
            session.query(ComplianceExport)
            .filter(ComplianceExport.status.in_(ACTIVE), ComplianceExport.created_at < now - timedelta(hours=1))
            .all()
        )
        for export in stuck:
            export.status, export.error, export.finished_at = "failed", "no worker finished it within an hour", now
    return len(old)


def queue_build(export_id: int) -> None:
    """Queue the build on the worker (the API never signs)."""
    build_compliance_export.apply_async(args=[export_id], queue="scan.low", retry=False)


@shared_task(name="src.reports.export.build_compliance_export", acks_late=True, ignore_result=True)
def build_compliance_export(export_id: int) -> str:
    return build(export_id)


@shared_task(name="src.reports.export.prune_compliance_exports", acks_late=True, ignore_result=True)
def prune_compliance_exports() -> int:
    """Hourly, from beat."""
    return prune()
