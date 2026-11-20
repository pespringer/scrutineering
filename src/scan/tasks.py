"""Celery tasks for the scan pipeline.

`run_scan` runs Trivy and Grype in parallel against one target, deduplicates
their findings, records what the scan observed, and leaves the scan in a
terminal state (`completed`, `partial`, `failed`, or `cancelled`) on every path.
Scans are created by `src.scan.records` before they are queued.
"""

import asyncio
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Optional

from celery import shared_task

from src.db.connection import get_session as get_db_session
from src.db.models import AuditEventType, Scan, ScanFinding, ScanStatus, Severity as DbSeverity, SeveritySnapshot
from src.db.repositories import AuditLogRepository
from src.scan.celery_app import create_celery_app
from src.scan.models import Severity
from src.scan.queue import scan_task_options
from src.scan.image_identity import parse_image_reference
from src.scan.records import create_pending_scan, mark_scan_failed, queue_scan
from src.scan.registry import credentials_for_host, resolve_digest
from src.scan.redis_cache import SyncRedisScanCache
from src.scan.runtime_discovery import run_discovery
from src.scan.scanners.base import ScannerError, ScannerFinding
from src.scan.scanners.grype import GrypeScanner
from src.scan.scanners.trivy import TrivyScanner
from src.scan.scheduled import schedule_active_scans
from src.config import get_settings
from src.scan.settings import ScannerSettings
from src.scan.utils.dedup import deduplicate_findings_with_report
from src.scan.utils.db import persist_findings
from src.telemetry.scan_metrics import record_scan, record_scan_latency

logger = logging.getLogger(__name__)

app = create_celery_app()
import src.remediation.worker  # noqa: E402,F401  # register remediation task with the worker app
import src.remediation.publish  # noqa: E402,F401  # register the publication task
import src.notifications.delivery  # noqa: E402,F401  # register the notification delivery task
from src.scan import sbom  # noqa: E402  # SBOMs; also registers the prune task
import src.remediation.evidence  # noqa: E402,F401  # register the evidence task
import src.scan.deployments  # noqa: E402,F401  # register the deployments prune task

TERMINAL_STATUSES = {ScanStatus.COMPLETED, ScanStatus.PARTIAL, ScanStatus.FAILED, ScanStatus.CANCELLED}


@shared_task(name="src.scan.tasks.schedule_active_scans", acks_late=True)
def schedule_inventory_scans() -> dict[str, int]:
    from src.scan.reliability import ScanCooldown

    cooldown = ScanCooldown(get_settings().scan_cooldown_seconds)
    return schedule_active_scans(
        lambda target, priority: queue_scan(target, priority=priority, trigger="scheduled"),
        cooldown=cooldown,
    )


@shared_task(name="src.scan.tasks.discover_runtime_scans", acks_late=True)
def discover_runtime_scans() -> dict:
    """Record the images of running containers and queue low-priority scans of those due one."""
    return run_discovery(get_settings(), queue=lambda image: queue_scan(image, priority="low", trigger="discovery"))


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _scan_status(scan_id: str) -> ScanStatus | None:
    with get_db_session() as session:
        scan = session.query(Scan).filter_by(scan_id=scan_id).first()
        return ScanStatus(scan.status) if scan else None


def _set_running(scan_id: str, phase: str, task_id: str | None) -> None:
    with get_db_session() as session:
        scan = session.query(Scan).filter_by(scan_id=scan_id).one()
        if scan.status in TERMINAL_STATUSES:
            return
        scan.status = ScanStatus.RUNNING.value
        scan.phase = phase
        if task_id:
            scan.task_id = task_id


def _finish_scan(
    scan_id: str, status: ScanStatus, *, total: int, counts: dict[str, int], error_message: str | None
) -> None:
    """Record a completed or partial result; never overwrite a cancellation."""
    now = _now()
    with get_db_session() as session:
        scan = session.query(Scan).filter_by(scan_id=scan_id).one()
        if scan.status == ScanStatus.CANCELLED:
            return
        scan.status = status.value
        scan.phase = status.value
        scan.total_findings = total
        scan.critical_count = counts.get("critical", 0)
        scan.high_count = counts.get("high", 0)
        scan.medium_count = counts.get("medium", 0)
        scan.low_count = counts.get("low", 0)
        scan.error_message = error_message
        scan.completed_at = now
        scan.image.last_scan_at = now
        scan.image.last_scan_id = scan_id


def _fail_scan(scan_id: str, reason: str, *, phase: str = "failed") -> None:
    """Best effort: if the database itself is down there is nothing more to record."""
    try:
        with get_db_session() as session:
            mark_scan_failed(session, scan_id, reason, phase=phase)
    except Exception:
        logger.exception("Unable to record failure for scan %s", scan_id)


def _record_scan_event(scan_id: str, event_type: AuditEventType, detail: dict) -> None:
    """Record worker outcomes without allowing audit persistence to fail a scan."""
    try:
        with get_db_session() as session:
            AuditLogRepository.record(
                session,
                event_type=event_type,
                entity_type="scan",
                entity_id=scan_id,
                detail=detail,
                actor="celery-worker",
                actor_kind="system",
            )
    except Exception:
        logger.exception("Unable to record scan audit event %s", scan_id)


def _write_severity_snapshot(image_id: int) -> None:
    """Persist today's open-finding posture so the dashboard trend has real data."""
    snapshot_date = _now().replace(hour=0, minute=0, second=0, microsecond=0)
    with get_db_session() as session:
        findings = (
            session.query(ScanFinding)
            .filter(
                ScanFinding.image_id == image_id,
                ScanFinding.resolved_at.is_(None),
            )
            .all()
        )
        counts = {severity.value: 0 for severity in DbSeverity}
        for finding in findings:
            if finding.severity:
                counts[finding.severity.value] += 1
        snapshot = session.query(SeveritySnapshot).filter_by(image_id=image_id, snapshot_date=snapshot_date).first()
        if snapshot is None:
            snapshot = SeveritySnapshot(image_id=image_id, snapshot_date=snapshot_date)
            session.add(snapshot)
        snapshot.critical_count = counts["critical"]
        snapshot.high_count = counts["high"]
        snapshot.medium_count = counts["medium"]
        snapshot.low_count = counts["low"]
        snapshot.total_open = len(findings)


def create_shared_scan_cache():
    """Build the optional cross-worker Redis cache from explicit settings."""
    settings = get_settings()
    if settings.scanner_cache_backend != "redis":
        return None
    import redis

    client = redis.Redis.from_url(settings.redis_url, decode_responses=True)
    return SyncRedisScanCache(client, ttl_seconds=settings.scanner_cache_ttl_seconds)


def enqueue_scan(image_name: str, *, priority: str = "normal", **kwargs):
    """Submit a scan with explicit broker queue and priority options.

    Callers should normally use `src.scan.records.queue_scan`, which creates the
    pending scan record first.
    """
    options = scan_task_options(priority)
    if kwargs.get("scan_id"):
        task_id = str(kwargs["scan_id"])
        if len(task_id) > 64 or any(char.isspace() for char in task_id):
            raise ValueError("invalid scan_id")
        options["task_id"] = task_id
    return run_scan.apply_async(args=[image_name], kwargs=kwargs, **options)


def run_scanner_sync(scanner, image_name: str, source_name: str, cache=None) -> list[dict]:
    """Run a single scanner synchronously and return normalized findings.

    This wrapper runs the async scanner method in a new event loop
    (Celery workers don't have a running loop by default).

    Args:
        scanner: ScannerAdapter instance
        image_name: Container image reference
        source_name: Scanner name string ('trivy' or 'grype')

    Returns:
        List of finding dicts with source_name attached.

    Raises:
        ScannerError: If the scanner fails.
    """
    if cache is not None:
        cached = cache.get_sync(source_name, image_name)
        if cached is not None:
            record_scan("cache_hit", source_name)
            return [
                (
                    ScannerFinding(
                        **{
                            **finding,
                            "severity": Severity(finding["severity"]) if finding.get("severity") else None,
                        }
                    ),
                    source_name,
                )
                for finding in cached
            ]

    async def _run():
        findings = await scanner.scan(image_name)
        return [(f, source_name) for f in findings]

    started = time.monotonic()
    try:
        findings = asyncio.run(_run())
        record_scan("completed", source_name)
        record_scan_latency(time.monotonic() - started, source_name)
    except Exception:
        record_scan("failed", source_name)
        record_scan_latency(time.monotonic() - started, source_name)
        raise
    if cache is not None:
        cache.set_sync(
            source_name,
            image_name,
            [
                {
                    **asdict(finding),
                    "severity": finding.severity.value if finding.severity else None,
                }
                for finding, _source in findings
            ],
        )
    return findings


def build_scanner(
    scanner_name: str, settings: ScannerSettings, *, credentials=None, registry_host: str = "", insecure: bool = False
):
    """Construct a scanner from settings, with this scan's registry credentials."""
    username, password = credentials if credentials else (None, None)
    if scanner_name == "trivy":
        return TrivyScanner(
            timeout=settings.timeout_seconds,
            cache_dir=settings.trivy_cache_dir,
            max_output_bytes=settings.max_output_bytes,
            max_findings=settings.max_findings,
            registry_username=username,
            registry_password=password,
            insecure=insecure,
        )
    if scanner_name == "grype":
        return GrypeScanner(
            timeout=settings.timeout_seconds,
            max_output_bytes=settings.max_output_bytes,
            max_findings=settings.max_findings,
            registry_username=username,
            registry_password=password,
            registry_authority=registry_host or None,
            insecure=insecure,
            local_registry_host=settings.local_registry_host,
        )
    raise ValueError(f"Unknown scanner: {scanner_name}")


def run_scanners_concurrently(
    scanner_names: list[str],
    image_name: str,
    max_workers: int | None = None,
    cache=None,
    *,
    settings: ScannerSettings | None = None,
    credentials=None,
    registry_host: str = "",
    insecure: bool = False,
) -> list[tuple[str, str, list[tuple[ScannerFinding, str]] | str]]:
    """Run scanners concurrently while preserving configured result order."""
    settings = settings or ScannerSettings()

    def scan_one(scanner_name: str) -> list[tuple[ScannerFinding, str]]:
        scanner = build_scanner(
            scanner_name, settings, credentials=credentials, registry_host=registry_host, insecure=insecure
        )
        source_name = scanner_name

        logger.info("Running %s scan on '%s'...", source_name, image_name)
        attempt = 0
        while True:
            try:
                if cache is None:
                    findings = run_scanner_sync(scanner, image_name, source_name)
                else:
                    findings = run_scanner_sync(scanner, image_name, source_name, cache)
                break
            except ScannerError as error:
                # Registry timeouts and vulnerability-DB downloads fail transiently; retry with backoff.
                if attempt >= settings.retry_attempts:
                    raise
                attempt += 1
                delay = settings.retry_backoff_seconds * (2 ** (attempt - 1))
                logger.warning(
                    "%s failed on '%s' (attempt %d of %d), retrying in %.1fs: %s",
                    source_name,
                    image_name,
                    attempt,
                    settings.retry_attempts + 1,
                    delay,
                    error,
                )
                if delay:
                    time.sleep(delay)
        logger.info(
            "%s found %d findings on '%s'",
            source_name,
            len(findings),
            image_name,
        )
        return findings

    if not scanner_names:
        return []

    worker_count = max_workers or len(scanner_names)
    worker_count = max(1, min(worker_count, len(scanner_names)))
    results = []

    with ThreadPoolExecutor(max_workers=worker_count, thread_name_prefix="scanner") as executor:
        futures = [(name, executor.submit(scan_one, name)) for name in scanner_names]
        for scanner_name, future in futures:
            try:
                results.append((scanner_name, "ok", future.result()))
            except ScannerError as error:
                logger.error(
                    "Scanner '%s' failed for '%s': %s",
                    scanner_name,
                    image_name,
                    error,
                )
                results.append((scanner_name, "error", str(error)))
            except Exception as error:
                logger.exception(
                    "Unexpected error running '%s' for '%s': %s",
                    scanner_name,
                    image_name,
                    error,
                )
                results.append((scanner_name, "error", f"Unexpected: {error}"))

    return results


class ImmutableIdentityError(RuntimeError):
    """The tag could not be pinned to a digest and REQUIRE_IMMUTABLE_SCAN_IDENTITY is set."""


def _resolve_scan_target(image_name: str, settings: ScannerSettings) -> dict:
    """Pin an image tag to its digest and pick this scan's registry credentials.

    Returns the reference to hand to the scanners (`repo@sha256:...` when
    resolved), the digest, and per-scan auth/transport settings.
    """
    if filesystem_path_target(image_name):
        return {
            "target": image_name,
            "digest": None,
            "credentials": None,
            "host": "",
            "insecure": False,
            "identity": "filesystem",
        }
    identity = parse_image_reference(image_name)
    credentials = credentials_for_host(identity.host)
    insecure = settings.insecure_host(identity.host)
    base = {"credentials": credentials, "host": identity.host, "insecure": insecure}
    try:
        digest = resolve_digest(identity, credentials=credentials, scheme="http" if insecure else "https")
    except Exception as exc:
        if settings.require_immutable_identity:
            raise ImmutableIdentityError(f"could not resolve {image_name} to a digest: {exc}") from exc
        logger.warning("Scanning %s by tag; digest resolution failed: %s", image_name, exc)
        return {**base, "target": image_name, "digest": None, "identity": "tag", "resolution_error": str(exc)[:300]}
    return {**base, "target": f"{identity.repo_name}@{digest}", "digest": digest, "identity": "digest"}


def filesystem_path_target(target: str) -> bool:
    return str(target or "").startswith("fs:")


def _record_digest(scan_id: str, digest: str) -> None:
    with get_db_session() as session:
        scan = session.query(Scan).filter_by(scan_id=scan_id).one()
        scan.image_digest = digest
        scan.image.digest = digest


def _result(scan_id: str, image_name: str, status: str, **extra) -> dict:
    return {
        "scan_id": scan_id,
        "image_name": image_name,
        "status": status,
        "findings": 0,
        "scanners_completed": [],
        "scanners_failed": [],
        "persisted": 0,
        "errors": [],
        **extra,
    }


@shared_task(bind=True, name="src.scan.tasks.run_scan", acks_late=True, task_time_limit=3600)
def run_scan(
    self,
    image_name: str,
    scan_id: Optional[str] = None,
    scanners: Optional[list[str]] = None,
    save_results: bool = True,
) -> dict:
    """Scan one target and leave its scan record in a terminal state.

    Args:
        image_name: The target: an image reference, or `fs:<path>` for an internal filesystem scan.
        scan_id: The pending scan created by `queue_scan`. A missing record is created here.
        scanners: Scanners to run. Defaults to ['trivy', 'grype'].
        save_results: Persist findings and observations. Defaults to True.
    """
    scanners = scanners or ["trivy", "grype"]
    try:
        with get_db_session() as session:
            scan = create_pending_scan(session, image_name, scan_id=scan_id, trigger="worker")
            scan_id, image_id = scan.scan_id, scan.image_id
    except Exception as exc:
        logger.exception("Unable to load or create the scan record for %s", image_name)
        return _result(scan_id or "", image_name, "failed", errors=[{"component": "database", "error": str(exc)}])

    try:
        return _execute_scan(self, image_name, scan_id, image_id, scanners, save_results)
    except Exception as exc:
        logger.exception("Scan %s failed unexpectedly", scan_id)
        _fail_scan(scan_id, f"worker error: {exc}")
        _record_scan_event(
            scan_id,
            AuditEventType.SCAN_FAILED,
            {
                "action": "worker_failed",
                "phase": "worker_error",
                "error": str(exc)[:500],
                "image_name": image_name,
            },
        )
        return _result(scan_id, image_name, "failed", errors=[{"component": "worker", "error": str(exc)}])


def _execute_scan(task, image_name: str, scan_id: str, image_id: int, scanners: list[str], save_results: bool) -> dict:
    task_id = getattr(task.request, "id", None)
    task_id = task_id if isinstance(task_id, str) else None
    if _scan_status(scan_id) == ScanStatus.CANCELLED:
        return _result(scan_id, image_name, "cancelled", errors=[{"component": "worker", "error": "scan_cancelled"}])

    logger.info("Starting scan %s for '%s' (scanners: %s)", scan_id, image_name, scanners)
    settings = ScannerSettings.from_env()
    _set_running(scan_id, "resolving", task_id)
    try:
        resolved = _resolve_scan_target(image_name, settings)
    except ImmutableIdentityError as exc:
        _fail_scan(scan_id, str(exc), phase="identity_unresolved")
        _record_scan_event(
            scan_id,
            AuditEventType.SCAN_FAILED,
            {
                "action": "worker_failed",
                "phase": "identity",
                "task_id": task_id,
                "error": str(exc)[:500],
                "image_name": image_name,
            },
        )
        return _result(scan_id, image_name, "failed", errors=[{"component": "identity", "error": str(exc)}])
    if resolved["digest"]:
        _record_digest(scan_id, resolved["digest"])
    _set_running(scan_id, "scanning", task_id)
    _record_scan_event(
        scan_id,
        AuditEventType.SCAN_STARTED,
        {
            "action": "worker_started",
            "phase": "scanning",
            "task_id": task_id,
            "image_name": image_name,
            "scanned_reference": resolved["target"],
            "identity": resolved["identity"],
            "resolution_error": resolved.get("resolution_error"),
            "scanners": scanners,
        },
    )
    task.update_state(state="SCANNING", meta={"scan_id": scan_id, "image_name": image_name, "phase": "running"})

    scanner_results = run_scanners_concurrently(
        scanners,
        resolved["target"],
        cache=create_shared_scan_cache(),
        settings=settings,
        credentials=resolved["credentials"],
        registry_host=resolved["host"],
        insecure=resolved["insecure"],
    )
    if _scan_status(scan_id) == ScanStatus.CANCELLED:
        _record_scan_event(
            scan_id,
            AuditEventType.SCAN_CANCELLED,
            {
                "action": "worker_stopped_after_cancel",
                "phase": "scanning",
                "task_id": task_id,
                "image_name": image_name,
            },
        )
        return _result(scan_id, image_name, "cancelled", errors=[{"component": "worker", "error": "scan_cancelled"}])

    all_findings: list[tuple[ScannerFinding, str]] = []
    errors: list[dict] = []
    completed: list[str] = []
    failed: list[str] = []
    for scanner_name, outcome, data in scanner_results:
        if outcome == "ok":
            all_findings.extend(data)
            completed.append(scanner_name)
        else:
            failed.append(scanner_name)
            errors.append({"scanner": scanner_name, "error": data})

    if not completed:
        # A dict in Celery's FAILURE state is read as exception metadata, so use a custom state.
        task.update_state(state="SCAN_FAILED", meta={"scan_id": scan_id, "image_name": image_name, "errors": errors})
        _fail_scan(scan_id, "all configured scanners failed: " + "; ".join(e["error"] for e in errors))
        _record_scan_event(
            scan_id,
            AuditEventType.SCAN_FAILED,
            {
                "action": "worker_failed",
                "phase": "scanning",
                "task_id": task_id,
                "errors": errors,
                "image_name": image_name,
            },
        )
        return _result(scan_id, image_name, "failed", scanners_failed=failed, errors=errors)

    status = ScanStatus.PARTIAL if failed else ScanStatus.COMPLETED
    deduped, dedup_report = deduplicate_findings_with_report(all_findings) if all_findings else ([], None)

    persisted = 0
    if save_results:
        try:
            persisted = persist_findings(
                scan_id=scan_id,
                image_id=image_id,
                deduped_findings=deduped,
                source_name=",".join(completed),
                reconcile_missing=status == ScanStatus.COMPLETED,
            )
        except Exception as exc:
            logger.exception("Failed to persist findings for scan %s", scan_id)
            reason = f"could not save findings: {exc}"
            _fail_scan(scan_id, reason, phase="persistence_failed")
            _record_scan_event(
                scan_id,
                AuditEventType.SCAN_FAILED,
                {
                    "action": "worker_failed",
                    "phase": "persistence",
                    "task_id": task_id,
                    "error": str(exc)[:500],
                    "image_name": image_name,
                },
            )
            errors.append({"component": "database", "error": str(exc)})
            return _result(
                scan_id,
                image_name,
                "failed",
                findings=len(deduped),
                scanners_completed=completed,
                scanners_failed=failed,
                errors=errors,
            )

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for finding in deduped:
        severity = str(finding.get("severity", "")).lower()
        if severity in counts:
            counts[severity] += 1
    _finish_scan(
        scan_id,
        status,
        total=len(deduped),
        counts=counts,
        error_message="; ".join(error.get("error", "") for error in errors) or None,
    )
    if status == ScanStatus.COMPLETED and save_results:
        try:
            _write_severity_snapshot(image_id)
        except Exception:
            logger.exception("Unable to write severity snapshot for scan %s", scan_id)
    sbom_status = None
    if save_results and not filesystem_path_target(image_name):
        trivy = build_scanner(
            "trivy",
            settings,
            credentials=resolved["credentials"],
            registry_host=resolved["host"],
            insecure=resolved["insecure"],
        )
        sbom_status = sbom.generate(scan_id, image_id, resolved["target"], trivy)
    _record_scan_event(
        scan_id,
        AuditEventType.SCAN_COMPLETED if status == ScanStatus.COMPLETED else AuditEventType.SCAN_FAILED,
        {
            "action": "worker_finished",
            "phase": status.value,
            "task_id": task_id,
            "status": status.value,
            "findings": len(deduped),
            "persisted": persisted,
            "scanners_completed": completed,
            "scanners_failed": failed,
            "errors": errors,
            "image_name": image_name,
            "sbom": sbom_status,
        },
    )

    findings_by_source: dict[str, int] = {}
    for _, source in all_findings:
        findings_by_source[source] = findings_by_source.get(source, 0) + 1
    dedup_summary = (
        dedup_report.summary()
        if dedup_report
        else {
            "total_raw_findings": 0,
            "unique_findings_after_dedup": 0,
            "merged_duplicates": 0,
            "dedup_ratio": 0.0,
            "findings_by_source": {},
        }
    )
    task.update_state(state="COMPLETED", meta={"scan_id": scan_id, "status": status.value, "findings": len(deduped)})
    logger.info("Scan %s %s for '%s': %d findings", scan_id, status.value, image_name, len(deduped))
    return _result(
        scan_id,
        image_name,
        status.value,
        findings=len(deduped),
        dedup_summary=dedup_summary,
        findings_by_source=findings_by_source,
        scanners_completed=completed,
        scanners_failed=failed,
        persisted=persisted,
        errors=errors,
    )
