"""Celery tasks for the scrutineering scan orchestrator.

This module defines the Celery task run_scan that orchestrates the full scan pipeline:
- Runs Trivy and Grype in parallel against a container image
- Parses JSON output from each scanner
- Deduplicates findings across scanners
- Persists results to PostgreSQL
- Handles partial failures gracefully
"""

import asyncio
from concurrent.futures import ThreadPoolExecutor
import logging
import os
import time
import uuid
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Optional

from celery import shared_task

from src.scan.celery_app import create_celery_app
from src.scan.scanners.base import ScannerError, ScannerFinding
from src.scan.scanners.trivy import TrivyScanner
from src.scan.scanners.grype import GrypeScanner
from src.scan.utils.dedup import deduplicate_findings_with_report
from src.scan.utils.db import init_db, persist_findings
from src.scan.queue import scan_task_options
from src.scan.redis_cache import SyncRedisScanCache
from src.scan.models import Severity
from src.db.connection import get_session as get_db_session
from src.db.models import Image, Scan, ScanStatus
from src.scan.image_identity import parse_image_reference
from src.scan.source_target import storage_reference
from src.scan.runtime_discovery import discover_runtime_containers, select_runtime_images
from src.scan.scheduled import schedule_active_scans
from src.telemetry.scan_metrics import record_scan, record_scan_latency

logger = logging.getLogger(__name__)

app = create_celery_app()
import src.remediation.worker  # noqa: F401  # register remediation task with the worker app
import src.remediation.reconciliation_tasks  # noqa: F401  # register stale-publication task
import src.remediation.recovery_tasks  # noqa: F401  # register provider recovery polling task
import src.remediation.retention_tasks  # noqa: F401  # register evidence retention task
import src.remediation.alert_tasks  # noqa: F401  # register deterministic alert delivery task
import src.remediation.post_merge_tasks  # noqa: F401  # register post-merge verification task
import src.remediation.verification_tasks  # noqa: F401  # register remediation verification task
import src.remediation.deployment_tasks  # noqa: F401  # register deployment observation task
import src.scan.retention_tasks  # noqa: F401  # register scan retention reporting task
import src.platform.backup_tasks  # noqa: F401  # register backup freshness task


@shared_task(name="src.scan.tasks.schedule_active_scans", acks_late=True)
def schedule_inventory_scans() -> dict[str, int]:
    from src.scan.reliability import ScanCooldown
    cooldown = ScanCooldown(int(os.environ.get("SCAN_COOLDOWN_SECONDS", "3600")))
    return schedule_active_scans(lambda image_name, priority: enqueue_scan(image_name, priority=priority), cooldown=cooldown)


@shared_task(name="src.scan.tasks.discover_runtime_scans", acks_late=True)
def discover_runtime_scans() -> dict[str, int | str]:
    """Discover running runtime images and queue bounded low-priority scans."""
    if os.environ.get("SCAN_RUNTIME_DISCOVERY_ENABLED", "false").lower() not in {"1", "true", "yes"}:
        return {"status": "disabled", "discovered": 0, "queued": 0}
    use_containerd = os.environ.get("SCAN_RUNTIME_USE_CONTAINERD", "false").lower() in {"1", "true", "yes"}
    containers = asyncio.run(discover_runtime_containers(
        use_containerd=use_containerd,
        docker_bin=os.environ.get("SCAN_RUNTIME_DOCKER_BIN", "docker"),
        ctr_bin=os.environ.get("SCAN_RUNTIME_CTR_BIN", "ctr"),
        containerd_namespace=os.environ.get("SCAN_RUNTIME_CONTAINERD_NAMESPACE", "default"),
    ))
    images = select_runtime_images(containers, limit=int(os.environ.get("SCAN_RUNTIME_MAX_IMAGES", "100")))
    for image in images:
        enqueue_scan(image, priority="low")
    return {"status": "queued", "discovered": len(containers), "queued": len(images)}


def _update_scan_record(scan_id: str, image_name: str, status: ScanStatus, *,
                        total_findings: int = 0, counts: dict[str, int] | None = None,
                        error_message: str | None = None) -> None:
    """Keep durable scan status aligned with Celery progress."""
    identity = parse_image_reference(image_name)
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    with get_db_session() as session:
        image = session.query(Image).filter_by(
            registry_name=identity.registry, repo_name=identity.repo_name, tag=identity.tag,
        ).first()
        if image is None:
            image = Image(registry_name=identity.registry, repo_name=identity.repo_name,
                          tag=identity.tag, digest=identity.digest)
            session.add(image)
            session.flush()
        scan = session.query(Scan).filter_by(scan_id=scan_id).first()
        if scan is None:
            scan = Scan(scan_id=scan_id, image_id=image.id, started_at=now)
            session.add(scan)
        elif scan.status == ScanStatus.CANCELLED and status not in {ScanStatus.FAILED, ScanStatus.PARTIAL}:
            return
        scan.status = status.value
        scan.total_findings = total_findings
        scan.critical_count = (counts or {}).get("critical", 0)
        scan.high_count = (counts or {}).get("high", 0)
        scan.medium_count = (counts or {}).get("medium", 0)
        scan.low_count = (counts or {}).get("low", 0)
        scan.error_message = error_message
        if status in {ScanStatus.COMPLETED, ScanStatus.PARTIAL, ScanStatus.FAILED}:
            scan.completed_at = now
            image.last_scan_at = now
        image.last_scan_id = scan_id


def _safe_update_scan_record(*args, **kwargs) -> None:
    """Do not turn a scanner result into a task failure when persistence is down."""
    try:
        _update_scan_record(*args, **kwargs)
    except Exception:
        logger.exception("Unable to update durable scan state")


def create_shared_scan_cache():
    """Build the optional cross-worker Redis cache from explicit settings."""
    if os.environ.get("SCANNER_CACHE_BACKEND", "local").lower() != "redis":
        return None
    import redis
    client = redis.Redis.from_url(os.environ.get("REDIS_URL", "redis://localhost:6379/0"), decode_responses=True)
    return SyncRedisScanCache(client, ttl_seconds=int(os.environ.get("SCANNER_CACHE_TTL_SECONDS", "3600")))


def enqueue_scan(image_name: str, *, priority: str = "normal", **kwargs):
    """Submit a scan with explicit broker queue and priority options."""
    options = scan_task_options(priority)
    if kwargs.get("scan_id"):
        task_id = str(kwargs["scan_id"])
        if len(task_id) > 64 or any(char.isspace() for char in task_id): raise ValueError("invalid scan_id")
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
            return [(ScannerFinding(**{
                **finding,
                "severity": Severity(finding["severity"]) if finding.get("severity") else None,
            }), source_name) for finding in cached]

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
        cache.set_sync(source_name, image_name, [{
            **asdict(finding),
            "severity": finding.severity.value if finding.severity else None,
        } for finding, _source in findings])
    return findings


def run_scanners_concurrently(
    scanner_names: list[str], image_name: str, max_workers: int | None = None, cache=None
) -> list[tuple[str, str, list[tuple[ScannerFinding, str]] | str]]:
    """Run scanners concurrently while preserving configured result order."""
    def scan_one(scanner_name: str) -> list[tuple[ScannerFinding, str]]:
        if scanner_name == "trivy":
            scanner = TrivyScanner()
            source_name = "trivy"
        elif scanner_name == "grype":
            scanner = GrypeScanner()
            source_name = "grype"
        else:
            raise ValueError(f"Unknown scanner: {scanner_name}")

        logger.info("Running %s scan on '%s'...", source_name, image_name)
        if cache is None:
            findings = run_scanner_sync(scanner, image_name, source_name)
        else:
            findings = run_scanner_sync(scanner, image_name, source_name, cache)
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

    with ThreadPoolExecutor(
        max_workers=worker_count, thread_name_prefix="scanner"
    ) as executor:
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


@shared_task(
    bind=True,
    name="src.scan.tasks.run_scan",
    acks_late=True,
    task_time_limit=3600,
)
def run_scan(
    self,
    image_name: str,
    scan_id: Optional[str] = None,
    scanners: Optional[list[str]] = None,
    save_results: bool = True,
) -> dict:
    """Orchestrate a full container image scan pipeline.

    Runs Trivy and Grype in parallel, deduplicates findings,
    and persists results to PostgreSQL.

    Args:
        image_name: Container image to scan (e.g., 'nginx:1.25')
        scan_id: Optional scan ID for tracking (generated if not provided)
        scanners: Optional list of scanners to run. Defaults to ['trivy', 'grype']
        save_results: Whether to persist findings to the database. Defaults to True.

    Returns:
        dict with scan results including:
        - scan_id: The scan tracking ID
        - image_name: The scanned image
        - status: 'completed', 'partial', or 'failed'
        - findings: Total unique findings after dedup
        - findings_by_source: Count per scanner
        - persisted: Number of findings saved to DB
        - errors: List of scanner errors encountered
    """
    scan_id = scan_id or str(uuid.uuid4())
    scanners = scanners or ["trivy", "grype"]

    storage_name = storage_reference(image_name)
    logger.info(
        "Starting scan %s for image '%s' (scanners: %s)",
        scan_id,
        image_name,
        scanners,
    )

    _safe_update_scan_record(scan_id, storage_name, ScanStatus.RUNNING)

    # Task state tracking
    self.update_state(
        state="SCANNING",
        meta={"scan_id": scan_id, "image_name": image_name, "phase": "running"},
    )

    all_findings: list[tuple[ScannerFinding, str]] = []
    errors: list[dict] = []
    scanners_completed: list[str] = []
    scanners_failed: list[str] = []

    # Run all scanners concurrently with isolated error handling. The helper
    # preserves configured order even when completion order differs.
    scanner_results = run_scanners_concurrently(scanners, image_name, cache=create_shared_scan_cache())
    for scanner_name, status, data in scanner_results:
        if status == "ok":
            all_findings.extend(data)
            scanners_completed.append(scanner_name)
        else:
            scanners_failed.append(scanner_name)
            errors.append({"scanner": scanner_name, "error": data})

    # Determine overall status
    if not scanners_completed:
        status = "failed"
        logger.error(
            "Scan %s failed completely for '%s'. All scanners failed.",
            scan_id,
            image_name,
        )
        # Keep the Celery result serializable: a dict in FAILURE state is
        # interpreted as exception metadata by the Redis backend. The durable
        # Scan row remains the source of truth for the operator-facing status.
        self.update_state(
            state="SCAN_FAILED",
            meta={
                "scan_id": scan_id,
                "image_name": image_name,
                "status": status,
                "errors": errors,
            },
        )
        _safe_update_scan_record(scan_id, storage_name, ScanStatus.FAILED,
                                 error_message="all configured scanners failed")
        return {
            "scan_id": scan_id,
            "image_name": image_name,
            "status": status,
            "findings": 0,
            "scanners_completed": scanners_completed,
            "scanners_failed": scanners_failed,
            "persisted": 0,
            "errors": errors,
        }

    if scanners_failed:
        status = "partial"
    else:
        status = "completed"

    # Deduplicate findings across scanners
    dedup_report = None
    if all_findings:
        deduped, dedup_report = deduplicate_findings_with_report(all_findings)
    else:
        deduped = []

    # Persist to database
    persisted = 0
    if save_results and (deduped or status == "completed"):
        try:
            persisted = persist_findings(
                scan_id=scan_id,
                image_name=storage_name,
                deduped_findings=deduped,
                source_name=",".join(scanners_completed),
                reconcile_missing=status == "completed",
            )
            logger.info(
                "Persisted %d findings for scan %s on '%s'",
                persisted,
                scan_id,
                image_name,
            )
        except Exception as e:
            logger.exception("Failed to persist findings for scan %s: %s", scan_id, e)
            errors.append({"component": "database", "error": str(e)})

    # Build dedup summary for the result
    dedup_summary = dedup_report.summary() if dedup_report else {"total_raw_findings": 0, "unique_findings_after_dedup": 0, "merged_duplicates": 0, "dedup_ratio": 0.0, "findings_by_source": {}}

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for finding in deduped:
        severity = str(finding.get("severity", "")).lower()
        if severity in counts:
            counts[severity] += 1
    _safe_update_scan_record(
        scan_id, storage_name, ScanStatus.PARTIAL if status == "partial" else ScanStatus.COMPLETED,
        total_findings=len(deduped), counts=counts,
        error_message="; ".join(error.get("error", "") for error in errors) or None,
    )

    # Build result summary
    # Count findings by source
    findings_by_source: dict[str, int] = {}
    for finding, source in all_findings:
        findings_by_source[source] = findings_by_source.get(source, 0) + 1

    # Update task state
    meta = {
        "scan_id": scan_id,
        "image_name": image_name,
        "status": status,
        "findings": len(deduped),
        "dedup_summary": dedup_summary,
        "findings_by_source": findings_by_source,
        "scanners_completed": scanners_completed,
        "scanners_failed": scanners_failed,
        "persisted": persisted,
        "errors": errors,
        "completed_at": datetime.now(timezone.utc).isoformat(),
    }

    self.update_state(state="COMPLETED", meta=meta)

    logger.info(
        "Scan %s %s for '%s': %d findings (%d new sources, %d persisting)",
        scan_id,
        status,
        image_name,
        len(deduped),
        len(scanners_completed),
        persisted,
    )

    return {
        "scan_id": scan_id,
        "image_name": image_name,
        "status": status,
        "findings": len(deduped),
        "dedup_summary": dedup_summary,
        "findings_by_source": findings_by_source,
        "scanners_completed": scanners_completed,
        "scanners_failed": scanners_failed,
        "persisted": persisted,
        "errors": errors,
    }


@shared_task(
    bind=True,
    name="src.scan.tasks.run_batch_scan",
    acks_late=True,
)
def run_batch_scan(
    self,
    image_names: list[str],
    scan_id_prefix: Optional[str] = None,
    scanners: Optional[list[str]] = None,
    save_results: bool = True,
) -> dict:
    """Run scans on multiple container images sequentially.

    Each image gets its own scan_id and runs through the full pipeline
    independently. Failures on one image don't affect others.

    Args:
        image_names: List of container images to scan
        scan_id_prefix: Optional prefix for scan IDs (default: random UUID prefix)
        scanners: Optional list of scanners (default: ['trivy', 'grype'])
        save_results: Whether to persist findings (default: True)

    Returns:
        dict with overall batch results and per-image status.
    """
    prefix = scan_id_prefix or str(uuid.uuid4())[:8]
    results = []
    total_findings = 0
    total_errors = 0

    logger.info("Starting batch scan of %d images (prefix: %s)", len(image_names), prefix)

    for idx, image_name in enumerate(image_names):
        current_scan_id = f"{prefix}-{idx + 1}"

        self.update_state(
            state="BATCH_SCANNING",
            meta={
                "batch_size": len(image_names),
                "current_index": idx,
                "current_image": image_name,
                "total_findings": total_findings,
                "total_errors": total_errors,
            },
        )

        try:
            result = run_scan(
                self,
                image_name=image_name,
                scan_id=current_scan_id,
                scanners=scanners,
                save_results=save_results,
            )
            results.append({"image_name": image_name, "scan_id": current_scan_id, **result})
            total_findings += result.get("findings", 0)
            if result.get("status") != "completed":
                total_errors += 1
        except Exception as e:
            logger.exception("Batch scan failed for image '%s': %s", image_name, e)
            results.append({"image_name": image_name, "scan_id": current_scan_id, "status": "failed", "error": str(e)})
            total_errors += 1

    return {
        "prefix": prefix,
        "total_images": len(image_names),
        "total_findings": total_findings,
        "total_errors": total_errors,
        "per_image_results": results,
    }
