"""Scan orchestration service — REST API for triggering and querying scans.

This module provides Express-style handlers that can be imported by the
planner server (src/planner/server.mjs) or run standalone. It bridges
the Node.js API layer with the Python Celery worker pipeline.

For a pure-Node test mode, a `scan_local` function runs a scanner
directly via child_process without requiring Celery.
"""

import asyncio
import logging
import os
from typing import Optional

from .registry import detect_registry, authenticate_to_registry
from .scanners.base import ScannerError, ScannerFinding
from .scanners.trivy import TrivyScanner
from .scanners.grype import GrypeScanner
from .utils.dedup import deduplicate_findings_with_report
from .utils.db import persist_findings, init_db

logger = logging.getLogger(__name__)


class ScanService:
    """High-level scanning API.

    Handles:
    - Registry detection and authentication
    - Scanner instantiation with correct parameters
    - Concurrent scan execution
    - Deduplication and persistence
    - CVSS-based risk scoring
    """

    def __init__(
        self,
        trivy_timeout: int = 600,
        grype_timeout: int = 600,
        severities: str = "CRITICAL,HIGH,MEDIUM,LOW,UNKNOWN",
        scanner_retry_attempts: int | None = None,
        scanner_retry_backoff: float | None = None,
    ):
        self.trivy_timeout = trivy_timeout
        self.grype_timeout = grype_timeout
        self.severities = severities
        self.scanner_retry_attempts = (
            int(os.environ.get("SCANNER_RETRY_ATTEMPTS", "2"))
            if scanner_retry_attempts is None else scanner_retry_attempts
        )
        self.scanner_retry_backoff = (
            float(os.environ.get("SCANNER_RETRY_BACKOFF_SECONDS", "0.25"))
            if scanner_retry_backoff is None else scanner_retry_backoff
        )
        if self.scanner_retry_attempts < 0 or self.scanner_retry_backoff < 0:
            raise ValueError("scanner retry settings must not be negative")

    async def scan(
        self,
        image_name: str,
        scanners: Optional[list[str]] = None,
        save_results: bool = True,
    ) -> dict:
        """Run a scan against a container image.

        Args:
            image_name: Image reference (e.g., 'nginx:latest')
            scanners: Scanners to run (default: ['trivy', 'grype'])
            save_results: Whether to persist to the database

        Returns:
            dict with scan_id, findings, status, errors, etc.
        """
        import uuid

        scan_id = str(uuid.uuid4())
        scanners = scanners or ["trivy", "grype"]

        # Detect registry and attempt auth
        registry = detect_registry(image_name)
        logger.info("Detected registry '%s' for image '%s'", registry, image_name)

        registry_creds = None
        if registry != "dockerhub":
            try:
                registry_creds = await authenticate_to_registry(registry)
                if registry_creds:
                    logger.info("Authenticated to registry '%s'", registry)
            except Exception as e:
                logger.warning(
                    "Could not authenticate to registry '%s' for '%s': %s",
                    registry, image_name, e,
                )

        # Build scanners
        scanner_instances = []
        scan_params = {"username": None, "password": None}
        if registry_creds:
            scan_params["username"], scan_params["password"] = registry_creds

        for s in scanners:
            if s == "trivy":
                scanner_instances.append(TrivyScanner(
                    severities=self.severities,
                    timeout=self.trivy_timeout,
                    **scan_params,
                ))
            elif s == "grype":
                scanner_instances.append(GrypeScanner(
                    timeout=self.grype_timeout,
                    **scan_params,
                ))
            else:
                logger.warning("Unknown scanner '%s', skipping", s)

        if not scanner_instances:
            return {
                "scan_id": scan_id,
                "image_name": image_name,
                "status": "failed",
                "errors": [{"component": "config", "error": "No valid scanners configured"}],
            }

        # Run scanners concurrently
        tasks = [self._run_single(scanner, image_name, scanner.source.value) for scanner in scanner_instances]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        all_findings = []
        errors = []
        scanners_completed = []
        scanners_failed = []

        for scanner, result in zip(scanner_instances, results):
            source = scanner.source.value
            if isinstance(result, Exception):
                logger.error("Scanner '%s' failed: %s", source, result)
                errors.append({"scanner": source, "error": str(result)})
                scanners_failed.append(source)
            else:
                all_findings.extend([(f, source) for f in result])
                scanners_completed.append(source)

        # Determine status
        if not scanners_completed:
            return {
                "scan_id": scan_id,
                "image_name": image_name,
                "status": "failed",
                "errors": errors,
            }

        status = "partial" if scanners_failed else "completed"

        # Deduplicate
        deduped = []
        dedup_summary = {}
        if all_findings:
            deduped, dedup_report = deduplicate_findings_with_report(all_findings)
            dedup_summary = dedup_report.summary()

        # Persist
        persisted = 0
        if save_results and deduped:
            try:
                persisted = persist_findings(
                    scan_id=scan_id,
                    image_name=image_name,
                    deduped_findings=deduped,
                    source_name=",".join(scanners_completed),
                )
            except Exception as e:
                logger.exception("Failed to persist findings: %s", e)
                errors.append({"component": "database", "error": str(e)})

        # Build findings_by_source
        findings_by_source = {}
        for _, source in all_findings:
            findings_by_source[source] = findings_by_source.get(source, 0) + 1

        # Compute risk score
        risk_score = self._compute_risk_score(deduped)

        return {
            "scan_id": scan_id,
            "image_name": image_name,
            "registry": registry,
            "status": status,
            "findings": len(deduped),
            "dedup_summary": dedup_summary,
            "findings_by_source": findings_by_source,
            "scanners_completed": scanners_completed,
            "scanners_failed": scanners_failed,
            "persisted": persisted,
            "errors": errors,
            "risk_score": risk_score,
            "scanners": scanners,
        }

    async def scan_batch(
        self,
        image_names: list[str],
        scanners: Optional[list[str]] = None,
        max_concurrent: int = 4,
        save_results: bool = True,
    ) -> dict:
        """Scan multiple images with a concurrency limit.

        Args:
            image_names: List of image references
            scanners: Scanners to use per image
            max_concurrent: Max concurrent scans (default: 4)
            save_results: Persist each scan's findings

        Returns:
            dict with per-image results and aggregate stats.
        """
        semaphore = asyncio.Semaphore(max_concurrent)
        total_findings = 0
        total_errors = 0
        per_image = []

        async def _scan_one(image_name):
            async with semaphore:
                return await self.scan(image_name, scanners, save_results)

        tasks = [_scan_one(img) for img in image_names]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for image_name, result in zip(image_names, results):
            if isinstance(result, Exception):
                entry = {
                    "image_name": image_name,
                    "status": "failed",
                    "error": str(result),
                }
                total_errors += 1
            else:
                entry = result
                if result["status"] != "completed":
                    total_errors += 1
            total_findings += entry.get("findings", 0)
            per_image.append(entry)

        return {
            "total_images": len(image_names),
            "total_findings": total_findings,
            "total_errors": total_errors,
            "per_image_results": per_image,
        }

    async def _run_single(
        self, scanner, image_name: str, source_name: str
    ) -> list[ScannerFinding]:
        """Run a scanner with bounded exponential backoff for transient failures."""
        for attempt in range(self.scanner_retry_attempts + 1):
            logger.info("Running %s scan on '%s' (attempt %d)...", source_name, image_name, attempt + 1)
            try:
                findings = await scanner.scan(image_name)
                logger.info("%s found %d findings on '%s'", source_name, len(findings), image_name)
                return findings
            except ScannerError:
                if attempt >= self.scanner_retry_attempts:
                    raise
                delay = self.scanner_retry_backoff * (2 ** attempt)
                logger.warning("%s scan failed; retrying in %.2fs", source_name, delay)
                await asyncio.sleep(delay)

    @staticmethod
    def _compute_risk_score(findings: list[dict]) -> dict:
        """Compute CVSS-based risk score for a set of findings.

        Returns:
            dict with:
                critical_count, high_count, medium_count, low_count
                max_cvss: highest CVSS v3 score found
                risk_level: 'critical', 'high', 'medium', 'low', 'info'
                weighted_score: 0-100 weighted severity score
        """
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
        max_cvss = 0.0
        score_map = {"CRITICAL": 10, "HIGH": 7.5, "MEDIUM": 5, "LOW": 2.5, "UNKNOWN": 0}
        weighted_total = 0

        for finding in findings:
            sev = finding.get("severity", "UNKNOWN").upper()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

            cvss_scores = finding.get("cvss_scores") or {}
            for score in cvss_scores.values():
                if score > max_cvss:
                    max_cvss = score

            weighted_total += score_map.get(sev, 0)

        # Normalize weighted score (cap at 100)
        risk_score_100 = min(weighted_total, 100.0)

        if severity_counts["CRITICAL"] > 0 or max_cvss >= 9.0:
            risk_level = "critical"
        elif severity_counts["HIGH"] > 0 or max_cvss >= 7.0:
            risk_level = "high"
        elif severity_counts["MEDIUM"] > 0 or max_cvss >= 4.0:
            risk_level = "medium"
        else:
            risk_level = "low"

        return {
            "critical_count": severity_counts["CRITICAL"],
            "high_count": severity_counts["HIGH"],
            "medium_count": severity_counts["MEDIUM"],
            "low_count": severity_counts["LOW"],
            "max_cvss": round(max_cvss, 1),
            "risk_level": risk_level,
            "weighted_score": round(risk_score_100, 1),
        }
