"""Deduplication engine for merging findings from multiple scanners.

Requirements:
- Fingerprint-based deduplication: hash of (CVE ID + package name + package version)
- When both scanners report the same CVE, keep the most complete finding (most metadata fields)
- Track which scanners reported each finding
- Handle cases where one scanner reports a CVE the other misses
- Maintain audit trail of deduplication decisions
"""

from __future__ import annotations

import hashlib
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from src.scan.scanners.base import ScannerFinding
from src.scan.models import Severity

logger = logging.getLogger(__name__)

SEVERITY_RANK = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.UNKNOWN: 1,
    None: 0,
}


def make_fingerprint(
    cve_id: Optional[str], package_name: str, package_version: Optional[str]
) -> str:
    """Create deterministic fingerprint for deduplication.

    Uses SHA-256 of the canonical key: CVE ID | package name | package version.
    """
    key = f"{cve_id or ''}|{package_name}|{package_version or ''}"
    return hashlib.sha256(key.encode()).hexdigest()[:64]


def _count_metadata_fields(finding: ScannerFinding) -> int:
    """Count how many metadata fields are populated on a finding.

    Used to determine the most complete finding when merging duplicates.
    """
    count = 0
    if finding.cve_id:
        count += 1
    if finding.package_version:
        count += 1
    if finding.package_type:
        count += 1
    if finding.title:
        count += 1
    if finding.description:
        count += 1
    if finding.severity:
        count += 1
    if finding.fixed_version:
        count += 1
    return count


def _pick_highest_severity(severities: list[Severity | None]) -> Severity | None:
    """Return the highest severity from a list."""
    return max(severities, key=lambda s: SEVERITY_RANK.get(s, 0)) if severities else None


def _merge_field(new_val: Any, existing_val: Any) -> Any:
    """Pick the best non-empty value between two fields.

    Prefers existing if both are present (stability), otherwise uses new_val.
    """
    if existing_val:
        return existing_val
    return new_val


def _build_merged_finding(
    fingerprint: str,
    group: list[tuple[ScannerFinding, str]],
) -> dict:
    """Build a single merged finding from a dedup group.

    Strategy:
    - Use the finding with the most metadata fields as the base
    - For each field, use the most complete non-empty value across all findings
    - Severity: take the highest reported
    - Sources: collect all scanner names that reported this finding
    - Audit trail: record which scanners contributed what
    """
    sources = sorted(set(src for _, src in group))

    # Find the base finding (most metadata fields populated)
    base_finding = max(group, key=lambda item: _count_metadata_fields(item[0]))[0]

    # Collect all severity values
    all_severities = [f.severity for f, _ in group]
    best_severity = _pick_highest_severity(all_severities)

    # Build union of metadata
    # For text fields, take the longest non-empty value
    # For fixed_version, take any non-empty one
    all_descriptions = [f.description for f, _ in group if f.description]
    all_titles = [f.title for f, _ in group if f.title]
    all_package_types = [f.package_type for f, _ in group if f.package_type]
    all_fixed_versions = [f.fixed_version for f, _ in group if f.fixed_version]
    all_versions = [f.package_version for f, _ in group if f.package_version]
    all_file_paths = [f.file_path for f, _ in group if f.file_path]

    merged = {
        "fingerprint": fingerprint,
        "package_name": base_finding.package_name,
        "package_version": max(all_versions, key=len) if all_versions else base_finding.package_version,
        "package_type": max(all_package_types, key=len) if all_package_types else base_finding.package_type,
        "cve_id": base_finding.cve_id,
        "title": max(all_titles, key=len) if all_titles else base_finding.title,
        "description": max(all_descriptions, key=len) if all_descriptions else base_finding.description,
        "severity": best_severity.value if best_severity else None,
        "fixed_version": all_fixed_versions[0] if all_fixed_versions else base_finding.fixed_version,
        "file_path": all_file_paths[0] if all_file_paths else base_finding.file_path,
        "sources": sources,
        "source_count": len(sources),
    }

    return merged


@dataclass
class DedupAuditEntry:
    """One entry in the deduplication audit trail."""

    fingerprint: str
    package_name: str
    cve_id: str | None
    sources: list[str]
    action: str  # 'merged' or 'unique'
    severity: str | None
    decision_reason: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class DedupReport:
    """Summary report of a deduplication run."""

    total_raw_findings: int
    unique_findings: int
    merged_findings: int
    findings_by_source: dict[str, int] = field(default_factory=dict)
    merged_findings_detail: list[DedupAuditEntry] = field(default_factory=list)
    unique_findings_detail: list[DedupAuditEntry] = field(default_factory=list)

    @property
    def dedup_ratio(self) -> float:
        """Ratio of raw findings reduced through dedup."""
        if self.total_raw_findings == 0:
            return 0.0
        return (self.total_raw_findings - self.unique_findings) / self.total_raw_findings

    def summary(self) -> dict:
        """Human-readable summary dict."""
        return {
            "total_raw_findings": self.total_raw_findings,
            "unique_findings_after_dedup": self.unique_findings,
            "merged_duplicates": self.merged_findings,
            "dedup_ratio": round(self.dedup_ratio, 2),
            "findings_by_source": dict(self.findings_by_source),
        }


def deduplicate_findings(
    findings: list[tuple[ScannerFinding, str]],  # (finding, source_name)
) -> list[dict]:
    """Deduplicate findings from multiple scanner runs.

    Args:
        findings: List of (ScannerFinding, source_name) tuples.
                  source_name should be 'trivy' or 'grype'.

    Returns:
        List of deduplicated finding dicts ready for persistence.
        Each dict includes a 'sources' field listing all scanners that
        reported this finding.
    """
    grouped: dict[str, list[tuple[ScannerFinding, str]]] = defaultdict(list)

    for finding, source_name in findings:
        fp = finding.make_fingerprint()
        grouped[fp].append((finding, source_name))

    deduplicated = []
    for fingerprint, group in grouped.items():
        merged = _build_merged_finding(fingerprint, group)
        deduplicated.append(merged)

    # Sort by severity (critical first)
    deduplicated.sort(
        key=lambda x: SEVERITY_RANK.get(
            getattr(Severity, x["severity"].upper(), "UNKNOWN")
            if x["severity"] else None, 0
        ),
        reverse=True,
    )

    return deduplicated


def deduplicate_findings_with_report(
    findings: list[tuple[ScannerFinding, str]],  # (finding, source_name)
) -> tuple[list[dict], DedupReport]:
    """Deduplicate findings and produce a full audit report.

    This is the same logic as deduplicate_findings but also returns
    a DedupReport with counts, audit trail, and per-source breakdowns.

    Args:
        findings: List of (ScannerFinding, source_name) tuples.

    Returns:
        Tuple of (deduplicated list, DedupReport).
    """
    grouped: dict[str, list[tuple[ScannerFinding, str]]] = defaultdict(list)

    for finding, source_name in findings:
        fp = finding.make_fingerprint()
        grouped[fp].append((finding, source_name))

    deduplicated = []
    merged_count = 0
    unique_count = 0
    source_counts: dict[str, int] = {}
    merged_audit: list[DedupAuditEntry] = []
    unique_audit: list[DedupAuditEntry] = []

    for fingerprint, group in grouped.items():
        merged = _build_merged_finding(fingerprint, group)
        deduplicated.append(merged)

        # Count per-source raw findings
        for _, source_name in group:
            source_counts[source_name] = source_counts.get(source_name, 0) + 1

        # Build audit entry
        finding_obj = group[0][0]
        severity_str = merged["severity"]

        if len(group) > 1:
            # This was a merged duplicate
            merged_count += 1
            sources_in_group = sorted(set(src for _, src in group))
            reasons = []
            for f, src in group:
                field_count = _count_metadata_fields(f)
                reasons.append(f"{src}: {field_count} fields")
            decision = f"Merged {len(group)} findings from {', '.join(sources_in_group)}. Details: {'; '.join(reasons)}."

            merged_audit.append(DedupAuditEntry(
                fingerprint=fingerprint,
                package_name=merged["package_name"],
                cve_id=merged["cve_id"],
                sources=sources_in_group,
                action="merged",
                severity=severity_str,
                decision_reason=decision,
            ))
            logger.info("DEDUP merged: %s (CVE: %s) from %s",
                       merged["package_name"], merged["cve_id"] or "N/A",
                       ", ".join(sources_in_group))
        else:
            # Unique finding from a single scanner
            unique_count += 1
            source = group[0][1]
            decision = f"Unique finding from {source}. No duplicate detected."

            unique_audit.append(DedupAuditEntry(
                fingerprint=fingerprint,
                package_name=merged["package_name"],
                cve_id=merged["cve_id"],
                sources=[source],
                action="unique",
                severity=severity_str,
                decision_reason=decision,
            ))

    # Sort deduplicated list
    deduplicated.sort(
        key=lambda x: SEVERITY_RANK.get(
            getattr(Severity, x["severity"].upper(), "UNKNOWN")
            if x["severity"] else None, 0
        ),
        reverse=True,
    )

    report = DedupReport(
        total_raw_findings=len(findings),
        unique_findings=len(deduplicated),
        merged_findings=merged_count,
        findings_by_source=source_counts,
        merged_findings_detail=merged_audit,
        unique_findings_detail=unique_audit,
    )

    logger.info(
        "DEDUP report: %d raw -> %d unique (%d merged, %d unique). Sources: %s",
        report.total_raw_findings,
        report.unique_findings,
        report.merged_findings,
        unique_count,
        source_counts,
    )

    return deduplicated, report
