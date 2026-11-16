"""Scan an image without recording it: used to verify a remediation's candidate image.

Runs the same scanners, settings and deduplication as a recorded scan, but saves
nothing, so candidate images never appear in the inventory.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from src.scan.settings import ScannerSettings

# Bound as a module: tasks imports the remediation worker, which imports this module.
import src.scan.tasks as tasks
from src.scan.utils.db import make_vuln_key
from src.scan.utils.dedup import deduplicate_findings_with_report

DEFAULT_SCANNERS = ("trivy", "grype")


@dataclass
class InspectionResult:
    complete: bool
    scanned_reference: str
    findings: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def vuln_keys(self) -> set[str]:
        return {make_vuln_key(item.get("cve_id") or "", item["package_name"]) for item in self.findings}


def inspect_image(image_name: str, scanners: tuple[str, ...] = DEFAULT_SCANNERS) -> InspectionResult:
    """Scan `image_name` with every scanner. `complete` is false if any scanner failed."""
    settings = ScannerSettings.from_env()
    resolved = tasks._resolve_scan_target(image_name, settings)
    results = tasks.run_scanners_concurrently(
        list(scanners),
        resolved["target"],
        cache=tasks.create_shared_scan_cache(),
        settings=settings,
        credentials=resolved["credentials"],
        registry_host=resolved["host"],
        insecure=resolved["insecure"],
    )
    findings, errors = [], []
    for name, outcome, data in results:
        if outcome == "ok":
            findings.extend(data)
        else:
            errors.append(f"{name}: {data}")
    deduped = deduplicate_findings_with_report(findings)[0] if findings else []
    return InspectionResult(complete=not errors, scanned_reference=resolved["target"], findings=deduped, errors=errors)
