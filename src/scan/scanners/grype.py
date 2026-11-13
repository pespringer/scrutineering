"""Grype scanner adapter for container image scanning."""

import asyncio
import json
import logging
from typing import Optional

from .base import ScannerAdapter, ScannerFinding, ScannerError
from src.scan.models import FindingSource, Severity

logger = logging.getLogger(__name__)

SEVERITY_MAP = {
    "Critical": Severity.CRITICAL,
    "High": Severity.HIGH,
    "Medium": Severity.MEDIUM,
    "Low": Severity.LOW,
    "Negligible": Severity.UNKNOWN,
    "Unknown": Severity.UNKNOWN,
}


class GrypeScanner(ScannerAdapter):
    """Adapter for Anchorage Grype container image scanning."""

    @property
    def source(self) -> FindingSource:
        return FindingSource.GRYPE

    def __init__(self, timeout: int = 600, grype_cmd: str = "grype", max_output_bytes: int = 50_000_000):
        if timeout < 1: raise ValueError("timeout must be positive")
        if max_output_bytes < 1: raise ValueError("max_output_bytes must be positive")
        self.timeout = timeout
        self.grype_cmd = grype_cmd
        self.max_output_bytes = max_output_bytes

    async def scan(self, image_name: str) -> list[ScannerFinding]:
        """Run Grype scan on a container image.

        Args:
            image_name: Container image reference (e.g., 'nginx:1.25')

        Returns:
            List of normalized ScannerFinding objects.

        Raises:
            ScannerError: If Grype fails to run or produces malformed output.
        """
        result = await asyncio.create_subprocess_exec(
            self.grype_cmd,
            "-o", "json",
            "-q",
            image_name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout, stderr = await asyncio.wait_for(
                result.communicate(), timeout=self.timeout
            )
        except asyncio.TimeoutError:
            result.kill()
            raise ScannerError(
                "grype", f"Scan timed out after {self.timeout}s", ""
            )

        if result.returncode != 0:
            stderr_text = stderr.decode(errors="replace").strip()
            raise ScannerError(
                "grype",
                f"Exit code {result.returncode}: {stderr_text[:500]}",
                stderr_text,
            )

        if len(stdout) > self.max_output_bytes: raise ScannerError("grype", "scan output exceeds size limit")
        return self._parse_grype_output(stdout.decode(errors="replace"))

    def _parse_grype_output(self, raw_json: str) -> list[ScannerFinding]:
        """Parse Grype JSON output into normalized findings."""
        try:
            data = json.loads(raw_json)
        except json.JSONDecodeError as e:
            raise ScannerError(
                "grype", f"Failed to parse JSON output: {e}", raw_json[:500]
            )

        findings = []
        matches = data.get("matches", [])

        for match in matches:
            vuln = match.get("vulnerability", {})
            artifact = match.get("artifact", {})

            severity_str = vuln.get("severity", "")
            severity = SEVERITY_MAP.get(severity_str, Severity.UNKNOWN)

            # Fix info
            fix_info = vuln.get("fix", {})
            fixed_version = fix_info.get("versions", [None])[0] if fix_info.get("versions") else None
            locations = artifact.get("locations") or []
            file_path = next((location.get("path") for location in locations if location.get("path")), None)

            finding = ScannerFinding(
                package_name=artifact.get("name", ""),
                package_version=artifact.get("version"),
                package_type=artifact.get("type"),
                cve_id=vuln.get("id"),
                title=vuln.get("description", "") or self._default_title(vuln, artifact),
                description=vuln.get("description"),
                severity=severity,
                fixed_version=fixed_version,
                file_path=file_path,
            )
            findings.append(finding)

        return findings

    def _default_title(self, vuln: dict, artifact: dict) -> str:
        """Generate a fallback title if none exists."""
        cve = vuln.get("id", "UNKNOWN")
        pkg = artifact.get("name", "unknown")
        return f"Vulnerability {cve} in {pkg}"

    async def version(self) -> str:
        """Get Grype version string."""
        try:
            proc = await asyncio.create_subprocess_exec(
                self.grype_cmd,
                "version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            return stdout.decode().strip()
        except (FileNotFoundError, Exception):
            return "unknown"
