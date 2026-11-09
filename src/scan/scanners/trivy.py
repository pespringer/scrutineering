"""Async CLI wrapper for Trivy container image vulnerability scanning.

Provides an async interface to the `trivy image` command with:
- JSON output parsing and normalization
- CVSS score extraction from NVD, Red Hat, Debian vendors
- Configurable severity filtering
- Timeout handling and graceful error recovery
- Support for private registries via registry credentials
"""

import asyncio
import json
import logging
from typing import Optional

from .base import ScannerAdapter, ScannerFinding, ScannerError
from src.scan.models import FindingSource, Severity

logger = logging.getLogger(__name__)

# Map Trivy severity strings to our canonical enum
SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "UNKNOWN": Severity.UNKNOWN,
}


class TrivyScanner(ScannerAdapter):
    """Adapter for Aqua Trivy container image scanning.

    Args:
        severity: Comma-separated severity levels to include (default: all)
        timeout: Max seconds to allow the scan to run (default: 600)
        cache_dir: Directory for Trivy's vulnerability cache
        registry_server: Optional private registry URL for authentication
        registry_username: Optional username for registry auth
        registry_password: Optional password/token for registry auth
    """

    @property
    def source(self) -> FindingSource:
        return FindingSource.TRIVY

    def __init__(
        self,
        severities: str = "CRITICAL,HIGH,MEDIUM,LOW,UNKNOWN",
        timeout: int = 600,
        trivy_cmd: str = "trivy",
        cache_dir: str = "/tmp/trivy-cache",
        registry_server: Optional[str] = None,
        registry_username: Optional[str] = None,
        registry_password: Optional[str] = None,
    ):
        if timeout < 1: raise ValueError("timeout must be positive")
        self.severities = ",".join(part.strip().upper() for part in severities.split(",") if part.strip())
        self.timeout = timeout
        self.trivy_cmd = trivy_cmd
        self.cache_dir = cache_dir
        self.registry_server = registry_server
        self.registry_username = registry_username
        self.registry_password = registry_password

    async def scan(self, image_name: str) -> list[ScannerFinding]:
        """Run Trivy scan on a container image.

        Args:
            image_name: Container image reference (e.g., 'nginx:1.25')

        Returns:
            List of normalized ScannerFinding objects with CVSS scores.

        Raises:
            ScannerError: If Trivy fails to run or produces malformed output.
        """
        # Build command
        cmd = [
            self.trivy_cmd,
            "image",
            "--format", "json",
            "--scanners", "vuln",
            "--severity", self.severities,
            "--cache-dir", self.cache_dir,
            image_name,
        ]

        # Add registry auth if provided
        if self.registry_server and self.registry_username and self.registry_password:
            cmd.insert(1, "--secret")  # placeholder — real auth via TRIVY_* env vars

        env = None
        # Set Trivy env vars for private registry auth
        if self.registry_server and self.registry_username and self.registry_password:
            env = {**__import__("os").environ}
            env["TRIVY_USERNAME"] = self.registry_username
            env["TRIVY_PASSWORD"] = self.registry_password

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )
        except FileNotFoundError:
            raise ScannerError(
                "trivy", f"Trivy binary not found at '{self.trivy_cmd}'", ""
            )

        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=self.timeout
            )
        except asyncio.TimeoutError:
            proc.kill()
            raise ScannerError(
                "trivy", f"Scan timed out after {self.timeout}s", ""
            )

        if proc.returncode not in (0, 1):
            # Trivy returns 1 when findings exist (not an error for us)
            stderr_text = stderr.decode(errors="replace").strip()
            raise ScannerError(
                "trivy",
                f"Exit code {proc.returncode}: {stderr_text[:500]}",
                stderr_text,
            )

        return self._parse_trivy_output(stdout.decode(errors="replace"))

    def _parse_trivy_output(self, raw_json: str) -> list[ScannerFinding]:
        """Parse Trivy JSON output into normalized ScannerFinding list.

        Trivy output structure:
        {
            "Results": [
                {
                    "Target": "alpine:3.14",
                    "Type": "pip",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2021-1234",
                            "Severity": "HIGH",
                            "Title": "...",
                            "Description": "...",
                            "PkgName": "openssl",
                            "InstalledVersion": "1.1.1",
                            "FixedVersion": "1.1.2",
                            "CVSS": {
                                "nvd": {"V3Score": 9.8, "V3Vector": "CVSS:3.1/..."},
                                "redhat": {"V3Score": 8.6, "V3Vector": "..."}
                            }
                        }
                    ]
                }
            ]
        }
        """
        try:
            data = json.loads(raw_json)
        except json.JSONDecodeError as e:
            raise ScannerError(
                "trivy", f"Failed to parse JSON output: {e}", raw_json[:500]
            )

        findings = []
        results = data.get("Results", [])

        for result in results:
            vulns = result.get("Vulnerabilities", [])
            result_type = result.get("Type", "")

            for vuln in vulns:
                severity_str = vuln.get("Severity", "UNKNOWN").upper()
                severity = SEVERITY_MAP.get(severity_str, Severity.UNKNOWN)

                # Extract CVSS scores from multiple vendors
                cvss = self._extract_cvss(vuln.get("CVSS", {}))

                finding = ScannerFinding(
                    package_name=vuln.get("PkgName", ""),
                    package_version=vuln.get("InstalledVersion"),
                    package_type=result_type,
                    cve_id=vuln.get("VulnerabilityID"),
                    title=vuln.get("Title", "") or self._default_title(vuln),
                    description=vuln.get("Description"),
                    severity=severity,
                    fixed_version=vuln.get("FixedVersion"),
                    cvss_scores=cvss["scores"],
                    cvss_vector=cvss.get("vector"),
                )
                findings.append(finding)

        return findings

    @staticmethod
    def _extract_cvss(cvss_data: dict) -> dict:
        """Extract CVSS scores from multiple vendor sections.

        Returns dict with:
            scores: dict of vendor -> score (float)
            vector: highest severity CVSS v3 vector string
            max_score: highest CVSS v3 score across all vendors
        """
        scores = {}
        vector = None
        max_score = 0.0

        vendor_order = ["nvd", "redhat", "debian", "ubuntu", "alpine",
                        "ghsa", "osv", "amazon", "oracle"]

        for vendor in vendor_order:
            vendor_data = cvss_data.get(vendor, {})
            if not vendor_data:
                continue

            score = vendor_data.get("V3Score") or vendor_data.get("V31Score")
            if score is not None:
                scores[vendor] = float(score)
                if float(score) > max_score:
                    max_score = float(score)
                    vector = vendor_data.get("V3Vector", "") or vendor_data.get("V31Vector", "")

        return {"scores": scores, "vector": vector or "", "max_score": max_score}

    @staticmethod
    def _default_title(vuln: dict) -> str:
        """Generate a fallback title if none exists."""
        cve = vuln.get("VulnerabilityID", "UNKNOWN")
        pkg = vuln.get("PkgName", "unknown")
        return f"Vulnerability {cve} in {pkg}"

    async def version(self) -> str:
        """Get Trivy version string."""
        try:
            proc = await asyncio.create_subprocess_exec(
                self.trivy_cmd,
                "version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            return stdout.decode().strip()
        except (FileNotFoundError, Exception):
            return "unknown"
