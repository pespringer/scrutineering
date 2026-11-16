"""Grype scanner adapter for container image scanning."""

import asyncio
import json
import logging
import os
from typing import Optional

from .base import ScannerAdapter, ScannerFinding, ScannerError
from src.scan.models import FindingSource, Severity
from src.scan.source_target import filesystem_path, relative_source_path

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

    def __init__(
        self,
        timeout: int = 600,
        grype_cmd: str = "grype",
        max_output_bytes: int = 50_000_000,
        max_findings: int = 100_000,
        registry_username: Optional[str] = None,
        registry_password: Optional[str] = None,
        registry_authority: Optional[str] = None,
        insecure: bool = False,
        local_registry_host: str = "registry:5000",
    ):
        if timeout < 1: raise ValueError("timeout must be positive")
        if max_output_bytes < 1: raise ValueError("max_output_bytes must be positive")
        if max_findings < 1: raise ValueError("max_findings must be positive")
        self.timeout = timeout
        self.grype_cmd = grype_cmd
        self.max_output_bytes = max_output_bytes
        self.max_findings = max_findings
        self.registry_username = registry_username
        self.registry_password = registry_password
        self.registry_authority = registry_authority
        self.insecure = insecure
        self.local_registry_host = local_registry_host

    async def scan(self, image_name: str) -> list[ScannerFinding]:
        """Run Grype scan on a container image.

        Args:
            image_name: Container image reference (e.g., 'nginx:1.25')

        Returns:
            List of normalized ScannerFinding objects.

        Raises:
            ScannerError: If Grype fails to run or produces malformed output.
        """
        root = filesystem_path(image_name)
        scan_target = self._registry_scan_target(image_name) if root is None else f"dir:{root}"
        command = [self.grype_cmd,
            "-o", "json",
            "-q",
            scan_target,
        ]
        result = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=self._environment() if root is None else None,
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
        findings = self._parse_grype_output(stdout.decode(errors="replace"), root_path=root)
        if len(findings) > self.max_findings:
            raise ScannerError("grype", "scan finding count exceeds limit")
        return findings

    def _environment(self) -> dict[str, str]:
        """Per-scan registry auth and transport settings, using Grype's own variables.

        Inherited GRYPE_REGISTRY_* settings are dropped so a global `.env` value
        cannot make every registry use plain HTTP; only this scan's settings apply.
        """
        base = {key: value for key, value in os.environ.items() if not key.startswith("GRYPE_REGISTRY_")}
        extra: dict[str, str] = {}
        if self.registry_username and self.registry_password:
            extra.update({
                "GRYPE_REGISTRY_AUTH_AUTHORITY": self.registry_authority or "",
                "GRYPE_REGISTRY_AUTH_USERNAME": self.registry_username,
                "GRYPE_REGISTRY_AUTH_PASSWORD": self.registry_password,
            })
        if self.insecure:
            extra.update({"GRYPE_REGISTRY_INSECURE_USE_HTTP": "true", "GRYPE_REGISTRY_INSECURE_SKIP_TLS_VERIFY": "true"})
        return {**base, **extra}

    def _registry_scan_target(self, image_name: str) -> str:
        """Read local-registry images straight from the registry (there is no Docker daemon)."""
        if self.local_registry_host and image_name.startswith(f"{self.local_registry_host}/"):
            return f"registry:{image_name}"
        return image_name

    def _parse_grype_output(self, raw_json: str, root_path=None) -> list[ScannerFinding]:
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
            raw_path = next((location.get("path") for location in locations if location.get("path")), None)
            file_path = relative_source_path(raw_path, root_path) if root_path else None

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
