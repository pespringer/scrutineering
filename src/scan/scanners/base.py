"""Scanner base class defining the adapter interface."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional

from src.scan.models import FindingSource, Severity


@dataclass
class ScannerFinding:
    """Normalized finding from any scanner."""

    package_name: str
    package_version: Optional[str]
    package_type: Optional[str]
    cve_id: Optional[str]
    title: str
    description: Optional[str]
    severity: Optional[Severity]
    fixed_version: Optional[str]
    cvss_scores: Optional[dict] = None  # {"nvd": 9.8, "redhat": 8.6}
    cvss_vector: Optional[str] = None  # "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    file_path: Optional[str] = None

    def make_fingerprint(self) -> str:
        """Create a dedup-friendly fingerprint."""
        import hashlib

        key = f"{self.cve_id or ''}|{self.package_name}|{self.package_version or ''}"
        return hashlib.sha256(key.encode()).hexdigest()[:64]


class ScannerAdapter(ABC):
    """Base class for scanner adapters (Trivy, Grype, etc.)."""

    @property
    @abstractmethod
    def source(self) -> FindingSource:
        """Return the FindingSource enum value for this scanner."""

    @abstractmethod
    async def scan(self, image_name: str) -> list[ScannerFinding]:
        """Run a scan against the given container image.

        Returns a list of normalized ScannerFinding objects.
        Scanner failures must be handled by raising a ScannerError.
        """


MAX_ERROR = 500


def error_line(stderr: str, markers: tuple[str, ...]) -> str:
    """The part of a failed scanner's stderr that names the cause (docs/design/scan-errors.md).

    Scanners log progress and warnings before the error, so the first line is rarely it. Returns
    the text after the first marker found, trying the markers in order, or else the last non-empty
    line, cut to `MAX_ERROR` characters.
    """
    lines = [line.strip() for line in stderr.splitlines() if line.strip()]
    for marker in markers:
        for line in lines:
            if marker in line:
                return line.split(marker, 1)[1].strip()[:MAX_ERROR]
    return lines[-1][:MAX_ERROR] if lines else "no error output"


class ScannerError(Exception):
    """Raised when a scanner fails (non-zero exit, timeout, malformed output)."""

    def __init__(self, scanner: str, message: str, output: str = ""):
        self.scanner = scanner
        self.output = output
        super().__init__(f"[{scanner}] {message}")
