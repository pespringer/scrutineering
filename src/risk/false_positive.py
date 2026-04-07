"""Automated false positive detection and filtering.

Uses heuristics to identify likely false positives:
  - Package in /usr/src (build-time dependencies)
  - Dev/test-only packages in production containers
  - Vulnerabilities in non-running components
  - Already-mitigated vulnerabilities
  - Vendor "will not fix" advisories
"""

from __future__ import annotations

import logging
import re
from typing import Any

from src.risk.models import FalsePositiveAssessment

log = logging.getLogger(__name__)


# Packages commonly flagged as vulnerable but are build-time only
# or otherwise irrelevant for runtime assessment
_BUILD_TIME_PACKAGES: set[str] = {
    "build-essential", "gcc", "g++", "make", "cmake",
    "autoconf", "automake", "libtool", "pkg-config",
    "python3-dev", "python-dev", "nodejs-dev",
    "linux-headers", "kernel-devel", "dkms",
    "ruby-dev", "perl-dev", "libssl-dev",
    # Test frameworks
    "pytest", "unittest", "mock", "faker", "testfixtures",
    "mocha", "jest", "chai", "sinon", "supertest",
    # Build tools in final images
    "maven", "gradle", "npm", "yarn", "pip",
    "cargo", "go", "rustc", "cabal",
}

# Packages that are documentation/examples only
_DOC_PACKAGES: set[str] = {
    "manpages", "man-db", "texinfo", "info",
    "doc-base", "debian-reference",
}

# Known vendor "will not fix" or "not affected" patterns
_WONT_FIX_KEYWORDS = [
    "wontfix", "will not fix", "not affected",
    "not vulnerable", "upstream rejected", "obsolete",
    "end of life", "eol", "legacy",
]

# Paths that indicate non-runtime code
_NON_RUNTIME_PATHS = [
    "/usr/src/", "/tmp/", "/var/cache/",
    "/root/.cache/", "/home/", "/opt/build/",
    "/node_modules/.cache/",
]

# OS-level packages that shouldn't trigger on container images
_OS_KERNEL_PACKAGES: set[str] = {
    "linux-image", "linux-headers", "kernel",
}


class FalsePositiveDetector:
    """Detects likely false positives in vulnerability assessments."""

    def assess(
        self,
        package_name: str = "",
        package_version: str | None = None,
        description: str = "",
        title: str = "",
        fixed_version: str | None = None,
        affected_paths: list[str] | None = None,
        is_build_stage: bool = False,
    ) -> FalsePositiveAssessment:
        """Assess whether a finding is likely a false positive."""
        reasons: list[str] = []
        confidence: float = 0.0
        pkg_lower = (package_name or "").lower()
        desc_lower = (description or "").lower()
        title_lower = (title or "").lower()

        # Check 1: Build-time/dev dependency
        if pkg_lower in _BUILD_TIME_PACKAGES:
            reasons.append(
                f"Package '{package_name}' appears to be a build-time or dev dependency"
            )
            confidence += 0.4

        # Check 2: Documentation package
        if pkg_lower in _DOC_PACKAGES:
            reasons.append(
                f"Package '{package_name}' is documentation-only"
            )
            confidence += 0.3

        # Check 3: Non-runtime paths
        if affected_paths:
            non_runtime = [p for p in affected_paths
                           if any(np in p for np in _NON_RUNTIME_PATHS)]
            if non_runtime:
                reasons.append(
                    f"Vulnerability found in non-runtime path(s): {', '.join(non_runtime[:3])}"
                )
                confidence += 0.3

        # Check 4: Build stage
        if is_build_stage:
            reasons.append("Vulnerability found in build stage only (not in final image)")
            confidence += 0.5

        # Check 5: Vendor won't-fix
        combined = " ".join([desc_lower, title_lower])
        wont_fix = [kw for kw in _WONT_FIX_KEYWORDS if kw in combined]
        if wont_fix:
            reasons.append(f"Vendor indicates '{wont_fix[0]}'")
            confidence += 0.2

        # Check 6: Already fixed in current version
        if fixed_version and package_version:
            if self._version_gte(package_version, fixed_version):
                reasons.append(
                    f"Package version {package_version} >= fixed version {fixed_version}"
                )
                confidence += 0.6

        # Check 7: OS kernel package in container
        if pkg_lower in _OS_KERNEL_PACKAGES and not self._is_host_scanner():
            reasons.append(
                f"OS kernel package '{package_name}' in container (kernel is provided by host)"
            )
            confidence += 0.35

        # Check 8: Description suggests non-applicability
        if any(phrase in desc_lower for phrase in [
            "only affects windows", "windows only",
            "not applicable to linux", "not used in this build",
            "configuration not present",
        ]):
            reasons.append("Description indicates platform/build mismatch")
            confidence += 0.45

        if not reasons:
            return FalsePositiveAssessment(
                is_false_positive=False,
                confidence=0.0,
                reasons=["No false positive indicators detected"],
            )

        confidence = min(0.95, confidence)
        return FalsePositiveAssessment(
            is_false_positive=confidence >= 0.7,
            confidence=confidence,
            reasons=reasons,
        )

    # -------------------------------------------------------------------
    # Private helpers
    # -------------------------------------------------------------------

    def _version_gte(self, current: str, fixed: str) -> bool:
        """Simple version comparison (handles semver-style)."""
        def _parts(v: str) -> list[int]:
            return [int(x) for x in re.split(r"[.\-+]", v) if x.isdigit()]
        try:
            return _parts(current) >= _parts(fixed)
        except (ValueError, TypeError):
            return False

    def _is_host_scanner(self) -> bool:
        """Check if we're scanning the host rather than a container.

        Default assumes container context; return False.
        """
        return False
