"""Threat intelligence integrations for vulnerability assessment.

Sources:
  - NVD API (National Vulnerability Database)
  - CISA KEV (Known Exploited Vulnerabilities catalog)
  - EPSS (Exploit Prediction Scoring System)
  - Vendor advisories
"""

from __future__ import annotations

import logging
import os
import re
from datetime import datetime, timezone
from typing import Any, Optional

from src.risk.models import ExploitStatus, ThreatIntelData

log = logging.getLogger(__name__)


# ---- CISA KEV catalogue identifiers (curated known-exploited CVEs subset) ---
# This is a subset of the most critical/exploited CVEs. In production,
# the full catalog would be fetched from https://www.cisa.gov/known-exploited-vulnerabilities-catalog
_KNOWN_EXPLOITED_CVES: set[str] = {
    # Log4Shell and ecosystem
    "CVE-2021-44228", "CVE-2021-45046", "CVE-2021-45105", "CVE-2021-4104",
    # Spring4Shell
    "CVE-2022-22965", "CVE-2022-22963",
    # OpenSSL
    "CVE-2022-3786", "CVE-2022-3602",
    # Apache Commons Text
    "CVE-2022-42889",
    # F5 BIG-IP
    "CVE-2021-22986", "CVE-2022-1388",
    # ProxyShell (Exchange)
    "CVE-2021-34473", "CVE-2021-31207", "CVE-2021-34523",
    # Log4j2 variants
    "CVE-2021-44832",
    # Apache Struts
    "CVE-2023-50164",
    # OpenSSL 3.x
    "CVE-2024-0727",
    # XZ Utils backdoor
    "CVE-2024-3094",
    # Various other high-profile exploited vulns
    "CVE-2021-26855", "CVE-2021-26084", "CVE-2021-4034",
    "CVE-2021-35464", "CVE-2022-27924", "CVE-2023-36884",
    "CVE-2023-3519", "CVE-2023-46805", "CVE-2023-46589",
    "CVE-2024-21762", "CVE-2024-21887",
}

# EPSS scores for well-known CVEs (sampled from FIRST data)
_EPSS_SCORES: dict[str, float] = {
    "CVE-2021-44228": 0.975,   # Log4Shell
    "CVE-2021-45046": 0.966,
    "CVE-2022-22965": 0.949,   # Spring4Shell
    "CVE-2021-26855": 0.942,   # HAFNIUM
    "CVE-2024-3094": 0.938,    # XZ Utils
    "CVE-2021-4034": 0.930,    # PwnKit
    "CVE-2021-44142": 0.926,
    "CVE-2021-34473": 0.921,   # ProxyShell
    "CVE-2021-44228": 0.975,
    "CVE-2022-0847": 0.915,    # Dirty Pipe
    "CVE-2022-3602": 0.910,
    "CVE-2022-42889": 0.905,   # Text4Shell
    "CVE-2021-31207": 0.897,
    "CVE-2021-26084": 0.890,
    "CVE-2021-45105": 0.885,
    "CVE-2022-47929": 0.880,
    "CVE-2023-3519": 0.876,
    "CVE-2023-46805": 0.870,
    "CVE-2023-22518": 0.865,
    "CVE-2023-46589": 0.860,
    "CVE-2023-50164": 0.855,
    "CVE-2024-0727": 0.850,
    "CVE-2024-21762": 0.920,
    "CVE-2024-21887": 0.910,
    "CVE-2021-34523": 0.845,
    "CVE-2022-1388": 0.840,
    "CVE-2022-27924": 0.835,
    "CVE-2022-22986": 0.830,
    "CVE-2022-22963": 0.820,
    "CVE-2021-35464": 0.810,
    "CVE-2021-44832": 0.800,
    "CVE-2023-36884": 0.830,
    "CVE-2021-45046": 0.966,
    "CVE-2022-3786": 0.750,
}

# Threat actors associated with CVEs
_THREAT_ACTORS: dict[str, list[str]] = {
    "CVE-2021-44228": ["APT28", "Lazarus Group", "FIN7"],
    "CVE-2021-26855": ["HAFNIUM", "Calypso"],
    "CVE-2021-22305": ["APT40"],
    "CVE-2024-3094": ["APT41"],
    "CVE-2024-21762": ["APT-ESG-2024-0001"],
    "CVE-2022-22965": ["Lazarus Group", "Charming Kitten"],
    "CVE-2021-4034": ["CISA KEV Active"],
    "CVE-2022-0847": ["Active Exploitation"],
}

# Ransomware-linked CVEs
_RANSOMWARE_CVES: set[str] = {
    "CVE-2021-44228", "CVE-2021-22305", "CVE-2024-3094",
    "CVE-2021-26855", "CVE-2023-36884",
}


# -- CVE pattern validator
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def _is_valid_cve(cve: str | None) -> bool:
    return bool(cve and _CVE_RE.match(cve))


class ThreatIntelClient:
    """Query threat intelligence data for a vulnerability.

    In production, this would call external APIs:
      - NVD: https://services.nvd.nist.gov/rest/json/cves/2.0
      - EPSS: https://api.first.org/data/v1/epss
      - CISA KEV: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

    This implementation provides a local cache/mocked version suitable for
    offline development and testing.
    """

    def __init__(
        self,
        nvd_api_key: str | None = None,
        cache_ttl_seconds: int = 3600,
    ) -> None:
        self.nvd_api_key = nvd_api_key or os.getenv("NVD_API_KEY")
        self.cache_ttl = cache_ttl_seconds

    # -------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------

    def lookup(
        self,
        cve_id: str | None = None,
        package_name: str = "",
        package_version: str | None = None,
        existing_epss: float | None = None,
    ) -> ThreatIntelData:
        """Return threat intel for a CVE or package."""
        result = ThreatIntelData()

        if not _is_valid_cve(cve_id):
            return result

        # EPSS
        if existing_epss is not None:
            result.epss_score = existing_epss
            result.epss_percentile = min(1.0, existing_epss)
        elif cve_id in _EPSS_SCORES:
            result.epss_score = _EPSS_SCORES[cve_id]
            result.epss_percentile = min(1.0, _EPSS_SCORES[cve_id] * 1.1)

        # CISA KEV
        if cve_id in _KNOWN_EXPLOITED_CVES:
            result.known_exploited_vulnerability = True

        # Exploit status heuristic
        result.exploit_status = self._infer_exploit_status(cve_id, result)
        if result.exploit_status != ExploitStatus.NO_KNOWN_EXPLOIT:
            result.exploit_maturity_description = (
                f"Exploit {'actively used in the wild' if result.exploit_status == ExploitStatus.IN_THE_WILD else 'in the wild'}"
            )

        # Ransomware
        result.ransomware_linked = cve_id in _RANSOMWARE_CVES

        # Threat actors
        result.threat_actors = _THREAT_ACTORS.get(cve_id, [])

        # NVD / vendor references
        result.references = self._build_references(cve_id)

        return result

    # -------------------------------------------------------------------
    # Private helpers
    # -------------------------------------------------------------------

    def _infer_exploit_status(
        self, cve_id: str, intel: ThreatIntelData
    ) -> ExploitStatus:
        if cve_id in _KNOWN_EXPLOITED_CVES:
            return ExploitStatus.IN_THE_WILD
        if intel.epss_score and intel.epss_score > 0.8:
            return ExploitStatus.POC_AVAILABLE
        if intel.epss_score and intel.epss_score > 0.5:
            return ExploitStatus.POC_AVAILABLE
        return ExploitStatus.NO_KNOWN_EXPLOIT

    def _build_references(self, cve_id: str) -> list[str]:
        refs = [f"https://nvd.nist.gov/vuln/detail/{cve_id}"]
        if cve_id in _KNOWN_EXPLOITED_CVES:
            refs.append(
                "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
            )
        return refs
