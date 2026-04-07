"""MITRE ATT&CK framework mapping.

Maps CVEs to ATT&CK techniques based on:
  - NVD CPE/cwe-to-technique correlations
  - Known exploit behavior patterns
  - Package type heuristics

Reference: https://attack.mitre.org/
"""

from __future__ import annotations

import logging
import re
from typing import Optional

from src.risk.models import MitreTactic, MitreMapping

log = logging.getLogger(__name__)


# -- MITRE ATT&CK technique database (subset of the most relevant) ----
_TECHNIQUES: dict[str, dict] = {
    # T1190 - Exploit Public-Facing Application
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": MitreTactic.INITIAL_ACCESS,
        "keywords": ["rce", "remote code execution", "deserialization",
                      "inject", "sql injection", "xss", "xxe",
                      "struts", "log4j", "spring", "proxyshell",
                      "exchange", "big-ip"],
    },
    # T1199 - Trusted Relationship
    "T1199": {
        "name": "Trusted Relationship",
        "tactic": MitreTactic.INITIAL_ACCESS,
        "keywords": ["supply chain", "compromised key", "trusted"],
    },
    # T1059 - Command and Scripting Interpreter
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": MitreTactic.EXECUTION,
        "keywords": ["command injection", "os command", "shell",
                      "bash", "powershell", "python code execution"],
    },
    # T1059.001 - PowerShell
    "T1059.001": {
        "name": "PowerShell",
        "tactic": MitreTactic.EXECUTION,
        "keywords": ["powershell execution"],
    },
    # T1068 - Exploitation for Privilege Escalation
    "T1068": {
        "name": "Exploitation for Privilege Escalation",
        "tactic": MitreTactic.PRIVILEGE_ESCALATION,
        "keywords": ["privilege escalation", "privesc", "escalat",
                      "pwnkit", "dirty pipe", "sudo", "cve-2021-4034",
                      "cve-2022-0847", "kernel"],
    },
    # T1055 - Process Injection
    "T1055": {
        "name": "Process Injection",
        "tactic": MitreTactic.DEFENSE_EVASION,
        "keywords": ["process injection", "dll injection",
                      "shared library", "ld_preload"],
    },
    # T1574 - Hijack Execution Flow
    "T1574": {
        "name": "Hijack Execution Flow",
        "tactic": MitreTactic.PERSISTENCE,
        "keywords": ["hijack", "dll search order", "path hijack"],
    },
    # T1552 - Unsecured Credentials
    "T1552": {
        "name": "Unsecured Credentials",
        "tactic": MitreTactic.CREDENTIAL_ACCESS,
        "keywords": ["credentials", "password", "key leak", "hardcoded",
                      "secret", "token", "credential exposure"],
    },
    # T1556 - Modify Authentication Process
    "T1556": {
        "name": "Modify Authentication Process",
        "tactic": MitreTactic.CREDENTIAL_ACCESS,
        "keywords": ["authentication bypass", "auth bypass", "credential stuffing"],
    },
    # T1114 - Email Collection
    "T1114": {
        "name": "Email Collection",
        "tactic": MitreTactic.COLLECTION,
        "keywords": ["email collection", "mailbox"],
    },
    # T1567 - Exfiltration Over Web Service
    "T1567": {
        "name": "Exfiltration Over Web Service",
        "tactic": MitreTactic.EXFILTRATION,
        "keywords": ["exfil", "data exfiltration", "upload"],
    },
    # T1499 - Endpoint Denial of Service
    "T1499": {
        "name": "Endpoint Denial of Service",
        "tactic": MitreTactic.IMPACT,
        "keywords": ["denial of service", "dos", "ddos", "amplification",
                      "memory exhaustion", "cpu exhaustion"],
    },
    # T1498 - Network Denial of Service
    "T1498": {
        "name": "Network Denial of Service",
        "tactic": MitreTactic.IMPACT,
        "keywords": ["network flood", "syn flood", "network dos"],
    },
    # T1485 - Data Destruction
    "T1485": {
        "name": "Data Destruction",
        "tactic": MitreTactic.IMPACT,
        "keywords": ["data destruction", "ransomware", "encrypt", "wiper",
                      "overwrite"],
    },
    # T1046 - Network Service Discovery
    "T1046": {
        "name": "Network Service Discovery",
        "tactic": MitreTactic.DISCOVERY,
        "keywords": ["service discovery", "port scan", "enumeration"],
    },
    # T1021 - Remote Services
    "T1021": {
        "name": "Remote Services",
        "tactic": MitreTactic.LATERAL_MOVEMENT,
        "keywords": ["lateral movement", "smb", "rdp", "ssh",
                      "remote execution", "psexec"],
    },
    # T1562 - Impair Defenses
    "T1562": {
        "name": "Impair Defenses",
        "tactic": MitreTactic.DEFENSE_EVASION,
        "keywords": ["disable", "bypass", "evasion", "antivirus",
                      "security bypass", "sandbox"],
    },
    # T1074 - Data Staged
    "T1074": {
        "name": "Data Staged",
        "tactic": MitreTactic.COLLECTION,
        "keywords": ["data staging", "archive", "compress sensitive"],
    },
    # T1105 - Ingress Tool Transfer
    "T1105": {
        "name": "Ingress Tool Transfer",
        "tactic": MitreTactic.COMMAND_AND_CONTROL,
        "keywords": ["download", "curl", "wget", "tool transfer"],
    },
    # T1505 - Server Software Component
    "T1505": {
        "name": "Server Software Component",
        "tactic": MitreTactic.PERSISTENCE,
        "keywords": ["webshell", "server component", "reverse shell"],
    },
}

# Known direct CVE-to-technique mappings (curated subset)
_CVE_DIRECT_MAP: dict[str, list[str]] = {
    "CVE-2021-44228": ["T1190", "T1059"],  # Log4Shell
    "CVE-2021-45046": ["T1190", "T1059"],
    "CVE-2021-45105": ["T1190"],
    "CVE-2021-44832": ["T1190"],
    "CVE-2022-22965": ["T1190", "T1059"],  # Spring4Shell
    "CVE-2022-22963": ["T1190"],
    "CVE-2021-4034": ["T1068"],  # PwnKit
    "CVE-2022-0847": ["T1068"],  # Dirty Pipe
    "CVE-2021-26855": ["T1190", "T1055"],  # HAFNIUM
    "CVE-2021-34473": ["T1190"],  # ProxyShell
    "CVE-2024-3094": ["T1190", "T1556"],  # XZ Utils backdoor
    "CVE-2023-36884": ["T1505"],  # Microsoft Office RCE
    "CVE-2023-3519": ["T1562"],
    "CVE-2023-50164": ["T1190"],  # Apache Struts
    "CVE-2024-21762": ["T1190"],
    "CVE-2024-21887": ["T1190"],
    "CVE-2022-1388": ["T1190"],
    "CVE-2022-42889": ["T1190"],  # Text4Shell
    "CVE-2022-3786": ["T1562"],
    "CVE-2022-3602": ["T1562"],
}

# Package type to technique heuristics
_PACKAGE_TECHNIQUES: dict[str, list[str]] = {
    "openssl": ["T1552", "T1556"],
    "openssh": ["T1021", "T1055"],
    "sudo": ["T1068"],
    "kernel": ["T1068"],
    "busybox": ["T1059"],
    "curl": ["T1105"],
    "wget": ["T1105"],
    "log4j": ["T1190", "T1059"],
    "jackson": ["T1190"],
    "fastjson": ["T1190"],
    "struts": ["T1190"],
    "spring": ["T1190", "T1059"],
    "nginx": ["T1190"],
    "apache": ["T1190"],
    "tomcat": ["T1190", "T1505"],
    "docker": ["T1068", "T1562"],
    "bash": ["T1059"],
    "python": ["T1059"],
}


class MitreAttckMapper:
    """Maps vulnerabilities to MITRE ATT&CK framework techniques."""

    def map_cve(self, cve_id: str | None = None,
                description: str | None = None,
                package_name: str | None = None,
                title: str = "") -> list[MitreMapping]:
        """Return ATT&CK mappings for a vulnerability."""
        mappings: list[MitreMapping] = []

        # 1. Direct CVE mapping (highest confidence)
        cve_norm = (cve_id or "").upper()
        if cve_norm in _CVE_DIRECT_MAP:
            for tech_id in _CVE_DIRECT_MAP[cve_norm]:
                mappings.append(self._make_mapping(tech_id, cve_norm))

        # 2. Description keyword matching (medium confidence)
        text = " ".join(filter(None, [title, description or ""])).lower()
        if text:
            mappings.extend(self._match_keywords("CVE", text))

        # 3. Package type heuristics (lower confidence)
        if package_name:
            pkg_lower = package_name.lower()
            for pkg_key, tech_ids in _PACKAGE_TECHNIQUES.items():
                if pkg_key in pkg_lower:
                    for tech_id in tech_ids:
                        mappings.extend(
                            [m for m in [self._make_mapping(tech_id, pkg_key)]
                             if m not in mappings]
                        )

        # Deduplicate by technique_id
        seen: dict[str, MitreMapping] = {}
        for m in mappings:
            if m.technique_id not in seen:
                seen[m.technique_id] = m
        return list(seen.values())

    def map_technique(self, technique_id: str) -> Optional[MitreMapping]:
        return self._make_mapping(technique_id) if technique_id in _TECHNIQUES else None

    def all_tactics(self) -> list[MitreTactic]:
        """List all ATT&CK tactics covered by our technique database."""
        return list(MitreTactic)

    # -------------------------------------------------------------------
    # Private helpers
    # -------------------------------------------------------------------

    def _make_mapping(self, technique_id: str,
                      source: str = "") -> Optional[MitreMapping]:
        tech = _TECHNIQUES.get(technique_id)
        if not tech:
            return None
        return MitreMapping(
            tactic=tech["tactic"],
            technique_id=technique_id,
            technique_name=tech["name"],
            sub_technique_id=technique_id if "." in technique_id else None,
            description=f"From {source}" if source else None,
        )

    def _match_keywords(self, source: str, text: str) -> list[MitreMapping]:
        matches = []
        for tech_id, tech_data in _TECHNIQUES.items():
            for kw in tech_data["keywords"]:
                if kw in text:
                    m = self._make_mapping(tech_id, source)
                    if m:
                        matches.append(m)
                    break
        return matches
