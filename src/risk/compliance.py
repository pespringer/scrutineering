"""Compliance framework modules.

Checks whether a vulnerability violates specific controls in:
  - NIST Cybersecurity Framework (CSF)
  - PCI DSS v4.0
  - SOC 2 (CC series)
  - HIPAA Security Rule
  - GDPR (Articles 32-33)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional

from src.risk.models import (
    ComplianceFinding,
    ComplianceFramework,
    DataSensitivity,
    NetworkExposure,
    RiskLevel,
)
from src.risk.threat_intel import ThreatIntelClient, _is_valid_cve

log = logging.getLogger(__name__)


# -- Control definitions per framework --------------------------------------------
# Each entry: (control_id, control_name, trigger_description, recommended_action)

NIST_CSF_CONTROLS: list[tuple[str, str, str]] = [
    ("DE.CM-1", "Network Monitoring", "Vulnerability in network-facing component with public exposure"),
    ("DE.CM-3", "Personnel Monitoring", "Vulnerability in user-facing application with confidential data access"),
    ("PR.AC-4", "Access Control", "Vulnerability allows privilege escalation or authentication bypass"),
    ("PR.AC-5", "Network Integrity", "Vulnerability in network protocol or service"),
    ("PR.DS-1", "Data-at-rest Protection", "Vulnerability affecting data storage or encryption"),
    ("PR.DS-5", "Protections Against Data Leaks", "Vulnerability allows data exfiltration"),
    ("PR.IP-1", "Baseline Configuration", "Vulnerability in outdated/unpatched component"),
    ("RS.RP-1", "Response Plan", "Known exploited vulnerability requires immediate response"),
    ("ID.RA-1", "Asset Vulnerabilities", "Any known CVE in an asset should be tracked"),
]

PCI_DSS_CONTROLS: list[tuple[str, str, str]] = [
    ("1.3.6", "Restrict Inbound Traffic", "Vulnerability in public-facing component"),
    ("2.2", "Develop Configuration Standards", "Vulnerability from misconfiguration"),
    ("6.2", "Critical Patches Within 1 Month", "Vulnerability with fix available"),
    ("6.4", "Critical Patches for Public-Facing Systems", "Vulnerability in internet-facing service"),
    ("6.5", "Address Coding Vulnerabilities", "Vulnerability allows injection attacks"),
    ("10.1", "Audit Trails", "Vulnerability impairs logging or audit capability"),
    ("11.2", "External Vulnerability Scanning", "External vulnerability detected"),
    ("11.3", "Internal Vulnerability Scanning", "Internal vulnerability requiring remediation"),
]

SOC2_CONTROLS: list[tuple[str, str, str]] = [
    ("CC6.1", "Logical Access Security", "Vulnerability allows unauthorized access"),
    ("CC6.6", "System Boundaries", "Vulnerability in externally accessible system"),
    ("CC7.1", "Monitoring Infrastructure", "Vulnerability in monitoring/telemetry"),
    ("CC7.2", "Detection of Anomalies", "Vulnerability enables evasion techniques"),
    ("CC8.1", "Change Management", "Unpatched vulnerability indicates gap in change process"),
]

HIPAA_CONTROLS: list[tuple[str, str, str]] = [
    ("164.312(a)(1)", "Access Control", "Vulnerability with access to PHI/ePHI data"),
    ("164.312(b)", "Audit Controls", "Vulnerability affecting audit/logging capability"),
    ("164.312(c)(1)", "Integrity Controls", "Vulnerability compromising data integrity"),
    ("164.312(d)", "Person or Entity Authentication", "Authentication bypass vulnerability"),
    ("164.312(e)(1)", "Transmission Security", "Vulnerability in TLS/communication"),
    ("164.316(b)(1)", "Security Management Process", "Known vulnerability in system processing ePHI"),
]

GDPR_CONTROLS: list[tuple[str, str, str]] = [
    ("Article 32(1)", "Security of Processing", "Vulnerability affecting systems processing personal data"),
    ("Article 32(2)", "Resilience", "Vulnerability reducing system resilience"),
    ("Article 33(1)", "Notification of Breach", "Known exploited vulnerability with data exposure risk"),
    ("Article 35", "Data Protection Impact Assessment", "High-risk vulnerability in data processing system"),
]


def _is_data_sensitive(data_sensitivity: DataSensitivity) -> bool:
    return data_sensitivity in (
        DataSensitivity.CONFIDENTIAL,
        DataSensitivity.RESTRICTED,
        DataSensitivity.REGULATED,
    )


def _is_public_facing(network_exposure: NetworkExposure) -> bool:
    return network_exposure in (NetworkExposure.PUBLIC_LB, NetworkExposure.PUBLIC_DIRECT)


def _is_severity_escalating(
    exploit_known: bool, priv_esc: bool, is_fixable: bool
) -> bool:
    return exploit_known or priv_esc


def _severity_from_cvss_and_exploit(
    cvss: float | None, exploit_known: bool, priv_esc: bool
) -> RiskLevel:
    base = cvss or 5.0
    if exploit_known or priv_esc:
        base = min(10, base + 2)
    if base >= 9.0:
        return RiskLevel.CRITICAL
    if base >= 7.0:
        return RiskLevel.HIGH
    if base >= 4.0:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


class ComplianceChecker:
    """Evaluates vulnerabilities against compliance framework controls."""

    def __init__(
        self, threat_intel: ThreatIntelClient | None = None
    ) -> None:
        self.threat_intel = threat_intel or ThreatIntelClient()

    def check_all(self,
                  cve_id: str | None = None,
                  cvss_score: float | None = None,
                  data_sensitivity: DataSensitivity = DataSensitivity.PUBLIC,
                  network_exposure: NetworkExposure = NetworkExposure.INTERNAL_ONLY,
                  description: str = "",
                  is_fixable: bool = False,
                  priv_esc: bool = False,
                  compliance_scope: list[ComplianceFramework] | None = None,
                  ) -> list[ComplianceFinding]:
        """Evaluate a vulnerability against applicable compliance frameworks."""
        findings: list[ComplianceFinding] = []
        scope = compliance_scope or list(ComplianceFramework)
        intel = self.threat_intel.lookup(cve_id)

        desc_lower = description.lower() if description else ""
        keyword_vuln = {
            "priv_esc": ("privilege escalation", "privesc", "sudo", "root"),
            "auth_bypass": ("auth bypass", "authentication bypass", "unauthenticated"),
            "injection": ("injection", "sql injection", "rce", "rce"),
            "data_exfil": ("exfil", "data leak", "information disclosure"),
            "dos": ("denial of service", "dos", "ddos"),
        }

        for framework in scope:
            controls = self._controls_for(framework)
            for ctrl_id, ctrl_name, trigger_hint in controls:
                violated = self._evaluate_trigger(
                    ctrl_id, framework, trigger_hint, desc_lower,
                    data_sensitivity, network_exposure, intel.known_exploited_vulnerability,
                    is_fixable, priv_esc, cvss_score,
                    any(kw in desc_lower for kw_list in keyword_vuln.values() for kw in kw_list),
                )
                if violated:
                    findings.append(ComplianceFinding(
                        framework=framework,
                        control_id=ctrl_id,
                        control_name=ctrl_name,
                        violated=True,
                        severity=_severity_from_cvss_and_exploit(
                            cvss_score, intel.known_exploited_vulnerability, priv_esc
                        ),
                        description=trigger_hint,
                        recommendation=f"Remediate {cve_id or 'vulnerability'} to maintain {framework.value} compliance for control {ctrl_id}.",
                    ))
        return findings

    # -------------------------------------------------------------------
    # Private helpers
    # -------------------------------------------------------------------

    def _controls_for(self, framework: ComplianceFramework) -> list[tuple[str, str, str]]:
        mapping: dict[ComplianceFramework, list[tuple[str, str, str]]] = {
            ComplianceFramework.NIST_CSF: NIST_CSF_CONTROLS,
            ComplianceFramework.PCI_DSS: PCI_DSS_CONTROLS,
            ComplianceFramework.SOC2: SOC2_CONTROLS,
            ComplianceFramework.HIPAA: HIPAA_CONTROLS,
            ComplianceFramework.GDPR: GDPR_CONTROLS,
        }
        return mapping.get(framework, [])

    def _evaluate_trigger(self, ctrl_id, framework, hint, desc_lower,
                          data_sensitivity, network_exposure, exploit_known,
                          is_fixable, priv_esc, cvss_score, has_vuln_kw) -> bool:
        """Heuristic evaluation of whether a control is violated."""
        # Generic: known exploited vuln always triggers concern
        if exploit_known and any(x in hint.lower() for x in ["known exploited", "response", "policies"]):
            return True

        # Public-facing systems
        if _is_public_facing(network_exposure) and any(
            k in hint.lower() for k in ["public", "external", "internet", "inbound", "externally"]
        ):
            return True

        # Sensitive data
        if _is_data_sensitive(data_sensitivity) and any(
            k in hint.lower() for k in ["data", "phi", "personal", "confidential", "storage", "processing"]
        ):
            return True

        # Fixable patch (PCI 6.2, SOC2 CC8.1, HIPAA 164.316)
        if is_fixable and any(
            k in ctrl_id for ctrl_id, k in [("6.2", "Patch"), ("CC8.1", "Change"), ("316", "Management")]
        ):
            return True

        # Privilege escalation / auth bypass
        if priv_esc and any(
            k in hint.lower() for k in ["privilege", "access control", "authentication", "logical access"]
        ):
            return True

        # Injection vulnerabilities
        if has_vuln_kw and any(
            k in hint.lower() for k in ["injection", "coding"]
        ):
            return True

        # Network facing
        if _is_public_facing(network_exposure) and any(
            k in hint.lower() for k in ["network", "protocol", "service"]
        ):
            return True

        # High severity vulns trigger NIST ID.RA-1
        if cvss_score and cvss_score >= 7.0 and ctrl_id == "ID.RA-1":
            return True

        return False
