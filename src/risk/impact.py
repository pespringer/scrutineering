"""Impact analysis per CVE.

Analyzes the potential impact of a vulnerability based on:
  - Container deployment context
  - Network topology
  - Data sensitivity
  - Attack chain analysis
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional

from src.risk.models import (
    ContainerContext,
    DataSensitivity,
    ImpactAnalysis,
    NetworkExposure,
    RiskLevel,
)

log = logging.getLogger(__name__)


# Keywords that indicate container escape possibility
_ESCAPE_KEYWORDS = [
    "container escape", "docker escape", "container breakout",
    "host filesystem", "/var/run/docker.sock", "privileged",
    "namespace", "cgroup", "apparmor", "seccomp", "selinux",
    "mount namespace", "kernel exploit", "namespace escape",
]

# Keywords indicating lateral movement risk
_LATERAL_KEYWORDS = [
    "lateral movement", "smb", "ssh", "rdp", "psexec", "wmi",
    "network share", "remote execution", "pass the hash",
    "credential theft", "domain controller", "kerberos",
    "active directory", "internal network", "peer",
]

# CWE patterns indicating dangerous capabilities
_DANGEROUS_CWE_PATTERNS = {
    # CWE-78: OS Command Injection
    "CWE-78": RiskLevel.CRITICAL,
    # CWE-89: SQL Injection
    "CWE-89": RiskLevel.HIGH,
    # CWE-94: Code Injection
    "CWE-94": RiskLevel.CRITICAL,
    # CWE-287: Improper Authentication
    "CWE-287": RiskLevel.CRITICAL,
    # CWE-306: Missing Authentication
    "CWE-306": RiskLevel.CRITICAL,
    # CWE-416: Use After Free
    "CWE-416": RiskLevel.HIGH,
    # CWE-502: Deserialization
    "CWE-502": RiskLevel.CRITICAL,
    # CWE-787: Out-of-bounds Write
    "CWE-787": RiskLevel.HIGH,
    # CWE-79: XSS
    "CWE-79": RiskLevel.MEDIUM,
    # CWE-200: Information Disclosure
    "CWE-200": RiskLevel.MEDIUM,
    # CWE-798: Hardcoded Credentials
    "CWE-798": RiskLevel.CRITICAL,
    # CWE-125: Out-of-bounds Read
    "CWE-125": RiskLevel.HIGH,
}

# Data impact scoring by sensitivity level
_SENSITIVITY_IMPACT: dict[DataSensitivity, RiskLevel] = {
    DataSensitivity.PUBLIC: RiskLevel.LOW,
    DataSensitivity.INTERNAL: RiskLevel.MEDIUM,
    DataSensitivity.CONFIDENTIAL: RiskLevel.HIGH,
    DataSensitivity.RESTRICTED: RiskLevel.CRITICAL,
    DataSensitivity.REGULATED: RiskLevel.CRITICAL,
}

# Network exposure amplification factor
_EXPOSURE_MULTIPLIER: dict[NetworkExposure, float] = {
    NetworkExposure.INTERNAL_ONLY: 1.0,
    NetworkExposure.VPC_PEERED: 1.5,
    NetworkExposure.PUBLIC_LB: 2.0,
    NetworkExposure.PUBLIC_DIRECT: 3.0,
}


def _detect_escape_risk(context: ContainerContext, description: str = "") -> bool:
    if context.privileged:
        return True
    if "docker.sock" in " ".join(context.volumes_mounted):
        return True
    if any(cap in context.capabilities_added for cap in [
        "SYS_ADMIN", "SYS_PTRACE", "DAC_OVERRIDE", "NET_ADMIN"
    ]):
        return True
    desc_lower = description.lower()
    return any(kw in desc_lower for kw in _ESCAPE_KEYWORDS)


def _detect_lateral_movement_risk(description: str = "") -> bool:
    return any(kw in description.lower() for kw in _LATERAL_KEYWORDS)


def _estimate_blast_radius(
    context: ContainerContext,
    severity: float | None = None,
    container_escape_possible: bool = False,
    lateral_movement_risk: bool = False,
) -> tuple[str, int]:
    """Estimate blast radius and affected services."""
    base_services = 1
    if lateral_movement_risk:
        base_services += 2
    if container_escape_possible:
        base_services += 3
    if context.orchestrator == "k8s":
        base_services += 1
    if context.network_exposure in (NetworkExposure.PUBLIC_LB, NetworkExposure.PUBLIC_DIRECT):
        base_services += 1
    if context.privileged:
        base_services += 2

    # Exposure multiplier
    multiplier = _EXPOSURE_MULTIPLIER.get(context.network_exposure, 1.0)
    estimate = max(base_services, int(base_services * multiplier))

    if container_escape_possible:
        desc = (
            f"Container escape risk: can affect other containers on the host, "
            f"potentially the host OS itself. ~{estimate} services at risk."
        )
    elif lateral_movement_risk:
        desc = (
            f"Lateral movement risk: attacker may pivot to other services. "
            f"~{estimate} services potentially reachable."
        )
    else:
        desc = f"Contained to this service. ~{estimate} service(s) potentially affected."

    return desc, estimate


class ImpactAnalyzer:
    """Analyzes the potential impact of a vulnerability."""

    def analyze(
        self,
        context: ContainerContext,
        description: str = "",
        cvss_score: float | None = None,
        cwe_id: str | None = None,
    ) -> ImpactAnalysis:
        """Perform impact analysis for a vulnerability."""
        container_escape = _detect_escape_risk(context, description)
        lateral_risk = _detect_lateral_movement_risk(description)
        blast_radius, services = _estimate_blast_radius(
            context, cvss_score, container_escape, lateral_risk
        )

        # Data exposure impact
        data_impact = _SENSITIVITY_IMPACT.get(
            context.data_sensitivity, RiskLevel.INFORMATIONAL
        )

        # Adjust based on CVSS
        if cvss_score and cvss_score >= 9.0:
            data_impact = max(data_impact, RiskLevel.CRITICAL, key=lambda r: RiskLevel(r).value)
        elif cvss_score and cvss_score >= 7.0:
            data_impact = max(data_impact, RiskLevel.HIGH, key=lambda r: RiskLevel(r).value)

        # Integrity/confidentiality/availability sub-scores
        integrity = RiskLevel.HIGH if container_escape else RiskLevel.MEDIUM
        confidentiality = data_impact
        availability = RiskLevel.HIGH if lateral_risk else RiskLevel.MEDIUM

        # CWE-based dependency risk
        dep_risk = None
        if cwe_id and cwe_id in _DANGEROUS_CWE_PATTERNS:
            dep_risk = _DANGEROUS_CWE_PATTERNS[cwe_id].value

        return ImpactAnalysis(
            blast_radius=blast_radius,
            affected_services_estimate=services,
            lateral_movement_risk=lateral_risk,
            data_exposure_risk=data_impact,
            availability_impact=availability,
            confidentiality_impact=confidentiality,
            integrity_impact=integrity,
            container_escape_possible=container_escape,
            dependency_risk=dep_risk,
        )
