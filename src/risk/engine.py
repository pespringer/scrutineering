"""Risk Assessment Engine — central orchestrator.

Ties together:
  - Threat intel (exploit availability, EPSS, CISA KEV)
  - Impact analysis (blast radius, lateral movement, container escape)
  - MITRE ATT&CK mapping
  - Compliance framework checks (NIST, PCI DSS, SOC 2, HIPAA, GDPR)
  - False positive detection
  - Contextual risk scoring (beyond raw CVSS)

Public API:
    engine.assess(VulnerabilityInput) -> ContextualRiskScore
    engine.assess_batch(BatchAssessmentRequest) -> BatchAssessmentResponse
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from src.risk.models import (
    BatchAssessmentRequest,
    BatchAssessmentResponse,
    ContextualRiskScore,
    FalsePositiveAssessment,
    ImpactAnalysis,
    MitreMapping,
    RiskLevel,
    ThreatIntelData,
    VulnerabilityInput,
)
from src.risk.mitre import MitreAttckMapper
from src.risk.threat_intel import ThreatIntelClient
from src.risk.compliance import ComplianceChecker
from src.risk.impact import ImpactAnalyzer
from src.risk.false_positive import FalsePositiveDetector

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Scoring weight configuration
# ---------------------------------------------------------------------------
_WEIGHTS = {
    "base_cvss": 0.25,           # Raw CVSS v3 score (0-10 -> 0-10)
    "epss": 0.15,                # EPSS exploit probability (0-1 -> 0-10)
    "kev": 0.15,                 # CISA Known Exploited (0 or 10)
    "exposure": 0.15,            # Network exposure factor (0-10)
    "sensitivity": 0.10,         # Data sensitivity (0-10)
    "container_risk": 0.10,      # Container escape / root / privileged (0-10)
    "age": 0.05,                 # Time since publication (0-10)
    "compliance": 0.05,          # Compliance violations (0-10)
}


def _clamp(v: float, lo: float = 0.0, hi: float = 10.0) -> float:
    return max(lo, min(hi, v))


def _risk_level(score: float) -> RiskLevel:
    if score >= 9.0:
        return RiskLevel.CRITICAL
    if score >= 7.0:
        return RiskLevel.HIGH
    if score >= 4.0:
        return RiskLevel.MEDIUM
    if score >= 1.0:
        return RiskLevel.LOW
    return RiskLevel.INFORMATIONAL


# Network exposure -> 0-10 scaling
_EXPOSURE_SCORE = {
    "internal_only": 1.0,
    "vpc_peered": 4.0,
    "public_load_balancer": 7.5,
    "public_direct": 9.5,
}

# Data sensitivity -> 0-10 scaling
_SENSITIVITY_SCORE = {
    "public": 1.0,
    "internal": 3.0,
    "confidential": 6.0,
    "restricted": 8.5,
    "regulated": 10.0,
}


class RiskAssessmentEngine:
    """Central risk assessment orchestrator.

    Usage:
        engine = RiskAssessmentEngine()
        score = engine.assess(vulnerability_input)
    """

    def __init__(
        self,
        threat_intel: Optional[ThreatIntelClient] = None,
        mitre_mapper: Optional[MitreAttckMapper] = None,
        compliance_checker: Optional[ComplianceChecker] = None,
        impact_analyzer: Optional[ImpactAnalyzer] = None,
        false_positive_detector: Optional[FalsePositiveDetector] = None,
    ):
        self.threat_intel = threat_intel or ThreatIntelClient()
        self.mitre_mapper = mitre_mapper or MitreAttckMapper()
        self.compliance = compliance_checker or ComplianceChecker(self.threat_intel)
        self.impact = impact_analyzer or ImpactAnalyzer()
        self.false_positive = false_positive_detector or FalsePositiveDetector()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def assess(self, vuln: VulnerabilityInput) -> ContextualRiskScore:
        """Produce a full contextual risk score for one vulnerability."""
        ctx = vuln.container_context
        desc = vuln.description or ""
        cve = vuln.cve_id or ""

        # 1. Threat intel lookup
        intel: ThreatIntelData = self.threat_intel.lookup(
            cve_id=vuln.cve_id,
            package_name=vuln.package_name,
            package_version=vuln.package_version,
            existing_epss=vuln.epss_score,
        )

        # 2. Impact analysis
        impact_result: ImpactAnalysis = self.impact.analyze(
            context=ctx,
            description=desc,
            cvss_score=vuln.cvss_score,
        )

        # 3. MITRE ATT&CK mapping
        mitre_mappings: list[MitreMapping] = self.mitre_mapper.map_cve(
            cve_id=vuln.cve_id,
            description=desc,
            package_name=vuln.package_name,
            title=vuln.title,
        )

        # 4. Compliance check
        compliance_findings = self.compliance.check_all(
            cve_id=vuln.cve_id,
            cvss_score=vuln.cvss_score,
            data_sensitivity=ctx.data_sensitivity,
            network_exposure=ctx.network_exposure,
            description=desc,
            is_fixable=bool(vuln.fixed_version),
            priv_esc=impact_result.container_escape_possible,
            compliance_scope=vuln.compliance_scope or [],
        )

        # 5. False positive detection
        fp: FalsePositiveAssessment = self.false_positive.assess(
            package_name=vuln.package_name,
            package_version=vuln.package_version,
            description=desc,
            title=vuln.title,
            fixed_version=vuln.fixed_version,
            is_build_stage=_is_build_stage(ctx),
        )

        # 6. Compute contextual score
        base_cvss = vuln.cvss_score or 5.0
        cvss_component = base_cvss  # already 0-10

        epss_component = (intel.epss_score or 0.0) * 10.0  # 0-1 -> 0-10

        kev_component = 10.0 if intel.known_exploited_vulnerability else 0.0

        exposure_component = _EXPOSURE_SCORE.get(
            ctx.network_exposure.value, 1.0
        )

        sensitivity_component = _SENSITIVITY_SCORE.get(
            ctx.data_sensitivity.value, 1.0
        )

        # Container risk: escape + root + privileged
        container_base = 2.0
        if impact_result.container_escape_possible:
            container_base += 5.0
        if ctx.runs_as_root:
            container_base += 1.5
        if ctx.privileged:
            container_base += 2.5
        container_component = min(10.0, container_base)

        # Age: older unfixed vulns are riskier
        age_days = vuln.age_days or 0
        age_component = min(10.0, age_days / 90.0 * 10.0)  # 90 days = max

        # Compliance: presence of violations adds to risk
        compliance_component = (
            min(10.0, len(compliance_findings) * 2.0)
            if compliance_findings
            else 0.0
        )

        # Weighted sum
        w = _WEIGHTS
        contextual = (
            w["base_cvss"] * cvss_component
            + w["epss"] * epss_component
            + w["kev"] * kev_component
            + w["exposure"] * exposure_component
            + w["sensitivity"] * sensitivity_component
            + w["container_risk"] * container_component
            + w["age"] * age_component
            + w["compliance"] * compliance_component
        )
        contextual = _clamp(contextual)

        # Exploitability estimate (0-10)
        exploitability = base_cvss * 0.5
        if intel.exploit_status.value == "in_the_wild":
            exploitability += 4.0
        elif intel.exploit_status.value == "poc_available":
            exploitability += 2.5
        exploitability = min(10.0, exploitability)

        # Priority score (0-100 integer, higher = more urgent)
        priority_score = int(round(contextual * 10.0))

        # Build scoring breakdown
        breakdown = {
            "base_cvss": round(cvss_component * w["base_cvss"], 2),
            "epss": round(epss_component * w["epss"], 2),
            "kev": round(kev_component * w["kev"], 2),
            "exposure": round(exposure_component * w["exposure"], 2),
            "sensitivity": round(sensitivity_component * w["sensitivity"], 2),
            "container_risk": round(container_component * w["container_risk"], 2),
            "age": round(age_component * w["age"], 2),
            "compliance": round(compliance_component * w["compliance"], 2),
        }

        recommendation = self._build_recommendation(
            contextual, intel, fp, impact_result
        )

        return ContextualRiskScore(
            cve_id=vuln.cve_id,
            package_name=vuln.package_name,
            package_version=vuln.package_version,
            base_cvss=base_cvss if vuln.cvss_score else None,
            contextual_risk_score=round(contextual, 2),
            priority_score=priority_score,
            risk_level=RiskLevel.CRITICAL if fp.is_false_positive else _risk_level(contextual),
            exploitability=round(_clamp(exploitability), 2),
            impact=impact_result,
            threat_intel=intel,
            mitre_mappings=mitre_mappings,
            compliance_findings=compliance_findings,
            false_positive=fp,
            scoring_breakdown=breakdown,
            recommendation=recommendation,
            assessed_at=datetime.now(timezone.utc),
        )

    def assess_batch(self, req: BatchAssessmentRequest) -> BatchAssessmentResponse:
        """Assess multiple vulnerabilities and return sorted by priority."""
        results = [self.assess(v) for v in req.vulnerabilities]
        results.sort(key=lambda r: r.priority_score, reverse=True)

        counts: dict[str, int] = {}
        for r in results:
            lvl = r.risk_level.value
            counts[lvl] = counts.get(lvl, 0) + 1

        return BatchAssessmentResponse(
            total_assessed=len(results),
            risk_level_counts=counts,
            assessed=results,
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_recommendation(
        score: float,
        intel: ThreatIntelData,
        fp: FalsePositiveAssessment,
        impact: ImpactAnalysis,
    ) -> str:
        if fp.is_false_positive:
            return (
                f"Likely false positive (confidence {fp.confidence:.0%}). "
                f"Review and consider suppressing: {', '.join(fp.reasons[:2])}"
            )
        if intel.known_exploited_vulnerability:
            return (
                "CRITICAL: Active exploitation detected in the wild. "
                "Immediate patching required. Consider temporary compensating controls "
                "(WAF rules, network segmentation) until fix is deployed."
            )
        if impact.container_escape_possible:
            return (
                "HIGH: Container escape risk detected. "
                "Review container security configuration immediately. "
                "Remove privileged mode and unnecessary capabilities."
            )
        if score >= 7.0:
            return (
                "High priority — schedule remediation within 24-48 hours. "
                "Validate fix in staging before rolling to production."
            )
        if score >= 4.0:
            return (
                "Medium priority — include in next patching cycle. "
                "Monitor for active exploitation."
            )
        return (
            "Low priority — monitor and include in regular maintenance cycle."
        )


def _is_build_stage(ctx) -> bool:
    """Heuristic: infer if the container is a build stage rather than production."""
    # Multi-stage builds typically have no exposed ports and no volumes
    if (
        not ctx.ports_exposed
        and not ctx.volumes_mounted
        and ctx.environment in ("build", "test")
    ):
        return True
    return False
