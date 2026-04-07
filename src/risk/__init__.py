"""Vulnerability Risk Assessment & Prioritization Engine.

Provides context-aware risk scoring beyond CVSS by incorporating:
  - Container deployment context (network exposure, data sensitivity)
  - Threat intelligence (exploit availability, active exploitation)
  - MITRE ATT&CK framework mapping
  - Compliance framework impact (NIST, PCI DSS, SOC 2, HIPAA, GDPR)
  - Automated false positive detection
"""

__all__ = [
    "RiskAssessmentEngine",
    "ContextualRiskScore",
    "MitreAttckMapper",
    "ThreatIntelClient",
    "ComplianceChecker",
    "ImpactAnalyzer",
    "FalsePositiveDetector",
]

from src.risk.engine import RiskAssessmentEngine, ContextualRiskScore
from src.risk.mitre import MitreAttckMapper
from src.risk.threat_intel import ThreatIntelClient
from src.risk.compliance import ComplianceChecker
from src.risk.impact import ImpactAnalyzer
from src.risk.false_positive import FalsePositiveDetector
