"""Pydantic models for the risk assessment engine."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class RiskLevel(str, Enum):
    """Human-interpretable risk levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"
    FALSE_POSITIVE = "false_positive"


class ExploitStatus(str, Enum):
    """Level of exploit maturity available."""
    NO_KNOWN_EXPLOIT = "none"
    POC_AVAILABLE = "poc_available"
    IN_THE_WILD = "in_the_wild"
    WEAPONIZED = "weaponized"


class NetworkExposure(str, Enum):
    """How exposed the vulnerable service is on the network."""
    INTERNAL_ONLY = "internal_only"
    VPC_PEERED = "vpc_peered"
    PUBLIC_LB = "public_load_balancer"
    PUBLIC_DIRECT = "public_direct"


class DataSensitivity(str, Enum):
    """Sensitivity tier of data accessible by the container."""
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"
    REGULATED = "regulated"  # PII, PHI, PCI data


class ComplianceFramework(str, Enum):
    """Supported compliance frameworks."""
    NIST_CSF = "nist_csf"
    PCI_DSS = "pci_dss"
    SOC2 = "soc2"
    HIPAA = "hipaa"
    GDPR = "gdpr"


class MitreTactic(str, Enum):
    """MITRE ATT&CK high-level tactics."""
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command_and_control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class ContainerContext(BaseModel):
    """Deployment context for a container image."""

    container_id: Optional[str] = None
    environment: str = Field(
        default="production",
        description="prod, staging, dev, test"
    )
    network_exposure: NetworkExposure = Field(
        default=NetworkExposure.INTERNAL_ONLY,
        description="How exposed is this container on the network"
    )
    data_sensitivity: DataSensitivity = Field(
        default=DataSensitivity.PUBLIC,
        description="Sensitivity of data the container can access"
    )
    internet_facing: bool = False
    runs_as_root: bool = False
    privileged: bool = False
    volumes_mounted: list[str] = Field(default_factory=list)
    capabilities_added: list[str] = Field(default_factory=list)
    ports_exposed: list[int] = Field(default_factory=list)
    orchestrator: Optional[str] = None  # k8s, docker_swarm, ecs, nomad
    namespace: Optional[str] = None
    service_mesh: bool = False
    has_resource_limits: bool = True
    image_pull_policy: str = "Always"
    custom_attributes: dict[str, Any] = Field(default_factory=dict)


class VulnerabilityInput(BaseModel):
    """A vulnerability to assess."""

    cve_id: Optional[str] = None
    package_name: str
    package_version: Optional[str] = None
    package_type: Optional[str] = None  # apk, npm, pip, osv, etc.
    title: str = ""
    description: Optional[str] = None
    cvss_score: Optional[float] = Field(default=None, ge=0, le=10)
    cvss_vector: Optional[str] = None
    cvss_v2_score: Optional[float] = Field(default=None, ge=0, le=10)
    cvss_v3_score: Optional[float] = Field(default=None, ge=0, le=10)
    cvss_v3_1_score: Optional[float] = Field(default=None, ge=0, le=10)
    cvss_v4_score: Optional[float] = Field(default=None, ge=0, le=10)
    fixed_version: Optional[str] = None
    epss_score: Optional[float] = Field(default=None, ge=0, le=1,
        description="EPSS exploit probability score (0-1)")
    exploit_status: Optional[ExploitStatus] = None
    is_fixable: bool = False
    age_days: Optional[int] = None
    # Deployment context
    container_context: ContainerContext = Field(
        default_factory=ContainerContext
    )
    # Compliance scope
    compliance_scope: list[ComplianceFramework] = Field(default_factory=list)


class BatchAssessmentRequest(BaseModel):
    """Assess multiple vulnerabilities at once."""

    vulnerabilities: list[VulnerabilityInput]
    global_tags: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------

class MitreMapping(BaseModel):
    """MITRE ATT&CK mapping for a CVE."""

    tactic: Optional[MitreTactic] = None
    technique_id: Optional[str] = None  # e.g. T1190
    technique_name: Optional[str] = None
    sub_technique_id: Optional[str] = None  # e.g. T1190.001
    description: Optional[str] = None


class ThreatIntelData(BaseModel):
    """Threat intelligence for a CVE."""

    exploit_status: ExploitStatus = ExploitStatus.NO_KNOWN_EXPLOIT
    exploit_maturity_description: Optional[str] = None
    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None
    known_exploited_vulnerability: bool = False  # CISA KEV list
    ransomware_linked: bool = False
    threat_actors: list[str] = Field(default_factory=list)
    kev_date: Optional[datetime] = None
    nvd_last_modified: Optional[datetime] = None
    references: list[str] = Field(default_factory=list)


class ComplianceFinding(BaseModel):
    """A compliance framework violation or concern."""

    framework: ComplianceFramework
    control_id: str  # e.g. "SI-2", "6.2", "CC7.2"
    control_name: str
    violated: bool
    severity: RiskLevel = RiskLevel.INFORMATIONAL
    description: str
    recommendation: str


class ImpactAnalysis(BaseModel):
    """Impact analysis for a CVE."""

    blast_radius: str = Field(
        description="Textual description of blast radius"
    )
    affected_services_estimate: int = Field(
        default=1,
        description="Estimated number of services that may be affected"
    )
    lateral_movement_risk: bool = False
    data_exposure_risk: RiskLevel = RiskLevel.INFORMATIONAL
    availability_impact: RiskLevel = RiskLevel.INFORMATIONAL
    confidentiality_impact: RiskLevel = RiskLevel.INFORMATIONAL
    integrity_impact: RiskLevel = RiskLevel.INFORMATIONAL
    container_escape_possible: bool = False
    dependency_risk: Optional[str] = None


class FalsePositiveAssessment(BaseModel):
    """False positive detection result."""

    is_false_positive: bool = False
    confidence: float = Field(
        ge=0, le=1,
        description="Confidence in the assessment (0-1)"
    )
    reasons: list[str] = Field(default_factory=list)


class ContextualRiskScore(BaseModel):
    """Complete risk assessment output for one vulnerability."""

    cve_id: Optional[str] = None
    package_name: str
    package_version: Optional[str] = None

    # Scores
    base_cvss: Optional[float] = None
    contextual_risk_score: float = Field(
        ge=0, le=10,
        description="Context-adjusted risk score (0-10)"
    )
    priority_score: int = Field(
        ge=0, le=100,
        description="Integer priority for sorting (higher = more urgent)"
    )

    # Interpretation
    risk_level: RiskLevel = RiskLevel.INFORMATIONAL
    exploitability: float = Field(
        ge=0, le=10,
        description="How easy it is to exploit this"
    )
    impact: ImpactAnalysis

    # Context factors
    threat_intel: Optional[ThreatIntelData] = None
    mitre_mappings: list[MitreMapping] = Field(default_factory=list)
    compliance_findings: list[ComplianceFinding] = Field(default_factory=list)
    false_positive: Optional[FalsePositiveAssessment] = None

    # Meta
    scoring_breakdown: dict[str, float] = Field(
        default_factory=dict,
        description="Component scores that make up the contextual score"
    )
    recommendation: str = ""
    assessed_at: Optional[datetime] = None


class BatchAssessmentResponse(BaseModel):
    """Response for batch vulnerability assessment."""

    total_assessed: int
    risk_level_counts: dict[str, int]
    assessed: list[ContextualRiskScore]
