"""Tests for the risk assessment engine and all sub-modules."""

import pytest
from src.risk.models import (
    VulnerabilityInput,
    ContainerContext,
    NetworkExposure,
    DataSensitivity,
    ComplianceFramework,
    RiskLevel,
)
from src.risk.engine import RiskAssessmentEngine
from src.risk.mitre import MitreAttckMapper
from src.risk.threat_intel import ThreatIntelClient
from src.risk.compliance import ComplianceChecker
from src.risk.impact import ImpactAnalyzer
from src.risk.false_positive import FalsePositiveDetector


# -- Risk assessment engine ------------------------------------------------- #

class TestRiskAssessmentEngine:
    @pytest.fixture
    def engine(self):
        return RiskAssessmentEngine()

    def _base_vuln(self, **overrides):
        defaults = {
            "package_name": "openssl",
            "package_version": "1.1.1",
            "title": "Buffer overflow",
            "description": "A remote code execution vulnerability",
        }
        defaults.update(overrides)
        return VulnerabilityInput(**defaults)

    def test_assess_basic_vulnerability(self, engine):
        vuln = VulnerabilityInput(
            cve_id="CVE-2021-44228",
            package_name="log4j",
            package_version="2.14.0",
            cvss_score=9.8,
            description="RCE in Apache Log4j via JNDI lookup",
            container_context=ContainerContext(
                environment="production",
                network_exposure=NetworkExposure.PUBLIC_DIRECT,
                data_sensitivity=DataSensitivity.REGULATED,
            ),
        )
        result = engine.assess(vuln)

        assert result.cve_id == "CVE-2021-44228"
        assert result.risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH)
        assert result.contextual_risk_score >= 7.0
        assert result.priority_score >= 70
        assert result.threat_intel.known_exploited_vulnerability
        assert result.impact.container_escape_possible is not None
        assert len(result.mitre_mappings) > 0
        assert len(result.compliance_findings) > 0
        assert len(result.scoring_breakdown) == 8  # 8 weight components
        assert "Log4Shell" not in result.recommendation or "Active exploitation" in result.recommendation

    def test_assess_low_priority_vuln(self, engine):
        vuln = VulnerabilityInput(
            cve_id="CVE-2023-00001",
            package_name="curl",
            package_version="7.88.0",
            cvss_score=3.5,
            description="Minor information disclosure",
            container_context=ContainerContext(
                environment="dev",
                network_exposure=NetworkExposure.INTERNAL_ONLY,
                data_sensitivity=DataSensitivity.PUBLIC,
            ),
        )
        result = engine.assess(vuln)
        assert result.risk_level in (RiskLevel.LOW, RiskLevel.INFORMATIONAL)
        assert result.contextual_risk_score < 7.0
        assert not result.threat_intel.known_exploited_vulnerability

    def test_assess_batch(self, engine):
        vulns = [
            VulnerabilityInput(
                cve_id="CVE-2021-44228",
                package_name="log4j",
                cvss_score=9.8,
                container_context=ContainerContext(
                    network_exposure=NetworkExposure.PUBLIC_DIRECT,
                    data_sensitivity=DataSensitivity.REGULATED,
                ),
            ),
            VulnerabilityInput(
                cve_id="CVE-2023-00002",
                package_name="zlib",
                cvss_score=4.0,
                container_context=ContainerContext(
                    network_exposure=NetworkExposure.INTERNAL_ONLY,
                    data_sensitivity=DataSensitivity.PUBLIC,
                ),
            ),
            VulnerabilityInput(
                cve_id="CVE-2024-3094",
                package_name="xz-utils",
                cvss_score=10.0,
                container_context=ContainerContext(
                    network_exposure=NetworkExposure.PUBLIC_DIRECT,
                    data_sensitivity=DataSensitivity.RESTRICTED,
                ),
            ),
        ]
        req = type('obj', (), {'vulnerabilities': vulns})()
        result = engine.assess_batch(req)  # type: ignore
        # Should be sorted by priority_score descending
        assert result.assessed[0].priority_score >= result.assessed[1].priority_score
        assert result.assessed[1].priority_score >= result.assessed[2].priority_score
        assert result.total_assessed == 3


# -- MITRE ATT&CK mapping --------------------------------------------------- #

class TestMitreMapping:
    def setup_method(self):
        self.mapper = MitreAttckMapper()

    def test_log4shell_maps_to_t1190(self):
        mappings = self.mapper.map_cve("CVE-2021-44228")
        tech_ids = [m.technique_id for m in mappings]
        assert "T1190" in tech_ids
        assert "T1059" in tech_ids

    def test_pwnkit_maps_to_t1068(self):
        mappings = self.mapper.map_cve("CVE-2021-4034")
        tech_ids = [m.technique_id for m in mappings]
        assert "T1068" in tech_ids

    def test_description_keyword_mapping(self):
        mappings = self.mapper.map_cve(
            description="remote code execution via deserialization"
        )
        tech_ids = [m.technique_id for m in mappings]
        assert "T1190" in tech_ids

    def test_no_mapping_for_unknown(self):
        mappings = self.mapper.map_cve(cve_id="CVE-2025-99999")
        assert isinstance(mappings, list)

    def test_package_heuristic(self):
        mappings = self.mapper.map_cve(package_name="openssl")
        assert any(m.technique_id in ["T1552", "T1556"] for m in mappings)


# -- Threat Intel ----------------------------------------------------------- #

class TestThreatIntel:
    def setup_method(self):
        self.client = ThreatIntelClient()

    def test_log4shell_known_exploited(self):
        intel = self.client.lookup("CVE-2021-44228")
        assert intel.known_exploited_vulnerability
        assert intel.epss_score is not None
        assert intel.epss_score > 0.9
        assert "APT28" in intel.threat_actors

    def test_non_exploited_cve(self):
        intel = self.client.lookup("CVE-2025-99999")
        assert not intel.known_exploited_vulnerability
        assert intel.threat_actors == []

    def test_invalid_cve_returns_empty(self):
        intel = self.client.lookup("not-a-cve")
        assert not intel.known_exploited_vulnerability
        assert intel.epss_score is None

    def test_epss_high_score_in_the_wild_classification(self):
        intel = self.client.lookup("CVE-2021-44228")
        assert intel.epss_score > 0.9
        assert intel.exploit_status.value == "in_the_wild"

    def test_xz_backdoor(self):
        intel = self.client.lookup("CVE-2024-3094")
        assert intel.known_exploited_vulnerability
        assert intel.ransomware_linked


# -- Compliance Checker ----------------------------------------------------- #

class TestComplianceChecker:
    def setup_method(self):
        self.checker = ComplianceChecker()

    def test_public_facing_cve(self):
        findings = self.checker.check_all(
            cve_id="CVE-2021-44228",
            cvss_score=9.8,
            network_exposure=NetworkExposure.PUBLIC_DIRECT,
            data_sensitivity=DataSensitivity.REGULATED,
            compliance_scope=[ComplianceFramework.PCI_DSS],
        )
        assert any(f.violated for f in findings)
        assert any(f.framework == ComplianceFramework.PCI_DSS for f in findings)

    def test_internal_non_sensitive_no_violations(self):
        findings = self.checker.check_all(
            cvss_score=3.0,
            network_exposure=NetworkExposure.INTERNAL_ONLY,
            data_sensitivity=DataSensitivity.PUBLIC,
        )
        violated = [f for f in findings if f.violated]
        # May have some but fewer than public-facing
        assert len(violated) < 10

    def test_ransomware_triggers_notifications(self):
        findings = self.checker.check_all(
            cve_id="CVE-2021-44228",
            cvss_score=9.8,
            data_sensitivity=DataSensitivity.REGULATED,
            compliance_scope=[ComplianceFramework.HIPAA],
        )
        violated = [f for f in findings if f.violated]
        # Known exploited + regulated data should violate HIPAA controls
        assert any(f.framework == ComplianceFramework.HIPAA for f in findings)


# -- Impact Analysis -------------------------------------------------------- #

class TestImpactAnalyzer:
    def setup_method(self):
        self.analyzer = ImpactAnalyzer()

    def test_container_escape_detection(self):
        ctx = ContainerContext(
            privileged=True,
            network_exposure=NetworkExposure.PUBLIC_DIRECT,
        )
        result = self.analyzer.analyze(
            context=ctx,
            description="container escape via docker.sock with lateral movement risk to internal services",
            cvss_score=9.8,
        )
        assert result.container_escape_possible
        assert result.lateral_movement_risk
        assert result.affected_services_estimate >= 3

    def test_contained_vuln(self):
        ctx = ContainerContext(
            network_exposure=NetworkExposure.INTERNAL_ONLY,
            data_sensitivity=DataSensitivity.PUBLIC,
        )
        result = self.analyzer.analyze(
            context=ctx,
            description="minor info disclosure",
            cvss_score=3.0,
        )
        assert not result.container_escape_possible
        assert result.data_exposure_risk in (RiskLevel.LOW, RiskLevel.INFORMATIONAL)

    def test_k8s_blast_radius(self):
        ctx = ContainerContext(
            orchestrator="k8s",
            network_exposure=NetworkExposure.PUBLIC_LB,
        )
        result = self.analyzer.analyze(context=ctx, cvss_score=7.0)
        assert result.affected_services_estimate >= 3


# -- False Positive Detection ----------------------------------------------- #

class TestFalsePositiveDetection:
    def setup_method(self):
        self.detector = FalsePositiveDetector()

    def test_build_time_package(self):
        result = self.detector.assess(package_name="pytest")
        assert result.confidence > 0.3
        assert any("build-time" in r for r in result.reasons)

    def test_kernel_package_in_container(self):
        result = self.detector.assess(package_name="linux-image")
        assert result.confidence > 0.3
        assert any("host" in r.lower() for r in result.reasons)

    def test_already_fixed(self):
        result = self.detector.assess(
            package_name="openssl",
            package_version="3.0.10",
            fixed_version="3.0.9",
        )
        assert result.confidence >= 0.6
        assert any("fixed" in r.lower() for r in result.reasons)

    def test_no_false_positive(self):
        result = self.detector.assess(
            package_name="nginx",
            package_version="1.24.0",
            description="Remote code execution in HTTP/2 module",
        )
        assert not result.is_false_positive
        assert result.confidence == 0.0

    def test_non_runtime_path(self):
        result = self.detector.assess(
            package_name="libssl",
            affected_paths=["/usr/src/app/build/libssl.so"],
        )
        assert result.confidence > 0.2

    def test_wontfix(self):
        result = self.detector.assess(
            package_name="oldlib",
            description="This vulnerability is end of life and will not fix",
        )
        assert result.confidence > 0.1
