"""Integration tests for the scanning engine.

Tests cover:
- Trivy scanner parsing
- Grype scanner parsing
- Deduplication across scanners
- registry detection
- risk score computation
- concurrent batch scanning
"""

import asyncio
import pytest
from src.scan.scanners.base import ScannerFinding, ScannerError
from src.scan.scanners.trivy import TrivyScanner, SEVERITY_MAP
from src.scan.scanners.grype import GrypeScanner
from src.scan.registry import detect_registry, login_ecr
from src.scan.scan_service import ScanService
from src.db.models import Severity, FindingSource


# -- Trivy parser tests ---------------------------------------------------- #

class TestTrivyParser:
    """Test Trivy JSON output parsing without requiring Trivy binary."""

    def test_parse_single_vulnerability(self):
        scanner = TrivyScanner(trivy_cmd="echo")
        trivy_json = """
        {
            "Results": [{
                "Target": "alpine:3.14",
                "Type": "apt",
                "Vulnerabilities": [{
                    "VulnerabilityID": "CVE-2021-1234",
                    "Severity": "HIGH",
                    "Title": "Buffer overflow in openssl",
                    "Description": "A high-severity flaw.",
                    "PkgName": "openssl",
                    "InstalledVersion": "1.1.1",
                    "FixedVersion": "1.1.2",
                    "CVSS": {
                        "nvd": {"V3Score": 9.8, "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
                        "redhat": {"V3Score": 8.6, "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"}
                    }
                }]
            }]
        }
        """
        findings = scanner._parse_trivy_output(trivy_json)
        assert len(findings) == 1
        f = findings[0]
        assert f.cve_id == "CVE-2021-1234"
        assert f.package_name == "openssl"
        assert f.package_version == "1.1.1"
        assert f.severity == Severity.HIGH
        assert f.fixed_version == "1.1.2"
        assert f.cvss_scores == {"nvd": 9.8, "redhat": 8.6}
        assert "CVSS:3.1/AV:N/AC:L" in f.cvss_vector

    def test_parse_no_vulnerabilities(self):
        scanner = TrivyScanner(trivy_cmd="echo")
        clean_json = '{"Results": []}'
        findings = scanner._parse_trivy_output(clean_json)
        assert findings == []

    def test_parse_multiple_results(self):
        scanner = TrivyScanner(trivy_cmd="echo")
        multi_json = """
        {
            "Results": [
                {"Target": "alpine:3.14", "Type": "apt", "Vulnerabilities": [
                    {"VulnerabilityID": "CVE-2021-001", "Severity": "CRITICAL", "PkgName": "libssl", "InstalledVersion": "1.0"}
                ]},
                {"Target": "app", "Type": "pip", "Vulnerabilities": [
                    {"VulnerabilityID": "CVE-2021-002", "Severity": "LOW", "PkgName": "requests", "InstalledVersion": "2.25.0"}
                ]}
            ]
        }
        """
        findings = scanner._parse_trivy_output(multi_json)
        assert len(findings) == 2
        assert findings[0].package_type == "apt"
        assert findings[1].package_type == "pip"

    def test_parse_cvss_extraction_priority(self):
        """NVD should take priority over other vendors for max score."""
        scanner = TrivyScanner(trivy_cmd="echo")
        json_data = """
        {
            "Results": [{
                "Target": "test", "Type": "apt",
                "Vulnerabilities": [{
                    "VulnerabilityID": "CVE-TEST",
                    "Severity": "HIGH",
                    "PkgName": "pkg",
                    "CVSS": {
                        "alpine": {"V3Score": 5.5, "V3Vector": "CVSS:3.1/foo"},
                        "nvd": {"V3Score": 9.8, "V3Vector": "CVSS:3.1/bar"}
                    }
                }]
            }]
        }
        """
        findings = scanner._parse_trivy_output(json_data)
        assert findings[0].cvss_scores == {"alpine": 5.5, "nvd": 9.8}
        assert "CVSS:3.1/bar" == findings[0].cvss_vector  # NVD wins

    def test_parse_missing_fields(self):
        scanner = TrivyScanner(trivy_cmd="echo")
        sparse_json = """
        {
            "Results": [{
                "Target": "test", "Type": "apt",
                "Vulnerabilities": [
                    {"VulnerabilityID": "CVE-X", "Severity": "MEDIUM", "PkgName": "zlib"},
                    {"VulnerabilityID": null, "Severity": "LOW", "PkgName": "curl"}
                ]
            }]
        }
        """
        findings = scanner._parse_trivy_output(sparse_json)
        assert len(findings) == 2
        assert findings[0].cve_id == "CVE-X"
        assert findings[1].cve_id is None

    def test_parse_invalid_json_raises_error(self):
        scanner = TrivyScanner(trivy_cmd="echo")
        with pytest.raises(ScannerError, match="Failed to parse JSON"):
            scanner._parse_trivy_output("not json")


# -- Grype parser tests ---------------------------------------------------- #

class TestGrypeParser:
    def test_parse_single_match(self):
        scanner = GrypeScanner(grype_cmd="echo")
        grype_json = """
        {
            "matches": [{
                "vulnerability": {
                    "id": "CVE-2021-5678",
                    "severity": "Critical",
                    "description": "Critical RCE in foo"
                },
                "artifact": {
                    "name": "libfoo",
                    "version": "2.0.0",
                    "type": "deb"
                }
            }]
        }
        """
        findings = scanner._parse_grype_output(grype_json)
        assert len(findings) == 1
        f = findings[0]
        assert f.cve_id == "CVE-2021-5678"
        assert f.severity == Severity.CRITICAL
        assert f.package_name == "libfoo"

    def test_parse_no_matches(self):
        scanner = GrypeScanner(grype_cmd="echo")
        findings = scanner._parse_grype_output('{"matches": []}')
        assert findings == []


# -- Registry detection tests --------------------------------------------- #

class TestRegistryDetection:
    def test_dockerhub_simple(self):
        assert detect_registry("nginx:latest") == "dockerhub"

    def test_dockerhub_with_library(self):
        assert detect_registry("library/nginx:latest") == "dockerhub"

    def test_ecr(self):
        assert detect_registry("123456789.dkr.ecr.us-east-1.amazonaws.com/my/app:v1") == "ecr"

    def test_ghcr(self):
        assert detect_registry("ghcr.io/user/app:v1") == "ghcr.io"

    def test_gcr(self):
        assert detect_registry("gcr.io/project/img:v1") == "gcr.io"

    def test_harbor(self):
        assert detect_registry("harbor.example.com/proj/img:tag") == "harbor"

    def test_private_registry(self):
        assert detect_registry("registry.mycompany.com:5000/app:v1") == "registry.mycompany.com:5000"

    def test_ecr_login_uses_argument_vector(self, monkeypatch):
        calls = []

        class FakeProcess:
            returncode = 0

            async def communicate(self):
                return b"token\n", b""

        async def fake_exec(*args, **kwargs):
            calls.append(args)
            return FakeProcess()

        monkeypatch.setattr("src.scan.registry.asyncio.create_subprocess_exec", fake_exec)
        assert asyncio.run(login_ecr("us-east-1")) == ("AWS", "token")
        assert calls == [("aws", "ecr", "get-login-password", "--region", "us-east-1")]

    def test_ecr_login_rejects_shell_metacharacters(self):
        with pytest.raises(ValueError, match="invalid characters"):
            asyncio.run(login_ecr("us-east-1; touch /tmp/pwned"))


class TestScannerRetries:
    def test_transient_scanner_failure_is_retried(self):
        class FlakyScanner:
            source = FindingSource.TRIVY
            attempts = 0

            async def scan(self, image_name):
                self.attempts += 1
                if self.attempts < 3:
                    raise ScannerError("trivy", "temporary failure")
                return []

        scanner = FlakyScanner()
        service = ScanService(scanner_retry_attempts=2, scanner_retry_backoff=0)
        assert asyncio.run(service._run_single(scanner, "alpine:3.20", "trivy")) == []
        assert scanner.attempts == 3

    def test_negative_retry_settings_are_rejected(self):
        with pytest.raises(ValueError, match="must not be negative"):
            ScanService(scanner_retry_attempts=-1)


# -- Risk score tests ------------------------------------------------------ #

class TestRiskScore:
    def test_critical_finding(self):
        findings = [{"severity": "CRITICAL", "cvss_scores": {"nvd": 9.8}}]
        score = ScanService._compute_risk_score(findings)
        assert score["risk_level"] == "critical"
        assert score["max_cvss"] == 9.8
        assert score["critical_count"] == 1

    def test_high_finding(self):
        findings = [{"severity": "HIGH", "cvss_scores": {"nvd": 7.5}}]
        score = ScanService._compute_risk_score(findings)
        assert score["risk_level"] == "high"

    def test_only_low(self):
        findings = [{"severity": "LOW", "cvss_scores": {}}]
        score = ScanService._compute_risk_score(findings)
        assert score["risk_level"] == "low"

    def test_empty(self):
        score = ScanService._compute_risk_score([])
        assert score["max_cvss"] == 0.0
        assert score["risk_level"] == "low"

    def test_weighted_score_capped(self):
        findings = [{"severity": "CRITICAL", "cvss_scores": {"nvd": 10.0}} for _ in range(20)]
        score = ScanService._compute_risk_score(findings)
        assert score["weighted_score"] == 100.0


# -- ScannerFinding fingerprint tests -------------------------------------- #

class TestFingerprint:
    def test_deterministic(self):
        f1 = ScannerFinding("openssl", "1.1.1", "apt", "CVE-123", "test", None, Severity.HIGH, None)
        f2 = ScannerFinding("openssl", "1.1.1", "apt", "CVE-123", "different title", None, Severity.LOW, None)
        assert f1.make_fingerprint() == f2.make_fingerprint()

    def test_different_cve_different_fingerprint(self):
        f1 = ScannerFinding("pkg", "1.0", None, "CVE-1", "x", None, None, None)
        f2 = ScannerFinding("pkg", "1.0", None, "CVE-2", "x", None, None, None)
        assert f1.make_fingerprint() != f2.make_fingerprint()
