"""Integration tests for the scanning engine.

Tests cover:
- Trivy scanner parsing
- Grype scanner parsing
- Deduplication across scanners
"""

import json

import pytest
from src.scan.scanners.base import ScannerFinding, ScannerError
from src.scan.scanners.trivy import TrivyScanner
from src.scan.scanners.grype import GrypeScanner
from src.db.models import Severity


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
                    "PkgPath": "requirements.txt",
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
        assert f.file_path is None, "image scans must not invent repository paths"
        assert f.cvss_scores == {"nvd": 9.8, "redhat": 8.6}
        assert "CVSS:3.1/AV:N/AC:L" in f.cvss_vector

    def test_parse_no_vulnerabilities(self):
        scanner = TrivyScanner(trivy_cmd="echo")
        clean_json = '{"Results": []}'
        findings = scanner._parse_trivy_output(clean_json)
        assert findings == []

    def test_parse_filesystem_target_as_source_path(self, tmp_path):
        scanner = TrivyScanner(trivy_cmd="echo")
        vuln = {
            "VulnerabilityID": "CVE-FS",
            "Severity": "HIGH",
            "PkgName": "lodash",
            "InstalledVersion": "4.17.20",
            "FixedVersion": "4.17.21",
        }
        raw = json.dumps({"Results": [{"Target": "package-lock.json", "Type": "npm", "Vulnerabilities": [vuln]}]})
        findings = scanner._parse_trivy_output(raw, root_path=tmp_path)
        assert findings[0].file_path == "package-lock.json"

    def test_parse_multiple_results(self):
        scanner = TrivyScanner(trivy_cmd="echo")
        multi_json = """
        {
            "Results": [
                {"Target": "alpine:3.14", "Type": "apt", "Vulnerabilities": [
                    {"VulnerabilityID": "CVE-2021-001", "Severity": "CRITICAL", "PkgName": "libssl",
                     "InstalledVersion": "1.0"}
                ]},
                {"Target": "app", "Type": "pip", "Vulnerabilities": [
                    {"VulnerabilityID": "CVE-2021-002", "Severity": "LOW", "PkgName": "requests",
                     "InstalledVersion": "2.25.0"}
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
    def test_local_registry_images_use_grype_registry_source(self, monkeypatch):
        monkeypatch.setenv("LOCAL_REGISTRY_HOST", "registry:5000")
        scanner = GrypeScanner(grype_cmd="echo")
        # The command is exercised by the integration path; this assertion
        # documents the supported registry source prefix without requiring the
        # vulnerability database in a unit test.
        assert scanner._registry_scan_target("registry:5000/app:latest") == "registry:registry:5000/app:latest"

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
                    "type": "deb",
                    "locations": [{"path": "package-lock.json"}]
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
        assert f.file_path is None, "image scans must not invent repository paths"

    def test_parse_filesystem_locations_as_relative_paths(self, tmp_path):
        scanner = GrypeScanner(grype_cmd="echo")
        artifact = {
            "name": "requests",
            "version": "2.0",
            "type": "python",
            "locations": [{"path": str(tmp_path / "requirements.txt")}],
        }
        raw = json.dumps({"matches": [{"vulnerability": {"id": "CVE-FS", "severity": "High"}, "artifact": artifact}]})
        findings = scanner._parse_grype_output(raw, root_path=tmp_path)
        assert findings[0].file_path == "requirements.txt"

    def test_parse_no_matches(self):
        scanner = GrypeScanner(grype_cmd="echo")
        findings = scanner._parse_grype_output('{"matches": []}')
        assert findings == []


# -- Registry detection tests --------------------------------------------- #


class TestFingerprint:
    def test_deterministic(self):
        f1 = ScannerFinding("openssl", "1.1.1", "apt", "CVE-123", "test", None, Severity.HIGH, None)
        f2 = ScannerFinding("openssl", "1.1.1", "apt", "CVE-123", "different title", None, Severity.LOW, None)
        assert f1.make_fingerprint() == f2.make_fingerprint()

    def test_different_cve_different_fingerprint(self):
        f1 = ScannerFinding("pkg", "1.0", None, "CVE-1", "x", None, None, None)
        f2 = ScannerFinding("pkg", "1.0", None, "CVE-2", "x", None, None, None)
        assert f1.make_fingerprint() != f2.make_fingerprint()
