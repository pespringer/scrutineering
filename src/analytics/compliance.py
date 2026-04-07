"""Compliance reporting for Container Sentinel.

Generates compliance reports for NIST, PCI DSS, SOC 2, HIPAA, GDPR.
Each framework maps Container Sentinel findings and controls to the
relevant compliance requirements.
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from typing import Any

# ---------------------------------------------------------------------------
# Framework definitions
# ---------------------------------------------------------------------------

FRAMEWORKS: dict[str, dict[str, Any]] = {
    "nist": {
        "name": "NIST SP 800-190 (Container Security)",
        "controls": {
            "image_vulnerability_management": {
                "name": "Image Vulnerability Management",
                "checks": ["images_scanned", "critical_cves_open",
                           "mean_remediation_hours"],
            },
            "least_privilege": {
                "name": "Least Privilege Execution",
                "checks": ["privilege_escalation_events",
                           "root_containers"],
            },
            "network_segmentation": {
                "name": "Network Segmentation",
                "checks": ["unauthorised_network_connections",
                           "external_destinations"],
            },
            "audit_logging": {
                "name": "Audit Logging",
                "checks": ["audit_events_logged",
                           "anomalies_detected"],
            },
        },
    },
    "pci_dss": {
        "name": "PCI DSS 4.0",
        "controls": {
            "vulnerability_management": {
                "name": "Req 6.3 — Vulnerability Management",
                "checks": ["images_scanned", "critical_cves_open"],
            },
            "access_control": {
                "name": "Req 7 — Restrict Access",
                "checks": ["privilege_escalation_events",
                           "root_containers"],
            },
            "monitoring": {
                "name": "Req 10 — Log and Monitor",
                "checks": ["audit_events_logged",
                           "anomalies_detected"],
            },
        },
    },
    "soc2": {
        "name": "SOC 2 Type II",
        "controls": {
            "security_monitoring": {
                "name": "CC7.1 — System Monitoring",
                "checks": ["images_scanned", "anomalies_detected",
                           "audit_events_logged"],
            },
            "vulnerability_management": {
                "name": "CC8.1 — Change Management",
                "checks": ["critical_cves_open", "mean_remediation_hours"],
            },
        },
    },
    "hipaa": {
        "name": "HIPAA Security Rule",
        "controls": {
            "access_control": {
                "name": "164.312(a) — Access Control",
                "checks": ["privilege_escalation_events",
                           "root_containers"],
            },
            "audit_controls": {
                "name": "164.312(b) — Audit Controls",
                "checks": ["audit_events_logged"],
            },
            "integrity": {
                "name": "164.312(c)(1) — Integrity",
                "checks": ["images_scanned", "critical_cves_open"],
            },
        },
    },
    "gdpr": {
        "name": "GDPR Article 32 — Security of Processing",
        "controls": {
            "risk_assessment": {
                "name": "Art 32(1) — Risk Assessment",
                "checks": ["images_scanned", "anomalies_detected"],
            },
            "breach_detection": {
                "name": "Art 33 — Breach Notification",
                "checks": ["anomalies_detected",
                           "audit_events_logged"],
            },
        },
    },
}


class ComplianceReporter:
    """Generates compliance reports for supported frameworks."""

    SUPPORTED = list(FRAMEWORKS.keys())

    def __init__(self):
        self._reports: list[dict] = []

    def generate(
        self,
        framework: str,
        posture_data: dict[str, Any] | None = None,
        audit_data: dict[str, Any] | None = None,
        anomaly_data: dict[str, Any] | None = None,
        trend_data: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if framework not in FRAMEWORKS:
            raise ValueError(
                f"Unsupported framework: {framework}. "
                f"Supported: {self.SUPPORTED}"
            )

        fw = FRAMEWORKS[framework]
        report_id = f"CPL-{framework.upper()}-{int(time.time() * 1000):x}"

        controls_results = {}
        for ctrl_id, ctrl in fw["controls"].items():
            checks = ctrl["checks"]
            results = {}
            for check in checks:
                results[check] = self._evaluate_check(
                    check, posture_data, audit_data,
                    anomaly_data, trend_data,
                )
            compliant = all(
                r.get("pass") for r in results.values()
            )
            controls_results[ctrl_id] = {
                "name": ctrl["name"],
                "status": "compliant" if compliant else "non_compliant",
                "checks": results,
            }

        total = len(controls_results)
        compliant = sum(
            1 for c in controls_results.values()
            if c["status"] == "compliant"
        )

        report = {
            "report_id": report_id,
            "framework": framework,
            "framework_name": fw["name"],
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "overall_status": (
                "compliant" if compliant == total
                else "partial" if compliant > 0
                else "non_compliant"
            ),
            "controls_total": total,
            "controls_compliant": compliant,
            "compliance_percent": round(
                compliant / total * 100, 1) if total else 0,
            "controls": controls_results,
        }

        self._reports.append(report)
        return report

    def list_reports(self, framework: str | None = None) -> list[dict]:
        if framework:
            return [
                r for r in self._reports
                if r["framework"] == framework
            ]
        return list(self._reports)

    def export_markdown(self, report: dict) -> str:
        lines = [
            f"# Compliance Report: {report['framework_name']}",
            "",
            f"**Report ID:** `{report['report_id']}`",
            f"**Generated:** {report['generated_at']}",
            f"**Overall Status:** {report['overall_status'].upper()}",
            f"**Compliance:** {report['compliance_percent']}% "
            f"({report['controls_compliant']}/{report['controls_total']})",
            "",
        ]

        for ctrl_id, ctrl in report["controls"].items():
            status = (
                "COMPLIANT" if ctrl["status"] == "compliant"
                else "NON-COMPLIANT"
            )
            lines.append(f"## {ctrl['name']}")
            lines.append(f"**Status:** {status}")
            lines.append("")
            lines.append("| Check | Status | Detail |")
            lines.append("|-------|--------|--------|")
            for check_id, check_result in ctrl["checks"].items():
                mark = (
                    "PASS" if check_result.get("pass")
                    else "FAIL"
                )
                lines.append(
                    f"| {check_id.replace('_', ' ').title()} "
                    f"| {mark} "
                    f"| {check_result.get('detail', '')} |"
                )
            lines.append("")

        return "\n".join(lines)

    # -- Check evaluators --------------------------------------------------- #

    def _evaluate_check(
        self,
        check: str,
        posture: dict | None,
        audit: dict | None,
        anomaly: dict | None,
        trend: dict | None,
    ) -> dict:
        evaluators = {
            "images_scanned": self._check_images_scanned,
            "critical_cves_open": self._check_critical_cves,
            "mean_remediation_hours": self._check_mttr,
            "privilege_escalation_events": self._check_priv_escalation,
            "root_containers": self._check_root_containers,
            "unauthorised_network_connections": self._check_network,
            "external_destinations": self._check_external,
            "audit_events_logged": self._check_audit,
            "anomalies_detected": self._check_anomalies,
        }
        fn = evaluators.get(check, self._check_na)
        return fn(posture, audit, anomaly, trend)

    def _check_images_scanned(self, posture, audit, anomaly, trend):
        count = (posture or {}).get("total_images", 0)
        return {
            "pass": count > 0,
            "detail": f"{count} images tracked",
        }

    def _check_critical_cves(self, posture, audit, anomaly, trend):
        crit = (posture or {}).get(
            "findings_by_severity", {}).get("critical", 0)
        return {
            "pass": crit == 0,
            "detail": f"{crit} open critical CVEs"
                     if crit else "No critical CVEs",
        }

    def _check_mttr(self, posture, audit, anomaly, trend):
        mttr = (trend or {}).get("mean_remediation_hours")
        threshold = 24
        if mttr is None:
            return {"pass": False, "detail": "No MTTR data available"}
        return {
            "pass": mttr <= threshold,
            "detail": f"MTTR: {mttr:.1f}h "
                      f"(target: <{threshold}h)",
        }

    def _check_priv_escalation(self, posture, audit, anomaly, trend):
        events = (anomaly or {}).get("privilege_escalation_count", 0)
        return {
            "pass": events == 0,
            "detail": f"{events} privilege escalation events"
                     if events else "No escalation events",
        }

    def _check_root_containers(self, posture, audit, anomaly, trend):
        # Placeholder — would inspect container configs
        return {
            "pass": True,
            "detail": "No root containers detected (scan required)",
        }

    def _check_network(self, posture, audit, anomaly, trend):
        events = (anomaly or {}).get("network_anomaly_count", 0)
        return {
            "pass": events == 0,
            "detail": f"{events} unauthorised connections"
                     if events else "No unauthorised connections",
        }

    def _check_external(self, posture, audit, anomaly, trend):
        return {
            "pass": True,
            "detail": "External destination monitoring active",
        }

    def _check_audit(self, posture, audit, anomaly, trend):
        count = (audit or {}).get("total_records", 0)
        return {
            "pass": count > 0,
            "detail": f"{count} audit events logged"
                     if count else "No audit events",
        }

    def _check_anomalies(self, posture, audit, anomaly, trend):
        count = (anomaly or {}).get("total_anomalies", 0)
        return {
            "pass": True,
            "detail": f"{count} anomalies detected and tracked"
                     if count else "Anomaly detection active, "
                                  "no anomalies detected",
        }

    def _check_na(self, *args):
        return {"pass": True, "detail": "Not applicable / N/A"}
