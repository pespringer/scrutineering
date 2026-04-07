"""Automated incident report generation for container forensics.

Generates forensic incident reports in JSON and markdown formats,
combining snapshots, network captures, timeline events, and
root cause analysis into a single cohesive report.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Incident report data class
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class IncidentReport:
    """A complete forensic incident report."""

    report_id: str
    container_id: str
    incident_severity: str
    generated_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc))

    # Title for the incident
    title: str = ""
    analyst: str = ""
    status: str = "open"  # open, investigating, contained, resolved

    # Sections
    executive_summary: str = ""
    timeline_summary: dict[str, Any] = field(default_factory=dict)
    snapshot_summary: dict[str, Any] = field(default_factory=dict)
    network_summary: dict[str, Any] = field(default_factory=dict)
    root_cause_hypotheses: list[dict[str, Any]] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    anomalies: list[dict[str, Any]] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    appendices: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "report_id": self.report_id,
            "container_id": self.container_id,
            "title": self.title,
            "severity": self.incident_severity,
            "status": self.status,
            "analyst": self.analyst,
            "generated_at": self.generated_at.isoformat(),
            "executive_summary": self.executive_summary,
            "timeline_summary": self.timeline_summary,
            "snapshot_summary": self.snapshot_summary,
            "network_summary": self.network_summary,
            "root_cause_hypotheses": self.root_cause_hypotheses,
            "findings": self.findings,
            "anomalies": self.anomalies,
            "recommendations": self.recommendations,
            "appendices": self.appendices,
        }


# ---------------------------------------------------------------------------
# Report generator
# ---------------------------------------------------------------------------


class IncidentReportGenerator:
    """Assembles forensic data into structured incident reports.

    Usage:
        gen = IncidentReportGenerator()
        report = gen.generate(
            container_id="abc123",
            severity="critical",
            title="Suspected container escape",
            snapshot=snapshot_data,
            network_flows=flows,
            timeline_events=events,
            rca_hypotheses=hypotheses,
        )
        gen.save_markdown(report, Path("/tmp/report.md"))
    """

    def __init__(self):
        self._reports: list[IncidentReport] = []

    def generate(
        self,
        container_id: str,
        severity: str,
        title: str = "",
        analyst: str = "",
        snapshot: dict[str, Any] | None = None,
        network_flows: list[dict[str, Any]] | None = None,
        dns_records: list[dict[str, Any]] | None = None,
        timeline_events: list[dict[str, Any]] | None = None,
        rca_hypotheses: list[dict[str, Any]] | None = None,
        findings: list[dict[str, Any]] | None = None,
        anomalies: list[dict[str, Any]] | None = None,
    ) -> IncidentReport:
        """Build a complete incident report from forensic components."""

        report_id = f"IR-{int(time.time() * 1000):x}-{container_id[:8]}"

        report = IncidentReport(
            report_id=report_id,
            container_id=container_id,
            incident_severity=severity,
            title=title or f"Incident report for {container_id[:12]}",
            analyst=analyst,
        )

        # -- Executive summary ------------------------------------------------
        report.executive_summary = self._build_exec_summary(
            severity, title, snapshot, rca_hypotheses, findings, anomalies)

        # -- Snapshot summary ------------------------------------------------
        if snapshot:
            report.snapshot_summary = {
                "captured_at": snapshot.get("captured_at", ""),
                "image": snapshot.get("image_name", ""),
                "status": snapshot.get("status", ""),
                "file_count": len(snapshot.get("filesystem", [])),
                "process_count": len(snapshot.get("processes", [])),
                "connection_count": len(snapshot.get("connections", [])),
                "snapshot_hash": snapshot.get("snapshot_hash", ""),
            }

        # -- Network summary --------------------------------------------------
        if network_flows:
            external = [f for f in network_flows if not f.get("is_internal")]
            report.network_summary = {
                "total_flows": len(network_flows),
                "external_connections": len(external),
                "unique_destinations": len({
                    f.get("dst") for f in external
                }),
                "protocols": list({
                    f.get("protocol") for f in network_flows
                    if f.get("protocol")
                }),
            }

        # -- DNS summary as appendix -----------------------------------------
        if dns_records:
            report.appendices["dns_queries"] = dns_records

        # -- Timeline summary ------------------------------------------------
        if timeline_events:
            report.timeline_summary = {
                "total_events": len(timeline_events),
                "first_event": timeline_events[0].get("timestamp", "")
                if timeline_events else "",
                "last_event": timeline_events[-1].get("timestamp", "")
                if timeline_events else "",
            }
            report.appendices["timeline_events"] = timeline_events

        # -- Root cause hypotheses --------------------------------------------
        if rca_hypotheses:
            report.root_cause_hypotheses = rca_hypotheses
            # Pull recommendations from top hypothesis
            top = rca_hypotheses[0]
            report.recommendations = top.get("recommended_actions", [])

        # -- Findings ---------------------------------------------------------
        if findings:
            report.findings = findings

        # -- Anomalies --------------------------------------------------------
        if anomalies:
            report.anomalies = anomalies

        self._reports.append(report)
        return report

    # -- Export --------------------------------------------------------------

    def to_json(self, report: IncidentReport) -> str:
        """Serialize report to JSON string."""
        return json.dumps(report.to_dict(), indent=2, default=str)

    def save_json(self, report: IncidentReport, path: Path | str) -> Path:
        """Write report to a JSON file."""
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(self.to_json(report))
        logger.info("Written incident report to %s", p)
        return p

    def to_markdown(self, report: IncidentReport) -> str:
        """Render report as a markdown document suitable for
        incident review meetings and post-mortem archives."""

        h = report.to_dict()
        lines: list[str] = []

        # Header
        lines.append("# Incident Report: " + h["title"])
        lines.append("")
        lines.append("**Report ID:** `" + h["report_id"] + "`")
        lines.append("**Container:** `" + h["container_id"] + "`")
        lines.append("**Severity:** " + h["severity"].upper())
        lines.append("**Status:** " + h["status"])
        lines.append("**Analyst:** " + (h.get("analyst") or "Automated"))
        lines.append("**Generated:** " + h["generated_at"])
        lines.append("")

        # Executive summary
        lines.append("## Executive Summary")
        lines.append("")
        lines.append(h.get("executive_summary", "Pending.") or "Pending.")
        lines.append("")

        # Snapshot
        if h.get("snapshot_summary"):
            ss = h["snapshot_summary"]
            lines.append("## Container Snapshot")
            lines.append("")
            lines.append("| Property | Value |")
            lines.append("|---|---|")
            for k, v in ss.items():
                lines.append("| " + k.replace("_", " ").title() + " | " + str(v) + " |")
            lines.append("")

        # Network
        if h.get("network_summary"):
            ns = h["network_summary"]
            lines.append("## Network Activity")
            lines.append("")
            lines.append("| Metric | Value |")
            lines.append("|---|---|")
            for k, v in ns.items():
                lines.append("| " + k.replace("_", " ").title() + " | " + str(v) + " |")
            lines.append("")

        # Root cause
        if h.get("root_cause_hypotheses"):
            lines.append("## Root Cause Hypotheses")
            lines.append("")
            for i, hyp in enumerate(h["root_cause_hypotheses"], 1):
                lines.append("### " + str(i) + ". " + hyp.get("pattern", "Unknown"))
                lines.append(
                    "**Confidence:** " +
                    "{:.0%}".format(hyp.get("confidence", 0)))
                lines.append(
                    "**MITRE ATT&CK:** " + ", ".join(hyp.get("mitre", [])))
                lines.append("")
                lines.append(hyp.get("description", ""))
                lines.append("")
            lines.append("")

        # Timeline
        if h.get("timeline_summary"):
            ts = h["timeline_summary"]
            lines.append("## Forensic Timeline")
            lines.append("")
            lines.append(
                "**Events:** " + str(ts.get("total_events", 0)) + " | "
                "**Window:** " + str(ts.get("first_event", "")) +
                " -> " + str(ts.get("last_event", "")))
            lines.append("")

        # Recommendations
        if h.get("recommendations"):
            lines.append("## Recommendations")
            lines.append("")
            for r in h["recommendations"]:
                lines.append("- " + r)
            lines.append("")

        # Findings table
        if h.get("findings"):
            lines.append("## Vulnerability Findings")
            lines.append("")
            lines.append("| CVE | Severity | Package | Fixable |")
            lines.append("|-----|----------|---------|---------|")
            for f in h["findings"]:
                lines.append(
                    "| " + str(f.get("cve_id", "-")) + " | "
                    + str(f.get("severity", "-")) + " | "
                    + str(f.get("package_name", "-")) + " | "
                    + ("Yes" if f.get("fixable") else "No") + " |"
                )
            lines.append("")

        return "\n".join(lines)

    def save_markdown(
        self, report: IncidentReport, path: Path | str
    ) -> Path:
        """Write report to a markdown file."""
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(self.to_markdown(report))
        logger.info("Written markdown report to %s", p)
        return p

    def get_reports(
        self,
        container_id: str | None = None,
        min_severity: str | None = None,
    ) -> list[IncidentReport]:
        """Query previously generated reports."""
        severity_order = {
            "critical": 4,
            "high": 3,
            "medium": 2,
            "low": 1,
        }
        min_rank = severity_order.get(min_severity, 0) if min_severity else 0
        results = []
        for r in self._reports:
            if container_id and r.container_id != container_id:
                continue
            if severity_order.get(r.incident_severity, 0) < min_rank:
                continue
            results.append(r)
        return results

    # -- Helpers -------------------------------------------------------------

    @staticmethod
    def _build_exec_summary(
        severity: str,
        title: str,
        snapshot: dict | None,
        rca: list | None,
        findings: list | None,
        anomalies: list | None,
    ) -> str:
        parts: list[str] = []
        if title:
            parts.append("Incident: **" + title + "**.")
        parts.append("Severity: **" + severity.upper() + "**.")

        counts: list[str] = []
        if findings:
            counts.append(str(len(findings)) + " scan findings detected")
        if anomalies:
            counts.append(str(len(anomalies)) + " anomalies observed")
        if counts:
            parts.append("Analysis identified " + ", ".join(counts) + ".")

        if rca and rca[0].get("pattern"):
            top = rca[0]
            conf = top.get("confidence", 0)
            parts.append(
                "Most likely cause: **" + top["pattern"] + "** "
                "(confidence: " + "{:.0%}".format(conf) + ")."
            )

        if snapshot:
            parts.append(
                "Container state captured: image "
                "`" + snapshot.get("image_name", "unknown") + "`, "
                "status `" + snapshot.get("status", "unknown") + "`."
            )

        return " ".join(parts)
