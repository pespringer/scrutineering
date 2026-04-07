"""Forensic timeline reconstruction and root cause analysis.

Timeline:
  - Merges events from multiple sources (scan findings, runtime events,
    audit logs, network captures) into a single chronological timeline.
  - Supports filtering by container, severity, time range, and event type.

Root Cause Analysis:
  - Correlates vulnerabilities with runtime anomalies to identify attack vectors.
  - Maps findings to MITRE ATT&CK techniques.
  - Scores severity based on exploitability and impact.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Timeline event
# ---------------------------------------------------------------------------

@dataclass(slots=True, order=True)
class TimelineEvent:
    """A single event in the forensic timeline."""
    timestamp: datetime
    source: str = ""                # scan, runtime, audit, network
    event_type: str = ""            # finding_created, anomaly, connection, etc.
    severity: str = ""
    container_id: str = ""
    description: str = ""
    details: dict[str, Any] = field(default_factory=dict, compare=False)

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp.isoformat(),
            "source": self.source,
            "event_type": self.event_type,
            "severity": self.severity,
            "container_id": self.container_id,
            "description": self.description,
            "details": self.details,
        }


SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _sev_rank(s: str) -> int:
    return SEVERITY_RANK.get(s.lower(), 0)


# ---------------------------------------------------------------------------
# Timeline assembler
# ---------------------------------------------------------------------------

class ForensicTimeline:
    """Assembles and queries a chronological forensic timeline.

    Usage:
        tl = ForensicTimeline()
        tl.add_event(TimelineEvent(...))
        events = tl.query(container_id="abc", since=..., to=...)
    """

    def __init__(self):
        self._events: list[TimelineEvent] = []

    def add_event(self, event: TimelineEvent) -> None:
        self._events.append(event)
        self._events.sort()

    def add_events(self, events: list[TimelineEvent]) -> None:
        self._events.extend(events)
        self._events.sort()

    def query(
        self,
        container_id: str | None = None,
        source: str | None = None,
        event_type: str | None = None,
        min_severity: str | None = None,
        since: datetime | None = None,
        to: datetime | None = None,
        limit: int = 500,
    ) -> list[dict]:
        results: list[TimelineEvent] = []
        min_rank = _sev_rank(min_severity) if min_severity else 0
        for ev in self._events:
            if since and ev.timestamp < since:
                continue
            if to and ev.timestamp > to:
                continue
            if container_id and ev.container_id != container_id:
                continue
            if source and ev.source != source:
                continue
            if event_type and ev.event_type != event_type:
                continue
            if _sev_rank(ev.severity) < min_rank:
                continue
            results.append(ev)
            if len(results) >= limit:
                break
        return [e.to_dict() for e in results]

    def summary(self) -> dict[str, Any]:
        total = len(self._events)
        by_source: dict[str, int] = defaultdict(int)
        by_severity: dict[str, int] = defaultdict(int)
        by_container: dict[str, int] = defaultdict(int)
        for ev in self._events:
            by_source[ev.source] += 1
            by_severity[ev.severity] += 1
            by_container[ev.container_id] += 1
        return {
            "total_events": total,
            "by_source": dict(by_source),
            "by_severity": dict(by_severity),
            "by_container": dict(by_container),
        }

    def clear(self) -> None:
        self._events.clear()


# ---------------------------------------------------------------------------
# Root cause analyzer
# ---------------------------------------------------------------------------

# Known attack patterns: vulnerability + anomaly -> attack vector
_ATTACK_PATTERNS: list[dict[str, Any]] = [
    {
        "name": "Container Escape via Privileged Syscall",
        "requires": {"syscall": {"ptrace", "setuid", "setgid"}},
        "anomaly": {"privilege_escalation", "unexpected_process"},
        "mitre": ["T1068", "T1611"],  # Exploit, Process Injection
        "description": "Container escape attempt using privileged syscalls",
    },
    {
        "name": "Cryptojacking",
        "requires": {"process": {"xmrig", "minerd", "cpuminer"}},
        "anomaly": {"crypto_mining", "resource_spike"},
        "mitre": ["T1496"],  # Resource Hijacking
        "description": "Cryptocurrency mining inside container",
    },
    {
        "name": "Reverse Shell / C2",
        "requires": {"syscall": {"execve"}},
        "anomaly": {"reverse_shell"},
        "mitre": ["T1059", "T1571"],  # Command/Script, Non-Standard Port
        "description": "Remote shell or command-and-control channel",
    },
    {
        "name": "Data Exfiltration",
        "requires": {},
        "anomaly": {"data_exfiltration", "network_anomaly"},
        "mitre": ["T1041", "T1048"],  # Exfil over C2/Alt Protocol
        "description": "Abnormal outbound data volume",
    },
    {
        "name": "Supply Chain Compromise",
        "requires": {"cve_found": True},
        "anomaly": {"unexpected_process", "file_anomaly"},
        "mitre": ["T1195"],  # Supply Chain
        "description": "New process in container with known CVEs",
    },
]


@dataclass(slots=True)
class RootCauseHypothesis:
    """A proposed root cause for an incident."""
    pattern_name: str
    confidence: float          # 0.0 - 1.0
    description: str
    mitre_techniques: list[str]
    evidence: dict[str, Any] = field(default_factory=dict)
    recommended_actions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "pattern": self.pattern_name,
            "confidence": self.confidence,
            "description": self.description,
            "mitre": self.mitre_techniques,
            "evidence": self.evidence,
            "recommended_actions": self.recommended_actions,
        }


class RootCauseAnalyzer:
    """Analysess forensic evidence to propose root cause hypotheses.

    Usage:
        rca = RootCauseAnalyzer()
        hypotheses = rca.analyze(container_id, anomalies, findings)
    """

    def __init__(self):
        self._patterns = _ATTACK_PATTERNS

    def analyze(
        self,
        container_id: str,
        anomalies: list[dict[str, Any]] | None = None,
        findings: list[dict[str, Any]] | None = None,
        network_events: list[dict[str, Any]] | None = None,
    ) -> list[RootCauseHypothesis]:
        """Return ranked hypotheses for the given container."""
        if not anomalies and not findings:
            return []

        anomaly_kinds = {a.get("kind", "") for a in (anomalies or [])}
        has_cves = bool(findings)
        processes = {
            a.get("evidence", {}).get("comm", "").lower()
            for a in (anomalies or [])
        }
        syscalls = {
            a.get("evidence", {}).get("syscall", "").lower()
            for a in (anomalies or [])
        }

        evidence = {
            "anomalies": anomalies or [],
            "findings": findings or [],
            "network_events": network_events or [],
        }

        hypotheses: list[RootCauseHypothesis] = []
        for pat in self._patterns:
            score = self._score_pattern(
                pat, anomaly_kinds, has_cves, processes, syscalls)
            if score > 0:
                hypotheses.append(RootCauseHypothesis(
                    pattern_name=pat["name"],
                    confidence=score,
                    description=pat["description"],
                    mitre_techniques=pat["mitre"],
                    evidence=evidence,
                    recommended_actions=self._recommend(pat["name"]),
                ))

        hypotheses.sort(key=lambda h: h.confidence, reverse=True)
        return hypotheses

    def _score_pattern(
        self, pat: dict, anomaly_kinds: set[str],
        has_cves: bool, processes: set[str], syscalls: set[str],
    ) -> float:
        pat_requires = pat.get("requires", {})
        pat_anomaly = pat.get("anomaly", set())

        score = 0.0
        matches = 0
        total_checks = 0

        # Check anomalies match
        if pat_anomaly:
            total_checks += 1
            if anomaly_kinds & pat_anomaly:
                matches += 1
                score += 0.5

        # Check process indicators
        if "process" in pat_requires:
            total_checks += 1
            indicator_set = pat_requires["process"]
            if processes & indicator_set:
                matches += 1
                score += 0.3

        # Check syscall indicators
        if "syscall" in pat_requires:
            total_checks += 1
            syscall_set = pat_requires["syscall"]
            if syscalls & syscall_set:
                matches += 1
                score += 0.3

        # Check CVE requirement
        if pat_requires.get("cve_found"):
            total_checks += 1
            if has_cves:
                matches += 1
                score += 0.2

        if total_checks == 0:
            return 0.0
        return min(score, 1.0)

    @staticmethod
    def _recommend(pattern_name: str) -> list[str]:
        recommendations: dict[str, list[str]] = {
            "Container Escape via Privileged Syscall": [
                "Isolate container immediately",
                "Review container security context / capabilities",
                "Check for privilege escalation indicators",
                "Audit cgroup and namespace configuration",
            ],
            "Cryptojacking": [
                "Kill mining processes",
                "Restrict container resource limits",
                "Investigate entrypoint for unauthorized modifications",
                "Rebuild container from known-good image",
            ],
            "Reverse Shell / C2": [
                "Block outbound connections to suspicious IPs",
                "Capture network traffic for forensic analysis",
                "Audit all running processes and file modifications",
                "Preserve container state before remediation",
            ],
            "Data Exfiltration": [
                "Block outbound traffic to identified destinations",
                "Audit all files accessed by container processes",
                "Review network flow logs for data volume",
                "Check for unauthorized data transfers",
            ],
            "Supply Chain Compromise": [
                "Rebuild from known-good base image",
                "Audit Dockerfile and build pipeline",
                "Scan all dependencies for known CVEs",
                "Implement image signing and verification",
            ],
        }
        return recommendations.get(pattern_name, [
            "Investigate further",
            "Review container logs and configuration",
            "Check for known vulnerabilities in image",
        ])
