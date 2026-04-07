"""SIEM integration — exports forensic data in common SIEM formats.

Supports:
  - CEF (Common Event Format) — ArcSight, Splunk
  - LEEF (Log Event Extended Format) — QRadar
  - Syslog (RFC 5424) — generic
  - JSON export — modern SIEMs (Elastic, Chronicle)
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# CEF Exporter
# ---------------------------------------------------------------------------

class SIEMExporter:
    """Exports forensic events in SIEM-compatible formats."""

    SEVERITY_MAP = {
        "critical": "10",
        "high": "8",
        "medium": "5",
        "low": "2",
        "info": "0",
    }

    @staticmethod
    def to_cef(
        timestamp: datetime | None = None,
        host: str = "ContainerSentinel",
        signature: str = "container-event",
        name: str = "",
        severity: str = "medium",
        extensions: dict[str, Any] | None = None,
    ) -> str:
        """Format as CEF: Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extensions

        See: ArcSight CEF specification.
        """
        ts = timestamp or datetime.now(timezone.utc)
        sev = SIEMExporter.SEVERITY_MAP.get(severity.lower(), "5")
        ext_str = ""
        if extensions:
            pairs = []
            for k, v in extensions.items():
                safe_k = k.replace(" ", "_")
                safe_v = str(v).replace("|", "\\|").replace("=", "\\=").replace("\n", "\\n")
                pairs.append(f"{safe_k}={safe_v}")
            ext_str = " ".join(pairs)
        return (
            f"CEF:0|ContainerSentinel|Forensics|1.0|"
            f"{signature}|{name}|{sev}|{ext_str}"
        )

    @staticmethod
    def to_leef(
        timestamp: datetime | None = None,
        host: str = "ContainerSentinel",
        event_type: str = "container-event",
        severity: str = "medium",
        attributes: dict[str, Any] | None = None,
    ) -> str:
        """Format as LEEF: Version|Vendor|Product|Version|Event ID|tab-separated attributes

        See: IBM QRadar LEEF specification.
        """
        ts = timestamp or datetime.now(timezone.utc)
        ts_str = ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond // 1000:03d}Z"
        sev = SIEMExporter.SEVERITY_MAP.get(severity.lower(), "5")
        attr_str = ""
        if attributes:
            pairs = []
            for k, v in attributes.items():
                safe_k = k.replace(" ", "_")
                safe_v = str(v).replace("\t", " ").replace("\n", " ")
                pairs.append(f"{safe_k}={safe_v}")
            attr_str = "\t" + "\t".join(pairs)
        return f"LEEF:2.0|ContainerSentinel|Forensics|1.0|{event_type}{attr_str}"

    @staticmethod
    def to_syslog_rfc5424(
        facility: int = 1,             # user-level
        severity: int = 5,             # notice
        hostname: str = "ContainerSentinel",
        app_name: str = "container-forensics",
        msg_id: str = "",
        message: str = "",
        structured_data: dict[str, dict[str, str]] | None = None,
    ) -> str:
        """Format as RFC 5424 syslog.

        <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG
        """
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        pri = facility * 8 + severity
        sd = "-"
        if structured_data:
            parts = []
            for sd_id, params in structured_data.items():
                kv = " ".join(f'{k}="{v}"' for k, v in params.items())
                parts.append(f"[{sd_id} {kv}]")
            sd = " ".join(parts) if parts else "-"
        procid = "-"
        return f"<{pri}>1 {ts} {hostname} {app_name} {procid} {msg_id} {sd} {message}"

    @staticmethod
    def to_json_event(
        event_type: str,
        container_id: str,
        severity: str,
        description: str,
        details: dict[str, Any] | None = None,
        timestamp: datetime | None = None,
    ) -> str:
        """Format as structured JSON for Elastic/Chronicle."""
        ts = timestamp or datetime.now(timezone.utc)
        event = {
            "@timestamp": ts.isoformat(),
            "event": {
                "type": event_type,
                "severity": severity,
                "description": description,
            },
            "container": {"id": container_id},
            "observer": {"product": "ContainerSentinel", "vendor": "ContainerSentinel"},
        }
        if details:
            event["container_forensics"] = details
        return json.dumps(event, separators=(",", ":"))

    # -- Batch export helpers ----------------------------------------------- #

    @staticmethod
    def export_cef_batch(events: list[dict[str, Any]]) -> list[str]:
        """Convert a list of event dicts to CEF lines."""
        lines = []
        for ev in events:
            lines.append(SIEMExporter.to_cef(
                timestamp=ev.get("timestamp"),
                signature=ev.get("signature", "container-event"),
                name=ev.get("name", ""),
                severity=ev.get("severity", "medium"),
                extensions=ev.get("extensions"),
            ))
        return lines

    @staticmethod
    def export_json_batch(events: list[dict[str, Any]]) -> list[str]:
        """Convert a list of event dicts to JSON lines."""
        lines = []
        for ev in events:
            lines.append(SIEMExporter.to_json_event(
                event_type=ev.get("event_type", "container-event"),
                container_id=ev.get("container_id", ""),
                severity=ev.get("severity", "medium"),
                description=ev.get("description", ""),
                details=ev.get("details"),
                timestamp=ev.get("timestamp"),
            ))
        return lines

    @staticmethod
    def to_elasticsearch_bulk(events: list[dict[str, Any]],
                               index: str = "container-sentinel") -> str:
        """Format for Elasticsearch bulk API."""
        lines: list[str] = []
        for ev in events:
            action = {"index": {"_index": index}}
            lines.append(json.dumps(action))
            lines.append(json.dumps(ev))
        return "\n".join(lines) + "\n"
