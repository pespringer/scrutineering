"""Alert manager for runtime monitoring events and anomalies.

Integrates with Sentinel's notification system to dispatch alerts
when anomalies are detected at configurable severity thresholds.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class Alert:
    """A generated alert record."""
    id: str
    anomaly_type: str
    severity: str
    container_id: str
    image_name: str | None
    title: str
    description: str
    evidence: dict[str, Any]
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat())
    acknowledged: bool = False
    acknowledged_at: str | None = None
    resolved: bool = False
    resolved_at: str | None = None
    notification_channels_sent: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "anomaly_type": self.anomaly_type,
            "severity": self.severity,
            "container_id": self.container_id,
            "image_name": self.image_name,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "created_at": self.created_at,
            "acknowledged": self.acknowledged,
            "acknowledged_at": self.acknowledged_at,
            "resolved": self.resolved,
            "resolved_at": self.resolved_at,
            "notification_channels_sent": self.notification_channels_sent,
        }


class AlertManager:
    """Manages alert lifecycle and delivers to notification channels.

    Supports:
      - In-memory alert store with deduplication
      - Severity-based threshold filtering (only alert above a level)
      - Rate limiting (suppress duplicates within a cooldown window)
      - Pluggable notification callbacks (Slack, email, webhook, etc.)
      - Acknowledgement and resolution tracking
    """

    SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3,
                      "critical": 4}

    def __init__(self,
                 min_alert_severity: str = "medium",
                 cooldown_seconds: int = 300,  # 5 min dedup window
                 max_alerts: int = 1000):
        self._min_sev = self.SEVERITY_ORDER.get(min_alert_severity, 2)
        self._cooldown = cooldown_seconds
        self._alerts: dict[str, Alert] = {}
        self._recent_keys: dict[str, float] = {}  # dedup key -> last_ts
        self._callbacks: list[Callable[[Alert], None]] = []
        self._max_alerts = max_alerts
        self._alert_counter = 0

    # -- Registration ------------------------------------------------------- #

    def register_callback(self, cb: Callable[[Alert], None]) -> None:
        """Register a notification callback."""
        self._callbacks.append(cb)

    # -- Alert creation / routing ------------------------------------------- #

    def create_alert(self,
                     anomaly_type: str,
                     severity: str,
                     container_id: str,
                     title: str,
                     description: str,
                     evidence: dict[str, Any] | None = None,
                     image_name: str | None = None,
                     ) -> str | None:
        """Create a new alert.  Returns alert ID on success or None if
        suppressed by severity threshold or cooldown."""
        sev_rank = self.SEVERITY_ORDER.get(severity, 0)
        if sev_rank < self._min_sev:
            return None  # below threshold

        # Dedup: same type + container within cooldown
        dedup_key = f"{anomaly_type}:{container_id}"
        now = time.time()
        prev = self._recent_keys.get(dedup_key, 0)
        if now - prev < self._cooldown:
            return None
        self._recent_keys[dedup_key] = now

        self._alert_counter += 1
        alert_id = f"ALERT-{int(time.time() * 1000):x}-{self._alert_counter:x}"
        alert = Alert(
            id=alert_id,
            anomaly_type=anomaly_type,
            severity=severity,
            container_id=container_id,
            image_name=image_name,
            title=title,
            description=description,
            evidence=evidence or {},
        )

        self._alerts[alert_id] = alert

        # Evict oldest if over max
        if len(self._alerts) > self._max_alerts:
            oldest_id = min(self._alerts,
                            key=lambda k: self._alerts[k].created_at)
            del self._alerts[oldest_id]

        # Fire callbacks
        for cb in self._callbacks:
            try:
                cb(alert)
            except Exception:
                logger.exception("Alert callback failed for %s", alert_id)

        return alert_id

    # -- Integration with analyzer ------------------------------------------ #

    def anomaly_handler(self) -> Callable:
        """Return a callback suitable for RuntimeBehaviorAnalyzer."""
        def _handler(anomaly_dict: dict) -> None:
            self.create_alert(
                anomaly_type=anomaly_dict.get("kind", "unknown"),
                severity=anomaly_dict.get("severity", "medium"),
                container_id=anomaly_dict.get("container_id", ""),
                image_name=anomaly_dict.get("image_name"),
                title=f"Runtime anomaly: {anomaly_dict.get('kind', '')}",
                description=anomaly_dict.get("description", ""),
                evidence=anomaly_dict.get("evidence", {}),
            )
        return _handler

    # -- Lifecycle management ----------------------------------------------- #

    def acknowledge(self, alert_id: str, actor: str | None = None) -> bool:
        alert = self._alerts.get(alert_id)
        if not alert:
            return False
        alert.acknowledged = True
        alert.acknowledged_at = datetime.now(timezone.utc).isoformat()
        return True

    def resolve(self, alert_id: str) -> bool:
        alert = self._alerts.get(alert_id)
        if not alert:
            return False
        alert.resolved = True
        alert.resolved_at = datetime.now(timezone.utc).isoformat()
        return True

    # -- Queries ------------------------------------------------------------ #

    def list_alerts(self,
                    container_id: str | None = None,
                    severity: str | None = None,
                    unresolved_only: bool = True,
                    limit: int = 100) -> list[dict]:
        results: list[dict] = []
        for alert in self._alerts.values():
            if unresolved_only and alert.resolved:
                continue
            if container_id and alert.container_id != container_id:
                continue
            if severity and alert.severity != severity:
                continue
            results.append(alert.to_dict())
            if len(results) >= limit:
                break
        # Sort most recent first
        results.sort(key=lambda a: a["created_at"], reverse=True)
        return results

    def stats(self) -> dict:
        total = len(self._alerts)
        by_severity: dict[str, int] = {}
        unresolved = 0
        for a in self._alerts.values():
            by_severity[a.severity] = by_severity.get(a.severity, 0) + 1
            if not a.resolved:
                unresolved += 1
        return {
            "total": total,
            "unresolved": unresolved,
            "by_severity": by_severity,
        }
