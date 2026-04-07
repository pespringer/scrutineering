"""Notification and alert dispatch system for Container Sentinel.

Supports multiple notification channels:
  - Slack (webhook)
  - Email (SMTP)
  - PagerDuty (Events API v2)
  - Generic webhooks

Features:
  - Pluggable channel backends
  - Severity-based routing
  - Rate limiting / cooldown per channel per event type
  - Template-based message formatting
"""

from __future__ import annotations

import json
import logging
import time
import urllib.request
import urllib.error
from typing import Any, Callable

logger = logging.getLogger(__name__)


# -- Message ----------------------------------------------------------------

class AlertMessage:
    """A formatted alert ready for dispatch."""

    def __init__(
        self,
        title: str,
        severity: str,
        body: str,
        container_id: str = "",
        image_name: str = "",
        alert_id: str = "",
        metadata: dict[str, Any] | None = None,
    ):
        self.title = title
        self.severity = severity
        self.body = body
        self.container_id = container_id
        self.image_name = image_name
        self.alert_id = alert_id
        self.metadata = metadata or {}

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "severity": self.severity,
            "body": self.body,
            "container_id": self.container_id,
            "image_name": self.image_name,
            "alert_id": self.alert_id,
            "metadata": self.metadata,
        }


# -- Channel backends -------------------------------------------------------

class BaseChannel:
    """Abstract notification channel."""

    def __init__(self, name: str, min_severity: str = "medium"):
        self.name = name
        self._min_severity = min_severity
        self._sent_count = 0

    def should_send(self, severity: str) -> bool:
        order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        return order.get(severity, 0) >= order.get(self._min_severity, 2)

    def send(self, message: AlertMessage) -> bool:
        raise NotImplementedError

    @property
    def sent_count(self) -> int:
        return self._sent_count


class WebhookChannel(BaseChannel):
    """Generic HTTP webhook channel."""

    def __init__(self, url: str, name: str = "webhook",
                 min_severity: str = "medium", headers: dict | None = None):
        super().__init__(name, min_severity)
        self.url = url
        self.headers = headers or {"Content-Type": "application/json"}

    def send(self, message: AlertMessage) -> bool:
        payload = json.dumps(message.to_dict()).encode()
        req = urllib.request.Request(
            self.url, data=payload, headers=self.headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                self._sent_count += 1
                logger.info("Webhook sent to %s: %s", self.url,
                            message.title)
                return True
        except Exception as exc:
            logger.error("Webhook failed: %s", exc)
            return False


class SlackChannel(BaseChannel):
    """Slack Incoming Webhook channel."""

    def __init__(self, webhook_url: str, channel: str = "#alerts",
                 username: str = "Container Sentinel",
                 min_severity: str = "medium"):
        super().__init__("slack", min_severity)
        self.webhook_url = webhook_url
        self.channel = channel
        self.username = username

    def send(self, message: AlertMessage) -> bool:
        severity_colors = {
            "critical": "#FF0000", "high": "#FF6600",
            "medium": "#FFCC00", "low": "#00CC00", "info": "#0099FF",
        }
        color = severity_colors.get(message.severity, "#CCCCCC")

        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text",
                         "text": f":warning: {message.title}"},
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn",
                     "text": f"*Severity:* {message.severity.upper()}"},
                    {"type": "mrkdwn",
                     "text": f"*Container:* `{message.container_id}`"},
                ],
            },
        ]
        if message.body:
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": message.body},
            })
        if message.metadata:
            fields = []
            for k, v in list(message.metadata.items())[:4]:
                fields.append({"type": "mrkdwn",
                               "text": f"*{k}:* {v}"})
            if fields:
                blocks.append({
                    "type": "section", "fields": fields})

        payload = json.dumps({
            "channel": self.channel,
            "username": self.username,
            "attachments": [{"color": color, "blocks": blocks}],
        }).encode()

        req = urllib.request.Request(
            self.webhook_url, data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                self._sent_count += 1
                return True
        except Exception as exc:
            logger.error("Slack notification failed: %s", exc)
            return False


class PagerDutyChannel(BaseChannel):
    """PagerDuty Events API v2 channel."""

    API_URL = "https://events.pagerduty.com/v2/enqueue"

    def __init__(self, routing_key: str, min_severity: str = "high",
                 dedup_key_prefix: str = "sentinel"):
        super().__init__("pagerduty", min_severity)
        self.routing_key = routing_key
        self.dedup_key_prefix = dedup_key_prefix

    def send(self, message: AlertMessage) -> bool:
        pd_severity = {
            "critical": "critical", "high": "error",
            "medium": "warning", "low": "info", "info": "info",
        }.get(message.severity, "warning")

        payload = {
            "routing_key": self.routing_key,
            "event_action": "trigger",
            "dedup_key": f"{self.dedup_key_prefix}-{message.alert_id}",
            "payload": {
                "summary": message.title,
                "severity": pd_severity,
                "source": message.container_id or "ContainerSentinel",
                "custom_details": {
                    "body": message.body,
                    "image": message.image_name,
                    **message.metadata,
                },
            },
        }

        req = urllib.request.Request(
            self.API_URL,
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                self._sent_count += 1
                return True
        except Exception as exc:
            logger.error("PagerDuty notification failed: %s", exc)
            return False


class EmailChannel(BaseChannel):
    """SMTP email channel (stub — uses a callback for actual sending)."""

    def __init__(self, recipients: list[str],
                 sender: str = "sentinel@localhost",
                 min_severity: str = "medium",
                 send_callback: Callable | None = None,
                 name: str | None = None):
        super().__init__(name or "email", min_severity)
        self.recipients = recipients
        self.sender = sender
        self._send = send_callback

    def send(self, message: AlertMessage) -> bool:
        subject = f"[Sentinel] [{message.severity.upper()}] {message.title}"
        body = (
            f"Alert: {message.title}\n"
            f"Severity: {message.severity.upper()}\n"
            f"Container: {message.container_id}\n"
            f"Image: {message.image_name}\n\n"
            f"{message.body}\n"
        )
        if self._send:
            try:
                self._send(
                    sender=self.sender,
                    recipients=self.recipients,
                    subject=subject,
                    body=body,
                )
                self._sent_count += 1
                return True
            except Exception as exc:
                logger.error("Email send failed: %s", exc)
                return False
        else:
            logger.info(
                "Email (no SMTP configured): %s -> %s: %s",
                subject, self.recipients, body[:200],
            )
            self._sent_count += 1
            return True


# -- Service ----------------------------------------------------------------

class NotificationService:
    """Manages notification channels and dispatches alerts.

    Usage:
        svc = NotificationService()
        svc.add_channel(WebhookChannel(url="https://hooks.example.com"))
        svc.dispatch(AlertMessage(
            title="CVE detected", severity="critical", body="..."))
    """

    SEVERITY_ORDER = {
        "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

    def __init__(self, default_min_severity: str = "medium",
                 cooldown_seconds: int = 300):
        self._channels: list[BaseChannel] = []
        self._default_min = default_min_severity
        self._cooldown = cooldown_seconds
        self._cooldowns: dict[str, float] = {}
        self._dispatch_count = 0

    def add_channel(self, channel: BaseChannel) -> None:
        self._channels.append(channel)

    def remove_channel(self, name: str) -> int:
        before = len(self._channels)
        self._channels = [c for c in self._channels if c.name != name]
        return before - len(self._channels)

    def dispatch(self, message: AlertMessage,
                 channels: list[str] | None = None) -> dict[str, bool]:
        """Send an alert to matching channels."""
        # Global cooldown (dedup)
        dedup_key = f"{message.title}:{message.container_id}"
        if self._in_cooldown(dedup_key):
            return {}

        results: dict[str, bool] = {}
        for channel in self._channels:
            if channels and channel.name not in channels:
                continue
            if not channel.should_send(message.severity):
                results[channel.name] = False
                continue
            success = channel.send(message)
            results[channel.name] = success

        if any(results.values()):
            self._set_cooldown(dedup_key)
            self._dispatch_count += 1

        return results

    def dispatch_from_dict(self, data: dict[str, Any],
                           channels: list[str] | None = None) -> dict:
        """Create and dispatch an AlertMessage from a dict."""
        msg = AlertMessage(
            title=data.get("title", "Alert"),
            severity=data.get("severity", "medium"),
            body=data.get("body", ""),
            container_id=data.get("container_id", ""),
            image_name=data.get("image_name", ""),
            alert_id=data.get("alert_id", ""),
            metadata=data.get("metadata"),
        )
        return self.dispatch(msg, channels=channels)

    def channel_stats(self) -> list[dict]:
        return [
            {"name": c.name, "sent": c.sent_count}
            for c in self._channels
        ]

    def summary(self) -> dict:
        return {
            "channels": len(self._channels),
            "total_dispatched": self._dispatch_count,
            "channels_stats": self.channel_stats(),
        }

    # -- Cooldown helpers --------------------------------------------------- #

    def _in_cooldown(self, key: str) -> bool:
        last = self._cooldowns.get(key, 0)
        return (time.time() - last) < self._cooldown

    def _set_cooldown(self, key: str) -> None:
        self._cooldowns[key] = time.time()
        # Evict old entries
        cutoff = time.time() - self._cooldown * 2
        self._cooldowns = {
            k: v for k, v in self._cooldowns.items()
            if v > cutoff
        }
