"""Container-level audit logging for forensic investigations.

Provides an append-only audit trail of all security-relevant events
within containers, backed by PostgreSQL for persistence and queryable
through a simple API.

Acceptance criteria covered:
  - Container-level audit logging
  - Append-only audit trail (immutable records)
  - Integration with the ContainerRuntime DB model
  - Queryable audit events for incident investigation
"""

from __future__ import annotations

import json
import hashlib
import logging
import time
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Sequence

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


def verify_audit_chain(records: Sequence[dict[str, Any]]) -> bool:
    """Verify ordering, previous links, and record hashes in exported records."""
    previous = ""
    for record in reversed(list(records)):
        if record.get("previous_hash", "") != previous:
            return False
        payload = {key: value for key, value in record.items() if key != "record_hash"}
        canonical = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
        digest = hashlib.sha256(canonical.encode()).hexdigest()
        if record.get("record_hash") != digest:
            return False
        previous = digest
    return True


# ---------------------------------------------------------------------------
# Audit record
# ---------------------------------------------------------------------------

@dataclass(slots=True, frozen=True)
class AuditRecord:
    """A single immutable audit log entry."""
    record_id: str
    container_id: str
    event_type: str
    timestamp: datetime
    severity: str = "info"
    actor: str = "system"
    action: str = ""
    subject: str = ""
    detail: dict[str, Any] = field(default_factory=dict)
    source: str = "audit_logger"
    previous_hash: str = ""
    record_hash: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_id": self.record_id,
            "container_id": self.container_id,
            "event_type": self.event_type,
            "timestamp": self.timestamp.isoformat(),
            "severity": self.severity,
            "actor": self.actor,
            "action": self.action,
            "subject": self.subject,
            "detail": self.detail,
            "source": self.source,
            "previous_hash": self.previous_hash,
            "record_hash": self.record_hash,
        }


# ---------------------------------------------------------------------------
# Well-known event types
# ---------------------------------------------------------------------------

class AuditEvent:
    CONTAINER_START     = "container_start"
    CONTAINER_STOP      = "container_stop"
    CONTAINER_RESTART   = "container_restart"
    EXEC_COMMAND        = "exec_command"
    FILE_MODIFIED       = "file_modified"
    FILE_CREATED        = "file_created"
    FILE_DELETED        = "file_deleted"
    NETWORK_CONNECT     = "network_connect"
    NETWORK_LISTEN      = "network_listen"
    PRIVILEGE_CHANGE    = "privilege_change"
    CONFIG_CHANGE       = "config_change"
    MOUNT_CHANGE        = "mount_change"
    USER_LOGIN          = "user_login"
    SCAN_INITIATED      = "scan_initiated"
    SCAN_COMPLETED      = "scan_completed"
    ANOMALY_DETECTED    = "anomaly_detected"
    ALERT_CREATED       = "alert_created"
    REMEDIATION_STARTED = "remediation_started"
    REMEDIATION_FAILED  = "remediation_failed"
    SNAPSHOT_CAPTURED   = "snapshot_captured"
    REPORT_GENERATED    = "report_generated"


# ---------------------------------------------------------------------------
# In-memory audit log (lightweight, for non-DB scenarios)
# ---------------------------------------------------------------------------

class AuditLogger:
    """Append-only audit logger with optional DB persistence.

    Usage:
        logger = AuditLogger()
        logger.log(AuditEvent.ANOMALY_DETECTED, "abc123", "High",
                   detail={"kind": "privilege_escalation"})
        records = logger.query(container_id="abc123")
    """

    # Well-known event types exposed as class attr
    EVENT = AuditEvent

    def __init__(
        self,
        max_records: int = 50_000,
        db_session_factory=None,  # callable returning a session
    ):
        if max_records < 1: raise ValueError("max_records must be positive")
        self._max_records = max_records
        self._records: list[AuditRecord] = []
        self._counter = 0
        self._last_hash = ""
        self._get_session = db_session_factory

    # -- Core logging ------------------------------------------------------- #

    def log(
        self,
        event_type: str,
        container_id: str,
        severity: str = "info",
        actor: str = "system",
        action: str = "",
        subject: str = "",
        detail: dict[str, Any] | None = None,
        persist: bool = True,
    ) -> AuditRecord:
        """Append a new audit record (immutable, append-only)."""
        self._counter += 1
        record_id = f"AUDIT-{int(time.time() * 1000):x}-{self._counter:x}"
        record_fields = dict(
            record_id=record_id,
            container_id=container_id,
            event_type=event_type,
            timestamp=datetime.now(timezone.utc),
            severity=severity,
            actor=actor,
            action=action or event_type,
            subject=subject,
            detail=detail or {},
            previous_hash=self._last_hash,
        )
        draft = AuditRecord(**record_fields, record_hash="")
        canonical = json.dumps({key: value for key, value in draft.to_dict().items() if key != "record_hash"}, sort_keys=True, separators=(",", ":"))
        record = replace(draft, record_hash=hashlib.sha256(canonical.encode()).hexdigest())
        self._last_hash = record.record_hash
        self._records.append(record)

        # Evict oldest if over max
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records:]

        # Persist to DB if configured
        if persist and self._get_session:
            self._persist_to_db(record)

        return record

    def export(self) -> list[dict[str, Any]]:
        records = [record.to_dict() for record in self._records]
        if not verify_audit_chain(records): raise RuntimeError("audit chain integrity check failed")
        return records

    def persist_record(self, record: AuditRecord) -> None:
        """Persist a single audit record to the database."""
        if not self._get_session:
            return
        self._persist_to_db(record)

    def _persist_to_db(self, record: AuditRecord) -> None:
        """Write the audit record to the audit_log table."""
        try:
            session: Session = self._get_session()
            from src.db.models import AuditLog, AuditEventType
            from src.db.models import ContainerRuntime

            # Map event_type strings to AuditEventType enums where possible
            event_map = {
                AuditEvent.SCAN_INITIATED: AuditEventType.SCAN_STARTED,
                AuditEvent.SCAN_COMPLETED: AuditEventType.SCAN_COMPLETED,
                AuditEvent.ANOMALY_DETECTED: AuditEventType.SYSTEM_ERROR,
                AuditEvent.ALERT_CREATED: AuditEventType.SYSTEM_ERROR,
                AuditEvent.REMEDIATION_STARTED: AuditEventType.REMEDIATION_STARTED,
                AuditEvent.REMEDIATION_FAILED: AuditEventType.REMEDIATION_FAILED,
                AuditEvent.REPORT_GENERATED: AuditEventType.COMPLIANCE_REPORT_GENERATED,
            }
            db_event_type = event_map.get(record.event_type, AuditEventType.SYSTEM_ERROR)

            entry = AuditLog(
                event_type=db_event_type,
                entity_type="runtime_event",
                entity_id=record.record_id,
                detail=record.to_dict(),
                previous_hash=record.previous_hash,
                record_hash=record.record_hash,
                actor=record.actor,
                actor_kind="runtime",
            )
            session.add(entry)
            session.commit()
        except Exception:
            logger.exception("Failed to persist audit record %s", record.record_id)

    # -- Convenience loggers ------------------------------------------------ #

    def log_container_lifecycle(
        self, container_id: str, status: str, detail: dict | None = None
    ) -> AuditRecord:
        event_map = {
            "start": AuditEvent.CONTAINER_START,
            "stop": AuditEvent.CONTAINER_STOP,
            "restart": AuditEvent.CONTAINER_RESTART,
            "die": AuditEvent.CONTAINER_STOP,
            "pause": AuditEvent.CONTAINER_STOP,
            "unpause": AuditEvent.CONTAINER_START,
        }
        event_type = event_map.get(status.lower(), AuditEvent.CONTAINER_START)
        return self.log(
            event_type=event_type,
            container_id=container_id,
            severity="info",
            action=f"container_{status}",
            subject=container_id[:12],
            detail=detail or {"status": status},
        )

    def log_exec(
        self, container_id: str, command: str, user: str = "root"
    ) -> AuditRecord:
        return self.log(
            event_type=AuditEvent.EXEC_COMMAND,
            container_id=container_id,
            severity="medium",
            actor=user,
            action="exec",
            subject=command,
            detail={"command": command, "user": user},
        )

    def log_file_change(
        self, container_id: str, path: str, action: str, detail: dict | None = None
    ) -> AuditRecord:
        event_map = {
            "create": AuditEvent.FILE_CREATED,
            "modify": AuditEvent.FILE_MODIFIED,
            "delete": AuditEvent.FILE_DELETED,
        }
        event_type = event_map.get(action.lower(), AuditEvent.FILE_MODIFIED)
        return self.log(
            event_type=event_type,
            container_id=container_id,
            severity="medium",
            action=f"file_{action}",
            subject=path,
            detail={"path": path, "action": action, **(detail or {})},
        )

    def log_network_event(
        self, container_id: str, remote: str, port: int, direction: str = "outbound"
    ) -> AuditRecord:
        return self.log(
            event_type=AuditEvent.NETWORK_CONNECT,
            container_id=container_id,
            severity="low",
            action=f"network_{direction}",
            subject=remote,
            detail={"remote": remote, "port": port, "direction": direction},
        )

    def log_privilege_change(
        self, container_id: str, old_user: str, new_user: str,
        syscall: str = "", detail: dict | None = None
    ) -> AuditRecord:
        return self.log(
            event_type=AuditEvent.PRIVILEGE_CHANGE,
            container_id=container_id,
            severity="high",
            action="privilege_change",
            subject=f"{old_user} -> {new_user}",
            detail={
                "old_user": old_user,
                "new_user": new_user,
                "syscall": syscall,
                **(detail or {}),
            },
        )

    # -- Queries ------------------------------------------------------------ #

    def query(
        self,
        container_id: str | None = None,
        event_type: str | None = None,
        min_severity: str | None = None,
        since: datetime | None = None,
        to: datetime | None = None,
        limit: int = 500,
        reverse: bool = True,
    ) -> list[dict[str, Any]]:
        """Query audit records with filtering."""
        severity_rank = {
            "critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0
        }
        min_rank = severity_rank.get(min_severity, 0) if min_severity else 0

        results: list[AuditRecord] = []
        for record in self._records:
            if container_id and record.container_id != container_id:
                continue
            if event_type and record.event_type != event_type:
                continue
            if severity_rank.get(record.severity, 0) < min_rank:
                continue
            if since and record.timestamp < since:
                continue
            if to and record.timestamp > to:
                continue
            results.append(record)
            if len(results) >= limit:
                break

        if reverse:
            results.reverse()
        return [r.to_dict() for r in results]

    def get_record(self, record_id: str) -> dict[str, Any] | None:
        """Retrieve a single audit record by ID."""
        for record in self._records:
            if record.record_id == record_id:
                return record.to_dict()
        return None

    def summary(
        self, container_id: str | None = None
    ) -> dict[str, Any]:
        """Return summary statistics."""
        by_event: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        for record in self._records:
            if container_id and record.container_id != container_id:
                continue
            by_event[record.event_type] = by_event.get(record.event_type, 0) + 1
            by_severity[record.severity] = by_severity.get(record.severity, 0) + 1
        return {
            "total_records": sum(by_event.values()),
            "by_event_type": by_event,
            "by_severity": by_severity,
        }

    def export_json(self) -> str:
        """Export the entire audit log as JSON."""
        return json.dumps(
            [r.to_dict() for r in self._records],
            indent=2,
            default=str,
        )

    def clear(self) -> None:
        """Clear the in-memory log (does not affect persisted records)."""
        self._records.clear()
        self._last_hash = ""
        self._counter = 0
