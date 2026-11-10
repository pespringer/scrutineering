"""In-memory lifecycle coordinator for remediation execution stages."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Iterable

from src.db.models import RemediationStatus
from .state_machine import transition


@dataclass
class RemediationLifecycle:
    status: RemediationStatus = RemediationStatus.PENDING
    history: list[RemediationStatus] = field(default_factory=lambda: [RemediationStatus.PENDING])
    remediation_id: int | None = None
    event_sink: Callable[[dict], None] | None = None
    events: list[dict] = field(default_factory=list)

    def advance(self, target: RemediationStatus) -> RemediationStatus:
        self.status = transition(self.status, target)
        if not self.history or self.history[-1] != self.status:
            self.history.append(self.status)
        event = {
            "remediation_id": self.remediation_id,
            "event_type": self.status.value,
            "sequence": len(self.events) + 1,
            "detail": {"from": self.history[-2].value if len(self.history) > 1 else "pending", "to": self.status.value},
        }
        self.events.append(event)
        if self.event_sink is not None:
            self.event_sink(event)
        return self.status

    def fail(self) -> RemediationStatus:
        return self.advance(RemediationStatus.FAILED)

    @property
    def terminal(self) -> bool:
        return self.status in {RemediationStatus.COMPLETED, RemediationStatus.FAILED, RemediationStatus.SKIPPED}

    @classmethod
    def recover(cls, event_records: Iterable[dict], *, remediation_id: int | None = None):
        """Rebuild a lifecycle from durable ordered events and fail on gaps."""
        lifecycle = cls(remediation_id=remediation_id)
        records = sorted(event_records, key=lambda record: record.get("sequence", 0))
        for expected, record in enumerate(records, 1):
            if record.get("sequence") != expected:
                raise ValueError("remediation event sequence contains a gap")
            target = RemediationStatus(record.get("event_type"))
            lifecycle.advance(target)
        lifecycle.events = [dict(record) for record in records]
        return lifecycle
