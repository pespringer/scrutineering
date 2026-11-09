"""In-memory lifecycle coordinator for remediation execution stages."""

from __future__ import annotations

from dataclasses import dataclass, field

from src.db.models import RemediationStatus
from .state_machine import transition


@dataclass
class RemediationLifecycle:
    status: RemediationStatus = RemediationStatus.PENDING
    history: list[RemediationStatus] = field(default_factory=lambda: [RemediationStatus.PENDING])

    def advance(self, target: RemediationStatus) -> RemediationStatus:
        self.status = transition(self.status, target)
        if not self.history or self.history[-1] != self.status:
            self.history.append(self.status)
        return self.status

    def fail(self) -> RemediationStatus:
        return self.advance(RemediationStatus.FAILED)

    @property
    def terminal(self) -> bool:
        return self.status in {RemediationStatus.COMPLETED, RemediationStatus.FAILED, RemediationStatus.SKIPPED}
