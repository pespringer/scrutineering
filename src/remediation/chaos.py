"""Deterministic failure plans used by recovery drills."""

from dataclasses import dataclass


@dataclass(frozen=True)
class FailurePlan:
    failures_before_success: int = 0
    failure_kind: str = "timeout"

    def outcome(self, attempt: int) -> str:
        if attempt <= self.failures_before_success:
            return self.failure_kind
        return "success"
