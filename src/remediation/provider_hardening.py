"""Provider request budgets, redaction, and circuit-state diagnostics."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ProviderRequestBudget:
    maximum_requests: int = 60
    used_requests: int = 0

    def admit(self) -> "ProviderRequestBudget":
        if self.maximum_requests < 1 or self.used_requests < 0:
            raise ValueError("invalid provider request budget")
        if self.used_requests >= self.maximum_requests:
            raise ValueError("provider request budget exhausted")
        return ProviderRequestBudget(self.maximum_requests, self.used_requests + 1)


def redact_provider_payload(payload: object, *, secret_keys: set[str] | None = None) -> object:
    keys = secret_keys or {"token", "authorization", "private-token", "password", "secret"}
    if isinstance(payload, dict):
        return {key: "[REDACTED]" if key.lower() in keys else redact_provider_payload(value, secret_keys=keys) for key, value in payload.items()}
    if isinstance(payload, list):
        return [redact_provider_payload(value, secret_keys=keys) for value in payload]
    return payload


def circuit_state(*, failures: int, threshold: int, opened: bool) -> dict[str, object]:
    if failures < 0 or threshold < 1:
        raise ValueError("invalid circuit state")
    return {"state": "open" if opened else "closed", "failures": failures, "threshold": threshold, "admit": not opened}
