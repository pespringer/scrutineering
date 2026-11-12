"""Local queue governance rules independent of any alert receiver."""

from __future__ import annotations

from dataclasses import dataclass


PRIORITIES = {"critical": 0, "high": 1, "normal": 2, "low": 3}


@dataclass(frozen=True)
class QueuePolicy:
    max_batch: int = 100
    tenant_required: bool = False

    def validate(self, *, priority: str, tenant: str | None = None) -> None:
        if priority not in PRIORITIES:
            raise ValueError("invalid alert priority")
        if self.max_batch < 1 or self.max_batch > 1000:
            raise ValueError("invalid queue batch limit")
        if self.tenant_required and not tenant:
            raise ValueError("tenant is required for this queue")


def fair_order(records: list[dict]) -> list[dict]:
    return sorted(records, key=lambda item: (PRIORITIES.get(item.get("priority", "normal"), 2), item.get("created_at", ""), item.get("id", 0)))


def compatible_payload(payload: dict, supported: tuple[str, ...] = ("alert-v1",)) -> bool:
    return payload.get("schema_version") in supported
