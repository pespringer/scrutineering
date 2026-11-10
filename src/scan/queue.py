"""Deterministic queue and priority policy for scan scheduling."""

from __future__ import annotations


PRIORITIES = {"low": 2, "normal": 5, "high": 9}


def load_queue_config(env: dict[str, str] | None = None) -> dict[str, object]:
    values = env or {}
    queues = str(values.get("CELERY_QUEUES", "scan.low,scan.normal,scan.high"))
    configured = {item.strip() for item in queues.split(",") if item.strip()}
    if len(configured) > 32: raise ValueError("too many configured queues")
    required = {f"scan.{name}" for name in PRIORITIES}
    missing = required - configured
    if missing:
        raise ValueError(f"CELERY_QUEUES is missing required queues: {', '.join(sorted(missing))}")
    return {"queues": tuple(sorted(configured)), "required": tuple(sorted(required)), "extra": tuple(sorted(configured - required))}


def scan_priority(severity: str | None = None, deadline: bool = False) -> str:
    if deadline or str(severity or "").lower() == "critical":
        return "high"
    if str(severity or "").lower() in {"low", "unknown"}:
        return "low"
    return "normal"


def scan_task_options(priority: str) -> dict[str, int | str]:
    key = str(priority).lower()
    if key not in PRIORITIES:
        raise ValueError(f"unknown scan priority: {priority}")
    return {"queue": f"scan.{key}", "priority": PRIORITIES[key]}
