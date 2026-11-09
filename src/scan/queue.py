"""Deterministic queue and priority policy for scan scheduling."""

from __future__ import annotations


PRIORITIES = {"low": 2, "normal": 5, "high": 9}


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
