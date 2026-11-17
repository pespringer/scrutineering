"""Which Celery queue and priority a scan runs at."""

from __future__ import annotations


PRIORITIES = {"low": 2, "normal": 5, "high": 9}


def scan_task_options(priority: str) -> dict[str, int | str]:
    key = str(priority).lower()
    if key not in PRIORITIES:
        raise ValueError(f"unknown scan priority: {priority}")
    return {"queue": f"scan.{key}", "priority": PRIORITIES[key]}
