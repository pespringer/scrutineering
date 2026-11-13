"""Scan health summaries for operator dashboards and smoke tests."""

from __future__ import annotations

from collections import Counter


def summarize_scan_health(records: list[dict]) -> dict[str, object]:
    counts = Counter(str(record.get("status", "unknown")) for record in records)
    total = len(records)
    terminal = sum(counts.get(status, 0) for status in ("completed", "partial", "failed", "cancelled"))
    return {"total": total, "by_status": dict(sorted(counts.items())), "terminal": terminal, "terminal_rate": terminal / total if total else 0.0, "degraded": counts.get("partial", 0) > 0 or counts.get("failed", 0) > 0}
