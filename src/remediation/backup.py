"""Portable backup manifest and restore-preflight helpers."""

from __future__ import annotations

from pathlib import Path

from src.platform.controls import backup_manifest, verify_backup


def write_backup_manifest(records: list[dict], path: str | Path, *, source: str = "postgres") -> dict:
    value = backup_manifest(records, source=source)
    Path(path).write_text(__import__("json").dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return value


def verify_restore_preflight(records: list[dict], manifest: dict) -> bool:
    return verify_backup(records, manifest)
