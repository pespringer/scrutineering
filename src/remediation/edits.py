"""Guarded, deterministic remediation file edits."""

from __future__ import annotations

from pathlib import Path


def replace_text(worktree: str | Path, relative_path: str, expected: str, replacement: str, *, expected_count: int = 1) -> Path:
    """Replace an exact text match inside a worktree; reject ambiguity/traversal."""
    if not expected or expected_count < 1:
        raise ValueError("expected text and positive expected_count are required")
    root = Path(worktree).resolve()
    target = (root / relative_path).resolve()
    if target != root and root not in target.parents:
        raise ValueError("edit path escapes worktree")
    if not target.is_file():
        raise FileNotFoundError(relative_path)
    content = target.read_text(encoding="utf-8")
    count = content.count(expected)
    if count != expected_count:
        raise ValueError(f"expected {expected_count} matches in {relative_path}, found {count}")
    target.write_text(content.replace(expected, replacement), encoding="utf-8")
    return target
