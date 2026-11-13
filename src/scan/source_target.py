"""Explicit filesystem scan target parsing and safe source-path normalization."""

from __future__ import annotations

from pathlib import Path


def filesystem_path(target: str) -> Path | None:
    value = str(target or "")
    if not value.startswith("fs:"):
        return None
    path = Path(value[3:]).expanduser().resolve()
    if not path.is_dir():
        raise ValueError("filesystem scan target must be an existing directory")
    return path


def storage_reference(target: str) -> str:
    path = filesystem_path(target)
    if path is None:
        return target
    name = "".join(char if char.isalnum() or char in {"-", "_"} else "-" for char in path.name).strip("-") or "repository"
    return f"local/{name}:filesystem"


def relative_source_path(path: str | None, root: Path) -> str | None:
    if not path:
        return None
    candidate = Path(path)
    try:
        relative = candidate.resolve().relative_to(root.resolve()) if candidate.is_absolute() else candidate
    except ValueError:
        return None
    value = relative.as_posix()
    if not value or value.startswith("/") or ".." in Path(value).parts:
        return None
    return value
