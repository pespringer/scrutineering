"""Conservative, exact-match remediation parsers."""

from __future__ import annotations

import re


def _replace_once(pattern: str, text: str, replacement: str, error: str = "dependency match must be unique") -> str:
    updated, count = re.subn(pattern, replacement, text, flags=re.MULTILINE)
    if count != 1:
        raise ValueError(error)
    return updated


def update_dockerfile_base(text: str, old: str, new: str) -> str:
    if not old or not new or "\n" not in old and old not in text:
        raise ValueError("base image values are required")
    pattern = re.compile(rf"^(\s*FROM\s+){re.escape(old)}(\s*(?:AS\s+\S+)?\s*)$", re.MULTILINE)
    updated, count = pattern.subn(rf"\g<1>{new}\g<2>", text)
    if count != 1:
        raise ValueError("Dockerfile base image match must be unique")
    return updated


def update_exact_dependency(text: str, package: str, old: str, new: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_.@/-]{1,256}", package): raise ValueError("invalid dependency name")
    pattern = re.compile(rf"^(\s*{re.escape(package)}\s*[=~><!]+\s*){re.escape(old)}(\s*)$", re.MULTILINE)
    updated, count = pattern.subn(rf"\g<1>{new}\g<2>", text)
    if count != 1: raise ValueError("dependency match must be unique")
    return updated


def update_json_dependency(text: str, package: str, old: str, new: str) -> str:
    pattern = re.compile(rf'("{re.escape(package)}"\s*:\s*"){re.escape(old)}(")')
    updated, count = pattern.subn(rf"\g<1>{new}\g<2>", text)
    if count != 1: raise ValueError("JSON dependency match must be unique")
    return updated


def update_requirements_dependency(text: str, package: str, old: str, new: str) -> str:
    """Update one pinned PEP 508 requirement without touching comments."""
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", package):
        raise ValueError("invalid Python dependency name")
    return _replace_once(
        rf"^(\s*{re.escape(package)}\s*==\s*){re.escape(old)}(\s*(?:#.*)?$)",
        text, rf"\g<1>{new}\g<2>",
    )


def update_go_module_dependency(text: str, package: str, old: str, new: str) -> str:
    """Update one exact ``require`` entry in a Go module file."""
    if not package or any(char.isspace() for char in package):
        raise ValueError("invalid Go module name")
    return _replace_once(
        rf"^(\s*{re.escape(package)}\s+){re.escape(old)}(\s*)$",
        text, rf"\g<1>{new}\g<2>",
    )


def update_cargo_dependency(text: str, package: str, old: str, new: str) -> str:
    """Update a simple pinned Cargo dependency declaration."""
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", package):
        raise ValueError("invalid Cargo dependency name")
    return _replace_once(
        rf"^(\s*{re.escape(package)}\s*=\s*\"\^?){re.escape(old)}(\"\s*)$",
        text, rf"\g<1>{new}\g<2>",
    )


def update_dependency_file(text: str, filename: str, package: str, old: str, new: str) -> str:
    """Dispatch to a conservative parser based on the manifest filename."""
    name = filename.rsplit("/", 1)[-1].lower()
    if name == "package.json":
        return update_json_dependency(text, package, old, new)
    if name in {"requirements.txt", "requirements-dev.txt"}:
        return update_requirements_dependency(text, package, old, new)
    if name == "go.mod":
        return update_go_module_dependency(text, package, old, new)
    if name == "cargo.toml":
        return update_cargo_dependency(text, package, old, new)
    raise ValueError(f"unsupported dependency manifest: {filename}")
