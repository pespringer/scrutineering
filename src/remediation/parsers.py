"""Conservative, exact-match remediation parsers."""

from __future__ import annotations

import re


def update_dockerfile_base(text: str, old: str, new: str) -> str:
    if not old or not new or "\n" not in old and old not in text:
        raise ValueError("base image values are required")
    pattern = re.compile(rf"^(\s*FROM\s+){re.escape(old)}(\s*(?:AS\s+\S+)?\s*)$", re.MULTILINE)
    updated, count = pattern.subn(rf"\g<1>{new}\g<2>", text)
    if count != 1:
        raise ValueError("Dockerfile base image match must be unique")
    return updated


def update_exact_dependency(text: str, package: str, old: str, new: str) -> str:
    pattern = re.compile(rf"^(\s*{re.escape(package)}\s*[=~><!]+\s*){re.escape(old)}(\s*)$", re.MULTILINE)
    updated, count = pattern.subn(rf"\g<1>{new}\g<2>", text)
    if count != 1: raise ValueError("dependency match must be unique")
    return updated


def update_json_dependency(text: str, package: str, old: str, new: str) -> str:
    pattern = re.compile(rf'("{re.escape(package)}"\s*:\s*"){re.escape(old)}(")')
    updated, count = pattern.subn(rf"\g<1>{new}\g<2>", text)
    if count != 1: raise ValueError("JSON dependency match must be unique")
    return updated
