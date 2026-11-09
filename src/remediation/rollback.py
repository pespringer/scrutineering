"""Validated rollback plans for published remediation changes."""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class RollbackPlan:
    merge_commit: str
    command: tuple[str, ...]
    verification_required: bool = True


def build_rollback_plan(merge_commit: str) -> RollbackPlan:
    if not re.fullmatch(r"[0-9a-f]{7,64}", merge_commit or ""):
        raise ValueError("merge_commit must be a hexadecimal Git commit ID")
    return RollbackPlan(
        merge_commit=merge_commit,
        command=("git", "revert", "--no-edit", merge_commit),
    )
