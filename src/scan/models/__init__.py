"""Backwards-compat shim — re-exports from new db package.

Legacy code (src/scan/utils/db.py, src/scan/models/) imports from
src.scan.models. These re-exports ensure the old code continues
to work after the refactor.
"""

from src.db.models import (
    Base,
    Severity,
    FindingSource,
    ScanFinding as ScanFinding,
)

__all__ = ["Base", "Severity", "FindingSource", "ScanFinding"]
