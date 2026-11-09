"""Versioned provenance metadata attached to scan evidence."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone


@dataclass(frozen=True)
class ScannerProvenance:
    """The exact tool/database versions used to produce scan evidence."""

    scanner: str
    scanner_version: str
    vulnerability_db_version: str | None = None

    def __post_init__(self) -> None:
        if not self.scanner.strip():
            raise ValueError("scanner must not be empty")
        if not self.scanner_version.strip():
            raise ValueError("scanner_version must not be empty")

    def as_dict(self) -> dict[str, str | None]:
        return asdict(self)


def provenance_maps(records: list[ScannerProvenance]) -> tuple[dict[str, str], dict[str, str]]:
    """Convert provenance records to stable scanner/database maps."""
    scanner_versions: dict[str, str] = {}
    database_versions: dict[str, str] = {}
    for record in records:
        scanner_versions[record.scanner] = record.scanner_version
        if record.vulnerability_db_version:
            database_versions[record.scanner] = record.vulnerability_db_version
    return dict(sorted(scanner_versions.items())), dict(sorted(database_versions.items()))


def validate_database_freshness(records: list[ScannerProvenance], max_age_days: int, now: datetime | None = None) -> bool:
    """Return false when any supplied vulnerability DB date is stale or absent."""
    if max_age_days < 0:
        raise ValueError("max_age_days must not be negative")
    cutoff = (now or datetime.now(timezone.utc)) - timedelta(days=max_age_days)
    for record in records:
        if not record.vulnerability_db_version:
            return False
        try:
            updated = datetime.fromisoformat(record.vulnerability_db_version.replace("Z", "+00:00"))
        except ValueError:
            return False
        if updated.tzinfo is None:
            updated = updated.replace(tzinfo=timezone.utc)
        if updated < cutoff:
            return False
    return True
