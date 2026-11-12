"""Provider publication reconciliation and stale-record policy."""

from __future__ import annotations

from datetime import datetime, timezone


RECONCILIABLE_STATUSES = frozenset({"pending", "failed", "merged"})


def publication_age_seconds(publication, *, now: datetime | None = None) -> int:
    """Return the age of the latest relevant publication timestamp."""
    reference = publication.completed_at or publication.merged_at or publication.created_at
    if reference is None:
        return 0
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    if reference.tzinfo is None:
        reference = reference.replace(tzinfo=timezone.utc)
    return max(0, int((current - reference).total_seconds()))


def publication_is_stale(publication, *, stale_after_seconds: int, now: datetime | None = None) -> bool:
    """Identify records that need operator reconciliation.

    A verified merge is terminal and never stale. Pending, failed, and merged
    records remain actionable when their latest state is older than the
    configured threshold; this includes merged records missing verification.
    """
    if publication.status not in RECONCILIABLE_STATUSES:
        return False
    if publication.status == "merged" and publication.verification_status == "verified":
        return False
    return publication_age_seconds(publication, now=now) >= stale_after_seconds
