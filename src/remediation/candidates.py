"""Daily cleanup: candidates are deleted from the registry 30 days after their remediation ended.

See docs/design/registry-management.md. It starts from the tags the registry holds, so a candidate
already deleted costs nothing, and deletes through the same checks and locks as an operator does
(src/scan/registry_delete.py). A tag the records don't match is left for an operator: its ID may come
from an earlier database.
"""

from __future__ import annotations

import logging
from collections import Counter
from datetime import datetime, timedelta

from celery import shared_task
from sqlalchemy.orm import Session

from src.db.connection import get_session
from src.db.models import Remediation
from src.db.repositories import RemediationRepository
from src.remediation.state_machine import TERMINAL
from src.scan.deployments import utcnow
from src.scan.registry_catalog import RegistryClient, RegistryError
from src.scan.registry_delete import CANDIDATE_TAG, Refused, Tag, delete_tag

logger = logging.getLogger(__name__)

RETENTION = timedelta(days=30)
# The registry answers these for every tag, so the run ends there.
REFUSES_ALL = frozenset({"registry_delete_disabled", "registry_delete_unsupported"})


def _candidate_tags(client: RegistryClient) -> dict[int, list[Tag]]:
    """Every candidate tag in the registry, by the remediation ID in its name."""
    tags: dict[int, list[Tag]] = {}
    for repository in client.repositories():
        try:
            names = client.tags(repository)
        except RegistryError as error:
            logger.warning("could not list the tags of %s: %s", repository, error)
            continue
        for name in names:
            if match := CANDIDATE_TAG.fullmatch(name):
                tags.setdefault(int(match.group(1)), []).append(Tag(repository, name))
    return tags


def _due_digest(session: Session, remediation_id: int, tag: Tag, cutoff: datetime) -> str | None:
    """The digest recorded for `tag`, if it's this remediation's candidate and is due now.

    `completed_at` alone doesn't say it ended: a retry leaves it set.
    """
    columns = (Remediation.status, Remediation.completed_at, Remediation.candidate_image, Remediation.candidate_digest)
    row = session.query(*columns).filter(Remediation.id == remediation_id).one_or_none()
    if row is None or row.status not in TERMINAL or row.candidate_image != tag.name:
        return None
    if row.completed_at is None or row.completed_at >= cutoff:
        return None
    return row.candidate_digest


def _prune_one(client: RegistryClient, remediation_id: int, tag: Tag, cutoff: datetime) -> str | None:
    """Delete one candidate if it's due, in its own transaction. Returns what happened, or None if it isn't due."""
    removed = False
    try:
        with get_session() as session:
            digest = _due_digest(session, remediation_id, tag, cutoff)
            if digest is None:
                return None

            def still_due() -> None:
                if _due_digest(session, remediation_id, tag, cutoff) != digest:
                    raise Refused("not_due", "Its remediation was run again meanwhile.")

            archived = delete_tag(session, client, tag, digest, still_due=still_due)
            removed = True
            detail = {"candidate": tag.name, "digest": digest, "archived_image_ids": archived}
            RemediationRepository.record_event(session, remediation_id, "candidate_deleted", detail)
    except Refused as refused:
        logger.info("kept %s (%s)", tag.name, refused.code)
        return refused.code
    except Exception:
        if not removed:
            logger.exception("could not delete %s", tag.name)
            return "delete_failed"
        logger.exception("deleted %s from the registry, but could not record it", tag.name)
        return "delete_not_recorded"
    return "deleted"


def prune(now: datetime | None = None) -> dict[str, int]:
    """Delete every candidate that is due. Returns how many had each outcome."""
    cutoff = (now or utcnow()) - RETENTION
    client = RegistryClient.local()
    try:
        candidates = _candidate_tags(client)
    except RegistryError as error:
        logger.warning("could not look for old candidates: %s", error)
        return {}
    outcomes: Counter = Counter()
    for remediation_id, tags in sorted(candidates.items()):
        for tag in tags:
            outcome = _prune_one(client, remediation_id, tag, cutoff)
            if outcome is not None:
                outcomes[outcome] += 1
            if outcome in REFUSES_ALL:
                logger.warning("candidates aren't cleaned up: %s", outcome)
                return dict(outcomes)
    if outcomes:
        logger.info("candidates ended over %d days ago: %s", RETENTION.days, dict(outcomes))
    return dict(outcomes)


@shared_task(name="src.remediation.candidates.prune_candidates", acks_late=True, ignore_result=True)
def prune_candidates() -> dict[str, int]:
    """Daily, from beat."""
    return prune()
