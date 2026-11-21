"""People who sign in, recorded for access reviews (docs/design/multi-user-roles.md, step 3).

The API records each identity the forward-auth proxy vouches for: its subject, email and roles. A
person is written at most once an hour, unless their email or roles change, and deleted after a year
unseen. Their subject stays in the audit log, which is history.
"""

from __future__ import annotations

import logging
import threading
from datetime import datetime, timedelta

from celery import shared_task
from sqlalchemy.exc import IntegrityError

from src.db.connection import get_session
from src.db.models import Principal
from src.scan.deployments import utcnow

logger = logging.getLogger(__name__)

RECORD_EVERY = timedelta(hours=1)
FORGET_AFTER = timedelta(days=365)

_lock = threading.Lock()
_recorded: dict[str, tuple[datetime, str | None, tuple[str, ...]]] = {}


def due(subject: str, email: str | None, roles: list[str], now: datetime) -> bool:
    """Whether this sign-in needs writing: first time in this process, an hour on, or changed details."""
    with _lock:
        last = _recorded.get(subject)
        return last is None or now - last[0] >= RECORD_EVERY or last[1:] != (email, tuple(roles))


def record(subject: str, email: str | None, roles: list[str], now: datetime | None = None) -> None:
    now = now or utcnow()
    with get_session() as session:
        principal = session.query(Principal).filter(Principal.subject == subject).one_or_none()
        if principal is None:
            principal = Principal(subject=subject, first_seen_at=now)
            session.add(principal)
        principal.email = email
        principal.roles = list(roles)
        principal.last_seen_at = now
    with _lock:
        _recorded[subject] = (now, email, tuple(roles))


def seen(subject: str, email: str | None, roles: list[str]) -> None:
    """Record a sign-in if due. Never fails the request that triggered it."""
    now = utcnow()
    if not due(subject, email, roles, now):
        return
    try:
        record(subject, email, roles, now)
    except IntegrityError:
        pass  # another API process recorded the same person first
    except Exception:  # noqa: BLE001 - a bookkeeping failure must not block sign-in
        logger.exception("could not record principal %s", subject)


def is_known(subject: str) -> bool:
    with get_session() as session:
        return session.query(Principal.id).filter(Principal.subject == subject).first() is not None


def prune(now: datetime | None = None) -> int:
    now = now or utcnow()
    with get_session() as session:
        old = session.query(Principal).filter(Principal.last_seen_at < now - FORGET_AFTER).all()
        subjects = [principal.subject for principal in old]
        for principal in old:
            session.delete(principal)
    with _lock:
        for subject in subjects:
            _recorded.pop(subject, None)
    return len(subjects)


@shared_task(name="src.api.principals.prune_principals", acks_late=True, ignore_result=True)
def prune_principals() -> int:
    """Daily, from beat."""
    return prune()
