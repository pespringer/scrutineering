"""The audit log's hash chain (docs/design/security-hardening.md).

Each record's `record_hash` covers its own fields and the previous record's hash, so changing, inserting or
deleting a record breaks every hash after it. Migration 0018 carries its own copy of `record_hash`; a test
keeps the two identical.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable

from src.db.models import AuditLog

logger = logging.getLogger(__name__)

# pg_advisory_xact_lock key that serialises audit writes, so the chain can't fork.
LOCK_KEY = 0x5C2A_0D17


def timestamp_text(value: datetime) -> str:
    return value.isoformat(timespec="microseconds")


def record_hash(
    previous_hash: str,
    *,
    timestamp: datetime,
    event_type: str,
    entity_type: str | None,
    entity_id: str | None,
    actor: str | None,
    actor_kind: str | None,
    detail: dict | None,
) -> str:
    """sha256 of the previous hash, a newline, and the record's fields as sorted, compact JSON."""
    fields = {
        "timestamp": timestamp_text(timestamp),
        "event_type": event_type,
        "entity_type": entity_type,
        "entity_id": entity_id,
        "actor": actor,
        "actor_kind": actor_kind,
        "detail": detail or {},
    }
    document = json.dumps(fields, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(f"{previous_hash}\n{document}".encode()).hexdigest()


def hash_of(record, previous_hash: str) -> str:
    """The hash an `AuditLog` row should carry, given the hash before it."""
    event_type = getattr(record.event_type, "value", record.event_type)
    return record_hash(
        previous_hash,
        timestamp=record.timestamp,
        event_type=event_type,
        entity_type=record.entity_type,
        entity_id=record.entity_id,
        actor=record.actor,
        actor_kind=record.actor_kind,
        detail=record.detail,
    )


@dataclass(frozen=True)
class Verification:
    intact: bool
    records: int
    first_broken_id: int | None

    def as_dict(self) -> dict:
        return {"intact": self.intact, "records": self.records, "first_broken_id": self.first_broken_id}


def verify(records: Iterable) -> Verification:
    """Walk `AuditLog` rows in id order from the first; report the first that doesn't chain."""
    previous = ""
    count = 0
    for record in records:
        count += 1
        if record.previous_hash != previous or record.record_hash != hash_of(record, previous):
            return Verification(False, count, record.id)
        previous = record.record_hash
    return Verification(True, count, None)


def verify_all(session) -> Verification:
    """Check the whole audit log, reading it in batches."""
    return verify(session.query(AuditLog).order_by(AuditLog.id.asc()).yield_per(1000))


STATUS_KEY = "scrutineering:audit-chain"
STATUS_TTL_SECONDS = 2 * 24 * 3600  # the check runs daily; a missed run shows as "not checked", not stale


def save_status(status: dict, redis_url: str) -> None:
    import redis

    try:
        redis.Redis.from_url(redis_url, socket_timeout=2, socket_connect_timeout=2).set(
            STATUS_KEY, json.dumps(status), ex=STATUS_TTL_SECONDS
        )
    except Exception as exc:  # noqa: BLE001 - the status panel then says nothing about the chain
        logger.warning("could not save the audit chain status: %s", exc)


def load_status(redis_url: str) -> dict | None:
    import redis

    try:
        raw = redis.Redis.from_url(redis_url, socket_timeout=2, socket_connect_timeout=2).get(STATUS_KEY)
        return json.loads(raw) if raw else None
    except Exception:  # noqa: BLE001
        return None
