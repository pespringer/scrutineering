"""Remediations keep the source they were approved with; audit records are hash-chained.

docs/design/security-hardening.md.

Revision ID: 0018_security_hardening
Revises: 0017_principals
"""

import hashlib
import json
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0018_security_hardening"
down_revision: Union[str, None] = "0017_principals"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

SOURCE_FIELDS = ("repository", "ref", "dockerfile_path", "build_context", "build_args", "test_command")

remediations = sa.table("remediations", sa.column("id", sa.BigInteger), sa.column("image_id", sa.BigInteger))
image_sources = sa.table(
    "image_sources",
    sa.column("image_id", sa.BigInteger),
    sa.column("repository", sa.String),
    sa.column("ref", sa.String),
    sa.column("dockerfile_path", sa.String),
    sa.column("build_context", sa.String),
    sa.column("build_args", sa.JSON),
    sa.column("test_command", sa.JSON),
)
audit_log = sa.table(
    "audit_log",
    sa.column("id", sa.BigInteger),
    sa.column("timestamp", sa.DateTime),
    sa.column("event_type", sa.String),
    sa.column("entity_type", sa.String),
    sa.column("entity_id", sa.String),
    sa.column("actor", sa.String),
    sa.column("actor_kind", sa.String),
    sa.column("detail", sa.JSON),
    sa.column("previous_hash", sa.String),
    sa.column("record_hash", sa.String),
)


def record_hash(previous_hash: str, row) -> str:
    """A frozen copy of src.db.audit_chain.record_hash; tests/test_audit_chain.py keeps them equal."""
    fields = {
        "timestamp": row.timestamp.isoformat(timespec="microseconds"),
        "event_type": row.event_type,
        "entity_type": row.entity_type,
        "entity_id": row.entity_id,
        "actor": row.actor,
        "actor_kind": row.actor_kind,
        "detail": row.detail or {},
    }
    document = json.dumps(fields, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(f"{previous_hash}\n{document}".encode()).hexdigest()


def upgrade() -> None:
    with op.batch_alter_table("remediations") as batch:
        batch.add_column(sa.Column("source", sa.JSON(), nullable=True))
    bind = op.get_bind()
    with_source = sa.table("remediations", sa.column("id", sa.BigInteger), sa.column("source", sa.JSON))
    rows = bind.execute(
        sa.select(remediations.c.id, *(image_sources.c[name] for name in SOURCE_FIELDS)).join(
            image_sources, image_sources.c.image_id == remediations.c.image_id
        )
    ).all()
    for row in rows:
        source = {name: getattr(row, name) for name in SOURCE_FIELDS}
        source["build_args"] = source["build_args"] or {}
        bind.execute(sa.update(with_source).where(with_source.c.id == row.id).values(source=source))

    previous = ""
    for row in bind.execute(sa.select(audit_log).order_by(audit_log.c.id)).all():
        current = record_hash(previous, row)
        bind.execute(
            sa.update(audit_log).where(audit_log.c.id == row.id).values(previous_hash=previous, record_hash=current)
        )
        previous = current


def downgrade() -> None:
    bind = op.get_bind()
    bind.execute(sa.update(audit_log).values(previous_hash=None, record_hash=None))
    with op.batch_alter_table("remediations") as batch:
        batch.drop_column("source")
