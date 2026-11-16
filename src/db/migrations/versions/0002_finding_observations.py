"""Record per-scan finding observations and stop rewriting finding history.

- New `finding_observations`: one row per (scan, finding) the scan saw.
- `scan_findings.vuln_key` (CVE + package, version-independent), backfilled.
- `scans.target`: the exact reference handed to the scanners.
- Drops `scan_findings.scan_id` (rewritten on every rescan, which erased scan
  history) after carrying it over as an observation, and the never-set
  `scan_findings.remediated` flag.

Revision ID: 0002_finding_observations
Revises: 0001_baseline
"""
import hashlib
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0002_finding_observations"
down_revision: Union[str, None] = "0001_baseline"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

SEVERITY = sa.Enum("critical", "high", "medium", "low", "unknown", name="severity", create_type=False)


def _vuln_key(cve_id: str | None, package_name: str | None) -> str:
    return hashlib.sha256(f"{cve_id or ''}:{package_name or ''}".encode()).hexdigest()[:64]


def upgrade() -> None:
    op.create_table(
        "finding_observations",
        sa.Column("id", sa.BigInteger().with_variant(sa.Integer(), "sqlite"), autoincrement=True, nullable=False),
        sa.Column("scan_id", sa.String(length=64), nullable=False),
        sa.Column("finding_id", sa.BigInteger(), nullable=False),
        sa.Column("severity", SEVERITY, nullable=True),
        sa.Column("fixed_version", sa.String(length=64), nullable=True),
        sa.Column("file_path", sa.String(length=1024), nullable=True),
        sa.Column("observed_at", sa.DateTime(), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["finding_id"], ["scan_findings.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.scan_id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("scan_id", "finding_id", name="uq_observation_scan_finding"),
    )
    op.create_index("idx_observations_finding_id", "finding_observations", ["finding_id"])

    with op.batch_alter_table("scans") as batch:
        batch.add_column(sa.Column("target", sa.String(length=1024), nullable=True))

    with op.batch_alter_table("scan_findings") as batch:
        batch.add_column(sa.Column("vuln_key", sa.String(length=64), nullable=True))

    bind = op.get_bind()
    findings = sa.table("scan_findings", sa.column("id"), sa.column("cve_id"), sa.column("package_name"),
                        sa.column("vuln_key"))
    for row in bind.execute(sa.select(findings.c.id, findings.c.cve_id, findings.c.package_name)).all():
        bind.execute(findings.update().where(findings.c.id == row.id)
                     .values(vuln_key=_vuln_key(row.cve_id, row.package_name)))

    # Keep the one piece of history the old column held: the last scan that saw each finding.
    op.execute(
        "INSERT INTO finding_observations (scan_id, finding_id, severity, fixed_version, file_path, observed_at) "
        "SELECT f.scan_id, f.id, f.severity, f.fixed_version, f.file_path, f.last_seen "
        "FROM scan_findings f JOIN scans s ON s.scan_id = f.scan_id"
    )

    with op.batch_alter_table("scan_findings") as batch:
        batch.alter_column("vuln_key", existing_type=sa.String(length=64), nullable=False)
        batch.drop_index("idx_findings_remediated")
        batch.drop_column("remediated")
        batch.drop_column("scan_id")
        batch.create_index("idx_findings_vuln_key", ["image_id", "vuln_key"])


def downgrade() -> None:
    with op.batch_alter_table("scan_findings") as batch:
        batch.drop_index("idx_findings_vuln_key")
        batch.add_column(sa.Column("scan_id", sa.String(length=64), nullable=True))
        batch.add_column(sa.Column("remediated", sa.Boolean(), nullable=True, server_default=sa.false()))
        batch.create_index("idx_findings_remediated", ["remediated"])
    op.execute(
        "UPDATE scan_findings SET scan_id = (SELECT o.scan_id FROM finding_observations o "
        "WHERE o.finding_id = scan_findings.id ORDER BY o.observed_at DESC, o.id DESC LIMIT 1)"
    )
    with op.batch_alter_table("scan_findings") as batch:
        batch.drop_column("vuln_key")
    with op.batch_alter_table("scans") as batch:
        batch.drop_column("target")
    op.drop_index("idx_observations_finding_id", table_name="finding_observations")
    op.drop_table("finding_observations")
