"""Add immutable scan provenance fields.

Revision ID: 20261108_01
Revises: a31ea1ff6a2f
"""

from alembic import op
import sqlalchemy as sa


revision = "20261108_01"
down_revision = "a31ea1ff6a2f"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("scans", sa.Column("image_digest", sa.String(128), nullable=True))
    op.add_column("scans", sa.Column("scanner_versions", sa.JSON(), nullable=False, server_default="{}"))
    op.add_column("scans", sa.Column("vulnerability_db_versions", sa.JSON(), nullable=False, server_default="{}"))
    op.add_column("scan_findings", sa.Column("vulnerability_db_version", sa.String(128), nullable=True))
    op.add_column("raw_scan_results", sa.Column("scanner_version", sa.String(64), nullable=True))
    op.add_column("raw_scan_results", sa.Column("vulnerability_db_version", sa.String(128), nullable=True))


def downgrade() -> None:
    op.drop_column("raw_scan_results", "vulnerability_db_version")
    op.drop_column("raw_scan_results", "scanner_version")
    op.drop_column("scan_findings", "vulnerability_db_version")
    op.drop_column("scans", "vulnerability_db_versions")
    op.drop_column("scans", "scanner_versions")
    op.drop_column("scans", "image_digest")
