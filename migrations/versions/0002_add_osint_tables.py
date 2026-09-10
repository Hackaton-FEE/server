"""add osint tables

Revision ID: 0002
Revises: 0001
Create Date: 2026-09-10
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "osint_scans",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("user_id", sa.String(length=36), nullable=False),
        sa.Column("target_type", sa.String(length=16), nullable=False),
        sa.Column("identifier_hint", sa.String(length=32), nullable=False),
        sa.Column("identifier_sha256", sa.String(length=64), nullable=False),
        sa.Column("consent_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("progress", sa.Integer(), nullable=False),
        sa.Column("exposure_score", sa.Integer(), nullable=True),
        sa.Column("risk_level", sa.String(length=16), nullable=True),
        sa.Column("engines", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_osint_scans_user_id", "osint_scans", ["user_id"])

    op.create_table(
        "osint_findings",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("scan_id", sa.String(length=36), nullable=False),
        sa.Column("platform", sa.String(length=120), nullable=False),
        sa.Column("category", sa.String(length=32), nullable=False),
        sa.Column("url", sa.String(length=500), nullable=True),
        sa.Column("username", sa.String(length=120), nullable=True),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("confidence", sa.Integer(), nullable=False),
        sa.Column("sources", sa.JSON(), nullable=False),
        sa.Column("details", sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["osint_scans.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_osint_findings_scan_id", "osint_findings", ["scan_id"])


def downgrade() -> None:
    op.drop_index("ix_osint_findings_scan_id", table_name="osint_findings")
    op.drop_table("osint_findings")
    op.drop_index("ix_osint_scans_user_id", table_name="osint_scans")
    op.drop_table("osint_scans")
