"""Persist DTVP decisions with append-only revision history."""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0003_assessment_revisions"
down_revision = "0002_inventory_snapshots"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "assessment_revisions",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("product_version_id", sa.String(length=36), nullable=False),
        sa.Column("inventory_snapshot_id", sa.String(length=36), nullable=False),
        sa.Column("finding_identity", sa.String(length=128), nullable=False),
        sa.Column("project_source_id", sa.String(length=512), nullable=False),
        sa.Column("component_source_id", sa.String(length=512), nullable=False),
        sa.Column("vulnerability_source_id", sa.String(length=512), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("actor", sa.String(length=255), nullable=True),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["product_version_id"], ["product_versions.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["inventory_snapshot_id"], ["inventory_snapshots.id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "product_version_id", "finding_identity", "revision",
            name="uq_assessment_revision_context",
        ),
    )
    op.create_index(
        "ix_assessment_revision_source_key",
        "assessment_revisions",
        ["project_source_id", "component_source_id", "vulnerability_source_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_assessment_revision_source_key", table_name="assessment_revisions")
    op.drop_table("assessment_revisions")
