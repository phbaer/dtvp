"""Persist complete source project discovery in DTVP."""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0004_source_project_catalog"
down_revision = "0003_assessment_revisions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "source_catalog_projects",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("source_connection_id", sa.String(length=36), nullable=False),
        sa.Column("external_project_id", sa.String(length=512), nullable=False),
        sa.Column("product_name", sa.String(length=255), nullable=False),
        sa.Column("version_name", sa.String(length=255), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("payload_sha256", sa.String(length=64), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["source_connection_id"], ["source_connections.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "source_connection_id", "external_project_id",
            name="uq_source_catalog_project_identity",
        ),
    )
    op.create_index(
        "ix_source_catalog_project_active",
        "source_catalog_projects",
        ["source_connection_id", "active"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_source_catalog_project_active", table_name="source_catalog_projects")
    op.drop_table("source_catalog_projects")
