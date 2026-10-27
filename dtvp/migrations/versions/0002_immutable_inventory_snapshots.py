"""Add immutable normalized inventory snapshots and source provenance."""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0002_inventory_snapshots"
down_revision = "0001_dtvp_catalog_sources"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("import_runs", sa.Column("initiated_by", sa.String(length=255), nullable=True))
    op.create_table(
        "inventory_snapshots",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("product_version_id", sa.String(length=36), nullable=False),
        sa.Column("source_connection_id", sa.String(length=36), nullable=False),
        sa.Column("import_run_id", sa.String(length=36), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("payload_sha256", sa.String(length=64), nullable=False),
        sa.Column("state_sha256", sa.String(length=64), nullable=False),
        sa.Column("captured_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["product_version_id"], ["product_versions.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["source_connection_id"], ["source_connections.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["import_run_id"], ["import_runs.id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "product_version_id", "revision", name="uq_inventory_snapshot_revision"
        ),
        sa.UniqueConstraint("import_run_id", name="uq_inventory_snapshot_import_run"),
    )
    op.create_index(
        "ix_inventory_snapshots_version_created",
        "inventory_snapshots",
        ["product_version_id", "created_at"],
        unique=False,
    )
    op.create_index(
        "ix_inventory_snapshots_payload_sha256",
        "inventory_snapshots",
        ["payload_sha256"],
        unique=False,
    )
    op.create_index(
        "ix_inventory_snapshots_state_sha256",
        "inventory_snapshots",
        ["state_sha256"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_inventory_snapshots_state_sha256", table_name="inventory_snapshots")
    op.drop_index("ix_inventory_snapshots_payload_sha256", table_name="inventory_snapshots")
    op.drop_index("ix_inventory_snapshots_version_created", table_name="inventory_snapshots")
    op.drop_table("inventory_snapshots")
    op.drop_column("import_runs", "initiated_by")
