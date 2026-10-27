"""Create initial DTVP product catalog and source synchronization records."""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0001_dtvp_catalog_sources"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "products",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_products_name", "products", ["name"], unique=False)

    op.create_table(
        "product_versions",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("product_id", sa.String(length=36), nullable=False),
        sa.Column("version", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["product_id"], ["products.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("product_id", "version", name="uq_product_version"),
    )
    op.create_index(
        "ix_product_versions_product_id", "product_versions", ["product_id"], unique=False
    )

    op.create_table(
        "source_connections",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("source_type", sa.String(length=80), nullable=False),
        sa.Column("display_name", sa.String(length=255), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("secret_ref", sa.String(length=512), nullable=True),
        sa.Column("config", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_source_connections_source_type", "source_connections", ["source_type"], unique=False
    )

    op.create_table(
        "external_references",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("source_connection_id", sa.String(length=36), nullable=False),
        sa.Column("external_type", sa.String(length=100), nullable=False),
        sa.Column("external_id", sa.String(length=512), nullable=False),
        sa.Column("local_type", sa.String(length=100), nullable=False),
        sa.Column("local_id", sa.String(length=128), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["source_connection_id"], ["source_connections.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "source_connection_id",
            "external_type",
            "external_id",
            name="uq_external_reference_source_identity",
        ),
    )
    op.create_index(
        "ix_external_reference_local",
        "external_references",
        ["local_type", "local_id"],
        unique=False,
    )

    op.create_table(
        "import_runs",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("source_connection_id", sa.String(length=36), nullable=False),
        sa.Column("request_id", sa.String(length=255), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("scope", sa.JSON(), nullable=False),
        sa.Column("cursor_before", sa.JSON(), nullable=True),
        sa.Column("cursor_after", sa.JSON(), nullable=True),
        sa.Column("counts", sa.JSON(), nullable=False),
        sa.Column("error_summary", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["source_connection_id"], ["source_connections.id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "source_connection_id", "request_id", name="uq_import_run_request"
        ),
    )
    op.create_index(
        "ix_import_runs_source_status",
        "import_runs",
        ["source_connection_id", "status"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_import_runs_source_status", table_name="import_runs")
    op.drop_table("import_runs")
    op.drop_index("ix_external_reference_local", table_name="external_references")
    op.drop_table("external_references")
    op.drop_index("ix_source_connections_source_type", table_name="source_connections")
    op.drop_table("source_connections")
    op.drop_index("ix_product_versions_product_id", table_name="product_versions")
    op.drop_table("product_versions")
    op.drop_index("ix_products_name", table_name="products")
    op.drop_table("products")
