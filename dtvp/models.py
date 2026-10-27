"""Initial source-neutral DTVP catalog and synchronization records."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


def _new_id() -> str:
    return str(uuid4())


def _now() -> datetime:
    return datetime.now(UTC)


class Product(Base):
    __tablename__ = "products"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_new_id)
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_now, onupdate=_now
    )

    versions: Mapped[list[ProductVersion]] = relationship(
        back_populates="product", cascade="all, delete-orphan"
    )


class ProductVersion(Base):
    __tablename__ = "product_versions"
    __table_args__ = (UniqueConstraint("product_id", "version", name="uq_product_version"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_new_id)
    product_id: Mapped[str] = mapped_column(
        ForeignKey("products.id", ondelete="CASCADE"), nullable=False, index=True
    )
    version: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_now
    )

    product: Mapped[Product] = relationship(back_populates="versions")
    snapshots: Mapped[list[InventorySnapshot]] = relationship(
        back_populates="product_version"
    )


class SourceConnection(Base):
    """A configured source; credentials are referenced, never stored in config."""

    __tablename__ = "source_connections"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_new_id)
    source_type: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    enabled: Mapped[bool] = mapped_column(default=True, nullable=False)
    secret_ref: Mapped[str | None] = mapped_column(String(512))
    config: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_now, onupdate=_now
    )

    import_runs: Mapped[list[ImportRun]] = relationship(back_populates="source")
    snapshots: Mapped[list[InventorySnapshot]] = relationship(back_populates="source")


class ExternalReference(Base):
    """Maps a provider identity to a DTVP identity without provider-shaped keys."""

    __tablename__ = "external_references"
    __table_args__ = (
        UniqueConstraint(
            "source_connection_id",
            "external_type",
            "external_id",
            name="uq_external_reference_source_identity",
        ),
        Index("ix_external_reference_local", "local_type", "local_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_new_id)
    source_connection_id: Mapped[str] = mapped_column(
        ForeignKey("source_connections.id", ondelete="CASCADE"), nullable=False
    )
    external_type: Mapped[str] = mapped_column(String(100), nullable=False)
    external_id: Mapped[str] = mapped_column(String(512), nullable=False)
    local_type: Mapped[str] = mapped_column(String(100), nullable=False)
    local_id: Mapped[str] = mapped_column(String(128), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_now
    )


class ImportRun(Base):
    """Durable status and cursor record for a source import/synchronization."""

    __tablename__ = "import_runs"
    __table_args__ = (
        UniqueConstraint(
            "source_connection_id", "request_id", name="uq_import_run_request"
        ),
        Index("ix_import_runs_source_status", "source_connection_id", "status"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_new_id)
    source_connection_id: Mapped[str] = mapped_column(
        ForeignKey("source_connections.id", ondelete="RESTRICT"), nullable=False
    )
    request_id: Mapped[str] = mapped_column(String(255), nullable=False)
    initiated_by: Mapped[str | None] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")
    scope: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    cursor_before: Mapped[dict | None] = mapped_column(JSON)
    cursor_after: Mapped[dict | None] = mapped_column(JSON)
    counts: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    error_summary: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_now
    )

    source: Mapped[SourceConnection] = relationship(back_populates="import_runs")


class InventorySnapshot(Base):
    """Immutable, normalized inventory revision captured from any connector."""

    __tablename__ = "inventory_snapshots"
    __table_args__ = (
        UniqueConstraint(
            "product_version_id", "revision", name="uq_inventory_snapshot_revision"
        ),
        UniqueConstraint("import_run_id", name="uq_inventory_snapshot_import_run"),
        Index("ix_inventory_snapshots_version_created", "product_version_id", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_new_id)
    product_version_id: Mapped[str] = mapped_column(
        ForeignKey("product_versions.id", ondelete="RESTRICT"), nullable=False
    )
    source_connection_id: Mapped[str] = mapped_column(
        ForeignKey("source_connections.id", ondelete="RESTRICT"), nullable=False
    )
    import_run_id: Mapped[str] = mapped_column(
        ForeignKey("import_runs.id", ondelete="RESTRICT"), nullable=False
    )
    revision: Mapped[int] = mapped_column(Integer, nullable=False)
    payload_sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    state_sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    captured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_now
    )

    product_version: Mapped[ProductVersion] = relationship(back_populates="snapshots")
    source: Mapped[SourceConnection] = relationship(back_populates="snapshots")
    import_run: Mapped[ImportRun] = relationship()


class AssessmentRevision(Base):
    """Append-only DTVP decision history for one imported finding context."""

    __tablename__ = "assessment_revisions"
    __table_args__ = (
        UniqueConstraint(
            "product_version_id", "finding_identity", "revision",
            name="uq_assessment_revision_context",
        ),
        Index(
            "ix_assessment_revision_source_key",
            "project_source_id", "component_source_id", "vulnerability_source_id",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_new_id)
    product_version_id: Mapped[str] = mapped_column(
        ForeignKey("product_versions.id", ondelete="RESTRICT"), nullable=False
    )
    inventory_snapshot_id: Mapped[str] = mapped_column(
        ForeignKey("inventory_snapshots.id", ondelete="RESTRICT"), nullable=False
    )
    finding_identity: Mapped[str] = mapped_column(String(128), nullable=False)
    project_source_id: Mapped[str] = mapped_column(String(512), nullable=False)
    component_source_id: Mapped[str] = mapped_column(String(512), nullable=False)
    vulnerability_source_id: Mapped[str] = mapped_column(String(512), nullable=False)
    revision: Mapped[int] = mapped_column(Integer, nullable=False)
    actor: Mapped[str | None] = mapped_column(String(255))
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_now
    )
