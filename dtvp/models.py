"""Initial source-neutral DTVP catalog and synchronization records."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import DateTime, ForeignKey, Index, JSON, String, Text, UniqueConstraint
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
