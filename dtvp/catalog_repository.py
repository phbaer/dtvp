"""Persistence operations for DTVP-owned product and source snapshots."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from uuid import NAMESPACE_URL, uuid4, uuid5

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from .database import get_session_factory
from .models import (
    ExternalReference,
    ImportRun,
    InventorySnapshot,
    Product,
    ProductVersion,
    SourceConnection,
)


class ImportRequestConflict(ValueError):
    """An idempotency key was reused for a different source scope."""


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _run_dict(run: ImportRun) -> dict:
    snapshot = run.cursor_after.get("snapshot_id") if run.cursor_after else None
    return {
        "id": run.id,
        "source_connection_id": run.source_connection_id,
        "request_id": run.request_id,
        "initiated_by": run.initiated_by,
        "status": run.status,
        "scope": run.scope,
        "cursor_before": run.cursor_before,
        "cursor_after": run.cursor_after,
        "counts": run.counts,
        "snapshot_id": snapshot,
        "error_summary": run.error_summary,
        "started_at": _iso(run.started_at),
        "finished_at": _iso(run.finished_at),
        "created_at": _iso(run.created_at),
    }


def ensure_source_connection(
    *, source_type: str, display_name: str, config: dict, secret_ref: str | None = None
) -> str:
    """Create or return a stable source connection without storing credentials."""
    identity = json.dumps(config, sort_keys=True, separators=(",", ":"))
    source_id = str(uuid5(NAMESPACE_URL, f"dtvp-source:{source_type}:{identity}"))
    session_factory = get_session_factory()
    with session_factory.begin() as session:
        source = session.get(SourceConnection, source_id)
        if source is None:
            session.add(
                SourceConnection(
                    id=source_id,
                    source_type=source_type,
                    display_name=display_name,
                    secret_ref=secret_ref,
                    config=config,
                )
            )
    return source_id


def begin_import_run(
    *,
    source_connection_id: str,
    request_id: str,
    scope: dict,
    initiated_by: str | None,
) -> tuple[dict, bool]:
    """Persist a run before fetching; the request ID provides replay safety."""
    session_factory = get_session_factory()
    with session_factory() as session:
        existing = session.scalar(
            select(ImportRun).where(
                ImportRun.source_connection_id == source_connection_id,
                ImportRun.request_id == request_id,
            )
        )
        if existing is not None:
            if existing.scope != scope:
                raise ImportRequestConflict(
                    "Import request_id was already used for a different scope"
                )
            return _run_dict(existing), False

    run = ImportRun(
        id=str(uuid4()),
        source_connection_id=source_connection_id,
        request_id=request_id,
        initiated_by=initiated_by,
        status="running",
        scope=scope,
        counts={},
        started_at=datetime.now(UTC),
    )
    try:
        with session_factory.begin() as session:
            session.add(run)
            session.flush()
    except IntegrityError:
        with session_factory() as session:
            existing = session.scalar(
                select(ImportRun).where(
                    ImportRun.source_connection_id == source_connection_id,
                    ImportRun.request_id == request_id,
                )
            )
            if existing is None:
                raise
            if existing.scope != scope:
                raise ImportRequestConflict(
                    "Import request_id was already used for a different scope"
                )
            return _run_dict(existing), False
    return _run_dict(run), True


def fail_import_run(run_id: str, error_summary: str) -> dict:
    session_factory = get_session_factory()
    with session_factory.begin() as session:
        run = session.get(ImportRun, run_id)
        if run is None:
            raise LookupError("Import run does not exist")
        if run.status != "running":
            return _run_dict(run)
        run.status = "failed"
        run.error_summary = error_summary[:1000]
        run.finished_at = datetime.now(UTC)
        session.flush()
        return _run_dict(run)


def publish_snapshot(
    *,
    run_id: str,
    source_connection_id: str,
    source_product_id: str,
    source_version_id: str,
    payload_sha256: str,
    state_sha256: str,
    captured_at: datetime,
    snapshot_counts: dict,
    product_name: str,
    version_name: str,
    _retry: bool = True,
) -> dict:
    """Atomically publish a snapshot and mark its import run complete."""
    session_factory = get_session_factory()
    try:
        with session_factory.begin() as session:
            run = session.get(ImportRun, run_id)
            if run is None:
                raise LookupError("Import run does not exist")
            if run.status != "running":
                return _run_dict(run)

            product_ref = session.scalar(
                select(ExternalReference).where(
                    ExternalReference.source_connection_id == source_connection_id,
                    ExternalReference.external_type == "product",
                    ExternalReference.external_id == source_product_id,
                )
            )
            if product_ref is None:
                product = Product(name=product_name)
                session.add(product)
                session.flush()
                version = ProductVersion(product_id=product.id, version=version_name)
                session.add(version)
                session.flush()
                session.add_all(
                    [
                        ExternalReference(
                            source_connection_id=source_connection_id,
                            external_type="product",
                            external_id=source_product_id,
                            local_type="product",
                            local_id=product.id,
                            observed_at=captured_at,
                        ),
                        ExternalReference(
                            source_connection_id=source_connection_id,
                            external_type="product-version",
                            external_id=source_version_id,
                            local_type="product-version",
                            local_id=version.id,
                            observed_at=captured_at,
                        ),
                    ]
                )
            else:
                product = session.get(Product, product_ref.local_id)
                version_ref = session.scalar(
                    select(ExternalReference).where(
                        ExternalReference.source_connection_id == source_connection_id,
                        ExternalReference.external_type == "product-version",
                        ExternalReference.external_id == source_version_id,
                    )
                )
                version = (
                    session.get(ProductVersion, version_ref.local_id)
                    if version_ref is not None
                    else None
                )
                if product is None:
                    raise LookupError("Mapped DTVP product does not exist")
                if version is None:
                    version = ProductVersion(product_id=product.id, version=version_name)
                    session.add(version)
                    session.flush()
                    session.add(
                        ExternalReference(
                            source_connection_id=source_connection_id,
                            external_type="product-version",
                            external_id=source_version_id,
                            local_type="product-version",
                            local_id=version.id,
                            observed_at=captured_at,
                        )
                    )

            latest = session.scalar(
                select(InventorySnapshot)
                .where(InventorySnapshot.product_version_id == version.id)
                .order_by(InventorySnapshot.revision.desc())
                .limit(1)
            )
            if latest is not None and latest.state_sha256 == state_sha256:
                snapshot_id = latest.id
                revision = latest.revision
                counts = {**snapshot_counts, "unchanged": True}
            else:
                revision = (latest.revision if latest else 0) + 1
                snapshot = InventorySnapshot(
                    product_version_id=version.id,
                    source_connection_id=source_connection_id,
                    import_run_id=run.id,
                    revision=revision,
                    payload_sha256=payload_sha256,
                    state_sha256=state_sha256,
                    captured_at=captured_at,
                )
                session.add(snapshot)
                session.flush()
                snapshot_id = snapshot.id
                counts = {**snapshot_counts, "unchanged": False}

            run.status = "succeeded"
            run.counts = counts
            run.cursor_after = {
                "snapshot_id": snapshot_id,
                "revision": revision,
                "payload_sha256": payload_sha256,
                "state_sha256": state_sha256,
            }
            run.finished_at = datetime.now(UTC)
            session.flush()
            return _run_dict(run)
    except IntegrityError:
        if not _retry:
            raise
        return publish_snapshot(
            run_id=run_id,
            source_connection_id=source_connection_id,
            source_product_id=source_product_id,
            source_version_id=source_version_id,
            payload_sha256=payload_sha256,
            state_sha256=state_sha256,
            captured_at=captured_at,
            snapshot_counts=snapshot_counts,
            product_name=product_name,
            version_name=version_name,
            _retry=False,
        )


def get_import_run(run_id: str) -> dict | None:
    with get_session_factory()() as session:
        run = session.get(ImportRun, run_id)
        return _run_dict(run) if run else None


def get_snapshot_record(snapshot_id: str) -> dict | None:
    with get_session_factory()() as session:
        snapshot = session.get(InventorySnapshot, snapshot_id)
        if snapshot is None:
            return None
        return {
            "id": snapshot.id,
            "product_version_id": snapshot.product_version_id,
            "source_connection_id": snapshot.source_connection_id,
            "import_run_id": snapshot.import_run_id,
            "revision": snapshot.revision,
            "payload_sha256": snapshot.payload_sha256,
            "state_sha256": snapshot.state_sha256,
            "captured_at": _iso(snapshot.captured_at),
            "created_at": _iso(snapshot.created_at),
        }


def get_version_snapshot_record(
    product_version_id: str, revision: int | None = None
) -> dict | None:
    with get_session_factory()() as session:
        query = select(InventorySnapshot).where(
            InventorySnapshot.product_version_id == product_version_id
        )
        if revision is not None:
            query = query.where(InventorySnapshot.revision == revision)
        snapshot = session.scalar(query.order_by(InventorySnapshot.revision.desc()).limit(1))
        if snapshot is None:
            return None
        return {
            "id": snapshot.id,
            "product_version_id": snapshot.product_version_id,
            "source_connection_id": snapshot.source_connection_id,
            "import_run_id": snapshot.import_run_id,
            "revision": snapshot.revision,
            "payload_sha256": snapshot.payload_sha256,
            "state_sha256": snapshot.state_sha256,
            "captured_at": _iso(snapshot.captured_at),
            "created_at": _iso(snapshot.created_at),
        }


def list_products(name: str | None = None) -> list[dict]:
    with get_session_factory()() as session:
        query = select(Product).order_by(Product.name, Product.id)
        if name:
            query = query.where(Product.name.ilike(f"%{name}%"))
        products = session.scalars(query).all()
        result = []
        for product in products:
            version_count = session.scalar(
                select(func.count(ProductVersion.id)).where(
                    ProductVersion.product_id == product.id
                )
            )
            result.append(
                {
                    "id": product.id,
                    "name": product.name,
                    "description": product.description,
                    "version_count": int(version_count or 0),
                    "created_at": _iso(product.created_at),
                    "updated_at": _iso(product.updated_at),
                }
            )
        return result


def list_product_versions(product_id: str) -> list[dict]:
    with get_session_factory()() as session:
        versions = session.scalars(
            select(ProductVersion)
            .where(ProductVersion.product_id == product_id)
            .order_by(ProductVersion.version, ProductVersion.id)
        ).all()
        result = []
        for version in versions:
            latest = session.scalar(
                select(InventorySnapshot)
                .where(InventorySnapshot.product_version_id == version.id)
                .order_by(InventorySnapshot.revision.desc())
                .limit(1)
            )
            result.append({
                "id": version.id,
                "product_id": version.product_id,
                "version": version.version,
                "created_at": _iso(version.created_at),
                "latest_snapshot_id": latest.id if latest else None,
                "latest_snapshot_revision": latest.revision if latest else None,
            })
        return result


def list_latest_source_snapshots(source_type: str, base_url: str) -> list[dict]:
    """Return latest published snapshots and identities for a configured source."""
    with get_session_factory()() as session:
        rows = session.execute(
            select(
                Product.name,
                ProductVersion.version,
                ExternalReference.external_id,
                InventorySnapshot.id,
                InventorySnapshot.payload_sha256,
                InventorySnapshot.revision,
                SourceConnection.config,
            )
            .join(ProductVersion, ProductVersion.product_id == Product.id)
            .join(InventorySnapshot, InventorySnapshot.product_version_id == ProductVersion.id)
            .join(SourceConnection, SourceConnection.id == InventorySnapshot.source_connection_id)
            .join(
                ExternalReference,
                (ExternalReference.source_connection_id == SourceConnection.id)
                & (ExternalReference.local_type == "product-version")
                & (ExternalReference.local_id == ProductVersion.id),
            )
            .where(SourceConnection.source_type == source_type)
            .order_by(InventorySnapshot.revision.desc())
        ).all()
        latest: dict[str, dict] = {}
        for name, version, external_id, snapshot_id, payload_hash, revision, config in rows:
            if (config or {}).get("base_url") != base_url or external_id in latest:
                continue
            latest[external_id] = {
                "product_name": name,
                "version_name": version,
                "source_version_id": external_id,
                "snapshot_id": snapshot_id,
                "payload_sha256": payload_hash,
                "revision": revision,
            }
        return list(latest.values())


def get_latest_source_snapshot(source_type: str, base_url: str, source_version_id: str) -> dict | None:
    """Return the latest snapshot record for one imported provider identity."""
    with get_session_factory()() as session:
        version_refs = session.scalars(
            select(ExternalReference)
            .join(SourceConnection, SourceConnection.id == ExternalReference.source_connection_id)
            .where(
                SourceConnection.source_type == source_type,
                ExternalReference.external_type == "product-version",
                ExternalReference.external_id == source_version_id,
            )
        ).all()
        version_ref = next(
            (
                candidate for candidate in version_refs
                if (source := session.get(SourceConnection, candidate.source_connection_id))
                and (source.config or {}).get("base_url") == base_url
            ),
            None,
        )
        if version_ref is None:
            return None
        source = session.get(SourceConnection, version_ref.source_connection_id)
        if source is None:
            return None
        snapshot = session.scalar(
            select(InventorySnapshot)
            .where(
                InventorySnapshot.product_version_id == version_ref.local_id,
                InventorySnapshot.source_connection_id == source.id,
            )
            .order_by(InventorySnapshot.revision.desc())
            .limit(1)
        )
        if snapshot is None:
            return None
        return {
            "id": snapshot.id,
            "revision": snapshot.revision,
            "payload_sha256": snapshot.payload_sha256,
            "captured_at": _iso(snapshot.captured_at),
        }
