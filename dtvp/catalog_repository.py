"""Persistence operations for DTVP-owned product and source snapshots."""

from __future__ import annotations

import json
import hashlib
from datetime import UTC, datetime
from uuid import NAMESPACE_URL, uuid4, uuid5

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from .database import get_session_factory
from .artifact_store import ArtifactStore
from .assessment_outbox_services import AssessmentRevisionConflictError, assessment_key
from .models import (
    AssessmentRevision,
    ExternalReference,
    ImportRun,
    InventorySnapshot,
    Product,
    ProductVersion,
    SourceConnection,
    SourceCatalogProject,
)


class ImportRequestConflict(ValueError):
    """An idempotency key was reused for a different source scope."""


def _resolve_assessment_context(
    session, payload: dict, source_type: str
) -> tuple[str, str, str]:
    key = assessment_key(payload)
    if key is None:
        raise ValueError("Assessment is missing its finding identity")
    project_id, component_id, vulnerability_id = key
    version_ref = session.scalar(
        select(ExternalReference)
        .join(SourceConnection, SourceConnection.id == ExternalReference.source_connection_id)
        .where(
            SourceConnection.source_type == source_type,
            ExternalReference.external_type == "product-version",
            ExternalReference.external_id == project_id,
        )
    )
    if version_ref is None:
        raise LookupError("Assessment finding has not been imported into DTVP")
    latest = session.scalar(
        select(InventorySnapshot)
        .where(
            InventorySnapshot.product_version_id == version_ref.local_id,
            InventorySnapshot.source_connection_id == version_ref.source_connection_id,
        )
        .order_by(InventorySnapshot.revision.desc())
        .limit(1)
    )
    if latest is None:
        raise LookupError("Assessment finding has no published DTVP snapshot")
    finding_identity = None
    if latest is not None:
        try:
            snapshot = ArtifactStore().get_json(latest.payload_sha256)
        except (OSError, ValueError):
            snapshot = {}
        for finding in (snapshot.get("security") or {}).get("findings") or []:
            vulnerability = finding.get("vulnerability") or {}
            if (
                str(finding.get("component_external_id") or "") == component_id
                and str(vulnerability.get("external_id") or "") == vulnerability_id
            ):
                finding_identity = str(finding.get("external_id") or "") or None
                if finding_identity:
                    break
    if not finding_identity:
        # Preserve a deterministic context for older DT findings whose export
        # lacks a stable finding UUID. The source keys remain provenance fields.
        finding_identity = hashlib.sha256(
            json.dumps([component_id, vulnerability_id], separators=(",", ":")).encode()
        ).hexdigest()
    return version_ref.local_id, latest.id, finding_identity


def persist_assessment_revisions(
    payloads: list[dict],
    *,
    actor: str | None = None,
    expected_revisions: dict[tuple[str, str, str], int] | None = None,
    only_if_absent: bool = False,
    source_type: str = "dependency-track",
) -> list[dict]:
    """Save accepted decisions in DTVP and append a revision per change."""
    if not payloads:
        return []
    results = []
    with get_session_factory().begin() as session:
        for payload in payloads:
            key = assessment_key(payload)
            if key is None:
                raise ValueError("Assessment is missing its finding identity")
            version_id, snapshot_id, finding_identity = _resolve_assessment_context(
                session, payload, source_type
            )
            # Lock the canonical version row so concurrent first decisions for
            # a finding serialize even before any revision row exists.
            session.scalar(
                select(ProductVersion.id)
                .where(ProductVersion.id == version_id)
                .with_for_update()
            )
            latest_by_source = session.scalar(
                select(AssessmentRevision)
                .where(
                    AssessmentRevision.product_version_id == version_id,
                    AssessmentRevision.project_source_id == key[0],
                    AssessmentRevision.component_source_id == key[1],
                    AssessmentRevision.vulnerability_source_id == key[2],
                )
                .order_by(AssessmentRevision.revision.desc())
                .with_for_update()
                .limit(1)
            )
            if latest_by_source is not None:
                if only_if_absent:
                    results.append(
                        {
                            "id": latest_by_source.id,
                            "revision": latest_by_source.revision,
                            "payload": dict(latest_by_source.payload or {}),
                            "actor": latest_by_source.actor,
                            "created_at": _iso(latest_by_source.created_at),
                        }
                    )
                    continue
                finding_identity = latest_by_source.finding_identity
            latest = latest_by_source or session.scalar(
                select(AssessmentRevision)
                .where(
                    AssessmentRevision.product_version_id == version_id,
                    AssessmentRevision.finding_identity == finding_identity,
                )
                .order_by(AssessmentRevision.revision.desc())
                .with_for_update()
                .limit(1)
            )
            current_revision = latest.revision if latest else 0
            expected = (expected_revisions or {}).get(key)
            if expected is not None and expected != current_revision:
                raise AssessmentRevisionConflictError(key, expected, current_revision)
            revision = current_revision + 1
            record = AssessmentRevision(
                product_version_id=version_id,
                inventory_snapshot_id=snapshot_id,
                finding_identity=finding_identity,
                project_source_id=key[0],
                component_source_id=key[1],
                vulnerability_source_id=key[2],
                revision=revision,
                actor=actor,
                payload=dict(payload),
            )
            session.add(record)
            session.flush()
            results.append(
                {
                    "id": record.id,
                    "revision": revision,
                    "payload": dict(payload),
                    "actor": actor,
                    "created_at": _iso(record.created_at),
                }
            )
    return results


def get_current_assessment(
    project_id: str, component_id: str, vulnerability_id: str
) -> dict | None:
    with get_session_factory()() as session:
        record = session.scalar(
            select(AssessmentRevision)
            .where(
                AssessmentRevision.project_source_id == project_id,
                AssessmentRevision.component_source_id == component_id,
                AssessmentRevision.vulnerability_source_id == vulnerability_id,
            )
            .order_by(AssessmentRevision.revision.desc())
            .limit(1)
        )
        if record is None:
            return None
        payload = record.payload or {}
        return {
            "analysisState": payload.get("state") or "NOT_SET",
            "analysisDetails": payload.get("details") or "",
            "isSuppressed": bool(payload.get("suppressed", False)),
            "dtvpRevision": record.revision,
            "dtvpSyncStatus": "local",
            "dtvpUpdateId": record.id,
            "dtvpSyncError": None,
            "actor": record.actor,
            "created_at": _iso(record.created_at),
        }


def list_assessment_revisions(
    product_version_id: str,
    *,
    project_id: str | None = None,
    component_id: str | None = None,
    vulnerability_id: str | None = None,
) -> list[dict]:
    with get_session_factory()() as session:
        query = select(AssessmentRevision).where(
            AssessmentRevision.product_version_id == product_version_id
        )
        if project_id:
            query = query.where(AssessmentRevision.project_source_id == project_id)
        if component_id:
            query = query.where(AssessmentRevision.component_source_id == component_id)
        if vulnerability_id:
            query = query.where(
                AssessmentRevision.vulnerability_source_id == vulnerability_id
            )
        records = session.scalars(
            query.order_by(AssessmentRevision.created_at, AssessmentRevision.revision)
        ).all()
        return [
            {
                "id": record.id,
                "product_version_id": record.product_version_id,
                "inventory_snapshot_id": record.inventory_snapshot_id,
                "finding_identity": record.finding_identity,
                "revision": record.revision,
                "actor": record.actor,
                "payload": record.payload,
                "created_at": _iso(record.created_at),
            }
            for record in records
        ]


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


def sync_source_catalog_projects(
    *, source_connection_id: str, projects: list[dict], complete: bool = True,
) -> list[dict]:
    """Atomically publish a complete discovered catalog and retain source records."""
    captured_at = datetime.now(UTC)
    artifacts: dict[str, str] = {}
    normalized = []
    for project in projects:
        external_id = str(project.get("external_id") or "").strip()
        product_name = str(project.get("product_name") or "").strip()
        version_name = str(project.get("version_name") or "")
        raw = project.get("source_artifacts")
        if not external_id or not product_name or not isinstance(raw, dict):
            raise ValueError("Source returned an invalid project catalog entry")
        if external_id in artifacts:
            raise ValueError("Source returned duplicate project identities")
        artifacts[external_id] = ArtifactStore().put_json(raw)
        normalized.append(
            {
                "external_id": external_id,
                "product_name": product_name,
                "version_name": version_name,
                "active": bool(project.get("active", True)),
                "payload_sha256": artifacts[external_id],
            }
        )

    with get_session_factory().begin() as session:
        existing = session.scalars(
            select(SourceCatalogProject).where(
                SourceCatalogProject.source_connection_id == source_connection_id
            )
        ).all()
        by_identity = {entry.external_project_id: entry for entry in existing}
        seen_ids = set(artifacts)
        if complete:
            for entry in existing:
                if entry.external_project_id not in seen_ids:
                    entry.active = False
        result = []
        for item in normalized:
            entry = by_identity.get(item["external_id"])
            if entry is None:
                entry = SourceCatalogProject(
                    source_connection_id=source_connection_id,
                    external_project_id=item["external_id"],
                    product_name=item["product_name"],
                    version_name=item["version_name"],
                    active=item["active"],
                    payload_sha256=item["payload_sha256"],
                    last_seen_at=captured_at,
                )
                session.add(entry)
            else:
                entry.product_name = item["product_name"]
                entry.version_name = item["version_name"]
                entry.active = item["active"]
                entry.payload_sha256 = item["payload_sha256"]
                entry.last_seen_at = captured_at
            result.append((item["external_id"], item["payload_sha256"], item["active"]))
    store = ArtifactStore()
    return [
        store.get_json(payload_hash)
        for _external_id, payload_hash, active in result
        if active
    ]


def list_source_catalog_projects() -> list[dict]:
    with get_session_factory()() as session:
        rows = session.execute(
            select(
                SourceCatalogProject.external_project_id,
                SourceCatalogProject.payload_sha256,
                SourceConnection.source_type,
            )
            .join(SourceConnection, SourceConnection.id == SourceCatalogProject.source_connection_id)
            .where(SourceCatalogProject.active.is_(True))
            .order_by(
                SourceCatalogProject.external_project_id,
                SourceCatalogProject.product_name,
                SourceCatalogProject.version_name,
                SourceConnection.source_type,
            )
        ).all()
    store = ArtifactStore()
    projects: dict[str, tuple[int, dict]] = {}
    for external_id, payload_hash, source_type in rows:
        priority = 0 if source_type == "dependency-track" else 1
        previous = projects.get(external_id)
        if previous is None or priority < previous[0]:
            projects[external_id] = (priority, store.get_json(payload_hash))
    return [project for _priority, project in projects.values()]


def get_latest_snapshot_for_source_project(
    source_project_id: str,
    preferred_base_url: str | None = None,
    source_type: str | None = None,
    preferred_source_type: str | None = "dependency-track",
) -> dict | None:
    with get_session_factory()() as session:
        query = (
            select(ExternalReference, SourceConnection)
            .join(SourceConnection, SourceConnection.id == ExternalReference.source_connection_id)
            .where(
                ExternalReference.external_type == "product-version",
                ExternalReference.external_id == source_project_id,
            )
        )
        if source_type:
            query = query.where(SourceConnection.source_type == source_type)
        refs = session.execute(query).all()
        candidates = []
        for version_ref, source in refs:
            latest = session.scalar(
                select(InventorySnapshot)
                .where(
                    InventorySnapshot.product_version_id == version_ref.local_id,
                    InventorySnapshot.source_connection_id == source.id,
                )
                .order_by(InventorySnapshot.revision.desc())
                .limit(1)
            )
            if latest is None:
                continue
            base_priority = (
                0
                if preferred_base_url
                and (source.config or {}).get("base_url") == preferred_base_url
                else 1
            )
            source_priority = (
                0 if preferred_source_type == source.source_type else 1
            )
            candidates.append(
                (source_priority, base_priority, latest.created_at, source, latest)
            )
        if not candidates:
            return None
        _source_priority, _base_priority, _created, source, snapshot = min(
            candidates,
            key=lambda item: (
                item[0],
                item[1],
                -item[2].timestamp(),
            ),
        )
        return {
            "id": snapshot.id,
            "revision": snapshot.revision,
            "payload_sha256": snapshot.payload_sha256,
            "source_type": source.source_type,
            "source_base_url": (source.config or {}).get("base_url"),
            "captured_at": _iso(snapshot.captured_at),
        }


def get_source_finding_analysis(
    project_id: str, component_id: str, vulnerability_id: str
) -> dict | None:
    record = get_latest_snapshot_for_source_project(
        project_id, preferred_source_type="dependency-track"
    )
    if record is None:
        return None
    try:
        snapshot = ArtifactStore().get_json(record["payload_sha256"])
    except (OSError, ValueError):
        return None
    for finding in (snapshot.get("security") or {}).get("findings") or []:
        if (
            str(finding.get("component_external_id") or "") == component_id
            and str(
                (finding.get("vulnerability") or {}).get("external_id") or ""
            ) == vulnerability_id
        ):
            analysis = finding.get("source_analysis")
            return analysis if isinstance(analysis, dict) else {}
    return None


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
            product = (
                session.get(Product, product_ref.local_id)
                if product_ref is not None
                else None
            )
            if product_ref is not None and product is None:
                raise LookupError("Mapped DTVP product does not exist")
            if product is None and product_ref is None:
                same_name = session.scalars(
                    select(Product).where(Product.name == product_name).limit(2)
                ).all()
                if len(same_name) == 1:
                    product = same_name[0]
            if product is None:
                product = Product(name=product_name)
                session.add(product)
                session.flush()
            if product_ref is None:
                session.add(
                    ExternalReference(
                        source_connection_id=source_connection_id,
                        external_type="product",
                        external_id=source_product_id,
                        local_type="product",
                        local_id=product.id,
                        observed_at=captured_at,
                    )
                )

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
            if version is None:
                version = session.scalar(
                    select(ProductVersion).where(
                        ProductVersion.product_id == product.id,
                        ProductVersion.version == version_name,
                    )
                )
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
            "state_sha256": snapshot.state_sha256,
            "captured_at": _iso(snapshot.captured_at),
        }


def get_local_product_version_id(
    source_type: str, base_url: str, source_version_id: str
) -> str | None:
    with get_session_factory()() as session:
        version_ref = session.scalar(
            select(ExternalReference)
            .join(SourceConnection, SourceConnection.id == ExternalReference.source_connection_id)
            .where(
                SourceConnection.source_type == source_type,
                SourceConnection.config["base_url"].as_string() == base_url,
                ExternalReference.external_type == "product-version",
                ExternalReference.external_id == source_version_id,
            )
        )
        return version_ref.local_id if version_ref else None
