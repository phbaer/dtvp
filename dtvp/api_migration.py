"""Explicit, authorized local snapshot migration; no external archive intake."""

import json

from fastapi import APIRouter, HTTPException, Request

from dtvp.api import DB, Auth, project_for, snapshot_for
from dtvp.api_contract import API_PREFIX
from dtvp.api_knowledge import projected_response, uncertain_response
from dtvp.knowledge.journal import CommitUncertain, Conflict, Name
from dtvp.knowledge.migration import (
    MAX_BUNDLE_BYTES,
    MAX_SOURCE_BYTES,
    MigrationApply,
    MigrationInput,
    apply_migration,
    migration_receipt,
    preview_migration,
)
from dtvp.migration_models import Release, Revision
from dtvp.models import Project
from dtvp.storage import canonical, digest

router = APIRouter(prefix=API_PREFIX)


def source_snapshot(project_id, data, db, actor):
    target = project_for(db, actor, project_id, "manage")
    actor.require(db, target, "write")
    snapshot = snapshot_for(db, actor, data.snapshot_id)
    actor.require(db, db.get(Project, snapshot.project_id), "snapshot")
    if snapshot.sha != data.snapshot_sha:
        raise HTTPException(409, "Selected local snapshot digest does not match")
    return snapshot


def capture(snapshot, artifacts, db):
    """Read only SQL-authorized immutable snapshot/source memberships, never arbitrary hashes."""
    try:
        if artifacts.path(snapshot.sha).stat().st_size > MAX_BUNDLE_BYTES:
            raise ValueError("Snapshot bundle exceeds the supported migration size")
        bundle = artifacts.read(snapshot.sha)
        if len(bundle) > MAX_BUNDLE_BYTES:
            raise ValueError("Snapshot bundle exceeds the supported migration size")
        payload = json.loads(bundle)
        release = db.get(Release, snapshot.release_id)
        if (
            not release
            or release.project_id != snapshot.project_id
            or payload.get("schema_version") != "dtvp.snapshot/1"
            or payload.get("project", {}).get("id") != snapshot.project_id
            or payload.get("release", {}).get("id") != snapshot.release_id
            or snapshot.manifest.get("sha256") != snapshot.sha
            or snapshot.manifest.get("selected_revision") != payload.get("selected_revision")
            or snapshot.manifest.get("files", {}).get("sbom")
            != digest(canonical(payload.get("sbom")))
        ):
            raise ValueError("Snapshot manifest and captured source membership disagree")
        entries = payload.get("source_revisions")
        if not isinstance(entries, list) or not entries or len(entries) > 200:
            raise ValueError("Migration requires 1 to 200 captured source revisions")
        raw_sources, seen, selected = {}, set(), None
        source_bytes = 0
        for entry in entries:
            if (
                not isinstance(entry, dict)
                or not isinstance(entry.get("id"), str)
                or entry["id"] in seen
            ):
                raise ValueError("Snapshot source revision IDs are malformed or duplicated")
            seen.add(entry["id"])
            revision = db.get(Revision, entry["id"])
            if (
                not revision
                or revision.release_id != snapshot.release_id
                or revision.artifact_sha != entry.get("sha256")
                or revision.source != entry.get("source")
            ):
                raise ValueError(
                    "Captured source revision is not a member of this snapshot's release"
                )
            if revision.id == payload.get("selected_revision"):
                selected = revision
            if revision.artifact_sha not in raw_sources:
                if (
                    source_bytes + artifacts.path(revision.artifact_sha).stat().st_size
                    > MAX_SOURCE_BYTES
                ):
                    raise ValueError("Captured sources exceed the supported migration size")
                raw_sources[revision.artifact_sha] = artifacts.read(revision.artifact_sha)
                source_bytes += len(raw_sources[revision.artifact_sha])
                if source_bytes > MAX_SOURCE_BYTES:
                    raise ValueError("Captured sources exceed the supported migration size")
        if not selected or selected.artifact_sha != payload.get("original_sha256"):
            raise ValueError("Selected original SBOM does not match its local source revision")
        proof = {
            "kind": "local_snapshot_membership",
            "snapshot_id": snapshot.id,
            "snapshot_sha": snapshot.sha,
            "project_id": snapshot.project_id,
            "release_id": snapshot.release_id,
            "selected_revision": selected.id,
            "source_revision_ids": sorted(seen),
            "provider_authenticity": "not_verified",
        }
        return bundle, raw_sources, proof
    except (OSError, ValueError, TypeError, AttributeError) as error:
        raise HTTPException(
            409, f"Local migration input is unavailable or inconsistent: {error}"
        ) from error


@router.post("/projects/{project_id}/versions/{version}/migration/v2/preview")
def preview(
    project_id: str, version: Name, data: MigrationInput, request: Request, db: DB, actor: Auth
):
    snapshot = source_snapshot(project_id, data, db, actor)
    bundle, originals, proof = capture(snapshot, request.app.state.artifacts, db)
    try:
        return preview_migration(
            request.app.state.knowledge,
            project_id=project_id,
            version=version,
            actor_id=actor.user.id,
            data=data,
            bundle=bundle,
            source_artifacts=originals,
            source_proof=proof,
        )
    except Conflict as error:
        raise HTTPException(409, str(error)) from error


@router.post("/projects/{project_id}/versions/{version}/migration/v2/apply", status_code=201)
def apply(
    project_id: str, version: Name, data: MigrationApply, request: Request, db: DB, actor: Auth
):
    snapshot = source_snapshot(project_id, data, db, actor)
    journal = request.app.state.knowledge
    try:
        receipt = migration_receipt(
            journal, project_id=project_id, version=version, actor_id=actor.user.id, data=data
        )
        if not receipt:
            bundle, originals, proof = capture(snapshot, request.app.state.artifacts, db)
            receipt = apply_migration(
                journal,
                project_id=project_id,
                version=version,
                actor_id=actor.user.id,
                data=data,
                bundle=bundle,
                source_artifacts=originals,
                source_proof=proof,
            )
    except Conflict as error:
        raise HTTPException(409, str(error)) from error
    except CommitUncertain as error:
        return uncertain_response(error, data.request_id)
    return projected_response(request, receipt)
