"""Authenticated catalog and Dependency-Track import endpoints."""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Callable

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from .artifact_store import ArtifactStore
from .catalog_repository import ImportRequestConflict
from .catalog_repository import (
    get_import_run,
    get_snapshot_record,
    get_version_snapshot_record,
    list_product_versions,
    list_products,
)
from .source_import_service import import_source_scope

logger = logging.getLogger(__name__)


class DependencyTrackImportRequest(BaseModel):
    request_id: str = Field(min_length=1, max_length=255)
    project_id: str = Field(min_length=1, max_length=255)


def create_source_import_router(
    *,
    current_user_dependency: Callable[..., Any],
    client_dependency: Callable[..., Any],
    get_user_role: Callable[[str], str],
    connector: Any,
) -> APIRouter:
    router = APIRouter(prefix="/catalog", tags=["DTVP catalog"])

    @router.post("/sources/dependency-track/sync")
    @router.post("/sources/dependency-track/import")
    async def import_dependency_track_project(
        body: DependencyTrackImportRequest,
        *,
        client=Depends(client_dependency),
        user=Depends(current_user_dependency),
    ):
        if get_user_role(user).upper() != "REVIEWER":
            raise HTTPException(status_code=403, detail="Only reviewers can import sources")
        try:
            run = await import_source_scope(
                connector=connector,
                client=client,
                source_base_url=client.base_url,
                request_id=body.request_id,
                initiated_by=user,
                scope={"project_id": body.project_id},
            )
        except ImportRequestConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except Exception as exc:
            logger.exception("Could not start Dependency-Track import")
            raise HTTPException(
                status_code=503,
                detail="DTVP could not start the source import; check backend logs.",
            ) from exc
        return {"run": run}

    @router.get("/products")
    async def products(
        name: str | None = Query(default=None, max_length=255),
        user=Depends(current_user_dependency),
    ):
        return await asyncio.to_thread(list_products, name)

    @router.get("/products/{product_id}/versions")
    async def product_versions(
        product_id: str,
        user=Depends(current_user_dependency),
    ):
        return await asyncio.to_thread(list_product_versions, product_id)

    @router.get("/versions/{version_id}/snapshots/{snapshot_id}")
    async def version_snapshot(
        version_id: str,
        snapshot_id: str,
        user=Depends(current_user_dependency),
    ):
        record = await asyncio.to_thread(get_snapshot_record, snapshot_id)
        if record is None or record["product_version_id"] != version_id:
            raise HTTPException(status_code=404, detail="DTVP snapshot not found")
        try:
            payload = await asyncio.to_thread(
                ArtifactStore().get_json, record["payload_sha256"]
            )
        except FileNotFoundError as exc:
            logger.exception("DTVP snapshot artifact is missing (snapshot_id=%s)", snapshot_id)
            raise HTTPException(status_code=503, detail="DTVP snapshot artifact is unavailable") from exc
        except (ValueError, OSError) as exc:
            logger.exception("DTVP snapshot artifact failed verification (snapshot_id=%s)", snapshot_id)
            raise HTTPException(status_code=503, detail="DTVP snapshot artifact is invalid") from exc
        return {"snapshot": record, "payload": payload}

    @router.get("/versions/{version_id}/snapshot")
    async def latest_version_snapshot(
        version_id: str,
        revision: int | None = Query(default=None, ge=1),
        user=Depends(current_user_dependency),
    ):
        record = await asyncio.to_thread(get_version_snapshot_record, version_id, revision)
        if record is None:
            raise HTTPException(status_code=404, detail="DTVP snapshot not found")
        try:
            payload = await asyncio.to_thread(
                ArtifactStore().get_json, record["payload_sha256"]
            )
        except FileNotFoundError as exc:
            logger.exception("DTVP snapshot artifact is missing (snapshot_id=%s)", record["id"])
            raise HTTPException(status_code=503, detail="DTVP snapshot artifact is unavailable") from exc
        except (ValueError, OSError) as exc:
            logger.exception("DTVP snapshot artifact failed verification (snapshot_id=%s)", record["id"])
            raise HTTPException(status_code=503, detail="DTVP snapshot artifact is invalid") from exc
        return {"snapshot": record, "payload": payload}

    @router.get("/import-runs/{run_id}")
    async def import_run(
        run_id: str,
        user=Depends(current_user_dependency),
    ):
        run = await asyncio.to_thread(get_import_run, run_id)
        if run is None:
            raise HTTPException(status_code=404, detail="DTVP import run not found")
        return run

    @router.get("/import-runs/{run_id}/artifact")
    async def import_run_artifact(
        run_id: str,
        user=Depends(current_user_dependency),
    ):
        run = await asyncio.to_thread(get_import_run, run_id)
        if run is None:
            raise HTTPException(status_code=404, detail="DTVP import run not found")
        payload_sha256 = (run.get("cursor_after") or {}).get("payload_sha256")
        if not payload_sha256:
            raise HTTPException(status_code=404, detail="Import run has no retained artifact")
        try:
            payload = await asyncio.to_thread(ArtifactStore().get_json, payload_sha256)
        except (FileNotFoundError, ValueError, OSError) as exc:
            logger.exception("DTVP import artifact is unavailable (run_id=%s)", run_id)
            raise HTTPException(status_code=503, detail="DTVP import artifact is unavailable") from exc
        return {"run": run, "payload": payload}

    return router
