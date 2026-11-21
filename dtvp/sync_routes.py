"""Read-only routes for the per-version sync state (ADR 0004)."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Callable, Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from .source_sync_state import SyncStateStore


def create_sync_router(
    sync_state: Callable[[], SyncStateStore],
    *,
    current_user_dependency: Callable[..., Any],
) -> APIRouter:
    router = APIRouter()

    @router.get("/sync/versions")
    def get_sync_versions(
        product: Optional[str] = Query(None, max_length=512),
        changed_since: Optional[str] = Query(None, max_length=64),
        _user: str = Depends(current_user_dependency),
    ) -> dict[str, Any]:
        """The sync state of every project version, or of one product; with
        ``changed_since`` (ISO 8601), only those whose content changed after
        it: what a client missed while disconnected."""
        if changed_since:
            try:
                datetime.fromisoformat(changed_since)
            except ValueError as exc:
                raise HTTPException(
                    status_code=422, detail="changed_since must be an ISO 8601 time"
                ) from exc
        return {
            "versions": sync_state().list_versions(
                product=product, changed_since=changed_since
            )
        }

    @router.get("/sync/status")
    def get_sync_status(
        _user: str = Depends(current_user_dependency),
    ) -> dict[str, Any]:
        return sync_state().status()

    return router
