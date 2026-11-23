"""Routes for the per-version sync state, requests and cancelling (ADR 0004)."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Callable, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from .source_sync_state import SourceUnavailable, SyncStateStore


class SyncRequest(BaseModel):
    """One project version, or every active version of a product."""

    project_uuid: Optional[str] = Field(default=None, min_length=1, max_length=200)
    product: Optional[str] = Field(default=None, min_length=1, max_length=512)


class SyncCancel(BaseModel):
    """What to stop: ``pass`` (the portfolio pass), ``requests`` (the waiting
    requests), ``running`` (the running version syncs); all three when left
    out."""

    scope: Optional[list[str]] = Field(default=None, max_length=3)


def create_sync_router(
    sync_state: Callable[[], SyncStateStore],
    *,
    current_user_dependency: Callable[..., Any],
    scheduler_status: Optional[Callable[[], dict[str, Any]]] = None,
    review_markers_kept: Optional[Callable[[], dict[str, dict[str, int]]]] = None,
    scheduler: Any = None,
    is_reviewer: Callable[[str], bool] = lambda _user: False,
) -> APIRouter:
    router = APIRouter()

    def versions_of(req: SyncRequest) -> list[str]:
        if bool(req.project_uuid) == bool(req.product):
            raise HTTPException(
                status_code=422, detail="Give either project_uuid or product"
            )
        rows = [
            row
            for row in sync_state().list_versions()
            if row.get("active_in_dt") and row.get("status") != "gone"
        ]
        if req.project_uuid:
            uuids = [row["project_uuid"] for row in rows if row["project_uuid"] == req.project_uuid]
        else:
            name = str(req.product).strip().lower()
            uuids = [
                row["project_uuid"]
                for row in rows
                if str(row.get("product_name") or "").strip().lower() == name
            ]
        if not uuids:
            raise HTTPException(status_code=404, detail="No active project version found")
        return uuids

    def require_reviewer(user: str) -> None:
        if not is_reviewer(user):
            raise HTTPException(status_code=403, detail="Reviewer role required")

    @router.post("/sync/requests")
    def request_reads(
        req: SyncRequest, user: str = Depends(current_user_dependency)
    ) -> dict[str, Any]:
        """Read a version, or every active version of a product, from the
        source before anything else (reviewers only). The request is
        persisted; its progress is under ``request`` in
        ``GET /sync/versions``. A repeat while one waits returns the waiting
        request's id."""
        require_reviewer(user)
        if scheduler is None:
            raise HTTPException(status_code=503, detail="The sync scheduler is not running")
        uuids = versions_of(req)
        requests = scheduler.request_reads(uuids, by=user)
        return {
            # One entry per version with its request id; ``new`` is False
            # for a request that was already waiting (repeats are one).
            "requests": requests,
            "requested": [entry["project_uuid"] for entry in requests if entry["new"]],
            "already_requested": [
                entry["project_uuid"] for entry in requests if not entry["new"]
            ],
        }

    @router.post("/sync/analysis-requests")
    async def request_analysis(
        req: SyncRequest, user: str = Depends(current_user_dependency)
    ) -> dict[str, Any]:
        """Ask the source to analyse a version, or every active version of a
        product, again; each is read when its analysis has finished
        (reviewers only). 501 when the source cannot be asked."""
        require_reviewer(user)
        if scheduler is None:
            raise HTTPException(status_code=503, detail="The sync scheduler is not running")
        if not scheduler.can_request_analysis:
            raise HTTPException(
                status_code=501, detail="The source cannot be asked for an analysis"
            )
        uuids = versions_of(req)
        try:
            accepted = await scheduler.request_analysis(uuids, by=user)
        except SourceUnavailable as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        return {
            "requested": accepted,
            "already_running": [uuid for uuid in uuids if uuid not in accepted],
        }

    @router.post("/sync/cancel")
    def cancel(req: SyncCancel, user: str = Depends(current_user_dependency)) -> dict[str, Any]:
        """Stop the running portfolio pass, withdraw the waiting requests and
        cancel the running version syncs (reviewers only). Staged reads are
        dropped; nothing counts as a failure."""
        require_reviewer(user)
        if scheduler is None:
            raise HTTPException(status_code=503, detail="The sync scheduler is not running")
        scope = req.scope or None
        if scope is not None:
            unknown = sorted(set(scope) - set(scheduler.CANCEL_SCOPES))
            if unknown:
                raise HTTPException(
                    status_code=422, detail=f"Unknown scope: {', '.join(unknown)}"
                )
        return scheduler.cancel(scope, by=user)

    @router.post("/sync/resume")
    def resume(user: str = Depends(current_user_dependency)) -> dict[str, Any]:
        """End the pause a cancel left (reviewers only)."""
        require_reviewer(user)
        if scheduler is None:
            raise HTTPException(status_code=503, detail="The sync scheduler is not running")
        scheduler.resume(by=user)
        return {"paused": False}

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
        status = sync_state().status()
        if scheduler_status is not None:
            # The scheduler's breaker, queue and watched products.
            status["scheduler_state"] = scheduler_status()
        if review_markers_kept is not None:
            # Per project version, why carried assessments kept their review
            # marker at the last read (plan_recreated_reviews).
            status["review_markers_kept"] = {
                project: dict(counts)
                for project, counts in review_markers_kept().items()
                if counts
            }
        return status

    return router
