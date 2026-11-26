"""REST endpoints of saved views, short links and default views (ADR 0015)."""

import asyncio
from typing import Annotated, Any, Callable, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict

from .first_seen import DEFAULT_CUTOFF_BASIS
from .saved_view_services import (
    CODE_LENGTH,
    MAX_GLOBAL_VIEWS,
    MAX_PERSONAL_VIEWS,
    SavedViewError,
    SavedViewStore,
)


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SavedViewCreateRequest(_Strict):
    name: str
    scope: Literal["personal", "global"] = "personal"
    project: Optional[str] = None
    query: str = ""


class SavedViewUpdateRequest(_Strict):
    name: Optional[str] = None
    scope: Optional[Literal["personal", "global"]] = None
    project: Optional[str] = None
    query: Optional[str] = None


class DefaultViewRequest(_Strict):
    target: Literal["user", "role"] = "user"
    role: Optional[str] = None
    project: Optional[str] = None
    code: Optional[str] = None


def create_saved_view_router(
    store: SavedViewStore,
    *,
    current_user_dependency: Callable[..., Any],
    get_user_role: Callable[[str], str],
) -> APIRouter:
    router = APIRouter()
    User = Annotated[str, Depends(current_user_dependency)]

    def role_of(user: str) -> str:
        return str(get_user_role(user) or "ANALYST").upper()

    async def run(method: Callable[..., Any], **kwargs: Any) -> Any:
        try:
            return await asyncio.to_thread(method, **kwargs)
        except SavedViewError as exc:
            raise HTTPException(status_code=exc.status, detail=str(exc)) from exc

    @router.get("/views")
    async def list_views(user: User, project: str = ""):
        role = role_of(user)
        views = await run(store.list_for, user=user, project=project or None)
        defaults = await run(
            store.defaults_for, user=user, role=role, project=project or None
        )
        return {
            "views": [view.public(user, role) for view in views],
            "defaults": defaults,
            "role": role,
            "can_manage_global": role == "REVIEWER",
            "limits": {
                "personal_views": MAX_PERSONAL_VIEWS,
                "global_views": MAX_GLOBAL_VIEWS,
                "code_length": CODE_LENGTH,
            },
        }

    @router.post("/views", status_code=201)
    async def create_view(req: SavedViewCreateRequest, user: User):
        role = role_of(user)
        view = await run(
            store.create,
            user=user,
            role=role,
            name=req.name,
            scope=req.scope,
            project=req.project,
            query=req.query,
            default_cutoff_basis=DEFAULT_CUTOFF_BASIS,
        )
        return view.public(user, role)

    @router.put("/views/defaults")
    async def set_default(req: DefaultViewRequest, user: User):
        role = role_of(user)
        await run(
            store.set_default,
            user=user,
            role=role,
            target=req.target,
            target_role=req.role,
            project=req.project,
            code=req.code,
        )
        return await run(
            store.defaults_for, user=user, role=role, project=req.project or None
        )

    @router.get("/views/{code}")
    async def resolve_view(code: str, user: User):
        view = await run(store.get, code=code)
        if view is None:
            raise HTTPException(status_code=404, detail="View not found")
        return view.public(user, role_of(user))

    @router.patch("/views/{code}")
    async def update_view(code: str, req: SavedViewUpdateRequest, user: User):
        role = role_of(user)
        changes = req.model_dump(exclude_unset=True)
        if changes.get("scope") is None:
            changes.pop("scope", None)
        if "name" in changes and changes["name"] is None:
            changes.pop("name")
        if "query" in changes and changes["query"] is None:
            changes.pop("query")
        view = await run(
            store.update, user=user, role=role, code=code, changes=changes,
            default_cutoff_basis=DEFAULT_CUTOFF_BASIS,
        )
        return view.public(user, role)

    @router.delete("/views/{code}")
    async def delete_view(code: str, user: User):
        await run(store.delete, user=user, role=role_of(user), code=code)
        return {"status": "deleted", "code": code}

    return router
