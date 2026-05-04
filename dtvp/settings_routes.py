import asyncio
import json
import os
from dataclasses import dataclass
from typing import Annotated, Any, Callable

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile


@dataclass(frozen=True)
class SettingsRouteDeps:
    get_user_role: Callable[[str], str]
    load_team_mapping: Callable[[], dict[str, Any]]
    load_user_roles: Callable[[], dict[str, Any] | None]
    load_rescore_rules: Callable[[], dict[str, Any] | None]
    get_team_mapping_path: Callable[[], str]
    get_user_roles_path: Callable[[], str]
    get_rescore_rules_path: Callable[[], str]
    write_bytes: Callable[[str, bytes], None]
    write_json: Callable[[str, Any], None]
    write_and_validate_json_bytes: Callable[[str, bytes], None]


def _require_reviewer(deps: SettingsRouteDeps, user: str, detail: str) -> None:
    if deps.get_user_role(user) != "REVIEWER":
        raise HTTPException(status_code=403, detail=detail)


def _ensure_parent_dir(path: str) -> None:
    dir_path = os.path.dirname(path)
    if dir_path:
        os.makedirs(dir_path, exist_ok=True)


def _register_mapping_routes(
    router: APIRouter,
    deps: SettingsRouteDeps,
    forbidden_response: dict[int | str, dict[str, Any]],
    current_user_dependency: Callable[..., Any],
) -> None:
    CurrentUser = Annotated[str, Depends(current_user_dependency)]

    @router.get("/settings/mapping", responses=forbidden_response)
    async def get_team_mapping(user: CurrentUser):
        _require_reviewer(deps, user, "Only reviewers can view team mapping")
        return deps.load_team_mapping()

    @router.post("/settings/mapping", responses=forbidden_response)
    async def upload_team_mapping(
        file: Annotated[UploadFile, File(...)],
        *,
        user: CurrentUser,
    ):
        _require_reviewer(deps, user, "Only reviewers can modify team mapping")
        target_path = deps.get_team_mapping_path()
        _ensure_parent_dir(target_path)

        try:
            content = await file.read()
            await asyncio.to_thread(
                deps.write_and_validate_json_bytes,
                target_path,
                content,
            )
            return {
                "status": "success",
                "message": f"Team mapping updated at {target_path}",
            }
        except Exception as exc:
            return {"status": "error", "message": str(exc)}

    @router.put("/settings/mapping", responses=forbidden_response)
    async def update_team_mapping(
        mapping: dict[str, Any],
        *,
        user: CurrentUser,
    ):
        _require_reviewer(deps, user, "Only reviewers can modify team mapping")
        target_path = deps.get_team_mapping_path()
        _ensure_parent_dir(target_path)

        try:
            await asyncio.to_thread(deps.write_json, target_path, mapping)
            return {
                "status": "success",
                "message": f"Team mapping updated at {target_path}",
            }
        except Exception as exc:
            return {"status": "error", "message": str(exc)}


def _register_role_routes(
    router: APIRouter,
    deps: SettingsRouteDeps,
    forbidden_response: dict[int | str, dict[str, Any]],
    current_user_dependency: Callable[..., Any],
) -> None:
    CurrentUser = Annotated[str, Depends(current_user_dependency)]

    @router.get("/settings/roles", responses=forbidden_response)
    async def get_roles(user: CurrentUser):
        _require_reviewer(deps, user, "Only reviewers can view roles")
        return deps.load_user_roles()

    @router.post("/settings/roles", responses=forbidden_response)
    async def upload_roles(
        file: Annotated[UploadFile, File(...)],
        *,
        user: CurrentUser,
    ):
        _require_reviewer(deps, user, "Only reviewers can modify roles")
        target_path = deps.get_user_roles_path()
        _ensure_parent_dir(target_path)

        try:
            content = await file.read()
            try:
                json.loads(content)
            except json.JSONDecodeError:
                return {"status": "error", "message": "Invalid JSON"}

            await asyncio.to_thread(deps.write_bytes, target_path, content)
            return {
                "status": "success",
                "message": f"User roles updated at {target_path}",
            }
        except Exception as exc:
            return {"status": "error", "message": str(exc)}

    @router.put("/settings/roles", responses=forbidden_response)
    async def update_roles(
        roles: dict[str, str],
        *,
        user: CurrentUser,
    ):
        _require_reviewer(deps, user, "Only reviewers can modify roles")
        target_path = deps.get_user_roles_path()
        _ensure_parent_dir(target_path)

        try:
            await asyncio.to_thread(deps.write_json, target_path, roles)
            return {
                "status": "success",
                "message": f"User roles updated at {target_path}",
            }
        except Exception as exc:
            return {"status": "error", "message": str(exc)}

    @router.get("/known-users")
    async def get_known_users(user: CurrentUser):
        roles = deps.load_user_roles()
        if roles is None:
            return []
        return sorted(roles.keys())


def _register_rescore_rule_routes(
    router: APIRouter,
    deps: SettingsRouteDeps,
    forbidden_response: dict[int | str, dict[str, Any]],
    current_user_dependency: Callable[..., Any],
) -> None:
    CurrentUser = Annotated[str, Depends(current_user_dependency)]

    @router.get("/settings/rescore-rules")
    async def get_rescore_rules(user: CurrentUser):
        rules = deps.load_rescore_rules()
        if rules is None:
            return {"transitions": []}
        return rules

    @router.post("/settings/rescore-rules", responses=forbidden_response)
    async def upload_rescore_rules(
        file: Annotated[UploadFile, File(...)],
        *,
        user: CurrentUser,
    ):
        _require_reviewer(deps, user, "Only reviewers can modify rescore rules")
        target_path = deps.get_rescore_rules_path()
        _ensure_parent_dir(target_path)

        try:
            content = await file.read()
            try:
                json.loads(content)
            except json.JSONDecodeError:
                return {"status": "error", "message": "Invalid JSON"}

            await asyncio.to_thread(deps.write_bytes, target_path, content)
            return {
                "status": "success",
                "message": f"Rescore rules updated at {target_path}",
            }
        except Exception as exc:
            return {"status": "error", "message": str(exc)}

    @router.put("/settings/rescore-rules", responses=forbidden_response)
    async def update_rescore_rules(
        rules: dict[str, Any],
        *,
        user: CurrentUser,
    ):
        _require_reviewer(deps, user, "Only reviewers can modify rescore rules")
        target_path = deps.get_rescore_rules_path()
        _ensure_parent_dir(target_path)

        try:
            await asyncio.to_thread(deps.write_json, target_path, rules)
            return {
                "status": "success",
                "message": f"Rescore rules updated at {target_path}",
            }
        except Exception as exc:
            return {"status": "error", "message": str(exc)}


def create_settings_router(
    deps: SettingsRouteDeps,
    *,
    forbidden_response: dict[int | str, dict[str, Any]],
    current_user_dependency: Callable[..., Any],
) -> APIRouter:
    router = APIRouter()

    _register_mapping_routes(router, deps, forbidden_response, current_user_dependency)
    _register_role_routes(router, deps, forbidden_response, current_user_dependency)
    _register_rescore_rule_routes(
        router,
        deps,
        forbidden_response,
        current_user_dependency,
    )

    return router
