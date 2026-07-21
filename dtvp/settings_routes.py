import asyncio
import json
import os
from dataclasses import dataclass
from typing import Annotated, Any, Callable

from fastapi import APIRouter, Depends, File, UploadFile

from .authorization import require_reviewer, validate_user_roles_config
from .rescore_rule_services import validate_rescore_rule_config
from .upload_security import (
    DEFAULT_SETTINGS_UPLOAD_MAX_BYTES,
    read_upload_limited,
)


@dataclass(frozen=True)
class SettingsRouteDeps:
    get_user_role: Callable[[str], str]
    load_team_mapping: Callable[[], dict[str, Any]]
    load_auto_analysis_guidance: Callable[[], dict[str, Any]]
    load_user_roles: Callable[[], dict[str, Any] | None]
    load_rescore_rules: Callable[[], dict[str, Any] | None]
    get_team_mapping_path: Callable[[], str]
    get_auto_analysis_guidance_path: Callable[[], str]
    get_user_roles_path: Callable[[], str]
    get_rescore_rules_path: Callable[[], str]
    write_bytes: Callable[[str, bytes], None]
    write_json: Callable[[str, Any], None]
    write_and_validate_json_bytes: Callable[[str, bytes], None]


def _require_reviewer(deps: SettingsRouteDeps, user: str, detail: str) -> None:
    require_reviewer(deps.get_user_role(user), detail)


def _ensure_parent_dir(path: str) -> None:
    dir_path = os.path.dirname(path)
    if dir_path:
        os.makedirs(dir_path, exist_ok=True)


async def _read_settings_upload(file: UploadFile) -> bytes:
    return await read_upload_limited(
        file,
        setting="DTVP_SETTINGS_UPLOAD_MAX_BYTES",
        default=DEFAULT_SETTINGS_UPLOAD_MAX_BYTES,
        label="Settings file",
    )


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

        content = await _read_settings_upload(file)
        try:
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

        content = await _read_settings_upload(file)
        try:
            try:
                parsed = json.loads(content)
            except json.JSONDecodeError:
                return {"status": "error", "message": "Invalid JSON"}
            try:
                roles = validate_user_roles_config(parsed)
            except ValueError as exc:
                return {
                    "status": "error",
                    "message": str(exc),
                }

            await asyncio.to_thread(deps.write_json, target_path, roles)
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
            normalized_roles = validate_user_roles_config(roles)
            await asyncio.to_thread(deps.write_json, target_path, normalized_roles)
            return {
                "status": "success",
                "message": f"User roles updated at {target_path}",
            }
        except Exception as exc:
            return {"status": "error", "message": str(exc)}

    @router.get("/known-users")
    async def get_known_users(user: CurrentUser):
        return sorted(deps.load_user_roles().keys())


def _register_auto_analysis_guidance_routes(
    router: APIRouter,
    deps: SettingsRouteDeps,
    forbidden_response: dict[int | str, dict[str, Any]],
    current_user_dependency: Callable[..., Any],
) -> None:
    CurrentUser = Annotated[str, Depends(current_user_dependency)]

    @router.get("/settings/auto-analysis-guidance", responses=forbidden_response)
    async def get_auto_analysis_guidance(user: CurrentUser):
        _require_reviewer(
            deps,
            user,
            "Only reviewers can view auto-analysis guidance",
        )
        return deps.load_auto_analysis_guidance()

    @router.post("/settings/auto-analysis-guidance", responses=forbidden_response)
    async def upload_auto_analysis_guidance(
        file: Annotated[UploadFile, File(...)],
        *,
        user: CurrentUser,
    ):
        _require_reviewer(
            deps,
            user,
            "Only reviewers can modify auto-analysis guidance",
        )
        target_path = deps.get_auto_analysis_guidance_path()
        _ensure_parent_dir(target_path)

        content = await _read_settings_upload(file)
        try:
            try:
                payload = json.loads(content)
            except json.JSONDecodeError:
                return {"status": "error", "message": "Invalid JSON"}
            if not isinstance(payload, dict):
                return {
                    "status": "error",
                    "message": "Auto-analysis guidance JSON must be an object",
                }

            await asyncio.to_thread(deps.write_json, target_path, payload)
            return {
                "status": "success",
                "message": f"Auto-analysis guidance updated at {target_path}",
            }
        except Exception as exc:
            return {"status": "error", "message": str(exc)}

    @router.put("/settings/auto-analysis-guidance", responses=forbidden_response)
    async def update_auto_analysis_guidance(
        guidance: dict[str, Any],
        *,
        user: CurrentUser,
    ):
        _require_reviewer(
            deps,
            user,
            "Only reviewers can modify auto-analysis guidance",
        )
        target_path = deps.get_auto_analysis_guidance_path()
        _ensure_parent_dir(target_path)

        try:
            await asyncio.to_thread(deps.write_json, target_path, guidance)
            return {
                "status": "success",
                "message": f"Auto-analysis guidance updated at {target_path}",
            }
        except Exception as exc:
            return {"status": "error", "message": str(exc)}


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

        content = await _read_settings_upload(file)
        try:
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
            validation_errors = validate_rescore_rule_config(rules)
            if validation_errors:
                return {
                    "status": "error",
                    "message": "; ".join(validation_errors),
                }
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
    _register_auto_analysis_guidance_routes(
        router,
        deps,
        forbidden_response,
        current_user_dependency,
    )
    _register_rescore_rule_routes(
        router,
        deps,
        forbidden_response,
        current_user_dependency,
    )

    return router
