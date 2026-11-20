import asyncio
import json
import os
from dataclasses import dataclass
from typing import Annotated, Any, Callable

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile

from .settings_files import write_settings_file as default_write_settings_file


@dataclass(frozen=True)
class SettingsRouteDeps:
    get_user_role: Callable[[str], str]
    load_team_mapping: Callable[[], dict[str, Any]]
    load_team_groups: Callable[[], dict[str, Any]]
    load_auto_analysis_guidance: Callable[[], dict[str, Any]]
    load_user_roles: Callable[[], dict[str, Any] | None]
    load_rescore_rules: Callable[[], dict[str, Any] | None]
    get_team_mapping_path: Callable[[], str]
    get_team_groups_path: Callable[[], str]
    get_auto_analysis_guidance_path: Callable[[], str]
    get_user_roles_path: Callable[[], str]
    get_rescore_rules_path: Callable[[], str]
    # Validates the document of a settings file, then writes it atomically
    # (``dtvp.settings_files.write_settings_file``).
    write_settings_file: Callable[..., str] = default_write_settings_file


def _require_reviewer(deps: SettingsRouteDeps, user: str, detail: str) -> None:
    if deps.get_user_role(user) != "REVIEWER":
        raise HTTPException(status_code=403, detail=detail)


def _ensure_parent_dir(path: str) -> None:
    dir_path = os.path.dirname(path)
    if dir_path:
        os.makedirs(dir_path, exist_ok=True)


async def _write(
    deps: SettingsRouteDeps,
    name: str,
    target_path: str,
    success_message: str,
    *,
    payload: Any = None,
    content: bytes | None = None,
    context: dict[str, Any] | None = None,
) -> dict[str, str]:
    """Validate and write a settings file; errors are reported, not raised."""
    _ensure_parent_dir(target_path)
    kwargs: dict[str, Any] = {"path": target_path, "context": context}
    if content is not None:
        kwargs["content"] = content
    else:
        kwargs["payload"] = payload
    try:
        await asyncio.to_thread(deps.write_settings_file, name, **kwargs)
    except Exception as exc:
        return {"status": "error", "message": str(exc)}
    return {"status": "success", "message": success_message}


def _register_mapping_routes(
    router: APIRouter,
    deps: SettingsRouteDeps,
    forbidden_response: dict[int | str, dict[str, Any]],
    current_user_dependency: Callable[..., Any],
) -> None:
    CurrentUser = Annotated[str, Depends(current_user_dependency)]

    @router.get("/settings/mapping", responses=forbidden_response)
    async def get_team_mapping(user: CurrentUser):
        # Component ownership is part of the analyst review context.  Keep the
        # mutating endpoints below reviewer-only, but let every authenticated
        # user resolve team-owned components consistently with the backend
        # filters.
        _ = user
        return deps.load_team_mapping()

    @router.post("/settings/mapping", responses=forbidden_response)
    async def upload_team_mapping(
        file: Annotated[UploadFile, File(...)],
        *,
        user: CurrentUser,
    ):
        _require_reviewer(deps, user, "Only reviewers can modify team mapping")
        target_path = deps.get_team_mapping_path()
        try:
            content = await file.read()
        except Exception as exc:
            return {"status": "error", "message": str(exc)}
        return await _write(
            deps,
            "team_mapping",
            target_path,
            f"Team mapping updated at {target_path}",
            content=content,
        )

    @router.put("/settings/mapping", responses=forbidden_response)
    async def update_team_mapping(
        mapping: dict[str, Any],
        *,
        user: CurrentUser,
    ):
        _require_reviewer(deps, user, "Only reviewers can modify team mapping")
        target_path = deps.get_team_mapping_path()
        return await _write(
            deps,
            "team_mapping",
            target_path,
            f"Team mapping updated at {target_path}",
            payload=mapping,
        )


def _register_team_group_routes(
    router: APIRouter,
    deps: SettingsRouteDeps,
    forbidden_response: dict[int | str, dict[str, Any]],
    current_user_dependency: Callable[..., Any],
) -> None:
    CurrentUser = Annotated[str, Depends(current_user_dependency)]

    @router.get("/settings/team-groups", responses=forbidden_response)
    async def get_team_groups(user: CurrentUser):
        _require_reviewer(deps, user, "Only reviewers can view team groups")
        return deps.load_team_groups()

    @router.put("/settings/team-groups", responses=forbidden_response)
    async def update_team_groups(
        groups: dict[str, Any],
        *,
        user: CurrentUser,
    ):
        _require_reviewer(deps, user, "Only reviewers can modify team groups")
        target_path = deps.get_team_groups_path()
        return await _write(
            deps,
            "team_groups",
            target_path,
            f"Team groups updated at {target_path}",
            payload=groups,
            context={"team_mapping": deps.load_team_mapping()},
        )


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
        try:
            content = await file.read()
        except Exception as exc:
            return {"status": "error", "message": str(exc)}
        return await _write(
            deps,
            "user_roles",
            target_path,
            f"User roles updated at {target_path}",
            content=content,
        )

    @router.put("/settings/roles", responses=forbidden_response)
    async def update_roles(
        roles: dict[str, str],
        *,
        user: CurrentUser,
    ):
        _require_reviewer(deps, user, "Only reviewers can modify roles")
        target_path = deps.get_user_roles_path()
        return await _write(
            deps,
            "user_roles",
            target_path,
            f"User roles updated at {target_path}",
            payload=roles,
        )

    @router.get("/known-users")
    async def get_known_users(user: CurrentUser):
        roles = deps.load_user_roles()
        if roles is None:
            return []
        return sorted(roles.keys())


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
        try:
            content = await file.read()
            payload = json.loads(content)
        except ValueError:
            return {"status": "error", "message": "Invalid JSON"}
        except Exception as exc:
            return {"status": "error", "message": str(exc)}
        # Stored re-indented, as before, not byte for byte.
        return await _write(
            deps,
            "auto_analysis_guidance",
            target_path,
            f"Auto-analysis guidance updated at {target_path}",
            payload=payload,
        )

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
        return await _write(
            deps,
            "auto_analysis_guidance",
            target_path,
            f"Auto-analysis guidance updated at {target_path}",
            payload=guidance,
        )


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
        try:
            content = await file.read()
        except Exception as exc:
            return {"status": "error", "message": str(exc)}
        return await _write(
            deps,
            "rescore_rules",
            target_path,
            f"Rescore rules updated at {target_path}",
            content=content,
        )

    @router.put("/settings/rescore-rules", responses=forbidden_response)
    async def update_rescore_rules(
        rules: dict[str, Any],
        *,
        user: CurrentUser,
    ):
        _require_reviewer(deps, user, "Only reviewers can modify rescore rules")
        target_path = deps.get_rescore_rules_path()
        return await _write(
            deps,
            "rescore_rules",
            target_path,
            f"Rescore rules updated at {target_path}",
            payload=rules,
        )


def create_settings_router(
    deps: SettingsRouteDeps,
    *,
    forbidden_response: dict[int | str, dict[str, Any]],
    current_user_dependency: Callable[..., Any],
) -> APIRouter:
    router = APIRouter()

    _register_mapping_routes(router, deps, forbidden_response, current_user_dependency)
    _register_team_group_routes(
        router,
        deps,
        forbidden_response,
        current_user_dependency,
    )
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
