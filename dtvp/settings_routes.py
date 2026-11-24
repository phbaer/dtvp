import asyncio
import json
import os
from dataclasses import dataclass
from typing import Annotated, Any, Awaitable, Callable, Optional

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile

from .settings_files import write_settings_file as default_write_settings_file
from .team_config import (
    is_team_format,
    selector_mapping,
    team_config_errors,
    team_config_from_document,
)


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
    # ``TeamMappingReportService.current`` (dtvp.team_mapping_report).
    mapping_report: Optional[Callable[..., Awaitable[dict[str, Any]]]] = None
    # The mapping file as stored (either format); defaults to
    # ``load_team_mapping``, which is the same for the older format.
    load_team_mapping_document: Optional[Callable[[], dict[str, Any]]] = None
    # ``TeamMappingReportService.tree`` and ``.preview``.
    mapping_tree: Optional[Callable[..., Awaitable[dict[str, Any]]]] = None
    mapping_preview: Optional[Callable[..., Awaitable[dict[str, Any]]]] = None


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


def _team_mapping_payload(payload: Any) -> tuple[Any, list[str]]:
    """What a save writes: the team format. A document in the older
    selector format is converted; one organised by team is checked as sent,
    then written normalised."""
    if not isinstance(payload, dict):
        return payload, ["Team mapping must be a JSON object"]
    if is_team_format(payload):
        errors = team_config_errors(payload)
        if errors:
            return payload, errors
    return team_config_from_document(payload).document(), []


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

    @router.get("/settings/mapping/report", responses=forbidden_response)
    async def get_team_mapping_report(
        user: CurrentUser,
        refresh: Annotated[bool, Query()] = False,
    ):
        """Findings that fall to ``*`` by project root and top-level
        component, findings owned per entry, and the component inventory.
        Built in the background: ``status`` is ``building`` (with the last
        report, ``stale`` when its inputs changed), ``ready`` or ``failed``.
        Everyone reads it; ``refresh`` (build again) is reviewer-only."""
        if deps.mapping_report is None:
            raise HTTPException(status_code=503, detail="The mapping report is not available")
        if refresh:
            _require_reviewer(deps, user, "Only reviewers can rebuild the mapping report")
        return await deps.mapping_report(refresh=refresh)

    @router.get("/settings/mapping/tree", responses=forbidden_response)
    async def get_team_mapping_tree(
        user: CurrentUser,
        project_uuid: Annotated[str, Query(min_length=1, max_length=200)],
        ref: Annotated[Optional[str], Query(max_length=2000)] = None,
    ):
        """One level of a version's BOM tree: the root, or the children of
        ``ref``, each with its owner (team and why) and finding counts."""
        _ = user
        if deps.mapping_tree is None:
            raise HTTPException(status_code=503, detail="The mapping tree is not available")
        try:
            return await deps.mapping_tree(project_uuid, ref)
        except LookupError as exc:
            raise HTTPException(
                status_code=404, detail="No active version or component with this id"
            ) from exc

    @router.post("/settings/mapping/tree", responses=forbidden_response)
    async def draft_team_mapping_tree(
        body: dict[str, Any],
        *,
        user: CurrentUser,
    ):
        """One level of a version's BOM tree as ``mapping`` (either format,
        not saved yet) would own it; a node whose owner differs under the
        saved mapping carries that as ``saved_owner``. Reviewer-only, like
        the preview."""
        _require_reviewer(deps, user, "Only reviewers can preview team mapping changes")
        if deps.mapping_tree is None:
            raise HTTPException(status_code=503, detail="The mapping tree is not available")
        mapping = body.get("mapping")
        project_uuid = body.get("project_uuid")
        ref = body.get("ref")
        if not isinstance(mapping, dict):
            raise HTTPException(status_code=422, detail="mapping must be an object")
        if not isinstance(project_uuid, str) or not 0 < len(project_uuid) <= 200:
            raise HTTPException(status_code=422, detail="project_uuid must be a version id")
        if ref is not None and (not isinstance(ref, str) or len(ref) > 2000):
            raise HTTPException(status_code=422, detail="ref must be a component reference")
        try:
            return await deps.mapping_tree(project_uuid, ref, selector_mapping(mapping))
        except LookupError as exc:
            raise HTTPException(
                status_code=404, detail="No active version or component with this id"
            ) from exc

    @router.post("/settings/mapping/preview", responses=forbidden_response)
    async def preview_team_mapping(
        body: dict[str, Any],
        *,
        user: CurrentUser,
    ):
        """Findings that would change owner if ``mapping`` (either format)
        replaced the saved one; ``projects`` limits it to these projects.
        Reviewer-only, like saving."""
        _require_reviewer(deps, user, "Only reviewers can preview team mapping changes")
        if deps.mapping_preview is None:
            raise HTTPException(status_code=503, detail="The mapping preview is not available")
        mapping = body.get("mapping")
        projects = body.get("projects")
        if not isinstance(mapping, dict):
            raise HTTPException(status_code=422, detail="mapping must be an object")
        if projects is not None and (
            not isinstance(projects, list) or not all(isinstance(item, str) for item in projects)
        ):
            raise HTTPException(status_code=422, detail="projects must be a list of names")
        return await deps.mapping_preview(selector_mapping(mapping), projects or None)

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
            parsed = json.loads(content)
        except ValueError:
            return {"status": "error", "message": "Invalid JSON"}
        except Exception as exc:
            return {"status": "error", "message": str(exc)}
        payload, errors = _team_mapping_payload(parsed)
        if errors:
            return {"status": "error", "message": "; ".join(errors)}
        return await _write(
            deps,
            "team_mapping",
            target_path,
            f"Team mapping updated at {target_path}",
            payload=payload,
        )

    @router.put("/settings/mapping", responses=forbidden_response)
    async def update_team_mapping(
        mapping: dict[str, Any],
        *,
        user: CurrentUser,
    ):
        _require_reviewer(deps, user, "Only reviewers can modify team mapping")
        target_path = deps.get_team_mapping_path()
        payload, errors = _team_mapping_payload(mapping)
        if errors:
            return {"status": "error", "message": "; ".join(errors)}
        return await _write(
            deps,
            "team_mapping",
            target_path,
            f"Team mapping updated at {target_path}",
            payload=payload,
        )

    @router.get("/settings/mapping/teams", responses=forbidden_response)
    async def get_team_mapping_teams(user: CurrentUser):
        """The mapping organised by team, for the editor. ``format`` says
        how the file is stored; a file in the older selector format is
        converted here (``warnings`` name what the conversion dropped) and
        written by team on the next save."""
        _ = user
        load = deps.load_team_mapping_document or deps.load_team_mapping
        config = team_config_from_document(load())
        return {
            "format": config.source_format,
            "teams": config.document(),
            "warnings": config.warnings,
        }


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
            # The team document: it also names teams without selectors.
            context={
                "team_mapping": (deps.load_team_mapping_document or deps.load_team_mapping)()
            },
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
