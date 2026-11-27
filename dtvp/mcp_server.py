"""MCP endpoint for AI agents (see docs/adr/0001 and docs/ai-access.md).

``McpToolService`` holds the behaviour and has no dependency on the MCP SDK;
``build_mcp_server`` exposes it as tools and ``create_mcp_app`` wraps the
Streamable HTTP transport in access-token authentication.

Every write made here is recorded with analyst authority, whatever the
token owner's role, names the token it came through, and is written to the
audit log. A team assessment is marked pending review and cannot approve or
change SSVC. Code evidence is stored beside the analyzer results and changes
no assessment at all: a person decides whether to use it. Text supplied by
the agent is data, never structure.
"""

import asyncio
import json
import re
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any, AsyncIterator, Awaitable, Callable

from .finding_keys import instance_finding_key
from .access_token_services import (
    SCOPE_READ,
    SCOPE_WRITE,
    AccessToken,
    AccessTokenStore,
    access_tokens_enabled,
    looks_like_access_token,
)
from .assessment_model import (
    ANALYSIS_JUSTIFICATIONS,
    RESERVED_DETAIL_PATTERN,
    analysis_response,
    set_shared_response,
)
from .assessment_review import changes_requests
from .assessment_use_cases import (
    AssessmentConflictError,
    AssessmentRequest,
    AssessmentUseCaseError,
    save_assessment,
    validate_code_evidence,
)
from .general_api_routes import (
    hydrate_task_group_detail,
    query_task_group_window,
    refresh_grouped_vuln_task_snapshots,
    start_grouped_vuln_task,
    task_for_user,
)
from .code_evidence_services import (
    CodeEvidenceError,
    normalize_evidence_input,
    resolve_targets,
)
from .logic import STATE_PRIORITY, global_decision, parse_assessment_blocks

AGENT_ROLE = "ANALYST"
ANALYSIS_STATES = tuple(STATE_PRIORITY)
MAX_DETAILS_LENGTH = 8000
MAX_SEARCH_LIMIT = 100
MAX_DEPENDENCY_CHAINS = 5
MAX_EVIDENCE_LIST_LIMIT = 50
MAX_ANALYZER_REPORT_LENGTH = 8000
DEFAULT_TASK_WAIT_SECONDS = 120.0
TASK_POLL_SECONDS = 0.1
SERVER_INSTRUCTIONS = """\
DTVP reviews Dependency-Track vulnerabilities across the versions of a project.

Read first: list_projects, then search_vulnerabilities, then get_vulnerability.
get_vulnerability returns every finding with its current revision and the
teams responsible for it.

To improve an assessment, call preview_assessment, check the result, then
call save_assessment with the same arguments plus the revisions you read.
You write one team's assessment at a time. Your change is recorded as that
team's draft and stays pending until a human reviewer approves it. You cannot
approve, write the General assessment, change CVSS or SSVC, or overwrite a
finding that changed after you read it: on a conflict, read it again.

Optional justification sets your team's NOT_AFFECTED reason; omit to preserve
it or pass NOT_SET to clear it. Valid values: dtvp://assessment-rules.
Optional code_evidence_ids selects supporting evidence for your team's draft;
omit/null to keep existing selections, [] to deselect. Evidence selection never
approves an assessment. Pass the same arguments from preview to save.

Write details as plain prose with your evidence and reasoning. Do not include
bracketed tags or '---' separators.

Use add_code_evidence to record what you found in the code (Markdown allowed).
Evidence never changes an assessment; a person decides whether to use it.
Check list_code_evidence first to avoid duplicates; pass an idempotency_key
when retrying. Provide assessment_summary as standalone decision rationale,
separate from the detailed report. Use add_code_evidence_attachment to upload
actual supporting bytes; local paths are not available to reviewers.
"""


def _shown_analyzer_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The analyzer runs the evidence list in the UI shows: benchmark-derived
    records are comparisons of a run, not evidence of their own."""
    return [
        record
        for record in records
        if str(record.get("source") or "").strip().lower() != "benchmark"
    ]


class McpToolError(Exception):
    """A failure the calling agent can understand and act on."""


@dataclass(frozen=True)
class McpServerDeps:
    route_deps: Any
    token_store: AccessTokenStore
    get_dt_client: Callable[[], Awaitable[Any]]
    logger: Any
    task_wait_seconds: float = DEFAULT_TASK_WAIT_SECONDS
    # Told of every authenticated MCP request (the sync's activity).
    note_request: Callable[[str], None] = lambda _user: None


def agent_label(token: AccessToken) -> str:
    # The label is written into a block header, which ends at the first
    # "---": keep it to plain words and single hyphens.
    cleaned = re.sub(r"[^A-Za-z0-9 ._-]", "", token.name)
    cleaned = re.sub(r"-{2,}", "-", cleaned)
    cleaned = " ".join(cleaned.split())[:40].strip(" -")
    return cleaned or f"token {token.token_id}"


def _components(group: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        component
        for version in group.get("affected_versions") or []
        for component in version.get("components") or []
        if isinstance(component, dict)
    ]


def _team_key(value: Any) -> str:
    return str(value or "").strip().casefold()


class McpToolService:
    def __init__(self, deps: McpServerDeps) -> None:
        self.deps = deps

    # -- helpers ----------------------------------------------------------

    @staticmethod
    def _require_scope(token: AccessToken, scope: str) -> None:
        if not token.has_scope(scope):
            raise McpToolError(f"This access token lacks the '{scope}' scope")

    async def _resolve_project(self, project: str) -> str:
        name = str(project or "").strip()
        if not name:
            raise McpToolError("A project name is required; see list_projects")
        client = await self.deps.get_dt_client()
        try:
            projects = await self.deps.route_deps.cache_manager.get_projects(
                client, name
            )
        except Exception as exc:
            self.deps.logger.error("MCP project lookup failed: %s", exc)
            raise McpToolError(
                "Project data is currently unavailable; try again later"
            ) from exc
        for candidate in projects:
            candidate_name = str(candidate.get("name") or "")
            if candidate_name.casefold() == name.casefold():
                return candidate_name
        raise McpToolError(f"Unknown project '{name}'; see list_projects")

    async def _project_task(self, token: AccessToken, project: str) -> dict[str, Any]:
        """Return the completed grouped snapshot for a project, building or
        joining the shared computation the web UI uses."""
        route_deps = self.deps.route_deps
        name = await self._resolve_project(project)
        started = start_grouped_vuln_task(
            route_deps,
            name=name,
            cve=None,
            response_mode="summary",
            user=token.username,
        )
        deadline = time.monotonic() + self.deps.task_wait_seconds
        while True:
            task = task_for_user(route_deps, started["task_id"], token.username)
            if task is None:
                raise McpToolError("The project snapshot expired; try again")
            status = task.get("status")
            if status == "completed":
                return task
            if status == "failed":
                raise McpToolError(
                    "Loading the project failed: "
                    f"{task.get('message') or 'unknown error'}"
                )
            if time.monotonic() >= deadline:
                raise McpToolError(
                    "The project is still loading "
                    f"({task.get('progress') or 0}% done); try again shortly"
                )
            await asyncio.sleep(TASK_POLL_SECONDS)

    @staticmethod
    def _find_group(task: dict[str, Any], vulnerability_id: str) -> dict[str, Any]:
        wanted = str(vulnerability_id or "").strip().casefold()
        if not wanted:
            raise McpToolError("A vulnerability id is required")
        groups = task.get("_full_result_by_id") or {}
        for group_id, group in groups.items():
            if str(group_id).casefold() == wanted:
                return group
        for group in groups.values():
            if any(str(alias).casefold() == wanted for alias in group.get("aliases") or []):
                return group
        raise McpToolError(
            f"Vulnerability '{vulnerability_id}' was not found in this project"
        )

    async def _current_analyses(
        self, components: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """The stored assessment of each finding, read from local state by
        its project/component/vulnerability identity.

        Neither the caller nor the shared task snapshot is trusted here: the
        snapshot is a view that other requests can refresh.
        """
        return await asyncio.to_thread(
            self.deps.route_deps.cache_manager.get_cached_assessments,
            components,
        )

    @staticmethod
    def _assessment_view(details: str) -> dict[str, Any]:
        shared_text, blocks = parse_assessment_blocks(details)
        return {
            "pending_review": "[status: pending review]" in details.casefold(),
            "changes_requested": changes_requests(details),
            # What is done about the finding; part of the Global assessment
            # and set by reviewers in the web form, not through these tools.
            "response": analysis_response(details),
            "unstructured_text": set_shared_response(shared_text, None),
            "blocks": [
                {
                    "team": block.get("team"),
                    "state": block.get("state"),
                    "justification": block.get("justification") or "NOT_SET",
                    "assessed_by": block.get("user"),
                    "reviewed_by": block.get("reviewer"),
                    "assessed_at_ms": int(block["timestamp"]) if block.get("timestamp") else None,
                    "reviewed_at_ms": block.get("reviewed_at_ms"),
                    "historical": bool(block.get("historical")),
                    "rescored_cvss": block.get("rescored"),
                    "rescored_vector": block.get("vector"),
                    "assigned": block.get("assigned") or [],
                    "details": block.get("details") or "",
                }
                for block in blocks
            ],
        }

    @staticmethod
    def _group_vuln_ids(group: dict[str, Any]) -> list[str]:
        return [
            str(value)
            for value in [group.get("id"), *(group.get("aliases") or [])]
            if str(value or "").strip()
        ]

    def _evidence_store(self) -> Any:
        store = getattr(self.deps.route_deps, "code_evidence_store", None)
        if store is None:
            raise McpToolError("Code evidence is not available on this server")
        return store

    async def _evidence_counts(
        self, project_name: Any, group: dict[str, Any]
    ) -> dict[str, int]:
        """How much evidence exists; a cheap hint that the tools exist."""
        vuln_ids = self._group_vuln_ids(group)
        store = getattr(self.deps.route_deps, "code_evidence_store", None)
        result_store = getattr(self.deps.route_deps, "code_analysis_result_store", None)
        agent = 0
        analyzer = 0
        try:
            if store is not None:
                agent = len(
                    await asyncio.to_thread(
                        store.list_for_vulnerability, str(project_name or ""), vuln_ids
                    )
                )
            if result_store is not None:
                analyzer = len(
                    _shown_analyzer_records(
                        await asyncio.to_thread(
                            result_store.list_result_metadata,
                            project_name=str(project_name or ""),
                            vuln_ids=vuln_ids,
                            limit=1000,
                        )
                    )
                )
        except Exception:
            self.deps.logger.exception("Counting code evidence failed")
        return {"agent": agent, "analyzer": analyzer}

    async def _audit(
        self,
        token: AccessToken,
        *,
        action: str,
        outcome: str,
        target: dict[str, Any],
        detail: str = "",
    ) -> None:
        await asyncio.to_thread(
            self.deps.token_store.record_audit,
            token=token,
            agent=agent_label(token),
            action=action,
            outcome=outcome,
            target=target,
            detail=detail,
        )

    # -- read tools -------------------------------------------------------

    async def list_projects(self, token: AccessToken, name: str = "") -> dict[str, Any]:
        self._require_scope(token, SCOPE_READ)
        client = await self.deps.get_dt_client()
        try:
            projects = await self.deps.route_deps.cache_manager.get_projects(
                client, str(name or "").strip()
            )
        except Exception as exc:
            self.deps.logger.error("MCP project listing failed: %s", exc)
            raise McpToolError(
                "Project data is currently unavailable; try again later"
            ) from exc
        versions_by_name: dict[str, list[str]] = {}
        for project in projects:
            project_name = str(project.get("name") or "").strip()
            if not project_name:
                continue
            versions = versions_by_name.setdefault(project_name, [])
            version = str(project.get("version") or "").strip()
            if version and version not in versions:
                versions.append(version)
        return {
            "projects": [
                {"name": project_name, "versions": versions}
                for project_name, versions in sorted(versions_by_name.items())
            ]
        }

    async def search_vulnerabilities(
        self,
        token: AccessToken,
        *,
        project: str,
        query: str = "",
        lifecycle: list[str] | None = None,
        teams: list[str] | None = None,
        severity: list[str] | None = None,
        analysis_state: list[str] | None = None,
        awaiting_review: bool = False,
        cutoff: str = "",
        cutoff_mode: str = "before",
        cutoff_basis: str = "",
        limit: int = 25,
        offset: int = 0,
    ) -> dict[str, Any]:
        self._require_scope(token, SCOPE_READ)
        limit = max(1, min(int(limit), MAX_SEARCH_LIMIT))
        offset = max(0, int(offset))
        task = await self._project_task(token, project)
        try:
            window = await asyncio.to_thread(
                query_task_group_window,
                self.deps.route_deps,
                task,
                q=str(query or ""),
                lifecycle=[str(v).upper() for v in lifecycle or []],
                teams=[str(v) for v in teams or []],
                original_severity=[str(v).upper() for v in severity or []],
                analysis=[str(v).upper() for v in analysis_state or []],
                awaiting_review=bool(awaiting_review),
                cutoff=str(cutoff or ""),
                cutoff_mode=str(cutoff_mode or "before"),
                cutoff_basis=str(cutoff_basis or ""),
                limit=limit,
                offset=offset,
                include_counts=bool(cutoff),
            )
        except ValueError as exc:
            raise McpToolError(str(exc)) from exc
        items = []
        for item in window.get("items") or []:
            metadata = item.get("list_metadata") or {}
            items.append(
                {
                    "id": item.get("id"),
                    "aliases": sorted(item.get("aliases") or []),
                    "title": item.get("title"),
                    "severity": item.get("severity"),
                    "original_severity": item.get("original_severity"),
                    "cvss_score": item.get("cvss_score"),
                    "rescored_cvss": item.get("rescored_cvss"),
                    "lifecycle": metadata.get("lifecycle"),
                    "analysis_state": metadata.get("technical_state"),
                    "pending_review": bool(metadata.get("is_pending")),
                    "teams": item.get("tags") or [],
                    "assessed_teams": metadata.get("assessed_teams") or [],
                    "components": metadata.get("component_names") or [],
                    "versions": metadata.get("versions") or [],
                    "new_findings": int(metadata.get("new_finding_count") or 0),
                }
            )
        cutoff_fields = (
            {
                "cutoff_basis": window.get("cutoff_basis"),
                "date_unknown": int(
                    ((window.get("counts") or {}).get("filtered") or {}).get(
                        "cutoff_unknown"
                    )
                    or 0
                )
            }
            if cutoff
            else {}
        )
        return {
            "project": task.get("_project_name"),
            **cutoff_fields,
            "matching": window.get("filtered", len(items)),
            "project_total": window.get("total", len(items)),
            "offset": offset,
            "limit": limit,
            "has_more": bool(window.get("has_more")),
            "items": items,
        }

    async def get_vulnerability(
        self,
        token: AccessToken,
        *,
        project: str,
        vulnerability_id: str,
    ) -> dict[str, Any]:
        self._require_scope(token, SCOPE_READ)
        task = await self._project_task(token, project)
        group = self._find_group(task, vulnerability_id)
        hydrated = await asyncio.to_thread(
            hydrate_task_group_detail, self.deps.route_deps, task, group
        )
        findings = []
        variants: dict[str, dict[str, Any]] = {}
        decided_blocks: list[dict[str, Any]] = []
        components = _components(hydrated)
        for component, current in zip(
            components, await self._current_analyses(components)
        ):
            chains = component.get("dependency_chains") or []
            findings.append(
                {
                    "finding_uuid": component.get("finding_uuid"),
                    "project_version": component.get("project_version"),
                    "component": component.get("component_name"),
                    "component_version": component.get("component_version"),
                    "component_purl": component.get("component_purl"),
                    "responsible_teams": component.get("tags") or [],
                    "analysis_state": current["state"],
                    "suppressed": current["suppressed"],
                    "revision": current["revision"],
                    "sync_status": current["sync_status"],
                    "attributed_on": component.get("attributed_on"),
                    "new_finding": bool(component.get("is_new_finding")),
                    "dependency_chains": chains[:MAX_DEPENDENCY_CHAINS],
                    "dependency_chains_truncated": bool(
                        component.get("dependency_chains_truncated")
                        or len(chains) > MAX_DEPENDENCY_CHAINS
                    ),
                }
            )
            # The same assessment written with different spacing is one
            # assessment; two writers once left a blank line in or out.
            variant = variants.setdefault(
                " ".join(str(current["details"] or "").split()),
                {**self._assessment_view(current["details"]), "finding_uuids": []},
            )
            variant["finding_uuids"].append(component.get("finding_uuid"))
            decided_blocks.extend(parse_assessment_blocks(str(current["details"] or ""))[1])
        decision = global_decision(decided_blocks)
        metadata = group.get("list_metadata") or {}
        return {
            "project": task.get("_project_name"),
            "id": hydrated.get("id"),
            "aliases": sorted(hydrated.get("aliases") or []),
            "title": hydrated.get("title"),
            "description": hydrated.get("description"),
            "severity": hydrated.get("severity"),
            "original_severity": hydrated.get("original_severity"),
            "cvss_score": hydrated.get("cvss_score"),
            "cvss_vector": hydrated.get("cvss_vector"),
            "rescored_cvss": hydrated.get("rescored_cvss"),
            "rescored_vector": hydrated.get("rescored_vector"),
            "responsible_teams": hydrated.get("tags") or [],
            "ssvc": hydrated.get("ssvc_summary"),
            "exploitation_evidence": hydrated.get("evidence_sources") or [],
            "code_analysis": hydrated.get("code_assessment_status"),
            "code_evidence": await self._evidence_counts(
                task.get("_project_name"), hydrated
            ),
            "findings": findings,
            # One entry when every finding carries the same assessment text.
            "assessments": list(variants.values()),
            "assessments_consistent": len(variants) <= 1,
            "lifecycle": metadata.get("lifecycle"),
            # The effective Global decision (docs/assessment-model.md#the-global-decision):
            # set by a reviewer (manual), else the worst team decision (derived).
            "global_decision": {
                "source": decision["source"],
                "state": decision["state"],
                "justification": decision["justification"],
                "teams": decision["teams"],
                "derived_state": (decision["derived"] or {}).get("state", "NOT_SET"),
                "derived_teams": (decision["derived"] or {}).get("teams", []),
            },
            "valid_states": list(ANALYSIS_STATES),
        }

    async def get_sync_status(self, token: AccessToken) -> dict[str, Any]:
        self._require_scope(token, SCOPE_READ)
        cache_manager = self.deps.route_deps.cache_manager
        status = await asyncio.to_thread(cache_manager.get_cache_status)
        return {
            "pending_exports": status.get("pending_updates", 0),
            "failed_exports": status.get("failed_exports", 0),
            "last_import_at": status.get("last_refreshed_at"),
            "projects": status.get("projects", 0),
        }

    # -- write tools ------------------------------------------------------

    async def _plan_assessment(
        self,
        task: dict[str, Any],
        *,
        vulnerability_id: str,
        team: str,
        state: str,
        details: str,
    ) -> tuple[dict[str, Any], str, str, str, list[tuple[dict[str, Any], dict[str, Any]]]]:
        group = self._find_group(task, vulnerability_id)

        normalized_state = str(state or "").strip().upper()
        if normalized_state not in ANALYSIS_STATES:
            raise McpToolError(
                f"Invalid state; use one of: {', '.join(ANALYSIS_STATES)}"
            )
        text = str(details or "").strip()
        if not text:
            raise McpToolError("Details with your evidence and reasoning are required")
        if len(text) > MAX_DETAILS_LENGTH:
            raise McpToolError(
                f"Details are limited to {MAX_DETAILS_LENGTH} characters"
            )
        if RESERVED_DETAIL_PATTERN.search(text):
            raise McpToolError(
                "Details must be plain prose: remove '---' separators and "
                "bracketed tags such as [Team: ...] or [State: ...]"
            )

        responsible = [str(tag) for tag in group.get("tags") or []]
        if _team_key(team) in {"", "general"}:
            raise McpToolError(
                "Name the team whose assessment you are writing; the General "
                "assessment is reserved for human reviewers. Responsible "
                f"teams: {', '.join(responsible) or 'none'}"
            )
        team_name = next(
            (tag for tag in responsible if _team_key(tag) == _team_key(team)), None
        )
        if team_name is None:
            raise McpToolError(
                f"Team '{team}' is not responsible for this vulnerability. "
                f"Responsible teams: {', '.join(responsible) or 'none'}"
            )

        found = _components(group)
        if not found:
            raise McpToolError("This vulnerability has no findings to assess")
        components = []
        for component in found:
            key = instance_finding_key(component)
            if key:
                components.append({**component, "finding_uuid": key})
        if not components:
            raise McpToolError(
                "The findings of this vulnerability have no project, component "
                "and vulnerability identity to assess them by"
            )
        targets = list(zip(components, await self._current_analyses(components)))
        return group, team_name, normalized_state, text, targets

    @staticmethod
    def _request(
        targets: list[tuple[dict[str, Any], dict[str, Any]]],
        *,
        team: str,
        state: str,
        details: str,
        justification: str | None = None,
        code_evidence_ids: list[str] | None = None,
    ) -> tuple[AssessmentRequest, dict[str, bool]]:
        """The save request and each finding's existing suppression, which a
        save through this endpoint never changes."""
        if justification is not None:
            justification = justification.strip().upper() or "NOT_SET"
            if justification not in (*ANALYSIS_JUSTIFICATIONS, "NOT_SET"):
                raise McpToolError(
                    "Invalid justification; use one of: "
                    + ", ".join((*ANALYSIS_JUSTIFICATIONS, "NOT_SET"))
                )
            if justification != "NOT_SET" and state != "NOT_AFFECTED":
                raise McpToolError("justification requires state NOT_AFFECTED")
        request = AssessmentRequest(
            justification=justification,
            **({"code_evidence_ids": code_evidence_ids} if code_evidence_ids is not None else {}),
            instances=[
                {
                    key: component.get(key)
                    for key in (
                        "project_uuid",
                        "component_uuid",
                        "vulnerability_uuid",
                        "finding_uuid",
                        "project_name",
                        "project_version",
                        "component_name",
                        "component_version",
                    )
                }
                for component, _current in targets
            ],
            state=state,
            details=details,
            team=team,
            # Stored text and revisions come from the server's own state;
            # nothing here is taken from the caller.
            original_analysis={
                component["finding_uuid"]: {
                    "analysisState": current["state"],
                    "analysisDetails": current["details"],
                    "isSuppressed": current["suppressed"],
                    "dtvpRevision": current["revision"],
                }
                for component, current in targets
            },
        )
        suppressed = {
            component["finding_uuid"]: bool(current["suppressed"])
            for component, current in targets
        }
        return request, suppressed

    async def preview_assessment(
        self,
        token: AccessToken,
        *,
        project: str,
        vulnerability_id: str,
        team: str,
        state: str,
        details: str,
        justification: str | None = None,
        code_evidence_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        self._require_scope(token, SCOPE_READ)
        task = await self._project_task(token, project)
        group, team_name, normalized_state, text, targets = await self._plan_assessment(
            task,
            vulnerability_id=vulnerability_id,
            team=team,
            state=state,
            details=details,
        )
        author = f"{token.username} (via {agent_label(token)})"
        changes = []
        request, _suppressed = self._request(
            targets,
            team=team_name,
            state=normalized_state,
            details=text,
            justification=justification,
            code_evidence_ids=code_evidence_ids,
        )
        try:
            validate_code_evidence(self.deps.route_deps, request, AGENT_ROLE)
        except AssessmentUseCaseError as exc:
            raise McpToolError(str(exc)) from exc
        payloads = self.deps.route_deps.build_assessment_payloads(
            request, author, AGENT_ROLE
        )
        current_by_uuid = {
            component["finding_uuid"]: current for component, current in targets
        }
        store = getattr(self.deps.route_deps, "code_evidence_store", None)
        chosen = {key: store.get(key) for key in request.code_evidence_ids} if store else {}
        for instance, payload in payloads:
            current = current_by_uuid[instance["finding_uuid"]]
            previous = store.current_selection(instance["finding_uuid"], team_name) if store else []
            selected = previous if code_evidence_ids is None else [
                key for key, record in chosen.items()
                if record["scope"] == "vulnerability" or any(
                    target.get("finding_uuid") == instance["finding_uuid"]
                    for target in record["targets"]
                )
            ]
            changes.append(
                {
                    "finding_uuid": instance["finding_uuid"],
                    "project_version": instance.get("project_version"),
                    "component": instance.get("component_name"),
                    "revision": current["revision"],
                    "current_state": current["state"],
                    "new_state": payload["state"],
                    "changed": (
                        payload["state"] != current["state"]
                        or payload["details"] != current["details"]
                        or set(selected) != set(previous)
                    ),
                    "code_evidence_ids": selected,
                    "new_assessment": self._assessment_view(payload["details"]),
                }
            )
        return {
            "project": task.get("_project_name"),
            "id": group.get("id"),
            "team": team_name,
            "state": normalized_state,
            "saved": False,
            **({"code_evidence_ids": request.code_evidence_ids} if code_evidence_ids is not None else {}),
            "pending_review_after_save": True,
            "expected_revisions": {
                change["finding_uuid"]: change["revision"] for change in changes
            },
            "changes": changes,
        }

    async def save_assessment(
        self,
        token: AccessToken,
        *,
        project: str,
        vulnerability_id: str,
        team: str,
        state: str,
        details: str,
        expected_revisions: dict[str, int],
        justification: str | None = None,
        code_evidence_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        self._require_scope(token, SCOPE_WRITE)
        task = await self._project_task(token, project)
        group, team_name, normalized_state, text, targets = await self._plan_assessment(
            task,
            vulnerability_id=vulnerability_id,
            team=team,
            state=state,
            details=details,
        )
        finding_uuids = [component["finding_uuid"] for component, _c in targets]
        audit_target = {
            "project": task.get("_project_name"),
            "vulnerability": group.get("id"),
            "team": team_name,
            "state": normalized_state,
            "findings": finding_uuids,
        }

        if not isinstance(expected_revisions, dict):
            raise McpToolError("expected_revisions must map finding_uuid to revision")
        stale: list[str] = []
        for component, current in targets:
            expected = expected_revisions.get(component["finding_uuid"])
            if isinstance(expected, bool) or not isinstance(expected, int):
                raise McpToolError(
                    "expected_revisions must contain the revision of every "
                    "finding of this vulnerability; read it with "
                    "get_vulnerability or preview_assessment. Missing: "
                    f"{component['finding_uuid']}"
                )
            if expected != current["revision"]:
                stale.append(component["finding_uuid"])
        if stale:
            await self._audit(
                token,
                action="save_assessment",
                outcome="conflict",
                target=audit_target,
                detail=f"stale revisions: {', '.join(stale)}",
            )
            raise McpToolError(
                "These findings changed after you read them; call "
                f"get_vulnerability again: {', '.join(stale)}"
            )

        route_deps = self.deps.route_deps
        author = f"{token.username} (via {agent_label(token)})"

        async def refresh_snapshots(payloads: list[tuple[dict, dict]]) -> None:
            try:
                await asyncio.to_thread(
                    refresh_grouped_vuln_task_snapshots,
                    route_deps.tasks,
                    payloads,
                    route_deps.load_team_mapping(),
                )
            except Exception:
                self.deps.logger.exception(
                    "Failed to refresh task snapshots after MCP assessment save"
                )

        client = await self.deps.get_dt_client()
        request, suppressed = self._request(
            targets,
            team=team_name,
            state=normalized_state,
            details=text,
            justification=justification,
            code_evidence_ids=code_evidence_ids,
        )
        try:
            # One transaction for every finding: all are saved or none.
            results = await save_assessment(
                route_deps,
                request,
                user=author,
                role=AGENT_ROLE,
                client=client,
                after_persist=refresh_snapshots,
                workflow_id="mcp-assessment",
                suppressed_by_finding=suppressed,
            )
        except AssessmentConflictError as exc:
            conflicting = [str(c.get("finding_uuid")) for c in exc.conflicts]
            await self._audit(
                token,
                action="save_assessment",
                outcome="conflict",
                target=audit_target,
                detail=f"stale revisions: {', '.join(conflicting)}",
            )
            raise McpToolError(
                "These findings changed after you read them; call "
                f"get_vulnerability again: {', '.join(conflicting)}"
            ) from exc
        except AssessmentUseCaseError as exc:
            await self._audit(
                token,
                action="save_assessment",
                outcome="rejected",
                target=audit_target,
                detail=str(exc),
            )
            raise McpToolError(str(exc)) from exc
        except Exception as exc:
            await self._audit(
                token,
                action="save_assessment",
                outcome="error",
                target=audit_target,
                detail=f"{type(exc).__name__}: {exc}",
            )
            raise

        revisions = {result["uuid"]: result["revision"] for result in results}
        await self._audit(
            token,
            action="save_assessment",
            outcome="success",
            target={**audit_target, "revisions": revisions},
        )
        return {
            "project": task.get("_project_name"),
            "id": group.get("id"),
            "team": team_name,
            "state": normalized_state,
            "saved": True,
            "pending_review": True,
            "assessed_by": author,
            "revisions": revisions,
            "export": "queued",
        }


    # -- code evidence ----------------------------------------------------

    async def add_code_evidence(
        self,
        token: AccessToken,
        *,
        project: str,
        vulnerability_id: str,
        title: str,
        body_markdown: str,
        assessment_summary: str | None = None,
        components: list[str] | None = None,
        finding_uuids: list[str] | None = None,
        references: list[str] | None = None,
        suggested_state: str | None = None,
        suggested_justification: str | None = None,
        confidence: str | None = None,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        self._require_scope(token, SCOPE_WRITE)
        store = self._evidence_store()
        task = await self._project_task(token, project)
        group = self._find_group(task, vulnerability_id)
        audit_target: dict[str, Any] = {
            "project": task.get("_project_name"),
            "vulnerability": group.get("id"),
        }
        try:
            scope, targets = resolve_targets(group, components, finding_uuids)
            audit_target["findings"] = [t["finding_uuid"] for t in targets]
            fields = normalize_evidence_input(
                title=title,
                body_markdown=body_markdown,
                assessment_summary=assessment_summary,
                references=references,
                suggested_state=suggested_state,
                suggested_justification=suggested_justification,
                confidence=confidence,
                idempotency_key=idempotency_key,
            )
            record, created = await asyncio.to_thread(
                lambda: store.add(
                    project_name=str(task.get("_project_name") or ""),
                    vuln_id=str(group.get("id") or ""),
                    vuln_ids=self._group_vuln_ids(group),
                    scope=scope,
                    targets=targets,
                    author_username=token.username,
                    token_id=token.token_id,
                    agent_label=agent_label(token),
                    authority=AGENT_ROLE,
                    **fields,
                )
            )
        except CodeEvidenceError as exc:
            await self._audit(
                token,
                action="add_code_evidence",
                outcome="rejected",
                target=audit_target,
                detail=str(exc),
            )
            raise McpToolError(str(exc)) from exc
        except Exception as exc:
            await self._audit(
                token,
                action="add_code_evidence",
                outcome="error",
                target=audit_target,
                detail=f"{type(exc).__name__}: {exc}",
            )
            raise
        await self._audit(
            token,
            action="add_code_evidence",
            outcome="success",
            target={
                **audit_target,
                "evidence_id": record["evidence_id"],
                "findings": [t.get("finding_uuid") for t in record["targets"]],
                "created": created,
            },
        )
        return {
            "project": record["project_name"],
            "id": record["vuln_id"],
            "evidence_id": record["evidence_id"],
            "created": created,
            "created_at": record["created_at"],
            "scope": record["scope"],
            "targets": record["targets"],
            "applied_to_assessment": False,
            "note": (
                "Recorded as code evidence. It changes no assessment; a "
                "person decides whether to use it in an assessment draft."
            ),
        }

    @staticmethod
    def _agent_item(record: dict[str, Any]) -> dict[str, Any]:
        return {
            "kind": "agent",
            "evidence_id": record["evidence_id"],
            "title": record["title"],
            "body_markdown": record["body_markdown"],
            "assessment_summary": record.get("assessment_summary"),
            "attachments": record.get("attachments", []),
            "references": record["references"],
            "scope": record["scope"],
            "targets": record["targets"],
            "suggested_state": record["suggested_state"],
            "suggested_justification": record["suggested_justification"],
            "confidence": record["confidence"],
            "author": record["author"],
            "created_at": record["created_at"],
            "withdrawn": record["withdrawn"],
            "applications": [
                {
                    "finding_uuid": application["finding_uuid"],
                    "applied_by": application["applied_by"],
                    "team": application.get("team", ""),
                    "assessment_revision": application.get("assessment_revision", -1),
                    "selected": application.get("selected", True),
                    "applied_at": application["applied_at"],
                }
                for application in record.get("applications") or []
            ],
        }

    @staticmethod
    def _analyzer_item(
        metadata: dict[str, Any], full: dict[str, Any] | None
    ) -> dict[str, Any]:
        assessment = metadata.get("assessment") or {}
        result_assessment = ((full or {}).get("result") or {}).get("assessment") or {}
        report = str(result_assessment.get("report_markdown") or "")
        return {
            "kind": "analyzer",
            "analysis_run_id": metadata.get("analysis_run_id"),
            "component": metadata.get("component_name"),
            "source": metadata.get("source"),
            "submitted_by": metadata.get("submitted_by"),
            "finished_at": metadata.get("finished_at"),
            "created_at": metadata.get("finished_at")
            or metadata.get("recorded_at")
            or metadata.get("submitted_at"),
            "model": metadata.get("model"),
            "verdict": assessment.get("verdict"),
            "confidence": assessment.get("confidence"),
            "exposure": assessment.get("exposure"),
            "application_eligible": bool(assessment.get("application_eligible")),
            "executive_summary": assessment.get("executive_summary") or {},
            "report_markdown": report[:MAX_ANALYZER_REPORT_LENGTH],
            "report_truncated": len(report) > MAX_ANALYZER_REPORT_LENGTH,
        }

    async def add_code_evidence_attachment(
        self, token: AccessToken, *, project: str, vulnerability_id: str,
        evidence_id: str, filename: str, content_base64: str,
        description: str = "", media_type: str = "application/octet-stream",
        replaces_attachment_id: str | None = None,
    ) -> dict[str, Any]:
        import base64
        from .code_evidence_services import MAX_ATTACHMENT_BYTES
        self._require_scope(token, SCOPE_WRITE)
        task = await self._project_task(token, project)
        group = self._find_group(task, vulnerability_id)
        record = self._evidence_store().get(evidence_id)
        target = {"project": project, "evidence_id": evidence_id}
        try:
            if record is None or record['project_name'] != task.get('_project_name') or not set(record['vuln_ids']).intersection(value.lower() for value in self._group_vuln_ids(group)):
                raise McpToolError("Evidence does not belong to this project and vulnerability")
            if record['author']['username'] != token.username:
                raise McpToolError("Only the evidence author may upload through MCP")
            if len(content_base64) > ((MAX_ATTACHMENT_BYTES + 2) // 3) * 4:
                raise McpToolError("Attachments are limited to 10 MiB")
            content = base64.b64decode(content_base64, validate=True)
            attachment = await asyncio.to_thread(self._evidence_store().add_attachment,
                evidence_id, filename=filename, content=content, uploaded_by=token.username,
                description=description, media_type=media_type, replaces_attachment_id=replaces_attachment_id)
        except (ValueError, McpToolError) as exc:
            await self._audit(token, action="add_code_evidence_attachment", outcome="rejected", target=target, detail=str(exc))
            raise McpToolError(str(exc)) from exc
        await self._audit(token, action="add_code_evidence_attachment", outcome="success",
            target={**target, "attachment_id": attachment['attachment_id']})
        return attachment

    async def list_code_evidence(
        self,
        token: AccessToken,
        *,
        project: str,
        vulnerability_id: str,
        components: list[str] | None = None,
        include_withdrawn: bool = False,
        limit: int = 20,
        offset: int = 0,
    ) -> dict[str, Any]:
        self._require_scope(token, SCOPE_READ)
        limit = max(1, min(int(limit), MAX_EVIDENCE_LIST_LIMIT))
        offset = max(0, int(offset))
        store = self._evidence_store()
        task = await self._project_task(token, project)
        group = self._find_group(task, vulnerability_id)
        project_name = str(task.get("_project_name") or "")
        vuln_ids = self._group_vuln_ids(group)
        component_names = [str(name) for name in components or [] if str(name).strip()]

        agent_records = await asyncio.to_thread(
            store.list_for_vulnerability,
            project_name,
            vuln_ids,
            component_names or None,
            bool(include_withdrawn),
        )
        result_store = getattr(self.deps.route_deps, "code_analysis_result_store", None)
        analyzer_records = (
            _shown_analyzer_records(
                await asyncio.to_thread(
                    result_store.list_result_metadata,
                    project_name=project_name,
                    vuln_ids=vuln_ids,
                    component_names=component_names or None,
                    limit=1000,
                )
            )
            if result_store is not None
            else []
        )
        merged: list[tuple[str, str, dict[str, Any]]] = [
            ("agent", str(record["created_at"] or ""), record)
            for record in agent_records
        ] + [
            (
                "analyzer",
                str(
                    record.get("finished_at")
                    or record.get("recorded_at")
                    or record.get("submitted_at")
                    or ""
                ),
                record,
            )
            for record in analyzer_records
        ]
        merged.sort(key=lambda entry: entry[1], reverse=True)
        page = merged[offset : offset + limit]

        agent_page = await asyncio.to_thread(
            store.with_applications,
            [record for kind, _when, record in page if kind == "agent"],
        )
        agent_by_id = {record["evidence_id"]: record for record in agent_page}
        analyzer_full = {}
        for kind, _when, record in page:
            if kind == "analyzer" and result_store is not None:
                run_id = record.get("analysis_run_id")
                analyzer_full[run_id] = await asyncio.to_thread(result_store.get, run_id)
        items = [
            self._agent_item(agent_by_id[record["evidence_id"]])
            if kind == "agent"
            else self._analyzer_item(record, analyzer_full.get(record.get("analysis_run_id")))
            for kind, _when, record in page
        ]
        return {
            "project": project_name,
            "id": group.get("id"),
            "total": len(merged),
            "offset": offset,
            "limit": limit,
            "has_more": offset + len(page) < len(merged),
            "items": items,
        }


# -- MCP wiring -----------------------------------------------------------


def _bearer_value(headers: Any) -> str | None:
    if headers is None:
        return None
    raw = headers.get("authorization") or headers.get("Authorization") or ""
    scheme, _, value = str(raw).partition(" ")
    value = value.strip()
    if scheme.lower() == "bearer" and looks_like_access_token(value):
        return value
    return None


def build_mcp_server(service: McpToolService) -> Any:
    from mcp.server.mcpserver import Context, MCPServer
    from mcp.server.mcpserver.exceptions import ToolError
    from mcp.types import ToolAnnotations

    class StrictMCPServer(MCPServer):
        """Reject unknown fields before the SDK drops extra arguments."""

        async def list_tools(self) -> list[Any]:
            tools = await super().list_tools()
            for tool in tools:
                tool.input_schema["additionalProperties"] = False
            return tools

        async def call_tool(self, name: str, arguments: dict[str, Any], context: Any = None) -> Any:
            tool = next((tool for tool in await self.list_tools() if tool.name == name), None)
            if tool is not None:
                unknown = set(arguments) - set(tool.input_schema.get("properties", {}))
                if unknown:
                    raise ToolError("Unknown arguments: " + ", ".join(sorted(unknown)))
            return await super().call_tool(name, arguments, context)

    server = StrictMCPServer(
        "dtvp",
        title="DTVP vulnerability review",
        instructions=SERVER_INSTRUCTIONS,
    )
    read_only = ToolAnnotations(readOnlyHint=True, openWorldHint=False)
    writes = ToolAnnotations(
        readOnlyHint=False,
        destructiveHint=False,
        idempotentHint=False,
        openWorldHint=False,
    )

    async def call(ctx: Any, method: Callable[..., Awaitable[Any]], **kwargs: Any) -> Any:
        plain = _bearer_value(ctx.headers)
        token = (
            await asyncio.to_thread(service.deps.token_store.verify, plain)
            if plain and access_tokens_enabled()
            else None
        )
        if token is None:
            raise ToolError("Invalid, expired, or revoked access token")
        try:
            return await method(token, **kwargs)
        except McpToolError as exc:
            raise ToolError(str(exc)) from exc

    @server.tool(annotations=read_only)
    async def list_projects(ctx: Context, name: str = "") -> dict[str, Any]:
        """List projects and their versions. `name` filters by project name."""
        return await call(ctx, service.list_projects, name=name)

    @server.tool(annotations=read_only)
    async def search_vulnerabilities(
        ctx: Context,
        project: str,
        query: str = "",
        lifecycle: list[str] | None = None,
        teams: list[str] | None = None,
        severity: list[str] | None = None,
        analysis_state: list[str] | None = None,
        awaiting_review: bool = False,
        cutoff: str = "",
        cutoff_mode: str = "before",
        cutoff_basis: str = "",
        limit: int = 25,
        offset: int = 0,
    ) -> dict[str, Any]:
        """Search the vulnerabilities of a project across all its versions.

        lifecycle: OPEN, INCOMPLETE, INCONSISTENT (Conflicting),
        READY_FOR_APPROVAL, ASSESSED. Rows report the lifecycle; Ready for
        approval is reported as NEEDS_APPROVAL. As a filter value
        NEEDS_APPROVAL is deprecated: it selects every vulnerability pending
        review, as awaiting_review does. Definitions:
        docs/assessment-model.md#lifecycle-decision-table.
        severity (before rescoring): CRITICAL, HIGH, MEDIUM, LOW, INFO, UNKNOWN.
        analysis_state: NOT_SET, IN_TRIAGE, EXPLOITABLE, NOT_AFFECTED,
        FALSE_POSITIVE, RESOLVED. awaiting_review: only vulnerabilities with
        an assessment submitted for review and not yet approved (rows with
        pending_review), whatever their lifecycle. cutoff: a date YYYY-MM-DD
        (UTC) or N days before today as "30d"; lists vulnerabilities with a
        finding dated on or before it (cutoff_mode "before", the default) or
        after it ("after"). cutoff_basis picks the date: "published" (the
        default; publication by the source, earliest across aliases) or
        "attributed" (first attributed by Dependency-Track to that component
        in any version of the project). Findings without a date are listed
        and counted in date_unknown. Values within a filter are
        alternatives; different filters must all match. Returns at most 100
        rows per call; page with offset.
        """
        return await call(
            ctx,
            service.search_vulnerabilities,
            project=project,
            query=query,
            lifecycle=lifecycle,
            teams=teams,
            severity=severity,
            analysis_state=analysis_state,
            awaiting_review=awaiting_review,
            cutoff=cutoff,
            cutoff_mode=cutoff_mode,
            cutoff_basis=cutoff_basis,
            limit=limit,
            offset=offset,
        )

    @server.tool(annotations=read_only)
    async def get_vulnerability(
        ctx: Context, project: str, vulnerability_id: str
    ) -> dict[str, Any]:
        """Full detail for one vulnerability: description, scores, every
        finding with its revision and responsible teams, dependency paths,
        exploitation evidence, and the current team assessments."""
        return await call(
            ctx,
            service.get_vulnerability,
            project=project,
            vulnerability_id=vulnerability_id,
        )

    @server.tool(annotations=read_only)
    async def get_sync_status(ctx: Context) -> dict[str, Any]:
        """How many local assessment changes still wait for export to
        Dependency-Track, how many exports keep failing, and when data was
        last imported."""
        return await call(ctx, service.get_sync_status)

    @server.tool(annotations=read_only)
    async def preview_assessment(
        ctx: Context,
        project: str,
        vulnerability_id: str,
        team: str,
        state: str,
        details: str,
        justification: str | None = None,
        code_evidence_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        """Show what save_assessment would store, without saving. Returns the
        resulting assessment per finding and the expected_revisions to pass
        to save_assessment. Optional justification is a NOT_AFFECTED reason
        from dtvp://assessment-rules; omit/null keeps it, NOT_SET clears it.
        code_evidence_ids selects supporting evidence; omit/null preserves
        selections, [] removes them. The same scope checks apply as on save."""
        return await call(
            ctx,
            service.preview_assessment,
            justification=justification,
            code_evidence_ids=code_evidence_ids,
            project=project,
            vulnerability_id=vulnerability_id,
            team=team,
            state=state,
            details=details,
        )

    @server.tool(name="save_assessment", annotations=writes)
    async def save_assessment_tool(
        ctx: Context,
        project: str,
        vulnerability_id: str,
        team: str,
        state: str,
        details: str,
        expected_revisions: dict[str, int],
        justification: str | None = None,
        code_evidence_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        """Record one team's assessment for every finding of a vulnerability.

        The change is a draft that stays pending until a human reviewer
        approves it. `team` must be responsible for the vulnerability.
        `expected_revisions` maps each finding_uuid to the revision you read;
        the save is rejected if any finding changed since. Needs a token
        with the write scope. Optional justification is a NOT_AFFECTED
        reason from dtvp://assessment-rules; omit/null keeps it, NOT_SET clears it.
        code_evidence_ids selects supporting evidence for this team only;
        omit/null preserves selections, [] removes them. Rationale is required.
        """
        return await call(
            ctx,
            service.save_assessment,
            justification=justification,
            code_evidence_ids=code_evidence_ids,
            project=project,
            vulnerability_id=vulnerability_id,
            team=team,
            state=state,
            details=details,
            expected_revisions=expected_revisions,
        )

    @server.tool(name="add_code_evidence", annotations=writes)
    async def add_code_evidence_tool(
        ctx: Context,
        project: str,
        vulnerability_id: str,
        title: str,
        body_markdown: str,
        assessment_summary: str | None = None,
        components: list[str] | None = None,
        finding_uuids: list[str] | None = None,
        references: list[str] | None = None,
        suggested_state: str | None = None,
        suggested_justification: str | None = None,
        confidence: str | None = None,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        """Record what you found in the code for one vulnerability.

        `assessment_summary` is optional standalone assessment prose (up to 10,000 characters), editable by the reviewer.
        `body_markdown` is your evidence as Markdown (up to 20,000 characters);
        `title` is one plain line (up to 160). The evidence is about the
        whole vulnerability, or only the `components` (names) or
        `finding_uuids` you give. It never changes an assessment: a person
        reads it and decides whether to use it. `suggested_state`,
        `suggested_justification` (with NOT_AFFECTED) and `confidence`
        (low, medium, high) are optional hints for that person. Pass the
        same `idempotency_key` when retrying the same call; reusing a key for
        different evidence is rejected. Needs a token with the write scope.
        """
        return await call(
            ctx,
            service.add_code_evidence,
            project=project,
            vulnerability_id=vulnerability_id,
            title=title,
            body_markdown=body_markdown,
            assessment_summary=assessment_summary,
            components=components,
            finding_uuids=finding_uuids,
            references=references,
            suggested_state=suggested_state,
            suggested_justification=suggested_justification,
            confidence=confidence,
            idempotency_key=idempotency_key,
        )

    @server.tool(name="add_code_evidence_attachment", annotations=writes)
    async def add_code_evidence_attachment(
        ctx: Context, project: str, vulnerability_id: str, evidence_id: str,
        filename: str, content_base64: str, description: str = "",
        media_type: str = "application/octet-stream", replaces_attachment_id: str | None = None,
    ) -> dict[str, Any]:
        """Upload immutable supporting material to evidence you authored, up to 10 MiB.

        Send base64 bytes, not local paths. Replacements name the latest attachment
        id; all versions stay downloadable. Requires write scope.
        """
        return await call(ctx, service.add_code_evidence_attachment,
            project=project, vulnerability_id=vulnerability_id, evidence_id=evidence_id,
            filename=filename, content_base64=content_base64, description=description,
            media_type=media_type, replaces_attachment_id=replaces_attachment_id)

    @server.tool(annotations=read_only)
    async def list_code_evidence(
        ctx: Context,
        project: str,
        vulnerability_id: str,
        components: list[str] | None = None,
        include_withdrawn: bool = False,
        limit: int = 20,
        offset: int = 0,
    ) -> dict[str, Any]:
        """Code evidence for a vulnerability, newest first: entries agents
        added (kind "agent") and code-analyzer runs (kind "analyzer").
        Withdrawn agent entries are left out unless `include_withdrawn`.
        Returns at most 50 items per call; page with offset."""
        return await call(
            ctx,
            service.list_code_evidence,
            project=project,
            vulnerability_id=vulnerability_id,
            components=components,
            include_withdrawn=include_withdrawn,
            limit=limit,
            offset=offset,
        )

    @server.resource(
        "dtvp://assessment-rules",
        name="assessment-rules",
        description="States, justifications, component ownership, and CVSS rescoring rules in force",
        mime_type="application/json",
    )
    def assessment_rules() -> str:
        route_deps = service.deps.route_deps
        return json.dumps(
            {
                "analysis_states": list(ANALYSIS_STATES),
                "analysis_justifications": [*ANALYSIS_JUSTIFICATIONS, "NOT_SET"],
                "team_mapping": route_deps.load_team_mapping(),
                "rescore_rules": route_deps.load_rescore_rules() or {},
            },
            sort_keys=True,
            default=str,
        )

    return server


async def _send_json(
    send: Any,
    status: int,
    detail: str,
    *,
    bearer: bool = False,
    allow: str = "",
) -> None:
    body = json.dumps({"detail": detail}).encode("utf-8")
    headers = [
        (b"content-type", b"application/json"),
        (b"content-length", str(len(body)).encode("ascii")),
    ]
    if bearer:
        headers.append((b"www-authenticate", b"Bearer"))
    if allow:
        headers.append((b"allow", allow.encode("ascii")))
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": body})


class McpEndpoint:
    """ASGI app for the MCP endpoint URL.

    Requests without a usable access token never reach the MCP transport.
    The transport itself lives only inside ``lifespan``, because its session
    manager can be started once per instance.
    """

    def __init__(self, deps: McpServerDeps) -> None:
        self.deps = deps
        self._transport: Any = None

    @asynccontextmanager
    async def lifespan(self) -> AsyncIterator[None]:
        from mcp.server.transport_security import TransportSecuritySettings

        server = build_mcp_server(McpToolService(self.deps))
        transport = server.streamable_http_app(
            streamable_http_path="/",
            # Each call is self-contained: no server-side sessions to hijack
            # or to lose when the single backend process restarts.
            stateless_http=True,
            json_response=True,
            # Host/Origin allow-lists defend cookie-authenticated localhost
            # servers against DNS rebinding. Every request here needs a
            # bearer token a browser never sends on its own, and the public
            # host name is decided by the deployment's reverse proxy.
            transport_security=TransportSecuritySettings(
                enable_dns_rebinding_protection=False
            ),
        )
        async with server.session_manager.run():
            self._transport = transport
            try:
                yield
            finally:
                self._transport = None

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            return
        if not access_tokens_enabled():
            await _send_json(send, 404, "Not Found")
            return
        if scope.get("method") != "POST":
            # Stateless JSON responses only: there is no server-to-client
            # stream to open with GET and no session to end with DELETE.
            await _send_json(send, 405, "Method Not Allowed", allow="POST")
            return
        headers = {
            key.decode("latin-1").lower(): value.decode("latin-1")
            for key, value in scope.get("headers") or []
        }
        plain = _bearer_value(headers)
        token = (
            await asyncio.to_thread(self.deps.token_store.verify, plain)
            if plain
            else None
        )
        if token is None:
            await _send_json(
                send,
                401,
                "Invalid, expired, or revoked access token",
                bearer=True,
            )
            return
        try:
            self.deps.note_request(token.username)
        except Exception:  # never fails the request
            pass
        transport = self._transport
        if transport is None:
            await _send_json(send, 503, "MCP endpoint is starting")
            return
        # The transport serves a single route at its own root.
        await transport(
            {**scope, "path": "/", "raw_path": b"/", "root_path": ""},
            receive,
            send,
        )
