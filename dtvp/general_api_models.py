"""Request models and dependency contract for the general API router."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Optional

from pydantic import BaseModel, Field

from .dt_client import DTClient


class AssessmentRequest(BaseModel):
    instances: list[dict] = Field(min_length=1, max_length=500)
    state: str = Field(min_length=1, max_length=50)
    details: str = Field(max_length=1_000_000)
    comment: Optional[str] = None
    justification: Optional[str] = None
    suppressed: bool = False
    team: Optional[str] = Field(default=None, max_length=200)
    assigned: Optional[list[str]] = Field(default=None, max_length=100)
    original_analysis: Optional[dict[str, dict[str, Any]]] = None
    force: bool = False
    comparison_mode: Optional[str] = "MERGE"
    analysis_run_ids: list[str] = Field(default_factory=list, max_length=100)


class AssessmentDetailsRequest(BaseModel):
    instances: list[dict] = Field(min_length=1, max_length=500)


class AssessmentRestoreRequest(BaseModel):
    task_id: str
    group_ids: Optional[list[str]] = None


class BulkWorkflowFilters(BaseModel):
    q: str = ""
    lifecycle: list[str] = Field(default_factory=list)
    inconsistency_reason: list[str] = Field(default_factory=list)
    analysis: list[str] = Field(default_factory=list)
    tag: str = ""
    team: str = ""
    id: str = ""
    component: str = ""
    assignee: str = ""
    dependency: list[str] = Field(default_factory=list)
    versions: list[str] = Field(default_factory=list)
    cvss_mismatch: bool = False
    attributed_before_days: Optional[int] = None
    attribution_mode: str = "older"
    tmrescore: list[str] = Field(default_factory=list)
    tmrescore_proposal_ids: list[str] = Field(default_factory=list)
    automatic_assessment: list[str] = Field(default_factory=list)
    automatic_assessment_ids: list[str] = Field(default_factory=list)


class BulkWorkflowRequest(BaseModel):
    task_id: str
    filters: BulkWorkflowFilters = Field(default_factory=BulkWorkflowFilters)


class BulkWorkflowApplyRequest(BulkWorkflowRequest):
    group_ids: list[str] = Field(default_factory=list)
    preview_token: str


@dataclass(frozen=True)
class GeneralApiRouteDeps:
    cache_manager: Any
    logger: Any
    tasks: dict[str, Any]
    dt_settings_cls: Callable[[], Any]
    get_dt_client_cls: Callable[[], type]
    create_tracked_task: Callable[[Any], Any]
    process_grouped_vulns_task: Callable[
        [str, str, Optional[str], DTClient, str], Awaitable[None]
    ]
    sort_projects_by_version: Callable[[list[dict[str, Any]]], list[dict[str, Any]]]
    load_team_mapping: Callable[[], dict[str, Any]]
    load_rescore_rules: Callable[[], dict[str, Any] | None]
    collect_version_snapshots: Callable[
        ...,
        Awaitable[
            tuple[list[dict[str, Any]], dict[str, Any], dict[str, dict[str, int]]]
        ],
    ]
    group_vulnerabilities: Callable[..., list[dict[str, Any]]]
    calculate_statistics: Callable[[list[dict[str, Any]]], dict[str, Any]]
    prune_grouped_vuln_tasks: Callable[[], list[str]]
    get_user_role: Callable[[str], str]
    fetch_current_assessment_analyses: Callable[
        [Any, DTClient], Awaitable[list[Any]]
    ]
    collect_assessment_conflicts: Callable[
        [AssessmentRequest, list[Any]], list[dict[str, Any]]
    ]
    build_assessment_payloads: Callable[
        [AssessmentRequest, str, str], list[tuple[dict, dict]]
    ]
    apply_assessment_payloads: Callable[..., Awaitable[list[dict[str, Any]]]]
    finalize_assessment_results: Callable[
        [list[dict[str, Any]]], Awaitable[list[dict[str, Any]]]
    ]
    get_bom_analysis_cache_cls: Callable[[], type]
    default_dependency_chain_limit: int
    service_unavailable_response: dict[int | str, dict[str, Any]]
    not_found_response: dict[int | str, dict[str, Any]]
    code_analysis_result_store: Any = None
