"""Transport-independent assessment use cases.

REST routes and other entry points (for example MCP tools) call these
functions so that permission checks, validation, conflict handling, and
persistence follow one set of rules. Nothing in this module depends on the
web framework; callers translate the raised errors to their own protocol.
"""

import asyncio
import hashlib
import json
import os
import re
import time
from typing import Any, Awaitable, Callable, Optional, Protocol

from pydantic import BaseModel, Field, PrivateAttr, field_validator

from .assessment_model import (
    ANALYSIS_RESPONSES,
    RESPONSE_NOT_SET,
    agreed_response,
    analysis_response,
    finding_key,
    normalize_override_label,
    normalize_response,
    normalize_version_override,
    parse_assessment,
    preserve_or_share_response,
    render_assessment,
    render_team_block,
    version_override,
    with_response,
    with_version_override,
)
from .assessment_outbox_services import (
    AssessmentRevisionConflictError,
    assessment_key,
)
from .assessment_review import (
    MAX_REVIEW_RATIONALE,
    REQUEST_CHANGES_ORIGIN,
    RESUBMIT_CHANGES_ORIGIN,
    WITHDRAW_CHANGES_ORIGIN,
    changes_requests,
    normalize_changes_requests,
    strip_changes_requests,
    with_changes_requests,
)
from .code_analysis_assessment_services import record_application_eligible
from .logic import (
    active_assessment_block,
    calculate_aggregated_state,
    clear_global_assessment,
    historical_blocks_of,
    insert_assessment_blocks,
    parse_assessment_blocks,
    remove_assessment_blocks,
    replace_assessment_block,
    without_historical_blocks,
)
from .ssvc_services import (
    SsvcInput,
    agreed_record as agreed_ssvc_record,
    evaluate as evaluate_ssvc,
    preserve_or_share_record as preserve_or_share_ssvc_record,
    validate_evidence as validate_ssvc_evidence,
)

AssessmentPayloads = list[tuple[dict[str, Any], dict[str, Any]]]


class TeamAssessmentFields(BaseModel):
    """One team's assessment (or the General one) as atomic fields."""

    team: str = Field(min_length=1, max_length=200)
    state: str = "NOT_SET"
    justification: Optional[str] = None
    assessed_by: Optional[str] = None
    reviewed_by: Optional[str] = None
    reviewed_at_ms: Optional[int] = None
    assessed_at_ms: Optional[int] = None
    rescored_score: Optional[float] = Field(default=None, ge=0, le=10)
    rescored_vector: Optional[str] = None
    ssvc: Optional[str] = None
    ssvc_details: Optional[str] = None
    assigned: list[str] = Field(default_factory=list)
    ticket: Optional[str] = None
    evidence_reviewed: Optional[str] = None
    version_coverage: Optional[str] = None
    historical: bool = False
    copied_from: Optional[str] = None
    details: str = ""


def _checked_response(value: Any) -> Optional[str]:
    """A response of the list, ``NOT_SET``, or ``None``; anything else is
    an error rather than a value that is silently dropped."""
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("response must be a string")
    text = value.strip().upper()
    if text in ("", RESPONSE_NOT_SET):
        return RESPONSE_NOT_SET
    normalized = normalize_response(text)
    if normalized is None:
        raise ValueError(
            "response must be one of "
            + ", ".join((*ANALYSIS_RESPONSES, RESPONSE_NOT_SET))
        )
    return normalized


class AssessmentFields(BaseModel):
    """A whole assessment as atomic fields; see ``assessment_model``."""

    # Text outside the team assessments. ``None`` keeps what is stored for
    # each finding; an empty string removes it.
    free_text: Optional[str] = None
    pending_review: bool = False
    rescored_score: Optional[float] = Field(default=None, ge=0, le=10)
    rescored_vector: Optional[str] = None
    # What is done about the finding (Dependency-Track's analysisResponse).
    # Part of the General assessment: a reviewer's save sets it, ``null`` or
    # ``NOT_SET`` removes it. A save that leaves it out, and every save by
    # someone who is not a reviewer, keeps what each finding has.
    response: Optional[str] = None
    # The finding's version override (ADR 0010), ``{label, reason}``. Read
    # only for saves: each finding keeps its stored one; a save may repeat
    # it, never change it.
    version_override: Optional[dict[str, Optional[str]]] = None
    teams: list[TeamAssessmentFields] = Field(default_factory=list)

    @field_validator("response", mode="before")
    @classmethod
    def _response_of_the_list(cls, value: Any) -> Optional[str]:
        checked = _checked_response(value)
        return None if checked == RESPONSE_NOT_SET else checked


class AssessmentRequest(BaseModel):
    instances: list[dict]
    state: str
    # The assessment as text in DTVP's markup. Ignored when ``fields`` is
    # given, which is the form new clients send.
    details: str = ""
    fields: Optional[AssessmentFields] = None
    # Free text to keep per finding ("project|component|vulnerability"),
    # read from the stored record by the use case; never client input.
    _stored_free_text: dict[str, str] = PrivateAttr(default_factory=dict)
    # Each finding's stored text, keyed like ``_stored_free_text``: the save
    # keeps what it would drop of it (``logic.keep_team_records``).
    _stored_details: dict[str, str] = PrivateAttr(default_factory=dict)
    comment: Optional[str] = None
    justification: Optional[str] = None
    # For a save as text (without ``fields``): the finding's response.
    # ``NOT_SET`` removes it; leaving it out keeps what each finding has,
    # whatever the text says. Reviewers only, with the General assessment.
    response: Optional[str] = None
    suppressed: bool = False
    team: Optional[str] = None
    assigned: Optional[list[str]] = None
    original_analysis: Optional[dict[str, dict[str, Any]]] = None
    force: bool = False
    # The reviewer's explicit approval: the only thing that removes pending
    # review from a stored assessment. Reviewers only.
    approve: bool = False
    resubmit_changes: bool = False
    review_task_id: str | None = None
    review_group_id: str | None = None
    # The revision each finding had when the use case read it, keyed by
    # (project, component, vulnerability); never client input.
    _stored_revisions: dict[tuple[str, str, str], int] = PrivateAttr(default_factory=dict)
    comparison_mode: Optional[str] = "MERGE"
    analysis_run_ids: list[str] = Field(default_factory=list)
    # Agent code evidence a person referenced in this assessment; recorded
    # as applications after the save, with the same scope checks for MCP.
    code_evidence_ids: list[str] = Field(default_factory=list)
    code_evidence_by_team: dict[str, list[str]] = Field(default_factory=dict)
    ssvc: SsvcInput | None = None

    @field_validator("response", mode="before")
    @classmethod
    def _response_of_the_list(cls, value: Any) -> Optional[str]:
        return _checked_response(value)


class AssessmentUseCaseError(Exception):
    """Base class for expected, caller-visible assessment failures."""


class AssessmentPermissionError(AssessmentUseCaseError):
    """The acting user may not perform the requested change."""


class AssessmentValidationError(AssessmentUseCaseError):
    """The request is well-formed but violates an assessment rule."""


def approval_blocker(
    instances: list[dict[str, Any]],
    stored: list[dict[str, Any]],
    team_mapping: dict[str, Any] | None = None,
) -> str | None:
    """Why the findings cannot be approved now, or None.

    Approval is for a vulnerability that is Ready for approval
    (docs/assessment-model.md#lifecycle-decision-table, ADR 0014): every
    finding has a state, they agree, and every required team has its own
    assessment or a General decision covers it. Read from the stored texts,
    as the card reads them. Outstanding requests still block approval after
    a clear removes the pending marker.
    """
    # Imported here: the grouped services import much of the application.
    from .assessment_scopes import has_pending_review_marker
    from .grouped_vuln_services import summarize_grouped_vulnerabilities

    if any(changes_requests(item.get("details")) for item in stored):
        return "A team must resubmit its assessment before approval"
    if not any(has_pending_review_marker(str(item.get("details") or "")) for item in stored):
        return None
    tags = list(dict.fromkeys(
        str(tag) for instance in instances for tag in instance.get("tags") or [] if tag
    ))
    versions: dict[str, dict[str, Any]] = {}
    for instance, current in zip(instances, stored):
        project = str(instance.get("project_uuid") or "")
        version = versions.setdefault(project, {
            "project_uuid": project,
            "project_version": instance.get("project_version"),
            "components": [],
        })
        version["components"].append({
            **instance,
            "analysis_state": current.get("state") or "NOT_SET",
            "analysis_details": current.get("details") or "",
        })
    group = {"id": "approval", "tags": tags, "affected_versions": list(versions.values())}
    metadata = summarize_grouped_vulnerabilities([group], team_mapping or {})[0]["list_metadata"]
    lifecycle = metadata["lifecycle"]
    if lifecycle == "NEEDS_APPROVAL":
        return None
    reasons = {
        "INCONSISTENT": "the findings disagree; resolve the conflict first",
        "INCOMPLETE": (
            "a finding has no state, or a team has no assessment and no Global "
            "decision covers it; record the Global decision or synchronize first"
        ),
        "OPEN": "nothing is decided yet",
    }
    return (
        "Only a vulnerability that is ready for approval can be approved: "
        + reasons.get(lifecycle, f"it is {lifecycle}")
    )


class AssessmentConflictError(AssessmentUseCaseError):
    """The stored assessment changed since the caller read it."""

    def __init__(self, conflicts: list[dict[str, Any]]) -> None:
        super().__init__("Assessment changed since it was loaded")
        self.conflicts = conflicts


class AssessmentUseCaseDeps(Protocol):
    cache_manager: Any
    logger: Any
    code_analysis_result_store: Any
    # Optional: deps without it cannot accept code_evidence_ids.
    code_evidence_store: Any
    get_user_role: Callable[[str], str]
    fetch_current_assessment_analyses: Callable[[Any, Any], Awaitable[list[Any]]]
    collect_assessment_conflicts: Callable[
        [AssessmentRequest, list[Any]], list[dict[str, Any]]
    ]
    build_assessment_payloads: Callable[
        [AssessmentRequest, str, str], AssessmentPayloads
    ]


def strict_dt_assessment_conflicts_enabled() -> bool:
    return os.getenv(
        "DTVP_ASSESSMENT_STRICT_DT_CONFLICTS",
        "false",
    ).strip().lower() in {"1", "true", "yes", "on", "enabled"}


def expected_assessment_revisions(
    req: AssessmentRequest,
) -> dict[tuple[str, str, str], int]:
    if req.force or not req.original_analysis:
        # No client view to compare with: the save is still guarded against
        # a write that lands between the use case's own read and its persist.
        return dict(req._stored_revisions)
    expected: dict[tuple[str, str, str], int] = {}
    for instance in req.instances:
        finding_uuid = instance.get("finding_uuid")
        original = (
            req.original_analysis.get(finding_uuid)
            if isinstance(finding_uuid, str)
            else None
        )
        if not isinstance(original, dict) or "dtvpRevision" not in original:
            continue
        key = assessment_key(instance)
        if key is None:
            continue
        try:
            expected[key] = max(0, int(original.get("dtvpRevision") or 0))
        except (TypeError, ValueError):
            continue
    return expected


def seen_assessments(
    req: AssessmentRequest,
) -> dict[tuple[str, str, str], dict[str, Any]]:
    """What each finding's assessment was when the author started editing,
    for the findings where the request says so."""
    seen: dict[tuple[str, str, str], dict[str, Any]] = {}
    for instance in req.instances:
        finding_uuid = instance.get("finding_uuid")
        original = (
            (req.original_analysis or {}).get(finding_uuid)
            if isinstance(finding_uuid, str)
            else None
        )
        key = assessment_key(instance)
        if key is None or not isinstance(original, dict):
            continue
        if not any(
            name in original
            for name in ("analysisDetails", "analysis_details", "analysisState")
        ):
            continue
        suppressed = original.get("isSuppressed", original.get("is_suppressed", False))
        seen[key] = {
            "state": str(
                original.get("analysisState")
                or original.get("analysis_state")
                or "NOT_SET"
            ),
            "details": str(
                original.get("analysisDetails")
                or original.get("analysis_details")
                or ""
            ),
            "suppressed": bool(suppressed),
        }
    return seen


def local_assessment_conflict(
    deps: AssessmentUseCaseDeps,
    req: AssessmentRequest,
    exc: AssessmentRevisionConflictError,
    additional_instances: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    instance = next(
        (
            candidate
            for candidate in [*req.instances, *(additional_instances or [])]
            if assessment_key(candidate) == exc.key
        ),
        {},
    )
    finding_uuid = instance.get("finding_uuid")
    original = (
        req.original_analysis.get(finding_uuid)
        if req.original_analysis and isinstance(finding_uuid, str)
        else None
    )
    current = deps.cache_manager.get_assessment_overlay(*exc.key) or {}
    return {
        "finding_uuid": finding_uuid,
        "project_name": instance.get("project_name"),
        "project_version": instance.get("project_version"),
        "component_name": instance.get("component_name"),
        "component_version": instance.get("component_version"),
        "current": current,
        "original": original or {},
        "your_change": {
            "analysisState": req.state,
            "analysisDetails": req.details,
            "isSuppressed": req.suppressed,
        },
    }


def accepted_assessment_results(
    payloads: AssessmentPayloads,
    persisted: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    records_by_key = {
        assessment_key(record.get("payload") or {}): record
        for record in persisted
    }
    results: list[dict[str, Any]] = []
    for instance, payload in payloads:
        record = records_by_key.get(assessment_key(payload)) or {}
        results.append(
            {
                "status": "success",
                "uuid": instance.get("finding_uuid"),
                "new_state": payload.get("state"),
                "new_details": payload.get("details"),
                "queued": True,
                "sync_status": "pending",
                "update_id": record.get("id"),
                "revision": int(record.get("revision") or 0),
            }
        )
    return results


def record_code_analysis_applications(
    deps: AssessmentUseCaseDeps,
    *,
    payloads: AssessmentPayloads,
    finalized: list[dict[str, Any]],
    user: str,
    workflow_id: str,
    fallback_run_ids: list[str] | None = None,
) -> None:
    store = deps.code_analysis_result_store
    if store is None:
        return
    results_by_uuid = {
        str(result.get("uuid") or ""): result
        for result in finalized
        if result.get("uuid")
    }
    try:
        for instance, payload in payloads:
            finding_uuid = str(instance.get("finding_uuid") or "").strip()
            if not finding_uuid:
                continue
            run_ids = list(
                dict.fromkeys(
                    str(run_id).strip()
                    for run_id in (
                        instance.get("analysis_run_ids") or fallback_run_ids or []
                    )
                    if str(run_id).strip()
                )
            )
            if not run_ids:
                continue
            result = results_by_uuid.get(finding_uuid) or {}
            status = (
                "queued"
                if result.get("queued")
                else "applied"
                if result.get("status") == "success"
                else "failed"
            )
            fingerprint = hashlib.sha256(
                json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
            ).hexdigest()
            group_id = str(
                instance.get("bulk_workflow_group_id")
                or instance.get("vuln_id")
                or instance.get("vulnerability_id")
                or ""
            )
            for run_id in run_ids:
                store.record_application(
                    analysis_run_id=run_id,
                    finding_uuid=finding_uuid,
                    group_id=group_id,
                    status=status,
                    applied_by=user,
                    workflow_id=workflow_id,
                    payload_fingerprint=fingerprint,
                )
    except Exception:
        deps.logger.exception("Failed to persist code-analysis application provenance")


def _code_evidence_store(deps: AssessmentUseCaseDeps) -> Any:
    return getattr(deps, "code_evidence_store", None)


def record_code_evidence_applications(
    deps: AssessmentUseCaseDeps,
    *,
    evidence_ids: list[str],
    payloads: AssessmentPayloads,
    finalized: list[dict[str, Any]],
    user: str,
    workflow_id: str,
    selections: dict[str, list[str] | None] | None = None,
) -> None:
    """Record which saved findings referenced which evidence. Like the
    analyzer provenance, a failure here is logged and never undoes the save."""
    store = _code_evidence_store(deps)
    if store is None or not selections:
        return
    if not evidence_ids and not store.has_applications(
        str(instance.get('finding_uuid') or '') for instance, _payload in payloads
    ):
        return
    results_by_uuid = {
        str(result.get("uuid") or ""): result
        for result in finalized
        if result.get("uuid")
    }
    try:
        for instance, _payload in payloads:
            finding_uuid = str(instance.get("finding_uuid") or "").strip()
            if not finding_uuid:
                continue
            result = results_by_uuid.get(finding_uuid) or {}
            status = (
                "queued"
                if result.get("queued")
                else "applied"
                if result.get("status") == "success"
                else "failed"
            )
            if result.get('status') != 'success':
                continue
            for team, chosen in selections.items():
                previous = store.current_selection(finding_uuid, team)
                selected_ids = chosen if chosen is not None else previous
                for evidence_id in sorted(set(previous) | set(selected_ids)):
                    record = store.get(evidence_id)
                    if record is None:
                        continue
                    if record['scope'] != 'vulnerability' and not any(t.get('finding_uuid') == finding_uuid for t in record['targets']):
                        continue
                    store.record_application(
                        evidence_id=evidence_id, finding_uuid=finding_uuid,
                        status=status, applied_by=user, workflow_id=workflow_id,
                        team=team, assessment_revision=int(result.get('revision', -1)),
                        selected=evidence_id in selected_ids,
                    )
    except Exception:
        deps.logger.exception("Failed to persist code-evidence application provenance")


def validate_code_evidence(
    deps: AssessmentUseCaseDeps,
    req: AssessmentRequest,
    role: str = "REVIEWER",
) -> list[str]:
    """The referenced evidence ids, each existing, not withdrawn, and about
    the project and vulnerability of at least one saved finding."""
    # Preserve omission: assigning the default would turn it into an explicit
    # deselection in model_fields_set. Normalize only supplied selections.
    if "code_evidence_ids" in req.model_fields_set:
        req.code_evidence_ids = list(dict.fromkeys(value.strip() for value in req.code_evidence_ids if value.strip()))
    if "code_evidence_by_team" in req.model_fields_set:
        req.code_evidence_by_team = {
            team: list(dict.fromkeys(value.strip() for value in ids if value.strip()))
            for team, ids in req.code_evidence_by_team.items()
        }
    evidence_ids = list(
        dict.fromkeys(
            str(evidence_id).strip()
            for evidence_id in [*req.code_evidence_ids, *(item for ids in req.code_evidence_by_team.values() for item in ids)]
            if str(evidence_id).strip()
        )
    )
    if role.upper() != 'REVIEWER' and any(team.casefold() != str(req.team or '').casefold() for team in req.code_evidence_by_team):
        raise AssessmentPermissionError("An analyst can select evidence only for their current team")
    if req.fields:
        canonical = {block.team.casefold(): block.team for block in req.fields.teams}
        req.code_evidence_by_team = {canonical.get(team.casefold(), team): ids for team, ids in req.code_evidence_by_team.items()}
    if req.fields:
        for block in req.fields.teams:
            chosen = req.code_evidence_by_team.get(block.team, [])
            if block.team.casefold() == str(req.team or 'General').casefold():
                chosen = chosen or req.code_evidence_ids
            if chosen and not block.details.strip():
                raise AssessmentValidationError("A standalone assessment rationale is required when selecting evidence")
    elif req.code_evidence_ids and not req.details.strip():
        raise AssessmentValidationError("A standalone assessment rationale is required when selecting evidence")
    if req.code_evidence_by_team:
        teams = {block.team.casefold() for block in req.fields.teams} if req.fields else {str(req.team or 'General').casefold()}
        if any(team.casefold() not in teams for team in req.code_evidence_by_team):
            raise AssessmentValidationError("Evidence selections must name a team present in the saved assessment")
    if not evidence_ids:
        return []
    store = _code_evidence_store(deps)
    if store is None:
        raise AssessmentValidationError("Code evidence is not available")
    instance_projects = {
        str(instance.get("project_name") or "").strip().casefold()
        for instance in req.instances
    }
    instance_findings = {
        str(instance.get("finding_uuid") or "").strip()
        for instance in req.instances
    }
    instance_vulnerabilities = {
        str(instance.get("vulnerability_uuid") or "").strip()
        for instance in req.instances
    }
    instance_findings.discard("")
    instance_vulnerabilities.discard("")
    for evidence_id in evidence_ids:
        record = store.get(evidence_id)
        if not record:
            raise AssessmentValidationError(f"Unknown code evidence {evidence_id}")
        if record.get("withdrawn"):
            raise AssessmentValidationError(
                f"Code evidence {evidence_id} was withdrawn and cannot be used"
            )
        if str(record.get("project_name") or "").casefold() not in instance_projects:
            raise AssessmentValidationError(
                f"Code evidence {evidence_id} belongs to another project"
            )
        targets = record.get("targets") or []
        target_findings = {str(t.get("finding_uuid") or "") for t in targets}
        target_vulnerabilities = {
            str(t.get("vulnerability_uuid") or "") for t in targets
        }
        if record.get('scope') != 'vulnerability' and instance_findings.isdisjoint(target_findings):
            raise AssessmentValidationError(f"Code evidence {evidence_id} belongs to another finding scope")
        if instance_findings.isdisjoint(target_findings) and (
            instance_vulnerabilities.isdisjoint(target_vulnerabilities - {""})
        ):
            raise AssessmentValidationError(
                f"Code evidence {evidence_id} belongs to another vulnerability"
            )
    return evidence_ids


def _validate_ssvc_change(req: AssessmentRequest, role: str) -> None:
    if "ssvc" not in req.model_fields_set:
        return
    if role.upper() != "REVIEWER" or (
        req.team and req.team.casefold() != "general"
    ):
        raise AssessmentPermissionError(
            "SSVC changes require a reviewer Global assessment"
        )
    if req.ssvc is not None:
        try:
            evaluate_ssvc(req.ssvc)
            validate_ssvc_evidence(req.ssvc)
        except ValueError as exc:
            raise AssessmentValidationError(str(exc)) from exc


def _validate_response_change(req: AssessmentRequest, role: str) -> None:
    """A save as text names a response only as a reviewer's General save.
    With ``fields`` the request-level value is not used at all."""
    if req.fields is not None or req.response is None:
        return
    if role.upper() != "REVIEWER" or (
        req.team and req.team.casefold() != "general"
    ):
        raise AssessmentPermissionError(
            "The response is part of the Global assessment, which reviewers save"
        )


def _same_override(left: Any, right: Any) -> bool:
    left, right = normalize_version_override(left), normalize_version_override(right)
    if left is None or right is None:
        return left is right
    return normalize_override_label(left["label"]) == normalize_override_label(
        right["label"]
    ) and (left["reason"] or None) == (right["reason"] or None)


def _validate_version_override_change(
    req: AssessmentRequest, stored_details: list[str]
) -> None:
    """A save keeps each finding's version override. It may name the one a
    finding has, or none; any other marker needs an override operation."""
    sent = (
        req.fields.version_override
        if req.fields is not None
        else version_override(req.details)
    )
    if normalize_version_override(sent) is None:
        return
    for existing in stored_details:
        if not _same_override(sent, version_override(existing)):
            raise AssessmentValidationError(
                "A save cannot change a finding's version override"
            )


def _changes_response(req: AssessmentRequest, role: str) -> bool:
    """Whether this save decides the response. Only a reviewer's does, and
    only when it names one: in its fields, or beside its text. Any other
    save keeps what each finding has stored, whatever its text says."""
    if role.upper() != "REVIEWER":
        return False
    if req.fields is not None:
        return "response" in req.fields.model_fields_set
    return req.response is not None


def _validate_analysis_runs(
    deps: AssessmentUseCaseDeps,
    req: AssessmentRequest,
) -> None:
    run_ids = set(req.analysis_run_ids)
    for instance in req.instances:
        instance_run_ids = instance.get("analysis_run_ids") or []
        if not isinstance(instance_run_ids, list) or any(
            not isinstance(run_id, str) for run_id in instance_run_ids
        ):
            raise AssessmentValidationError(
                "analysis_run_ids must be a list of strings"
            )
        run_ids.update(instance_run_ids)
    for run_id in run_ids:
        store = deps.code_analysis_result_store
        record = store.get(run_id) if store is not None else None
        if not record or not record_application_eligible(record):
            raise AssessmentValidationError(
                "Analyzer result is unverified or ineligible; "
                "rerun analysis before applying it."
            )


async def save_assessment(
    deps: AssessmentUseCaseDeps,
    req: AssessmentRequest,
    *,
    user: str,
    client: Any,
    role: str | None = None,
    after_persist: Callable[[AssessmentPayloads], Awaitable[None]] | None = None,
    workflow_id: str = "individual-assessment",
    suppressed_by_finding: dict[str, bool] | None = None,
    approval_instances: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Validate and durably record one assessment change.

    ``suppressed_by_finding`` overrides the request-wide suppression flag per
    finding UUID, so one atomic save can keep differing values.

    ``role`` defaults to the user's configured role; callers acting with
    reduced authority pass a narrower one. ``after_persist`` runs once the
    change is committed (for example to refresh live views); its failures
    are the callback's own responsibility and never undo the save.

    Raises AssessmentPermissionError, AssessmentValidationError, or
    AssessmentConflictError. Returns one accepted result per instance.
    """
    if role is None:
        role = deps.get_user_role(user)
    if req.approve and str(role or "").upper() != "REVIEWER":
        raise AssessmentPermissionError("Only reviewers can approve an assessment")
    load_team_mapping = getattr(deps, "load_team_mapping", None)
    mapping = load_team_mapping() if load_team_mapping and (req.approve or req.resubmit_changes) else {}
    resubmitted_team: str | None = None
    if req.resubmit_changes:
        if req.approve or not req.team or _is_general(req.team):
            raise AssessmentValidationError("Resubmit a named team's assessment without approving it")
        supplied = {
            (assessment_key(instance), instance.get("finding_uuid"))
            for instance in req.instances
        }
        if (
            not req.review_task_id or not req.review_group_id or not approval_instances
            or len(supplied) != len(req.instances)
            or any(key is None or not finding_uuid for key, finding_uuid in supplied)
            or supplied != {
                (assessment_key(instance), instance.get("finding_uuid"))
                for instance in approval_instances
            }
        ):
            raise AssessmentValidationError("Reload the full vulnerability before resubmitting")
        resubmitted_team = _review_team_key(req.team, mapping)
        if resubmitted_team not in _review_owning_teams(approval_instances, mapping):
            raise AssessmentValidationError("Only an owning team can resubmit its assessment")
    if req.fields is not None:
        # The assessment arrives as fields. Its text, which the checks and
        # the store work with, is rendered here and nowhere in the client.
        try:
            rendered = render_assessment(req.fields.model_dump())
        except ValueError as exc:
            raise AssessmentValidationError(str(exc)) from exc
        req = req.model_copy(update={"details": rendered})
        req.model_fields_set.add("details")
    else:
        clean_text = strip_changes_requests(req.details)
        if req.details != clean_text:
            req = req.model_copy(update={"details": clean_text})
    # The stored text, never a client's view of it, is what a save may not
    # lose and where the SSVC record and the response are kept from.
    stored = await asyncio.to_thread(
        deps.cache_manager.get_cached_assessments, req.instances
    )
    stored_details = [current["details"] for current in stored]
    review_revisions: dict[tuple[str, str, str], int] = {}
    if req.approve:
        review_instances = approval_instances if approval_instances is not None else req.instances
        review_stored = stored
        if review_instances is not req.instances:
            review_stored = await asyncio.to_thread(
                deps.cache_manager.get_cached_assessments, review_instances
            )
        blocker = approval_blocker(
            review_instances, review_stored, mapping
        )
        if blocker:
            raise AssessmentValidationError(blocker)
        review_revisions = {
            key: int(current["revision"])
            for instance, current in zip(review_instances, review_stored, strict=True)
            if (key := assessment_key(instance)) is not None
        }
    req._stored_revisions = {
        key: int(current["revision"])
        for instance, current in zip(req.instances, stored)
        if (key := assessment_key(instance)) is not None
    }
    if req.fields is not None and req.fields.free_text is None:
        # The client did not touch the free text: keep each finding's.
        req._stored_free_text = {
            finding_key(instance): kept
            for instance, text in zip(req.instances, stored_details)
            if (kept := parse_assessment("", text, False)["free_text"])
        }
    req._stored_details = {
        finding_key(instance): text
        for instance, text in zip(req.instances, stored_details)
    }
    if (
        strict_dt_assessment_conflicts_enabled()
        and not req.force
        and req.original_analysis
    ):
        current_analyses = await deps.fetch_current_assessment_analyses(req, client)
        conflicts = deps.collect_assessment_conflicts(req, current_analyses)
        if conflicts:
            raise AssessmentConflictError(conflicts)

    _validate_ssvc_change(req, role)
    _validate_response_change(req, role)
    _validate_version_override_change(req, stored_details)
    _validate_analysis_runs(deps, req)
    evidence_ids = validate_code_evidence(deps, req, role)

    payloads = deps.build_assessment_payloads(req, user, role)
    open_requests = [
        changes_requests(current.get("details"))
        for current in stored
    ]
    resubmitted_revisions: dict[tuple[str, str, str], int] = {}
    if resubmitted_team is not None:
        def team_is_requested(requests: list[dict[str, Any]]) -> bool:
            return any(
                _review_team_key(request["team"], mapping) == resubmitted_team
                for request in requests
            )

        if not any(team_is_requested(requests) for requests in open_requests):
            raise AssessmentValidationError("This team has no outstanding changes request")
        for (instance, payload), current, requests in zip(payloads, stored, open_requests, strict=True):
            block = _review_team_block(payload["details"], resubmitted_team, mapping)
            if not block or block.get("state") in (None, "", "NOT_SET"):
                raise AssessmentValidationError("Set a decision for the team before resubmitting")
            if team_is_requested(requests):
                key = assessment_key(instance)
                original = (req.original_analysis or {}).get(instance.get("finding_uuid"))
                revision = original.get("dtvpRevision") if isinstance(original, dict) else None
                if type(revision) is not int or revision != int(current["revision"]):
                    raise AssessmentConflictError([{
                        "finding_uuid": instance.get("finding_uuid"),
                        "current": deps.cache_manager.get_assessment_overlay(*key) or {},
                    }])
                resubmitted_revisions[key] = revision
            # An explicit resubmission changes just the addressed team.
            # Read the other teams and free text anew from the stored record.
            base = current.get("details") or ""
            before = _review_team_block(base, resubmitted_team, mapping)
            rendered = render_team_block({**block, "reviewer": None, "reviewed_at_ms": None})
            if before:
                base = replace_assessment_block(base, before["team"], rendered)
            else:
                base = insert_assessment_blocks(base, [rendered])
            payload["details"] = base
            payload["state"] = calculate_aggregated_state(base)
            payload["suppressed"] = bool(current["suppressed"])
        workflow_id = RESUBMIT_CHANGES_ORIGIN
    keep_ssvc = "ssvc" not in req.model_fields_set
    keep_response = not _changes_response(req, role)
    if not req.resubmit_changes and (keep_ssvc or keep_response):
        # Never trust client-supplied original_analysis/headers as authority
        # for what reviewers decide with the Global assessment: the SSVC
        # record and the response. Preserve each finding's stored value; a
        # finding without a record takes the one the others stored agree on.
        shared_ssvc = agreed_ssvc_record(stored_details) if keep_ssvc else None
        shared_response = agreed_response(stored_details) if keep_response else None
        for (_instance, payload), existing in zip(payloads, stored_details):
            if keep_ssvc:
                payload["details"] = preserve_or_share_ssvc_record(
                    payload["details"], existing, shared_ssvc
                )
            if keep_response:
                payload["details"] = preserve_or_share_response(
                    payload["details"], existing, shared_response
                )
    # Until override scopes exist (ADR 0010 step 7), every save keeps each
    # finding's stored version override exactly.
    for (_instance, payload), existing in zip(payloads, stored_details):
        payload["details"] = with_version_override(
            payload["details"], version_override(existing)
        )
    if not keep_response and req.fields is None:
        # A reviewer's save as text names the response beside the text.
        for _instance, payload in payloads:
            payload["details"] = with_response(payload["details"], req.response)
    if suppressed_by_finding:
        for instance, payload in payloads:
            finding_uuid = instance.get("finding_uuid")
            if finding_uuid in suppressed_by_finding:
                payload["suppressed"] = bool(suppressed_by_finding[finding_uuid])
    for (_instance, payload), requests in zip(payloads, open_requests):
        if resubmitted_team is not None:
            requests = [
                request for request in requests
                if _review_team_key(request["team"], mapping) != resubmitted_team
            ]
            if not _PENDING_REVIEW.search(payload["details"]):
                payload["details"] = f'{payload["details"].rstrip()}\n\n[Status: Pending Review]'
        payload["details"] = with_changes_requests(payload["details"], requests)
    expected = expected_assessment_revisions(req)
    if req.approve:
        expected = {**review_revisions, **req._stored_revisions, **expected}
    if req.resubmit_changes:
        expected = {**req._stored_revisions, **expected, **resubmitted_revisions}
    if req.approve:
        workflow_id = "assessment-approval"
    try:
        persisted = await deps.cache_manager.persist_assessment_updates(
            [payload for _instance, payload in payloads],
            replace=True,
            expected_revisions=expected,
            author=user,
            origin=workflow_id,
            seen=seen_assessments(req),
        )
    except AssessmentRevisionConflictError as exc:
        raise AssessmentConflictError(
            [local_assessment_conflict(deps, req, exc, approval_instances)]
        ) from exc

    if after_persist is not None:
        await after_persist(payloads)

    finalized = accepted_assessment_results(payloads, persisted)
    record_code_analysis_applications(
        deps,
        payloads=payloads,
        finalized=finalized,
        user=user,
        workflow_id=workflow_id,
        fallback_run_ids=req.analysis_run_ids,
    )
    record_code_evidence_applications(
        deps,
        evidence_ids=evidence_ids,
        payloads=payloads,
        finalized=finalized,
        user=user,
        workflow_id=workflow_id,
        selections={
            **({block.team: None for block in req.fields.teams} if req.fields else {req.team or 'General': None}),
            **({req.team or 'General': req.code_evidence_ids} if 'code_evidence_ids' in req.model_fields_set else {}),
            **req.code_evidence_by_team,
        },
    )
    return finalized


ORIGIN_DELETION = "assessment-deletion"


def _review_team_key(team: str, mapping: dict[str, Any]) -> str:
    from .team_assessment_restore_services import canonical_team_key

    return canonical_team_key(team, mapping)


def _review_owning_teams(instances: list[dict[str, Any]], mapping: dict[str, Any]) -> set[str]:
    return {
        _review_team_key(tag, mapping)
        for instance in instances for tag in instance.get("tags") or []
    }


def _review_team_block(details: str, key: str, mapping: dict[str, Any]) -> dict[str, Any] | None:
    _, blocks = parse_assessment_blocks(details)
    return next((
        block for block in blocks
        if not block.get("historical") and _review_team_key(block.get("team") or "", mapping) == key
    ), None)


async def request_assessment_changes(
    deps: AssessmentUseCaseDeps,
    instances: list[dict[str, Any]],
    *,
    team: str,
    rationale: str | None,
    user: str,
    revisions: dict[str, int],
    withdraw: bool = False,
    after_persist: Callable[[AssessmentPayloads], Awaitable[None]] | None = None,
) -> list[dict[str, Any]]:
    from .assessment_scopes import has_pending_review_marker

    if deps.get_user_role(user).upper() != "REVIEWER":
        raise AssessmentPermissionError("Only reviewers can request assessment changes")
    if not instances or any(assessment_key(instance) is None for instance in instances):
        raise AssessmentValidationError("The vulnerability has no reviewable findings")
    [feedback] = normalize_changes_requests([{
        "team": team,
        "rationale": rationale,
        "reviewer": user,
        "requested_at_ms": int(time.time() * 1000),
    }]) or [None]
    if feedback is None and not withdraw:
        raise AssessmentValidationError(
            f"Name a non-Global team and enter a rationale of 1 to {MAX_REVIEW_RATIONALE} characters"
        )
    load_team_mapping = getattr(deps, "load_team_mapping", None)
    mapping = load_team_mapping() if load_team_mapping else {}
    team_key = _review_team_key(team, mapping)
    if not withdraw and team_key not in _review_owning_teams(instances, mapping):
        raise AssessmentValidationError("Only an owning team's assessment can be returned")
    identities = {
        str(instance.get("finding_uuid") or "") for instance in instances
    }
    if "" in identities or len(identities) != len(instances) or identities != revisions.keys():
        raise AssessmentValidationError("Reload the vulnerability before requesting changes")
    stored = await asyncio.to_thread(deps.cache_manager.get_cached_assessments, instances)
    payloads: AssessmentPayloads = []
    expected: dict[tuple[str, str, str], int] = {}
    has_submission = False
    has_request = False
    for instance, current in zip(instances, stored, strict=True):
        key = assessment_key(instance)
        revision = int(current["revision"])
        if revisions[instance["finding_uuid"]] != revision:
            raise AssessmentConflictError([{
                "finding_uuid": instance["finding_uuid"],
                "current": deps.cache_manager.get_assessment_overlay(*key) or {},
            }])
        details = current.get("details") or ""
        requests = changes_requests(details)
        requests_for_other_teams = [
            request for request in requests
            if _review_team_key(request["team"], mapping) != team_key
        ]
        has_matching_request = len(requests_for_other_teams) != len(requests)
        has_request = has_request or has_matching_request
        if has_matching_request and not withdraw:
            raise AssessmentValidationError("Changes are already requested for this team")
        expected[key] = revision
        if withdraw and not has_matching_request:
            continue
        block = _review_team_block(details, team_key, mapping) if not withdraw else None
        if (
            block and block.get("state") not in (None, "", "NOT_SET")
            and not block.get("reviewer") and has_pending_review_marker(details)
        ):
            has_submission = True
        payloads.append((instance, _payload(
            instance, current["state"], with_changes_requests(
                details, requests_for_other_teams if withdraw else [*requests, feedback]
            ),
            current["suppressed"],
        )))
    if withdraw and not has_request:
        raise AssessmentValidationError("This team has no outstanding changes request")
    if not withdraw and not has_submission:
        raise AssessmentValidationError("Only a submitted team assessment can be returned")
    return await _persist_explicit_change(
        deps, payloads, expected, user=user, origin=(
            WITHDRAW_CHANGES_ORIGIN if withdraw else REQUEST_CHANGES_ORIGIN
        ),
        after_persist=after_persist,
    )


async def delete_assessment(
    deps: AssessmentUseCaseDeps,
    instances: list[dict[str, Any]],
    *,
    team: str | None,
    user: str,
    role: str | None = None,
    after_persist: Callable[[AssessmentPayloads], Awaitable[None]] | None = None,
) -> list[dict[str, Any]]:
    """Delete one team's assessment of the given findings, or all of it.

    A deletion is a local change like any other: it gets a revision, is
    exported, and so removes the assessment from the source as well. That is
    what distinguishes it from the source merely reporting nothing, which is
    treated as a loss and repaired.

    ``team`` is a team name, "General" for the global assessment, or ``None``
    for everything. General clears shared review fields and suppression too,
    even without a General block; it keeps team records. Removing General or
    everything needs the reviewer role. Findings where there is nothing to
    remove are left untouched and not returned.
    """
    if role is None:
        role = deps.get_user_role(user)
    reviewer = role.upper() == "REVIEWER"
    if (team is None or team.strip().casefold() == "general") and not reviewer:
        raise AssessmentPermissionError(
            "Only reviewers can clear the Global assessment or a whole assessment"
        )
    if team is not None and not team.strip():
        raise AssessmentValidationError("Name the team whose assessment to clear")
    keyed = [instance for instance in instances if assessment_key(instance) is not None]
    if not keyed or len(keyed) != len(instances):
        raise AssessmentValidationError(
            "Each instance needs project_uuid, component_uuid, and vulnerability_uuid"
        )

    # The text to cut from and the revision to guard are the stored ones.
    stored = await asyncio.to_thread(
        deps.cache_manager.get_cached_assessments, keyed
    )
    payloads: AssessmentPayloads = []
    expected: dict[tuple[str, str, str], int] = {}
    for instance, current in zip(keyed, stored):
        payload = _cleared_payload(instance, current, team, reviewer)
        if payload is None:
            continue
        payload["details"] = with_changes_requests(
            payload["details"], changes_requests(current.get("details"))
        )
        expected[assessment_key(instance)] = int(current["revision"])
        payloads.append((instance, payload))
    if not payloads:
        raise AssessmentValidationError("There is no such assessment to clear")

    return await _persist_explicit_change(
        deps, payloads, expected, user=user, origin=ORIGIN_DELETION,
        after_persist=after_persist,
    )


_PENDING_REVIEW = re.compile(r"\[Status: Pending Review\]", re.IGNORECASE)


def _payload(
    instance: dict[str, Any], state: str, details: str, suppressed: bool
) -> dict[str, Any]:
    key = assessment_key(instance)
    return {
        "project_uuid": key[0],
        "component_uuid": key[1],
        "vulnerability_uuid": key[2],
        "state": state,
        "details": details,
        "suppressed": suppressed,
    }


def _cleared_payload(
    instance: dict[str, Any],
    current: dict[str, Any],
    team: str | None,
    reviewer: bool,
) -> dict[str, Any] | None:
    """The finding with ``team``'s assessment (``None``: all of it) removed;
    ``None`` when there is nothing to remove."""
    global_clear = _is_general(team)
    details = (
        clear_global_assessment(current["details"]) if global_clear
        else remove_assessment_blocks(current["details"], team)
    )
    suppressed = False if team is None or global_clear else bool(current["suppressed"])
    was_pending = bool(_PENDING_REVIEW.search(current["details"]))
    if (
        details
        and not global_clear
        and calculate_aggregated_state(details) != "NOT_SET"
        # What remains was not reviewed in this form; a reviewer's
        # deletion is not an approval of what was pending.
        and (not reviewer or was_pending)
    ):
        details += "\n\n[Status: Pending Review]"
    state = calculate_aggregated_state(details) if details else "NOT_SET"
    # Compare without the review marker, which is re-derived above.
    before = _PENDING_REVIEW.sub("", current["details"])
    unchanged = (
        remove_assessment_blocks(details, "").strip()
        == remove_assessment_blocks(before, "").strip()
        and suppressed == bool(current["suppressed"])
    )
    if global_clear:
        # A pending marker may be the only Global field. Removing it is a
        # real change even when the preserved team blocks are identical.
        unchanged = (
            details.strip() == current["details"].strip()
            and state == current["state"]
            and suppressed == bool(current["suppressed"])
        )
    if unchanged:
        return None
    return _payload(instance, state, details, suppressed)


async def _persist_explicit_change(
    deps: AssessmentUseCaseDeps,
    payloads: AssessmentPayloads,
    expected: dict[tuple[str, str, str], int],
    *,
    user: str,
    origin: str,
    after_persist: Callable[[AssessmentPayloads], Awaitable[None]] | None,
) -> list[dict[str, Any]]:
    """Persist texts built from the stored ones (a deletion, a cleanup):
    each a new revision, guarded by the revision it was built from, and
    exported like any change."""
    try:
        persisted = await deps.cache_manager.persist_assessment_updates(
            [payload for _instance, payload in payloads],
            replace=True,
            expected_revisions=expected,
            author=user,
            origin=origin,
        )
    except AssessmentRevisionConflictError as exc:
        raise AssessmentConflictError(
            [
                {
                    "finding_uuid": next(
                        (
                            instance.get("finding_uuid")
                            for instance, _payload in payloads
                            if assessment_key(instance) == exc.key
                        ),
                        None,
                    ),
                    "current": deps.cache_manager.get_assessment_overlay(*exc.key) or {},
                }
            ]
        ) from exc
    if after_persist is not None:
        await after_persist(payloads)
    return accepted_assessment_results(payloads, persisted)


ORIGIN_CLEANUP = "assessment-cleanup"
CLEANUP_ACTIONS = ("apply", "clear")


def _is_general(team: str | None) -> bool:
    return team is not None and team.strip().casefold() == "general"


def _applied_text(
    target: str, source: str, team: str | None, reviewer: bool
) -> str:
    """``target`` with ``source``'s assessment for ``team`` (``None``: the
    whole assessment). The target keeps its own historical blocks and its
    version override; those belong to the finding, not to the decision."""
    if team is None:
        text = without_historical_blocks(source)
        pending = bool(_PENDING_REVIEW.search(text))
        text = insert_assessment_blocks(
            _PENDING_REVIEW.sub("", text).strip(), historical_blocks_of(target)
        )
        if pending:
            text = f"{text}\n\n[Status: Pending Review]"
        return with_version_override(text, version_override(target))
    block = active_assessment_block(source, team)
    if block is None:
        raise AssessmentValidationError(
            f"The assessment to keep has no {'Global' if _is_general(team) else team} assessment"
        )
    pending = bool(_PENDING_REVIEW.search(target)) or bool(
        _PENDING_REVIEW.search(source)
    ) or not reviewer
    text = _PENDING_REVIEW.sub("", target).strip()
    if active_assessment_block(text, team) is not None:
        text = replace_assessment_block(text, team, block)
    else:
        text = insert_assessment_blocks(text, [block], first=_is_general(team))
    if _is_general(team):
        # The response stands beside the blocks and belongs to the General
        # assessment, as its SSVC record, which is part of the block.
        text = with_response(text, analysis_response(source))
    return f"{text}\n\n[Status: Pending Review]" if pending else text


async def clean_up_assessment(
    deps: AssessmentUseCaseDeps,
    instances: list[dict[str, Any]],
    *,
    action: str,
    team: str | None,
    source: dict[str, Any] | None,
    user: str,
    role: str | None = None,
    revisions: dict[str, int] | None = None,
    dry_run: bool = False,
    after_persist: Callable[[AssessmentPayloads], Awaitable[None]] | None = None,
) -> list[dict[str, Any]]:
    """Make the findings of a vulnerability agree: give the selected ones
    the assessment of ``source`` (``apply``), or remove theirs (``clear``),
    for ``team`` or, with ``None``, the whole assessment.

    The texts are built from the stored ones, never from a client's view,
    and written like any change: a revision each, exported. ``dry_run``
    returns the same per finding without writing anything, so that what a
    reviewer previewed is what is saved; ``revisions`` (``"project|
    component|vulnerability"`` to the revision previewed, the kept finding's
    included) turns any change in between into a conflict. Findings that would not change are left
    alone and reported as unchanged in a dry run only.
    """
    if action not in CLEANUP_ACTIONS:
        raise AssessmentValidationError(f"Unknown cleanup action: {action}")
    if role is None:
        role = deps.get_user_role(user)
    reviewer = role.upper() == "REVIEWER"
    if (team is None or _is_general(team)) and not reviewer:
        raise AssessmentPermissionError(
            "Only reviewers can clean up the Global assessment or a whole assessment"
        )
    if team is not None and not team.strip():
        raise AssessmentValidationError("Name the team whose assessment to clean up")
    keyed = [instance for instance in instances if assessment_key(instance) is not None]
    if not keyed or len(keyed) != len(instances):
        raise AssessmentValidationError(
            "Each instance needs project_uuid, component_uuid, and vulnerability_uuid"
        )
    revisions = revisions or {}

    def guard(key: tuple[str, str, str], stored_revision: int) -> int:
        previewed = revisions.get("|".join(key))
        if previewed is not None and int(previewed) != stored_revision:
            raise AssessmentConflictError(
                [{"finding_uuid": None, "current": deps.cache_manager.get_assessment_overlay(*key) or {}}]
            )
        return stored_revision

    source_text = ""
    source_state = "NOT_SET"
    source_suppressed = False
    source_key = None
    source_revision = None
    if action == "apply":
        source_key = assessment_key(source or {})
        if source_key is None:
            raise AssessmentValidationError("Name the finding whose assessment to keep")
        (kept,) = await asyncio.to_thread(
            deps.cache_manager.get_cached_assessments, [source]
        )
        source_revision = guard(source_key, int(kept["revision"]))
        source_text = kept["details"]
        source_state = kept["state"]
        source_suppressed = bool(kept["suppressed"])
        if not source_text.strip() and source_state == "NOT_SET":
            raise AssessmentValidationError(
                "The finding to keep has no assessment; clear the others instead"
            )

    targets = [instance for instance in keyed if assessment_key(instance) != source_key]
    stored = await asyncio.to_thread(deps.cache_manager.get_cached_assessments, targets)
    payloads: AssessmentPayloads = []
    expected: dict[tuple[str, str, str], int] = {}
    preview: list[dict[str, Any]] = []
    for instance, current in zip(targets, stored):
        key = assessment_key(instance)
        expected_revision = guard(key, int(current["revision"]))
        if action == "clear":
            payload = _cleared_payload(instance, current, team, reviewer)
        else:
            details = _applied_text(current["details"], source_text, team, reviewer)
            if team is None:
                state, suppressed = source_state, source_suppressed
            else:
                state = calculate_aggregated_state(details) if details else "NOT_SET"
                suppressed = bool(current["suppressed"])
            unchanged = (
                " ".join(details.split()) == " ".join(current["details"].split())
                and state == current["state"]
                and suppressed == bool(current["suppressed"])
            )
            payload = None if unchanged else _payload(instance, state, details, suppressed)
        preview.append(
            {
                "finding_uuid": instance.get("finding_uuid"),
                "project_uuid": key[0],
                "component_uuid": key[1],
                "vulnerability_uuid": key[2],
                "revision": expected_revision,
                # The kept finding's revision: a confirm sends it back with
                # the others, so a change to it in between is a conflict too.
                "source_revision": source_revision,
                "changed": payload is not None,
                "before": {
                    "state": current["state"],
                    "details": current["details"],
                    "suppressed": bool(current["suppressed"]),
                },
                "after": None if payload is None else {
                    "state": payload["state"],
                    "details": payload["details"],
                    "suppressed": payload["suppressed"],
                },
            }
        )
        if payload is not None:
            expected[key] = expected_revision
            payloads.append((instance, payload))
    if dry_run:
        return preview
    if not payloads:
        raise AssessmentValidationError("The selected findings already agree; nothing to change")
    return await _persist_explicit_change(
        deps, payloads, expected, user=user, origin=ORIGIN_CLEANUP,
        after_persist=after_persist,
    )
