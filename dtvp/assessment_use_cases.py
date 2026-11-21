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
from typing import Any, Awaitable, Callable, Optional, Protocol

from pydantic import BaseModel, Field, PrivateAttr, field_validator

from .assessment_model import (
    ANALYSIS_RESPONSES,
    RESPONSE_NOT_SET,
    analysis_response,
    finding_key,
    normalize_override_label,
    normalize_response,
    normalize_version_override,
    parse_assessment,
    render_assessment,
    version_override,
    with_response,
    with_version_override,
)
from .assessment_outbox_services import (
    AssessmentRevisionConflictError,
    assessment_key,
)
from .code_analysis_assessment_services import record_application_eligible
from .logic import calculate_aggregated_state, remove_assessment_blocks
from .ssvc_services import (
    SsvcInput,
    evaluate as evaluate_ssvc,
    preserve_record as preserve_ssvc_record,
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
    # The revision each finding had when the use case read it, keyed by
    # (project, component, vulnerability); never client input.
    _stored_revisions: dict[tuple[str, str, str], int] = PrivateAttr(default_factory=dict)
    comparison_mode: Optional[str] = "MERGE"
    analysis_run_ids: list[str] = Field(default_factory=list)
    # Agent code evidence a person referenced in this assessment; recorded
    # as applications after the save. Never accepted from MCP tools.
    code_evidence_ids: list[str] = Field(default_factory=list)
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
) -> dict[str, Any]:
    instance = next(
        (
            candidate
            for candidate in req.instances
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
) -> None:
    """Record which saved findings referenced which evidence. Like the
    analyzer provenance, a failure here is logged and never undoes the save."""
    store = _code_evidence_store(deps)
    if store is None or not evidence_ids:
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
            for evidence_id in evidence_ids:
                store.record_application(
                    evidence_id=evidence_id,
                    finding_uuid=finding_uuid,
                    status=status,
                    applied_by=user,
                    workflow_id=workflow_id,
                )
    except Exception:
        deps.logger.exception("Failed to persist code-evidence application provenance")


def _validate_code_evidence(
    deps: AssessmentUseCaseDeps,
    req: AssessmentRequest,
) -> list[str]:
    """The referenced evidence ids, each existing, not withdrawn, and about
    the project and vulnerability of at least one saved finding."""
    evidence_ids = list(
        dict.fromkeys(
            str(evidence_id).strip()
            for evidence_id in req.code_evidence_ids
            if str(evidence_id).strip()
        )
    )
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
    if req.fields is not None:
        # The assessment arrives as fields. Its text, which the checks and
        # the store work with, is rendered here and nowhere in the client.
        try:
            rendered = render_assessment(req.fields.model_dump())
        except ValueError as exc:
            raise AssessmentValidationError(str(exc)) from exc
        req = req.model_copy(update={"details": rendered})
        req.model_fields_set.add("details")
    # The stored text, never a client's view of it, is what a save may not
    # lose and where the SSVC record and the response are kept from.
    stored = await asyncio.to_thread(
        deps.cache_manager.get_cached_assessments, req.instances
    )
    stored_details = [current["details"] for current in stored]
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
    evidence_ids = _validate_code_evidence(deps, req)

    payloads = deps.build_assessment_payloads(req, user, role)
    keep_ssvc = "ssvc" not in req.model_fields_set
    keep_response = not _changes_response(req, role)
    if keep_ssvc or keep_response:
        # Never trust client-supplied original_analysis/headers as authority
        # for what reviewers decide with the Global assessment: the SSVC
        # record and the response. Preserve each finding's stored value.
        for (_instance, payload), existing in zip(payloads, stored_details):
            if keep_ssvc:
                payload["details"] = preserve_ssvc_record(payload["details"], existing)
            if keep_response:
                payload["details"] = with_response(
                    payload["details"], analysis_response(existing)
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
    try:
        persisted = await deps.cache_manager.persist_assessment_updates(
            [payload for _instance, payload in payloads],
            replace=True,
            expected_revisions=expected_assessment_revisions(req),
            author=user,
            origin=workflow_id,
            seen=seen_assessments(req),
        )
    except AssessmentRevisionConflictError as exc:
        raise AssessmentConflictError(
            [local_assessment_conflict(deps, req, exc)]
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
    )
    return finalized


ORIGIN_DELETION = "assessment-deletion"


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
    for everything including suppression. Removing the General assessment or
    everything needs the reviewer role. Findings where there is nothing to
    remove are left untouched and not returned.
    """
    if role is None:
        role = deps.get_user_role(user)
    reviewer = role.upper() == "REVIEWER"
    if (team is None or team.strip().casefold() == "general") and not reviewer:
        raise AssessmentPermissionError(
            "Only reviewers can delete the General assessment or a whole assessment"
        )
    if team is not None and not team.strip():
        raise AssessmentValidationError("Name the team whose assessment to delete")
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
        details = remove_assessment_blocks(current["details"], team)
        suppressed = False if team is None else bool(current["suppressed"])
        was_pending = bool(
            re.search(r"\[Status: Pending Review\]", current["details"], re.IGNORECASE)
        )
        if (
            details
            and calculate_aggregated_state(details) != "NOT_SET"
            # What remains was not reviewed in this form; a reviewer's
            # deletion is not an approval of what was pending.
            and (not reviewer or was_pending)
        ):
            details += "\n\n[Status: Pending Review]"
        state = calculate_aggregated_state(details) if details else "NOT_SET"
        # Compare without the review marker, which is re-derived above.
        before = re.sub(
            r"\[Status: Pending Review\]", "", current["details"], flags=re.IGNORECASE
        )
        unchanged = (
            remove_assessment_blocks(details, "").strip()
            == remove_assessment_blocks(before, "").strip()
            and suppressed == bool(current["suppressed"])
        )
        if unchanged:
            continue
        key = assessment_key(instance)
        expected[key] = int(current["revision"])
        payloads.append(
            (
                instance,
                {
                    "project_uuid": key[0],
                    "component_uuid": key[1],
                    "vulnerability_uuid": key[2],
                    "state": state,
                    "details": details,
                    "suppressed": suppressed,
                },
            )
        )
    if not payloads:
        raise AssessmentValidationError("There is no such assessment to delete")

    try:
        persisted = await deps.cache_manager.persist_assessment_updates(
            [payload for _instance, payload in payloads],
            replace=True,
            expected_revisions=expected,
            author=user,
            origin=ORIGIN_DELETION,
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
