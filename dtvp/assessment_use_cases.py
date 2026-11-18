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

from pydantic import BaseModel, Field

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


class AssessmentRequest(BaseModel):
    instances: list[dict]
    state: str
    details: str
    comment: Optional[str] = None
    justification: Optional[str] = None
    suppressed: bool = False
    team: Optional[str] = None
    assigned: Optional[list[str]] = None
    original_analysis: Optional[dict[str, dict[str, Any]]] = None
    force: bool = False
    comparison_mode: Optional[str] = "MERGE"
    analysis_run_ids: list[str] = Field(default_factory=list)
    ssvc: SsvcInput | None = None


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
        return {}
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
    if (
        strict_dt_assessment_conflicts_enabled()
        and not req.force
        and req.original_analysis
    ):
        current_analyses = await deps.fetch_current_assessment_analyses(req, client)
        conflicts = deps.collect_assessment_conflicts(req, current_analyses)
        if conflicts:
            raise AssessmentConflictError(conflicts)

    if role is None:
        role = deps.get_user_role(user)
    _validate_ssvc_change(req, role)
    _validate_analysis_runs(deps, req)

    payloads = deps.build_assessment_payloads(req, user, role)
    if "ssvc" not in req.model_fields_set:
        # Never trust client-supplied original_analysis/headers as authority
        # for reviewer-only SSVC. Preserve each finding's stored record.
        stored_details = await asyncio.to_thread(
            deps.cache_manager.get_cached_assessment_details, req.instances
        )
        for (_instance, payload), existing in zip(payloads, stored_details):
            payload["details"] = preserve_ssvc_record(payload["details"], existing)
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
        if details and not reviewer and calculate_aggregated_state(details) != "NOT_SET":
            # What remains was not reviewed in this form.
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
