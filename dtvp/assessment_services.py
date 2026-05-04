import asyncio
import re
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Sequence

from .dt_client import DTClient
from .general_api_routes import AssessmentRequest


@dataclass(frozen=True)
class AssessmentServiceDeps:
    cache_manager: Any
    logger: Any
    calculate_aggregated_state: Callable[[str], str]
    process_assessment_details: Callable[..., tuple[str, str]]


def _normalize_analysis_details(details: Optional[str]) -> str:
    if not details:
        return ""

    normalized = re.sub(r"\[Date:\s*[^\]]*\]", "", details)
    normalized = re.sub(r"\[Assessed By:\s*[^\]]*\]", "", normalized)
    normalized = re.sub(r"\[Rescored:\s*[\d\.]+\]", "", normalized)
    normalized = re.sub(r"\[Rescored Vector:\s*[^\]]+\]", "", normalized)
    normalized = normalized.replace("[Status: Pending Review]", "")
    normalized = re.sub(r"\s+", " ", normalized)
    return normalized.strip()


def _get_analysis_snapshot(analysis: Dict[str, Any]) -> tuple[str, str, bool]:
    state = analysis.get("analysisState") or analysis.get("analysis_state") or "NOT_SET"
    details = analysis.get("analysisDetails") or analysis.get("analysis_details") or ""
    suppressed = (
        analysis.get("isSuppressed")
        if "isSuppressed" in analysis
        else analysis.get("is_suppressed", False)
    )
    return str(state or "NOT_SET"), str(details or ""), bool(suppressed)


async def fetch_current_assessment_analyses(
    deps: AssessmentServiceDeps,
    req: AssessmentRequest,
    client: DTClient,
) -> List[Dict[str, Any] | BaseException | None]:
    analysis_tasks = [
        deps.cache_manager.get_analysis(
            client,
            project_uuid=instance["project_uuid"],
            component_uuid=instance["component_uuid"],
            vulnerability_uuid=instance["vulnerability_uuid"],
            refresh=True,
        )
        for instance in req.instances
    ]
    return await asyncio.gather(*analysis_tasks, return_exceptions=True)


def collect_assessment_conflicts(
    deps: AssessmentServiceDeps,
    req: AssessmentRequest,
    current_analyses: Sequence[Dict[str, Any] | BaseException | None],
) -> List[Dict[str, Any]]:
    if not req.original_analysis:
        return []

    conflicts: List[Dict[str, Any]] = []
    for instance, current in zip(req.instances, current_analyses):
        if not isinstance(current, dict):
            continue

        finding_uuid = instance.get("finding_uuid")
        if not isinstance(finding_uuid, str):
            continue

        original = req.original_analysis.get(finding_uuid)
        if not original:
            continue

        curr_state, curr_details, curr_suppressed = _get_analysis_snapshot(current)
        orig_state, orig_details, orig_suppressed = _get_analysis_snapshot(original)
        details_match = _normalize_analysis_details(
            curr_details
        ) == _normalize_analysis_details(orig_details)

        has_conflict = (
            (curr_state or "") != (orig_state or "")
            or not details_match
            or curr_suppressed != orig_suppressed
        )
        if not has_conflict:
            continue

        deps.logger.warning(
            "Conflict found for %s: state=%s→%s details_match=%s suppressed=%s→%s",
            finding_uuid,
            orig_state,
            curr_state,
            details_match,
            orig_suppressed,
            curr_suppressed,
        )
        conflicts.append(
            {
                "finding_uuid": finding_uuid,
                "project_name": instance.get("project_name"),
                "project_version": instance.get("project_version"),
                "component_name": instance.get("component_name"),
                "component_version": instance.get("component_version"),
                "current": current,
                "original": original,
                "your_change": {
                    "analysisState": req.state,
                    "analysisDetails": req.details,
                    "isSuppressed": req.suppressed,
                },
            }
        )

    return conflicts


def build_assessment_payloads(
    deps: AssessmentServiceDeps,
    req: AssessmentRequest,
    user: str,
    role: str,
) -> List[tuple[dict, dict]]:
    payloads: List[tuple[dict, dict]] = []
    for instance in req.instances:
        finding_uuid = instance.get("finding_uuid")
        original_analysis = (
            req.original_analysis.get(finding_uuid)
            if req.original_analysis and isinstance(finding_uuid, str)
            else None
        )
        existing_details = ""
        if original_analysis:
            existing_details = (
                original_analysis.get("analysisDetails")
                or original_analysis.get("analysis_details")
                or ""
            )

        if req.comparison_mode == "REPLACE":
            final_details_str = req.details
            aggregated_state = deps.calculate_aggregated_state(req.details)
        else:
            final_details_str, aggregated_state = deps.process_assessment_details(
                req.details,
                user,
                role,
                req.team,
                req.state,
                existing_details,
                assigned=req.assigned,
            )

        payload = {
            "project_uuid": instance["project_uuid"],
            "component_uuid": instance["component_uuid"],
            "vulnerability_uuid": instance["vulnerability_uuid"],
            "state": aggregated_state,
            "details": final_details_str,
            "suppressed": req.suppressed,
        }
        payloads.append((instance, payload))

    return payloads


async def _try_update_assessment_payload(
    deps: AssessmentServiceDeps,
    client: DTClient,
    instance: dict,
    payload: dict,
) -> Dict[str, Any]:
    try:
        deps.logger.debug(
            "Updating instance: %s (Vulnerability: %s)",
            instance.get("finding_uuid"),
            instance.get("vulnerability_uuid"),
        )
        await client.update_analysis(**payload)
        return {
            "status": "success",
            "uuid": instance["finding_uuid"],
            "new_state": payload["state"],
            "new_details": payload["details"],
        }
    except Exception as exc:
        return {
            "status": "error",
            "uuid": instance.get("finding_uuid"),
            "error": str(exc),
            "payload": payload,
        }


async def apply_assessment_payloads(
    deps: AssessmentServiceDeps,
    client: DTClient,
    payloads: List[tuple[dict, dict]],
) -> List[Dict[str, Any]]:
    return await asyncio.gather(
        *[
            _try_update_assessment_payload(deps, client, instance, payload)
            for instance, payload in payloads
        ]
    )


async def finalize_assessment_results(
    deps: AssessmentServiceDeps,
    api_results: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    for result in api_results:
        if result["status"] == "error":
            payload = result.pop("payload")
            try:
                await deps.cache_manager.queue_analysis_update(payload, replace=True)
                result["queued"] = True
            except Exception as queue_error:
                result["queued"] = False
                result["error"] += f" (queue failed: {queue_error})"
        results.append(result)
    return results
