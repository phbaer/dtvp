import asyncio
import inspect
import os
import re
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, List, Optional, Sequence

import httpx

from .dt_client import DTClient
from .general_api_models import AssessmentRequest


ASSESSMENT_WRITE_RETRY_STATUS_CODES = frozenset(
    {408, 425, 429, 500, 502, 503, 504}
)
DEFAULT_ASSESSMENT_IO_CONCURRENCY = 4
DEFAULT_ASSESSMENT_WRITE_MAX_ATTEMPTS = 3
DEFAULT_ASSESSMENT_WRITE_RETRY_BASE_SECONDS = 0.5
MAX_ASSESSMENT_WRITE_RETRY_DELAY_SECONDS = 30.0
AssessmentWriteProgress = Callable[
    [int, int, Dict[str, Any]], Awaitable[None] | None
]


@dataclass(frozen=True)
class AssessmentServiceDeps:
    cache_manager: Any
    logger: Any
    calculate_aggregated_state: Callable[[str], str]
    process_assessment_details: Callable[..., tuple[str, str]]
    build_authorized_analyst_assessment_details: Callable[..., tuple[str, str]]


def _positive_int_setting(
    deps: AssessmentServiceDeps,
    name: str,
    default: int,
) -> int:
    raw_value = os.getenv(name, str(default))
    try:
        return max(1, int(raw_value))
    except (TypeError, ValueError):
        deps.logger.warning(
            "Invalid %s=%r, falling back to %d",
            name,
            raw_value,
            default,
        )
        return default


def get_assessment_io_concurrency(deps: AssessmentServiceDeps) -> int:
    return _positive_int_setting(
        deps,
        "DTVP_ASSESSMENT_IO_CONCURRENCY",
        DEFAULT_ASSESSMENT_IO_CONCURRENCY,
    )


def get_assessment_write_max_attempts(deps: AssessmentServiceDeps) -> int:
    return _positive_int_setting(
        deps,
        "DTVP_ASSESSMENT_WRITE_MAX_ATTEMPTS",
        DEFAULT_ASSESSMENT_WRITE_MAX_ATTEMPTS,
    )


def _retry_after_seconds(exc: Exception) -> float | None:
    if not isinstance(exc, httpx.HTTPStatusError) or exc.response is None:
        return None
    retry_after = exc.response.headers.get("Retry-After")
    if retry_after is None:
        return None
    try:
        return max(
            0.0,
            min(float(retry_after), MAX_ASSESSMENT_WRITE_RETRY_DELAY_SECONDS),
        )
    except (TypeError, ValueError):
        return None


def _retryable_assessment_write_error(exc: Exception) -> bool:
    if isinstance(exc, httpx.HTTPStatusError):
        return (
            exc.response is not None
            and exc.response.status_code in ASSESSMENT_WRITE_RETRY_STATUS_CODES
        )
    return isinstance(exc, httpx.TransportError)


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
    if not req.instances:
        return []

    results: list[Dict[str, Any] | BaseException | None] = [None] * len(
        req.instances
    )
    next_index = 0

    async def worker() -> None:
        nonlocal next_index
        while next_index < len(req.instances):
            index = next_index
            next_index += 1
            instance = req.instances[index]
            try:
                results[index] = await deps.cache_manager.get_analysis(
                    client,
                    project_uuid=instance["project_uuid"],
                    component_uuid=instance["component_uuid"],
                    vulnerability_uuid=instance["vulnerability_uuid"],
                    refresh=True,
                )
            except Exception as exc:
                results[index] = exc

    workers = [
        asyncio.create_task(worker())
        for _ in range(
            min(get_assessment_io_concurrency(deps), len(req.instances))
        )
    ]
    await asyncio.gather(*workers)
    return results


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
            if role.upper() == "ANALYST":
                final_details_str, aggregated_state = (
                    deps.build_authorized_analyst_assessment_details(
                        requested_details=req.details,
                        current_details=existing_details,
                        team=req.team,
                        username=user,
                    )
                )
            else:
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
    *,
    max_attempts: int,
    retry_base_delay_seconds: float,
) -> Dict[str, Any]:
    for attempt in range(1, max_attempts + 1):
        try:
            deps.logger.debug(
                "Updating instance: %s (Vulnerability: %s; attempt %d/%d)",
                instance.get("finding_uuid"),
                instance.get("vulnerability_uuid"),
                attempt,
                max_attempts,
            )
            await client.update_analysis(**payload)
            result = {
                "status": "success",
                "uuid": instance.get("finding_uuid"),
                "new_state": payload["state"],
                "new_details": payload["details"],
            }
            if attempt > 1:
                result["attempts"] = attempt
            return result
        except Exception as exc:
            if attempt >= max_attempts or not _retryable_assessment_write_error(exc):
                return {
                    "status": "error",
                    "uuid": instance.get("finding_uuid"),
                    "error": str(exc),
                    "attempts": attempt,
                    "payload": payload,
                }

            retry_after = _retry_after_seconds(exc)
            delay = (
                retry_after
                if retry_after is not None
                else min(
                    retry_base_delay_seconds * (2 ** (attempt - 1)),
                    MAX_ASSESSMENT_WRITE_RETRY_DELAY_SECONDS,
                )
            )
            deps.logger.warning(
                "Transient Dependency-Track assessment write failure for %s "
                "(attempt %d/%d); retrying in %.2fs: %s",
                instance.get("finding_uuid"),
                attempt,
                max_attempts,
                delay,
                exc,
            )
            if delay > 0:
                await asyncio.sleep(delay)

    raise AssertionError("assessment write retry loop exited unexpectedly")


async def apply_assessment_payloads(
    deps: AssessmentServiceDeps,
    client: DTClient,
    payloads: List[tuple[dict, dict]],
    *,
    concurrency: int | None = None,
    max_attempts: int | None = None,
    retry_base_delay_seconds: float = DEFAULT_ASSESSMENT_WRITE_RETRY_BASE_SECONDS,
    progress_callback: AssessmentWriteProgress | None = None,
) -> List[Dict[str, Any]]:
    if not payloads:
        return []

    resolved_concurrency = max(
        1,
        concurrency or get_assessment_io_concurrency(deps),
    )
    resolved_attempts = max(
        1,
        max_attempts or get_assessment_write_max_attempts(deps),
    )
    results: list[Dict[str, Any] | None] = [None] * len(payloads)
    next_index = 0
    completed = 0
    progress_lock = asyncio.Lock()

    async def worker() -> None:
        nonlocal completed, next_index
        while next_index < len(payloads):
            index = next_index
            next_index += 1
            instance, payload = payloads[index]
            result = await _try_update_assessment_payload(
                deps,
                client,
                instance,
                payload,
                max_attempts=resolved_attempts,
                retry_base_delay_seconds=max(0.0, retry_base_delay_seconds),
            )
            results[index] = result
            if progress_callback is None:
                continue
            async with progress_lock:
                completed += 1
                try:
                    callback_result = progress_callback(
                        completed,
                        len(payloads),
                        result,
                    )
                    if inspect.isawaitable(callback_result):
                        await callback_result
                except Exception:
                    deps.logger.exception(
                        "Assessment write progress callback failed"
                    )

    workers = [
        asyncio.create_task(worker())
        for _ in range(min(resolved_concurrency, len(payloads)))
    ]
    await asyncio.gather(*workers)
    return [result for result in results if result is not None]


async def finalize_assessment_results(
    deps: AssessmentServiceDeps,
    api_results: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    failed_results: list[tuple[Dict[str, Any], dict[str, Any]]] = []
    for result in api_results:
        if result["status"] == "error":
            payload = result.pop("payload")
            failed_results.append((result, payload))
        results.append(result)

    if not failed_results:
        return results

    bulk_queue = getattr(deps.cache_manager, "queue_analysis_updates", None)
    if callable(bulk_queue):
        try:
            await bulk_queue(
                [payload for _result, payload in failed_results],
                replace=True,
            )
            for result, _payload in failed_results:
                result["queued"] = True
            return results
        except Exception:
            deps.logger.exception(
                "Failed to queue assessment updates as one batch; "
                "falling back to individual queue writes"
            )

    for result, payload in failed_results:
        try:
            await deps.cache_manager.queue_analysis_update(payload, replace=True)
            result["queued"] = True
        except Exception as queue_error:
            result["queued"] = False
            result["error"] += f" (queue failed: {queue_error})"
    return results
