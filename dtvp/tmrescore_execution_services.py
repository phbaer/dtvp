import json
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Optional

import httpx

from .tmrescore_task_services import (
    calculate_tmrescore_progress,
    is_tmrescore_terminal_status,
)


@dataclass(frozen=True)
class TMRescoreExecutionServiceDeps:
    logger: Any
    get_tmrescore_client_cls: Callable[[], type]
    describe_tmrescore_progress: Callable[[str, int], str]
    touch_tmrescore_analysis_task: Callable[..., None]
    append_tmrescore_analysis_log: Callable[[dict[str, Any], str], None]
    cache_tmrescore_project_results: Callable[..., None]
    build_tmrescore_analysis_response: Callable[
        [dict[str, Any], dict[str, Any]], dict[str, Any]
    ]
    sleep: Callable[[float], Awaitable[Any]]
    loop_time: Callable[[], float]


@dataclass(frozen=True)
class TMRescoreInventoryRequest:
    session_id: str
    threatmodel_bytes: bytes
    synthetic_sbom: dict[str, Any]
    items_csv_bytes: Optional[bytes]
    config_bytes: Optional[bytes]
    chain_analysis: bool
    prioritize: bool
    what_if: bool
    enrich: bool
    mitre_enrichment: bool
    offline: bool
    max_wait_seconds: float


@dataclass(frozen=True)
class TMRescoreExecutionRequest:
    project_name: str
    threatmodel_bytes: bytes
    synthetic_sbom: dict[str, Any]
    dtvp_original_proposals: dict[str, dict[str, Any]]
    items_csv_bytes: Optional[bytes]
    config_bytes: Optional[bytes]
    chain_analysis: bool
    prioritize: bool
    what_if: bool
    enrich: bool
    mitre_enrichment: bool
    offline: bool


async def wait_for_tmrescore_completion(
    deps: TMRescoreExecutionServiceDeps,
    task: dict[str, Any],
    tmrescore_client: Any,
    max_wait_seconds: float,
) -> None:
    session_id = task["session_id"]
    deadline = deps.loop_time() + max_wait_seconds

    while True:
        progress_payload = await tmrescore_client.get_progress(session_id)
        status = str(progress_payload.get("status") or task.get("status") or "running")
        progress = calculate_tmrescore_progress(
            progress_payload,
            int(task.get("progress") or 0),
        )
        message = progress_payload.get("message") or deps.describe_tmrescore_progress(
            status, progress
        )
        normalized_status = status.lower()

        task["status"] = status
        task["progress"] = max(int(task.get("progress") or 0), min(progress, 100))
        task["step"] = progress_payload.get("step")
        task["total_steps"] = progress_payload.get("total_steps")
        task["message"] = message
        deps.touch_tmrescore_analysis_task(
            task,
            mark_terminal=is_tmrescore_terminal_status(normalized_status),
        )
        deps.append_tmrescore_analysis_log(task, message)

        if normalized_status in {"completed", "skeptic_gate_failed"}:
            return
        if normalized_status == "failed":
            failure_result: dict[str, Any] = {}
            try:
                failure_result = await tmrescore_client.get_results(session_id)
            except (httpx.HTTPError, RuntimeError):
                pass
            raise RuntimeError(
                failure_result.get("error")
                or progress_payload.get("error")
                or progress_payload.get("detail")
                or message
            )
        if deps.loop_time() >= deadline:
            raise TimeoutError(
                f"Timed out while waiting for tmrescore analysis session {session_id} to complete"
            )
        await deps.sleep(1.5)


async def submit_tmrescore_inventory(
    deps: TMRescoreExecutionServiceDeps,
    task: dict[str, Any],
    tmrescore_client: Any,
    request: TMRescoreInventoryRequest,
) -> Optional[dict[str, Any]]:
    try:
        return await tmrescore_client.analyze_inventory(
            request.session_id,
            threatmodel_bytes=request.threatmodel_bytes,
            sbom_bytes=json.dumps(request.synthetic_sbom).encode("utf-8"),
            items_csv_bytes=request.items_csv_bytes,
            config_bytes=request.config_bytes,
            chain_analysis=request.chain_analysis,
            prioritize=request.prioritize,
            what_if=request.what_if,
            enrich=request.enrich,
            mitre_enrichment=request.mitre_enrichment,
            offline=request.offline,
            background=True,
        )
    except httpx.ReadTimeout, httpx.TimeoutException:
        task["message"] = "TMRescore is still processing remotely. Polling progress..."
        deps.append_tmrescore_analysis_log(task, task["message"])
        await wait_for_tmrescore_completion(
            deps,
            task,
            tmrescore_client,
            request.max_wait_seconds,
        )
        return None
    except httpx.HTTPStatusError as exc:
        if exc.response is None or exc.response.status_code not in {502, 503, 504}:
            raise
        task["message"] = (
            f"TMRescore returned HTTP {exc.response.status_code} while still running. Polling progress..."
        )
        deps.append_tmrescore_analysis_log(task, task["message"])
        await wait_for_tmrescore_completion(
            deps,
            task,
            tmrescore_client,
            request.max_wait_seconds,
        )
        return None


async def resolve_tmrescore_service_result(
    deps: TMRescoreExecutionServiceDeps,
    task: dict[str, Any],
    tmrescore_client: Any,
    service_result: Optional[dict[str, Any]],
    max_wait_seconds: float,
) -> dict[str, Any]:
    fetch_terminal_result = service_result is None
    if service_result is not None:
        returned_status = str(service_result.get("status") or "completed")
        normalized_status = returned_status.lower()
        if normalized_status == "failed":
            raise RuntimeError(
                service_result.get("error") or "TMRescore analysis failed"
            )
        if not is_tmrescore_terminal_status(normalized_status):
            task["status"] = returned_status
            task["progress"] = max(
                int(task.get("progress") or 0),
                int(service_result.get("progress") or 70),
            )
            task["message"] = service_result.get(
                "message"
            ) or deps.describe_tmrescore_progress(
                returned_status,
                task["progress"],
            )
            deps.touch_tmrescore_analysis_task(task)
            deps.append_tmrescore_analysis_log(task, task["message"])
            await wait_for_tmrescore_completion(
                deps,
                task,
                tmrescore_client,
                max_wait_seconds,
            )
            fetch_terminal_result = True

    if fetch_terminal_result:
        return await tmrescore_client.get_results(task["session_id"])
    return service_result


async def run_tmrescore_analysis_task(
    deps: TMRescoreExecutionServiceDeps,
    task: dict[str, Any],
    settings: Any,
    request: TMRescoreExecutionRequest,
) -> None:
    session_id = task["session_id"]
    max_wait_seconds = max(settings.DTVP_TMRESCORE_TIMEOUT_SECONDS * 4, 900.0)

    try:
        client_cls = deps.get_tmrescore_client_cls()
        async with client_cls(settings) as tmrescore_client:
            task["status"] = "running"
            task["progress"] = max(int(task.get("progress") or 0), 25)
            task["message"] = "Uploading analysis inputs to tmrescore..."
            deps.touch_tmrescore_analysis_task(task)
            deps.append_tmrescore_analysis_log(task, task["message"])
            service_result = await submit_tmrescore_inventory(
                deps,
                task,
                tmrescore_client,
                TMRescoreInventoryRequest(
                    session_id=session_id,
                    threatmodel_bytes=request.threatmodel_bytes,
                    synthetic_sbom=request.synthetic_sbom,
                    items_csv_bytes=request.items_csv_bytes,
                    config_bytes=request.config_bytes,
                    chain_analysis=request.chain_analysis,
                    prioritize=request.prioritize,
                    what_if=request.what_if,
                    enrich=request.enrich,
                    mitre_enrichment=request.mitre_enrichment,
                    offline=request.offline,
                    max_wait_seconds=max_wait_seconds,
                ),
            )
            final_service_result = await resolve_tmrescore_service_result(
                deps,
                task,
                tmrescore_client,
                service_result,
                max_wait_seconds,
            )
            vex_results = await tmrescore_client.get_results_vex(session_id)

            deps.cache_tmrescore_project_results(
                request.project_name,
                session_id,
                task["scope"],
                task["latest_version"],
                task["analyzed_versions"],
                vex_results,
                request.dtvp_original_proposals,
            )

            final_result = deps.build_tmrescore_analysis_response(
                final_service_result, task
            )
            result_status = str(final_service_result.get("status") or "completed").lower()
            task["status"] = "completed"
            task["progress"] = 100
            task["message"] = (
                "TMRescore analysis completed with a review-skeptic gate failure."
                if result_status == "skeptic_gate_failed"
                else "TMRescore analysis completed."
            )
            task["result"] = final_result
            task["error"] = None
            deps.touch_tmrescore_analysis_task(task, mark_terminal=True)
            deps.append_tmrescore_analysis_log(task, task["message"])
    except Exception as exc:
        deps.logger.warning(
            "TMRescore analysis task for %s session %s failed: %s",
            request.project_name,
            session_id,
            exc,
        )
        task["status"] = "failed"
        task["error"] = str(exc)
        task["message"] = str(exc)
        task["progress"] = 100
        deps.touch_tmrescore_analysis_task(task, mark_terminal=True)
        deps.append_tmrescore_analysis_log(task, f"TMRescore analysis failed: {exc}")
