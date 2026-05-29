from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Optional


@dataclass(frozen=True)
class AnalysisQueueServiceDeps:
    get_code_analysis_settings_cls: Callable[[], type]
    get_code_analysis_client_cls: Callable[[], type]
    code_analysis_not_configured_detail: str
    sleep: Callable[[float], Awaitable[Any]]


@dataclass(frozen=True)
class AnalysisQueueRuntimeDeps:
    logger: Any
    sleep: Callable[[float], Awaitable[Any]]


def reindex_queue_items(items: dict[str, Any], order: list[str]) -> None:
    pos = 1
    for queue_id in order:
        item = items.get(queue_id)
        if item and item.status == "queued":
            item.position = pos
            pos += 1
        elif item:
            item.position = 0


def prune_finished_queue_items(
    items: dict[str, Any],
    order: list[str],
    *,
    current_time: float,
    ttl_seconds: int,
    parse_timestamp: Callable[[Optional[str]], Optional[float]],
) -> int:
    expired_queue_ids: list[str] = []

    for queue_id, item in items.items():
        if item.status not in ("completed", "failed", "cancelled"):
            continue
        finished_at = parse_timestamp(item.finished_at) or parse_timestamp(
            item.submitted_at
        )
        if finished_at is None:
            continue
        if current_time - finished_at >= ttl_seconds:
            expired_queue_ids.append(queue_id)

    for queue_id in expired_queue_ids:
        items.pop(queue_id, None)

    if expired_queue_ids:
        expired_queue_ids_set = set(expired_queue_ids)
        order[:] = [
            queue_id for queue_id in order if queue_id not in expired_queue_ids_set
        ]
        reindex_queue_items(items, order)

    return len(expired_queue_ids)


def get_next_queued_item(items: dict[str, Any], order: list[str]) -> Optional[Any]:
    for queue_id in order:
        item = items.get(queue_id)
        if item and item.status == "queued":
            return item
    return None


def start_analysis_queue_item(
    runtime_deps: AnalysisQueueRuntimeDeps,
    items: dict[str, Any],
    order: list[str],
    item: Any,
) -> None:
    item.status = "running"
    item.position = 0
    reindex_queue_items(items, order)
    runtime_deps.logger.info(
        "Analysis queue: running %s (vuln=%s, component=%s)",
        item.queue_id,
        item.vuln_id,
        item.component_name,
    )


async def run_analysis_queue_cleanup_loop(
    runtime_deps: AnalysisQueueRuntimeDeps,
    is_running: Callable[[], bool],
    prune_finished: Callable[[], int],
) -> None:
    while is_running():
        await runtime_deps.sleep(60)
        prune_finished()


async def run_analysis_queue_worker(
    runtime_deps: AnalysisQueueRuntimeDeps,
    is_running: Callable[[], bool],
    prune_finished: Callable[[], int],
    get_next_item: Callable[[], Optional[Any]],
    wait_for_work: Callable[[], Awaitable[None]],
    start_item: Callable[[Any], None],
    process_item: Callable[[Any], Awaitable[None]],
    finish_item: Callable[..., None],
) -> None:
    runtime_deps.logger.info("Analysis queue worker started")
    while is_running():
        prune_finished()
        next_item = get_next_item()

        if not next_item:
            await wait_for_work()
            continue

        start_item(next_item)

        try:
            await process_item(next_item)
        except Exception as exc:
            runtime_deps.logger.exception(
                "Analysis queue item %s failed", next_item.queue_id
            )
            finish_item(next_item, status="failed", error=str(exc))


async def process_analysis_queue_item(
    deps: AnalysisQueueServiceDeps,
    item: Any,
    finish_item: Callable[..., None],
) -> None:
    settings_cls = deps.get_code_analysis_settings_cls()
    settings = settings_cls()
    if not settings.enabled:
        raise RuntimeError(deps.code_analysis_not_configured_detail)

    client_cls = deps.get_code_analysis_client_cls()
    async with client_cls(settings) as client:
        job = await client.start_assessment(
            vuln_id=item.vuln_id,
            component_name=item.component_name,
            cvss_vector=item.cvss_vector,
            user_guidance=item.user_guidance,
        )
        item.job_id = job.get("job_id")
        if not item.job_id:
            raise RuntimeError("Code analysis service did not return a job ID")

        while True:
            await deps.sleep(2)
            status = await client.get_job_status(item.job_id)
            service_status = status.get("status", "")
            if "progress" in status:
                item.progress = status["progress"]
            if service_status == "completed":
                result = await client.get_job_result(item.job_id)
                finish_item(item, status="completed", result=result)
                return
            if service_status == "failed":
                finish_item(
                    item,
                    status="failed",
                    error=status.get("error", "Analysis failed"),
                )
                return
