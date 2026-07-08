import asyncio
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
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


_MODEL_KEYS = ("model", "llm_model", "selected_model", "default_model")
_BACKEND_KEYS = ("llm_backend", "backend", "llm_base_url", "base_url")
_PROVIDER_KEYS = ("llm_provider", "provider")
_MODEL_SETTING_ATTRS = (
    "DTVP_CODE_ANALYSIS_MODEL",
    "DTVP_AGENYZER_MODEL",
    "model",
)
_BACKEND_SETTING_ATTRS = (
    "DTVP_CODE_ANALYSIS_LLM_BACKEND",
    "DTVP_AGENYZER_LLM_BACKEND",
    "llm_backend",
)
_PROVIDER_SETTING_ATTRS = (
    "DTVP_CODE_ANALYSIS_LLM_PROVIDER",
    "DTVP_AGENYZER_LLM_PROVIDER",
    "llm_provider",
)


def _string_value(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _find_first_metadata_value(value: Any, keys: tuple[str, ...]) -> Optional[str]:
    key_set = {key.lower() for key in keys}
    if isinstance(value, dict):
        for key, inner in value.items():
            if str(key).lower() in key_set:
                found = _string_value(inner)
                if found:
                    return found
        for inner in value.values():
            found = _find_first_metadata_value(inner, keys)
            if found:
                return found
    elif isinstance(value, list):
        for inner in value:
            found = _find_first_metadata_value(inner, keys)
            if found:
                return found
    return None


def _normalize_log_entry(entry: Any) -> Optional[str]:
    if entry is None:
        return None
    if isinstance(entry, str):
        return entry.strip() or None
    if isinstance(entry, dict):
        for key in ("message", "msg", "text", "event", "activity"):
            value = _string_value(entry.get(key))
            if value:
                timestamp = _string_value(
                    entry.get("timestamp")
                    or entry.get("time")
                    or entry.get("created_at")
                )
                level = _string_value(entry.get("level") or entry.get("status"))
                prefix = " ".join(part for part in (timestamp, level) if part)
                return f"{prefix} {value}".strip()
    return str(entry).strip() or None


def _append_item_log(item: Any, message: str) -> None:
    normalized = _normalize_log_entry(message)
    if not normalized:
        return
    existing_logs = list(getattr(item, "logs", None) or [])
    if normalized not in existing_logs:
        existing_logs.append(normalized)
    item.logs = existing_logs[-200:]


def _extract_status_logs(status: dict[str, Any]) -> list[str]:
    candidates: list[Any] = []
    for key in ("logs", "log", "events", "messages"):
        if key in status:
            candidates.append(status[key])
    progress = status.get("progress")
    if isinstance(progress, dict):
        for key in ("logs", "log", "events", "messages"):
            if key in progress:
                candidates.append(progress[key])
        activity = _string_value(progress.get("current_activity"))
        if activity:
            candidates.append(
                {
                    "timestamp": progress.get("last_updated_at"),
                    "message": activity,
                }
            )
        active_agents = progress.get("active_agents")
        if isinstance(active_agents, list):
            for agent in active_agents:
                if not isinstance(agent, dict):
                    continue
                agent_name = _string_value(agent.get("agent"))
                agent_activity = _string_value(agent.get("activity"))
                if agent_activity:
                    message = (
                        f"{agent_name}: {agent_activity}"
                        if agent_name
                        else agent_activity
                    )
                    candidates.append(
                        {
                            "timestamp": progress.get("last_updated_at"),
                            "status": agent.get("status"),
                            "message": message,
                        }
                    )

    result: list[str] = []
    for candidate in candidates:
        if isinstance(candidate, list):
            entries = candidate
        else:
            entries = [candidate]
        for entry in entries:
            normalized = _normalize_log_entry(entry)
            if normalized:
                result.append(normalized)
    return result


def _merge_item_status_metadata(item: Any, status: dict[str, Any]) -> None:
    model = _find_first_metadata_value(status, _MODEL_KEYS)
    backend = _find_first_metadata_value(status, _BACKEND_KEYS)
    provider = _find_first_metadata_value(status, _PROVIDER_KEYS)
    if model and not getattr(item, "model", None):
        item.model = model
    if backend and not getattr(item, "llm_backend", None):
        item.llm_backend = backend
    if provider and not getattr(item, "llm_provider", None):
        item.llm_provider = provider

    llm_metadata = status.get("llm") or status.get("llm_metadata")
    if isinstance(llm_metadata, dict):
        existing = getattr(item, "llm_metadata", None) or {}
        item.llm_metadata = {**existing, **llm_metadata}

    existing_logs = list(getattr(item, "logs", None) or [])
    for entry in _extract_status_logs(status):
        if entry not in existing_logs:
            existing_logs.append(entry)
    item.logs = existing_logs[-200:]


def _settings_value(settings: Any, attrs: tuple[str, ...]) -> Optional[str]:
    for attr in attrs:
        value = _string_value(getattr(settings, attr, None))
        if value:
            return value
    return None


def _seed_item_metadata_from_settings(item: Any, settings: Any) -> None:
    if not getattr(item, "model", None):
        item.model = _settings_value(settings, _MODEL_SETTING_ATTRS)
    if not getattr(item, "llm_backend", None):
        item.llm_backend = _settings_value(settings, _BACKEND_SETTING_ATTRS)
    if not getattr(item, "llm_provider", None):
        item.llm_provider = _settings_value(settings, _PROVIDER_SETTING_ATTRS)


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
    if not getattr(item, "started_at", None):
        item.started_at = datetime.now(UTC).isoformat()
    item.abort_requested = False
    item.abort_error = None
    reindex_queue_items(items, order)
    runtime_deps.logger.info(
        "Analysis queue: running %s (vuln=%s, component=%s)",
        item.queue_id,
        item.vuln_id,
        item.component_name,
    )
    _append_item_log(
        item,
        f"DTVP started scan for {item.component_name} ({item.vuln_id})",
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
    get_capacity: Callable[[], int],
) -> None:
    runtime_deps.logger.info("Analysis queue worker started")
    active_tasks: set[asyncio.Task[Any]] = set()

    async def process_started_item(item: Any) -> None:
        try:
            await process_item(item)
        except Exception as exc:
            runtime_deps.logger.exception(
                "Analysis queue item %s failed", item.queue_id
            )
            finish_item(item, status="failed", error=str(exc))

    try:
        while is_running():
            prune_finished()
            capacity = max(1, int(get_capacity() or 1))

            while len(active_tasks) < capacity:
                next_item = get_next_item()
                if not next_item:
                    break

                start_item(next_item)
                task = asyncio.create_task(process_started_item(next_item))
                active_tasks.add(task)
                task.add_done_callback(active_tasks.discard)

            if not active_tasks:
                await wait_for_work()
                continue

            if len(active_tasks) >= capacity:
                done, _pending = await asyncio.wait(
                    active_tasks,
                    return_when=asyncio.FIRST_COMPLETED,
                )
                active_tasks.difference_update(done)
                continue

            wait_task = asyncio.create_task(wait_for_work())
            done, _pending = await asyncio.wait(
                active_tasks | {wait_task},
                return_when=asyncio.FIRST_COMPLETED,
            )
            if wait_task not in done:
                wait_task.cancel()
                with suppress(asyncio.CancelledError):
                    await wait_task
            active_tasks.difference_update(done - {wait_task})
    finally:
        if active_tasks:
            done, pending = await asyncio.wait(active_tasks, timeout=0)
            active_tasks.difference_update(done)
            for task in pending:
                task.cancel()
            for task in pending:
                with suppress(asyncio.CancelledError):
                    await task


async def process_analysis_queue_item(
    deps: AnalysisQueueServiceDeps,
    item: Any,
    finish_item: Callable[..., None],
) -> None:
    settings_cls = deps.get_code_analysis_settings_cls()
    settings = settings_cls()
    if not settings.enabled:
        raise RuntimeError(deps.code_analysis_not_configured_detail)
    _seed_item_metadata_from_settings(item, settings)

    client_cls = deps.get_code_analysis_client_cls()
    async with client_cls(settings) as client:
        async def submit_to_analyzer() -> dict[str, Any]:
            parent_job_id = _string_value(getattr(item, "parent_job_id", None))
            follow_up_question = _string_value(
                getattr(item, "follow_up_question", None)
            )
            if parent_job_id and follow_up_question and hasattr(
                client, "start_follow_up"
            ):
                try:
                    _append_item_log(
                        item,
                        f"Submitting follow-up scan to analyzer job {parent_job_id}",
                    )
                    extra_guidance = _string_value(
                        getattr(item, "follow_up_user_guidance", None)
                    )
                    if extra_guidance:
                        _append_item_log(
                            item,
                            "Using analyzer-native parent context with reviewer guidance",
                        )
                    else:
                        _append_item_log(
                            item,
                            "Using analyzer-native parent context",
                        )
                    return await client.start_follow_up(
                        parent_job_id,
                        question=follow_up_question,
                        vuln_id=item.vuln_id,
                        component_name=item.component_name,
                        cvss_vector=item.cvss_vector,
                        user_guidance=extra_guidance,
                        model=getattr(item, "model", None),
                        llm_backend=getattr(item, "llm_backend", None),
                        llm_provider=getattr(item, "llm_provider", None),
                    )
                except Exception as exc:
                    _append_item_log(
                        item,
                        "Analyzer follow-up context unavailable; using compact "
                        f"DTVP guidance fallback: {exc}",
                    )

            _append_item_log(item, "Submitting scan to analyzer")
            return await client.start_assessment(
                vuln_id=item.vuln_id,
                component_name=item.component_name,
                cvss_vector=item.cvss_vector,
                user_guidance=item.user_guidance,
                affected_product_versions=getattr(
                    item,
                    "affected_product_versions",
                    [],
                ),
                model=getattr(item, "model", None),
                llm_backend=getattr(item, "llm_backend", None),
                llm_provider=getattr(item, "llm_provider", None),
            )

        async def abort_if_requested() -> bool:
            if getattr(item, "status", "") in {"completed", "failed", "cancelled"}:
                return True
            if getattr(item, "status", "") != "running":
                return False
            if not getattr(item, "abort_requested", False):
                return False
            if not getattr(item, "job_id", None):
                return False

            try:
                await client.delete_job(item.job_id)
            except Exception as exc:
                item.abort_requested = False
                item.abort_error = str(exc)
                _append_item_log(item, f"Abort refused: {exc}")
                return False

            _append_item_log(item, "Abort accepted by analyzer")
            finish_item(item, status="cancelled")
            return True

        job = await submit_to_analyzer()
        item.job_id = job.get("job_id")
        _merge_item_status_metadata(item, job)
        if not item.job_id:
            raise RuntimeError("Code analysis service did not return a job ID")
        _append_item_log(item, f"Analyzer job {item.job_id} accepted")
        if await abort_if_requested():
            return

        while True:
            await deps.sleep(2)
            if await abort_if_requested():
                return
            status = await client.get_job_status(item.job_id)
            _merge_item_status_metadata(item, status)
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
            if service_status == "cancelled":
                _append_item_log(item, "Analyzer reported scan cancelled")
                finish_item(
                    item,
                    status="cancelled",
                    error=status.get("error"),
                )
                return
