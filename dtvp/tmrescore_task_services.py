from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Optional


@dataclass(frozen=True)
class TMRescoreTaskServiceDeps:
    tmrescore_analysis_tasks: dict[str, dict[str, Any]]
    get_tmrescore_task_ttl_seconds: Callable[[], int]
    context_path: str


def touch_tmrescore_analysis_task(
    task: dict[str, Any],
    *,
    mark_terminal: bool = False,
) -> None:
    now = datetime.now().timestamp()
    task["updated_at"] = now
    if mark_terminal:
        task["completed_at"] = now


def prune_tmrescore_analysis_tasks(
    deps: TMRescoreTaskServiceDeps,
    now: Optional[float] = None,
) -> None:
    current_time = now if now is not None else datetime.now().timestamp()
    ttl_seconds = deps.get_tmrescore_task_ttl_seconds()

    expired_session_ids = []
    for session_id, task in deps.tmrescore_analysis_tasks.items():
        status = str(task.get("status") or "").lower()
        if status not in {"completed", "failed"}:
            continue
        completed_at = (
            task.get("completed_at") or task.get("updated_at") or task.get("created_at")
        )
        if completed_at is None:
            continue
        if current_time - float(completed_at) >= ttl_seconds:
            expired_session_ids.append(session_id)

    for session_id in expired_session_ids:
        deps.tmrescore_analysis_tasks.pop(session_id, None)


def append_tmrescore_analysis_log(task: dict[str, Any], message: str) -> None:
    if not message:
        return
    log_entries = task.setdefault("log", [])
    if not log_entries or log_entries[-1] != message:
        log_entries.append(message)
    touch_tmrescore_analysis_task(task)


def build_tmrescore_analysis_response(
    deps: TMRescoreTaskServiceDeps,
    result: dict[str, Any],
    task: dict[str, Any],
) -> dict[str, Any]:
    session = task["session"]
    session_id = result.get("session_id") or session.get("session_id")
    return {
        **result,
        "session": session,
        "scope": task["scope"],
        "recommended_scope": "merged_versions",
        "latest_version": task["latest_version"],
        "analyzed_versions": task["analyzed_versions"],
        "sbom_component_count": task["sbom_component_count"],
        "sbom_vulnerability_count": task["sbom_vulnerability_count"],
        "strategy_note": task["strategy_note"],
        "llm_enrichment": task["llm_enrichment"],
        "download_urls": {
            "json": f"{deps.context_path}/api/tmrescore/sessions/{session_id}/results/json",
            "vex": f"{deps.context_path}/api/tmrescore/sessions/{session_id}/results/vex",
        },
    }


def describe_tmrescore_progress(status: str, progress: int) -> str:
    normalized_status = (status or "running").lower()
    if normalized_status == "completed":
        return "VScorer analysis completed."
    if normalized_status == "failed":
        return "VScorer analysis failed."
    if progress >= 95:
        return "Finalizing VScorer outputs..."
    if progress >= 75:
        return "Rescoring vulnerabilities against the threat model..."
    if progress >= 45:
        return "Correlating threat model data with the synthetic SBOM..."
    if progress >= 20:
        return "Uploading analysis inputs to VScorer..."
    return "Preparing VScorer analysis session..."


def build_tmrescore_cached_state(
    task: dict[str, Any],
    *,
    include_result: bool = False,
) -> dict[str, Any]:
    status = str(task.get("status") or "running")
    return {
        "session_id": task["session_id"],
        "status": status,
        "progress": int(task.get("progress") or 0),
        "message": task.get("message")
        or describe_tmrescore_progress(status, int(task.get("progress") or 0)),
        "log": task.get("log") or [],
        "error": task.get("error"),
        "scope": task.get("scope"),
        "latest_version": task.get("latest_version"),
        "analyzed_versions": task.get("analyzed_versions") or [],
        "llm_enrichment": task.get("llm_enrichment")
        or {"enabled": False, "ollama_model": None},
        "created_at": task.get("created_at"),
        "updated_at": task.get("updated_at"),
        "completed_at": task.get("completed_at"),
        "result": task.get("result") if include_result else None,
        "wizard_context": task.get("wizard_context"),
        "wizard_catalogs": task.get("wizard_catalogs"),
        "wizard_url": task.get("wizard_url"),
    }


def get_latest_tmrescore_project_task(
    deps: TMRescoreTaskServiceDeps,
    project_name: str,
) -> Optional[dict[str, Any]]:
    matching_tasks = [
        task
        for task in deps.tmrescore_analysis_tasks.values()
        if task.get("project_name") == project_name
    ]
    if not matching_tasks:
        return None
    return max(
        matching_tasks,
        key=lambda task: float(task.get("updated_at") or task.get("created_at") or 0.0),
    )
