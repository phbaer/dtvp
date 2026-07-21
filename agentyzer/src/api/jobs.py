"""Job management — in-memory job record and progress tracking helpers."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional

from src.api.models import (
    ActiveAgentStatus,
    AssessRequest,
    AssessResponse,
    BackendInformation,
    JobProgress,
    JobStatus,
    JobStatusResponse,
    ServiceConfiguration,
)
from src.pipeline.graph import PIPELINE_STEP_ORDER


class Job:
    """In-memory record for a background assessment job."""

    __slots__ = (
        "id",
        "owner",
        "status",
        "created_at",
        "finished_at",
        "request",
        "result",
        "error",
        "completed_steps",
        "total_steps",
        "progress_percent",
        "current_step",
        "current_title",
        "current_agent",
        "current_activity",
        "last_completed_step",
        "last_updated_at",
        "active_agents",
        "step_statuses",
        "completed_step_names",
        "logs",
        "llm_metadata",
        "parent_job_id",
        "follow_up_question",
        "compact_context",
    )

    def __init__(
        self,
        job_id: str,
        request: AssessRequest,
        *,
        owner: str = "service",
    ) -> None:
        self.id = job_id
        self.owner = owner
        self.status = JobStatus.pending
        self.created_at = datetime.now(timezone.utc).isoformat()
        self.finished_at: Optional[str] = None
        self.request = request
        self.result: Optional[AssessResponse] = None
        self.error: Optional[str] = None
        self.completed_steps = 0
        self.total_steps = len(PIPELINE_STEP_ORDER)
        self.progress_percent = 0
        self.current_step: Optional[str] = None
        self.current_title: Optional[str] = None
        self.current_agent: Optional[str] = None
        self.current_activity: Optional[str] = None
        self.last_completed_step: Optional[str] = None
        self.last_updated_at: Optional[str] = None
        self.active_agents: Dict[str, Dict[str, str]] = {}
        self.step_statuses: Dict[str, str] = {}
        self.completed_step_names: set[str] = set()
        self.logs: list[dict[str, Any] | str] = []
        self.llm_metadata: dict[str, Any] = {}
        self.parent_job_id: Optional[str] = None
        self.follow_up_question: Optional[str] = None
        self.compact_context: Optional[Dict[str, Any]] = None


# ===================================================================== #
# Progress helpers                                                       #
# ===================================================================== #


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _recompute_job_progress(job: Job) -> None:
    job.completed_steps = len(job.completed_step_names)
    if job.status == JobStatus.completed:
        job.progress_percent = 100
        return
    total = max(job.total_steps, 1)
    job.progress_percent = min(99, int((job.completed_steps / total) * 100))


def _set_current_agent_from_active(job: Job) -> None:
    if not job.active_agents:
        return
    current = next(reversed(job.active_agents.values()))
    job.current_step = current["step"]
    job.current_title = current["title"]
    job.current_agent = current["agent"]
    job.current_activity = current["activity"]


def _progress_event_fields(event: Dict[str, Any]) -> tuple[str, str, str, str, str]:
    phase = str(event.get("phase") or "")
    step = str(event.get("step") or "")
    title = str(event.get("title") or step)
    agent = str(event.get("agent") or step)
    activity = str(event.get("activity") or title)
    return phase, step, title, agent, activity


def append_job_log(job: Job, message: str, *, level: str = "info") -> None:
    """Append a recent live log entry to the job status snapshot."""
    job.logs.append({"timestamp": _now_iso(), "level": level, "message": message})
    del job.logs[:-200]


def _handle_progress_start(
    job: Job,
    *,
    step: str,
    title: str,
    agent: str,
    activity: str,
) -> None:
    job.active_agents[step] = {
        "step": step,
        "title": title,
        "agent": agent,
        "activity": activity,
        "status": "running",
    }
    job.step_statuses[step] = "running"
    job.current_step = step
    job.current_title = title
    job.current_agent = agent
    job.current_activity = activity
    append_job_log(job, f"{agent}: {activity}")
    _recompute_job_progress(job)


def _handle_progress_completed(
    job: Job,
    event: Dict[str, Any],
    *,
    step: str,
    title: str,
    agent: str,
) -> None:
    report = event.get("report") or {}
    report_status = str(event.get("status") or report.get("status") or "completed")
    findings = report.get("findings") or {}
    if step == "filter_advisory" and (
        report_status == "filtered" or findings.get("relevant") is False
    ):
        job.total_steps = 4
    job.active_agents.pop(step, None)
    job.step_statuses[step] = "completed"
    job.completed_step_names.add(step)
    job.last_completed_step = step
    if job.active_agents:
        _set_current_agent_from_active(job)
    else:
        job.current_step = step
        job.current_title = title
        job.current_agent = agent
        job.current_activity = f"Completed {title.lower()}"
    append_job_log(job, f"Completed {title}")
    _recompute_job_progress(job)


def _handle_progress_failed(
    job: Job,
    *,
    step: str,
    title: str,
    agent: str,
    activity: str,
) -> None:
    job.active_agents.pop(step, None)
    job.step_statuses[step] = "failed"
    job.current_step = step
    job.current_title = title
    job.current_agent = agent
    job.current_activity = activity
    append_job_log(job, f"{agent}: {activity}", level="error")
    _recompute_job_progress(job)


def _handle_progress_heartbeat(
    job: Job,
    *,
    step: str,
    title: str,
    agent: str,
    activity: str,
) -> None:
    job.active_agents[step] = {
        "step": step,
        "title": title,
        "agent": agent,
        "activity": activity,
        "status": "running",
    }
    job.step_statuses[step] = "running"
    job.current_step = step
    job.current_title = title
    job.current_agent = agent
    job.current_activity = activity
    append_job_log(job, f"{agent}: {activity}")
    _recompute_job_progress(job)


def apply_progress_event(job: Job, event: Dict[str, Any]) -> None:
    """Dispatch a pipeline progress event to the appropriate handler."""
    phase, step, title, agent, activity = _progress_event_fields(event)
    if not step:
        return

    job.last_updated_at = _now_iso()

    if phase == "start":
        _handle_progress_start(
            job,
            step=step,
            title=title,
            agent=agent,
            activity=activity,
        )
        return

    if phase == "completed":
        _handle_progress_completed(
            job,
            event,
            step=step,
            title=title,
            agent=agent,
        )
        return

    if phase == "failed":
        _handle_progress_failed(
            job,
            step=step,
            title=title,
            agent=agent,
            activity=activity,
        )
        return

    if phase in {"heartbeat", "progress"}:
        _handle_progress_heartbeat(
            job,
            step=step,
            title=title,
            agent=agent,
            activity=activity,
        )


def job_progress_snapshot(job: Job) -> JobProgress:
    """Build a serialisable progress snapshot for a job."""
    active_agents = [
        ActiveAgentStatus(**agent_state) for agent_state in job.active_agents.values()
    ]
    return JobProgress(
        completed_steps=job.completed_steps,
        total_steps=job.total_steps,
        percent=job.progress_percent,
        current_step=job.current_step,
        current_title=job.current_title,
        current_agent=job.current_agent,
        current_activity=job.current_activity,
        last_completed_step=job.last_completed_step,
        last_updated_at=job.last_updated_at,
        active_agents=active_agents,
        step_statuses=dict(job.step_statuses),
        logs=job.logs[-50:],
    )


def job_status_response(
    job: Job,
    *,
    configuration: ServiceConfiguration | None = None,
    backend: BackendInformation | None = None,
) -> JobStatusResponse:
    """Build the serialisable status response for a job."""
    return JobStatusResponse(
        job_id=job.id,
        status=job.status,
        created_at=job.created_at,
        finished_at=job.finished_at,
        error=job.error,
        progress=job_progress_snapshot(job),
        request=job.request.model_dump(exclude_none=True),
        model=job.llm_metadata.get("model"),
        llm_backend=job.llm_metadata.get("host") or job.llm_metadata.get("backend"),
        llm_provider=job.llm_metadata.get("provider"),
        llm=job.llm_metadata or None,
        logs=job.logs[-200:],
        configuration=configuration,
        backend=backend,
    )
