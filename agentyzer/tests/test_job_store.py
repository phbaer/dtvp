from datetime import UTC, datetime, timedelta

from src.api.jobs import Job
from src.api.models import (
    AnalysisJustification,
    AnalysisResponse,
    AnalysisState,
    Assessment,
    AssessRequest,
    AssessResponse,
    JobStatus,
)
from src.job_runtime import JobRuntime
from src.job_store import JobStore


NOW = datetime(2026, 7, 21, 10, 0, tzinfo=UTC)


def _job(job_id: str, *, owner: str = "alice") -> Job:
    job = Job(
        job_id,
        AssessRequest(
            vuln_id="CVE-2026-0001",
            component_name="example-component",
            user_guidance="Inspect the HTTP entry point.",
        ),
        owner=owner,
    )
    return job


def _completed_job(job_id: str, finished_at: datetime) -> Job:
    job = _job(job_id)
    job.status = JobStatus.completed
    job.created_at = (finished_at - timedelta(minutes=1)).isoformat()
    job.finished_at = finished_at.isoformat()
    job.result = AssessResponse(
        assessment=Assessment(
            affected=False,
            verdict="Not Affected",
            confidence="High",
            exposure="none",
            summary="No vulnerable path.",
            reasoning="The vulnerable API is not reachable.",
            analysis=AnalysisState.NOT_AFFECTED,
            justification=AnalysisJustification.CODE_NOT_REACHABLE,
            response=AnalysisResponse.NOT_SET,
            details="Static analysis found no call path.",
        ),
        steps=[],
    )
    return job


def test_job_store_round_trips_owner_result_and_progress(tmp_path):
    path = tmp_path / "jobs.sqlite"
    store = JobStore(
        path_provider=lambda: str(path),
        now_provider=lambda: NOW,
    )
    job = _completed_job("job-1", NOW)
    job.completed_step_names = {"clone_repo", "scan_code"}
    job.completed_steps = 2
    job.progress_percent = 100
    job.logs = [{"level": "info", "message": "complete"}]
    job.llm_metadata = {"provider": "ollama", "model": "mistral"}

    assert store.save(job) == set()

    restored = store.load()[job.id]
    assert restored.owner == "alice"
    assert restored.status == JobStatus.completed
    assert restored.request.user_guidance == "Inspect the HTTP entry point."
    assert restored.result is not None
    assert restored.result.assessment.verdict == "Not Affected"
    assert restored.completed_step_names == {"clone_repo", "scan_code"}
    assert restored.llm_metadata["model"] == "mistral"
    assert path.stat().st_mode & 0o777 == 0o600


def test_job_store_prunes_expired_terminal_jobs_but_keeps_pending(tmp_path):
    store = JobStore(
        path_provider=lambda: str(tmp_path / "jobs.sqlite"),
        retention_seconds_provider=lambda: 60,
        max_records_provider=lambda: 100,
        now_provider=lambda: NOW,
    )
    expired = _completed_job("expired", NOW - timedelta(minutes=2))
    pending = _job("pending")
    pending.created_at = (NOW - timedelta(days=1)).isoformat()

    removed = store.save(expired)
    store.save(pending)

    assert removed == {expired.id}
    assert set(store.load()) == {pending.id}


def test_job_store_enforces_record_bound_using_oldest_terminal_jobs(tmp_path):
    store = JobStore(
        path_provider=lambda: str(tmp_path / "jobs.sqlite"),
        retention_seconds_provider=lambda: 0,
        max_records_provider=lambda: 2,
        now_provider=lambda: NOW,
    )
    pending = _job("pending")
    oldest = _completed_job("oldest", NOW - timedelta(minutes=2))
    newest = _completed_job("newest", NOW)

    store.save(pending)
    store.save(oldest)
    removed = store.save(newest)

    assert removed == {oldest.id}
    assert set(store.load()) == {pending.id, newest.id}


def test_job_store_delete_removes_persisted_job(tmp_path):
    store = JobStore(path_provider=lambda: str(tmp_path / "jobs.sqlite"))
    job = _job("delete-me")
    store.save(job)

    store.delete(job.id)

    assert store.load() == {}


def test_job_runtime_restores_pending_and_terminalizes_running(tmp_path):
    store = JobStore(
        path_provider=lambda: str(tmp_path / "jobs.sqlite"),
        retention_seconds_provider=lambda: 0,
    )
    pending = _job("pending")
    running = _job("running")
    running.status = JobStatus.running
    running.current_activity = "Scanning source"
    store.save(pending)
    store.save(running)

    runtime = JobRuntime(store=store, max_concurrent_jobs=2)
    recovery = runtime.restore()

    assert recovery.pending_jobs == (runtime.jobs[pending.id],)
    assert recovery.interrupted_count == 1
    assert runtime.jobs[running.id].status == JobStatus.failed
    assert "service restart" in (runtime.jobs[running.id].error or "")
    assert runtime.jobs[running.id].active_agents == {}
    assert store.load()[running.id].status == JobStatus.failed
