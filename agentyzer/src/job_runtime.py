"""Lifecycle coordinator for durable asynchronous assessment jobs."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, AsyncIterator, Awaitable, Callable

from src.api.jobs import Job, append_job_log
from src.api.models import JobStatus
from src.job_store import JobStore


class JobStoreUnavailable(RuntimeError):
    """Raised when a required durable job-store operation fails."""


class JobCapacityExceeded(RuntimeError):
    """Raised when accepting another async job would exceed configured limits."""


@dataclass(frozen=True)
class JobRecovery:
    interrupted_count: int
    pending_jobs: tuple[Job, ...]


@dataclass
class JobRuntime:
    store: JobStore
    max_concurrent_jobs: int
    max_queued_jobs: int = 100
    max_active_jobs_per_owner: int = 10
    logger: Any = None
    jobs: dict[str, Job] = field(default_factory=dict, init=False)
    tasks: dict[str, asyncio.Task[Any]] = field(default_factory=dict, init=False)
    inline_requests_by_owner: dict[str, int] = field(default_factory=dict, init=False)
    inline_request_count: int = field(default=0, init=False)
    shutting_down: bool = field(default=False, init=False)
    semaphore: asyncio.Semaphore = field(init=False)

    def __post_init__(self) -> None:
        self.max_concurrent_jobs = max(1, int(self.max_concurrent_jobs))
        self.max_queued_jobs = max(1, int(self.max_queued_jobs))
        self.max_active_jobs_per_owner = max(
            1,
            int(self.max_active_jobs_per_owner),
        )
        self.semaphore = asyncio.Semaphore(self.max_concurrent_jobs)

    def ensure_submission_capacity(self, owner: str) -> None:
        """Reject new work before it can create an unbounded task backlog."""
        pending = sum(
            job.status == JobStatus.pending for job in self.jobs.values()
        )
        if pending >= self.max_queued_jobs:
            raise JobCapacityExceeded(
                "The Agentyzer assessment queue is full; retry later."
            )

        owner_active = sum(
            job.owner == owner
            and job.status in (JobStatus.pending, JobStatus.running)
            for job in self.jobs.values()
        )
        owner_active += self.inline_requests_by_owner.get(owner, 0)
        if owner_active >= self.max_active_jobs_per_owner:
            raise JobCapacityExceeded(
                "This caller already has the maximum number of active assessment "
                "jobs; retry after one finishes."
            )

    def admit_inline_request(self, owner: str) -> None:
        """Reserve bounded admission before an HTTP request waits for execution."""

        if self.inline_request_count >= self.max_concurrent_jobs:
            raise JobCapacityExceeded(
                "The Agentyzer inline assessment capacity is full; retry later."
            )

        owner_active = sum(
            job.owner == owner
            and job.status in (JobStatus.pending, JobStatus.running)
            for job in self.jobs.values()
        )
        owner_active += self.inline_requests_by_owner.get(owner, 0)
        if owner_active >= self.max_active_jobs_per_owner:
            raise JobCapacityExceeded(
                "This caller already has the maximum number of active assessment "
                "requests; retry after one finishes."
            )

        self.inline_request_count += 1
        self.inline_requests_by_owner[owner] = (
            self.inline_requests_by_owner.get(owner, 0) + 1
        )

    def release_inline_request(self, owner: str) -> None:
        """Release a reservation created by :meth:`admit_inline_request`."""

        owner_count = self.inline_requests_by_owner.get(owner, 0)
        if owner_count <= 1:
            self.inline_requests_by_owner.pop(owner, None)
        else:
            self.inline_requests_by_owner[owner] = owner_count - 1
        if owner_count > 0:
            self.inline_request_count = max(0, self.inline_request_count - 1)

    @asynccontextmanager
    async def inline_execution_slot(self, owner: str) -> AsyncIterator[None]:
        """Admit one inline request, then share the bounded execution semaphore."""

        self.admit_inline_request(owner)
        try:
            async with self.semaphore:
                yield
        finally:
            self.release_inline_request(owner)

    def _remove_pruned(self, job_ids: set[str]) -> None:
        for job_id in job_ids:
            self.jobs.pop(job_id, None)

    def restore(self) -> JobRecovery:
        self.jobs.clear()
        self.jobs.update(self.store.load())
        interrupted_count = 0
        now = datetime.now(UTC).isoformat()
        for job in list(self.jobs.values()):
            if job.status != JobStatus.running:
                continue
            job.status = JobStatus.failed
            job.finished_at = now
            job.last_updated_at = now
            job.error = "Assessment interrupted by Agentyzer service restart."
            job.active_agents.clear()
            job.current_activity = "Assessment interrupted by service restart"
            append_job_log(job, job.error, level="error")
            self._remove_pruned(self.store.save(job))
            interrupted_count += 1
        pending_jobs = tuple(
            job for job in self.jobs.values() if job.status == JobStatus.pending
        )
        return JobRecovery(
            interrupted_count=interrupted_count,
            pending_jobs=pending_jobs,
        )

    def prune(self) -> None:
        try:
            self._remove_pruned(self.store.prune())
        except Exception:
            if self.logger:
                self.logger.exception("Failed to prune the Agentyzer job store")

    def visible_to(self, owner: str) -> dict[str, Job]:
        self.prune()
        if owner == "*":
            return self.jobs
        return {
            job_id: job for job_id, job in self.jobs.items() if job.owner == owner
        }

    def persist(self, job: Job, *, required: bool = False) -> None:
        try:
            self._remove_pruned(self.store.save(job))
        except Exception as exc:
            if self.logger:
                self.logger.exception("Failed to persist Agentyzer job %s", job.id)
            if required:
                raise JobStoreUnavailable from exc

    def delete(self, job_id: str) -> None:
        try:
            self.store.delete(job_id)
        except Exception as exc:
            if self.logger:
                self.logger.exception(
                    "Failed to delete persisted Agentyzer job %s",
                    job_id,
                )
            raise JobStoreUnavailable from exc
        self.jobs.pop(job_id, None)

    def schedule(
        self,
        job: Job,
        runner: Callable[[Job], Awaitable[None]],
    ) -> None:
        task = asyncio.create_task(runner(job))
        self.tasks[job.id] = task
        task.add_done_callback(lambda _task: self.tasks.pop(job.id, None))

    async def shutdown(self) -> None:
        self.shutting_down = True
        tasks = list(self.tasks.values())
        for task in tasks:
            if not task.done():
                task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
