import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Optional

from pydantic import BaseModel, Field


class AnalysisQueueItem(BaseModel):
    queue_id: str
    vuln_id: str
    component_name: str
    project_name: Optional[str] = None
    cvss_vector: Optional[str] = None
    user_guidance: Optional[str] = None
    affected_product_versions: list[str] = Field(default_factory=list)
    model: Optional[str] = None
    llm_backend: Optional[str] = None
    llm_provider: Optional[str] = None
    llm_metadata: Optional[dict[str, Any]] = None
    parent_run_id: Optional[str] = None
    parent_job_id: Optional[str] = None
    follow_up_question: Optional[str] = None
    follow_up_user_guidance: Optional[str] = None
    context_mode: Optional[str] = None
    context_fingerprint: Optional[str] = None
    context_summary: Optional[dict[str, Any]] = None
    source: str = "manual"
    submitted_by: str
    submitted_at: str
    started_at: Optional[str] = None
    status: str = "queued"
    position: int = 0
    job_id: Optional[str] = None
    error: Optional[str] = None
    result: Optional[dict] = None
    finished_at: Optional[str] = None
    progress: Optional[dict] = None
    logs: list[str] = Field(default_factory=list)
    abort_requested: bool = False
    abort_error: Optional[str] = None


@dataclass(frozen=True)
class AnalysisQueueDeps:
    runtime_deps: Any
    service_deps: Any
    get_analysis_queue_ttl_seconds: Callable[[], int]
    get_analysis_queue_capacity: Callable[[], int]
    parse_iso_timestamp: Callable[[Optional[str]], Optional[float]]
    utc_now: Callable[[], datetime]
    reindex_queue_items: Callable[[dict[str, AnalysisQueueItem], list[str]], None]
    prune_finished_queue_items: Callable[..., int]
    get_next_queued_item: Callable[
        [dict[str, AnalysisQueueItem], list[str]], Optional[AnalysisQueueItem]
    ]
    start_analysis_queue_item: Callable[..., None]
    process_analysis_queue_item: Callable[..., Any]
    run_analysis_queue_cleanup_loop: Callable[..., Any]
    run_analysis_queue_worker: Callable[..., Any]
    create_event: Callable[[], Any]
    create_lock: Callable[[], Any]
    record_completed_result: Callable[[AnalysisQueueItem], None] = lambda _item: None


class AnalysisQueue:
    def __init__(self, deps: AnalysisQueueDeps):
        self._deps = deps
        self._items: dict[str, AnalysisQueueItem] = {}
        self._order: list[str] = []
        self._event = deps.create_event()
        self._running = True
        self._lock = deps.create_lock()

    def reset_runtime_state(self):
        self._event = self._deps.create_event()
        self._lock = self._deps.create_lock()
        self._running = True

    def _reindex(self):
        self._deps.reindex_queue_items(self._items, self._order)

    def prune_finished(self, now: Optional[float] = None) -> int:
        current_time = now if now is not None else self._deps.utc_now().timestamp()
        return self._deps.prune_finished_queue_items(
            self._items,
            self._order,
            current_time=current_time,
            ttl_seconds=self._deps.get_analysis_queue_ttl_seconds(),
            parse_timestamp=self._deps.parse_iso_timestamp,
        )

    def capacity(self) -> int:
        try:
            return max(1, int(self._deps.get_analysis_queue_capacity()))
        except (TypeError, ValueError):
            return 1

    def submit(
        self,
        vuln_id: str,
        component_name: str,
        submitted_by: str,
        project_name: Optional[str] = None,
        cvss_vector: Optional[str] = None,
        user_guidance: Optional[str] = None,
        affected_product_versions: Optional[list[str]] = None,
        model: Optional[str] = None,
        llm_backend: Optional[str] = None,
        llm_provider: Optional[str] = None,
        parent_run_id: Optional[str] = None,
        parent_job_id: Optional[str] = None,
        follow_up_question: Optional[str] = None,
        follow_up_user_guidance: Optional[str] = None,
        context_mode: Optional[str] = None,
        context_fingerprint: Optional[str] = None,
        context_summary: Optional[dict[str, Any]] = None,
        source: str = "manual",
    ) -> AnalysisQueueItem:
        self.prune_finished()
        queue_id = str(uuid.uuid4())
        item = AnalysisQueueItem(
            queue_id=queue_id,
            vuln_id=vuln_id,
            component_name=component_name,
            project_name=project_name,
            cvss_vector=cvss_vector,
            user_guidance=user_guidance,
            affected_product_versions=[
                str(version).strip()
                for version in (affected_product_versions or [])
                if str(version).strip()
            ],
            model=model,
            llm_backend=llm_backend,
            llm_provider=llm_provider,
            parent_run_id=parent_run_id,
            parent_job_id=parent_job_id,
            follow_up_question=follow_up_question,
            follow_up_user_guidance=follow_up_user_guidance,
            context_mode=context_mode,
            context_fingerprint=context_fingerprint,
            context_summary=context_summary,
            source=source,
            submitted_by=submitted_by,
            submitted_at=self._deps.utc_now().isoformat(),
        )
        self._items[queue_id] = item
        self._order.append(queue_id)
        self._reindex()
        self._event.set()
        return item

    def find_existing(
        self,
        vuln_id: str,
        component_name: str,
        *,
        statuses: tuple[str, ...] = ("queued", "running", "completed", "failed"),
    ) -> Optional[AnalysisQueueItem]:
        self.prune_finished()
        normalized_vuln = vuln_id.strip().lower()
        normalized_component = component_name.strip().lower()
        for item in self._items.values():
            if item.status not in statuses:
                continue
            if item.vuln_id.strip().lower() != normalized_vuln:
                continue
            if item.component_name.strip().lower() != normalized_component:
                continue
            return item
        return None

    def submit_once(
        self,
        vuln_id: str,
        component_name: str,
        submitted_by: str,
        project_name: Optional[str] = None,
        cvss_vector: Optional[str] = None,
        user_guidance: Optional[str] = None,
        affected_product_versions: Optional[list[str]] = None,
        model: Optional[str] = None,
        llm_backend: Optional[str] = None,
        llm_provider: Optional[str] = None,
        parent_run_id: Optional[str] = None,
        parent_job_id: Optional[str] = None,
        follow_up_question: Optional[str] = None,
        follow_up_user_guidance: Optional[str] = None,
        context_mode: Optional[str] = None,
        context_fingerprint: Optional[str] = None,
        context_summary: Optional[dict[str, Any]] = None,
        source: str = "manual",
        duplicate_statuses: tuple[str, ...] = (
            "queued",
            "running",
            "completed",
            "failed",
        ),
    ) -> tuple[AnalysisQueueItem, bool]:
        existing = self.find_existing(
            vuln_id,
            component_name,
            statuses=duplicate_statuses,
        )
        if existing:
            return existing, False

        return (
            self.submit(
                vuln_id=vuln_id,
                component_name=component_name,
                submitted_by=submitted_by,
                project_name=project_name,
                cvss_vector=cvss_vector,
                user_guidance=user_guidance,
                affected_product_versions=affected_product_versions,
                model=model,
                llm_backend=llm_backend,
                llm_provider=llm_provider,
                parent_run_id=parent_run_id,
                parent_job_id=parent_job_id,
                follow_up_question=follow_up_question,
                follow_up_user_guidance=follow_up_user_guidance,
                context_mode=context_mode,
                context_fingerprint=context_fingerprint,
                context_summary=context_summary,
                source=source,
            ),
            True,
        )

    def get(self, queue_id: str) -> Optional[AnalysisQueueItem]:
        self.prune_finished()
        return self._items.get(queue_id)

    def list_all(self) -> list[AnalysisQueueItem]:
        self.prune_finished()
        return [self._items[qid] for qid in self._order if qid in self._items]

    def cancel(self, queue_id: str) -> bool:
        item = self._items.get(queue_id)
        if not item or item.status not in ("queued",):
            return False
        item.status = "cancelled"
        item.finished_at = self._deps.utc_now().isoformat()
        self._order = [qid for qid in self._order if qid != queue_id]
        self._reindex()
        return True

    def request_abort(self, queue_id: str) -> Optional[AnalysisQueueItem]:
        item = self._items.get(queue_id)
        if not item or item.status != "running":
            return None
        item.abort_requested = True
        item.abort_error = None
        return item

    def clear_abort(self, queue_id: str, error: Optional[str] = None) -> bool:
        item = self._items.get(queue_id)
        if not item:
            return False
        item.abort_requested = False
        item.abort_error = error
        return True

    def finish_running_cancelled(self, queue_id: str) -> bool:
        item = self._items.get(queue_id)
        if not item or item.status != "running":
            return False
        self._finish_item(item, status="cancelled")
        self._reindex()
        return True

    def remove_finished(self, queue_id: str) -> bool:
        item = self._items.get(queue_id)
        if not item or item.status in ("queued", "running"):
            return False
        self._order = [qid for qid in self._order if qid != queue_id]
        del self._items[queue_id]
        return True

    def remove_finished_by_statuses(self, statuses: set[str]) -> int:
        removable_statuses = {
            status
            for status in statuses
            if status in {"completed", "failed", "cancelled"}
        }
        if not removable_statuses:
            return 0
        removed = 0
        for queue_id, item in list(self._items.items()):
            if not item or item.status not in removable_statuses:
                continue
            self._items.pop(queue_id, None)
            removed += 1
        if removed:
            self._order = [
                queue_id for queue_id in self._order if queue_id in self._items
            ]
            self._reindex()
        return removed

    def cancel_all_queued(self) -> int:
        cancelled = 0
        for queue_id in list(self._order):
            item = self._items.get(queue_id)
            if not item or item.status != "queued":
                continue
            if self.cancel(queue_id):
                cancelled += 1
        return cancelled

    def shutdown(self):
        self._running = False
        self._event.set()

    async def cleanup_loop(self):
        await self._deps.run_analysis_queue_cleanup_loop(
            self._deps.runtime_deps,
            lambda: self._running,
            self.prune_finished,
        )

    async def _wait_for_work(self) -> None:
        await self._event.wait()
        self._event.clear()

    def _get_next_queued_item(self) -> Optional[AnalysisQueueItem]:
        return self._deps.get_next_queued_item(self._items, self._order)

    def _start_item(self, item: AnalysisQueueItem) -> None:
        self._deps.start_analysis_queue_item(
            self._deps.runtime_deps,
            self._items,
            self._order,
            item,
        )

    def _finish_item(
        self,
        item: AnalysisQueueItem,
        *,
        status: str,
        result: Optional[dict] = None,
        error: Optional[str] = None,
    ) -> None:
        item.status = status
        item.result = result
        item.error = error
        item.finished_at = self._deps.utc_now().isoformat()
        item.abort_requested = False
        if status == "completed" and result:
            self._deps.record_completed_result(item)
        self.prune_finished()

    async def _process_item(self, item: AnalysisQueueItem) -> None:
        await self._deps.process_analysis_queue_item(
            self._deps.service_deps,
            item,
            self._finish_item,
        )

    async def worker(self):
        await self._deps.run_analysis_queue_worker(
            self._deps.runtime_deps,
            lambda: self._running,
            self.prune_finished,
            self._get_next_queued_item,
            self._wait_for_work,
            self._start_item,
            self._process_item,
            self._finish_item,
            self.capacity,
        )
