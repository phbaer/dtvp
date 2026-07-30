import uuid
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Optional

from pydantic import BaseModel, Field


class AnalysisQueueFullError(RuntimeError):
    pass


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
    get_analysis_queue_max_pending: Callable[[], int]
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
        self._queued_ids: deque[str] = deque()
        self._queued_members: set[str] = set()
        self._target_index: dict[tuple[str, str], set[str]] = defaultdict(set)
        self._hidden_order_ids: set[str] = set()
        self._positions_dirty = False
        self._event = deps.create_event()
        self._running = True
        self._lock = deps.create_lock()

    def reset_runtime_state(self):
        self._event = self._deps.create_event()
        self._lock = self._deps.create_lock()
        self._running = True
        with self._lock:
            self._rebuild_indexes_locked()

    def reset_contents(self) -> None:
        with self._lock:
            self._items.clear()
            self._order.clear()
            self._queued_ids.clear()
            self._queued_members.clear()
            self._target_index.clear()
            self._hidden_order_ids.clear()
            self._positions_dirty = False
            self._event.clear()
            self._running = True

    @staticmethod
    def _target_key(vuln_id: str, component_name: str) -> tuple[str, str]:
        return (vuln_id.strip().lower(), component_name.strip().lower())

    def _index_item_locked(self, item: AnalysisQueueItem) -> None:
        self._target_index[
            self._target_key(item.vuln_id, item.component_name)
        ].add(item.queue_id)

    def _deindex_item_locked(self, item: AnalysisQueueItem) -> None:
        key = self._target_key(item.vuln_id, item.component_name)
        queue_ids = self._target_index.get(key)
        if not queue_ids:
            return
        queue_ids.discard(item.queue_id)
        if not queue_ids:
            self._target_index.pop(key, None)

    def _rebuild_indexes_locked(self) -> None:
        self._queued_ids.clear()
        self._queued_members.clear()
        self._target_index.clear()
        self._hidden_order_ids.intersection_update(self._items)
        position = 1
        for queue_id in self._order:
            item = self._items.get(queue_id)
            if not item:
                continue
            self._index_item_locked(item)
            if item.status == "queued":
                self._queued_ids.append(queue_id)
                self._queued_members.add(queue_id)
                item.position = position
                position += 1
            else:
                item.position = 0
        self._positions_dirty = False

    def _refresh_positions_locked(self) -> None:
        if not self._positions_dirty:
            return
        queued_ids: deque[str] = deque()
        queued_members: set[str] = set()
        position = 1
        for queue_id in self._queued_ids:
            item = self._items.get(queue_id)
            if not item or item.status != "queued" or queue_id in queued_members:
                continue
            queued_ids.append(queue_id)
            queued_members.add(queue_id)
            item.position = position
            position += 1
        self._queued_ids = queued_ids
        self._queued_members = queued_members
        self._positions_dirty = False

    def _find_existing_locked(
        self,
        vuln_id: str,
        component_name: str,
        statuses: tuple[str, ...],
    ) -> Optional[AnalysisQueueItem]:
        key = self._target_key(vuln_id, component_name)
        queue_ids = self._target_index.get(key)
        if not queue_ids:
            return None
        stale_ids: list[str] = []
        for queue_id in queue_ids:
            item = self._items.get(queue_id)
            if not item:
                stale_ids.append(queue_id)
                continue
            if item.status in statuses:
                return item
        for queue_id in stale_ids:
            queue_ids.discard(queue_id)
        if not queue_ids:
            self._target_index.pop(key, None)
        return None

    def prune_finished(self, now: Optional[float] = None) -> int:
        with self._lock:
            current_time = (
                now if now is not None else self._deps.utc_now().timestamp()
            )
            removed = self._deps.prune_finished_queue_items(
                self._items,
                self._order,
                current_time=current_time,
                ttl_seconds=self._deps.get_analysis_queue_ttl_seconds(),
                parse_timestamp=self._deps.parse_iso_timestamp,
            )
            if removed:
                self._rebuild_indexes_locked()
            return removed

    def capacity(self) -> int:
        try:
            return max(1, int(self._deps.get_analysis_queue_capacity()))
        except (TypeError, ValueError):
            return 1

    def max_pending(self) -> int:
        try:
            return max(1, int(self._deps.get_analysis_queue_max_pending()))
        except (TypeError, ValueError):
            return 1000

    def can_accept(self) -> bool:
        with self._lock:
            return len(self._queued_members) < self.max_pending()

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
        with self._lock:
            if len(self._queued_members) >= self.max_pending():
                raise AnalysisQueueFullError(
                    f"Analysis queue has reached its {self.max_pending()} pending-item limit."
                )
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
                position=len(self._queued_members) + 1,
            )
            self._items[queue_id] = item
            self._order.append(queue_id)
            self._queued_ids.append(queue_id)
            self._queued_members.add(queue_id)
            self._index_item_locked(item)
            self._event.set()
            return item

    def find_existing(
        self,
        vuln_id: str,
        component_name: str,
        *,
        statuses: tuple[str, ...] = ("queued", "running", "completed", "failed"),
    ) -> Optional[AnalysisQueueItem]:
        with self._lock:
            return self._find_existing_locked(
                vuln_id,
                component_name,
                statuses,
            )

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
        with self._lock:
            existing = self._find_existing_locked(
                vuln_id=vuln_id,
                component_name=component_name,
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
        with self._lock:
            item = self._items.get(queue_id)
            if item and item.status == "queued" and self._positions_dirty:
                self._refresh_positions_locked()
            return item

    def list_all(self) -> list[AnalysisQueueItem]:
        with self._lock:
            self._refresh_positions_locked()
            return [
                self._items[queue_id]
                for queue_id in self._order
                if queue_id in self._items
                and queue_id not in self._hidden_order_ids
            ]

    def list_page(
        self,
        *,
        offset: int = 0,
        limit: int = 100,
        newest_first: bool = True,
    ) -> list[AnalysisQueueItem]:
        with self._lock:
            self._refresh_positions_locked()
            result: list[AnalysisQueueItem] = []
            skipped = 0
            order = reversed(self._order) if newest_first else iter(self._order)
            for queue_id in order:
                item = self._items.get(queue_id)
                if not item or queue_id in self._hidden_order_ids:
                    continue
                if skipped < offset:
                    skipped += 1
                    continue
                result.append(item)
                if len(result) >= limit:
                    break
            return result

    def cancel(self, queue_id: str) -> bool:
        with self._lock:
            item = self._items.get(queue_id)
            if not item or item.status not in ("queued",):
                return False
            item.status = "cancelled"
            item.position = 0
            item.finished_at = self._deps.utc_now().isoformat()
            self._queued_members.discard(queue_id)
            self._hidden_order_ids.add(queue_id)
            self._positions_dirty = True
            return True

    def request_abort(self, queue_id: str) -> Optional[AnalysisQueueItem]:
        with self._lock:
            item = self._items.get(queue_id)
            if not item or item.status != "running":
                return None
            item.abort_requested = True
            item.abort_error = None
            return item

    def clear_abort(self, queue_id: str, error: Optional[str] = None) -> bool:
        with self._lock:
            item = self._items.get(queue_id)
            if not item:
                return False
            item.abort_requested = False
            item.abort_error = error
            return True

    def finish_running_cancelled(self, queue_id: str) -> bool:
        with self._lock:
            item = self._items.get(queue_id)
            if not item or item.status != "running":
                return False
            self._finish_item(item, status="cancelled")
            return True

    def remove_finished(self, queue_id: str) -> bool:
        with self._lock:
            item = self._items.get(queue_id)
            if not item or item.status in ("queued", "running"):
                return False
            self._deindex_item_locked(item)
            self._hidden_order_ids.discard(queue_id)
            if queue_id in self._queued_members:
                self._queued_members.discard(queue_id)
                self._positions_dirty = True
            del self._items[queue_id]
            self._order = [
                ordered_id
                for ordered_id in self._order
                if ordered_id != queue_id
            ]
            return True

    def remove_finished_by_statuses(self, statuses: set[str]) -> int:
        removable_statuses = {
            status
            for status in statuses
            if status in {"completed", "failed", "cancelled"}
        }
        if not removable_statuses:
            return 0
        with self._lock:
            removed = 0
            for queue_id, item in list(self._items.items()):
                if not item or item.status not in removable_statuses:
                    continue
                self._deindex_item_locked(item)
                if queue_id in self._queued_members:
                    self._queued_members.discard(queue_id)
                    self._positions_dirty = True
                self._items.pop(queue_id, None)
                self._hidden_order_ids.discard(queue_id)
                removed += 1
            if removed:
                self._order = [
                    queue_id
                    for queue_id in self._order
                    if queue_id in self._items
                ]
            return removed

    def cancel_all_queued(self) -> int:
        with self._lock:
            finished_at = self._deps.utc_now().isoformat()
            cancelled = 0
            for queue_id in tuple(self._queued_members):
                item = self._items.get(queue_id)
                if not item or item.status != "queued":
                    continue
                item.status = "cancelled"
                item.position = 0
                item.finished_at = finished_at
                self._hidden_order_ids.add(queue_id)
                cancelled += 1
            self._queued_members.clear()
            self._queued_ids.clear()
            self._positions_dirty = False
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
        with self._lock:
            while self._queued_ids:
                queue_id = self._queued_ids[0]
                item = self._items.get(queue_id)
                if (
                    item
                    and item.status == "queued"
                    and queue_id in self._queued_members
                ):
                    return item
                self._queued_ids.popleft()
                self._queued_members.discard(queue_id)
            return None

    def _start_item(self, item: AnalysisQueueItem) -> None:
        with self._lock:
            self._queued_members.discard(item.queue_id)
            if self._queued_ids and self._queued_ids[0] == item.queue_id:
                self._queued_ids.popleft()
            self._positions_dirty = True
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
        should_record_result = status == "completed" and bool(result)
        with self._lock:
            if item.queue_id in self._queued_members:
                self._queued_members.discard(item.queue_id)
                self._positions_dirty = True
            item.status = status
            item.position = 0
            item.result = result
            item.error = error
            item.finished_at = self._deps.utc_now().isoformat()
            item.abort_requested = False
        if should_record_result:
            self._deps.record_completed_result(item)

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
