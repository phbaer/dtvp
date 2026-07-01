import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Optional

from pydantic import BaseModel


class AnalysisQueueItem(BaseModel):
    queue_id: str
    vuln_id: str
    component_name: str
    cvss_vector: Optional[str] = None
    user_guidance: Optional[str] = None
    source: str = "manual"
    submitted_by: str
    submitted_at: str
    status: str = "queued"
    position: int = 0
    job_id: Optional[str] = None
    error: Optional[str] = None
    result: Optional[dict] = None
    finished_at: Optional[str] = None
    progress: Optional[dict] = None


@dataclass(frozen=True)
class AnalysisQueueDeps:
    runtime_deps: Any
    service_deps: Any
    get_analysis_queue_ttl_seconds: Callable[[], int]
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

    def submit(
        self,
        vuln_id: str,
        component_name: str,
        submitted_by: str,
        cvss_vector: Optional[str] = None,
        user_guidance: Optional[str] = None,
        source: str = "manual",
    ) -> AnalysisQueueItem:
        self.prune_finished()
        queue_id = str(uuid.uuid4())
        item = AnalysisQueueItem(
            queue_id=queue_id,
            vuln_id=vuln_id,
            component_name=component_name,
            cvss_vector=cvss_vector,
            user_guidance=user_guidance,
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
        cvss_vector: Optional[str] = None,
        user_guidance: Optional[str] = None,
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
                cvss_vector=cvss_vector,
                user_guidance=user_guidance,
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

    def remove_finished(self, queue_id: str) -> bool:
        item = self._items.get(queue_id)
        if not item or item.status in ("queued", "running"):
            return False
        self._order = [qid for qid in self._order if qid != queue_id]
        del self._items[queue_id]
        return True

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
        )
