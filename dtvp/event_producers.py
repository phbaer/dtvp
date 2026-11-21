"""The producers of the app-wide event stream so far (ADR 0004, step 2).

They are fed by listener hooks of the cache manager and publish to the
``EventHub``. None of them reads Dependency-Track.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional

import httpx

from .event_hub import AUDIENCE_REVIEWER, EventHub

logger = logging.getLogger(__name__)

# Fields whose change makes a listed version "changed", with the name the
# event reports. The source's own change marks are opaque (dtvp/ports.py);
# the risk score and metrics are left out on purpose: every export of an
# assessment changes them.
PROJECT_LIST_FIELDS = {
    "name": "name",
    "version": "version",
    "active": "active",
    "dtvpSourceMarks": "source_data",
}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _by_uuid(projects: Iterable[Any]) -> Dict[str, Dict[str, Any]]:
    result: Dict[str, Dict[str, Any]] = {}
    for project in projects or []:
        if isinstance(project, dict) and project.get("uuid"):
            result[str(project["uuid"])] = project
    return result


def _ref(project: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "uuid": project.get("uuid"),
        "name": project.get("name"),
        "version": project.get("version"),
    }


def project_list_diff(
    previous: Iterable[Any] | None,
    current: Iterable[Any] | None,
    *,
    limit: int = 100,
) -> Optional[Dict[str, Any]]:
    """What changed between two project lists, or None when nothing did."""
    before = _by_uuid(previous or [])
    after = _by_uuid(current or [])
    if not before and after:
        return {
            "initial": True,
            "count": len(after),
            "added": [],
            "removed": [],
            "changed": [],
            "truncated": False,
        }

    added = [_ref(after[uuid]) for uuid in after if uuid not in before]
    removed = [_ref(before[uuid]) for uuid in before if uuid not in after]
    changed = []
    for uuid, project in after.items():
        old = before.get(uuid)
        if old is None:
            continue
        fields = [
            label
            for field, label in PROJECT_LIST_FIELDS.items()
            # A list stored before the source marked its data has nothing to
            # compare the marks with: not a change.
            if (field != "dtvpSourceMarks" or field in old)
            and old.get(field) != project.get(field)
        ]
        if fields:
            changed.append({**_ref(project), "fields": fields})

    if not added and not removed and not changed:
        return None
    truncated = any(len(items) > limit for items in (added, removed, changed))
    return {
        "added": added[:limit],
        "removed": removed[:limit],
        "changed": changed[:limit],
        "truncated": truncated,
        "count": len(after),
    }


class ProjectListEventProducer:
    """Publishes ``projects.changed`` after the stored project list changed."""

    def __init__(self, hub: EventHub, *, limit: int = 100) -> None:
        self._hub = hub
        self._limit = limit

    def __call__(self, previous: List[Dict[str, Any]], current: List[Dict[str, Any]]) -> None:
        diff = project_list_diff(previous, current, limit=self._limit)
        if diff is not None:
            self._hub.publish("projects.changed", diff)


class SourceStateTracker:
    """Whether Dependency-Track can be reached, and the sync backlog.

    Called directly (``tracker(ok, exc)``) it follows single reads; with the
    scheduler, its circuit breaker sets the state (``set_state``), reads only
    note their success, and ``set_backlog`` adds how many versions wait.
    Publishes ``source.state`` on a transition only."""

    def __init__(
        self,
        hub: EventHub,
        clock: Callable[[], datetime] = _now,
    ) -> None:
        self._hub = hub
        self._clock = clock
        self._state: Dict[str, Any] = {
            "dt": "unknown",
            "since": _iso(clock()),
            "last_success_at": None,
            "error_class": None,
            "backlog": 0,
        }
        self._published_backlog = 0

    def snapshot(self) -> Dict[str, Any]:
        return dict(self._state)

    def note_success(self) -> None:
        """A read succeeded: ``ok`` once known, otherwise only the time."""
        if self._state.get("dt") == "unknown":
            self.set_state("ok")
            return
        self._state = {**self._state, "last_success_at": _iso(self._clock())}

    def set_state(self, dt_state: str, error_class: Optional[str] = None) -> None:
        now = _iso(self._clock())
        state = dict(self._state)
        if dt_state == "ok":
            state["last_success_at"] = now
        state["error_class"] = error_class
        changed = state["dt"] != dt_state
        if changed:
            state["dt"] = dt_state
            state["since"] = now
        self._state = state
        if changed:
            self._hub.publish("source.state", dict(state))

    def set_backlog(self, backlog: int) -> None:
        """How many versions wait for a sync; published when it changes
        between empty and not, or by at least ten, so the stream stays calm."""
        before = self._published_backlog
        self._state = {**self._state, "backlog": int(backlog)}
        if (before == 0) != (backlog == 0) or abs(backlog - before) >= 10:
            self._published_backlog = int(backlog)
            self._hub.publish("source.state", dict(self._state))

    def __call__(self, ok: bool, exc: BaseException | None = None) -> None:
        now = _iso(self._clock())
        if ok:
            dt_state = "ok"
            error_class = None
        else:
            status = (
                exc.response.status_code
                if isinstance(exc, httpx.HTTPStatusError) and exc.response is not None
                else None
            )
            dt_state = "misconfigured" if status in (401, 403) else "down"
            error_class = type(exc).__name__ if exc is not None else None

        state = dict(self._state)
        if ok:
            state["last_success_at"] = now
        state["error_class"] = error_class
        changed = state["dt"] != dt_state
        if changed:
            state["dt"] = dt_state
            state["since"] = now
        self._state = state
        if changed:
            self._hub.publish("source.state", dict(state))


class AssessmentEventProducer:
    """Publishes ``assessments.changed`` per product, with its origin:
    ``local`` (a save, a carry-over, a discarded export), ``dt`` (the source
    changed an assessment) or ``export_echo`` (the source now holds DTVP's
    own export). Registered after the task-snapshot listener, so open views
    are already up to date."""

    def __init__(
        self,
        hub: EventHub,
        project_versions: Callable[[], List[Dict[str, Any]]],
    ) -> None:
        self._hub = hub
        self._project_versions = project_versions

    def __call__(
        self, keys: Iterable[Any], *, value_changed: bool = True, origin: str = "local"
    ) -> None:
        by_project: Dict[str, int] = {}
        for key in keys or []:
            if not key:
                continue
            project_uuid = str(key[0])
            by_project[project_uuid] = by_project.get(project_uuid, 0) + 1
        if not by_project:
            return
        names = {
            str(project.get("uuid")): project.get("name")
            for project in self._project_versions() or []
            if isinstance(project, dict) and project.get("uuid")
        }
        grouped: Dict[Optional[str], Dict[str, int]] = {}
        for project_uuid, count in by_project.items():
            name = names.get(project_uuid)
            # A project known only by its uuid has no product name.
            product = name if name and name != project_uuid else None
            grouped.setdefault(product, {})[project_uuid] = count
        for product, counts in grouped.items():
            self._hub.publish(
                "assessments.changed",
                {
                    "product": product,
                    "project_uuids": sorted(counts),
                    "keys_count": sum(counts.values()),
                    "origin": origin,
                },
                product=product,
            )


def export_state_from_entries(entries: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    """The export queue in numbers, with the rules of the cache status."""
    entries = list(entries or [])
    return {
        "pending": len(entries),
        "failed": sum(1 for entry in entries if entry.get("last_error")),
        "oldest_pending_at": min(
            (str(entry.get("created_at")) for entry in entries if entry.get("created_at")),
            default=None,
        ),
    }


class _CoalescingProducer:
    """A producer woken by a cache-status listener.

    ``mark_dirty`` may run on any thread and only sets a flag. ``run``
    calls ``publish_if_changed`` at most every ``min_interval`` seconds while
    marked, and every ``safety_interval`` seconds otherwise."""

    name = "Event producer"

    def __init__(
        self,
        hub: EventHub,
        *,
        min_interval: float = 2.0,
        safety_interval: float = 60.0,
    ) -> None:
        self._hub = hub
        self._min_interval = min_interval
        self._safety_interval = safety_interval
        self._loop: asyncio.AbstractEventLoop | None = None
        self._wake: asyncio.Event | None = None

    def mark_dirty(self) -> None:
        loop, wake = self._loop, self._wake
        if loop is None or wake is None:
            return
        try:
            loop.call_soon_threadsafe(wake.set)
        except RuntimeError:
            pass

    async def publish_if_changed(self) -> bool:  # pragma: no cover - abstract
        raise NotImplementedError

    async def run(self) -> None:
        self._loop = asyncio.get_running_loop()
        self._wake = asyncio.Event()
        first = True
        while True:
            if not first:
                try:
                    await asyncio.wait_for(
                        self._wake.wait(), timeout=self._safety_interval
                    )
                except TimeoutError:
                    pass
                await asyncio.sleep(self._min_interval)
            first = False
            self._wake.clear()
            try:
                await self.publish_if_changed()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("%s failed", self.name)


class ExportStateProducer(_CoalescingProducer):
    """Publishes ``export.state`` to reviewers when the export queue changed."""

    name = "Export state event"

    def __init__(
        self,
        hub: EventHub,
        cache_manager: Any,
        *,
        min_interval: float = 2.0,
        safety_interval: float = 60.0,
    ) -> None:
        super().__init__(
            hub, min_interval=min_interval, safety_interval=safety_interval
        )
        self._cache_manager = cache_manager
        self._last: tuple | None = None

    def _list_pending(self) -> List[Dict[str, Any]]:
        return self._cache_manager.assessment_outbox.list_pending()

    async def publish_if_changed(self) -> bool:
        entries = await asyncio.to_thread(self._list_pending)
        state = export_state_from_entries(entries)
        key = (state["pending"], state["failed"], state["oldest_pending_at"])
        if key == self._last:
            return False
        self._last = key
        self._hub.publish("export.state", state, audience=AUDIENCE_REVIEWER)
        return True


class CacheRefreshProducer(_CoalescingProducer):
    """Publishes ``cache.refreshed`` when the cache's ``last_refreshed_at``
    moved, for example after the background refresh of active versions
    saved new findings. The first value it sees is only remembered: a client
    that connects later fetches the cache status anyway."""

    name = "Cache refresh event"

    def __init__(
        self,
        hub: EventHub,
        last_refreshed_at: Callable[[], Optional[str]],
        *,
        min_interval: float = 2.0,
        safety_interval: float = 60.0,
    ) -> None:
        super().__init__(
            hub, min_interval=min_interval, safety_interval=safety_interval
        )
        self._read = last_refreshed_at
        self._seen = False
        self._last: Optional[str] = None

    async def publish_if_changed(self) -> bool:
        value = self._read()
        value = str(value) if value else None
        if not self._seen:
            self._seen = True
            self._last = value
            return False
        if value is None or value == self._last:
            return False
        self._last = value
        self._hub.publish("cache.refreshed", {"last_refreshed_at": value})
        return True
