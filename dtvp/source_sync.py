"""The background owner of Dependency-Track reads (ADR 0004 step 5).

``SourceSync`` reads the project list every refresh interval, plans which
versions are due, and syncs them in priority order, at most two at a time,
each one staged and committed once (``SyncStateStore.stage``/``commit``).
Every Dependency-Track call it and the export make goes through one token
bucket and one circuit breaker (``LimitedSource``). It publishes
``version.sync_state``, ``version.synced``, ``version.sync_failed`` and the
backlog in ``source.state``.

What is due (ADR 0004, "Schedule and priorities"):

- watched products (``ProductInterest``): findings every 120 s; vulnerability
  records on a list signal or after 6 h; the BOM on a BOM signal or after 24 h;
- every other active version: imported once (backfill), then re-read on a
  list signal or after 12 h;
- a failed version waits for its backoff (doubling, at most 1 h).

The readers still read through the cache's client-taking methods; the
store-only readers that serve the previous generation while a sync is
staged come with step 6.
"""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable, Optional

import httpx

from .ports import AnalysisTrigger, ChangeHints, source_display_name
from .source_sync_state import (
    KIND_BOM,
    KIND_FINDINGS,
    KIND_VULNS,
    STATUS_FAILED,
    STATUS_GONE,
        STATUS_QUEUED,
    SourceUnavailable,
    finding_key,
)

logger = logging.getLogger(__name__)

KINDS = (KIND_FINDINGS, KIND_VULNS, KIND_BOM)

# Priorities: lower runs first; one level up per 10 minutes of waiting.
P0_REQUEST, P1_WATCHED_FIRST, P2_DUE, P3_BACKFILL, P4_SAFETY = range(5)
AGING_SECONDS = 600


def _env_float(name: str, default: float, minimum: float = 0.0) -> float:
    try:
        value = float(os.getenv(name, str(default)))
    except ValueError:
        return default
    return value if value >= minimum else default


@dataclass(frozen=True)
class Schedule:
    """The intervals of ADR 0004's user decisions 1 and 2, in seconds."""

    watched_findings: float = 120
    watched_vulns: float = 6 * 3600
    watched_bom: float = 24 * 3600
    safety: float = 12 * 3600
    # A source without change hints (ports.ChangeHints): every active
    # version is read again on these intervals instead.
    unhinted_findings: float = 3600
    unhinted_vulns: float = 6 * 3600
    unhinted_bom: float = 24 * 3600
    max_backoff: float = 3600
    base_backoff: float = 60
    concurrency: int = 2

    @classmethod
    def from_env(cls) -> "Schedule":
        return cls(
            watched_findings=_env_float("DTVP_SYNC_WATCHED_FINDINGS_SECONDS", 120, 1),
            safety=_env_float("DTVP_SYNC_SAFETY_SECONDS", 12 * 3600, 60),
            unhinted_findings=_env_float(
                "DTVP_SYNC_UNHINTED_FINDINGS_SECONDS", 3600, 60
            ),
            concurrency=int(_env_float("DTVP_SYNC_CONCURRENCY", 2, 1)),
        )


# -- limits --------------------------------------------------------------------


class TokenBucket:
    """One budget for every Dependency-Track request: ``rate`` per second,
    ``burst`` at once."""

    def __init__(
        self,
        rate: float = 4.0,
        burst: float = 8.0,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[Any]] = asyncio.sleep,
    ) -> None:
        self.rate = rate
        self.burst = burst
        self._tokens = burst
        self._clock = clock
        self._sleep = sleep
        self._updated = clock()
        self._lock = asyncio.Lock()

    def _refill(self) -> None:
        now = self._clock()
        self._tokens = min(self.burst, self._tokens + (now - self._updated) * self.rate)
        self._updated = now

    async def acquire(self) -> None:
        async with self._lock:
            while True:
                self._refill()
                if self._tokens >= 1:
                    self._tokens -= 1
                    return
                await self._sleep((1 - self._tokens) / self.rate)


BREAKER_OK, BREAKER_DOWN, BREAKER_MISCONFIGURED = "ok", "down", "misconfigured"


def _status_code(exc: BaseException) -> Optional[int]:
    if isinstance(exc, httpx.HTTPStatusError) and exc.response is not None:
        return exc.response.status_code
    return None


class CircuitBreaker:
    """Opens after ``threshold`` consecutive transport, 5xx or 429 failures,
    or at once on 401/403 (``misconfigured``). While open, all
    Dependency-Track work pauses; a probe every ``probe_interval`` closes it
    again. ``on_change(state, error_class)`` is told of every transition."""

    def __init__(
        self,
        threshold: int = 5,
        probe_interval: float = 30.0,
        *,
        clock: Callable[[], float] = time.monotonic,
        on_change: Callable[[str, Optional[str]], None] = lambda *_: None,
    ) -> None:
        self.threshold = threshold
        self.probe_interval = probe_interval
        self._clock = clock
        self._on_change = on_change
        self.state = BREAKER_OK
        self.failures = 0
        self.opened_at: Optional[float] = None
        self.error_class: Optional[str] = None

    @property
    def open(self) -> bool:
        return self.state != BREAKER_OK

    def probe_due(self) -> bool:
        return self.open and (
            self.opened_at is None or self._clock() - self.opened_at >= self.probe_interval
        )

    def _set(self, state: str, error_class: Optional[str]) -> None:
        changed = state != self.state
        self.state = state
        self.error_class = error_class
        self.opened_at = self._clock() if state != BREAKER_OK else None
        if changed:
            self._on_change(state, error_class)

    def success(self) -> None:
        self.failures = 0
        if self.open:
            self._set(BREAKER_OK, None)

    def failure(self, exc: BaseException) -> None:
        status = _status_code(exc)
        name = type(exc).__name__
        if status in (401, 403):
            self._set(BREAKER_MISCONFIGURED, name)
            return
        counts = (
            isinstance(exc, (httpx.TransportError, OSError, asyncio.TimeoutError))
            or status == 429
            or (status is not None and status >= 500)
        )
        if not counts:
            return
        self.failures += 1
        if self.failures >= self.threshold:
            self._set(BREAKER_DOWN, name)
        elif self.open:
            # A failed probe: wait another interval.
            self.opened_at = self._clock()

    def observe(self, ok: bool, exc: BaseException | None = None) -> None:
        """For the cache's source-state listeners (project-list reads): a
        success closes the breaker. Failures are counted where the call is
        made (``LimitedSource``), so a failed scheduled read counts once. A
        ``misconfigured`` breaker (the scheduler's key was refused) is only
        closed by the scheduler's own calls: a request-path read may use
        other credentials."""
        if ok and self.state != BREAKER_MISCONFIGURED:
            self.success()


class LimitedSource:
    """A source whose every request takes a token and whose every call
    reports to the breaker. While the breaker is open, calls fail with
    ``SourceUnavailable``.

    A source with a request hook (``BudgetedTransport``, the Dependency-Track
    client) takes the token per HTTP request, so a paginated list or a
    per-finding fallback pays for every page; any other source pays per
    call. Install it once per client (``SourceSync.limited``)."""

    def __init__(self, source: Any, bucket: TokenBucket, breaker: CircuitBreaker) -> None:
        self._source = source
        self._bucket = bucket
        self._breaker = breaker
        hook = getattr(source, "add_request_hook", None)
        self._per_request = callable(hook)
        if self._per_request:
            hook(bucket.acquire)

    async def probe(self) -> None:
        """One cheap request within the budget, also while the breaker is
        open; raises when the source does not answer."""
        ping = getattr(self._source, "ping", None)
        if not self._per_request:
            await self._bucket.acquire()
        if callable(ping):
            await ping()
        else:
            await self._source.get_projects("")

    def __getattr__(self, name: str) -> Any:
        target = getattr(self._source, name)
        if not callable(target) or not inspect.iscoroutinefunction(target):
            return target

        async def call(*args: Any, **kwargs: Any) -> Any:
            if self._breaker.open:
                raise SourceUnavailable(f"Dependency-Track is {self._breaker.state}")
            if not self._per_request:
                await self._bucket.acquire()
            try:
                result = await target(*args, **kwargs)
            except Exception as exc:
                self._breaker.failure(exc)
                raise
            self._breaker.success()
            return result

        return call


# -- planning ------------------------------------------------------------------


def _parse(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


# How long after a read its documents are surely stored (they are written
# by a background thread).
STORE_SETTLE_SECONDS = 300.0


def _older(value: Optional[str], now: datetime, seconds: float) -> bool:
    at = _parse(value)
    return at is None or (now - at).total_seconds() >= seconds


@dataclass
class SyncItem:
    project_uuid: str
    priority: int
    kinds: tuple[str, ...]
    enqueued_at: float

    def effective(self, now: float) -> int:
        return max(0, self.priority - int((now - self.enqueued_at) // AGING_SECONDS))


def _stagger(project_uuid: str) -> float:
    """A fixed factor between 0.75 and 1 per version, so regular re-reads of
    many versions spread over the interval instead of falling due at once."""
    digest = hashlib.sha256(project_uuid.encode("utf-8")).digest()
    return 0.75 + 0.25 * (int.from_bytes(digest[:2], "big") / 65536)


def plan_version(
    row: dict[str, Any],
    *,
    watched: bool,
    now: datetime,
    schedule: Schedule,
    hinted: bool = True,
    stored_findings_at: Optional[str] = "unknown",
) -> Optional[tuple[int, tuple[str, ...]]]:
    """What is due for one version, with its priority, or ``None``.

    ``hinted``: the source offers change hints (ports.ChangeHints). Then an
    unwatched version is read again when a hint changes, or by the safety
    re-read. Without hints, every active version is read again on the
    ``unhinted_*`` intervals, staggered per version."""
    if not row.get("active_in_dt") or row.get("status") == STATUS_GONE:
        return None
    due_at = _parse(row.get("next_due_at"))
    # A failing version waits for its backoff, a requested one too.
    if row.get("settled_status") == STATUS_FAILED and due_at is not None and due_at > now:
        return None
    if row.get("requested_at"):
        return P0_REQUEST, KINDS
    if row.get("last_success_at") is None:
        return (P1_WATCHED_FIRST if watched else P3_BACKFILL), KINDS
    # The sync state says read, but no findings are stored for the version:
    # the two disagree (a database restored or replaced without the other).
    # Read everything again; ``stored_findings_at`` is "unknown" when the
    # caller cannot tell. Stored documents are written in the background, so
    # only a read older than ``STORE_SETTLE_SECONDS`` counts. (A restore with
    # ``python -m dtvp.backup`` starts with an empty sync state, so every
    # version counts as never read.)
    if stored_findings_at is None and _older(
        row.get("last_success_at"), now, STORE_SETTLE_SECONDS
    ):
        return P2_DUE, KINDS
    if hinted:
        bom_signal = row.get("source_bom_hint") != row.get("read_bom_signal")
        analysis_signal = row.get("source_analysis_hint") != row.get("read_analysis_signal")
        if bom_signal:
            return P2_DUE, KINDS
        if analysis_signal:
            return P2_DUE, (KIND_FINDINGS, KIND_VULNS)
    if watched:
        kinds = tuple(
            kind
            for kind, column, interval in (
                (KIND_FINDINGS, "findings_read_at", schedule.watched_findings),
                (KIND_VULNS, "vulns_read_at", schedule.watched_vulns),
                (KIND_BOM, "bom_read_at", schedule.watched_bom),
            )
            if _older(row.get(column), now, interval)
        )
        if kinds:
            return P2_DUE, kinds
    if not hinted:
        stagger = _stagger(str(row.get("project_uuid") or ""))
        kinds = tuple(
            kind
            for kind, column, interval in (
                (KIND_FINDINGS, "findings_read_at", schedule.unhinted_findings),
                (KIND_VULNS, "vulns_read_at", schedule.unhinted_vulns),
                (KIND_BOM, "bom_read_at", schedule.unhinted_bom),
            )
            if _older(row.get(column), now, interval * stagger)
        )
        if kinds:
            return P3_BACKFILL, kinds
    if _older(row.get("last_success_at"), now, schedule.safety):
        return P4_SAFETY, KINDS
    return None


# -- the scheduler -------------------------------------------------------------


@dataclass
class _Throttle:
    seconds: float
    last: dict[str, float] = field(default_factory=dict)

    def allow(self, key: str, now: float) -> bool:
        if now - self.last.get(key, float("-inf")) < self.seconds:
            return False
        self.last[key] = now
        return True


class SourceSync:
    # Beyond this many versions queued at once (a first start, an upgrade),
    # per-version queued events give way to the backlog in ``source.state``.
    QUEUED_EVENT_LIMIT = 20
    # Planning reads every row: on a change, or at least this often.
    PLAN_INTERVAL_SECONDS = 15.0

    def __init__(
        self,
        cache: Any,
        *,
        hub: Any = None,
        interest: Any = None,
        source_state: Any = None,
        schedule: Optional[Schedule] = None,
        bucket: Optional[TokenBucket] = None,
        breaker: Optional[CircuitBreaker] = None,
        now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.cache = cache
        self.hub = hub
        self.interest = interest
        self.source_state = source_state
        self.schedule = schedule or Schedule.from_env()
        self.bucket = bucket or TokenBucket(
            _env_float("DTVP_DT_REQUESTS_PER_SECOND", 4.0, 0.1),
            _env_float("DTVP_DT_REQUEST_BURST", 8.0, 1.0),
        )
        self.breaker = breaker or CircuitBreaker(on_change=self._breaker_changed)
        self._now = now
        self._monotonic = monotonic
        self.queue: dict[str, SyncItem] = {}
        self.running: set[str] = set()
        self._tasks: set[asyncio.Task] = set()
        self._export: Optional[asyncio.Task] = None
        self._state_throttle = _Throttle(5.0)
        self._backlog: Optional[int] = None
        self._next_list_read = 0.0
        self._next_plan = 0.0
        self._plan_dirty = True
        self._watched_seen: Optional[frozenset[str]] = None
        self._limited: Optional[tuple[Any, LimitedSource]] = None
        # Analyses the source was asked for, followed until they finish.
        self._analyses: dict[str, asyncio.Task] = {}
        # Whether the source offers change hints (ports.ChangeHints); known
        # once a client is seen.
        self.hinted = True

    def limited(self, client: Any) -> LimitedSource:
        """The budgeted view of ``client``, built once per client (its
        request hook is installed once)."""
        if self._limited is None or self._limited[0] is not client:
            self._limited = (client, LimitedSource(client, self.bucket, self.breaker))
            hinted = isinstance(client, ChangeHints)
            if hinted != self.hinted:
                self.hinted = hinted
                self.mark_dirty()
        return self._limited[1]

    def mark_dirty(self) -> None:
        """Plan on the next pass (the list, a sync or the interest changed)."""
        self._plan_dirty = True

    def _wake(self) -> None:
        self.mark_dirty()
        wake = getattr(self.cache, "wake_sync", None)
        if callable(wake):
            wake()

    # -- requests (ADR 0004 step 8) ------------------------------------------

    # How often a requested analysis is asked whether it finished, and for
    # how long at most; then the version is read anyway.
    ANALYSIS_POLL_SECONDS = 10.0
    ANALYSIS_MAX_SECONDS = 1800.0

    def request_reads(
        self, project_uuids: list[str], *, by: Optional[str]
    ) -> list[dict[str, Any]]:
        """Read these versions before anything else (P0). Returns one entry
        per version with its ``request_id``; ``new`` is False for a request
        that was already waiting."""
        requests = self.cache.sync_state.request(
            project_uuids, by=by, at=self._now().isoformat()
        )
        new = [entry for entry in requests if entry["new"]]
        if new:
            logger.info("%s requested a read of %d version(s)", by or "someone", len(new))
            self._wake()
        return requests

    @property
    def source_name(self) -> str:
        return source_display_name(self._limited[0] if self._limited else None)

    @property
    def can_request_analysis(self) -> bool:
        return self._limited is not None and isinstance(self._limited[0], AnalysisTrigger)

    async def request_analysis(self, project_uuids: list[str], *, by: Optional[str]) -> list[str]:
        """Ask the source to analyse these versions again, within the shared
        budget and breaker; each version is read when its analysis has
        finished (or after ``ANALYSIS_MAX_SECONDS``). Returns the versions
        the source accepted."""
        if not self.can_request_analysis:
            raise NotImplementedError("The source cannot be asked for an analysis")
        if self.breaker.open:
            raise SourceUnavailable("The source is unavailable")
        limited = self._limited[1]
        accepted: list[str] = []
        for uuid in dict.fromkeys(project_uuids):
            if uuid in self._analyses:
                continue  # one at a time per version
            token = await limited.request_analysis(uuid)
            accepted.append(uuid)
            row = self.cache.sync_state.row(uuid) or {"project_uuid": uuid}
            self._publish_state(row, "analysing", force=True)
            task = asyncio.create_task(self._follow_analysis(limited, uuid, token, by))
            self._analyses[uuid] = task
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)
            task.add_done_callback(lambda _t, uuid=uuid: self._analyses.pop(uuid, None))
        if accepted:
            logger.info("%s requested an analysis of %d version(s)", by or "someone", len(accepted))
        return accepted

    async def _follow_analysis(
        self, limited: Any, uuid: str, token: Optional[str], by: Optional[str]
    ) -> None:
        """Wait for the source's analysis, then request the read."""
        waited = 0.0
        while token and waited < self.ANALYSIS_MAX_SECONDS:
            await asyncio.sleep(self.ANALYSIS_POLL_SECONDS)
            waited += self.ANALYSIS_POLL_SECONDS
            try:
                if not await limited.analysis_running(token):
                    break
            except Exception as exc:
                logger.info("Could not follow the analysis of %s: %s", uuid, exc)
                break
        self.request_reads([uuid], by=by)

    # -- interest --------------------------------------------------------------

    def watched_products(self) -> set[str]:
        watched = getattr(self.interest, "watched", None)
        if not callable(watched):
            return set()
        return {str(name).strip().lower() for name in watched() if str(name).strip()}

    # -- queue -----------------------------------------------------------------

    def recover(self) -> None:
        """At startup: settle what a restart interrupted, and sync the
        interrupted versions again first (their change is seen anew)."""
        interrupted = self.cache.sync_state.recover()
        self.queue.clear()
        tick = self._monotonic()
        for uuid in interrupted:
            self.queue[uuid] = SyncItem(uuid, P2_DUE, KINDS, tick)
        if interrupted:
            self.cache.sync_state.set_statuses(interrupted, STATUS_QUEUED)
            logger.info("Sync recovery: %d interrupted version(s) queued again", len(interrupted))
        self.mark_dirty()

    def plan(self) -> None:
        now = self._now()
        tick = self._monotonic()
        products = self.watched_products()
        self._watched_seen = frozenset(products)
        rows = self.cache.sync_state.rows()
        # The versions of watched products, for the cache status.
        self.cache.active_project_uuids = {
            row["project_uuid"]
            for row in rows
            if str(row.get("product_name") or "").lower() in products
            and row.get("status") != STATUS_GONE
        }
        queued: list[dict[str, Any]] = []
        dropped: list[str] = []
        # When each version's findings were stored, in one query: a version
        # whose sync state says read but whose findings are missing or older
        # is read again (LocalStore.snapshot_times).
        snapshot_times = getattr(getattr(self.cache, "store", None), "snapshot_times", None)
        stored = snapshot_times(KIND_FINDINGS) if callable(snapshot_times) else None
        for row in rows:
            uuid = row["project_uuid"]
            if uuid in self.running:
                continue
            watched = str(row.get("product_name") or "").lower() in products
            due = plan_version(
                row, watched=watched, now=now, schedule=self.schedule, hinted=self.hinted,
                stored_findings_at=(
                    stored.get(uuid) if stored is not None else "unknown"
                ),
            )
            existing = self.queue.get(uuid)
            if due is None:
                if existing is not None and existing.priority != P0_REQUEST:
                    del self.queue[uuid]
                    dropped.append(uuid)
                continue
            priority, kinds = due
            if existing is None:
                self.queue[uuid] = SyncItem(uuid, priority, kinds, tick)
                queued.append(row)
            else:
                existing.priority = min(existing.priority, priority)
                existing.kinds = tuple(k for k in KINDS if k in set(existing.kinds) | set(kinds))
        # One transaction each, not one per version.
        self.cache.sync_state.set_statuses([row["project_uuid"] for row in queued], STATUS_QUEUED)
        self.cache.sync_state.settle(dropped)
        if 0 < len(queued) <= self.QUEUED_EVENT_LIMIT:
            positions = {
                item.project_uuid: index + 1 for index, item in enumerate(self._ordered(tick))
            }
            for row in queued:
                self._publish_state(
                    row, STATUS_QUEUED, position=positions.get(row["project_uuid"])
                )
        self._plan_dirty = False
        self._next_plan = tick + self.PLAN_INTERVAL_SECONDS
        self._update_backlog()

    def _plan_due(self) -> bool:
        if self._plan_dirty or self._monotonic() >= self._next_plan:
            return True
        watched = getattr(self.interest, "watched", None)
        if callable(watched):
            current = frozenset(str(n).strip().lower() for n in watched() if str(n).strip())
            return current != self._watched_seen
        return False

    def _ordered(self, tick: float) -> list[SyncItem]:
        return sorted(
            self.queue.values(), key=lambda item: (item.effective(tick), item.enqueued_at)
        )

    def next_items(self, slots: int) -> list[SyncItem]:
        chosen = self._ordered(self._monotonic())[: max(0, slots)]
        for item in chosen:
            del self.queue[item.project_uuid]
        return chosen

    # -- one version -----------------------------------------------------------

    def _finding_ids(self, project_uuid: str) -> dict[str, str]:
        findings = self.cache._load_project_cache(self.cache._findings_path(project_uuid), [])
        ids = {}
        for finding in findings if isinstance(findings, list) else []:
            if isinstance(finding, dict) and (key := finding_key(finding)):
                vulnerability = finding.get("vulnerability") or {}
                ids[f"{key[0]}:{key[1]}"] = str(vulnerability.get("vulnId") or key[1])
        return ids

    async def sync_version(self, client: Any, item: SyncItem, budget: Any = None) -> bool:
        uuid = item.project_uuid
        store = self.cache.sync_state
        before = self._finding_ids(uuid)
        store.stage(uuid, at=self._now().isoformat())
        row = store.row(uuid) or {"project_uuid": uuid}
        failures_before = int(row.get("consecutive_failures") or 0)
        self._publish_state(row, "syncing", force=True)
        try:
            if KIND_FINDINGS in item.kinds:
                await self.cache.get_vulnerabilities(client, uuid, refresh=True)
            if KIND_VULNS in item.kinds:
                await self.cache.get_project_vulnerabilities(client, uuid, refresh=True)
            if KIND_BOM in item.kinds:
                await self.cache.get_bom(client, uuid, refresh=True)
        except Exception as exc:
            self._failed(uuid, exc, failures_before)
            return False
        try:
            await self.cache.refresh_fixed_versions(client, uuid, budget=budget)
        except Exception as exc:  # the recommendation's ranges never fail a sync
            logger.warning("Failed to read the fixed versions of %s: %s", uuid, exc)
        kinds, first, generation = store.commit(
            uuid, at=self._now().isoformat(), kinds_read=item.kinds
        )
        if not self.hinted and KIND_FINDINGS in kinds and KIND_BOM not in item.kinds:
            # Without change hints, changed findings are the sign that the
            # components may have changed: read the BOM next.
            store.forget_read(uuid, KIND_BOM)
            self.mark_dirty()
        row = store.row(uuid) or row
        self._publish_state(row, row.get("status") or "synced", force=True)
        if kinds or first:
            after = self._finding_ids(uuid)
            added = sorted(set(after) - set(before))
            new_ids = sorted({after[key] for key in added})
            self._publish(
                "version.synced",
                {
                    "uuid": uuid,
                    "product": row.get("product_name"),
                    "version": row.get("version"),
                    "synced_at": row.get("last_success_at"),
                    "generation": generation,
                    "first_import": first,
                    "kinds_changed": kinds,
                    "findings_added": len(added),
                    "findings_removed": len(set(before) - set(after)),
                    "new_vuln_ids": new_ids[:20],
                    "truncated": len(new_ids) > 20,
                    "vulns_changed": KIND_VULNS in kinds,
                    "analyses_changed_in_dt": int(row.get("analyses_changed_in_dt") or 0),
                    "bom_changed": KIND_BOM in kinds,
                },
                product=row.get("product_name"),
            )
        return True

    def _failed(self, uuid: str, exc: BaseException, failures_before: int = 0) -> None:
        store = self.cache.sync_state
        if not isinstance(exc, SourceUnavailable):
            row = store.row(uuid) or {}
            if int(row.get("consecutive_failures") or 0) == failures_before:
                # Failed outside a recorded read (a cache write, a merge, a
                # busy database): record it, or it would get no backoff.
                store.record_failure(uuid, exc, at=self._now().isoformat())
        store.drop_stage(uuid)
        row = store.row(uuid) or {"project_uuid": uuid}
        if isinstance(exc, SourceUnavailable):
            # The breaker refused the call: not this version's failure. It
            # is planned again once the breaker closes.
            self._publish_state(row, row.get("status") or "", force=True)
            return
        failures = max(1, int(row.get("consecutive_failures") or 1))
        delay = min(
            self.schedule.max_backoff, self.schedule.base_backoff * 2 ** (failures - 1)
        )
        next_due = self._now() + timedelta(seconds=delay)
        store.set_next_due(uuid, next_due.isoformat())
        self._publish_state(row, row.get("status") or STATUS_FAILED, force=True)
        if failures == 1:
            # On the transition only.
            self._publish(
                "version.sync_failed",
                {
                    "uuid": uuid,
                    "product": row.get("product_name"),
                    "error_class": type(exc).__name__,
                    "consecutive_failures": failures,
                    "last_success_at": row.get("last_success_at"),
                    "next_attempt_at": next_due.isoformat(),
                },
                product=row.get("product_name"),
            )
        logger.info("Sync of %s failed (%d in a row): %s", uuid, failures, exc)

    # -- the loop --------------------------------------------------------------

    async def run_cycle(self, client: Any, *, wait: bool = True) -> None:
        """One pass: the export, the project list when due, a probe while
        the breaker is open, then version syncs into the free slots. With
        ``wait=False`` (the loop) the syncs run on while the next passes
        start, so a slow version holds only its own slot and the export and
        a save's wakeup are never blocked behind it."""
        if self.breaker.open:
            if self.breaker.probe_due():
                await self._probe(client)
            if self.breaker.open:
                self._update_backlog()
                return
        limited = self.limited(client)
        self._start_export(limited)
        tick = self._monotonic()
        if tick >= self._next_list_read:
            self._next_list_read = tick + self.cache.refresh_interval_seconds
            await self.cache._refresh_project_list(limited)
            self.mark_dirty()
        if self._plan_due():
            self.plan()
        slots = self.schedule.concurrency - len(self.running)
        items = self.next_items(slots)
        if items:
            budget_type = getattr(self.cache, "read_budget", None)
            budget = budget_type() if callable(budget_type) else None
            for item in items:
                self.running.add(item.project_uuid)
                task = asyncio.create_task(self._run_item(limited, item, budget))
                self._tasks.add(task)
                task.add_done_callback(self._tasks.discard)
            self._update_backlog()
        if wait:
            await self.drain()

    def _start_export(self, client: Any) -> None:
        """The automatic export runs beside the loop, one at a time: an
        export waiting on a project's findings read must not stop the
        list reads, the planning or new syncs."""
        if self._export is not None and not self._export.done():
            return

        async def export() -> None:
            try:
                await self.cache.export_if_automatic(client)
            except Exception as exc:
                logger.warning("Automatic export failed: %s", exc)

        self._export = asyncio.create_task(export())
        self._tasks.add(self._export)
        self._export.add_done_callback(self._tasks.discard)

    async def drain(self) -> None:
        """Wait for the running syncs and the export (tests, shutdown)."""
        while self._tasks:
            await asyncio.gather(*list(self._tasks), return_exceptions=True)

    async def _run_item(self, client: Any, item: SyncItem, budget: Any) -> None:
        try:
            await self.sync_version(client, item, budget)
        except Exception:
            logger.exception("Sync of %s failed unexpectedly", item.project_uuid)
        finally:
            self.running.discard(item.project_uuid)
            self.mark_dirty()
            self._update_backlog()

    async def _probe(self, client: Any) -> None:
        try:
            await self.limited(client).probe()
        except Exception as exc:
            self.breaker.failure(exc)
            return
        self.breaker.success()

    async def run(self, client: Any, *, wakeup: Optional[asyncio.Event] = None) -> None:
        self.recover()
        try:
            while True:
                try:
                    await self.run_cycle(client, wait=False)
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    logger.warning("Source sync cycle failed: %s", exc)
                if wakeup is not None:
                    wakeup.clear()
                    try:
                        await asyncio.wait_for(wakeup.wait(), timeout=1.0)
                    except TimeoutError:
                        pass
                else:
                    await asyncio.sleep(1.0)
        finally:
            # Stop the running syncs before the caller closes the client.
            tasks = list(self._tasks)
            for task in tasks:
                task.cancel()
            # Their reads run in the cache's shared, shielded fetches.
            cancel_fetches = getattr(self.cache, "cancel_inflight_fetches", None)
            if callable(cancel_fetches):
                tasks += cancel_fetches()
            if tasks:
                await asyncio.wait(tasks, timeout=5.0)

    # -- events ----------------------------------------------------------------

    def _publish(self, type: str, data: dict, *, product: Optional[str] = None) -> None:
        if self.hub is None:
            return
        try:
            self.hub.publish(type, data, product=product)
        except Exception:
            logger.exception("Failed to publish %s", type)

    def _publish_state(
        self,
        row: dict[str, Any],
        status: str,
        *,
        force: bool = False,
        position: Optional[int] = None,
    ) -> None:
        uuid = row.get("project_uuid")
        if not uuid:
            return
        if not force and not self._state_throttle.allow(str(uuid), self._monotonic()):
            return
        if force:
            self._state_throttle.last[str(uuid)] = self._monotonic()
        self._publish(
            "version.sync_state",
            {"uuid": uuid, "product": row.get("product_name"), "status": status, "position": position},
            product=row.get("product_name"),
        )

    def _update_backlog(self) -> None:
        backlog = len(self.queue) + len(self.running)
        if backlog == self._backlog:
            return
        self._backlog = backlog
        set_backlog = getattr(self.source_state, "set_backlog", None)
        if callable(set_backlog):
            set_backlog(backlog)

    def _breaker_changed(self, state: str, error_class: Optional[str]) -> None:
        if state == BREAKER_OK:
            # Versions refused while it was open are planned again.
            self.mark_dirty()
        set_state = getattr(self.source_state, "set_state", None)
        if callable(set_state):
            set_state(state, error_class)

    def status(self) -> dict[str, Any]:
        return {
            "source": {
                "name": self.source_name,
                "can_request_analysis": self.can_request_analysis,
            },
            "analysing": sorted(self._analyses),
            "breaker": self.breaker.state,
            "queued": len(self.queue),
            "running": sorted(self.running),
            "watched_products": sorted(self.watched_products()),
        }
