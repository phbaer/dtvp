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
import contextvars
import hashlib
import inspect
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable, Optional

import httpx

from .ports import AnalysisTrigger, BulkFindings, ChangeHints, source_display_name
from .source_sync_state import (
    KIND_BOM,
    KIND_FINDINGS,
    KIND_VULNS,
    STATUS_FAILED,
    STATUS_GONE,
        STATUS_QUEUED,
    SourceUnavailable,
    finding_key,
    portfolio_digest,
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


# What the requests of the current sync or pass cost: set by ``SourceSync``
# around a version sync or a portfolio pass, filled by ``TokenBucket`` and
# ``LimitedSource`` (one dict per task, so concurrent syncs keep apart).
_METRICS: contextvars.ContextVar[Optional[dict[str, float]]] = contextvars.ContextVar(
    "source_sync_metrics", default=None
)
# Work that only uses the budget nobody else wants (the version ranges of
# the recommendation): it waits while any other request waits.
_LOW_PRIORITY: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "source_sync_low_priority", default=False
)


def _count(name: str, amount: float = 1.0) -> None:
    metrics = _METRICS.get()
    if metrics is not None:
        metrics[name] = metrics.get(name, 0.0) + amount


class TokenBucket:
    """One budget for every Dependency-Track request: ``rate`` per second,
    ``burst`` at once. Low-priority work (``_LOW_PRIORITY``) takes a token
    only while no other request waits for one."""

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
        self._waiting = 0

    def _refill(self) -> None:
        now = self._clock()
        self._tokens = min(self.burst, self._tokens + (now - self._updated) * self.rate)
        self._updated = now

    async def acquire(self) -> None:
        started = self._clock()
        if _LOW_PRIORITY.get():
            while True:
                async with self._lock:
                    self._refill()
                    if self._waiting == 0 and self._tokens >= 1:
                        self._tokens -= 1
                        break
                await self._sleep(max(1.0 / self.rate, 0.01))
        else:
            self._waiting += 1
            try:
                async with self._lock:
                    while True:
                        self._refill()
                        if self._tokens >= 1:
                            self._tokens -= 1
                            break
                        await self._sleep((1 - self._tokens) / self.rate)
            finally:
                self._waiting -= 1
        _count("requests")
        _count("budget_wait", self._clock() - started)


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
            started = time.perf_counter()
            try:
                result = await target(*args, **kwargs)
            except Exception as exc:
                self._breaker.failure(exc)
                raise
            finally:
                # Time in the source's calls, budget waits of per-request
                # sources included.
                _count("source_seconds", time.perf_counter() - started)
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
        # The portfolio pass (ADR 0004): the running one, the versions it
        # holds back, when the last one ended, and how many pages it read.
        self._pass: Optional[asyncio.Task] = None
        self._pass_holds: set[str] = set()
        self._pass_ended = float("-inf")
        self._pass_pages: Optional[int] = None
        self.pass_progress: Optional[dict[str, Any]] = None
        # What runs now, per version: its task, phase and timings (status,
        # progress events, cancel); the last pass's and syncs' timings.
        self._items: dict[str, dict[str, Any]] = {}
        self.last_pass: Optional[dict[str, Any]] = None
        self.recent: list[dict[str, Any]] = []
        # The version ranges of the recommendation, read in the budget
        # nobody else wants, between syncs (``_maybe_enrich``).
        self._enrich: Optional[asyncio.Task] = None
        self._next_enrich = 0.0
        self.enrich_progress: Optional[dict[str, Any]] = None
        self._progress_sent = float("-inf")
        self._progress_pending: Optional[asyncio.TimerHandle] = None

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
        chosen = [
            item for item in self._ordered(self._monotonic())
            if item.project_uuid not in self._pass_holds
        ][: max(0, slots)]
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

    def _phase(self, uuid: str, name: str) -> None:
        """A version sync moved on to ``name``; closes the previous phase."""
        entry = self._items.get(uuid)
        if entry is None:
            return
        now = time.perf_counter()
        previous = entry.get("phase")
        if previous:
            timings = entry.setdefault("timings", {})
            timings[previous] = timings.get(previous, 0.0) + now - entry["phase_started"]
        entry["phase"] = name
        entry["phase_started"] = now
        self._progress()

    async def sync_version(self, client: Any, item: SyncItem, budget: Any = None) -> bool:
        """Read the due kinds of one version, staged, and commit once.
        ``budget`` is no longer used here: the version ranges of the
        recommendation are read between syncs (``_maybe_enrich``)."""
        uuid = item.project_uuid
        store = self.cache.sync_state
        entry = self._items.setdefault(uuid, {})
        entry.update(started=time.perf_counter(), timings={}, phase=None)
        metrics: dict[str, float] = {}
        token = _METRICS.set(metrics)
        try:
            self._phase(uuid, "preparing")
            before = self._finding_ids(uuid)
            store.stage(uuid, at=self._now().isoformat())
            row = store.row(uuid) or {"project_uuid": uuid}
            entry.update(product=row.get("product_name"), version=row.get("version"))
            failures_before = int(row.get("consecutive_failures") or 0)
            self._publish_state(row, "syncing", force=True)
            try:
                if KIND_FINDINGS in item.kinds:
                    self._phase(uuid, KIND_FINDINGS)
                    await self.cache.get_vulnerabilities(client, uuid, refresh=True)
                if KIND_VULNS in item.kinds:
                    self._phase(uuid, KIND_VULNS)
                    await self.cache.get_project_vulnerabilities(client, uuid, refresh=True)
                if KIND_BOM in item.kinds:
                    self._phase(uuid, KIND_BOM)
                    await self.cache.get_bom(client, uuid, refresh=True)
            except Exception as exc:
                self._phase(uuid, "failed")
                self._failed(uuid, exc, failures_before)
                return False
            self._phase(uuid, "commit")
            kinds, first, generation = store.commit(
                uuid, at=self._now().isoformat(), kinds_read=item.kinds
            )
            if not self.hinted and KIND_FINDINGS in kinds and KIND_BOM not in item.kinds:
                # Without change hints, changed findings are the sign that the
                # components may have changed: read the BOM next.
                store.forget_read(uuid, KIND_BOM)
                self.mark_dirty()
            row = store.row(uuid) or row
            self._phase(uuid, "events")
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
        finally:
            _METRICS.reset(token)
            self._phase(uuid, None)
            self._record_sync(uuid, item, metrics)
            if "task" not in entry:
                self._items.pop(uuid, None)  # called directly, not by the loop

    RECENT_LIMIT = 20

    def _record_sync(self, uuid: str, item: SyncItem, metrics: dict[str, float]) -> None:
        """One INFO line per sync with where its time went, and the last
        ones in ``status()``."""
        entry = self._items.get(uuid) or {}
        timings = {name: round(seconds, 3) for name, seconds in (entry.get("timings") or {}).items()}
        total = time.perf_counter() - entry.get("started", time.perf_counter())
        summary = {
            "uuid": uuid,
            "product": entry.get("product"),
            "version": entry.get("version"),
            "kinds": list(item.kinds),
            "seconds": round(total, 3),
            "phases": timings,
            "requests": int(metrics.get("requests", 0)),
            "budget_wait_seconds": round(metrics.get("budget_wait", 0.0), 3),
            "source_seconds": round(metrics.get("source_seconds", 0.0), 3),
        }
        self.recent = (self.recent + [summary])[-self.RECENT_LIMIT:]
        logger.info(
            "Synced %s %s in %.1f s (%s); %d request(s), %.1f s waiting for the budget, "
            "%.1f s in the source",
            entry.get("product") or uuid, entry.get("version") or "", total,
            ", ".join(f"{name} {seconds:.1f} s" for name, seconds in timings.items()) or "nothing",
            summary["requests"], summary["budget_wait_seconds"], summary["source_seconds"],
        )

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
        self._maybe_start_pass(limited)
        slots = self.schedule.concurrency - len(self.running)
        items = self.next_items(slots)
        if items:
            for item in items:
                self.running.add(item.project_uuid)
                task = asyncio.create_task(self._run_item(limited, item, None))
                self._items[item.project_uuid] = {"task": task}
                self._tasks.add(task)
                task.add_done_callback(self._tasks.discard)
            self._update_backlog()
        self._maybe_enrich(limited)
        if wait:
            await self.drain()

    # -- the portfolio pass (ADR 0004, "Portfolio pass") ------------------------

    # A pass is worth it when more versions are due for a findings re-read
    # than it takes pages (at least this many), and at most this often.
    PASS_MIN_VERSIONS = 5
    PASS_MIN_INTERVAL_SECONDS = 60.0

    def _pass_candidates(self) -> list[str]:
        """Queued versions a portfolio list can settle: due for a findings
        re-read, read before (a first import needs the version's own read),
        not running. The safety re-read stays a full read of the version:
        it catches what a portfolio list cannot show (justification and
        response)."""
        rows = {row["project_uuid"]: row for row in self.cache.sync_state.rows()}
        return [
            uuid
            for uuid, item in self.queue.items()
            if KIND_FINDINGS in item.kinds
            and item.priority != P4_SAFETY
            and uuid not in self.running
            and (rows.get(uuid) or {}).get("last_success_at")
        ]

    # Requests a version read takes one by one (findings, vulnerability
    # records, BOM): a pass is worth it once it costs fewer pages than that.
    REQUESTS_PER_VERSION = 3

    def _maybe_start_pass(self, client: Any) -> None:
        if not isinstance(getattr(client, "_source", client), BulkFindings):
            return
        candidates = self._pass_candidates()
        if self._pass is not None and not self._pass.done():
            # Versions that come due while a pass runs wait for the next
            # pass rather than being read one by one beside it.
            if len(candidates) >= self.PASS_MIN_VERSIONS:
                self._pass_holds |= set(candidates)
            return
        requested = any(
            self.queue[uuid].priority == P0_REQUEST for uuid in candidates
        )
        # A person's request does not wait for the interval between passes,
        # unless the last pass failed (no retry every second).
        last_failed = (self.last_pass or {}).get("outcome") == "failed"
        if (
            (not requested or last_failed)
            and self._monotonic() - self._pass_ended < self.PASS_MIN_INTERVAL_SECONDS
        ):
            return
        if len(candidates) < self.PASS_MIN_VERSIONS:
            return
        if (self._pass_pages or 0) > len(candidates) * self.REQUESTS_PER_VERSION:
            return
        self._pass_holds = set(candidates)
        self._pass = asyncio.create_task(self._portfolio_pass(client, candidates))
        self._tasks.add(self._pass)
        self._pass.add_done_callback(self._tasks.discard)

    async def _portfolio_pass(self, client: Any, candidates: list[str]) -> None:
        """One portfolio-wide findings list instead of a read per version:
        a version whose share of it shows what its last findings read showed
        is marked checked; the others are read one by one as planned."""
        started_at = self._now().isoformat()
        size = int(_env_float("DTVP_SYNC_PORTFOLIO_PAGE_SIZE", 1000.0, 1.0))
        # The analysis hints as the pass starts: what it reads covers them.
        hints = {
            row["project_uuid"]: row.get("source_analysis_hint")
            for row in self.cache.sync_state.rows()
            if row["project_uuid"] in set(candidates)
        }
        unchanged: list[str] = []
        metrics: dict[str, float] = {}
        token = _METRICS.set(metrics)
        started = time.perf_counter()
        last_page = [started]
        page_seconds: list[float] = []
        timings: dict[str, float] = {}
        reasons: dict[str, int] = {}

        def on_page(read: int, total: int) -> None:
            now = time.perf_counter()
            page_seconds.append(now - last_page[0])
            last_page[0] = now
            self.pass_progress = {
                "phase": "reading", "versions": len(candidates),
                "pages_read": read, "pages_total": total,
            }
            self._publish(
                "source.portfolio_pass",
                {"phase": "reading", "pages_read": read, "pages_total": total},
            )
            self._progress()

        outcome = "failed"
        try:
            self.pass_progress = {
                "phase": "reading", "versions": len(candidates),
                "pages_read": 0, "pages_total": None,
            }
            self._publish("source.portfolio_pass", {"phase": "started", "versions": len(candidates)})
            self._progress(force=True)
            by_version = await client.portfolio_findings(page_size=size, on_page=on_page)
            timings["list"] = time.perf_counter() - started
            compare_started = time.perf_counter()
            known = self.cache.sync_state.portfolio_digests()
            # Versions read before the pass existed have no digest yet: seed
            # it from their stored findings, so the first pass after the
            # upgrade already settles the unchanged ones. The stored findings
            # carry DTVP's own values over the source's; where those differ
            # (an assessment not exported yet) the version is read once,
            # which is the safe side.
            seeded = {
                uuid: portfolio_digest(stored)
                for uuid in candidates
                if not known.get(uuid)
                and isinstance(
                    stored := self.cache._load_project_cache(
                        self.cache._findings_path(uuid), None
                    ),
                    list,
                )
            }
            if seeded:
                self.cache.sync_state.set_portfolio_digests(seeded)
                known.update(seeded)
            for uuid in candidates:
                recorded = known.get(uuid)
                if not recorded:
                    reasons["no_digest"] = reasons.get("no_digest", 0) + 1
                elif uuid not in by_version:
                    reasons["not_in_list"] = reasons.get("not_in_list", 0) + 1
                elif recorded == portfolio_digest(by_version[uuid]):
                    unchanged.append(uuid)
                else:
                    reasons["changed"] = reasons.get("changed", 0) + 1
            reasons["unchanged"] = len(unchanged)
            timings["compare"] = time.perf_counter() - compare_started
            mark_started = time.perf_counter()
            answered = self.cache.sync_state.mark_checked(
                unchanged, at=self._now().isoformat(), started_at=started_at,
                analysis_hints=hints,
            )
            timings["mark_checked"] = time.perf_counter() - mark_started
            for uuid in unchanged:
                item = self.queue.get(uuid)
                if item is None:
                    continue
                remaining = tuple(k for k in item.kinds if k != KIND_FINDINGS)
                if item.priority == P0_REQUEST or not remaining:
                    # Answered (a request) or nothing else due: settled.
                    del self.queue[uuid]
                else:
                    item.kinds = remaining
            self._pass_pages = (self.pass_progress or {}).get("pages_total")
            outcome = "done"
            logger.info(
                "Portfolio pass in %.1f s: %d version(s) unchanged, %d to read one by one "
                "(%s); %s page(s) in %.1f s (slowest %.1f s), %.1f s waiting for the "
                "budget, compare %.2f s, marking %.2f s; %d request(s) answered",
                time.perf_counter() - started, len(unchanged), len(candidates) - len(unchanged),
                ", ".join(f"{k} {v}" for k, v in sorted(reasons.items()) if k != "unchanged") or "none",
                self._pass_pages, timings.get("list", 0.0), max(page_seconds, default=0.0),
                metrics.get("budget_wait", 0.0), timings.get("compare", 0.0),
                timings.get("mark_checked", 0.0), len(answered),
            )
            self._publish(
                "source.portfolio_pass",
                {
                    "phase": "done",
                    "unchanged": len(unchanged),
                    "changed": len(candidates) - len(unchanged),
                    "pages": self._pass_pages,
                    "reasons": reasons,
                },
            )
        except asyncio.CancelledError:
            outcome = "cancelled"
            logger.info("Portfolio pass cancelled")
            self._publish("source.portfolio_pass", {"phase": "cancelled"})
            raise
        except Exception as exc:
            # The versions are read one by one, as without a pass.
            logger.warning("Portfolio pass failed, reading versions one by one: %s", exc)
            self._publish("source.portfolio_pass", {"phase": "failed", "error_class": type(exc).__name__})
        finally:
            _METRICS.reset(token)
            self.last_pass = {
                "outcome": outcome,
                "versions": len(candidates),
                "reasons": reasons,
                "pages": len(page_seconds),
                "seconds": round(time.perf_counter() - started, 3),
                "timings": {name: round(value, 3) for name, value in timings.items()},
                "page_seconds_max": round(max(page_seconds, default=0.0), 3),
                "requests": int(metrics.get("requests", 0)),
                "budget_wait_seconds": round(metrics.get("budget_wait", 0.0), 3),
            }
            self._pass_holds = set()
            self._pass_ended = self._monotonic()
            self.pass_progress = None
            self.mark_dirty()
            self._update_backlog()
            self._progress(force=True)
            wake = getattr(self.cache, "wake_sync", None)
            if callable(wake):
                wake()

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

    # -- the version ranges of the recommendation ------------------------------

    # How often the ranges are looked at when nothing else is to do.
    ENRICH_INTERVAL_SECONDS = 60.0

    def _maybe_enrich(self, client: Any) -> None:
        """Read the version ranges (``refresh_fixed_versions``) only when no
        version waits or runs and no pass runs, at low priority in the
        budget: they enrich the recommendation and must never slow a read
        down. (They used to run inside every version sync, with a fresh
        allowance of reads each time.)"""
        if self._enrich is not None and not self._enrich.done():
            return
        if self.queue or self.running or (self._pass is not None and not self._pass.done()):
            return
        if self._monotonic() < self._next_enrich:
            return
        refresh = getattr(self.cache, "refresh_fixed_versions", None)
        if not callable(refresh):
            return
        self._next_enrich = self._monotonic() + self.ENRICH_INTERVAL_SECONDS
        self._enrich = asyncio.create_task(self._enrich_ranges(client))
        self._tasks.add(self._enrich)
        self._enrich.add_done_callback(self._tasks.discard)

    async def _enrich_ranges(self, client: Any) -> None:
        token = _LOW_PRIORITY.set(True)
        reads = checked = 0
        try:
            budget_type = getattr(self.cache, "read_budget", None)
            budget = budget_type() if callable(budget_type) else None
            products = self.watched_products()
            rows = sorted(
                (
                    row for row in self.cache.sync_state.rows()
                    if row.get("last_success_at") and row.get("status") != STATUS_GONE
                ),
                key=lambda row: str(row.get("product_name") or "").lower() not in products,
            )
            self.enrich_progress = {"versions": len(rows), "checked": 0, "reads": 0}
            for row in rows:
                if self.queue or self.running or (self._pass is not None and not self._pass.done()):
                    break  # reads come first; the rest follows next time
                if budget is not None and getattr(budget, "remaining", 1) <= 0:
                    break
                reads += await self.cache.refresh_fixed_versions(
                    client, row["project_uuid"], budget=budget
                ) or 0
                checked += 1
                self.enrich_progress = {"versions": len(rows), "checked": checked, "reads": reads}
                self._progress()
            if reads:
                logger.info(
                    "Read the version ranges of %d vulnerabilit%s for %d version(s)",
                    reads, "y" if reads == 1 else "ies", checked,
                )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.warning("Reading the version ranges failed: %s", exc)
        finally:
            _LOW_PRIORITY.reset(token)
            self.enrich_progress = None
            self._progress(force=True)

    # -- cancel ------------------------------------------------------------------

    CANCEL_SCOPES = ("pass", "requests", "running")

    def cancel(self, scope: Optional[list[str]] = None, *, by: Optional[str] = None) -> dict[str, Any]:
        """Stop what runs on a person's word: the portfolio pass, the waiting
        requests, the running version syncs (their staged reads are dropped,
        each version keeps what it had). Nothing of it counts as a failure:
        no backoff, no breaker. Returns what was cancelled."""
        wanted = set(scope or self.CANCEL_SCOPES)
        result: dict[str, Any] = {"pass": False, "requests": [], "running": []}
        if "pass" in wanted and self._pass is not None and not self._pass.done():
            self._pass.cancel()
            result["pass"] = True
        if "requests" in wanted:
            withdrawn = self.cache.sync_state.cancel_requests(
                at=self._now().isoformat(), by=by
            )
            for uuid in withdrawn:
                item = self.queue.get(uuid)
                if item is not None and item.priority == P0_REQUEST:
                    del self.queue[uuid]
            result["requests"] = withdrawn
        if "running" in wanted:
            for uuid, entry in list(self._items.items()):
                task = entry.get("task")
                if task is not None and not task.done():
                    task.cancel()
                    result["running"].append(uuid)
            # Their reads run in the cache's shared, shielded fetches.
            cancel_fetches = getattr(self.cache, "cancel_inflight_fetches", None)
            if result["running"] and callable(cancel_fetches):
                cancel_fetches(result["running"])
            if self._enrich is not None and not self._enrich.done():
                self._enrich.cancel()
        if result["pass"] or result["requests"] or result["running"]:
            logger.info(
                "%s cancelled: %s",
                by or "someone",
                ", ".join(
                    part for part in (
                        "the portfolio pass" if result["pass"] else "",
                        f"{len(result['requests'])} request(s)" if result["requests"] else "",
                        f"{len(result['running'])} running sync(s)" if result["running"] else "",
                    ) if part
                ),
            )
        self.mark_dirty()
        self._update_backlog()
        self._publish("source.sync_cancelled", {**result, "by": by})
        self._progress(force=True)
        return result

    # -- progress ----------------------------------------------------------------

    # At most this many progress events per second.
    PROGRESS_INTERVAL_SECONDS = 0.5

    def progress(self) -> dict[str, Any]:
        """What runs now: the pass, the running syncs with their phase, the
        version ranges, and how many wait."""
        now = time.perf_counter()
        running = []
        for uuid in sorted(self.running):
            entry = self._items.get(uuid) or {}
            running.append(
                {
                    "uuid": uuid,
                    "product": entry.get("product"),
                    "version": entry.get("version"),
                    "phase": entry.get("phase"),
                    "seconds": round(now - entry["started"], 1) if "started" in entry else None,
                }
            )
        return {
            "pass": self.pass_progress,
            "running": running,
            "queued": len(self.queue),
            "requested": sum(1 for item in self.queue.values() if item.priority == P0_REQUEST),
            "ranges": self.enrich_progress,
        }

    def _progress(self, *, force: bool = False) -> None:
        """Publish ``source.sync_progress``, at most every
        ``PROGRESS_INTERVAL_SECONDS``; a throttled update is sent once the
        interval has passed, so the last state always arrives."""
        if self.hub is None:
            return
        now = time.monotonic()
        wait = self._progress_sent + self.PROGRESS_INTERVAL_SECONDS - now
        if not force and wait > 0:
            if self._progress_pending is None:
                try:
                    loop = asyncio.get_running_loop()
                except RuntimeError:
                    return
                self._progress_pending = loop.call_later(wait, self._send_progress)
            return
        self._send_progress()

    def _send_progress(self) -> None:
        if self._progress_pending is not None:
            self._progress_pending.cancel()
            self._progress_pending = None
        self._progress_sent = time.monotonic()
        self._publish("source.sync_progress", self.progress())

    async def drain(self) -> None:
        """Wait for the running syncs and the export (tests, shutdown)."""
        while self._tasks:
            await asyncio.gather(*list(self._tasks), return_exceptions=True)

    async def _run_item(self, client: Any, item: SyncItem, budget: Any) -> None:
        uuid = item.project_uuid
        try:
            await self.sync_version(client, item, budget)
        except asyncio.CancelledError:
            # Cancelled by a person (``cancel``) or at shutdown: the staged
            # read is dropped, the version keeps what it had; no failure,
            # no backoff.
            store = self.cache.sync_state
            store.drop_stage(uuid)
            row = store.row(uuid) or {"project_uuid": uuid}
            self._publish_state(row, "cancelled", force=True)
            logger.info("Sync of %s cancelled", uuid)
        except Exception:
            logger.exception("Sync of %s failed unexpectedly", uuid)
        finally:
            self.running.discard(uuid)
            self._items.pop(uuid, None)
            self.mark_dirty()
            self._update_backlog()
            self._progress(force=not self.running)

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
            "portfolio_pass": self.pass_progress,
            "last_portfolio_pass": self.last_pass,
            "progress": self.progress(),
            "recent_syncs": list(self.recent),
            "breaker": self.breaker.state,
            "queued": len(self.queue),
            "running": sorted(self.running),
            "watched_products": sorted(self.watched_products()),
        }
