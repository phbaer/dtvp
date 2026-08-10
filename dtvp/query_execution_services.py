import asyncio
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, Hashable


class QueryCapacityError(RuntimeError):
    pass


class QuerySupersededError(RuntimeError):
    pass


async def _await_thread_future(future: asyncio.Future[Any]) -> Any:
    if sys.version_info[:3] != (3, 14, 0):
        return await future

    # CPython 3.14.0 can leave the selector asleep when a concurrent worker
    # completes during callback registration. Patch releases use the normal
    # await path; only the affected initial release gets a timer-backed wakeup.
    while not future.done():
        await asyncio.sleep(0.01)
    return future.result()


class BoundedQueryExecutor:
    """Isolate CPU-heavy task queries and keep their pending queue bounded."""

    def __init__(
        self,
        *,
        workers_provider: Callable[[], int],
        max_pending_provider: Callable[[], int],
    ):
        self.workers_provider = workers_provider
        self.max_pending_provider = max_pending_provider
        self._lock = threading.RLock()
        self._executor: ThreadPoolExecutor | None = None
        self._workers = 0
        self._outstanding = 0
        self._active = 0
        self._key_outstanding: dict[Hashable, int] = {}
        self._latest_generations: dict[Hashable, int] = {}
        self._accepted_total = 0
        self._completed_total = 0
        self._rejected_total = 0
        self._superseded_total = 0
        self._failed_total = 0
        self._queue_seconds_total = 0.0
        self._execution_seconds_total = 0.0
        self._max_outstanding = 0

    def _get_executor_locked(self) -> ThreadPoolExecutor:
        workers = max(1, int(self.workers_provider()))
        if self._executor is None:
            self._workers = workers
            self._executor = ThreadPoolExecutor(
                max_workers=workers,
                thread_name_prefix="dtvp-group-query",
            )
        return self._executor

    def _is_superseded(self, key: Hashable | None, generation: int) -> bool:
        if key is None or generation <= 0:
            return False
        with self._lock:
            return self._latest_generations.get(key, generation) > generation

    async def run(
        self,
        function: Callable[..., Any],
        *args: Any,
        key: Hashable | None = None,
        generation: int = 0,
        **kwargs: Any,
    ) -> Any:
        with self._lock:
            executor = self._get_executor_locked()
            if key is not None and generation > 0:
                self._latest_generations[key] = max(
                    generation,
                    self._latest_generations.get(key, generation),
                )

            capacity = self._workers + max(0, int(self.max_pending_provider()))
            if self._outstanding >= capacity:
                self._rejected_total += 1
                raise QueryCapacityError(
                    f"Grouped-query capacity is full ({capacity} requests)"
                )

            self._outstanding += 1
            self._accepted_total += 1
            self._max_outstanding = max(
                self._max_outstanding,
                self._outstanding,
            )
            if key is not None:
                self._key_outstanding[key] = self._key_outstanding.get(key, 0) + 1

        queued_at = time.perf_counter()

        def finish_outstanding() -> None:
            with self._lock:
                self._outstanding = max(0, self._outstanding - 1)
                if key is not None:
                    remaining = self._key_outstanding.get(key, 1) - 1
                    if remaining > 0:
                        self._key_outstanding[key] = remaining
                    else:
                        self._key_outstanding.pop(key, None)
                        self._latest_generations.pop(key, None)

        def invoke() -> Any:
            started_at = time.perf_counter()
            with self._lock:
                self._active += 1
                self._queue_seconds_total += started_at - queued_at
            try:
                if self._is_superseded(key, generation):
                    raise QuerySupersededError("Grouped query was superseded")
                result = function(*args, **kwargs)
                if self._is_superseded(key, generation):
                    raise QuerySupersededError("Grouped query was superseded")
                with self._lock:
                    self._completed_total += 1
                return result
            except QuerySupersededError:
                with self._lock:
                    self._superseded_total += 1
                raise
            except BaseException:
                with self._lock:
                    self._failed_total += 1
                raise
            finally:
                finished_at = time.perf_counter()
                with self._lock:
                    self._active = max(0, self._active - 1)
                    self._execution_seconds_total += finished_at - started_at
                finish_outstanding()

        try:
            future = asyncio.get_running_loop().run_in_executor(executor, invoke)
        except RuntimeError:
            # Submission can fail during application shutdown, before invoke
            # has a chance to release the reserved capacity.
            finish_outstanding()
            raise
        # A cancelled asyncio waiter must not cancel a queued thread future:
        # invoke() owns the accounting cleanup and may not have started yet.
        return await _await_thread_future(asyncio.shield(future))

    def stats(self) -> dict[str, Any]:
        with self._lock:
            workers = self._workers or max(1, int(self.workers_provider()))
            max_pending = max(0, int(self.max_pending_provider()))
            return {
                "workers": workers,
                "max_pending": max_pending,
                "capacity": workers + max_pending,
                "outstanding": self._outstanding,
                "active": self._active,
                "queued": max(0, self._outstanding - self._active),
                "accepted_total": self._accepted_total,
                "completed_total": self._completed_total,
                "rejected_total": self._rejected_total,
                "superseded_total": self._superseded_total,
                "failed_total": self._failed_total,
                "max_outstanding": self._max_outstanding,
                "queue_time_ms_total": round(self._queue_seconds_total * 1000, 3),
                "execution_time_ms_total": round(
                    self._execution_seconds_total * 1000,
                    3,
                ),
            }

    def shutdown(self) -> None:
        with self._lock:
            executor = self._executor
            self._executor = None
            self._workers = 0
            self._outstanding = 0
            self._active = 0
            self._key_outstanding.clear()
            self._latest_generations.clear()
        if executor is not None:
            executor.shutdown(wait=False, cancel_futures=True)


class BoundedWorkExecutor:
    """Run background CPU work in a dedicated pool with async backpressure."""

    def __init__(
        self,
        *,
        name: str,
        workers_provider: Callable[[], int],
        max_pending_provider: Callable[[], int],
    ):
        self.name = name
        self.workers_provider = workers_provider
        self.max_pending_provider = max_pending_provider
        self._lock = threading.RLock()
        self._executor: ThreadPoolExecutor | None = None
        self._semaphore: asyncio.Semaphore | None = None
        self._workers = 0
        self._max_pending = 0
        self._waiting = 0
        self._outstanding = 0
        self._active = 0
        self._accepted_total = 0
        self._completed_total = 0
        self._failed_total = 0
        self._queue_seconds_total = 0.0
        self._execution_seconds_total = 0.0
        self._max_outstanding = 0

    def _initialize_locked(
        self,
    ) -> tuple[ThreadPoolExecutor, asyncio.Semaphore]:
        if self._executor is None:
            self._workers = max(1, int(self.workers_provider()))
            self._max_pending = max(0, int(self.max_pending_provider()))
            self._executor = ThreadPoolExecutor(
                max_workers=self._workers,
                thread_name_prefix=self.name,
            )
            self._semaphore = asyncio.Semaphore(
                self._workers + self._max_pending
            )
        assert self._semaphore is not None
        return self._executor, self._semaphore

    async def run(
        self,
        function: Callable[..., Any],
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        loop = asyncio.get_running_loop()
        with self._lock:
            executor, semaphore = self._initialize_locked()
            self._waiting += 1
        try:
            await semaphore.acquire()
        finally:
            with self._lock:
                self._waiting = max(0, self._waiting - 1)

        queued_at = time.perf_counter()
        with self._lock:
            self._outstanding += 1
            self._accepted_total += 1
            self._max_outstanding = max(
                self._max_outstanding,
                self._outstanding,
            )

        def invoke() -> Any:
            started_at = time.perf_counter()
            with self._lock:
                self._active += 1
                self._queue_seconds_total += started_at - queued_at
            try:
                result = function(*args, **kwargs)
                with self._lock:
                    self._completed_total += 1
                return result
            except BaseException:
                with self._lock:
                    self._failed_total += 1
                raise
            finally:
                finished_at = time.perf_counter()
                with self._lock:
                    self._active = max(0, self._active - 1)
                    self._outstanding = max(0, self._outstanding - 1)
                    self._execution_seconds_total += finished_at - started_at
                try:
                    loop.call_soon_threadsafe(semaphore.release)
                except RuntimeError:
                    pass

        try:
            future = loop.run_in_executor(executor, invoke)
        except BaseException:
            with self._lock:
                self._outstanding = max(0, self._outstanding - 1)
            semaphore.release()
            raise
        # Keep queued work alive after caller cancellation so invoke() can
        # release its reserved semaphore slot and outstanding counter.
        return await _await_thread_future(asyncio.shield(future))

    def stats(self) -> dict[str, Any]:
        with self._lock:
            workers = self._workers or max(1, int(self.workers_provider()))
            max_pending = (
                self._max_pending
                if self._executor is not None
                else max(0, int(self.max_pending_provider()))
            )
            return {
                "workers": workers,
                "max_pending": max_pending,
                "capacity": workers + max_pending,
                "waiting": self._waiting,
                "outstanding": self._outstanding,
                "active": self._active,
                "queued": max(0, self._outstanding - self._active),
                "accepted_total": self._accepted_total,
                "completed_total": self._completed_total,
                "failed_total": self._failed_total,
                "max_outstanding": self._max_outstanding,
                "queue_time_ms_total": round(self._queue_seconds_total * 1000, 3),
                "execution_time_ms_total": round(
                    self._execution_seconds_total * 1000,
                    3,
                ),
            }

    def shutdown(self) -> None:
        with self._lock:
            executor = self._executor
            self._executor = None
            self._semaphore = None
            self._workers = 0
            self._max_pending = 0
        if executor is not None:
            executor.shutdown(wait=False, cancel_futures=True)
