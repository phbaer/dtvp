import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, Hashable


class QueryCapacityError(RuntimeError):
    pass


class QuerySupersededError(RuntimeError):
    pass


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
        self._key_outstanding: dict[Hashable, int] = {}
        self._latest_generations: dict[Hashable, int] = {}

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
                raise QueryCapacityError(
                    f"Grouped-query capacity is full ({capacity} requests)"
                )

            self._outstanding += 1
            if key is not None:
                self._key_outstanding[key] = self._key_outstanding.get(key, 0) + 1

        def invoke() -> Any:
            if self._is_superseded(key, generation):
                raise QuerySupersededError("Grouped query was superseded")
            result = function(*args, **kwargs)
            if self._is_superseded(key, generation):
                raise QuerySupersededError("Grouped query was superseded")
            return result

        try:
            return await asyncio.get_running_loop().run_in_executor(executor, invoke)
        finally:
            with self._lock:
                self._outstanding = max(0, self._outstanding - 1)
                if key is not None:
                    remaining = self._key_outstanding.get(key, 1) - 1
                    if remaining > 0:
                        self._key_outstanding[key] = remaining
                    else:
                        self._key_outstanding.pop(key, None)
                        self._latest_generations.pop(key, None)

    def shutdown(self) -> None:
        with self._lock:
            executor = self._executor
            self._executor = None
            self._workers = 0
            self._outstanding = 0
            self._key_outstanding.clear()
            self._latest_generations.clear()
        if executor is not None:
            executor.shutdown(wait=False, cancel_futures=True)
