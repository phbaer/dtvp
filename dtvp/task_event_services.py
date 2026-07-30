import asyncio
import threading
from typing import Callable


class TaskEventHub:
    """Fan out task mutations without a polling loop per connected client."""

    def __init__(self):
        self._lock = threading.RLock()
        self._versions: dict[str, int] = {}
        self._waiters: dict[str, set[asyncio.Future[None]]] = {}
        self._payloads: dict[str, tuple[int, str]] = {}

    def version(self, task_id: str) -> int:
        with self._lock:
            return self._versions.get(task_id, 0)

    def notify(self, task_id: str) -> int:
        with self._lock:
            version = self._versions.get(task_id, 0) + 1
            self._versions[task_id] = version
            self._payloads.pop(task_id, None)
            waiters = tuple(self._waiters.pop(task_id, ()))

        for waiter in waiters:
            loop = waiter.get_loop()

            def wake(target: asyncio.Future[None] = waiter) -> None:
                if not target.done():
                    target.set_result(None)

            loop.call_soon_threadsafe(wake)
        return version

    async def wait(
        self,
        task_id: str,
        after_version: int,
        *,
        timeout_seconds: float,
    ) -> int:
        loop = asyncio.get_running_loop()
        waiter = loop.create_future()
        with self._lock:
            current = self._versions.get(task_id, 0)
            if current > after_version:
                return current
            self._waiters.setdefault(task_id, set()).add(waiter)

        try:
            await asyncio.wait_for(waiter, timeout=timeout_seconds)
        except TimeoutError:
            pass
        finally:
            with self._lock:
                task_waiters = self._waiters.get(task_id)
                if task_waiters is not None:
                    task_waiters.discard(waiter)
                    if not task_waiters:
                        self._waiters.pop(task_id, None)
        return self.version(task_id)

    def serialized_payload(
        self,
        task_id: str,
        version: int,
        builder: Callable[[], str],
    ) -> str:
        with self._lock:
            cached = self._payloads.get(task_id)
            if cached is not None and cached[0] == version:
                return cached[1]

        payload = builder()
        with self._lock:
            if self._versions.get(task_id, 0) == version:
                self._payloads[task_id] = (version, payload)
        return payload

    def forget(self, task_id: str) -> None:
        with self._lock:
            self._versions.pop(task_id, None)
            self._payloads.pop(task_id, None)
