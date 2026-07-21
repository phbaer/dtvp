"""Fail-closed process coordination for process-local runtime workers."""

from __future__ import annotations

import fcntl
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO


def get_instance_lock_path() -> str:
    return os.getenv("DTVP_INSTANCE_LOCK_PATH", "data/dtvp-runtime.lock").strip()


@dataclass
class ProcessLease:
    """Hold an advisory exclusive lock for the lifetime of one service process."""

    path: str
    service_name: str
    _handle: IO[str] | None = field(default=None, init=False)

    def acquire(self) -> None:
        if self._handle is not None:
            return
        path = Path(self.path)
        path.parent.mkdir(parents=True, exist_ok=True)
        flags = os.O_CREAT | os.O_RDWR
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags, 0o600)
        handle = os.fdopen(descriptor, "r+", encoding="utf-8")
        try:
            metadata = os.fstat(handle.fileno())
            if not stat.S_ISREG(metadata.st_mode):
                raise RuntimeError(f"{self.service_name} lease path must be a regular file")
            os.fchmod(handle.fileno(), 0o600)
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            handle.seek(0)
            handle.truncate()
            handle.write(f"pid={os.getpid()}\n")
            handle.flush()
            os.fsync(handle.fileno())
        except BlockingIOError as exc:
            handle.close()
            raise RuntimeError(
                f"Another {self.service_name} process holds {path}. "
                "Multiple workers require a shared task coordinator and are not supported."
            ) from exc
        except Exception:
            handle.close()
            raise
        self._handle = handle

    def release(self) -> None:
        handle = self._handle
        if handle is None:
            return
        self._handle = None
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        finally:
            handle.close()

    def __enter__(self) -> ProcessLease:
        self.acquire()
        return self

    def __exit__(self, *_args: object) -> None:
        self.release()
