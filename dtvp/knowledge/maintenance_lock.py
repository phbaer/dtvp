"""Process leases excluding stopped-writer maintenance from runtime writers.

The lock file is persistent: unlinking it would split the exclusion domain.
All processes using a journal must share its parent directory and POSIX locks.
"""

import fcntl
import os
import stat
from pathlib import Path


class MaintenanceBusy(ValueError):
    """A runtime or maintenance process already holds an incompatible lease."""


class RuntimeLease:
    def __init__(self, journal_root: Path, *, exclusive: bool = False):
        self._fd = None
        parent = Path(journal_root).resolve().parent
        parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(
            parent / ".knowledge-maintenance.lock",
            os.O_CREAT | os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
        )
        try:
            metadata = os.fstat(fd)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise ValueError("Invalid knowledge maintenance lock file")
            try:
                fcntl.flock(fd, (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH) | fcntl.LOCK_NB)
            except BlockingIOError:
                raise MaintenanceBusy(
                    "Knowledge maintenance requires stopped API, workers and local writers"
                    if exclusive
                    else "Knowledge maintenance is active; retry after maintenance completes"
                ) from None
        except BaseException:
            os.close(fd)
            raise
        self._fd = fd

    def close(self):
        if self._fd is not None:
            fd, self._fd = self._fd, None
            os.close(fd)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def __del__(self):
        self.close()


def maintenance_exclusive(journal_root: Path) -> RuntimeLease:
    return RuntimeLease(journal_root, exclusive=True)
