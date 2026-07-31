"""Bounded reads for files and Git blobs from untrusted repositories."""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any

DEFAULT_MAX_FILE_BYTES = 1_000_000
DEFAULT_MAX_TOTAL_BYTES = 24_000_000


@dataclass
class RepositoryReadBudget:
    """Track a byte budget shared by one repository-analysis operation."""

    remaining_bytes: int = DEFAULT_MAX_TOTAL_BYTES

    def permits(self, size: int) -> bool:
        return 0 <= size <= self.remaining_bytes

    def consume(self, size: int) -> None:
        self.remaining_bytes = max(0, self.remaining_bytes - size)


def _inside_repository(repo_real: str, candidate_real: str) -> bool:
    try:
        return os.path.commonpath((repo_real, candidate_real)) == repo_real
    except ValueError:
        return False


def _open_bounded_repository_file(
    repo_path: str,
    file_path: str,
    *,
    max_bytes: int,
    budget: RepositoryReadBudget | None,
) -> int | None:
    if max_bytes < 0:
        return None

    try:
        repo_real = os.path.realpath(repo_path)
        if not os.path.isdir(repo_real):
            return None

        candidate = os.path.abspath(file_path)
        if not _inside_repository(repo_real, candidate):
            return None

        before = os.lstat(candidate)
        if not stat.S_ISREG(before.st_mode) or before.st_size > max_bytes:
            return None
        if budget is not None and not budget.permits(before.st_size):
            return None

        candidate_real = os.path.realpath(candidate)
        if not _inside_repository(repo_real, candidate_real):
            return None

        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        flags |= getattr(os, "O_NONBLOCK", 0)
        descriptor = os.open(candidate, flags)
        try:
            after = os.fstat(descriptor)
            if (
                not stat.S_ISREG(after.st_mode)
                or after.st_size > max_bytes
                or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
            ):
                os.close(descriptor)
                return None
            if budget is not None and not budget.permits(after.st_size):
                os.close(descriptor)
                return None

            # Recheck the object reached by the open descriptor. This closes
            # parent-directory replacement races on Linux, the packaged runtime.
            if os.path.exists("/proc/self/fd"):
                opened_real = os.path.realpath(f"/proc/self/fd/{descriptor}")
                if not _inside_repository(repo_real, opened_real):
                    os.close(descriptor)
                    return None
            return descriptor
        except Exception:
            os.close(descriptor)
            raise
    except (OSError, ValueError):
        return None


def repository_file_is_safe(
    repo_path: str,
    file_path: str,
    *,
    max_bytes: int = DEFAULT_MAX_FILE_BYTES,
) -> bool:
    """Return whether *file_path* is a bounded regular file inside *repo_path*."""

    descriptor = _open_bounded_repository_file(
        repo_path,
        file_path,
        max_bytes=max_bytes,
        budget=None,
    )
    if descriptor is None:
        return False
    os.close(descriptor)
    return True


def read_repository_text(
    repo_path: str,
    file_path: str,
    *,
    max_bytes: int = DEFAULT_MAX_FILE_BYTES,
    budget: RepositoryReadBudget | None = None,
) -> str | None:
    """Read a repository file without following links or exceeding byte caps."""

    descriptor = _open_bounded_repository_file(
        repo_path,
        file_path,
        max_bytes=max_bytes,
        budget=budget,
    )
    if descriptor is None:
        return None

    chunks: list[bytes] = []
    total = 0
    try:
        while total <= max_bytes:
            chunk = os.read(descriptor, min(64 * 1024, max_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        if total > max_bytes:
            return None
    except OSError:
        return None
    finally:
        os.close(descriptor)

    if budget is not None:
        if not budget.permits(total):
            return None
        budget.consume(total)
    return b"".join(chunks).decode("utf-8", errors="ignore")


def read_repository_blob_text(
    repo: Any,
    ref: str,
    path: str,
    *,
    max_bytes: int = DEFAULT_MAX_FILE_BYTES,
    budget: RepositoryReadBudget | None = None,
) -> str | None:
    """Read a regular file from a Git tree without materializing an unbounded blob."""

    try:
        normalized = PurePosixPath(path)
        if normalized.is_absolute() or ".." in normalized.parts or "\x00" in path:
            return None
        blob = repo.tree(ref) / normalized.as_posix()
        if blob.type != "blob" or blob.mode == 0o120000 or blob.size > max_bytes:
            return None
        if budget is not None and not budget.permits(blob.size):
            return None
        content = blob.data_stream.read(max_bytes + 1)
    except Exception:
        return None

    if len(content) > max_bytes:
        return None
    if budget is not None:
        if not budget.permits(len(content)):
            return None
        budget.consume(len(content))
    return content.decode("utf-8", errors="ignore")
