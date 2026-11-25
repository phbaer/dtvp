import json
import os
import tempfile
from typing import Any

# Mode of a file written for the first time when no mode is given. A file
# that already exists keeps its mode.
DEFAULT_FILE_MODE = 0o644


def read_text(path: str, encoding: str = "utf-8") -> str:
    with open(path, "r", encoding=encoding) as file_handle:
        return file_handle.read()


def fsync_directory(directory: str) -> None:
    """Make a rename in ``directory`` durable. Filesystems that cannot sync a
    directory are skipped."""
    try:
        descriptor = os.open(directory or ".", os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(descriptor)
    except OSError:
        pass
    finally:
        os.close(descriptor)


def atomic_write_bytes(path: str, data: bytes, *, mode: int | None = None) -> None:
    """Replace ``path`` with ``data`` so that a reader sees the old or the new
    content, never a part.

    The data goes to a temporary file in the same directory, is synced, and
    is renamed over the target; the directory is synced after. The
    temporary file is removed on any failure. Without ``mode`` an existing
    file keeps its mode and a new one gets ``DEFAULT_FILE_MODE``.
    """
    path = os.fspath(path)
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    if mode is None:
        try:
            mode = os.stat(path).st_mode & 0o7777
        except FileNotFoundError:
            mode = DEFAULT_FILE_MODE
    descriptor, tmp_path = tempfile.mkstemp(dir=directory, prefix=".tmp-")
    try:
        with os.fdopen(descriptor, "wb") as file_handle:
            file_handle.write(data)
            file_handle.flush()
            os.fsync(file_handle.fileno())
        os.chmod(tmp_path, mode)
        os.replace(tmp_path, path)
    except BaseException:
        try:
            os.remove(tmp_path)
        except OSError:
            pass
        raise
    fsync_directory(directory)


def write_bytes(path: str, content: bytes) -> None:
    atomic_write_bytes(path, content)


def json_document_bytes(payload: Any) -> bytes:
    """A settings document as River writes it: JSON with an indent of 2."""
    return json.dumps(payload, indent=2).encode("utf-8")


def write_json(path: str, payload: Any) -> None:
    atomic_write_bytes(path, json_document_bytes(payload))


def validate_json_bytes(content: bytes) -> None:
    json.loads(content)


def write_and_validate_json_bytes(path: str, content: bytes) -> None:
    validate_json_bytes(content)
    atomic_write_bytes(path, content)
