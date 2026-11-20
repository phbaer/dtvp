"""ZIP containers shared by the project archive and the instance dump.

Writing: deterministic JSON and JSONL encodings, a streaming ZIP writer whose
members carry fixed dates and modes (so the same input gives the same member
bytes), and an atomic output file. Reading: a ZIP reader that checks member
names, the member count, the declared sizes and, optionally, the compression
ratio before any data is read, and that streams lines with a length limit.
"""

import hashlib
import json
import os
import posixpath
import tempfile
import zipfile
import zlib
from contextlib import contextmanager
from dataclasses import dataclass
from typing import IO, Any, Iterator

from .file_io_services import fsync_directory

FIXED_DATE_TIME = (1980, 1, 1, 0, 0, 0)
MEMBER_MODE = 0o600
COMPRESS_LEVEL = 6


class BundleError(ValueError):
    """A container violates a limit or is damaged. ``code`` names the rule
    (see docs/backup-and-restore.md)."""

    def __init__(self, message: str, *, code: str) -> None:
        self.code = code
        super().__init__(message)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def stable_json_bytes(data: Any, *, indent: int | None = 2) -> bytes:
    """Sorted keys, UTF-8 kept as is, and a trailing newline."""
    return json.dumps(data, indent=indent, sort_keys=True, ensure_ascii=False).encode(
        "utf-8"
    ) + b"\n"


def jsonl_line(record: Any) -> bytes:
    """One record as one compact, sorted line."""
    return (
        json.dumps(record, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def assert_safe_member_name(name: str, error_cls: type[Exception] | None = None) -> None:
    """Refuse absolute, parent-relative, empty or non-normalized names."""
    unsafe = (
        not name
        or name.startswith("/")
        or name.startswith("\\")
        or posixpath.normpath(name) != name
        or name == "."
        or any(part in {"", ".", ".."} for part in name.split("/"))
    )
    if not unsafe:
        return
    message = f"Unsafe archive path: {name!r}"
    if error_cls is None:
        raise BundleError(message, code="C1")
    raise error_cls(message)


@contextmanager
def atomic_output(path: str, mode: int = 0o600) -> Iterator[IO[bytes]]:
    """A binary file that replaces ``path`` only when the block succeeds.

    The data goes to a temporary file in the target directory, which is
    synced, given ``mode`` and renamed over ``path``; the directory is synced
    after. On any error the temporary file is removed and ``path`` is left
    as it was.
    """
    directory = os.path.dirname(os.fspath(path)) or "."
    os.makedirs(directory, exist_ok=True)
    descriptor, tmp_path = tempfile.mkstemp(dir=directory, prefix=".tmp-")
    try:
        with os.fdopen(descriptor, "wb") as handle:
            yield handle
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp_path, mode)
        os.replace(tmp_path, path)
    except BaseException:
        try:
            os.remove(tmp_path)
        except OSError:
            pass
        raise
    fsync_directory(directory)


@dataclass(frozen=True)
class MemberStats:
    name: str
    sha256: str
    bytes: int
    lines: int


class _MemberWriter:
    def __init__(self, name: str, stream: IO[bytes]) -> None:
        self.name = name
        self._stream = stream
        self._digest = hashlib.sha256()
        self.bytes = 0
        self.lines = 0
        self.stats: MemberStats | None = None

    def write(self, data: bytes) -> None:
        self._stream.write(data)
        self._digest.update(data)
        self.bytes += len(data)
        self.lines += data.count(b"\n")

    def _close(self) -> MemberStats:
        self._stream.close()
        self.stats = MemberStats(self.name, self._digest.hexdigest(), self.bytes, self.lines)
        return self.stats


def _member_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=FIXED_DATE_TIME)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = MEMBER_MODE << 16
    if hasattr(info, "compress_level"):
        info.compress_level = COMPRESS_LEVEL
    else:  # pragma: no cover - Python before 3.13
        info._compresslevel = COMPRESS_LEVEL
    return info


class ZipBundleWriter:
    """Streams members into a ZIP file. Works on unseekable output such as
    a pipe (members then carry data descriptors)."""

    def __init__(self, fileobj: IO[bytes]) -> None:
        self._zip = zipfile.ZipFile(
            fileobj,
            "w",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=COMPRESS_LEVEL,
            allowZip64=True,
        )
        self.members: list[MemberStats] = []

    @contextmanager
    def member(self, name: str) -> Iterator[_MemberWriter]:
        assert_safe_member_name(name)
        stream = self._zip.open(_member_info(name), "w", force_zip64=True)
        writer = _MemberWriter(name, stream)
        try:
            yield writer
        except BaseException:
            stream.close()
            raise
        self.members.append(writer._close())

    def write_member(self, name: str, data: bytes) -> MemberStats:
        with self.member(name) as writer:
            writer.write(data)
        assert writer.stats is not None
        return writer.stats

    def close(self) -> None:
        self._zip.close()

    def abort(self) -> None:
        """Give up a container that failed half-way: release it without
        writing the central directory. The output is to be discarded."""
        self._zip._didModify = False  # zipfile has no public abort
        try:
            self._zip.close()
        except ValueError:  # pragma: no cover - a member is still open
            pass

    def __enter__(self) -> "ZipBundleWriter":
        return self

    def __exit__(self, exc_type: Any, *exc_info: Any) -> None:
        if exc_type is None:
            self.close()
        else:
            self.abort()


_DAMAGE = (zipfile.BadZipFile, zlib.error, EOFError, OSError, NotImplementedError)


class ZipBundleReader:
    """Reads a ZIP container within limits.

    The checks that need no data run when it is opened: every member name is
    safe, the member count, the sum of the declared uncompressed sizes and,
    when ``max_ratio`` is set, the compression ratio of each member. Reading
    a member counts the bytes actually produced and fails on more than the
    declared size; ``zipfile`` verifies the CRC at the end of each member.
    """

    def __init__(
        self,
        path: str,
        *,
        max_members: int,
        max_total_uncompressed: int,
        max_ratio: float | None = None,
        max_line_bytes: int,
    ) -> None:
        self.path = path
        self.max_line_bytes = max_line_bytes
        try:
            self._zip = zipfile.ZipFile(path, "r")
        except (zipfile.BadZipFile, EOFError, OSError) as exc:
            raise BundleError(f"Not a readable ZIP file: {exc}", code="C10") from exc
        try:
            infos = self._zip.infolist()
            for info in infos:
                assert_safe_member_name(info.filename)
            if len(infos) > max_members:
                raise BundleError(
                    f"The container has {len(infos)} members; at most "
                    f"{max_members} are allowed",
                    code="C4",
                )
            names = [info.filename for info in infos]
            if len(set(names)) != len(names):
                raise BundleError("The container lists a member twice", code="C10")
            total = sum(info.file_size for info in infos)
            if total > max_total_uncompressed:
                raise BundleError(
                    f"The container declares {total} uncompressed bytes; at most "
                    f"{max_total_uncompressed} are allowed",
                    code="C5",
                )
            if max_ratio is not None:
                for info in infos:
                    ratio = info.file_size / max(info.compress_size, 1)
                    if ratio > max_ratio:
                        raise BundleError(
                            f"Member {info.filename} expands {ratio:.0f}-fold; at "
                            f"most {max_ratio:.0f} is allowed",
                            code="C5",
                        )
        except BaseException:
            self._zip.close()
            raise
        self._infos = {info.filename: info for info in infos}
        self.total_declared = total

    def names(self) -> list[str]:
        return list(self._infos)

    def declared_size(self, name: str) -> int:
        return self._infos[name].file_size

    def __contains__(self, name: str) -> bool:
        return name in self._infos

    def _open(self, name: str) -> IO[bytes]:
        info = self._infos[name]  # KeyError for a missing member
        try:
            return self._zip.open(info, "r")
        except _DAMAGE as exc:
            raise BundleError(f"Member {name} cannot be read: {exc}", code="C10") from exc

    def read_bytes(self, name: str) -> bytes:
        declared = self._infos[name].file_size
        handle = self._open(name)
        try:
            data = handle.read(declared + 1)
            if len(data) > declared:
                raise BundleError(
                    f"Member {name} is larger than it declares", code="C10"
                )
            if handle.read(1):  # pragma: no cover - read() already ran to EOF
                raise BundleError(f"Member {name} is larger than it declares", code="C10")
        except _DAMAGE as exc:
            raise BundleError(f"Member {name} is damaged: {exc}", code="C10") from exc
        finally:
            handle.close()
        return data

    def iter_lines(self, name: str) -> Iterator[bytes]:
        """The lines of a member, each with its newline (the last may lack
        one). A line longer than ``max_line_bytes`` without its newline
        fails."""
        declared = self._infos[name].file_size
        limit = self.max_line_bytes + 1
        handle = self._open(name)
        produced = 0
        try:
            while True:
                try:
                    line = handle.readline(limit)
                except _DAMAGE as exc:
                    raise BundleError(
                        f"Member {name} is damaged: {exc}", code="C10"
                    ) from exc
                if not line:
                    break
                produced += len(line)
                if produced > declared:
                    raise BundleError(
                        f"Member {name} is larger than it declares", code="C10"
                    )
                if len(line) == limit and not line.endswith(b"\n"):
                    raise BundleError(
                        f"A line in {name} is longer than {self.max_line_bytes} bytes",
                        code="C9",
                    )
                yield line
        finally:
            handle.close()

    def close(self) -> None:
        self._zip.close()

    def __enter__(self) -> "ZipBundleReader":
        return self

    def __exit__(self, *exc_info: Any) -> None:
        self.close()
