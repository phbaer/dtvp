"""Bounded extraction of source archives into isolated analysis workspaces."""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
import tarfile
import threading
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, Iterable

import py7zr
import rarfile
from py7zr import Py7zIO, WriterFactory


def _positive_env_int(name: str, default: int) -> int:
    try:
        value = int(os.environ.get(name, str(default)))
    except (TypeError, ValueError):
        return default
    return value if value > 0 else default


MAX_ARCHIVE_BYTES = _positive_env_int(
    "AGENTYZER_ARCHIVE_MAX_INPUT_BYTES", 1024 * 1024 * 1024
)
MAX_ARCHIVE_MEMBERS = _positive_env_int("AGENTYZER_ARCHIVE_MAX_MEMBERS", 50_000)
MAX_ARCHIVES = _positive_env_int("AGENTYZER_ARCHIVE_MAX_ARCHIVES", 25)
MAX_ARCHIVE_NESTING = _positive_env_int("AGENTYZER_ARCHIVE_MAX_NESTING", 2)
MAX_ARCHIVE_MEMBER_BYTES = _positive_env_int(
    "AGENTYZER_ARCHIVE_MAX_MEMBER_BYTES", 256 * 1024 * 1024
)
MAX_ARCHIVE_EXTRACTED_BYTES = _positive_env_int(
    "AGENTYZER_ARCHIVE_MAX_EXTRACTED_BYTES", 2 * 1024 * 1024 * 1024
)

_ARCHIVES_DIRNAME = "__agentyzer_archives__"
_COPY_CHUNK_BYTES = 1024 * 1024
_WINDOWS_DRIVE_RE = re.compile(r"^[A-Za-z]:")
_ARCHIVE_SUFFIXES = (
    ".tar",
    ".tar.gz",
    ".tgz",
    ".tar.bz2",
    ".tbz",
    ".tbz2",
    ".tar.xz",
    ".txz",
    ".tar.zst",
    ".tzst",
    ".zip",
    ".7z",
    ".rar",
    ".jar",
    ".war",
    ".ear",
    ".whl",
    ".nupkg",
    ".apk",
    ".aar",
)
_DISCOVERY_SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "node_modules",
    "vendor",
    _ARCHIVES_DIRNAME,
}


class ArchiveError(RuntimeError):
    """Raised when an archive cannot be safely prepared for analysis."""


@dataclass(frozen=True)
class _ArchiveMember:
    name: str
    size: int
    is_directory: bool = False
    is_link: bool = False
    is_special: bool = False
    is_encrypted: bool = False
    source: Any = None


@dataclass(frozen=True)
class _PreparedMember:
    relative_path: Path
    size: int
    is_directory: bool
    source: Any


class _ExtractionBudget:
    def __init__(self) -> None:
        self.members_seen = 0
        self.declared_bytes = 0
        self.total_written = 0
        self._lock = threading.Lock()

    def add_member(self, size: int) -> None:
        with self._lock:
            self.members_seen += 1
            if self.members_seen > MAX_ARCHIVE_MEMBERS:
                raise ArchiveError(
                    "Repository archives contain more than "
                    f"AGENTYZER_ARCHIVE_MAX_MEMBERS ({MAX_ARCHIVE_MEMBERS})"
                )
            self.declared_bytes += max(0, size)
            if self.declared_bytes > MAX_ARCHIVE_EXTRACTED_BYTES:
                raise ArchiveError(
                    "Repository archives expand beyond "
                    "AGENTYZER_ARCHIVE_MAX_EXTRACTED_BYTES "
                    f"({MAX_ARCHIVE_EXTRACTED_BYTES} bytes)"
                )

    def reserve(self, size: int) -> None:
        if size <= 0:
            return
        with self._lock:
            next_total = self.total_written + size
            if next_total > MAX_ARCHIVE_EXTRACTED_BYTES:
                raise ArchiveError(
                    "Archive expands beyond AGENTYZER_ARCHIVE_MAX_EXTRACTED_BYTES "
                    f"({MAX_ARCHIVE_EXTRACTED_BYTES} bytes)"
                )
            self.total_written = next_total

    def release(self, size: int) -> None:
        if size <= 0:
            return
        with self._lock:
            self.total_written = max(0, self.total_written - size)


class _LimitedFile(Py7zIO):
    """File-backed py7zr writer that also enforces actual output limits."""

    def __init__(self, path: Path, budget: _ExtractionBudget) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._handle = path.open("w+b")
        self._budget = budget
        self._size = 0
        self._closed = False

    def write(self, data: bytes | bytearray) -> int:
        if self._closed:
            raise ValueError("write to closed archive member")
        start = self._handle.tell()
        proposed_end = start + len(data)
        if proposed_end > MAX_ARCHIVE_MEMBER_BYTES:
            raise ArchiveError(
                "Archive member expands beyond AGENTYZER_ARCHIVE_MAX_MEMBER_BYTES "
                f"({MAX_ARCHIVE_MEMBER_BYTES} bytes)"
            )
        reserved = max(0, proposed_end - self._size)
        self._budget.reserve(reserved)
        try:
            written = self._handle.write(data)
        except Exception:
            self._budget.release(reserved)
            raise
        actual_end = start + written
        actual_growth = max(0, actual_end - self._size)
        self._budget.release(reserved - actual_growth)
        self._size = max(self._size, actual_end)
        return written

    def read(self, size: int | None = None) -> bytes:
        if self._closed:
            raise ValueError("read from closed archive member")
        return self._handle.read(-1 if size is None else size)

    def seek(self, offset: int, whence: int = 0) -> int:
        if self._closed:
            raise ValueError("seek on closed archive member")
        return self._handle.seek(offset, whence)

    def flush(self) -> None:
        if not self._closed:
            self._handle.flush()

    def size(self) -> int:
        return self._size

    def close(self) -> None:
        if not self._closed:
            self._handle.close()
            self._closed = True


class _SevenZipWriterFactory(WriterFactory):
    def __init__(
        self,
        destination: Path,
        members: dict[str, _PreparedMember],
        budget: _ExtractionBudget,
    ) -> None:
        self._destination = destination
        self._members = members
        self._budget = budget

    def create(self, filename: str) -> Py7zIO:
        member = self._members.get(filename)
        if member is None or member.is_directory:
            raise ArchiveError(f"Unexpected 7z member during extraction: {filename!r}")
        return _LimitedFile(self._destination / member.relative_path, self._budget)


def archive_workspace_path(repository_path: str, workspace_id: str) -> Path:
    safe_workspace_id = re.sub(r"[^A-Za-z0-9._-]", "_", workspace_id)[:128]
    if not safe_workspace_id:
        raise ArchiveError("Archive workspace identifier is empty")
    return Path(repository_path) / _ARCHIVES_DIRNAME / safe_workspace_id


def extract_archive(
    path: str | Path,
    repository_path: str,
    workspace_id: str,
    *,
    archive_key: str | None = None,
    budget: _ExtractionBudget | None = None,
) -> str:
    """Extract one repository archive and return its generated scan root."""
    archive_path = Path(path).expanduser().resolve(strict=True)
    if not archive_path.is_file():
        raise ArchiveError(f"Archive source is not a regular file: {archive_path}")
    input_size = archive_path.stat().st_size
    if input_size > MAX_ARCHIVE_BYTES:
        raise ArchiveError(
            "Archive exceeds AGENTYZER_ARCHIVE_MAX_INPUT_BYTES "
            f"({MAX_ARCHIVE_BYTES} bytes)"
        )

    repository = Path(repository_path).expanduser().resolve()
    repository.mkdir(parents=True, exist_ok=True)
    archive_root = repository / _ARCHIVES_DIRNAME
    if archive_root.is_symlink():
        raise ArchiveError(
            f"Archive workspace root must not be a symbolic link: {archive_root}"
        )
    try:
        archive_root.mkdir()
    except FileExistsError:
        if archive_root.is_symlink() or not archive_root.is_dir():
            raise ArchiveError(
                f"Archive workspace root is not a directory: {archive_root}"
            ) from None

    analysis_workspace = archive_workspace_path(str(repository), workspace_id)
    if archive_key:
        if analysis_workspace.is_symlink():
            raise ArchiveError(
                "Archive analysis workspace must not be a symbolic link: "
                f"{analysis_workspace}"
            )
        try:
            analysis_workspace.mkdir()
        except FileExistsError:
            if analysis_workspace.is_symlink() or not analysis_workspace.is_dir():
                raise ArchiveError(
                    "Archive analysis workspace is not a directory: "
                    f"{analysis_workspace}"
                ) from None
        workspace = analysis_workspace / _safe_path_component(archive_key)
    else:
        workspace = analysis_workspace

    try:
        workspace.mkdir()
    except FileExistsError:
        raise ArchiveError(f"Archive workspace already exists: {workspace}") from None
    destination = workspace / "content"
    destination.mkdir()
    extraction_budget = budget or _ExtractionBudget()

    try:
        archive_type = _detect_archive_type(archive_path)
        if archive_type == "zip":
            _extract_zip(archive_path, destination, extraction_budget)
        elif archive_type == "tar":
            _extract_tar(archive_path, destination, extraction_budget)
        elif archive_type == "7z":
            _extract_7z(archive_path, destination, extraction_budget)
        elif archive_type == "rar":
            _extract_rar(archive_path, destination, extraction_budget)
        else:
            raise ArchiveError(
                "Unsupported archive format. Supported formats are tar, tar.gz, "
                "tar.bz2, tar.xz, tar.zst, zip, 7z, and rar."
            )
        return str(_select_scan_root(destination))
    except ArchiveError:
        shutil.rmtree(workspace, ignore_errors=True)
        raise
    except Exception as exc:
        shutil.rmtree(workspace, ignore_errors=True)
        raise ArchiveError(
            f"Failed to extract {archive_path.name}: {str(exc).strip() or exc.__class__.__name__}"
        ) from None


def cleanup_archive_workspace(repository_path: str, workspace_id: str) -> None:
    """Remove the extraction workspace for one completed analysis."""
    workspace = archive_workspace_path(repository_path, workspace_id)
    if workspace.is_dir():
        shutil.rmtree(workspace)
    try:
        workspace.parent.rmdir()
    except OSError:
        pass


def inspect_repository_archives(
    repository_path: str,
    workspace_id: str,
) -> dict[str, Any]:
    """Discover and safely expand archives contained in a repository.

    Extracted files live under a unique directory inside the analysis checkout,
    so the existing dependency, version, AST, and source scanners discover them
    without executing archive content or modifying tracked files.
    """
    repository = Path(repository_path).expanduser().resolve(strict=True)
    if not repository.is_dir():
        raise ArchiveError(f"Repository path is not a directory: {repository}")

    queue: list[tuple[Path, str, int]] = [
        (path, path.relative_to(repository).as_posix(), 0)
        for path in _discover_archives(repository)
    ]
    budget = _ExtractionBudget()
    reports: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    seen_paths: set[Path] = set()
    attempted = 0

    while queue and attempted < MAX_ARCHIVES:
        archive_path, display_path, nesting_level = queue.pop(0)
        try:
            resolved_archive = archive_path.resolve(strict=True)
        except OSError as exc:
            errors.append({"path": display_path, "error": str(exc)})
            continue
        if resolved_archive in seen_paths:
            continue
        seen_paths.add(resolved_archive)
        attempted += 1

        archive_type = _detect_archive_type(resolved_archive)
        if archive_type is None:
            errors.append(
                {
                    "path": display_path,
                    "error": (
                        "File has a supported archive extension but invalid or "
                        "unsupported archive content"
                    ),
                }
            )
            continue

        before_members = budget.members_seen
        before_bytes = budget.total_written
        digest = hashlib.sha256(display_path.encode()).hexdigest()[:12]
        archive_key = f"{attempted:02d}-{_safe_path_component(resolved_archive.stem)}-{digest}"
        try:
            scan_root = Path(
                extract_archive(
                    resolved_archive,
                    str(repository),
                    workspace_id,
                    archive_key=archive_key,
                    budget=budget,
                )
            )
        except ArchiveError as exc:
            errors.append({"path": display_path, "error": str(exc)})
            continue

        reports.append(
            {
                "path": display_path,
                "format": archive_type,
                "nesting_level": nesting_level,
                "members": budget.members_seen - before_members,
                "extracted_bytes": budget.total_written - before_bytes,
                "scan_root": scan_root.relative_to(repository).as_posix(),
            }
        )

        if nesting_level < MAX_ARCHIVE_NESTING:
            for nested_path in _discover_archives(scan_root):
                nested_relative = nested_path.relative_to(scan_root).as_posix()
                queue.append(
                    (
                        nested_path,
                        f"{display_path}!{nested_relative}",
                        nesting_level + 1,
                    )
                )

    return {
        "discovered": attempted + len(queue),
        "inspected": len(reports),
        "archives": reports,
        "errors": errors,
        "truncated": bool(queue),
        "limits": {
            "max_archives": MAX_ARCHIVES,
            "max_nesting": MAX_ARCHIVE_NESTING,
            "max_members": MAX_ARCHIVE_MEMBERS,
            "max_member_bytes": MAX_ARCHIVE_MEMBER_BYTES,
            "max_extracted_bytes": MAX_ARCHIVE_EXTRACTED_BYTES,
        },
    }


def _discover_archives(root: Path) -> list[Path]:
    archives: list[Path] = []
    for current_root, dirs, files in os.walk(root):
        dirs[:] = sorted(
            directory
            for directory in dirs
            if directory not in _DISCOVERY_SKIP_DIRS
            and not (Path(current_root) / directory).is_symlink()
        )
        for filename in sorted(files):
            path = Path(current_root) / filename
            if path.is_symlink() or not path.is_file():
                continue
            if filename.lower().endswith(_ARCHIVE_SUFFIXES):
                archives.append(path)
    return archives


def _safe_path_component(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "_", value).strip("._")[:80]
    return cleaned or hashlib.sha256(value.encode()).hexdigest()[:16]


def _detect_archive_type(path: Path) -> str | None:
    if zipfile.is_zipfile(path):
        return "zip"
    if tarfile.is_tarfile(path):
        return "tar"
    if py7zr.is_7zfile(path):
        return "7z"
    if rarfile.is_rarfile(path):
        return "rar"
    return None


def _normalize_member_name(name: str) -> Path | None:
    if not isinstance(name, str) or not name:
        raise ArchiveError("Archive contains an empty member name")
    if any(ord(char) < 32 or ord(char) == 127 for char in name):
        raise ArchiveError(f"Archive member contains control characters: {name!r}")

    portable_name = name.replace("\\", "/")
    if _WINDOWS_DRIVE_RE.match(portable_name):
        raise ArchiveError(f"Archive member uses an absolute drive path: {name!r}")
    pure_path = PurePosixPath(portable_name)
    if pure_path.is_absolute() or ".." in pure_path.parts:
        raise ArchiveError(f"Archive member escapes the extraction root: {name!r}")

    parts = tuple(part for part in pure_path.parts if part not in ("", "."))
    if not parts:
        return None
    return Path(*parts)


def _prepare_members(
    members: Iterable[_ArchiveMember],
    budget: _ExtractionBudget,
) -> list[_PreparedMember]:
    prepared: list[_PreparedMember] = []
    seen_kinds: dict[Path, str] = {}

    for member in members:
        size = max(0, int(member.size or 0))
        budget.add_member(0 if member.is_directory else size)
        relative_path = _normalize_member_name(member.name)
        if relative_path is None:
            continue
        if member.is_link:
            raise ArchiveError(f"Archive links are not allowed: {member.name!r}")
        if member.is_special:
            raise ArchiveError(
                f"Archive special filesystem entries are not allowed: {member.name!r}"
            )
        if member.is_encrypted:
            raise ArchiveError(
                f"Password-protected archive members are not supported: {member.name!r}"
            )

        kind = "directory" if member.is_directory else "file"
        previous_kind = seen_kinds.get(relative_path)
        if previous_kind and previous_kind != kind:
            raise ArchiveError(
                f"Archive member is both a file and directory: {member.name!r}"
            )
        if previous_kind == "file":
            raise ArchiveError(f"Archive contains duplicate file: {member.name!r}")
        seen_kinds[relative_path] = kind

        if not member.is_directory:
            if size > MAX_ARCHIVE_MEMBER_BYTES:
                raise ArchiveError(
                    f"Archive member {member.name!r} exceeds "
                    "AGENTYZER_ARCHIVE_MAX_MEMBER_BYTES "
                    f"({MAX_ARCHIVE_MEMBER_BYTES} bytes)"
                )
        prepared.append(
            _PreparedMember(
                relative_path=relative_path,
                size=size,
                is_directory=member.is_directory,
                source=member.source,
            )
        )

    if not any(not member.is_directory for member in prepared):
        raise ArchiveError("Archive contains no regular files to analyze")
    return prepared


def _create_directories(destination: Path, members: Iterable[_PreparedMember]) -> None:
    directories = sorted(
        (member for member in members if member.is_directory),
        key=lambda member: len(member.relative_path.parts),
    )
    for member in directories:
        (destination / member.relative_path).mkdir(parents=True, exist_ok=True)


def _copy_member(
    source: BinaryIO,
    target: Path,
    expected_size: int,
    budget: _ExtractionBudget,
) -> None:
    writer = _LimitedFile(target, budget)
    try:
        while chunk := source.read(_COPY_CHUNK_BYTES):
            writer.write(chunk)
        if writer.size() != expected_size:
            raise ArchiveError(
                f"Archive member size changed during extraction: expected "
                f"{expected_size} bytes, received {writer.size()} bytes"
            )
    finally:
        writer.close()


def _extract_zip(
    path: Path,
    destination: Path,
    budget: _ExtractionBudget | None = None,
) -> None:
    extraction_budget = budget or _ExtractionBudget()
    with zipfile.ZipFile(path) as archive:
        members: list[_ArchiveMember] = []
        for info in archive.infolist():
            unix_mode = (info.external_attr >> 16) & 0xFFFF
            file_type = stat.S_IFMT(unix_mode)
            is_link = file_type == stat.S_IFLNK
            is_special = file_type not in (0, stat.S_IFREG, stat.S_IFDIR, stat.S_IFLNK)
            members.append(
                _ArchiveMember(
                    name=info.filename,
                    size=info.file_size,
                    is_directory=info.is_dir(),
                    is_link=is_link,
                    is_special=is_special,
                    is_encrypted=bool(info.flag_bits & 0x1),
                    source=info,
                )
            )
        prepared = _prepare_members(members, extraction_budget)
        _create_directories(destination, prepared)
        for member in prepared:
            if member.is_directory:
                continue
            with archive.open(member.source, "r") as source:
                _copy_member(
                    source,
                    destination / member.relative_path,
                    member.size,
                    extraction_budget,
                )


def _extract_tar(
    path: Path,
    destination: Path,
    budget: _ExtractionBudget | None = None,
) -> None:
    extraction_budget = budget or _ExtractionBudget()
    with tarfile.open(path, mode="r:*") as archive:
        members = [
            _ArchiveMember(
                name=info.name,
                size=info.size,
                is_directory=info.isdir(),
                is_link=info.issym() or info.islnk(),
                is_special=not (info.isdir() or info.isreg() or info.issym() or info.islnk()),
                source=info,
            )
            for info in archive.getmembers()
        ]
        prepared = _prepare_members(members, extraction_budget)
        _create_directories(destination, prepared)
        for member in prepared:
            if member.is_directory:
                continue
            source = archive.extractfile(member.source)
            if source is None:
                raise ArchiveError(
                    f"Could not read tar member: {member.relative_path.as_posix()}"
                )
            with source:
                _copy_member(
                    source,
                    destination / member.relative_path,
                    member.size,
                    extraction_budget,
                )


def _extract_7z(
    path: Path,
    destination: Path,
    budget: _ExtractionBudget | None = None,
) -> None:
    extraction_budget = budget or _ExtractionBudget()
    with py7zr.SevenZipFile(path, mode="r") as archive:
        if archive.needs_password():
            raise ArchiveError("Password-protected 7z archives are not supported")
        members = [
            _ArchiveMember(
                name=info.filename,
                size=info.uncompressed,
                is_directory=info.is_directory,
                is_link=info.is_symlink,
                is_special=not (info.is_directory or info.is_file or info.is_symlink),
                source=info,
            )
            for info in archive.list()
        ]
        prepared = _prepare_members(members, extraction_budget)
        _create_directories(destination, prepared)
        member_map = {
            str(member.source.filename): member
            for member in prepared
            if not member.is_directory
        }
        archive.extractall(
            factory=_SevenZipWriterFactory(
                destination,
                member_map,
                extraction_budget,
            )
        )


def _extract_rar(
    path: Path,
    destination: Path,
    budget: _ExtractionBudget | None = None,
) -> None:
    extraction_budget = budget or _ExtractionBudget()
    if shutil.which("unrar") is None and shutil.which("unrar-free") is not None:
        rarfile.UNRAR_TOOL = "unrar-free"
        rarfile.tool_setup(force=True)

    with rarfile.RarFile(path) as archive:
        if archive.needs_password():
            raise ArchiveError("Password-protected RAR archives are not supported")
        members = [
            _ArchiveMember(
                name=info.filename,
                size=info.file_size,
                is_directory=info.is_dir(),
                is_link=info.is_symlink(),
                is_special=not (info.is_dir() or info.is_file() or info.is_symlink()),
                is_encrypted=info.needs_password(),
                source=info,
            )
            for info in archive.infolist()
        ]
        prepared = _prepare_members(members, extraction_budget)
        _create_directories(destination, prepared)
        for member in prepared:
            if member.is_directory:
                continue
            try:
                with archive.open(member.source, "r") as source:
                    _copy_member(
                        source,
                        destination / member.relative_path,
                        member.size,
                        extraction_budget,
                    )
            except rarfile.RarCannotExec:
                raise ArchiveError(
                    "RAR extraction requires an unrar-compatible helper; install "
                    "unrar-free or use the Agentyzer container image"
                ) from None


def _select_scan_root(destination: Path) -> Path:
    entries = list(destination.iterdir())
    if len(entries) == 1 and entries[0].is_dir():
        return entries[0]
    return destination
