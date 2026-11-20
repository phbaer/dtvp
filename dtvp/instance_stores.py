"""Everything DTVP persists, resolved in one place, and the instance lock.

``resolve_instance_stores`` is the single registry of the files an instance
consists of: the record databases, the record files, the settings files,
caches that can be rebuilt, and legacy inputs that were imported once. The
instance dump (``dtvp.backup``) and the restore work from it.

``claim_instance`` takes an exclusive lock on the data directory before the
databases are opened, so only one DTVP process (or one restore) uses an
instance at a time, and refuses to open an instance a restore left
half-finished.

This module must not import ``dtvp.main`` or ``dtvp.dt_cache``: importing
``dt_cache`` opens the databases.
"""

import fcntl
import glob
import json
import os
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from .access_token_services import (
    ACCESS_TOKEN_MIGRATION_NAMESPACE,
    get_access_tokens_path,
)
from .assessment_outbox_services import (
    ASSESSMENT_OUTBOX_MIGRATION_NAMESPACE,
    get_assessment_outbox_path,
    get_legacy_assessment_outbox_path,
)
from .code_analysis_diagnostics import get_code_analysis_diagnostics_path
from .code_analysis_result_services import (
    CODE_ANALYSIS_RESULT_MIGRATION_NAMESPACE,
    _legacy_json_path_for_configured_path,
    get_code_analysis_results_path,
    get_code_analysis_results_sqlite_path,
)
from .file_io_services import atomic_write_bytes
from .finding_lifecycle_services import FINDING_LIFECYCLE_MIGRATION_NAMESPACE
from .grouped_vuln_summary_index_services import get_grouped_vuln_summary_index_path
from .local_store import LOCAL_STORE_MIGRATION_NAMESPACE, get_database_path
from .settings_files import SETTINGS_FILES
from .ssvc_enrichment_services import get_ssvc_cache_path
from .tmrescore_cache_services import get_tmrescore_cache_path

LOCK_FILENAME = ".dtvp-instance.lock"
EXPORT_LOCK_FILENAME = ".dtvp-export.lock"
REGISTRY_FILENAME = ".dtvp-instance.json"
JOURNAL_PATTERN = ".dtvp-restore-*.json"


def get_dt_cache_path() -> str:
    return os.getenv("DTVP_DT_CACHE_PATH", "data/dt_cache")


def _real(path: str | os.PathLike[str]) -> str:
    return os.path.realpath(os.fspath(path))


@dataclass(frozen=True)
class SqliteStore:
    """A SQLite file holding records, with the migration namespaces in it."""

    name: str
    path: str
    namespaces: tuple[str, ...]


@dataclass(frozen=True)
class FileStore:
    name: str
    path: str


@dataclass(frozen=True)
class InstanceStores:
    dt_cache_dir: str
    sqlite_records: tuple[SqliteStore, ...]
    json_records: tuple[FileStore, ...]
    config: tuple[FileStore, ...]
    caches: tuple[FileStore, ...]
    legacy_inputs: tuple[FileStore, ...]
    lock_path: str
    export_lock_path: str
    registry_path: str
    journal_glob: str

    def sqlite_store(self, name: str) -> SqliteStore:
        for store in self.sqlite_records:
            if store.name == name:
                return store
        raise KeyError(name)

    def store_for_namespace(self, namespace: str) -> SqliteStore:
        for store in self.sqlite_records:
            if namespace in store.namespaces:
                return store
        raise KeyError(namespace)

    def config_path(self, name: str) -> str:
        for item in self.config:
            if item.name == name:
                return item.path
        raise KeyError(name)

    def json_record_path(self, name: str) -> str:
        for item in self.json_records:
            if item.name == name:
                return item.path
        raise KeyError(name)

    def journals(self) -> list[str]:
        return sorted(glob.glob(self.journal_glob))

    def as_comparable(self) -> dict[str, str]:
        """Logical name to resolved path, for every record, setting and
        cache. Two processes agree on an instance when these are equal."""
        comparable: dict[str, str] = {}
        for store in self.sqlite_records:
            comparable[f"sqlite:{store.name}"] = store.path
        for item in self.json_records:
            comparable[f"json:{item.name}"] = item.path
        for item in self.config:
            comparable[f"config:{item.name}"] = item.path
        for item in self.caches:
            comparable[f"cache:{item.name}"] = item.path
        return comparable


def resolve_instance_stores(dt_cache_dir: str | None = None) -> InstanceStores:
    """Resolve every persisted path from the environment and working
    directory, as the backend does. ``dt_cache_dir`` overrides
    ``DTVP_DT_CACHE_PATH`` for the paths derived from it. Paths are absolute
    and resolved, including files that do not exist yet."""
    dt_cache = _real(dt_cache_dir or get_dt_cache_path())
    candidates = (
        ("main", get_database_path(dt_cache), LOCAL_STORE_MIGRATION_NAMESPACE),
        (
            "assessment_outbox",
            get_assessment_outbox_path(dt_cache),
            ASSESSMENT_OUTBOX_MIGRATION_NAMESPACE,
        ),
        # What happened to findings: kept in the assessment records' file.
        (
            "assessment_outbox",
            get_assessment_outbox_path(dt_cache),
            FINDING_LIFECYCLE_MIGRATION_NAMESPACE,
        ),
        ("access_tokens", get_access_tokens_path(), ACCESS_TOKEN_MIGRATION_NAMESPACE),
        (
            "code_analysis_results",
            get_code_analysis_results_sqlite_path(),
            CODE_ANALYSIS_RESULT_MIGRATION_NAMESPACE,
        ),
    )
    merged: dict[str, tuple[str, list[str]]] = {}
    for name, path, namespace in candidates:
        resolved = _real(path)
        if resolved in merged:
            merged[resolved][1].append(namespace)
        else:
            merged[resolved] = (name, [namespace])
    sqlite_records = tuple(
        SqliteStore(name, path, tuple(namespaces))
        for path, (name, namespaces) in merged.items()
    )
    return InstanceStores(
        dt_cache_dir=dt_cache,
        sqlite_records=sqlite_records,
        json_records=(
            FileStore("tmrescore_proposals", _real(get_tmrescore_cache_path())),
        ),
        config=tuple(
            FileStore(item.name, _real(item.path())) for item in SETTINGS_FILES
        ),
        caches=(
            FileStore(
                "grouped_vuln_summary_index",
                _real(get_grouped_vuln_summary_index_path()),
            ),
            FileStore("ssvc_enrichment", _real(get_ssvc_cache_path())),
            FileStore(
                "code_analysis_diagnostics",
                _real(get_code_analysis_diagnostics_path()),
            ),
        ),
        legacy_inputs=(
            FileStore("dt_cache_json", dt_cache),
            FileStore(
                "assessment_outbox_file",
                _real(get_legacy_assessment_outbox_path(dt_cache)),
            ),
            FileStore(
                "pending_updates", _real(os.path.join(dt_cache, "pending_updates.json"))
            ),
            FileStore(
                "code_analysis_results_json",
                _real(
                    _legacy_json_path_for_configured_path(
                        get_code_analysis_results_path()
                    )
                ),
            ),
        ),
        lock_path=os.path.join(dt_cache, LOCK_FILENAME),
        export_lock_path=os.path.join(dt_cache, EXPORT_LOCK_FILENAME),
        registry_path=os.path.join(dt_cache, REGISTRY_FILENAME),
        journal_glob=os.path.join(glob.escape(dt_cache), JOURNAL_PATTERN),
    )


# -- locks ---------------------------------------------------------------


class InstanceBusyError(RuntimeError):
    """Another process holds the instance lock."""


class RestoreInProgressError(RuntimeError):
    """A restore journal exists: a restore did not finish."""


def try_lock_exclusive(path: str) -> int | None:
    """Take an exclusive, non-blocking ``flock`` on ``path`` through a new
    descriptor. Returns the descriptor, or ``None`` when someone else holds
    the lock. Never re-entrant: a second call in the same process fails
    while the first descriptor is open."""
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(descriptor)
        return None
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def unlock(descriptor: int | None) -> None:
    if descriptor is None:
        return
    try:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)


def write_instance_registry(stores: InstanceStores) -> None:
    document = {
        "written_at": datetime.now(UTC).isoformat(),
        "pid": os.getpid(),
        "stores": stores.as_comparable(),
    }
    atomic_write_bytes(
        stores.registry_path,
        json.dumps(document, indent=2, sort_keys=True).encode("utf-8") + b"\n",
        mode=0o600,
    )


def read_instance_registry(stores: InstanceStores) -> dict[str, Any] | None:
    try:
        with open(stores.registry_path, "r", encoding="utf-8") as handle:
            document = json.load(handle)
    except FileNotFoundError:
        return None
    return document if isinstance(document, dict) else None


_claims: dict[str, list[int]] = {}
_claims_lock = threading.Lock()


def claim_instance(dt_cache_dir: str) -> str:
    """Hold the instance lock of a data directory for this process.

    Idempotent and counted per resolved directory, because one process may
    open several stores on the same directory. Raises ``InstanceBusyError``
    when another process or a restore holds it, and
    ``RestoreInProgressError`` while a restore journal exists. On success the
    resolved paths are recorded in ``.dtvp-instance.json``. Returns the key
    to pass to ``release_instance``.
    """
    stores = resolve_instance_stores(dt_cache_dir)
    key = stores.lock_path
    with _claims_lock:
        claim = _claims.get(key)
        if claim is not None:
            claim[1] += 1
            return key
        descriptor = try_lock_exclusive(stores.lock_path)
        if descriptor is None:
            raise InstanceBusyError(
                f"The DTVP instance lock {stores.lock_path} is held: another "
                "DTVP process or a restore is using this data directory. Run "
                "one DTVP process per data directory."
            )
        try:
            journals = stores.journals()
            if journals:
                raise RestoreInProgressError(
                    "A restore of this DTVP instance did not finish "
                    f"({', '.join(journals)}). Complete or undo it with "
                    "`python -m dtvp.backup recover --resume` or "
                    "`python -m dtvp.backup recover --abort` before starting DTVP."
                )
            write_instance_registry(stores)
        except BaseException:
            unlock(descriptor)
            raise
        _claims[key] = [descriptor, 1]
        return key


def release_instance(key: str | None) -> None:
    """Drop one claim; the lock is released with the last one."""
    if not key:
        return
    with _claims_lock:
        claim = _claims.get(key)
        if claim is None:
            return
        claim[1] -= 1
        if claim[1] > 0:
            return
        del _claims[key]
        unlock(claim[0])
