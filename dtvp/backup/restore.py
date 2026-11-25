"""Offline restore of an instance dump, and recovery of an interrupted one.

A restore holds the instance lock and the export lock for its whole run, so
the backend cannot start and no export runs. It checks everything first,
stages complete new files beside their targets, proves that the staged files
give back the dump, and only then swaps them in under a journal. A crash
leaves either the untouched original (no journal yet) or a journal that
``recover --resume`` completes or ``recover --abort`` undoes; the backend
refuses to start while the journal exists.
"""

import hashlib
import json
import os
import shutil
import tempfile
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from ..bundle_io import jsonl_line
from ..code_analysis_result_services import (
    get_code_analysis_results_max_records,
    get_code_analysis_results_retention_days,
)
from ..file_io_services import atomic_write_bytes, fsync_directory
from ..instance_stores import (
    InstanceStores,
    SqliteStore,
    read_instance_registry,
    resolve_instance_stores,
    try_lock_exclusive,
    unlock,
)
from ..settings_files import SETTINGS_FILE_NAMES
from ..tmrescore_cache_services import serialize_tmrescore_cache
from . import schemas
from .container import DumpReader
from .entities import ENTITIES, INSTANCE_METADATA_KEYS
from .errors import DumpError, Finding
from .manifest import sanitize_dependency_track_url
from .sqlite_source import SqliteDumpSource, direct_store
from .sqlite_target import (
    as_restored,
    SIDE_FILES,
    SqliteDumpTarget,
    remove_stale,
    result_row,
    staged_path,
    table_has_rows,
)
from .verify import read_all

JOURNAL_PREFIX = ".dtvp-restore-"


def _now() -> str:
    return datetime.now(UTC).isoformat()


@dataclass
class RestoreOptions:
    replace: bool = False
    new_instance: bool = False
    accept_dt_url_change: bool = False
    accept_pruning: bool = False
    accept_path_change: bool = False
    allow_unknown: bool = False


@dataclass
class RestoreResult:
    dump_id: str
    run_id: str
    dry_run: bool
    lock_held: bool | None
    refusals: list[Finding]
    warnings: list[Finding]
    actions: list[dict[str, Any]]
    records: dict[str, int] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return not self.refusals


def restore_run_id(dump_id: str, started: datetime | None = None) -> str:
    """Names one restore run: the dump id and the UTC start time. Restoring
    the same dump again gets new names for the files it moves aside."""
    stamp = (started or datetime.now(UTC)).astimezone(UTC).strftime("%Y%m%dT%H%M%SZ")
    return f"{dump_id}-{stamp}"


def aside_path(target: str, run_id: str) -> str:
    return f"{target}.pre-restore-{run_id}"


def journal_path(stores: InstanceStores, dump_id: str) -> str:
    return os.path.join(stores.dt_cache_dir, f"{JOURNAL_PREFIX}{dump_id}.json")


# -- the actions of a swap --------------------------------------------------------


def plan_actions(
    stores: InstanceStores,
    run_id: str,
    *,
    staged_databases: dict[str, str],
    staged_files: dict[str, str | None],
) -> list[dict[str, Any]]:
    """Every file the swap touches, in order: each database after its side
    files, then the record file, the settings files and the caches.

    A side file goes to the aside name of its database plus its suffix
    (``x.sqlite-wal`` to ``x.sqlite.pre-restore-<run>-wal``), so SQLite
    pairs a moved WAL or hot journal with the moved database."""
    actions: list[dict[str, Any]] = []

    def add(target: str, staged: str | None, kind: str, aside: str) -> None:
        actions.append(
            {
                "target": target,
                "staged": staged,
                "aside": aside,
                "original_existed": os.path.lexists(target),
                "kind": kind,
            }
        )

    def add_database(path: str, staged: str | None, kind: str) -> None:
        aside = aside_path(path, run_id)
        for suffix in SIDE_FILES:
            add(path + suffix, None, f"{kind}-side-file", aside + suffix)
        add(path, staged, kind, aside)

    for store in stores.sqlite_records:
        add_database(store.path, staged_databases[store.path], "database")
    for item in stores.json_records:
        add(item.path, staged_files.get(item.path), "record-file", aside_path(item.path, run_id))
    for item in stores.config:
        add(item.path, staged_files.get(item.path), "settings", aside_path(item.path, run_id))
    for item in stores.caches:
        add_database(item.path, None, "cache")
    return actions


def check_asides_free(actions: list[dict[str, Any]]) -> None:
    """T9: no file this run would move aside to exists already. Only
    ``recover --resume`` may find one, because its journal proves that this
    run made it."""
    taken = [action["aside"] for action in actions if os.path.lexists(action["aside"])]
    if taken:
        raise DumpError(
            "T9",
            "Files from an earlier restore are in the way ("
            + ", ".join(taken[:5])
            + "); move or remove them, then run the restore again",
        )


def _replace(source: str, target: str) -> None:
    """The only rename of the swap; tests inject crashes here."""
    os.replace(source, target)


def _forward(actions: list[dict[str, Any]]) -> None:
    # An existing aside means this run already moved the original (resume);
    # a new run refuses existing asides first (T9).
    for action in actions:
        target, staged, aside = action["target"], action["staged"], action["aside"]
        if action["original_existed"] and not os.path.lexists(aside):
            if os.path.lexists(target):
                _replace(target, aside)
        if staged and os.path.lexists(staged):
            _replace(staged, target)
        fsync_directory(os.path.dirname(target))


def _inconsistent(action: dict[str, Any]) -> DumpError:
    return DumpError(
        "T2",
        "Recovery stopped: the files of this action were changed outside River; "
        f"fix them by hand and run recover again: {json.dumps(action)}",
    )


def _backward(actions: list[dict[str, Any]]) -> None:
    for action in reversed(actions):
        target, staged, aside = action["target"], action["staged"], action["aside"]
        target_exists = os.path.lexists(target)
        aside_exists = os.path.lexists(aside)
        if staged and target_exists and os.path.lexists(staged) and aside_exists:
            raise _inconsistent(action)
        if (
            staged
            and target_exists
            and not os.path.lexists(staged)
            and (not action["original_existed"] or aside_exists)
        ):
            _replace(target, staged)
            target_exists = False
        if action["original_existed"] and aside_exists:
            if target_exists:
                raise _inconsistent(action)
            _replace(aside, target)
        fsync_directory(os.path.dirname(target))


def _write_journal(path: str, document: dict[str, Any]) -> None:
    atomic_write_bytes(
        path, json.dumps(document, indent=2, sort_keys=True).encode() + b"\n", mode=0o600
    )


def _write_registry(stores: InstanceStores, comparable: dict[str, str]) -> None:
    document = {"written_at": _now(), "pid": os.getpid(), "stores": comparable}
    atomic_write_bytes(
        stores.registry_path,
        json.dumps(document, indent=2, sort_keys=True).encode() + b"\n",
        mode=0o600,
    )


def _finish_swap(stores: InstanceStores, journal: str, comparable: dict[str, str]) -> None:
    _write_registry(stores, comparable)
    os.remove(journal)
    fsync_directory(stores.dt_cache_dir)


# -- locks ---------------------------------------------------------------------


class _Locks:
    """The instance locks of every directory the backend locks (dt_cache and
    each directory of a record database, record file or cache), then the
    export lock. A backend of another dt_cache that shares one of those
    directories holds its lock, so the restore cannot swap its files."""

    def __init__(self, stores: InstanceStores) -> None:
        os.makedirs(stores.dt_cache_dir, exist_ok=True)
        self.held: list[int] = []
        try:
            for path in stores.instance_lock_paths():
                descriptor = try_lock_exclusive(path)
                if descriptor is None:
                    raise DumpError(
                        "T1",
                        f"The instance lock {path} is held: stop the River backend "
                        "that uses this directory (or the other restore) first",
                    )
                self.held.append(descriptor)
            descriptor = try_lock_exclusive(stores.export_lock_path)
            if descriptor is None:
                raise DumpError("T1", "An export is running; wait for it to finish")
            self.held.append(descriptor)
        except BaseException:
            self.release()
            raise

    def release(self) -> None:
        while self.held:
            unlock(self.held.pop())


def _lock_held(stores: InstanceStores) -> bool | None:
    """Probe the instance locks for a dry run, without creating their files."""
    for path in stores.instance_lock_paths():
        if not os.path.exists(path):
            continue
        descriptor = try_lock_exclusive(path)
        if descriptor is None:
            return True
        unlock(descriptor)
    return False


# -- target checks ---------------------------------------------------------------


def _record_tables() -> dict[str, dict[str, str | None]]:
    """Per namespace, the dumped tables and which rows count as records."""
    tables: dict[str, dict[str, str | None]] = {}
    keys = ", ".join(f"'{key}'" for key in INSTANCE_METADATA_KEYS)
    for spec in ENTITIES.values():
        if spec.table is None:
            continue
        where = f"key IN ({keys})" if spec.table == "store_metadata" else None
        tables.setdefault(spec.namespace, {})[spec.table] = where
    return tables


def check_paths(stores: InstanceStores, options: RestoreOptions) -> list[Finding]:
    """T6 and T7: the paths this command resolved are the backend's."""
    registry = read_instance_registry(stores)
    if registry is None:
        if options.new_instance:
            return [Finding("T7", "No backend has run here; restoring as a new instance")]
        raise DumpError(
            "T7",
            f"{stores.registry_path} does not exist: no River backend has run with "
            "this data directory, or this command resolves other paths than the "
            "backend. Run it with the backend's environment and working directory "
            "(docker compose run --rm dtvp ...), or pass --new-instance",
        )
    expected = stores.as_comparable()
    recorded = registry.get("stores") or {}
    if recorded != expected:
        differences = sorted(
            name
            for name in set(recorded) | set(expected)
            if recorded.get(name) != expected.get(name)
        )
        message = (
            "The backend recorded other paths than this command resolves: "
            + ", ".join(f"{name} {recorded.get(name)!r} vs {expected.get(name)!r}" for name in differences[:5])
        )
        if not options.accept_path_change:
            raise DumpError("T6", message + ". Pass --accept-path-change if intended")
        return [Finding("T6", message)]
    return []


def check_free_space(stores: InstanceStores, declared: int) -> None:
    """T8: room for the staged copies beside each target."""
    needed: dict[str, int] = {}
    for store in stores.sqlite_records:
        directory = os.path.dirname(store.path)
        needed[directory] = needed.get(directory, 0) + 2 * declared
    for directory, amount in needed.items():
        os.makedirs(directory, exist_ok=True)
        free = shutil.disk_usage(directory).free
        if free < amount:
            raise DumpError(
                "T8", f"{directory} has {free} bytes free; staging needs about {amount}"
            )


def check_target(
    stores: InstanceStores,
    manifest: dict[str, Any],
    options: RestoreOptions,
    results: list[tuple[str, str, str, str]],
) -> tuple[list[Finding], list[Finding]]:
    """T3, T4, T5. Returns (refusals, warnings); an override turns a refusal
    into a warning."""
    refusals: list[Finding] = []
    warnings: list[Finding] = []

    def rule(code: str, message: str, overridden: bool, flag: str) -> None:
        if overridden:
            warnings.append(Finding(code, message))
        else:
            refusals.append(Finding(code, f"{message}. Pass {flag} if intended"))

    occupied = []
    tables = _record_tables()
    for store in stores.sqlite_records:
        wanted: dict[str, str | None] = {}
        for namespace in store.namespaces:
            wanted.update(tables.get(namespace, {}))
        occupied += [f"{store.path}:{table}" for table in table_has_rows(store.path, wanted)]
    for item in stores.json_records:
        if os.path.exists(item.path):
            occupied.append(item.path)
    if occupied:
        rule(
            "T3",
            "The target already holds records (" + ", ".join(occupied[:5]) + "); they "
            "would be moved aside, including its access tokens",
            options.replace,
            "--replace",
        )
    present_config = [item.path for item in stores.config if os.path.exists(item.path)]
    if present_config:
        warnings.append(
            Finding("T3", "Settings files on the target are moved aside: " + ", ".join(present_config))
        )

    dumped_url = manifest["source"]["dependency_track_url"]
    try:
        from ..dt_client import DTSettings

        target_url = sanitize_dependency_track_url(DTSettings().api_url)
    except Exception:  # pragma: no cover - configuration errors
        target_url = None
    if dumped_url is None:
        warnings.append(Finding("T4", "The dump does not name its Dependency-Track"))
    elif dumped_url != target_url:
        rule(
            "T4",
            f"The dump was taken against {dumped_url}; this River uses {target_url}",
            options.accept_dt_url_change,
            "--accept-dt-url-change",
        )

    pruned = would_prune(results)
    if pruned:
        rule(
            "T5",
            f"{len(pruned)} restored code-analysis result(s) would be deleted by this "
            "River's DTVP_CODE_ANALYSIS_RESULTS_MAX_RECORDS or RETENTION_DAYS",
            options.accept_pruning,
            "--accept-pruning",
        )
    return refusals, warnings


def would_prune(results: list[tuple[str, str, str, str]]) -> list[str]:
    """The run ids the target's pruning would delete, computed like
    ``CodeAnalysisResultStore._prune_locked`` from (run id, finished_at,
    submitted_at, record_timestamp)."""
    removed = set()
    retention_days = get_code_analysis_results_retention_days()
    if retention_days > 0:
        cutoff = (datetime.now(UTC) - timedelta(days=retention_days)).isoformat()
        removed |= {run for run, _f, _s, stamp in results if stamp != "" and stamp < cutoff}
    kept = [row for row in results if row[0] not in removed]
    kept.sort(key=lambda row: (row[1], row[2], row[0]), reverse=True)
    removed |= {row[0] for row in kept[get_code_analysis_results_max_records():]}
    return sorted(removed)


# -- the restore -------------------------------------------------------------------


class _Expected:
    """Per entity: the digest of the canonical lines of the records as
    validated (after upcasting and dropping unknown fields), and the run
    rows that pruning looks at."""

    def __init__(self) -> None:
        self.digests: dict[str, Any] = {name: hashlib.sha256() for name in schemas.ENTITY_ORDER}
        self.counts: dict[str, int] = dict.fromkeys(schemas.ENTITY_ORDER, 0)
        self.results: list[tuple[str, str, str, str]] = []

    def observe(self, entity: str, record: dict[str, Any]) -> None:
        # Compared with what the staged files hold, which is the record as
        # a restore writes it.
        self.digests[entity].update(jsonl_line(as_restored(entity, record)))
        self.counts[entity] += 1
        if entity == "code_analysis_result":
            row = result_row(record)
            self.results.append((row[0], row[6], row[7], row[9]))


def _stage(
    reader: DumpReader,
    stores: InstanceStores,
    dump_id: str,
) -> tuple[dict[str, str], dict[str, str | None]]:
    """Second pass: build the staged files. Returns the staged databases
    (target to staged path) and the other staged files (None: absent)."""
    target = SqliteDumpTarget(stores.sqlite_records, dump_id)
    try:
        for name in schemas.ENTITY_ORDER:
            target.write_entity(name, reader.iter_records(name))
        target.write_sequences(reader.manifest["cut_point"]["sequences"])
        target.finish()
    finally:
        target.close()
    staged_files: dict[str, str | None] = {}
    for item in stores.config:
        data = reader.read_config(item.name)
        staged_files[item.path] = _stage_file(item.path, dump_id, data)
    proposals = {
        record["project_name"]: record["snapshot"]
        for record in reader.iter_records("tmrescore_proposal")
    }
    path = stores.json_record_path("tmrescore_proposals")
    staged_files[path] = _stage_file(
        path, dump_id, serialize_tmrescore_cache(proposals) if proposals else None
    )
    return dict(target.staged), staged_files


def _stage_file(target: str, dump_id: str, data: bytes | None) -> str | None:
    path = staged_path(target, dump_id)
    remove_stale(path)
    if data is None:
        return None
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    fsync_directory(os.path.dirname(path))
    return path


def prove_round_trip(
    stores: InstanceStores,
    staged_databases: dict[str, str],
    staged_files: dict[str, str | None],
    manifest: dict[str, Any],
    expected: _Expected,
) -> None:
    """P2: read the staged files back as a dump would and compare every
    entity's records, the settings and the sequences with the dump."""
    snapshots = [
        direct_store(SqliteStore(store.name, staged_databases[store.path], store.namespaces))
        for store in stores.sqlite_records
    ]
    tmrescore_path = staged_files.get(stores.json_record_path("tmrescore_proposals"))
    source = SqliteDumpSource(
        snapshots,
        tmrescore=_read(tmrescore_path),
        config={item.name: _read(staged_files.get(item.path)) for item in stores.config},
        include_access_tokens=manifest["contains_credentials"],
        include_source="source" not in manifest["excluded"],
    )
    try:
        for name in schemas.ENTITY_ORDER:
            digest = hashlib.sha256()
            count = 0
            for record in source.iter_entity(name):
                digest.update(jsonl_line(record))
                count += 1
            if count != expected.counts[name] or digest.digest() != expected.digests[name].digest():
                raise DumpError(
                    "P2",
                    f"The staged {name} records differ from the dump "
                    f"({count} read back, {expected.counts[name]} dumped)",
                )
        if source.sequences() != manifest["cut_point"]["sequences"]:
            raise DumpError("P2", "The staged sequences differ from the dump")
        config = source.config()
        for name in SETTINGS_FILE_NAMES:
            spec = manifest["config"][name]
            data = config.get(name)
            if spec["absent"] != (data is None) or (
                data is not None and hashlib.sha256(data).hexdigest() != spec["sha256"]
            ):
                raise DumpError("P2", f"The staged settings file {name} differs from the dump")
    finally:
        source.close()


def _read(path: str | None) -> bytes | None:
    if path is None:
        return None
    with open(path, "rb") as handle:
        return handle.read()


def _cleanup_staged(stores: InstanceStores, dump_id: str) -> None:
    """Remove every staged file of a restore that stopped before its swap."""
    targets = [store.path for store in stores.sqlite_records]
    targets += [item.path for item in (*stores.json_records, *stores.config)]
    for target in targets:
        remove_stale(staged_path(target, dump_id))


def restore_dump(
    path: str,
    *,
    options: RestoreOptions | None = None,
    dry_run: bool = False,
    stores: InstanceStores | None = None,
) -> RestoreResult:
    """Restore a dump into this instance (offline). See the module docs."""
    options = options or RestoreOptions()
    stores = stores or resolve_instance_stores()
    if dry_run:
        return _dry_run(path, stores, options)
    started = datetime.now(UTC)
    locks = _Locks(stores)
    try:
        if stores.journals():
            raise DumpError(
                "T2",
                "A restore journal exists: run `python -m dtvp.backup recover "
                "--resume` or `--abort` first",
            )
        warnings = check_paths(stores, options)
        with DumpReader(path, allow_unknown=options.allow_unknown) as reader:
            check_free_space(stores, reader.declared_bytes)
            expected = _Expected()
            verified = read_all(reader, allow_unknown=options.allow_unknown, observe=expected.observe)
            if verified.errors:
                raise DumpError(verified.errors[0].code, verified.errors[0].message)
            refusals, target_warnings = check_target(stores, reader.manifest, options, expected.results)
            if refusals:
                raise DumpError(refusals[0].code, refusals[0].message)
            warnings += verified.warnings + target_warnings
            dump_id = reader.checked.dump_id
            run_id = restore_run_id(dump_id, started)
            check_asides_free(_planned_actions(stores, reader.manifest, dump_id, run_id))
            try:
                staged_databases, staged_files = _stage(reader, stores, dump_id)
                prove_round_trip(stores, staged_databases, staged_files, reader.manifest, expected)
            except BaseException:
                _cleanup_staged(stores, dump_id)
                raise
            manifest = reader.manifest
        actions = plan_actions(
            stores, run_id, staged_databases=staged_databases, staged_files=staged_files
        )
        comparable = stores.as_comparable()
        journal = journal_path(stores, dump_id)
        # The journal exists only once staging is complete.
        _write_journal(
            journal,
            {
                "dump_id": dump_id,
                "run_id": run_id,
                "created_at": _now(),
                "registry": comparable,
                "actions": actions,
            },
        )
        _forward(actions)
        _finish_swap(stores, journal, comparable)
        return RestoreResult(
            dump_id=dump_id,
            run_id=run_id,
            dry_run=False,
            lock_held=None,
            refusals=[],
            warnings=warnings,
            actions=actions,
            records={name: spec["records"] for name, spec in manifest["entities"].items()},
        )
    finally:
        locks.release()


def _planned_actions(
    stores: InstanceStores, manifest: dict[str, Any], dump_id: str, run_id: str
) -> list[dict[str, Any]]:
    """The actions a run would take, before anything is staged."""
    staged_files: dict[str, str | None] = {
        item.path: (None if manifest["config"][item.name]["absent"] else staged_path(item.path, dump_id))
        for item in stores.config
    }
    proposals_path = stores.json_record_path("tmrescore_proposals")
    staged_files[proposals_path] = (
        staged_path(proposals_path, dump_id)
        if manifest["entities"]["tmrescore_proposal"]["records"]
        else None
    )
    return plan_actions(
        stores,
        run_id,
        staged_databases={s.path: staged_path(s.path, dump_id) for s in stores.sqlite_records},
        staged_files=staged_files,
    )


def _dry_run(path: str, stores: InstanceStores, options: RestoreOptions) -> RestoreResult:
    refusals: list[Finding] = []
    warnings: list[Finding] = []
    lock_held = _lock_held(stores)
    if stores.journals():
        refusals.append(Finding("T2", "A restore journal exists; use recover"))
    try:
        warnings += check_paths(stores, options)
    except DumpError as exc:
        refusals.append(Finding(exc.code, exc.message))
    with DumpReader(path, allow_unknown=options.allow_unknown) as reader:
        expected = _Expected()
        verified = read_all(reader, allow_unknown=options.allow_unknown, observe=expected.observe)
        refusals += verified.errors
        warnings += verified.warnings
        target_refusals, target_warnings = check_target(stores, reader.manifest, options, expected.results)
        refusals += target_refusals
        warnings += target_warnings
        dump_id = reader.checked.dump_id
        run_id = restore_run_id(dump_id)
        actions = _planned_actions(stores, reader.manifest, dump_id, run_id)
        try:
            check_asides_free(actions)
        except DumpError as exc:
            refusals.append(Finding(exc.code, exc.message))
    return RestoreResult(
        dump_id=dump_id,
        run_id=run_id,
        dry_run=True,
        lock_held=lock_held,
        refusals=refusals,
        warnings=warnings,
        actions=actions,
        records=dict(verified.records),
    )


# -- recover ----------------------------------------------------------------------


def recover(mode: str, *, stores: InstanceStores | None = None) -> dict[str, Any]:
    """Complete (``resume``) or undo (``abort``) an interrupted restore."""
    if mode not in ("resume", "abort"):
        raise ValueError(mode)
    stores = stores or resolve_instance_stores()
    locks = _Locks(stores)
    try:
        journals = stores.journals()
        if not journals:
            raise DumpError("T2", "There is no restore journal to recover")
        if len(journals) > 1:
            raise DumpError("T2", f"More than one restore journal: {', '.join(journals)}")
        journal = journals[0]
        with open(journal, "r", encoding="utf-8") as handle:
            document = json.load(handle)
        actions = document["actions"]
        if mode == "resume":
            _forward(actions)
            _finish_swap(stores, journal, document["registry"])
        else:
            _backward(actions)
            os.remove(journal)
            fsync_directory(stores.dt_cache_dir)
        return {
            "dump_id": document["dump_id"],
            "run_id": document.get("run_id", document["dump_id"]),
            "mode": mode,
            "actions": len(actions),
        }
    finally:
        locks.release()


# -- verify --deep --------------------------------------------------------------------


def verify_deep(path: str, *, allow_unknown: bool = True) -> dict[str, Any]:
    """Stage a dump into a temporary directory (no target, no lock) and prove
    the round trip (P1-P3)."""
    with tempfile.TemporaryDirectory(prefix=".dtvp-verify-") as directory:
        stores = _scratch_stores(directory)
        with DumpReader(path, allow_unknown=allow_unknown) as reader:
            expected = _Expected()
            verified = read_all(reader, allow_unknown=allow_unknown, observe=expected.observe)
            if verified.errors:
                raise DumpError(verified.errors[0].code, verified.errors[0].message)
            staged_databases, staged_files = _stage(reader, stores, reader.checked.dump_id)
            prove_round_trip(stores, staged_databases, staged_files, reader.manifest, expected)
            return {
                "dump_id": reader.checked.dump_id,
                "records": verified.records,
                "warnings": [str(item) for item in verified.warnings],
            }


def _scratch_stores(directory: str) -> InstanceStores:
    from ..instance_stores import FileStore

    real = os.path.realpath(directory)
    main = SqliteStore(
        "main",
        os.path.join(real, "dtvp.sqlite3"),
        ("local_store", "assessment_outbox", "finding_lifecycle", "access_tokens", "saved_views"),
    )
    results = SqliteStore(
        "code_analysis_results",
        os.path.join(real, "code_analysis_results.sqlite"),
        ("code_analysis_results",),
    )
    return InstanceStores(
        dt_cache_dir=real,
        sqlite_records=(main, results),
        json_records=(FileStore("tmrescore_proposals", os.path.join(real, "tmrescore_proposals.json")),),
        config=tuple(FileStore(name, os.path.join(real, f"{name}.json")) for name in SETTINGS_FILE_NAMES),
        caches=(),
        legacy_inputs=(),
        lock_path=os.path.join(real, ".lock"),
        export_lock_path=os.path.join(real, ".export.lock"),
        registry_path=os.path.join(real, ".registry.json"),
        journal_glob=os.path.join(real, ".journal-*.json"),
    )
