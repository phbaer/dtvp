"""Explicit bounded offline collection, with SQL roots and exact recovery copies."""

import argparse
import json
import os
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import inspect, select

from dtvp.knowledge.garbage_collection import preview_unreferenced_objects
from dtvp.knowledge.journal import Journal, sync_directory
from dtvp.knowledge.maintenance_lock import maintenance_exclusive
from dtvp.knowledge.operational_roots import snapshot_operational_roots
from dtvp.knowledge.projection import cursor
from dtvp.storage import canonical, digest

MAX_PLAN_BYTES = 16 * 1024 * 1024


def _write_new(path, value):
    raw = value if isinstance(value, bytes) else canonical(value)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    sync_directory(path.parent)


@contextmanager
def _offline(journal_dir, engine):
    root = Path(journal_dir).resolve()
    if not (root / "FORMAT").is_file() or not (root / "HEAD").is_file():
        raise ValueError("Offline cleanup requires an existing initialized journal")
    with maintenance_exclusive(root), engine.connect() as connection:
        if connection.dialect.name == "postgresql":
            connection.exec_driver_sql("SET LOCAL lock_timeout = '5s'")
            names = inspect(connection).get_table_names()
            quote = connection.dialect.identifier_preparer.quote
            if names:
                connection.exec_driver_sql(
                    "LOCK TABLE "
                    + ", ".join(quote(name) for name in sorted(names))
                    + " IN SHARE MODE"
                )
        elif connection.dialect.name == "sqlite":
            connection.exec_driver_sql("BEGIN EXCLUSIVE")
        else:
            raise ValueError("Offline cleanup supports PostgreSQL or isolated SQLite only")
        try:
            journal = Journal(root)
            position = connection.execute(select(cursor)).one()
            head = journal.head()
            sequence = journal.load(head)["sequence"] if head else 0
            if position.publication_sha != head or position.sequence != sequence:
                raise ValueError("Operational database projection does not match this journal")
            yield journal, connection
        finally:
            connection.rollback()


def _plan(journal, connection, *, min_age_days, evaluated_at, limit):
    if isinstance(min_age_days, bool) or not isinstance(min_age_days, int) or min_age_days < 1:
        raise ValueError("Cleanup requires an explicit positive minimum age in days")
    operational = snapshot_operational_roots(connection, journal)
    audit = preview_unreferenced_objects(
        journal,
        min_age_days=min_age_days,
        operational_roots=operational["roots"],
        now=evaluated_at,
        limit=limit,
        age_filtered=True,
    )
    if audit["statistics"]["ignored_staging_files"]:
        raise ValueError("Unfinished staging files require investigation before cleanup")
    plan = {
        "format": "dtvp.offline-cleanup/1",
        "journal": str(journal.root),
        "evaluated_at": evaluated_at.isoformat(),
        "min_age_days": min_age_days,
        "limit": limit,
        "database": operational,
        "audit_digest": audit["plan_hash"],
        "head": audit["head"],
        "objects": [{"sha256": item["sha256"], "bytes": item["bytes"]} for item in audit["items"]],
        "total_age_matching": audit["total"],
        "operational_references_complete": True,
        "requires_offline_maintenance": True,
        "recovery_copy_required": True,
    }
    return {**plan, "plan_digest": digest(canonical(plan))}


def plan_cleanup(journal_dir, engine, *, min_age_days, limit=200):
    with _offline(journal_dir, engine) as (journal, connection):
        return _plan(
            journal,
            connection,
            min_age_days=min_age_days,
            evaluated_at=datetime.now(UTC),
            limit=limit,
        )


def apply_cleanup(journal_dir, engine, plan, *, recovery_dir):
    if not isinstance(plan, dict) or plan.get("format") != "dtvp.offline-cleanup/1":
        raise ValueError("Unsupported offline cleanup plan")
    if len(canonical(plan)) > MAX_PLAN_BYTES:
        raise ValueError("Offline cleanup plan exceeds its size bound")
    if digest(
        canonical({key: value for key, value in plan.items() if key != "plan_digest"})
    ) != plan.get("plan_digest"):
        raise ValueError("Offline cleanup plan digest differs")
    stamp = datetime.fromisoformat(plan["evaluated_at"])
    if stamp.tzinfo is None or stamp > datetime.now(UTC):
        raise ValueError("Invalid cleanup observation time")
    recovery = Path(recovery_dir).resolve()
    root = Path(journal_dir).resolve()
    if recovery == root.parent or root.parent in recovery.parents:
        raise ValueError("Recovery copies must be outside the installation artifact directory")
    with _offline(root, engine) as (journal, connection):
        current = _plan(
            journal,
            connection,
            min_age_days=plan["min_age_days"],
            evaluated_at=stamp,
            limit=plan["limit"],
        )
        if current != plan:
            raise ValueError("Cleanup inputs changed; prepare and review a new plan")
        recovery.mkdir(mode=0o700, parents=False, exist_ok=False)
        sync_directory(recovery.parent)
        _write_new(recovery / "plan.json", plan)
        # Complete every recovery copy before deleting the first original.
        for item in plan["objects"]:
            raw = journal.objects.read(item["sha256"])
            if len(raw) != item["bytes"]:
                raise ValueError("Cleanup object size changed")
            _write_new(recovery / item["sha256"], raw)
        _write_new(
            recovery / "recovery-ready.json",
            {
                "format": "dtvp.offline-cleanup-recovery/1",
                "plan_digest": plan["plan_digest"],
                "objects": plan["objects"],
            },
        )
        with journal.writer():
            if (
                journal.head() != plan["head"]
                or snapshot_operational_roots(connection, journal) != plan["database"]
            ):
                raise ValueError("Cleanup references changed before deletion")
            # Recheck all bytes and copies before any unlink, including manual tampering.
            for item in plan["objects"]:
                sha = item["sha256"]
                if journal.objects.read(sha) != (recovery / sha).read_bytes():
                    raise ValueError("Recovery copy differs from original bytes")
            removed = []
            for item in plan["objects"]:
                sha = item["sha256"]
                path = journal.objects.path(sha)
                path.unlink()
                sync_directory(path.parent)
                removed.append(sha)
                _write_new(
                    recovery / ("removed-" + sha + ".json"), {"sha256": sha, "bytes": item["bytes"]}
                )
        receipt = {
            "format": "dtvp.offline-cleanup-receipt/1",
            "plan_digest": plan["plan_digest"],
            "removed": removed,
            "recovery_directory": str(recovery),
        }
        _write_new(recovery / "receipt.json", receipt)
        return receipt


def main():
    from dtvp.db import engine_for

    parser = argparse.ArgumentParser(description="Offline journal cleanup; stop API/workers first")
    parser.add_argument("--journal", type=Path, required=True)
    parser.add_argument("--database-url-env", default="DTVP_DATABASE_URL")
    commands = parser.add_subparsers(dest="command", required=True)
    preview = commands.add_parser("plan")
    preview.add_argument("--min-age-days", type=int, required=True)
    preview.add_argument("--limit", type=int, default=200)
    preview.add_argument("--output", type=Path, required=True)
    apply = commands.add_parser("apply")
    apply.add_argument("--plan", type=Path, required=True)
    apply.add_argument("--recovery-dir", type=Path, required=True)
    args = parser.parse_args()
    database_url = os.getenv(args.database_url_env)
    if not database_url:
        parser.error("Set the selected operational database URL environment variable")
    engine = engine_for(database_url)
    try:
        if args.command == "plan":
            result = plan_cleanup(
                args.journal, engine, min_age_days=args.min_age_days, limit=args.limit
            )
            _write_new(args.output, result)
        else:
            if args.plan.stat().st_size > MAX_PLAN_BYTES:
                raise ValueError("Offline cleanup plan exceeds its size bound")
            result = apply_cleanup(
                args.journal,
                engine,
                json.loads(args.plan.read_bytes()),
                recovery_dir=args.recovery_dir,
            )
        print(json.dumps(result, indent=2))
    finally:
        engine.dispose()


if __name__ == "__main__":
    main()
