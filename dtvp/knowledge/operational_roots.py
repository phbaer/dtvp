"""Bounded, secret-free SQL snapshot for stopped-writer journal maintenance."""

import hashlib
import re
from datetime import date, datetime

from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import MetaData, Table, inspect, select

from dtvp.db import ROOT
from dtvp.knowledge import projection  # noqa: F401 -- register projection tables
from dtvp.knowledge.journal import CorruptJournal
from dtvp.models import Base
from dtvp.storage import canonical

MAX_ROWS = 1_000_000
MAX_BYTES = 256 * 1024 * 1024
TOKEN = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])")
SHA = re.compile(r"[0-9a-f]{64}")
NATIVE_KINDS = {
    "analyse-native",
    "import-dt-native",
    "refresh-advisories-native",
    "match-osv-native",
}


def _encode(value):
    if isinstance(value, (datetime, date)):
        return {"$timestamp": value.isoformat()}
    if isinstance(value, dict):
        return {key: _encode(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_encode(item) for item in value]
    return value


def _values(value):
    pending = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, str):
            yield item
        elif isinstance(item, dict):
            pending.extend(item.keys())
            pending.extend(item.values())
        elif isinstance(item, (list, tuple)):
            pending.extend(item)


def _required(journal, value, roots):
    if not isinstance(value, str) or not SHA.fullmatch(value):
        raise CorruptJournal("Invalid retained operational object reference")
    try:
        journal.objects.read(value)
    except (OSError, ValueError) as error:
        raise CorruptJournal("Retained operational object is missing or corrupt") from error
    roots.add(value)


def _job_roots(journal, row, roots):
    if row["kind"] not in NATIVE_KINDS:
        return
    for field in ("payload", "result"):
        document = row[field]
        if not isinstance(document, dict):
            raise CorruptJournal("Invalid retained native job document")
        for key in ("capture_sha256", "progress_sha256", "report_sha256"):
            if key in document:
                _required(journal, document[key], roots)
        if "raw_artifact_shas" in document:
            values = document["raw_artifact_shas"]
            if not isinstance(values, list):
                raise CorruptJournal("Invalid retained operational artifact list")
            for value in values:
                _required(journal, value, roots)
    payload = row["payload"]
    correlations = [payload.get("correlation")]
    follow_up = payload.get("follow_up")
    if isinstance(follow_up, dict):
        correlations.append(follow_up.get("parent_correlation"))
        if "parent_report_sha256" in follow_up:
            _required(journal, follow_up["parent_report_sha256"], roots)
        correlation = payload.get("correlation")
        if isinstance(correlation, dict) and "submission_sha256" in correlation:
            wire = follow_up.get("wire_request")
            if (
                not isinstance(wire, dict)
                or hashlib.sha256(canonical(wire)).hexdigest() != (correlation["submission_sha256"])
            ):
                raise CorruptJournal("Retained follow-up submission fingerprint differs")
    for correlation in correlations:
        if isinstance(correlation, dict) and "issued_receipt_sha256" in correlation:
            _required(journal, correlation["issued_receipt_sha256"], roots)


def snapshot_operational_roots(connection, journal):
    """Read every current-schema row; callers stop writers and own transaction/locks.

    All statuses remain retained. Ordinary hash-like values are roots only when
    present in journal storage; credentials and fingerprints are not object IDs.
    Known checkpoint references fail closed when missing. No row data is returned.
    """
    inspector = inspect(connection)
    expected = {name: set(table.columns.keys()) for name, table in Base.metadata.tables.items()}
    expected["alembic_version"] = {"version_num"}
    if inspector.get_view_names() or set(inspector.get_table_names()) != set(expected):
        raise ValueError("Operational cleanup requires the exact current database schema")
    if connection.dialect.name == "postgresql" and inspector.get_materialized_view_names():
        raise ValueError("Operational cleanup does not support materialized views")
    for name, columns in expected.items():
        if {column["name"] for column in inspector.get_columns(name)} != columns:
            raise ValueError("Operational cleanup requires the exact current database columns")
    head = ScriptDirectory.from_config(Config(str(ROOT / "alembic.ini"))).get_current_head()
    if MigrationContext.configure(connection).get_current_heads() != (head,):
        raise ValueError("Operational cleanup requires the current migration revision")

    tables = dict(Base.metadata.tables)
    tables["alembic_version"] = Table("alembic_version", MetaData(), autoload_with=connection)
    hasher = hashlib.sha256()
    hasher.update(
        canonical(
            {
                "format": "dtvp.operational-roots/1",
                "schema": {name: sorted(columns) for name, columns in expected.items()},
            }
        )
    )
    roots, counts, rows, size = set(), {}, 0, 0
    for name, table in sorted(tables.items()):
        keys = list(table.primary_key.columns)
        if not keys:
            raise ValueError("Operational cleanup requires deterministic table primary keys")
        counts[name] = 0
        result = connection.execute(
            select(table).order_by(*keys).execution_options(stream_results=True)
        )
        try:
            for row in result.mappings():
                rows += 1
                if rows > MAX_ROWS:
                    raise ValueError("Operational snapshot exceeds configured row bound")
                try:
                    document = dict(row)
                    raw = canonical([name, _encode(document)])
                except (TypeError, ValueError, RecursionError) as error:
                    raise ValueError("Operational snapshot contains unsupported values") from error
                size += len(raw)
                if size > MAX_BYTES:
                    raise ValueError("Operational snapshot exceeds configured byte bound")
                hasher.update(len(raw).to_bytes(8, "big"))
                hasher.update(raw)
                counts[name] += 1
                if name == "jobs":
                    _job_roots(journal, document, roots)
                for value in _values(document):
                    for match in TOKEN.finditer(value):
                        sha = match.group().lower()
                        if sha in roots or not journal.objects.path(sha).exists():
                            continue
                        _required(journal, sha, roots)
        finally:
            result.close()
    return {
        "format": "dtvp.operational-roots/1",
        "database_digest": hasher.hexdigest(),
        "roots": sorted(roots),
        "table_counts": counts,
        "schema_revision": head,
    }
