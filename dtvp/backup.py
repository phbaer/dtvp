"""Sealed logical recovery data before implicit schema upgrades."""

import hashlib
import json
import os
from datetime import date, datetime
from pathlib import Path

from sqlalchemy import MetaData, inspect, select


def encode(value):
    if isinstance(value, (datetime, date)):
        return {"$timestamp": value.isoformat()}
    raise TypeError(type(value).__name__)


def backup(connection, directory: Path, revision: str):
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    name = f"schema-{revision}-{datetime.now().strftime('%Y%m%dT%H%M%S%f')}"
    partial = directory / (name + ".partial")
    target = directory / (name + ".jsonl")
    metadata = MetaData()
    metadata.reflect(bind=connection)
    hasher, count = hashlib.sha256(), 0
    fd = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        for table in metadata.sorted_tables:
            for row in connection.execute(select(table)).mappings():
                raw = (
                    json.dumps(
                        {"table": table.name, "row": dict(row)}, default=encode, sort_keys=True
                    )
                    + "\n"
                ).encode()
                stream.write(raw)
                hasher.update(raw)
                count += 1
        stream.flush()
        os.fsync(stream.fileno())
    os.rename(partial, target)
    manifest = target.with_suffix(".manifest.json")
    descriptor = os.open(manifest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        json.dump(
            {
                "schema": revision,
                "sha256": hasher.hexdigest(),
                "rows": count,
                "tables": inspect(connection).get_table_names(),
            },
            stream,
        )
        stream.flush()
        os.fsync(stream.fileno())
    return target
