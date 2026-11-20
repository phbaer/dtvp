"""The ports export and restore are written against. The SQLite adapters
(``sqlite_source``, ``sqlite_target``) own the storage details; another
storage engine implements the same ports without changing the format."""

from dataclasses import dataclass, field
from typing import Any, Iterator, Protocol


@dataclass(frozen=True)
class MigrationInfo:
    namespace: str
    version: int
    name: str
    checksum: str

    def as_manifest(self) -> dict[str, Any]:
        return {
            "namespace": self.namespace,
            "version": self.version,
            "name": self.name,
            "checksum": self.checksum,
        }


@dataclass(frozen=True)
class StoreInfo:
    name: str
    namespaces: tuple[str, ...]
    migrations: tuple[MigrationInfo, ...] = ()
    snapshot_at: str | None = None
    snapshot_method: str = "absent"
    extra: dict[str, Any] = field(default_factory=dict, compare=False)

    def as_manifest(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "namespaces": list(self.namespaces),
            "migrations": [migration.as_manifest() for migration in self.migrations],
            "snapshot_at": self.snapshot_at,
            "snapshot_method": self.snapshot_method,
        }


class DumpSource(Protocol):
    def stores(self) -> list[StoreInfo]: ...

    def iter_entity(self, name: str) -> Iterator[dict[str, Any]]:
        """The records of an entity, in the entity's defined order."""
        ...

    def sequences(self) -> dict[str, int]: ...

    def config(self) -> dict[str, bytes | None]:
        """Each settings file's bytes, or None when it does not exist."""
        ...

    def close(self) -> None: ...


class DumpTarget(Protocol):
    def write_entity(self, name: str, records: Iterator[dict[str, Any]]) -> int: ...

    def write_sequences(self, sequences: dict[str, int]) -> None: ...

    def write_config(self, config: dict[str, bytes | None]) -> None: ...

    def finish(self) -> None: ...

    def close(self) -> None: ...
