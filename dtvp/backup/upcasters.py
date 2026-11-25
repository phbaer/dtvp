"""Upcasters from older entity schema versions to the current one.

``UPCASTERS[(entity, from_n)] = (to_n, function)``. A function takes a record
of version ``from_n`` and returns one of ``to_n``; it must be pure. The
reader applies the chain up to the current version and validates after
upcasting. Every upcaster comes with frozen fixtures of the old version.
Version 1 is the first version of every entity, so the table is empty.
"""

from typing import Any, Callable

from .errors import DumpError
from .schemas import ENTITY_SCHEMA_VERSIONS

Upcast = Callable[[dict[str, Any]], dict[str, Any]]

UPCASTERS: dict[tuple[str, int], tuple[int, Upcast]] = {}


def upcast_chain(
    entity: str,
    from_version: int,
    *,
    current: dict[str, int] | None = None,
    upcasters: dict[tuple[str, int], tuple[int, Upcast]] | None = None,
) -> list[Upcast]:
    """The functions that bring a record of ``from_version`` to the current
    version. Refuses a newer version (F7) and a gap in the chain (F8)."""
    target = (current or ENTITY_SCHEMA_VERSIONS)[entity]
    table = UPCASTERS if upcasters is None else upcasters
    if from_version > target:
        raise DumpError(
            "F7",
            f"{entity} records are schema version {from_version}; this River "
            f"reads up to version {target}. Use a newer River.",
        )
    chain: list[Upcast] = []
    version = from_version
    while version < target:
        link = table.get((entity, version))
        if link is None:
            raise DumpError(
                "F8",
                f"No upcaster for {entity} records from schema version {version}",
            )
        version, function = link
        chain.append(function)
    return chain


def apply_chain(chain: list[Upcast], record: dict[str, Any]) -> dict[str, Any]:
    for function in chain:
        record = function(record)
    return record
