"""What each data-changing migration means for dumped records.

A restore builds the target schema with the target's own migrations and
writes the records through the current code. A migration that changes rows
(INSERT, UPDATE or DELETE) could change what a record means; each one is
listed here, and tests/test_backup_coverage.py fails on a migration that is
missing or names an upcaster that does not exist.

- ``Baseline``: applied before dump/1 existed; every dump is written from a
  fully migrated database, so no dump holds data from before it.
- ``NoRecordEffect``: changes only data that is not dumped, or nothing a
  record means.
- ``Upcaster``: records of an older entity schema need the named upcaster.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class Baseline:
    pass


@dataclass(frozen=True)
class NoRecordEffect:
    reason: str


@dataclass(frozen=True)
class Upcaster:
    entity: str
    from_version: int


Effect = Baseline | NoRecordEffect | Upcaster

MIGRATION_RECORD_EFFECTS: dict[tuple[str, int], Effect] = {
    ("local_store", 2): Baseline(),
    ("assessment_outbox", 3): Baseline(),
    ("assessment_outbox", 4): Baseline(),
    ("assessment_outbox", 6): Baseline(),
    ("assessment_outbox", 7): Baseline(),
    ("assessment_outbox", 8): Baseline(),
    ("assessment_outbox", 9): NoRecordEffect("derived fields tables only"),
    ("local_store", 6): NoRecordEffect("sync_versions only, which is not dumped"),
    ("local_store", 7): NoRecordEffect("sync_versions only, which is not dumped"),
    ("local_store", 8): NoRecordEffect("sync_versions only, which is not dumped"),
    ("local_store", 9): NoRecordEffect("sync_versions only, which is not dumped"),
}
