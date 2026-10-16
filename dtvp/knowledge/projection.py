"""Disposable active-state projection. Journal publication precedes SQL writes."""

from sqlalchemy import Column, Integer, String, Table, delete, insert, select, update

from dtvp.knowledge.journal import CorruptJournal, Ref
from dtvp.models import Base, Document

heads = Table(
    "knowledge_heads",
    Base.metadata,
    Column("ref_key", String(1000), primary_key=True),
    Column("project_id", String(200), nullable=False, index=True),
    Column("kind", String(20), nullable=False),
    Column("name", String(200), nullable=False),
    Column("state_sha", String(64), nullable=False),
)
records = Table(
    "knowledge_records",
    Base.metadata,
    Column("ref_key", String(1000), primary_key=True),
    Column("section", String(40), primary_key=True),
    Column("record_key", String(200), primary_key=True),
    Column("sha", String(64), nullable=False),
    Column("data", Document, nullable=False),
)
cursor = Table(
    "knowledge_cursor",
    Base.metadata,
    Column("id", Integer, primary_key=True),
    Column("publication_sha", String(64)),
    Column("sequence", Integer, nullable=False),
)


def apply_state(connection, journal, ref, state_sha):
    state = journal.verify_state(state_sha)
    if state.project_id != ref.project_id:
        raise CorruptJournal("Reference and state product lines disagree")
    current = connection.execute(select(heads).where(heads.c.ref_key == ref.key)).first()
    if current and current.state_sha == state_sha:
        return
    # Tags and constituent sources need only references. Their immutable data
    # is loaded on demand; source intake must not create product inventory rows.
    if ref.kind == "branch":
        for section in state.sections:
            old = dict(
                connection.execute(
                    select(records.c.record_key, records.c.sha).where(
                        records.c.ref_key == ref.key, records.c.section == section
                    )
                ).all()
            )
            new = journal.records(state_sha, section)
            changed = {key for key in old.keys() | new.keys() if old.get(key) != new.get(key)}
            # Bounded SQL parameter batches also support the isolated SQLite adapter.
            keys = sorted(changed)
            for offset in range(0, len(keys), 200):
                batch = keys[offset : offset + 200]
                connection.execute(
                    delete(records).where(
                        records.c.ref_key == ref.key,
                        records.c.section == section,
                        records.c.record_key.in_(batch),
                    )
                )
                values = [
                    dict(
                        ref_key=ref.key,
                        section=section,
                        record_key=key,
                        sha=new[key],
                        data=journal.load(new[key]),
                    )
                    for key in batch
                    if key in new
                ]
                if values:
                    connection.execute(insert(records), values)
    values = dict(project_id=ref.project_id, kind=ref.kind, name=ref.name, state_sha=state_sha)
    if current:
        connection.execute(update(heads).where(heads.c.ref_key == ref.key).values(**values))
    else:
        connection.execute(insert(heads).values(ref_key=ref.key, **values))


def catch_up(engine, journal, *, rebuild=False):
    """One atomic SQL update, serialized with other projections/publications.

    Rebuild reads complete current manifests, not historical business events.
    It changes only knowledge_* tables; auth, v2 data and jobs are untouched.
    """
    with journal.writer(), engine.begin() as connection:
        position = connection.execute(
            select(cursor).where(cursor.c.id == 1).with_for_update()
        ).first()
        head = journal.head()
        if not position:
            raise CorruptJournal("Missing projection checkpoint; rebuild explicitly")
        if rebuild:
            connection.execute(delete(records))
            connection.execute(delete(heads))
            # Verify reference transaction history before using the complete head.
            for _ in journal.publications(head):
                pass
            if head:
                from dtvp.knowledge.journal import Publication

                publication = journal.load(head, Publication)
                for key, state_sha in publication.refs.items():
                    apply_state(connection, journal, Ref.model_validate_json(key), state_sha)
                sequence = publication.sequence
            else:
                sequence = 0
        else:
            sequence = position.sequence
            for _, publication in journal.publications(head, after=position.publication_sha):
                for change in publication.updates:
                    apply_state(connection, journal, change.ref, change.target)
                sequence = publication.sequence
        connection.execute(
            update(cursor).where(cursor.c.id == 1).values(publication_sha=head, sequence=sequence)
        )
        return {"publication": head, "sequence": sequence}


def is_current(engine, journal):
    """Read one guarded checkpoint; never project data or verify full history.

    The writer lock prevents a journal publication/projection from moving between
    these reads. This only establishes cursor alignment, not object completeness
    or external evidence correctness; offline verification remains separate.
    """
    from dtvp.knowledge.journal import Publication

    with journal.writer(), engine.connect() as connection:
        head = journal.head()
        position = connection.execute(select(cursor).where(cursor.c.id == 1)).first()
        sequence = journal.load(head, Publication).sequence if head else 0
        return bool(position and position.publication_sha == head and position.sequence == sequence)
