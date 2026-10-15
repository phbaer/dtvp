"""Offline verification of a pinned committed journal; no SQL or repair writes."""

from dtvp.knowledge.journal import CorruptJournal, Section


def verify_journal(journal):
    head = journal.head()
    if head is None:
        return {"head": None, "publications": 0, "states": 0, "objects": 0, "bytes": 0}
    objects, pending, states = set(), [], set()
    publications = list(journal.publications(head=head))
    for sha, publication in publications:
        objects.add(sha)
        for update in publication.updates:
            revision = journal.state(update.target)
            if revision.project_id != update.ref.project_id:
                raise CorruptJournal("Published state belongs to another product line")
            pending.append((update.target, revision.project_id))
    while pending:
        sha, project_id = pending.pop()
        revision = journal.state(sha)
        if revision.project_id != project_id:
            raise CorruptJournal("State parent belongs to another product line")
        if sha in states:
            continue
        states.add(sha)
        objects.add(sha)
        for section in revision.sections.values():
            objects.add(section)
            objects.update(journal.load(section, Section).records.values())
        objects.update(revision.artifacts)
        pending.extend((parent, project_id) for parent in revision.parents)
    try:
        size = sum(len(journal.objects.read(sha)) for sha in sorted(objects))
    except (ValueError, OSError) as error:
        raise CorruptJournal("Committed history references corrupt or missing data") from error
    return {
        "head": head,
        "publications": len(publications),
        "states": len(states),
        "objects": len(objects),
        "bytes": size,
    }
