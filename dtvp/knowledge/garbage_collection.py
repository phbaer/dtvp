"""Bounded global orphan audit. Reachability is not deletion eligibility.

Publication locking cannot fence object staging or SQL-backed jobs. Consequently
this module deliberately provides no collection operation or executable plan.
"""

import json
import re
import stat
from datetime import UTC, datetime

from dtvp.knowledge.journal import CorruptJournal, Section
from dtvp.storage import canonical, digest

SHA = re.compile(r"^[0-9a-f]{64}$")
BLOCKERS = [
    "Object staging is not fenced by the journal publication lock.",
    "Operational job/checkpoint references are not exhaustively registered with the journal.",
    "Storage-unreachable objects may still belong to active or retryable operations.",
]


def _inventory(journal, max_objects, max_bytes):
    result, ignored, size = {}, 0, 0
    for shard in journal.objects.root.iterdir():
        if shard.is_symlink():
            raise CorruptJournal("Object storage contains a symbolic link")
        if not shard.is_dir() or not re.fullmatch(r"[0-9a-f]{2}", shard.name):
            raise CorruptJournal("Unexpected object storage entry")
        for path in shard.iterdir():
            if len(result) + ignored >= max_objects:
                raise ValueError("Orphan audit exceeds configured storage bounds")
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise CorruptJournal("Object storage entry is not a private regular file")
            sha = shard.name + path.name
            if not SHA.fullmatch(sha):
                # Artifacts.put uses temporary regular files before atomic linking.
                ignored += 1
                continue
            size += info.st_size
            if len(result) >= max_objects or size > max_bytes:
                raise ValueError("Orphan audit exceeds configured storage bounds")
            result[sha] = {
                "bytes": info.st_size,
                "mtime_ns": info.st_mtime_ns,
                "ctime_ns": info.st_ctime_ns,
                "inode": info.st_ino,
                "device": info.st_dev,
            }
    return result, ignored


def _sha_values(value):
    pending = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, str) and SHA.fullmatch(item):
            yield item
        elif isinstance(item, dict):
            pending.extend(item.keys())
            pending.extend(item.values())
        elif isinstance(item, list):
            pending.extend(item)


def preview_unreferenced_objects(
    journal,
    *,
    min_age_days=None,
    operational_roots=(),
    now=None,
    offset=0,
    limit=50,
    max_objects=100_000,
    max_bytes=256 * 1024 * 1024,
    age_filtered=False,
):
    """Inspect all projects/history; caller must enforce instance-wide authority.

    Operational roots are supplemental *hints*, never a completeness declaration.
    Age is filesystem modification age, not time since last use. No default
    policy enables cleanup, and even age-matching objects remain ineligible.
    The digest pins this observation, not permission to execute deletion.
    """
    if offset < 0 or not 1 <= limit <= 200:
        raise ValueError("Invalid orphan audit page bounds")
    if min_age_days is not None and (
        isinstance(min_age_days, bool) or not isinstance(min_age_days, int) or min_age_days < 1
    ):
        raise ValueError("Minimum age must be an explicit positive number of days")
    if not 1 <= max_objects <= 100_000 or not 1 <= max_bytes <= 256 * 1024 * 1024:
        raise ValueError("Invalid orphan audit storage bounds")
    now = now or datetime.now(UTC)
    if now.tzinfo is None:
        raise ValueError("Audit time must include a timezone")
    roots = sorted(set(operational_roots))
    if any(not isinstance(sha, str) or not SHA.fullmatch(sha) for sha in roots):
        raise ValueError("Invalid supplemental operational root")

    with journal.writer():
        head = journal.head()
        inventory, ignored = _inventory(journal, max_objects, max_bytes)
        # Check every advertised digest, including orphan bytes; corruption must
        # never be silently reclassified as disposable data.
        for sha in inventory:
            try:
                journal.objects.read(sha)
            except (ValueError, OSError) as error:
                raise CorruptJournal("Object audit found corrupt or missing bytes") from error

        protected, states, pending = set(), set(), []
        publications = list(journal.publications(head=head)) if head else []
        for sha, publication in publications:
            protected.add(sha)
            for update in publication.updates:
                pending.append((update.target, update.ref.project_id))
            # Protect the complete retained reference snapshot, not only updates.
            pending.extend((target, None) for target in publication.refs.values())
        while pending:
            sha, project_id = pending.pop()
            revision = journal.state(sha)
            if project_id is not None and revision.project_id != project_id:
                raise CorruptJournal("Retained state crosses product lines")
            if sha in states:
                continue
            states.add(sha)
            protected.add(sha)
            for section in revision.sections.values():
                protected.add(section)
                protected.update(journal.load(section, Section).records.values())
            protected.update(revision.artifacts)
            pending.extend((parent, revision.project_id) for parent in revision.parents)

        protected.update(roots)
        pending = list(protected)
        inspected = set()
        while pending:
            sha = pending.pop()
            if sha in inspected:
                continue
            inspected.add(sha)
            if sha not in inventory:
                raise CorruptJournal("Retained or operational root references missing bytes")
            raw = journal.objects.read(sha)
            try:
                value = json.loads(raw)
            except ValueError, UnicodeError, RecursionError:
                continue  # Opaque source/issued bytes are protected as a whole.
            # Conservatively retain stored objects mentioned by opaque records,
            # such as export index buckets and assessment revision references.
            for target in _sha_values(value):
                if target in inventory and target not in protected:
                    protected.add(target)
                    pending.append(target)

        if journal.head() != head or _inventory(journal, max_objects, max_bytes) != (
            inventory,
            ignored,
        ):
            raise ValueError("Object storage changed during audit; retry")
        facts = {
            "format": "dtvp.orphan-audit/1",
            "head": head,
            "evaluated_at": now.isoformat(),
            "min_age_days": min_age_days,
            "operational_root_hints": roots,
            "inventory": inventory,
            "protected": sorted(protected),
            "ignored_staging_files": ignored,
            "age_filtered": age_filtered,
        }
        items = []
        for sha in sorted(inventory.keys() - protected):
            info = inventory[sha]
            age = (now.timestamp() - info["mtime_ns"] / 1_000_000_000) / 86400
            items.append(
                {
                    "sha256": sha,
                    "bytes": info["bytes"],
                    "status": "storage_unreachable",
                    "modification_age_days": max(0, int(age)),
                    "age_matches_policy": min_age_days is not None and age >= min_age_days,
                    "eligible_for_deletion": False,
                }
            )
        listed = [item for item in items if item["age_matches_policy"]] if age_filtered else items
        return {
            "format": facts["format"],
            "head": head,
            "plan_hash": digest(canonical(facts)),
            "evaluated_at": facts["evaluated_at"],
            "min_age_days": min_age_days,
            "operational_root_hints": roots,
            "operational_references_complete": False,
            "execution_supported": False,
            "blockers": list(BLOCKERS),
            "items": listed[offset : offset + limit],
            "total": len(listed),
            "next_offset": offset + limit if offset + limit < len(listed) else None,
            "statistics": {
                "objects": len(inventory),
                "protected_objects": len(protected),
                "storage_unreachable_objects": len(items),
                "storage_unreachable_bytes": sum(item["bytes"] for item in items),
                "age_matching_objects": sum(item["age_matches_policy"] for item in items),
                "eligible_for_deletion": 0,
                "ignored_staging_files": ignored,
            },
        }


def main():
    """Instance-operator audit only; deliberately no deletion command."""
    import argparse
    from pathlib import Path

    from dtvp.knowledge.journal import Journal

    parser = argparse.ArgumentParser(description="Read-only global journal orphan audit")
    parser.add_argument("--journal", type=Path, required=True)
    parser.add_argument("--min-age-days", type=int)
    parser.add_argument("--operational-root", action="append", default=[])
    parser.add_argument("--offset", type=int, default=0)
    parser.add_argument("--limit", type=int, default=50)
    args = parser.parse_args()
    root = args.journal.resolve()
    if not (root / "FORMAT").is_file() or not (root / "HEAD").is_file():
        parser.error("Select an existing initialized journal; audit does not create one")
    result = preview_unreferenced_objects(
        Journal(root),
        min_age_days=args.min_age_days,
        operational_roots=args.operational_root,
        offset=args.offset,
        limit=args.limit,
    )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
