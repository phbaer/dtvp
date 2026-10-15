"""Local immutable snapshots with one durable, atomic publication pointer.

The journal is authoritative. Filesystem flock serializes writers, including
separate API processes. HEAD replacement is the commit point for all references.
An exception during/after replacement is an uncertain commit: retry the same
request ID. No PostgreSQL transaction is involved in publishing knowledge.
"""

import fcntl
import json
import os
import tempfile
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

from dtvp.storage import Artifacts, canonical

Sha = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
Name = Annotated[str, Field(min_length=1, max_length=200, pattern=r"^[^\x00-\x1f\x7f]+$")]
RecordKey = Annotated[str, Field(min_length=1, max_length=200)]
SectionName = Literal[
    "inventory", "ownership", "vulnerabilities", "assessments", "reviews", "scoring", "history"
]
SECTIONS = SectionName.__args__


class Conflict(ValueError):
    """Expected heads or idempotency inputs no longer match."""


class CorruptJournal(RuntimeError):
    """Never recover by silently discarding an unreadable committed state."""


class CommitUncertain(OSError):
    """Retry the identical request; HEAD may already reference this publication."""

    def __init__(self, publication):
        super().__init__("Publication durability is uncertain; retry the same request")
        self.publication = publication


class Record(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Section(Record):
    format: Literal["dtvp.section/1"] = "dtvp.section/1"
    records: dict[RecordKey, Sha]


class Revision(Record):
    format: Literal["dtvp.state/1"] = "dtvp.state/1"
    project_id: Name
    version: Name
    actor_id: Name
    created_at: str
    reason: Name
    parents: list[Sha]
    sections: dict[SectionName, Sha]
    artifacts: list[Sha] = Field(default_factory=list)


class Ref(Record):
    kind: Literal["branch", "tag", "source", "policy", "evidence"] = "branch"
    project_id: Name
    name: Name

    @property
    def key(self):
        # Names never become filesystem paths; length-prefixed JSON is unambiguous.
        return canonical(self.model_dump()).decode()


class Update(Record):
    ref: Ref
    expected: Sha | None
    target: Sha


class Publication(Record):
    format: Literal["dtvp.publication/1"] = "dtvp.publication/1"
    sequence: int = Field(ge=1)
    previous: Sha | None
    request_id: Name
    fingerprint: Sha
    updates: list[Update]
    refs: dict[str, Sha]


def sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def durable_directory(path):
    if not path.exists():
        durable_directory(path.parent)
        path.mkdir(exist_ok=True)
        sync_directory(path.parent)


class Journal:
    def __init__(self, root: Path):
        self.root = root.resolve()
        durable_directory(self.root)
        with self.writer():
            if not (self.root / "FORMAT").exists():
                existing = {p.name for p in self.root.iterdir()} - {"writer.lock"}
                if existing and not (
                    existing == {"HEAD"} and (self.root / "HEAD").read_text() == "EMPTY\n"
                ):
                    raise CorruptJournal("Uninitialized journal contains data; recover explicitly")
                self._replace_head("EMPTY")
                with (self.root / "FORMAT").open("xb") as marker:
                    marker.write(b"dtvp.journal/1\n")
                    marker.flush()
                    os.fsync(marker.fileno())
                sync_directory(self.root)
            elif (self.root / "FORMAT").read_bytes() != b"dtvp.journal/1\n":
                raise CorruptJournal("Unsupported journal format")
        self.objects = Artifacts(self.root / "objects")
        sync_directory(self.root)
        self._receipt_head = None
        self._receipts = {}

    @contextmanager
    def writer(self):
        with (self.root / "writer.lock").open("a+b") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)

    def store(self, value):
        raw = canonical(value.model_dump(mode="json") if isinstance(value, BaseModel) else value)
        if not raw:
            raise ValueError("Empty object")
        return self.objects.put(raw)

    def load(self, sha, model=None):
        try:
            value = json.loads(self.objects.read(sha))
            return model.model_validate(value) if model else value
        except (ValueError, OSError) as error:
            raise CorruptJournal(f"Invalid or missing journal object {sha}") from error

    def head(self):
        try:
            value = (self.root / "HEAD").read_text().strip()
        except FileNotFoundError:
            raise CorruptJournal("Journal HEAD is missing; recover explicitly") from None
        if value == "EMPTY":
            return None
        if not isinstance(value, str) or len(value) != 64:
            raise CorruptJournal("Invalid journal HEAD")
        self.load(value, Publication)
        return value

    def publications(self, head=None, after=None):
        """Chronological committed publications; unreachable objects are ignored."""
        sha = head if head is not None else self.head()
        pending, seen = [], set()
        while sha and sha != after:
            if sha in seen:
                raise CorruptJournal("Publication cycle")
            seen.add(sha)
            publication = self.load(sha, Publication)
            pending.append((sha, publication))
            sha = publication.previous
        if after and sha != after:
            raise CorruptJournal("Projection checkpoint is outside committed history")
        base = self.load(after, Publication) if after else None
        previous_refs, sequence = (base.refs, base.sequence) if base else ({}, 0)
        for sha, publication in reversed(pending):
            if publication.sequence != sequence + 1:
                raise CorruptJournal("Publication sequence gap")
            refs = dict(previous_refs)
            for update in publication.updates:
                if refs.get(update.ref.key) != update.expected:
                    raise CorruptJournal("Publication parent references disagree")
                refs[update.ref.key] = update.target
            if refs != publication.refs:
                raise CorruptJournal("Publication reference snapshot disagrees")
            previous_refs, sequence = refs, publication.sequence
            yield sha, publication

    def references(self):
        head = self.head()
        return dict(self.load(head, Publication).refs) if head else {}

    def resolve(self, ref):
        return self.references().get(ref.key)

    def state(self, sha):
        revision = self.load(sha, Revision)
        if set(revision.sections) != set(SECTIONS):
            raise CorruptJournal("State must contain every knowledge section")
        return revision

    def records(self, sha, section):
        state = self.state(sha)
        return self.load(state.sections[section], Section).records

    def snapshot(
        self, *, project_id, version, actor_id, reason, sections, parents=(), artifacts=()
    ):
        if set(sections) != set(SECTIONS):
            raise ValueError("Provide every section of the complete state")
        for parent in parents:
            if self.state(parent).project_id != project_id:
                raise ValueError("State parents must belong to the same product line")
        roots = {}
        for name, records in sections.items():
            roots[name] = self.store(
                Section(records={key: self.store(value) for key, value in records.items()})
            )
        return self.store(
            Revision(
                project_id=project_id,
                version=version,
                actor_id=actor_id,
                reason=reason,
                created_at=datetime.now(UTC).isoformat(),
                parents=list(parents),
                sections=roots,
                artifacts=list(artifacts),
            )
        )

    def verify_state(self, sha):
        state = self.state(sha)
        try:
            for root in state.sections.values():
                for value in self.load(root, Section).records.values():
                    self.objects.read(value)
            for artifact in state.artifacts:
                self.objects.read(artifact)
        except (ValueError, OSError) as error:
            raise CorruptJournal(f"State {sha} references corrupt or missing data") from error
        return state

    def _replace_head(self, sha):
        fd, name = tempfile.mkstemp(prefix="HEAD-", dir=self.root)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write((sha + "\n").encode())
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(name, self.root / "HEAD")
            sync_directory(self.root)
        finally:
            Path(name).unlink(missing_ok=True)

    def receipt(self, request_id, fingerprint):
        # Disposable in-memory index; refresh only publications since our last read.
        head = self.head()
        for sha, publication in self.publications(head, after=self._receipt_head):
            self._receipts[publication.request_id] = (sha, publication)
        self._receipt_head = head
        receipt = self._receipts.get(request_id)
        if receipt and receipt[1].fingerprint != fingerprint:
            raise Conflict("Request ID already belongs to different input")
        return receipt

    def publish(self, *, request_id, fingerprint, updates, checks=(), branch_heads=None):
        if not updates or len({u.ref.key for u in updates}) != len(updates):
            raise ValueError("Publish at least one distinct reference")
        with self.writer():
            if receipt := self.receipt(request_id, fingerprint):
                return receipt
            previous = self.head()
            before = self.load(previous, Publication) if previous else None
            refs = dict(before.refs) if before else {}
            for ref, expected in checks:
                if refs.get(ref.key) != expected:
                    raise Conflict("Referenced policy changed; retry against current state")
            for project_id, expected in (branch_heads or {}).items():
                actual = {
                    ref.name: sha
                    for key, sha in refs.items()
                    if (ref := Ref.model_validate_json(key)).project_id == project_id
                    and ref.kind == "branch"
                }
                if actual != expected:
                    raise Conflict("Product versions changed; reload ownership configuration")
            for update in updates:
                existing = refs.get(update.ref.key)
                if existing != update.expected:
                    raise Conflict("Branch changed; reload and reconcile")
                if update.ref.kind == "tag" and existing is not None:
                    raise Conflict("Release tags are immutable")
                state = self.verify_state(update.target)
                if state.project_id != update.ref.project_id:
                    raise ValueError("Reference must stay within its product line")
                if update.ref.kind == "branch" and state.version != update.ref.name:
                    raise ValueError("Branch and state versions disagree")
                if (
                    existing
                    and update.ref.kind in {"branch", "source", "policy", "evidence"}
                    and existing not in state.parents
                ):
                    raise ValueError("Branch update must retain its current head as a parent")
                refs[update.ref.key] = update.target
            publication = Publication(
                sequence=before.sequence + 1 if before else 1,
                previous=previous,
                request_id=request_id,
                fingerprint=fingerprint,
                updates=updates,
                refs=refs,
            )
            sha = self.store(publication)
            try:
                self._replace_head(sha)
            except OSError as error:
                raise CommitUncertain(sha) from error
            return sha, publication

    def diff(self, left, right):
        before, after = self.state(left), self.state(right)
        if before.project_id != after.project_id:
            raise ValueError("Comparison requires the same product line")
        changes = {}
        for section in SECTIONS:
            if before.sections[section] == after.sections[section]:
                continue
            old, new = self.records(left, section), self.records(right, section)
            changes[section] = {
                "added": sorted(new.keys() - old.keys()),
                "removed": sorted(old.keys() - new.keys()),
                "changed": sorted(key for key in old.keys() & new.keys() if old[key] != new[key]),
            }
        return {"from": left, "to": right, "changes": changes}
