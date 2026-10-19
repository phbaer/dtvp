"""Read-only mapping of retained SQL data for explicit snapshot migration.

These models expose no review runtime or ingestion/publication operations.
Historical migrations and existing stored data are deliberately preserved.
"""

from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from dtvp.models import Base, Document, Record


class Release(Record, Base):
    __tablename__ = "releases"
    __table_args__ = (UniqueConstraint("project_id", "version"),)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), index=True)
    version: Mapped[str] = mapped_column(String(200))
    generation: Mapped[int] = mapped_column(Integer, default=0)
    metadata_json: Mapped[dict] = mapped_column(Document, default=dict)
    metadata_version: Mapped[int] = mapped_column(Integer, default=0)


class Revision(Record, Base):
    __tablename__ = "revisions"
    __table_args__ = (UniqueConstraint("release_id", "source", "event_id"),)
    release_id: Mapped[str] = mapped_column(ForeignKey("releases.id"), index=True)
    source: Mapped[str] = mapped_column(String(200))
    event_id: Mapped[str] = mapped_column(String(200))
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    artifact_sha: Mapped[str] = mapped_column(String(64))
    format: Mapped[str] = mapped_column(String(40))
    completeness: Mapped[str] = mapped_column(String(20))
    document: Mapped[dict] = mapped_column(Document)
    context: Mapped[dict] = mapped_column(Document, default=dict)


class Component(Record, Base):
    __tablename__ = "components"
    __table_args__ = (UniqueConstraint("release_id", "identity"),)
    release_id: Mapped[str] = mapped_column(ForeignKey("releases.id"), index=True)
    identity: Mapped[str] = mapped_column(String(1000))
    name: Mapped[str] = mapped_column(String(500))
    version: Mapped[str] = mapped_column(String(200))
    purl: Mapped[str] = mapped_column(String(2000), default="")
    metadata_json: Mapped[dict] = mapped_column(Document, default=dict)
    metadata_version: Mapped[int] = mapped_column(Integer, default=0)


class Finding(Record, Base):
    __tablename__ = "findings"
    __table_args__ = (UniqueConstraint("release_id", "component_id", "identifier"),)
    release_id: Mapped[str] = mapped_column(ForeignKey("releases.id"), index=True)
    component_id: Mapped[str] = mapped_column(ForeignKey("components.id"), index=True)
    identifier: Mapped[str] = mapped_column(String(200), index=True)
    kind: Mapped[str] = mapped_column(String(50), default="sca")
    evidence_revision: Mapped[int] = mapped_column(Integer, default=1)
    state_version: Mapped[int] = mapped_column(Integer, default=1)
    active: Mapped[bool] = mapped_column(Boolean, default=True)


class Observation(Record, Base):
    __tablename__ = "observations"
    __table_args__ = (UniqueConstraint("finding_id", "revision_id", "source", "fingerprint"),)
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id"), index=True)
    revision_id: Mapped[str] = mapped_column(ForeignKey("revisions.id"), index=True)
    source: Mapped[str] = mapped_column(String(200))
    fingerprint: Mapped[str] = mapped_column(String(64))
    assertion: Mapped[dict] = mapped_column(Document)


class Evidence(Record, Base):
    __tablename__ = "evidence"
    __table_args__ = (UniqueConstraint("finding_id", "source", "external_id"),)
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id"), index=True)
    source: Mapped[str] = mapped_column(String(200))
    external_id: Mapped[str] = mapped_column(String(200))
    snapshot_id: Mapped[str | None] = mapped_column(ForeignKey("snapshots.id"))
    assertion: Mapped[dict] = mapped_column(Document)
    fingerprint: Mapped[str] = mapped_column(String(64))
    input_revision: Mapped[int | None] = mapped_column(Integer)
    published_revision: Mapped[int | None] = mapped_column(Integer)


class Decision(Record, Base):
    __tablename__ = "decisions"
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id"), index=True)
    author_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    workspace_id: Mapped[str] = mapped_column(ForeignKey("workspaces.id"))
    evidence_revision: Mapped[int] = mapped_column(Integer)
    state: Mapped[str] = mapped_column(String(30))
    rationale: Mapped[str] = mapped_column(String(6000))
    details: Mapped[dict] = mapped_column(Document, default=dict)
    status: Mapped[str] = mapped_column(String(20), default="submitted")


class Approval(Record, Base):
    __tablename__ = "approvals"
    decision_id: Mapped[str] = mapped_column(ForeignKey("decisions.id"), unique=True)
    reviewer_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    evidence_revision: Mapped[int] = mapped_column(Integer)
    policy: Mapped[dict] = mapped_column(Document)


class Snapshot(Record, Base):
    __tablename__ = "snapshots"
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), index=True)
    release_id: Mapped[str] = mapped_column(ForeignKey("releases.id"))
    author_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    sha: Mapped[str] = mapped_column(String(64))
    manifest: Mapped[dict] = mapped_column(Document)


class RescorePolicy(Base):
    __tablename__ = "rescore_policies"
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), primary_key=True)
    version: Mapped[int] = mapped_column(Integer, default=1)
    config: Mapped[dict] = mapped_column(Document)


class ReviewScope(Base):
    __tablename__ = "review_scopes"
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id"), primary_key=True)
    workspace_ids: Mapped[list] = mapped_column(Document)


class FinalRescoring(Record, Base):
    __tablename__ = "final_rescorings"
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id"), index=True)
    coordinator_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    evidence_revision: Mapped[int] = mapped_column(Integer)
    review_digest: Mapped[str] = mapped_column(String(64))
    proposal: Mapped[dict] = mapped_column(Document)
