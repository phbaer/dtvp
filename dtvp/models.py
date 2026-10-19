"""Operational SQL identities, authorization, jobs and provider pacing only."""

import uuid
from datetime import UTC, datetime

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Index, Integer, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

Document = JSON().with_variant(JSONB(), "postgresql")


def now():
    return datetime.now(UTC)


def uid():
    return str(uuid.uuid4())


class Base(DeclarativeBase):
    pass


class Record:
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Workspace(Record, Base):
    __tablename__ = "workspaces"
    name: Mapped[str] = mapped_column(String(200), unique=True)


class User(Record, Base):
    __tablename__ = "users"
    __table_args__ = (UniqueConstraint("issuer", "subject"),)
    issuer: Mapped[str] = mapped_column(String(500))
    subject: Mapped[str] = mapped_column(String(500))
    name: Mapped[str] = mapped_column(String(200))
    org_admin: Mapped[bool] = mapped_column(Boolean, default=False)


class Membership(Base):
    __tablename__ = "memberships"
    workspace_id: Mapped[str] = mapped_column(ForeignKey("workspaces.id"), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), primary_key=True)
    roles: Mapped[list] = mapped_column(Document)


class Credential(Record, Base):
    __tablename__ = "credentials"
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    kind: Mapped[str] = mapped_column(String(20))
    name: Mapped[str] = mapped_column(String(200), default="session")
    workspace_id: Mapped[str | None] = mapped_column(ForeignKey("workspaces.id"))
    projects: Mapped[list] = mapped_column(Document, default=list)
    capabilities: Mapped[list] = mapped_column(Document, default=list)
    csrf_hash: Mapped[str | None] = mapped_column(String(64))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)


class Project(Record, Base):
    __tablename__ = "projects"
    __table_args__ = (UniqueConstraint("workspace_id", "name"),)
    workspace_id: Mapped[str] = mapped_column(ForeignKey("workspaces.id"), index=True)
    name: Mapped[str] = mapped_column(String(200))
    metadata_json: Mapped[dict] = mapped_column(Document, default=dict)


class Grant(Base):
    __tablename__ = "project_grants"
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(ForeignKey("workspaces.id"), primary_key=True)
    capabilities: Mapped[list] = mapped_column(Document)




















class Job(Record, Base):
    __tablename__ = "jobs"
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), index=True)
    actor_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    kind: Mapped[str] = mapped_column(String(40))
    status: Mapped[str] = mapped_column(String(20), default="queued")
    payload: Mapped[dict] = mapped_column(Document)
    result: Mapped[dict] = mapped_column(Document, default=dict)
    error: Mapped[str] = mapped_column(String(1000), default="")
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    lease_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    lease_token: Mapped[str | None] = mapped_column(String(36))
    available_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


Index("ix_job_claim", Job.status, Job.available_at, Job.lease_until)


class Audit(Record, Base):
    __tablename__ = "audit"
    project_id: Mapped[str | None] = mapped_column(ForeignKey("projects.id"), index=True)
    actor_id: Mapped[str] = mapped_column(String(36))
    action: Mapped[str] = mapped_column(String(100))
    subject_id: Mapped[str] = mapped_column(String(200))
    details: Mapped[dict] = mapped_column(Document, default=dict)








class AdvisoryProviderThrottle(Base):
    """Instance-wide dispatch pacing; operational SQL state, no journal roots."""

    __tablename__ = "advisory_provider_throttles"
    provider: Mapped[str] = mapped_column(String(20), primary_key=True)
    last_dispatch_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cooldown_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
