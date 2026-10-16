"""Automatic synchronization is recoverable, pinned and never a business-state write."""

from datetime import timedelta

import pytest
from fastapi import HTTPException
from pydantic import ValidationError
from sqlalchemy import select

from dtvp.auth import Actor, capabilities
from dtvp.jobs import claim
from dtvp.knowledge.journal import Conflict
from dtvp.knowledge.sync_jobs import (
    KIND,
    Relationship,
    SynchronizationInput,
    configure,
    execute,
    job_view,
    policy,
    reconcile,
)
from dtvp.models import Credential, Job, Membership, Project, now
from tests.test_knowledge_analysis_jobs import env as analysis_env
from tests.test_knowledge_assessments import current
from tests.test_knowledge_synchronization import parallel, publish

source_env = analysis_env


@pytest.fixture
def env(source_env):
    value = source_env
    with value.factory.begin() as db:
        db.add(Project(id="project", workspace_id="team", name="Parallel"))
        member = db.scalar(select(Membership).where(Membership.user_id == "author"))
        member.roles = ["admin"]
    parallel(value.journal)
    return value


def author(db):
    from tests.test_knowledge_analysis_jobs import actor

    actor = actor(db)
    return Actor(actor.user, actor.credential, {"team": capabilities(["admin"])})


def configured(env, **kwargs):
    data = SynchronizationInput(
        request_id=kwargs.pop("request_id", "policy"),
        expected_policy=kwargs.pop("expected_policy", None),
        relationships=[
            Relationship(
                relationship_id="cascade", source_version="7.1.1", target_version="7.1.2", **kwargs
            )
        ],
    )
    with env.factory() as db:
        return configure(env.journal, project_id="project", actor=author(db), data=data)


def jobs(env):
    with env.factory() as db:
        return list(db.scalars(select(Job).where(Job.kind == KIND)))


def test_policy_cas_replay_and_relationship_validation(env):
    configured(env)
    initial = env.journal.head()
    configured(env)
    assert env.journal.head() == initial
    with pytest.raises(Conflict):
        configured(env, request_id="different")
    for field in (
        {"source_version": "same", "target_version": "same"},
        {"source_version": "one", "target_version": "two", "context_mapping": {"a": "c", "b": "c"}},
    ):
        with pytest.raises(ValidationError):
            Relationship(relationship_id="bad", **field)


def test_scan_recovers_enqueue_gap_and_deduplicates_without_knowledge_writes(env):
    configured(env)
    head = env.journal.head()
    assert not jobs(env)
    assert reconcile(env.factory, env.journal) == 1
    assert reconcile(env.factory, env.journal) == 0
    identity, token = claim(env.factory)
    execute(env.factory, env.journal, env.settings, identity, token)
    result = jobs(env)[0]
    assert result.status == "succeeded"
    report = env.journal.load(result.result["artifact_sha"])
    assert report["automatic_proposal"]
    assert report["summary"]["by_category"] == {"reusable_content": 1}
    assert report["items"][0]["requires_new_target_review"]
    assert env.journal.head() == head
    assert not job_view(result, env.journal)["stale"]
    assert reconcile(env.factory, env.journal) == 0


def test_pins_remain_frozen_when_target_advances_and_cancel_is_not_requeued(env):
    configured(env)
    reconcile(env.factory, env.journal)
    original = jobs(env)[0]
    publish(env.journal, current(env.journal, "7.1.2"))
    assert job_view(original, env.journal)["stale"]
    identity, token = claim(env.factory)
    execute(env.factory, env.journal, env.settings, identity, token)
    assert jobs(env)[0].payload == original.payload
    assert reconcile(env.factory, env.journal) == 1
    with env.factory.begin() as db:
        for value in db.scalars(select(Job).where(Job.kind == KIND, Job.status == "queued")):
            value.status = "cancelled"
    assert reconcile(env.factory, env.journal) == 0


def test_credential_and_role_revocation_fail_closed(env):
    configured(env)
    reconcile(env.factory, env.journal)
    identity, token = claim(env.factory)
    with env.factory.begin() as db:
        db.get(Credential, "credential").revoked = True
    with pytest.raises(ValueError, match="revoked"):
        execute(env.factory, env.journal, env.settings, identity, token)
    with env.factory.begin() as db:
        db.get(Credential, "credential").revoked = False
        db.scalar(select(Membership).where(Membership.user_id == "author")).roles = ["viewer"]
    with pytest.raises(HTTPException):
        execute(env.factory, env.journal, env.settings, identity, token)


def test_expired_lease_cannot_publish(env):
    configured(env)
    reconcile(env.factory, env.journal)
    identity, token = claim(env.factory)
    with env.factory.begin() as db:
        db.get(Job, identity).lease_until = now() - timedelta(seconds=1)
    with pytest.raises(ValueError, match="lease lost"):
        execute(env.factory, env.journal, env.settings, identity, token)


def test_missing_version_waits_and_empty_policy_stops_new_work(env):
    with env.factory() as db:
        configure(
            env.journal,
            project_id="project",
            actor=author(db),
            data=SynchronizationInput(
                request_id="missing",
                expected_policy=None,
                relationships=[
                    Relationship(
                        relationship_id="later", source_version="7.1.1", target_version="future"
                    )
                ],
            ),
        )
    assert reconcile(env.factory, env.journal) == 0
    state, _ = policy(env.journal, "project")
    with env.factory() as db:
        configure(
            env.journal,
            project_id="project",
            actor=author(db),
            data=SynchronizationInput(request_id="stop", expected_policy=state, relationships=[]),
        )
    assert reconcile(env.factory, env.journal) == 0


def test_cyclic_relationships_do_not_create_feedback_or_copy_approvals(env):
    with env.factory() as db:
        configure(
            env.journal,
            project_id="project",
            actor=author(db),
            data=SynchronizationInput(
                request_id="cycle",
                expected_policy=None,
                relationships=[
                    Relationship(
                        relationship_id="forward", source_version="7.1.1", target_version="7.1.2"
                    ),
                    Relationship(
                        relationship_id="reverse", source_version="7.1.2", target_version="7.1.1"
                    ),
                ],
            ),
        )
    before = env.journal.head()
    assert reconcile(env.factory, env.journal) == 2
    for _ in range(2):
        identity, token = claim(env.factory)
        execute(env.factory, env.journal, env.settings, identity, token)
    assert env.journal.head() == before
    assert reconcile(env.factory, env.journal) == 0
    assert all(job.status == "succeeded" for job in jobs(env))
