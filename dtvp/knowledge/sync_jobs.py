"""Durable, read-only synchronization proposals from latest configured branch pins."""

from datetime import timedelta
from uuid import NAMESPACE_URL, uuid5

from pydantic import Field, model_validator
from sqlalchemy import select

from dtvp.auth import aware
from dtvp.jobs import actor_for
from dtvp.knowledge.journal import SECTIONS, Conflict, Name, Ref, Sha, Update
from dtvp.knowledge.synchronization import _scopes, synchronization_preview
from dtvp.knowledge.workspace import load_sections
from dtvp.models import Job, Project, now
from dtvp.schemas import RequestModel
from dtvp.storage import canonical, digest

KIND = "propose-sync-native"
MAX_ROWS = 2000
MAX_BYTES = 16 * 1024 * 1024


class Relationship(RequestModel):
    relationship_id: Name
    source_version: Name
    target_version: Name
    basis: Sha | None = None
    context_mapping: dict[Name, Name] = Field(default_factory=dict, max_length=1000)

    @model_validator(mode="after")
    def distinct(self):
        if self.source_version == self.target_version:
            raise ValueError("Synchronization needs distinct source and target versions")
        if len(set(self.context_mapping.values())) != len(self.context_mapping):
            raise ValueError("Context mappings cannot collapse source contexts")
        return self


class SynchronizationInput(RequestModel):
    request_id: Name
    expected_policy: Sha | None
    relationships: list[Relationship] = Field(default_factory=list, max_length=20)

    @model_validator(mode="after")
    def unique(self):
        if len({r.relationship_id for r in self.relationships}) != len(self.relationships):
            raise ValueError("Relationship IDs must be unique")
        return self


def policy_ref(project_id):
    return Ref(kind="policy", project_id=project_id, name="synchronization")


def policy(journal, project_id):
    state = journal.resolve(policy_ref(project_id))
    config = (
        journal.load(journal.records(state, "history")["configuration"])
        if state
        else {"relationships": []}
    )
    return state, config


def configure(journal, *, project_id, actor, data):
    payload = data.model_dump(mode="json")
    fingerprint = digest(
        canonical(
            ["synchronization-policy/1", project_id, actor.user.id, actor.credential.id, payload]
        )
    )
    request_id = digest(canonical([project_id, actor.user.id, data.request_id]))
    with journal.writer():
        receipt = journal.receipt(request_id, fingerprint)
    if receipt:
        return receipt
    previous = journal.resolve(policy_ref(project_id))
    if previous != data.expected_policy:
        raise Conflict("Synchronization policy changed; reload before configuring")
    sections = {key: {} for key in SECTIONS}
    sections["history"]["configuration"] = {
        "format": "dtvp.synchronization-policy/1",
        "relationships": payload["relationships"],
        "actor_id": actor.user.id,
        "credential_id": actor.credential.id,
    }
    state = journal.snapshot(
        project_id=project_id,
        version="@synchronization",
        actor_id=actor.user.id,
        reason="Configure automatic synchronization proposals",
        parents=[previous] if previous else [],
        sections=sections,
    )
    return journal.publish(
        request_id=request_id,
        fingerprint=fingerprint,
        updates=[Update(ref=policy_ref(project_id), expected=previous, target=state)],
    )


def capture(refs, project_id, policy_state, relationship):
    return {
        "policy": policy_state,
        "relationship": relationship,
        "source": refs.get(Ref(project_id=project_id, name=relationship["source_version"]).key),
        "target": refs.get(Ref(project_id=project_id, name=relationship["target_version"]).key),
    }


def reconcile(factory, journal):
    """Recover enqueue gaps by rescanning committed refs, without publishing knowledge.

    At most 100 configured products per pass, rotated deterministically by the
    caller's SQL rows. Existing jobs are durable dedupe/diagnostic records.
    """
    refs = journal.references()
    projects = sorted(
        {
            ref.project_id
            for key in refs
            if (ref := Ref.model_validate_json(key)).kind == "policy"
            and ref.name == "synchronization"
        }
    )
    # A process cursor bounds one pass while ensuring every configured project is revisited.
    cursor = getattr(reconcile, "cursor", "")
    selected = ([p for p in projects if p > cursor] + [p for p in projects if p <= cursor])[:100]
    created = 0
    for project_id in selected:
        state = refs[policy_ref(project_id).key]
        config = journal.load(journal.records(state, "history")["configuration"])
        with factory.begin() as db:
            if not db.scalar(select(Project).where(Project.id == project_id).with_for_update()):
                continue
            for relationship in config["relationships"]:
                inputs = capture(refs, project_id, state, relationship)
                if not inputs["source"] or not inputs["target"]:
                    continue
                identity = str(uuid5(NAMESPACE_URL, canonical([KIND, project_id, inputs]).decode()))
                if db.get(Job, identity):
                    continue
                db.add(
                    Job(
                        id=identity,
                        project_id=project_id,
                        actor_id=config["actor_id"],
                        kind=KIND,
                        payload={"credential_id": config["credential_id"], "inputs": inputs},
                    )
                )
                created += 1
    if selected:
        reconcile.cursor = selected[-1]
    return created


def _locked(db, identity, token):
    value = db.scalar(select(Job).where(Job.id == identity).with_for_update())
    if (
        not value
        or value.kind != KIND
        or value.status != "running"
        or value.lease_token != token
        or not value.lease_until
        or aware(value.lease_until) <= now()
    ):
        raise ValueError("Synchronization proposal lease lost")
    actor = actor_for(db, value)
    actor.require(db, db.get(Project, value.project_id), "read")
    actor.require(db, db.get(Project, value.project_id), "manage")
    return value


def execute(factory, journal, settings, identity, token):
    with factory.begin() as db:
        job = _locked(db, identity, token)
        inputs, project_id = job.payload["inputs"], job.project_id
        job.lease_until = now() + timedelta(seconds=90)
    relationship = inputs["relationship"]
    scopes, unknown = _scopes(
        load_sections(journal, inputs["source"]), journal.state(inputs["source"]).version
    )
    if len(scopes) + len(unknown) > MAX_ROWS:
        raise ValueError("Automatic synchronization exceeds 2000 rows; narrow relationship scope")
    report = synchronization_preview(
        journal,
        project_id,
        inputs["source"],
        inputs["target"],
        basis=relationship["basis"],
        context_mapping=relationship["context_mapping"],
        paginate=False,
    )
    report = {**report, "automatic_proposal": True}
    raw = canonical(report)
    if len(raw) > MAX_BYTES:
        raise ValueError("Automatic synchronization proposal exceeds 16 MiB")
    with factory.begin() as db:
        job = _locked(db, identity, token)
        sha = journal.objects.put(raw)
        job.result = {
            "artifact_sha": sha,
            "preview_digest": report["preview_digest"],
            "total": report["total"],
        }
        job.status, job.lease_until = "succeeded", None


def job_view(job, journal):
    inputs = job.payload["inputs"]
    current = capture(
        journal.references(),
        job.project_id,
        journal.resolve(policy_ref(job.project_id)),
        inputs["relationship"],
    )
    return {
        "id": job.id,
        "kind": job.kind,
        "status": job.status,
        "inputs": inputs,
        "stale": inputs != current,
        "attempts": job.attempts,
        "error": job.error,
        "result": job.result,
        "created_at": job.created_at.isoformat(),
    }
