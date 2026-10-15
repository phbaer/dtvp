"""Durable, read-only DT captures and exact-input native baseline publication."""

from contextlib import contextmanager
from datetime import datetime, timedelta
from uuid import NAMESPACE_URL, uuid5

from sqlalchemy import select

from dtvp.auth import aware
from dtvp.jobs import actor_for
from dtvp.knowledge.dependency_track import (
    DependencyTrackImportInput,
    _binding,
    collect_dependency_track,
    publish_dependency_track,
)
from dtvp.knowledge.journal import CommitUncertain, Conflict, Ref
from dtvp.knowledge.service import part_ref
from dtvp.knowledge.workspace import load_sections
from dtvp.models import Job, Project, now
from dtvp.providers import client
from dtvp.storage import canonical, digest

KIND = "import-dt-native"
SourceJobInput = DependencyTrackImportInput
MAX_COLLECTION_SECONDS = 900


def _authorize(db, actor, project_id):
    project = db.get(Project, project_id)
    for capability in ("read", "write"):
        actor.require(db, project, capability)
    return project


def _connection(settings, project, version):
    value = project.metadata_json
    for key in ("connectors", "dependency-track", "versions", version):
        value = value.get(key) if isinstance(value, dict) else None
    external = value.get("project_id") if isinstance(value, dict) else None
    if not external:
        raise ValueError(
            "A dedicated Dependency-Track project binding is required for this product version"
        )
    _, external, endpoint, source = _binding(settings, external)
    return external, endpoint, source


def _ref(project_id, version, data):
    return (
        part_ref(project_id, version, data.part_id)
        if data.part_id
        else Ref(project_id=project_id, name=version)
    )


def _target(journal, project_id, version, data, source):
    if journal.resolve(_ref(project_id, version, data)) != data.expected:
        raise Conflict("Selected product version or source part head changed")
    if data.expected:
        revision = journal.state(data.expected)
        if revision.project_id != project_id or revision.version != version:
            raise Conflict("Expected DT intake state belongs to another product version")
        baseline = load_sections(journal, data.expected)["inventory"].get("baseline", {})
        if baseline.get("source") != source:
            raise Conflict("Changing source authority requires explicit policy")
        if baseline.get("kind") == "assembly" or baseline.get("part_id") != data.part_id:
            raise Conflict("DT intake target does not match the selected baseline/source part")
        if data.build_number <= baseline.get("build_number", -1):
            raise Conflict("DT build number must advance the accepted source")
    if data.predecessor:
        if data.expected:
            raise ValueError("A predecessor is only allowed when creating a version")
        predecessor = journal.verify_state(data.predecessor)
        if predecessor.project_id != project_id:
            raise ValueError("DT predecessor belongs to another product line")


def enqueue_source(db, journal, settings, *, project_id, version, actor, data):
    project = _authorize(db, actor, project_id)
    external, endpoint, source = _connection(settings, project, version)
    fingerprint = digest(
        canonical(
            [
                "dt.source-job/1",
                project_id,
                version,
                actor.user.id,
                data.model_dump(mode="json"),
                external,
                endpoint,
            ]
        )
    )
    identity = str(
        uuid5(
            NAMESPACE_URL,
            canonical(["dtvp.source-job/1", project_id, actor.user.id, data.request_id]).decode(),
        )
    )
    db.scalar(select(Project).where(Project.id == project_id).with_for_update())
    existing = db.get(Job, identity)
    if existing:
        if existing.kind != KIND or existing.payload["fingerprint"] != fingerprint:
            raise Conflict("DT source request ID already belongs to different input")
        return existing
    _target(journal, project_id, version, data, source)
    job = Job(
        id=identity,
        project_id=project_id,
        actor_id=actor.user.id,
        kind=KIND,
        payload={
            "format": "dtvp.source-job/1",
            "version": version,
            "credential_id": actor.credential.id,
            "fingerprint": fingerprint,
            "external_project_id": external,
            "endpoint_digest": endpoint,
            "intake": data.model_dump(mode="json"),
        },
    )
    db.add(job)
    db.flush()
    return job


def _locked(db, job_id, token):
    job = db.scalar(select(Job).where(Job.id == job_id).with_for_update())
    return (
        job
        if job and job.kind == KIND and job.status == "running" and job.lease_token == token
        else None
    )


def _validate(db, journal, settings, job, *, collecting=False):
    actor = actor_for(db, job)
    project = _authorize(db, actor, job.project_id)
    external, endpoint, source = _connection(settings, project, job.payload["version"])
    if external != job.payload["external_project_id"] or endpoint != job.payload["endpoint_digest"]:
        raise PermissionError(
            "Configured DT source binding changed; a new intake request is required"
        )
    if collecting:
        _target(
            journal,
            job.project_id,
            job.payload["version"],
            SourceJobInput.model_validate(job.payload["intake"]),
            source,
        )
        started = job.payload.get("collection_started_at")
        if (
            started
            and datetime.fromisoformat(started) + timedelta(seconds=MAX_COLLECTION_SECONDS) < now()
        ):
            raise ValueError(
                "DT collection exceeded its bounded observation interval; retry explicitly"
            )
    return actor


class _AuthorizedHTTP:
    def __init__(self, transport, factory, journal, settings, job_id, token):
        self.transport, self.factory, self.journal, self.settings = (
            transport,
            factory,
            journal,
            settings,
        )
        self.job_id, self.token = job_id, token

    @contextmanager
    def stream(self, method, url, **kwargs):
        if method != "GET":
            raise ValueError("Native DT source jobs permit only GET requests")
        with self.factory.begin() as db:
            job = _locked(db, self.job_id, self.token)
            if not job:
                raise ValueError("DT source job was cancelled or lost its lease")
            _validate(db, self.journal, self.settings, job, collecting=True)
            job.lease_until = now() + timedelta(seconds=90)
        with self.transport.stream(method, url, **kwargs) as response:
            yield response


def _stop(job, status, error=""):
    job.status, job.error, job.lease_until = status, error, None


def _publish(db, journal, settings, job):
    _validate(db, journal, settings, job)
    capture = journal.load(job.payload["capture_sha256"])
    try:
        receipt = publish_dependency_track(
            journal,
            settings=settings,
            external_project_id=job.payload["external_project_id"],
            capture=capture,
            project_id=job.project_id,
            version=job.payload["version"],
            actor_id=job.actor_id,
            data=SourceJobInput.model_validate(job.payload["intake"]),
        )
    except Conflict, CommitUncertain:
        _stop(
            job,
            "import_pending",
            "Frozen DT capture publication pending; retry preserves the exact expected state and input",
        )
        return
    job.result = {**job.result, "publication": receipt[0], "state": receipt[1].updates[0].target}
    _stop(job, "succeeded")


def execute_source(factory, journal, settings, job_id, token):
    """Checkpoint the full successful capture before any journal publication."""
    with factory.begin() as db:
        job = _locked(db, job_id, token)
        if not job:
            return
        _validate(db, journal, settings, job)
        if job.payload.get("capture_sha256"):
            _publish(db, journal, settings, job)
            return
        job.payload = {**job.payload, "collection_started_at": now().isoformat()}
        _validate(db, journal, settings, job, collecting=True)
        external = job.payload["external_project_id"]
    with client() as transport:
        guarded = _AuthorizedHTTP(transport, factory, journal, settings, job_id, token)
        capture, artifacts = collect_dependency_track(settings, external, http=guarded)
    for sha, raw in artifacts.items():
        if journal.objects.put(raw) != sha:
            raise ValueError("DT collector artifact digest differs from its capture manifest")
    capture_sha = journal.store(capture)
    with factory.begin() as db:
        job = _locked(db, job_id, token)
        if not job:
            return
        _validate(db, journal, settings, job)
        job.payload = {
            **job.payload,
            "capture_sha256": capture_sha,
            "raw_artifact_shas": sorted(artifacts),
        }
        job.result = {
            "capture_sha256": capture_sha,
            "raw_artifact_shas": sorted(artifacts),
            "remote_snapshot_consistent": False,
        }
    # Publication can commit while this SQL transaction subsequently fails. The
    # frozen checkpoint survives and exact native request replay resolves that case.
    with factory.begin() as db:
        job = _locked(db, job_id, token)
        if job:
            _publish(db, journal, settings, job)


def retry_source(db, journal, settings, *, project_id, job_id, actor):
    job = db.scalar(
        select(Job).where(Job.id == job_id, Job.project_id == project_id).with_for_update()
    )
    if not job or job.kind != KIND or job.actor_id != actor.user.id:
        raise PermissionError("Only the requesting actor may retry this native DT intake")
    _authorize(db, actor, project_id)
    if job.status not in {"failed", "import_pending"}:
        raise Conflict("Only a failed or pending-publication DT intake can be retried")
    job.payload = {
        **job.payload,
        "credential_id": actor.credential.id,
        "collection_started_at": None,
    }
    _validate(db, journal, settings, job, collecting=not bool(job.payload.get("capture_sha256")))
    job.status, job.error, job.available_at = "queued", "", now()
    job.lease_token, job.lease_until = None, None
    return job


def source_job_view(job):
    data = job.payload["intake"]
    return {
        "id": job.id,
        "kind": job.kind,
        "status": job.status,
        "version": job.payload["version"],
        "part_id": data.get("part_id"),
        "expected": data["expected"],
        "build_number": data["build_number"],
        "external_project_id": job.payload["external_project_id"],
        "attempts": job.attempts,
        "created_at": aware(job.created_at).isoformat(),
        "error": job.error,
        "result": job.result,
    }
