"""Leased exact-ID refresh: checkpoint responses before atomic evidence publication."""

from contextlib import contextmanager
from datetime import datetime, timedelta
from uuid import NAMESPACE_URL, uuid5

from sqlalchemy import select

from dtvp.auth import aware
from dtvp.jobs import actor_for
from dtvp.knowledge.advisory_sources import (
    AdvisoryRefreshInput,
    baseline_identifiers,
    collect_advisories,
    enabled,
    publish_advisories,
)
from dtvp.knowledge.evidence import evidence_ref
from dtvp.knowledge.journal import CommitUncertain, Conflict
from dtvp.models import Job, Project, now
from dtvp.providers import client
from dtvp.storage import canonical, digest

KIND = "refresh-advisories-native"
MAX_COLLECTION_SECONDS = 900


def _authorize(db, actor, project_id):
    project = db.get(Project, project_id)
    for capability in ("read", "evidence"):
        actor.require(db, project, capability)
    return project


def _inputs(journal, project_id, data):
    if journal.resolve(evidence_ref(project_id)) != data.expected_evidence:
        raise Conflict("Product evidence selection changed; use a new explicit refresh request")
    if set(data.identifiers) - baseline_identifiers(journal, project_id, data.expected_versions):
        raise ValueError(
            "Refresh identifiers must already be claimed by pinned baseline observations"
        )


def enqueue_advisory_refresh(db, journal, settings, *, project_id, actor, data):
    _authorize(db, actor, project_id)
    enabled(settings, data.provider)
    fingerprint = digest(
        canonical(["dtvp.advisory-job/1", project_id, actor.user.id, data.model_dump(mode="json")])
    )
    identity = str(
        uuid5(NAMESPACE_URL, canonical([KIND, project_id, actor.user.id, data.request_id]).decode())
    )
    db.scalar(select(Project).where(Project.id == project_id).with_for_update())
    existing = db.get(Job, identity)
    if existing:
        if existing.kind != KIND or existing.payload["fingerprint"] != fingerprint:
            raise Conflict("Advisory request ID already belongs to different input")
        return existing
    _inputs(journal, project_id, data)
    job = Job(
        id=identity,
        project_id=project_id,
        actor_id=actor.user.id,
        kind=KIND,
        payload={
            "format": "dtvp.advisory-job/1",
            "credential_id": actor.credential.id,
            "fingerprint": fingerprint,
            "intake": data.model_dump(mode="json"),
        },
    )
    db.add(job)
    db.flush()
    return job


def _locked(db, identity, token):
    job = db.scalar(select(Job).where(Job.id == identity).with_for_update())
    return (
        job
        if job and job.kind == KIND and job.status == "running" and job.lease_token == token
        else None
    )


def _validate(db, journal, settings, job, *, collecting=False):
    actor = actor_for(db, job)
    _authorize(db, actor, job.project_id)
    data = AdvisoryRefreshInput.model_validate(job.payload["intake"])
    enabled(settings, data.provider)
    if collecting:
        schedule = job.payload.get("schedule")
        if schedule:
            from dtvp.knowledge.advisory_schedule import policy_ref as schedule_ref

            if journal.resolve(schedule_ref(job.project_id)) != schedule["policy"]:
                raise Conflict("Advisory schedule changed; obsolete collection cannot continue")
        _inputs(journal, job.project_id, data)
        started = job.payload.get("collection_started_at")
        if (
            started
            and datetime.fromisoformat(started) + timedelta(seconds=MAX_COLLECTION_SECONDS) < now()
        ):
            raise ValueError("Provider collection exceeded its bounded observation interval")
    return actor, data


class _AuthorizedHTTP:
    def __init__(self, transport, factory, journal, settings, identity, token):
        self.transport, self.factory, self.journal, self.settings, self.identity, self.token = (
            transport,
            factory,
            journal,
            settings,
            identity,
            token,
        )

    @contextmanager
    def stream(self, method, url, **kwargs):
        if method != "GET":
            raise ValueError("Advisory refresh permits only exact-ID GET requests")
        from dtvp.knowledge.advisory_schedule import wait_for_provider_slot

        wait_for_provider_slot(self.factory, self.identity)
        with self.factory.begin() as db:
            job = _locked(db, self.identity, self.token)
            if not job:
                raise ValueError("Advisory job cancelled or lease lost")
            _validate(db, self.journal, self.settings, job, collecting=True)
            job.lease_until = now() + timedelta(seconds=90)
        with self.transport.stream(method, url, **kwargs) as response:
            if response.status_code == 429:
                from dtvp.knowledge.advisory_schedule import record_retry_after

                record_retry_after(self.factory, self.identity, response.headers.get("Retry-After"))
            yield response


def _publish(db, journal, settings, job):
    _, data = _validate(db, journal, settings, job)
    try:
        receipt = publish_advisories(
            journal,
            settings=settings,
            project_id=job.project_id,
            actor_id=job.actor_id,
            data=data,
            capture=journal.load(job.payload["capture_sha256"]),
        )
    except Conflict, CommitUncertain:
        job.status, job.lease_until = "import_pending", None
        job.error = "Frozen advisory publication pending; retry preserves exact heads, evidence selection and input"
        return
    job.result = {
        **job.result,
        "publication": receipt[0],
        "evidence_state": receipt[1].updates[0].target,
        "versions": {
            update.ref.name: update.target
            for update in receipt[1].updates
            if update.ref.kind == "branch"
        },
    }
    job.status, job.error, job.lease_until = "succeeded", "", None


def execute_advisory_refresh(factory, journal, settings, identity, token):
    with factory.begin() as db:
        job = _locked(db, identity, token)
        if not job:
            return
        _, data = _validate(db, journal, settings, job)
        if job.payload.get("capture_sha256"):
            _publish(db, journal, settings, job)
            return
        job.payload = {**job.payload, "collection_started_at": now().isoformat()}
        _validate(db, journal, settings, job, collecting=True)
    with client() as transport:
        guarded = _AuthorizedHTTP(transport, factory, journal, settings, identity, token)
        capture, artifacts = collect_advisories(
            settings, data.provider, data.identifiers, http=guarded
        )
    for sha, raw in artifacts.items():
        if journal.objects.put(raw) != sha:
            raise ValueError("Provider raw response digest differs from capture")
    capture_sha = journal.store(capture)
    with factory.begin() as db:
        job = _locked(db, identity, token)
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
    with factory.begin() as db:
        job = _locked(db, identity, token)
        if job:
            _publish(db, journal, settings, job)


def retry_advisory_refresh(db, journal, settings, *, project_id, job_id, actor):
    job = db.scalar(
        select(Job).where(Job.id == job_id, Job.project_id == project_id).with_for_update()
    )
    if not job or job.kind != KIND or job.actor_id != actor.user.id:
        raise PermissionError("Only the requesting actor may retry this advisory refresh")
    _authorize(db, actor, project_id)
    if job.status not in {"failed", "import_pending"}:
        raise Conflict("Only failed or pending-publication refreshes can be retried")
    job.payload = {
        **job.payload,
        "credential_id": actor.credential.id,
        "collection_started_at": None,
    }
    _validate(db, journal, settings, job, collecting=not bool(job.payload.get("capture_sha256")))
    job.status, job.error, job.available_at = "queued", "", now()
    job.lease_token, job.lease_until = None, None
    return job


def advisory_job_view(job):
    data = job.payload["intake"]
    return {
        "id": job.id,
        "kind": job.kind,
        "status": job.status,
        "provider": data["provider"],
        "identifiers": data["identifiers"],
        "expected_versions": data["expected_versions"],
        "expected_evidence": data["expected_evidence"],
        "revision": data["revision"],
        "attempts": job.attempts,
        "created_at": aware(job.created_at).isoformat(),
        "error": job.error,
        "result": job.result,
    }
