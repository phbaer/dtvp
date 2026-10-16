"""Explicit leased OSV queries with per-query durable checkpoints and frozen publication."""

import time
from contextlib import contextmanager
from datetime import datetime, timedelta
from uuid import NAMESPACE_URL, uuid5

from sqlalchemy import select

from dtvp.auth import aware
from dtvp.jobs import actor_for
from dtvp.knowledge.journal import CommitUncertain, Conflict
from dtvp.knowledge.osv_matching import (
    CAPTURE_FORMAT,
    ENDPOINT,
    LIMITATIONS,
    MatchingInput,
    enabled,
    publish_matches,
    read_query,
    validate_inputs,
)
from dtvp.models import Job, Project, now
from dtvp.providers import client
from dtvp.storage import canonical, digest

KIND = "match-osv-native"
MAX_COLLECTION_SECONDS = 900


def authorize(db, actor, project_id):
    project = db.get(Project, project_id)
    actor.require(db, project, "read")
    actor.require(db, project, "evidence")


def enqueue_matching(db, journal, settings, *, project_id, actor, data):
    authorize(db, actor, project_id)
    enabled(settings)
    fingerprint = digest(
        canonical(
            ["dtvp.osv-matching-job/1", project_id, actor.user.id, data.model_dump(mode="json")]
        )
    )
    identity = str(
        uuid5(NAMESPACE_URL, canonical([KIND, project_id, actor.user.id, data.request_id]).decode())
    )
    db.scalar(select(Project).where(Project.id == project_id).with_for_update())
    existing = db.get(Job, identity)
    if existing:
        if existing.kind != KIND or existing.payload["fingerprint"] != fingerprint:
            raise Conflict("Matching request ID already belongs to different input")
        return existing
    coverage = validate_inputs(journal, project_id, data)
    job = Job(
        id=identity,
        project_id=project_id,
        actor_id=actor.user.id,
        kind=KIND,
        payload={
            "format": "dtvp.osv-matching-job/1",
            "credential_id": actor.credential.id,
            "fingerprint": fingerprint,
            "intake": data.model_dump(mode="json"),
        },
        result={
            "selected_queries": len(data.purls),
            "completed_queries": 0,
            "unqueried_eligible_purls": coverage["eligible_purls"] - len(data.purls),
            "unsupported_occurrences": coverage["unsupported_occurrences"],
            "unqueried_coverage": "unknown",
        },
    )
    db.add(job)
    db.flush()
    return job


def locked(db, identity, token):
    job = db.scalar(select(Job).where(Job.id == identity).with_for_update())
    return (
        job
        if job
        and job.kind == KIND
        and job.status == "running"
        and job.lease_token == token
        and job.lease_until is not None
        and aware(job.lease_until) > now()
        else None
    )


def validate(db, journal, settings, job, *, collecting=False):
    actor = actor_for(db, job)
    authorize(db, actor, job.project_id)
    enabled(settings)
    data = MatchingInput.model_validate(job.payload["intake"])
    if collecting:
        validate_inputs(journal, job.project_id, data)
        started = job.payload.get("collection_started_at")
        if (
            started
            and datetime.fromisoformat(started) + timedelta(seconds=MAX_COLLECTION_SECONDS) < now()
        ):
            raise ValueError("OSV collection exceeded its bounded observation interval")
    return data


class AuthorizedHTTP:
    def __init__(self, transport, factory, journal, settings, identity, token, started_at):
        self.transport, self.factory, self.journal, self.settings, self.identity, self.token = (
            transport,
            factory,
            journal,
            settings,
            identity,
            token,
        )

        self.started_monotonic = time.monotonic()
        self.prior_elapsed = max(0, (now() - datetime.fromisoformat(started_at)).total_seconds())
        self.last_check = self.started_monotonic

    def guard(self, *, force=False):
        moment = time.monotonic()
        if self.prior_elapsed + moment - self.started_monotonic > MAX_COLLECTION_SECONDS:
            raise ValueError("OSV collection exceeded its bounded observation interval")
        if not force and moment - self.last_check < 10:
            return
        with self.factory.begin() as db:
            job = locked(db, self.identity, self.token)
            if not job:
                raise ValueError("Matching job cancelled, lease expired or ownership lost")
            validate(db, self.journal, self.settings, job, collecting=True)
            job.lease_until = now() + timedelta(seconds=90)
        self.last_check = moment

    @contextmanager
    def stream(self, method, url, **kwargs):
        kwargs["headers"] = {"Accept-Encoding": "identity"}
        if method != "POST" or str(url) != ENDPOINT or kwargs.get("follow_redirects") is not False:
            raise ValueError(
                "Matching permits only fixed-endpoint OSV POST queries without redirects"
            )
        with self.factory.begin() as db:
            job = locked(db, self.identity, self.token)
            if not job:
                raise ValueError("Matching job cancelled or lease lost")
            data = validate(db, self.journal, self.settings, job, collecting=True)
            if kwargs.get("json", {}).get("package", {}).get("purl") not in data.purls:
                raise ValueError("Matching query escaped the explicit package selection")
            job.lease_until = now() + timedelta(seconds=90)
        self.guard(force=True)
        with self.transport.stream(method, url, **kwargs) as response:
            self.guard(force=True)
            if response.headers.get("content-encoding", "identity").lower() not in {"", "identity"}:
                raise ValueError("OSV matching requires an identity-encoded bounded response")
            yield GuardedResponse(response, self.guard)
            self.guard(force=True)


def publish(db, journal, settings, job):
    data = validate(db, journal, settings, job)
    try:
        receipt = publish_matches(
            journal,
            settings=settings,
            project_id=job.project_id,
            actor_id=job.actor_id,
            data=data,
            capture=journal.load(job.payload["capture_sha256"]),
        )
    except Conflict, CommitUncertain:
        job.status, job.lease_until = "import_pending", None
        job.error = "Frozen matching publication pending; retry preserves exact queries, heads and evidence selection"
        return
    job.result = {
        **job.result,
        "publication": receipt[0],
        "remaining_selected_coverage": "published_provider_observations",
        "evidence_state": receipt[1].updates[0].target,
        "versions": {
            update.ref.name: update.target
            for update in receipt[1].updates
            if update.ref.kind == "branch"
        },
    }
    job.status, job.error, job.lease_until = "succeeded", "", None


def execute_matching(factory, journal, settings, identity, token):
    with factory.begin() as db:
        job = locked(db, identity, token)
        if not job:
            return
        data = validate(db, journal, settings, job)
        if job.payload.get("capture_sha256"):
            publish(db, journal, settings, job)
            return
        if not job.payload.get("collection_started_at"):
            job.payload = {**job.payload, "collection_started_at": now().isoformat()}
        validate(db, journal, settings, job, collecting=True)
        started = job.payload["collection_started_at"]
        progress = (
            journal.load(job.payload["progress_sha256"])
            if job.payload.get("progress_sha256")
            else {"queries": []}
        )
        if [item.get("purl") for item in progress["queries"]] != data.purls[
            : len(progress["queries"])
        ]:
            raise ValueError("Frozen matching progress differs from selected package order")
        queries = progress["queries"]
    with client() as transport:
        guarded = AuthorizedHTTP(transport, factory, journal, settings, identity, token, started)
        for purl in data.purls[len(queries) :]:
            total_bytes = sum(page["bytes"] for query in queries for page in query["pages"])
            total_pages = sum(len(query["pages"]) for query in queries)
            query, artifacts = read_query(
                guarded, purl, prior_bytes=total_bytes, prior_pages=total_pages
            )
            for sha, raw in artifacts.items():
                if journal.objects.put(raw) != sha:
                    raise ValueError("Captured OSV response hash differs")
            queries.append(query)
            progress_sha = journal.store({"queries": queries})
            # Commit this complete query before the next package can contact OSV.
            with factory.begin() as db:
                job = locked(db, identity, token)
                if not job:
                    return
                validate(db, journal, settings, job, collecting=True)
                job.payload = {**job.payload, "progress_sha256": progress_sha}
                job.result = {
                    **job.result,
                    "progress_sha256": progress_sha,
                    "completed_queries": len(queries),
                    "raw_artifact_shas": sorted(
                        {page["sha256"] for query in queries for page in query["pages"]}
                    ),
                    "remaining_selected_coverage": "unknown"
                    if len(queries) < len(data.purls)
                    else "captured_not_published",
                }
    capture = {
        "format": CAPTURE_FORMAT,
        "purls": data.purls,
        "queries": queries,
        "started_at": started,
        "completed_at": now().isoformat(),
        "limitations": LIMITATIONS,
    }
    capture_sha = journal.store(capture)
    with factory.begin() as db:
        job = locked(db, identity, token)
        if not job:
            return
        validate(db, journal, settings, job)
        job.payload = {**job.payload, "capture_sha256": capture_sha}
        job.result = {
            **job.result,
            "capture_sha256": capture_sha,
            "remote_snapshot_consistent": False,
        }
    with factory.begin() as db:
        job = locked(db, identity, token)
        if job:
            publish(db, journal, settings, job)


def retry_matching(db, journal, settings, *, project_id, job_id, actor):
    job = db.scalar(
        select(Job).where(Job.id == job_id, Job.project_id == project_id).with_for_update()
    )
    if not job or job.kind != KIND or job.actor_id != actor.user.id:
        raise PermissionError("Only the submitting actor may retry this matching job")
    authorize(db, actor, project_id)
    if job.status not in {"failed", "import_pending"}:
        raise Conflict("Only failed or pending matching jobs can be retried")
    job.payload = {**job.payload, "credential_id": actor.credential.id}
    validate(db, journal, settings, job, collecting=not bool(job.payload.get("capture_sha256")))
    job.status, job.error, job.available_at = "queued", "", now()
    job.lease_token, job.lease_until = None, None
    return job


def job_view(job):
    data = job.payload["intake"]
    return {
        "id": job.id,
        "kind": job.kind,
        "status": job.status,
        "purls": data["purls"],
        "expected_versions": data["expected_versions"],
        "expected_evidence": data["expected_evidence"],
        "revision": data["revision"],
        "attempts": job.attempts,
        "created_at": aware(job.created_at).isoformat(),
        "error": job.error,
        "result": job.result,
        "limitations": LIMITATIONS,
    }


class GuardedResponse:
    def __init__(self, response, guard):
        self.response, self.guard = response, guard

    def __getattr__(self, name):
        return getattr(self.response, name)

    def iter_bytes(self):
        for chunk in self.response.iter_bytes():
            self.guard()
            yield chunk
        self.guard(force=True)
