"""Durable native Agentyzer orchestration; ambiguous remote writes never repeat."""

import re
from datetime import timedelta
from urllib.parse import quote
from uuid import NAMESPACE_URL, uuid5

import httpx
from pydantic import Field
from sqlalchemy import select

from dtvp.auth import aware
from dtvp.jobs import actor_for
from dtvp.knowledge.agentyzer import derive_analysis_input
from dtvp.knowledge.agentyzer_results import AgentyzerResultInput, import_agentyzer_result
from dtvp.knowledge.assessments import target_fingerprint
from dtvp.knowledge.journal import CommitUncertain, Conflict, Name, Ref, Sha
from dtvp.knowledge.workspace import load_sections
from dtvp.models import Job, Project, now
from dtvp.providers import client, read_json
from dtvp.schemas import RequestModel
from dtvp.storage import canonical, digest

KIND = "analyse-native"
REMOTE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,199}$")


class AnalysisJobInput(RequestModel):
    request_id: Name
    expected: Sha
    context_id: Sha
    vulnerability_id: Name
    user_guidance: str = Field(default="", max_length=6000)


def _endpoint(settings):
    if not settings.agentyzer_enabled or not settings.agentyzer_url:
        raise ValueError("External Agentyzer is disabled; no request was sent")
    return digest(settings.agentyzer_url.rstrip("/").encode())


def _authorize(db, actor, project_id):
    project = db.get(Project, project_id)
    for capability in ("read", "snapshot", "evidence"):
        actor.require(db, project, capability)
    return project


def _repository(project):
    return project.metadata_json.get("connectors", {}).get("agentyzer", {}).get("component_name")


def _head(journal, project_id, version):
    state = journal.resolve(Ref(project_id=project_id, name=version))
    if not state:
        raise Conflict("Product version has no current baseline")
    return state


def _semantic_current(journal, job):
    receipt = job.payload["receipt"]
    head = _head(journal, job.project_id, job.payload["version"])
    fingerprint = target_fingerprint(
        load_sections(journal, head),
        job.payload["version"],
        receipt["context_id"],
        receipt["vulnerability_id"],
    )
    if fingerprint != receipt["assessment_fingerprint"]:
        raise Conflict("Source context changed; explicitly request analysis of the new baseline")
    return head


def enqueue_analysis(db, journal, settings, *, project_id, version, actor, data):
    project = _authorize(db, actor, project_id)
    endpoint = _endpoint(settings)
    fingerprint = digest(
        canonical([project_id, version, actor.user.id, data.model_dump(mode="json"), endpoint])
    )
    identity = str(
        uuid5(
            NAMESPACE_URL,
            canonical(
                ["dtvp.native-analysis/1", project_id, actor.user.id, data.request_id]
            ).decode(),
        )
    )
    # Serialize project-local enqueue; the deterministic primary key is the final guard.
    db.scalar(select(Project).where(Project.id == project_id).with_for_update())
    existing = db.get(Job, identity)
    if existing:
        if existing.kind != KIND or existing.payload["fingerprint"] != fingerprint:
            raise Conflict("Analysis request ID belongs to different input")
        return existing
    if _head(journal, project_id, version) != data.expected:
        raise Conflict("Product version changed; reload before requesting analysis")
    derived = derive_analysis_input(journal, data.expected, data.context_id, data.vulnerability_id)
    if derived["receipt"]["project_id"] != project_id or derived["receipt"]["version"] != version:
        raise ValueError("Analysis receipt belongs to another product version")
    if not derived["ready_to_submit"]:
        raise ValueError("Producer-qualified source inputs are incomplete")
    request = dict(derived["request"])
    if _repository(project) != request["component_name"]:
        raise PermissionError("Repository is not authorized by the project's Agentyzer binding")
    if data.user_guidance:
        request["user_guidance"] = data.user_guidance
    job = Job(
        id=identity,
        project_id=project_id,
        actor_id=actor.user.id,
        kind=KIND,
        payload={
            "format": "dtvp.analysis-job/1",
            "fingerprint": fingerprint,
            "credential_id": actor.credential.id,
            "version": version,
            "receipt": derived["receipt"],
            "request": request,
            "endpoint_digest": endpoint,
            "submission_started": False,
        },
    )
    db.add(job)
    db.flush()
    return job


def _validate(db, journal, settings, job, *, check_material=True):
    if not job or job.kind != KIND:
        raise ValueError("Native analysis job unavailable")
    actor = actor_for(db, job)
    project = _authorize(db, actor, job.project_id)
    if job.payload["endpoint_digest"] != _endpoint(settings):
        raise ValueError("Agentyzer endpoint changed; request a new analysis explicitly")
    if _repository(project) != job.payload["request"]["component_name"]:
        raise PermissionError("Authorized analysis repository binding changed")
    if aware(job.created_at) + timedelta(seconds=settings.agentyzer_timeout_seconds) < now():
        raise ValueError("Analysis observation expired; request a new analysis explicitly")
    if check_material:
        _semantic_current(journal, job)
    return actor


def _locked(db, job_id, token):
    job = db.scalar(select(Job).where(Job.id == job_id).with_for_update())
    if not job or job.status != "running" or job.lease_token != token:
        return None
    return job


def _stop(job, status, message):
    job.status, job.error, job.lease_until = status, message, None


def _data(job, journal):
    return AgentyzerResultInput(
        request_id="native-job:" + job.id,
        expected=job.payload["import_expected"],
        input_receipt=job.payload["receipt"],
        raw_report=journal.load(job.payload["report_sha256"]),
        source_label="Agentyzer managed job",
    )


def _import(db, journal, settings, job):
    _validate(db, journal, settings, job, check_material=False)
    try:
        receipt = import_agentyzer_result(
            journal,
            project_id=job.project_id,
            version=job.payload["version"],
            actor_id=job.actor_id,
            data=_data(job, journal),
        )
    except (Conflict, CommitUncertain) as error:
        _stop(
            job,
            "import_pending",
            "Retained report publication pending; retry explicitly to resolve its receipt/current baseline",
        )
        return "uncertain" if isinstance(error, CommitUncertain) else "conflict"
    job.result = {**job.result, "publication": receipt[0], "state": receipt[1].updates[0].target}
    _stop(job, "succeeded", "")
    return "succeeded"


def execute_analysis(factory, journal, settings, job_id, token):
    """One leased step. Root worker dispatches KIND here before v2 release logic."""
    with factory.begin() as db:
        job = _locked(db, job_id, token)
        if not job:
            return
        _validate(
            db,
            journal,
            settings,
            job,
            check_material=not bool(job.payload.get("submission_started")),
        )
        if job.payload.get("report_sha256"):
            _import(db, journal, settings, job)
            return
        payload = dict(job.payload)
        if not payload.get("remote_id"):
            if payload["submission_started"]:
                _stop(
                    job,
                    "submission_unknown",
                    "Remote submission outcome unknown; no automatic resubmission is permitted",
                )
                return
            job.payload = {**payload, "submission_started": True}
            payload = dict(job.payload)
    # Submission marker is committed before any external write. No idempotency API
    # exists in the inspected Agentyzer contract, so POST errors are ambiguous.
    headers = (
        {"Authorization": "Bearer " + settings.agentyzer_token} if settings.agentyzer_token else {}
    )
    base = settings.agentyzer_url.rstrip("/")
    with client() as http:
        if not payload.get("remote_id"):
            try:
                with factory.begin() as db:
                    job = _locked(db, job_id, token)
                    if not job:
                        return
                    _validate(db, journal, settings, job)
                submitted = read_json(
                    http, "POST", base + "/assess", headers=headers, json=payload["request"]
                )
                remote = submitted.get("job_id") if isinstance(submitted, dict) else None
                if not isinstance(remote, str) or not REMOTE_ID.fullmatch(remote):
                    raise ValueError("Remote submission returned no usable job identifier")
            except httpx.HTTPError, ValueError, TypeError:
                with factory.begin() as db:
                    job = _locked(db, job_id, token)
                    if job:
                        _stop(
                            job,
                            "submission_unknown",
                            "Remote submission outcome unknown; no automatic resubmission is permitted",
                        )
                return
            with factory.begin() as db:
                job = _locked(db, job_id, token)
                if not job:
                    return
                job.payload = {**job.payload, "remote_id": remote}
                payload = dict(job.payload)
        remote = payload["remote_id"]
        path = base + "/jobs/" + quote(remote, safe="")
        for suffix in ("", "/result"):
            with factory.begin() as db:
                job = _locked(db, job_id, token)
                if not job:
                    return
                _validate(db, journal, settings, job, check_material=False)
                # Each bounded request gets a fresh lease. Final writes still check token.
                job.lease_until = now() + timedelta(seconds=90)
            try:
                response = read_json(http, "GET", path + suffix, headers=headers)
            except httpx.HTTPStatusError:
                with factory.begin() as db:
                    job = _locked(db, job_id, token)
                    if job:
                        _stop(
                            job,
                            "failed",
                            "Remote job unavailable or unauthorized; explicit retry required",
                        )
                return
            except httpx.HTTPError, ValueError, TypeError:
                with factory.begin() as db:
                    job = _locked(db, job_id, token)
                    if job:
                        _stop(
                            job, "queued", "Remote observation unavailable; retrying safe polling"
                        )
                        job.available_at = now() + timedelta(seconds=3)
                return
            if not suffix:
                if not isinstance(response, dict) or response.get("job_id") != remote:
                    raise ValueError("Remote job status identity differs from submitted job")
                status = response.get("status")
                if status in {"pending", "running"}:
                    with factory.begin() as db:
                        job = _locked(db, job_id, token)
                        if job:
                            _stop(job, "queued", "")
                            job.result = {"remote_status": status}
                            job.available_at = now() + timedelta(seconds=3)
                    return
                if status != "completed":
                    with factory.begin() as db:
                        job = _locked(db, job_id, token)
                        if job:
                            _stop(
                                job,
                                "failed",
                                "Remote analysis failed or was cancelled; explicit retry required",
                            )
                    return
                native_job = response
            else:
                envelope = {
                    "format": "dtvp.agentyzer-result-envelope/1",
                    "job": native_job,
                    "report": response,
                }
    report_sha = journal.store(envelope)
    with factory.begin() as db:
        job = _locked(db, job_id, token)
        if not job:
            return
        _validate(db, journal, settings, job, check_material=False)
        job.payload = {
            **job.payload,
            "report_sha256": report_sha,
            "import_expected": _head(journal, job.project_id, job.payload["version"]),
        }
        job.result = {**job.result, "report_sha256": report_sha, "remote_status": "completed"}
    # The exact publication input is durable before journal publication. A crash
    # after publication replays the same receipt, never creates another report.
    with factory.begin() as db:
        job = _locked(db, job_id, token)
        if job:
            _import(db, journal, settings, job)


def retry_analysis(db, journal, settings, *, project_id, job_id, actor):
    job = db.scalar(
        select(Job).where(Job.id == job_id, Job.project_id == project_id).with_for_update()
    )
    if not job or job.kind != KIND or job.actor_id != actor.user.id:
        raise PermissionError("Only the requesting actor may retry this native analysis")
    _authorize(db, actor, project_id)
    if job.status not in {"failed", "import_pending"}:
        raise Conflict(
            "This job cannot be retried; unknown submissions require explicit reconciliation or a new request"
        )
    job.payload = {**job.payload, "credential_id": actor.credential.id}
    _validate(
        db, journal, settings, job, check_material=not bool(job.payload.get("submission_started"))
    )
    if job.payload.get("report_sha256"):
        # First resolve the original exact receipt. Only a proven CAS failure can
        # select the current head under this explicit retry; changed evidence stays stale.
        outcome = _import(db, journal, settings, job)
        if outcome != "conflict":
            return job
        job.payload = {
            **job.payload,
            "import_expected": _head(journal, job.project_id, job.payload["version"]),
        }
    elif not job.payload.get("remote_id"):
        raise Conflict("No known remote job can be retried safely")
    job.status, job.error, job.available_at = "queued", "", now()
    job.lease_token, job.lease_until = None, None
    return job


def job_view(job):
    return {
        "id": job.id,
        "kind": job.kind,
        "status": job.status,
        "version": job.payload["version"],
        "context_id": job.payload["receipt"]["context_id"],
        "vulnerability_id": job.payload["receipt"]["vulnerability_id"],
        "state": job.payload["receipt"]["state"],
        "attempts": job.attempts,
        "error": job.error,
        "result": job.result,
        "created_at": aware(job.created_at).isoformat(),
        "requires_explicit_reconciliation": job.status == "submission_unknown",
    }
