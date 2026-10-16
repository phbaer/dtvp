"""Explicit authenticated recovery of one unknown submission; never repeats POST."""

import copy
import re
from datetime import timedelta
from types import SimpleNamespace
from urllib.parse import quote
from uuid import uuid4

from pydantic import Field
from sqlalchemy import select

from dtvp.auth import aware
from dtvp.jobs import actor_for
from dtvp.knowledge.agentyzer_results import _json
from dtvp.knowledge.analysis_jobs import (
    KIND,
    REMOTE_ID,
    _authorize,
    _head,
    _validate,
    private_protocol,
    public_evidence,
)
from dtvp.knowledge.issued_exports import resolve_issued_export
from dtvp.knowledge.journal import Conflict, Name
from dtvp.models import Credential, Job, now
from dtvp.providers import client, read_json
from dtvp.schemas import RequestModel
from dtvp.storage import canonical, digest


class ReconcileInput(RequestModel):
    request_id: Name
    remote_id: str = Field(min_length=1, max_length=200, pattern=REMOTE_ID.pattern)


def configured(settings):
    return private_protocol(settings)


def _transport(settings):
    if not configured(settings):
        raise ValueError(
            "Authenticated reconciliation requires a configured ASCII service token of at least 32 characters"
        )
    return digest(canonical([settings.agentyzer_url, settings.agentyzer_token]))


def _actor(db, actor_id, credential_id):
    credential = db.get(Credential, credential_id)
    if not credential or credential.user_id != actor_id:
        raise PermissionError("Reconciliation credential does not belong to requesting actor")
    try:
        return actor_for(
            db, SimpleNamespace(actor_id=actor_id, payload={"credential_id": credential_id})
        )
    except ValueError:
        raise PermissionError("Reconciliation credential is revoked or expired") from None


def _selected(db, project_id, job_id, actor_id):
    job = db.scalar(
        select(Job).where(Job.id == job_id, Job.project_id == project_id).with_for_update()
    )
    if not job or job.kind != KIND or job.actor_id != actor_id:
        raise PermissionError("Only the original actor may reconcile this native analysis")
    return job


def _checked(db, journal, settings, job, actor_id, credential_id):
    actor = _actor(db, actor_id, credential_id)
    _authorize(db, actor, job.project_id)
    # Explicit recovery binds the current authenticated session, exactly as retry does.
    candidate = SimpleNamespace(
        kind=job.kind,
        actor_id=job.actor_id,
        project_id=job.project_id,
        created_at=job.created_at,
        payload={**job.payload, "credential_id": credential_id},
    )
    _validate(db, journal, settings, candidate, check_material=True)
    if (
        job.status != "submission_unknown"
        or not job.payload.get("submission_started")
        or job.payload.get("remote_id")
        or job.payload.get("report_sha256")
    ):
        raise Conflict("Only an unattached unknown submission can be reconciled")
    correlation = job.payload.get("correlation")
    if (
        not isinstance(correlation, dict)
        or correlation.get("format") != "dtvp.analysis-correlation/1"
        or not isinstance(correlation.get("nonce"), str)
        or not re.fullmatch(r"[a-f0-9]{64}", correlation["nonce"])
    ):
        raise Conflict(
            "Legacy unknown submission has no private binding proof; it cannot be reconciled"
        )
    issued = resolve_issued_export(
        journal, job.project_id, correlation["issued_receipt_sha256"], kind="agentyzer-input"
    )
    if (
        not issued
        or issued["payload"]["receipt"] != job.payload["receipt"]
        or correlation["input_receipt_sha256"] != digest(canonical(job.payload["receipt"]))
        or correlation["job_id"] != job.id
        or correlation["request_sha256"] != digest(canonical(job.payload["request"]))
    ):
        raise Conflict("Private correlation differs from the exact issued DTVP input")
    return _transport(settings)


def _proof(response, payload, remote_id):
    if not isinstance(response, dict) or set(response) != {
        "format",
        "job_id",
        "status",
        "binding",
        "request",
        "report",
    }:
        raise ValueError("Authenticated job proof has an unsupported shape")
    if (
        response["format"] != "agentyzer.dtvp-binding/1"
        or response["job_id"] != remote_id
        or response["status"] != "completed"
    ):
        raise ValueError("Authenticated proof must describe the exact completed remote job")
    if response["binding"] != payload["correlation"] or response["request"] != payload["request"]:
        raise ValueError("Remote request/private binding differs from the exact issued request")
    report = response["report"]
    source = report.get("source_input") if isinstance(report, dict) else None
    commit = payload["request"].get("source_commit")
    if (
        not isinstance(source, dict)
        or not commit
        or source.get("binding") != "verified_git_commit"
        or source.get("requested_commit") != commit
        or source.get("resolved_commit") != commit
    ):
        raise ValueError("Remote execution does not report the exact qualified Git commit")
    envelope = {
        "format": "dtvp.agentyzer-result-envelope/1",
        "job": {"job_id": remote_id, "status": "completed", "request": response["request"]},
        "report": report,
    }
    public_evidence(envelope, payload["correlation"])
    # Retain the exact public report/request, but never archive/export the nonce.
    observation = {
        "format": "dtvp.authenticated-job-observation/1",
        "remote_id": remote_id,
        "binding_sha256": digest(canonical(response["binding"])),
        "response_sha256": digest(canonical(response)),
        "verification": "configured-service request association and receipt consistency only; not provider/source/binary authenticity",
    }
    envelope["transport_observation"] = observation
    _json(envelope)
    return envelope, observation


def reconcile_analysis(
    factory, journal, settings, *, project_id, job_id, actor_id, credential_id, data, http=None
):
    fingerprint = digest(canonical([project_id, job_id, actor_id, data.model_dump(mode="json")]))
    lease = str(uuid4())
    with factory.begin() as db:
        job = _selected(db, project_id, job_id, actor_id)
        _authorize(db, _actor(db, actor_id, credential_id), project_id)
        existing = job.payload.get("reconciliation")
        if existing:
            if existing["request_id"] == data.request_id and existing["fingerprint"] == fingerprint:
                return job
            raise Conflict("This analysis already has a different explicit reconciliation")
        transport = _checked(db, journal, settings, job, actor_id, credential_id)
        requests = dict(job.payload.get("reconciliation_requests", {}))
        if data.request_id in requests and requests[data.request_id] != fingerprint:
            raise Conflict("Reconciliation request ID belongs to different input")
        if data.request_id not in requests and len(requests) >= 100:
            raise Conflict(
                "Reconciliation request identity limit reached; retry an existing exact request"
            )
        requests[data.request_id] = fingerprint
        attempt = job.payload.get("reconciliation_attempt")
        if (
            attempt
            and attempt["request_id"] == data.request_id
            and attempt["fingerprint"] != fingerprint
        ):
            raise Conflict("Reconciliation request ID belongs to different input")
        if attempt and job.lease_until and aware(job.lease_until) > now():
            raise Conflict(
                "A reconciliation observation is already in progress; retry after its lease"
            )
        job.payload = {
            **job.payload,
            "reconciliation_requests": requests,
            "reconciliation_attempt": {"request_id": data.request_id, "fingerprint": fingerprint},
        }
        job.lease_token, job.lease_until = lease, now() + timedelta(seconds=90)
        payload = copy.deepcopy(job.payload)
    # SQL intent/lease is durable before a bounded authenticated GET. There is
    # deliberately no POST, automatic remote search, or public result refetch.
    try:
        with factory.begin() as db:
            job = _selected(db, project_id, job_id, actor_id)
            if job.lease_token != lease or not job.lease_until or aware(job.lease_until) <= now():
                raise Conflict("Reconciliation lease changed")
            if _checked(db, journal, settings, job, actor_id, credential_id) != transport:
                raise Conflict("Reconciliation transport credential changed")

        def fetch(connection):
            return read_json(
                connection,
                "GET",
                settings.agentyzer_url.rstrip("/")
                + "/jobs/"
                + quote(data.remote_id, safe="")
                + "/dtvp-binding",
                headers={"Authorization": "Bearer " + settings.agentyzer_token},
            )

        if http is None:
            with client() as connection:
                response = fetch(connection)
        else:
            response = fetch(http)
        envelope, observation = _proof(response, payload, data.remote_id)
        report_sha = journal.store(envelope)
        observation_sha = digest(canonical(observation))
        with factory.begin() as db:
            job = _selected(db, project_id, job_id, actor_id)
            if job.lease_token != lease or not job.lease_until or aware(job.lease_until) <= now():
                raise Conflict("Reconciliation cancelled or its lease changed")
            if _checked(db, journal, settings, job, actor_id, credential_id) != transport:
                raise Conflict("Reconciliation transport credential changed")
            job.payload = {
                **job.payload,
                "credential_id": credential_id,
                "remote_id": data.remote_id,
                "report_sha256": report_sha,
                "import_expected": _head(journal, project_id, job.payload["version"]),
                "reconciliation": {
                    "request_id": data.request_id,
                    "fingerprint": fingerprint,
                    "observation_sha256": observation_sha,
                },
            }
            job.result = {
                **job.result,
                "remote_status": "completed",
                "report_sha256": report_sha,
                "reconciliation_observation_sha256": observation_sha,
                "association": "authenticated service response; receipt consistency only",
            }
            job.status, job.error, job.available_at = "queued", "", now()
            job.lease_token, job.lease_until = None, None
            return job
    except Exception:
        with factory.begin() as db:
            job = db.get(Job, job_id)
            if job and job.status == "submission_unknown" and job.lease_token == lease:
                job.lease_token, job.lease_until = None, None
        raise
