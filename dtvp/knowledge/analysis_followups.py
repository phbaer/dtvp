"""Exact parent-bound native follow-ups; remote writes retain unknown outcomes."""

import copy
import re
import secrets
from types import SimpleNamespace
from urllib.parse import quote
from uuid import NAMESPACE_URL, uuid5

from pydantic import Field, field_validator
from sqlalchemy import select

from dtvp.knowledge.analysis_jobs import (
    KIND,
    REMOTE_ID,
    _authorize,
    _endpoint,
    _head,
    _repository,
    _semantic_current,
    private_protocol,
    public_evidence,
)
from dtvp.knowledge.issued_exports import resolve_issued_export
from dtvp.knowledge.journal import Conflict, Name, Sha
from dtvp.models import Job, Project
from dtvp.providers import client, read_json
from dtvp.schemas import RequestModel
from dtvp.storage import canonical, digest

SCOPE = ("component_name", "vuln_id", "project_versions", "assessment_scope", "source_commit")


class FollowUpInput(RequestModel):
    request_id: Name
    expected: Sha
    parent_report_sha256: Sha
    question: str = Field(min_length=1, max_length=6000)
    user_guidance: str = Field(default="", max_length=6000)

    @field_validator("question")
    @classmethod
    def meaningful_question(cls, value):
        if not value.strip():
            raise ValueError("Follow-up question must contain meaningful text")
        return value


def _current_actor(db, actor):
    from dtvp.jobs import actor_for

    db.refresh(actor.credential)
    try:
        return actor_for(
            db,
            SimpleNamespace(actor_id=actor.user.id, payload={"credential_id": actor.credential.id}),
        )
    except ValueError:
        raise PermissionError("Follow-up request credential is revoked or expired") from None


def scope(request):
    return {key: request.get(key) for key in SCOPE}


def _enabled(settings):
    if not private_protocol(settings):
        raise ValueError(
            "Bound native follow-ups require explicit authenticated reconciliation configuration"
        )
    return _endpoint(settings)


def parent_material(
    db, journal, settings, *, project_id, version, parent_id, report_sha, check_material=True
):
    parent = db.scalar(select(Job).where(Job.id == parent_id, Job.project_id == project_id))
    if (
        not parent
        or parent.kind != KIND
        or parent.status != "succeeded"
        or parent.payload.get("version") != version
        or parent.payload.get("report_sha256") != report_sha
    ):
        raise Conflict(
            "Follow-up requires the exact completed native parent report in this product version"
        )
    payload = parent.payload
    remote = payload.get("remote_id")
    correlation = payload.get("correlation")
    if (
        not isinstance(remote, str)
        or not REMOTE_ID.fullmatch(remote)
        or not isinstance(correlation, dict)
        or correlation.get("format")
        not in {"dtvp.analysis-correlation/1", "dtvp.analysis-followup-correlation/1"}
        or not re.fullmatch(r"[a-f0-9]{64}", correlation.get("nonce", ""))
        or correlation.get("job_id") != parent.id
        or correlation.get("input_receipt_sha256") != digest(canonical(payload["receipt"]))
    ):
        raise Conflict("Parent has no private association suitable for a bound follow-up")
    if payload["endpoint_digest"] != _enabled(settings):
        raise Conflict("Parent Agentyzer endpoint changed")
    project = db.get(Project, project_id)
    if _repository(project) != payload["request"]["component_name"]:
        raise PermissionError("Parent analysis repository is no longer authorized")
    if check_material:
        _semantic_current(journal, parent)
    issued = resolve_issued_export(
        journal, project_id, correlation["issued_receipt_sha256"], kind="agentyzer-input"
    )
    if not issued or issued["payload"]["receipt"] != payload["receipt"]:
        raise Conflict("Parent differs from its exact issued source receipt")
    envelope = journal.load(report_sha)
    if (
        envelope.get("format") != "dtvp.agentyzer-result-envelope/1"
        or envelope.get("job", {}).get("job_id") != remote
        or envelope["job"].get("status") != "completed"
    ):
        raise Conflict("Retained parent report has no exact completed remote identity")
    public_evidence(envelope, correlation)
    request, report = envelope["job"].get("request"), envelope.get("report")
    if not isinstance(request, dict) or not isinstance(report, dict):
        raise Conflict("Retained parent lacks public request/report evidence")
    expected_scope = scope(issued["payload"]["request"])
    source = report.get("source_input", {})
    commit = expected_scope["source_commit"]
    if (
        scope(request) != expected_scope
        or not isinstance(source, dict)
        or not commit
        or source.get("binding") != "verified_git_commit"
        or source.get("requested_commit") != commit
        or source.get("resolved_commit") != commit
    ):
        raise Conflict("Retained parent source differs from the exact qualified input")
    pins = {
        "job_id": remote,
        "request_sha256": digest(canonical(request)),
        "report_sha256": digest(canonical(report)),
        "binding_sha256": digest(canonical(correlation)),
        "scope_sha256": digest(canonical(expected_scope)),
    }
    return parent, pins, expected_scope


def check_parent_proof(value, pins, expected_scope):
    if (
        not isinstance(value, dict)
        or set(value) != {"format", "parent", "scope"}
        or value["format"] != "agentyzer.dtvp-follow-up-parent/1"
        or value["parent"] != pins
        or value["scope"] != expected_scope
    ):
        raise ValueError("Authenticated follow-up parent proof differs from exact retained input")


def fetch_parent(http, settings, pins, expected_scope):
    value = read_json(
        http,
        "GET",
        settings.agentyzer_url.rstrip("/")
        + "/jobs/"
        + quote(pins["job_id"], safe="")
        + "/dtvp-follow-up-parent",
        headers={"Authorization": "Bearer " + settings.agentyzer_token},
    )
    check_parent_proof(value, pins, expected_scope)


def enqueue_followup(db, journal, settings, *, project_id, version, parent_id, actor, data):
    actor = _current_actor(db, actor)
    _authorize(db, actor, project_id)
    if not data.question.strip():
        raise ValueError("Follow-up question must contain meaningful text")
    endpoint = _enabled(settings)
    fingerprint = digest(
        canonical(
            [project_id, version, parent_id, actor.user.id, data.model_dump(mode="json"), endpoint]
        )
    )
    identity = str(
        uuid5(
            NAMESPACE_URL,
            canonical(
                ["dtvp.native-followup/1", project_id, actor.user.id, data.request_id]
            ).decode(),
        )
    )
    db.scalar(select(Project).where(Project.id == project_id).with_for_update())
    existing = db.get(Job, identity)
    if existing:
        if existing.kind != KIND or existing.payload["fingerprint"] != fingerprint:
            raise Conflict("Follow-up request ID belongs to different input")
        return existing
    if _head(journal, project_id, version) != data.expected:
        raise Conflict("Product version changed before follow-up")
    parent, pins, expected_scope = parent_material(
        db,
        journal,
        settings,
        project_id=project_id,
        version=version,
        parent_id=parent_id,
        report_sha=data.parent_report_sha256,
    )
    # Capability/authenticated parent check is read-only and precedes child enqueue.
    with client() as http:
        fetch_parent(http, settings, pins, expected_scope)
    actor = _current_actor(db, actor)
    _authorize(db, actor, project_id)
    if _head(journal, project_id, version) != data.expected:
        raise Conflict("Product version changed during follow-up preparation")
    parent_material(
        db,
        journal,
        settings,
        project_id=project_id,
        version=version,
        parent_id=parent_id,
        report_sha=data.parent_report_sha256,
    )
    wire = {"question": data.question, "user_guidance": data.user_guidance}
    correlation = {
        "format": "dtvp.analysis-followup-correlation/1",
        "job_id": identity,
        "nonce": secrets.token_hex(32),
        "input_receipt_sha256": digest(canonical(parent.payload["receipt"])),
        "issued_receipt_sha256": parent.payload["correlation"]["issued_receipt_sha256"],
        "submission_sha256": digest(canonical(wire)),
    }
    job = Job(
        id=identity,
        project_id=project_id,
        actor_id=actor.user.id,
        kind=KIND,
        payload={
            "format": "dtvp.analysis-followup-job/1",
            "fingerprint": fingerprint,
            "credential_id": actor.credential.id,
            "version": version,
            "receipt": copy.deepcopy(parent.payload["receipt"]),
            "request": copy.deepcopy(parent.payload["request"]),
            "endpoint_digest": endpoint,
            "submission_started": False,
            "correlation": correlation,
            "follow_up": {
                "parent_job_id": parent_id,
                "parent_report_sha256": data.parent_report_sha256,
                "parent": pins,
                "scope": expected_scope,
                "wire_request": wire,
                "parent_correlation": copy.deepcopy(parent.payload["correlation"]),
            },
        },
    )
    db.add(job)
    db.flush()
    return job


def validate_followup(db, journal, settings, job, *, check_material=True):
    follow = job.payload["follow_up"]
    parent, pins, expected_scope = parent_material(
        db,
        journal,
        settings,
        project_id=job.project_id,
        version=job.payload["version"],
        parent_id=follow["parent_job_id"],
        report_sha=follow["parent_report_sha256"],
        check_material=check_material,
    )
    if (
        pins != follow["parent"]
        or expected_scope != follow["scope"]
        or parent.payload["receipt"] != job.payload["receipt"]
        or parent.payload["correlation"] != follow["parent_correlation"]
        or digest(canonical(follow["wire_request"]))
        != job.payload["correlation"]["submission_sha256"]
    ):
        raise Conflict("Frozen follow-up input differs from its exact parent")


def outbound(payload):
    follow = payload["follow_up"]
    return {
        **follow["wire_request"],
        "dtvp_follow_up": {
            "format": "dtvp.follow-up-binding/1",
            "parent": follow["parent"],
            "correlation": payload["correlation"],
        },
    }


def result_proof(response, payload, remote_id):
    follow = payload["follow_up"]
    expected_binding = {
        "format": "dtvp.follow-up-binding/1",
        "parent": follow["parent"],
        "correlation": payload["correlation"],
    }
    if (
        not isinstance(response, dict)
        or set(response)
        != {"format", "job_id", "status", "binding", "request", "report", "submission", "parent"}
        or response["format"] != "agentyzer.dtvp-follow-up-binding/1"
        or response["job_id"] != remote_id
        or response["status"] != "completed"
        or response["binding"] != expected_binding
        or response["parent"] != follow["parent"]
        or response["submission"] != follow["wire_request"]
        or not isinstance(response["request"], dict)
        or scope(response["request"]) != follow["scope"]
    ):
        raise ValueError(
            "Authenticated follow-up association differs from frozen wire/parent/source input"
        )
    report = response["report"]
    source = report.get("source_input", {}) if isinstance(report, dict) else {}
    commit = follow["scope"]["source_commit"]
    if (
        not isinstance(source, dict)
        or not commit
        or source.get("binding") != "verified_git_commit"
        or source.get("requested_commit") != commit
        or source.get("resolved_commit") != commit
    ):
        raise ValueError("Follow-up report lacks the exact qualified Git source")
    observation = {
        "format": "dtvp.authenticated-follow-up-observation/1",
        "remote_id": remote_id,
        "binding_sha256": digest(canonical(expected_binding)),
        "response_sha256": digest(canonical(response)),
        "verification": "configured-service parent/request association and receipt consistency only; not source/binary authenticity",
    }
    envelope = {
        "format": "dtvp.agentyzer-result-envelope/1",
        "job": {"job_id": remote_id, "status": "completed", "request": response["request"]},
        "report": report,
        "follow_up": {
            "parent_job_id": follow["parent_job_id"],
            "parent_report_sha256": follow["parent_report_sha256"],
            "parent": follow["parent"],
        },
        "transport_observation": observation,
    }
    public_evidence(envelope, payload["correlation"])
    public_evidence(envelope, follow["parent_correlation"])
    return envelope, observation
