"""External Agentyzer client; checkpoint every poll, never replay an ambiguous POST."""

from datetime import timedelta
from urllib.parse import quote

from sqlalchemy import select

from dtvp.auth import aware
from dtvp.domain import import_evidence, lock_release
from dtvp.jobs import actor_for
from dtvp.models import Finding, Job, Project, now
from dtvp.providers import client, read_json
from dtvp.storage import canonical, digest


def enabled(settings):
    return (settings.playground and not settings.agentyzer_enabled) or (
        settings.agentyzer_enabled and bool(settings.agentyzer_url)
    )


def mode(settings):
    return "synthetic" if settings.playground and not settings.agentyzer_enabled else "external"


def normalize(report, target):
    assessment = report.get("assessment")
    if not isinstance(assessment, dict):
        raise ValueError("Agentyzer returned no assessment")
    version = assessment.get("version_analysis") or {}
    comparison = version.get("comparison_inputs") or {} if isinstance(version, dict) else {}
    target_verified = (
        isinstance(comparison, dict)
        and comparison.get("component_name") == target["package_name"]
        and version.get("detected_version") == target["version"]
        and bool(target["version"])
    )
    application = assessment.get("application_eligible") is True and target_verified
    rescoring = assessment.get("rescoring_eligible") is True and application
    affected = assessment.get("affected")
    coverage = assessment.get("code_coverage") or {}
    exclusion = isinstance(coverage, dict) and coverage.get("permits_exclusion") is True
    proposal = (
        "affected"
        if application and affected is True and assessment.get("analysis") == "EXPLOITABLE"
        else "not_affected"
        if application
        and affected is False
        and exclusion
        and assessment.get("analysis") in {"NOT_AFFECTED", "FALSE_POSITIVE"}
        else None
    )
    return {
        "kind": "code-analysis",
        "application_eligible": application,
        "target_verified": target_verified,
        "rescoring_eligible": rescoring,
        "proposal_state": proposal,
        "summary": str(assessment.get("summary") or "No summary supplied")[:2000],
        "rationale": str(assessment.get("reasoning") or assessment.get("summary") or "")[:6000],
        "verdict": str(assessment.get("verdict") or "Unknown")[:100],
        "confidence": str(assessment.get("confidence") or "Unknown")[:100],
        "code_coverage": {"permits_exclusion": exclusion},
    }


def synthetic_report(outcome, target):
    if outcome == "failure":
        raise ValueError("Simulated Agentyzer failure; existing decisions remain unchanged")
    eligible = outcome == "eligible"
    return {
        "assessment": {
            "application_eligible": eligible,
            "rescoring_eligible": False,
            "affected": True if eligible else None,
            "verdict": "Affected" if eligible else "Inconclusive",
            "confidence": "High" if eligible else "Unknown",
            "analysis": "EXPLOITABLE" if eligible else "IN_TRIAGE",
            "summary": "Synthetic code analysis: reachable dependency."
            if eligible
            else "Synthetic code analysis: source coverage is incomplete.",
            "reasoning": "Playground evidence only. A reviewer must assess applicability to the release.",
            "code_coverage": {"permits_exclusion": False, "synthetic": True},
            "version_analysis": {
                "detected_version": target["version"],
                "comparison_inputs": {"component_name": target["package_name"]},
            },
        },
        "steps": [],
    }


def validate_job(db, job, settings):
    actor = actor_for(db, job)
    project = actor.require(db, db.get(Project, job.project_id), "evidence")
    finding = db.get(Finding, job.payload["finding_id"])
    if not enabled(settings):
        raise ValueError("Agentyzer disabled; no outbound request was sent")
    if (
        mode(settings) != job.payload["mode"]
        or digest(settings.agentyzer_url.encode()) != job.payload["endpoint_digest"]
    ):
        raise ValueError("Agentyzer deployment changed; submit a new analysis")
    binding = project.metadata_json.get("connectors", {}).get("agentyzer", {}).get("component_name")
    if job.payload["mode"] == "external" and binding != job.payload["request"]["component_name"]:
        raise ValueError("Agentyzer repository binding changed; submit a new analysis")
    if (
        not finding
        or not finding.active
        or finding.evidence_revision != job.payload["evidence_revision"]
    ):
        raise ValueError("Finding evidence changed; submit a new analysis")
    return actor, finding


def execute(factory, artifacts, settings, job_id, token):
    with factory.begin() as db:
        job = db.scalar(select(Job).where(Job.id == job_id).with_for_update())
        if job.status != "running" or job.lease_token != token:
            return
        validate_job(db, job, settings)
        if aware(job.created_at) < now() - timedelta(seconds=settings.agentyzer_timeout_seconds):
            raise ValueError("Agentyzer observation timed out; retry explicitly")
        payload = dict(job.payload)
        remote_id = payload.get("remote_id")
        if payload["mode"] == "external" and not remote_id:
            if payload.get("submission_started"):
                raise ValueError(
                    "Agentyzer submission outcome unknown; retry explicitly to start a new run"
                )
            # Commit BEFORE the external POST. Lease recovery must never repeat it.
            job.payload = {**payload, "submission_started": True}
    report = None
    if payload["mode"] == "synthetic":
        report = synthetic_report(payload["demo_outcome"], payload["target"])
        remote_id = f"synthetic-{job_id}"
    else:
        headers = (
            {"Authorization": f"Bearer {settings.agentyzer_token}"}
            if settings.agentyzer_token
            else {}
        )
        base = settings.agentyzer_url.rstrip("/")
        with client() as http:
            if not remote_id:
                parent = payload.get("parent_remote_id")
                path = f"/jobs/{quote(parent, safe='')}/follow-up" if parent else "/assess"
                body = (
                    {
                        "question": payload["question"],
                        "user_guidance": payload["request"]["user_guidance"],
                    }
                    if parent
                    else payload["request"]
                )
                submitted = read_json(http, "POST", base + path, headers=headers, json=body)
                remote_id = submitted.get("job_id")
                if not isinstance(remote_id, str) or not remote_id or len(remote_id) > 200:
                    raise ValueError(
                        "Agentyzer returned an invalid job identifier; retry explicitly"
                    )
                with factory.begin() as db:
                    job = db.scalar(select(Job).where(Job.id == job_id).with_for_update())
                    if job.status != "running" or job.lease_token != token:
                        return
                    job.payload = {**job.payload, "remote_id": remote_id}
            remote_path = base + f"/jobs/{quote(remote_id, safe='')}"
            status = read_json(http, "GET", remote_path, headers=headers)
            state = status.get("status")
            if state in {"pending", "running"}:
                with factory.begin() as db:
                    job = db.scalar(select(Job).where(Job.id == job_id).with_for_update())
                    if job.status != "running" or job.lease_token != token:
                        return
                    validate_job(db, job, settings)
                    job.status = "queued"
                    job.available_at = now() + timedelta(seconds=3)
                    job.lease_until = None
                    job.result = {"remote_status": state}
                return
            if state != "completed":
                raise ValueError(
                    "Agentyzer run failed or disappeared; retry explicitly. Existing decisions are preserved"
                )
            report = read_json(http, "GET", remote_path + "/result", headers=headers)
    assertion = normalize(report, payload["target"])
    report_sha = artifacts.put(canonical(report))
    with factory.begin() as db:
        # Match lock ordering used by decisions/imports before taking the job lock.
        lock_release(db, payload["release_id"])
        job = db.scalar(select(Job).where(Job.id == job_id).with_for_update())
        if job.status != "running" or job.lease_token != token:
            return
        actor, finding = validate_job(db, job, settings)
        assertion.update(
            {
                "job_id": job.id,
                "report_sha256": report_sha,
                "input_evidence_revision": payload["evidence_revision"],
                "target": payload["target"],
                "synthetic": payload["mode"] == "synthetic",
            }
        )
        evidence = import_evidence(
            db, actor.user.id, finding, source="agentyzer", external_id=job.id, assertion=assertion
        )
        job.payload = {**job.payload, "remote_id": remote_id}
        job.result = {
            **assertion,
            "evidence_id": evidence.id,
            "evidence_revision": finding.evidence_revision,
        }
        job.status = "succeeded"
        job.error = ""
        job.lease_until = None
