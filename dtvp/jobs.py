"""PostgreSQL leases and atomic publication. External writes are never retried implicitly."""

import time
from datetime import timedelta

from fastapi import HTTPException
from sqlalchemy import and_, or_, select

from dtvp.auth import Actor, aware, capabilities
from dtvp.domain import import_evidence, import_sbom, inventory, lock_release
from dtvp.models import Credential, Finding, Job, Membership, Project, Release, User, now, uid
from dtvp.providers import ADVISORY_PROVIDERS, MATCHERS, client, import_dt
from dtvp.storage import canonical, digest


def enqueue(db, actor, release, kind, payload):
    job = Job(
        project_id=release.project_id,
        actor_id=actor.user.id,
        kind=kind,
        payload={
            **payload,
            "release_id": release.id,
            "generation": release.generation,
            "credential_id": actor.credential.id,
        },
    )
    db.add(job)
    db.flush()
    return job


def claim(factory):
    with factory.begin() as db:
        job = db.scalar(
            select(Job)
            .where(
                or_(
                    and_(Job.status == "queued", Job.available_at <= now()),
                    and_(Job.status == "running", Job.lease_until < now()),
                )
            )
            .order_by(Job.created_at)
            .with_for_update(skip_locked=True)
            .limit(1)
        )
        if not job:
            return None
        job.status = "running"
        job.attempts += 1
        job.lease_token = uid()
        job.lease_until = now() + timedelta(seconds=90)
        return job.id, job.lease_token


def heartbeat(factory, job_id, token):
    with factory.begin() as db:
        job = db.scalar(select(Job).where(Job.id == job_id).with_for_update())
        if job.status != "running" or job.lease_token != token:
            raise ValueError("Job cancelled or lease lost")
        job.lease_until = now() + timedelta(seconds=90)


def actor_for(db, job):
    credential = db.get(Credential, job.payload["credential_id"])
    if not credential or credential.revoked or aware(credential.expires_at) <= now():
        raise ValueError("Request credential revoked or expired; submit a new job")
    user = db.get(User, job.actor_id)
    return Actor(
        user,
        credential,
        {
            m.workspace_id: capabilities(m.roles)
            for m in db.scalars(select(Membership).where(Membership.user_id == user.id))
        },
    )


def execute(factory, artifacts, settings, job_id, token):
    with factory() as db:
        job = db.get(Job, job_id)
        actor = actor_for(db, job)
        actor.require(
            db, db.get(Project, job.project_id), "write" if job.kind != "enrich" else "evidence"
        )
        release = db.get(Release, job.payload["release_id"])
        effective, components, active_ids = inventory(db, release)
        payload, kind = dict(job.payload), job.kind
        targets = [dict(id=c.id, purl=c.purl) for c in components.values() if c.id in active_ids]
        findings = [
            (f.id, f.identifier)
            for f in db.scalars(
                select(Finding).where(Finding.release_id == release.id, Finding.active.is_(True))
            )
        ]
    results = []
    with client() as http:
        if kind == "match":
            matcher = MATCHERS[payload["provider"]](http)
            for component in targets:
                heartbeat(factory, job_id, token)
                response = (
                    matcher.query(component["purl"])
                    if component["purl"]
                    else {"status": "unsupported", "reason": "No PURL", "advisories": []}
                )
                results.append((component, response))
        elif kind == "enrich":
            provider = ADVISORY_PROVIDERS[payload["provider"]](http)
            for finding_id, identifier in findings:
                heartbeat(factory, job_id, token)
                results.append((finding_id, provider.get(identifier)))
        elif kind == "import-dt":
            results = import_dt(
                http, settings.dt_url, settings.dt_api_key, payload["external_project_id"]
            )
    with factory.begin() as db:
        release = lock_release(db, payload["release_id"])
        job = db.scalar(select(Job).where(Job.id == job_id).with_for_update())
        if job.status != "running" or job.lease_token != token:
            return
        actor = actor_for(db, job)
        actor.require(
            db, db.get(Project, job.project_id), "write" if kind != "enrich" else "evidence"
        )
        if release.generation != payload["generation"]:
            raise ValueError("Release changed during job; rerun against current inventory")
        if kind == "match":
            coverage = []
            for component, response in results:
                coverage.append(
                    {
                        "component_id": component["id"],
                        "status": response["status"],
                        "reason": response.get("reason"),
                    }
                )
                for advisory in response["advisories"]:
                    identifier = advisory["id"]
                    cves = [
                        a["id"] for a in advisory.get("aliases", []) if a["id"].startswith("CVE-")
                    ]
                    if len(cves) == 1:
                        identifier = cves[0]
                    finding = db.scalar(
                        select(Finding).where(
                            Finding.release_id == release.id,
                            Finding.component_id == component["id"],
                            Finding.identifier == identifier,
                        )
                    )
                    if not finding:
                        finding = Finding(
                            release_id=release.id,
                            component_id=component["id"],
                            identifier=identifier,
                        )
                        db.add(finding)
                        db.flush()
                    finding.active = True
                    assertion = {
                        "kind": "match",
                        "advisory": advisory,
                        "method": response["method"],
                        "purl": component["purl"],
                        "checked_at": now().isoformat(),
                    }
                    import_evidence(
                        db,
                        actor.user.id,
                        finding,
                        source=payload["provider"],
                        external_id=f"{job.id}:{advisory['id']}",
                        assertion=assertion,
                    )
            job.result = {"coverage": coverage, "checked_at": now().isoformat()}
        elif kind == "enrich":
            for finding_id, assertion in results:
                import_evidence(
                    db,
                    actor.user.id,
                    db.get(Finding, finding_id),
                    source=payload["provider"],
                    external_id=job.id + ":" + finding_id,
                    assertion=assertion,
                )
            job.result = {"count": len(results), "checked_at": now().isoformat()}
        elif kind == "import-dt":
            revision = import_sbom(
                db,
                artifacts,
                release,
                canonical(results),
                source="dependency-track",
                event_id=job.id,
                occurred_at=now(),
                completeness="complete",
                context={"external_project_id": payload["external_project_id"]},
                actor_id=actor.user.id,
            )
            job.result = {"revision_id": revision.id, "sha256": digest(canonical(results))}
        job.status = "succeeded"
        job.lease_until = None


def work_once(factory, artifacts, settings):
    claimed = claim(factory)
    if not claimed:
        return False
    job_id, token = claimed
    try:
        execute(factory, artifacts, settings, job_id, token)
    except Exception as error:
        with factory.begin() as db:
            job = db.scalar(select(Job).where(Job.id == job_id).with_for_update())
            if job.status == "running" and job.lease_token == token:
                job.status = "failed"
                # Do not persist URLs, provider response bodies, or credentials in errors.
                job.error = (
                    error.detail
                    if isinstance(error, HTTPException)
                    else (
                        str(error)[:500]
                        if isinstance(error, ValueError)
                        else f"{type(error).__name__}: provider operation failed; retry explicitly"
                    )
                )
                job.lease_until = None
    return True


def run(factory, artifacts, settings):
    while True:
        if not work_once(factory, artifacts, settings):
            time.sleep(1)
