"""PostgreSQL leases and atomic publication. External writes are never retried implicitly."""

import logging
import time
from datetime import timedelta

from fastapi import HTTPException
from sqlalchemy import and_, or_, select

from dtvp.auth import Actor, aware, capabilities
from dtvp.knowledge.maintenance_lock import RuntimeLease
from dtvp.models import Credential, Job, Membership, User, now, uid

logger = logging.getLogger(__name__)

NATIVE_JOB_KINDS = frozenset(
    {
        "analyse-native",
        "import-dt-native",
        "refresh-advisories-native",
        "match-osv-native",
        "propose-sync-native",
    }
)


def claim(factory):
    with factory.begin() as db:
        job = db.scalar(
            select(Job)
            .where(
                Job.kind.in_(NATIVE_JOB_KINDS),
                or_(
                    and_(Job.status == "queued", Job.available_at <= now()),
                    and_(Job.status == "running", Job.lease_until < now()),
                ),
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
        kind, engine = db.get(Job, job_id).kind, db.get_bind()
    if kind not in NATIVE_JOB_KINDS:
        raise ValueError("Unsupported retained job kind; only native jobs can execute")
    from dtvp.knowledge.journal import Journal
    from dtvp.knowledge.projection import catch_up

    journal = Journal(artifacts.root / "knowledge")
    if kind == "propose-sync-native":
        from dtvp.knowledge.sync_jobs import execute as execute_native
    elif kind == "analyse-native":
        from dtvp.knowledge.analysis_jobs import execute_analysis as execute_native
    elif kind == "match-osv-native":
        from dtvp.knowledge.osv_jobs import execute_matching as execute_native
    elif kind == "refresh-advisories-native":
        from dtvp.knowledge.advisory_jobs import execute_advisory_refresh as execute_native
    else:
        from dtvp.knowledge.source_jobs import execute_source as execute_native
    execute_native(factory, journal, settings, job_id, token)
    try:
        catch_up(engine, journal)
        projection = "current"
    except Exception:
        logger.exception("Native job knowledge projection awaits recovery")
        projection = "pending"
    with factory.begin() as completed:
        job = completed.scalar(select(Job).where(Job.id == job_id).with_for_update())
        if job.status == "succeeded":
            job.result = {**job.result, "projection": projection}
    return


def work_once(factory, artifacts, settings):
    with RuntimeLease(artifacts.root / "knowledge"):
        return _work_once(factory, artifacts, settings)


def _work_once(factory, artifacts, settings):
    # Recover journal/SQL enqueue gaps without delaying knowledge publication.
    # Repeated failures are logged; unrelated queued jobs must remain executable.
    from dtvp.knowledge.journal import Journal
    from dtvp.knowledge.sync_jobs import reconcile

    last_scan = getattr(_work_once, "last_sync_scan", 0)
    if time.monotonic() - last_scan >= 5:
        _work_once.last_sync_scan = time.monotonic()
        try:
            reconcile(factory, Journal(artifacts.root / "knowledge"))
        except Exception:
            logger.exception("Automatic synchronization scheduling awaits reconciliation")
    last_advisory_scan = getattr(_work_once, "last_advisory_scan", 0)
    if time.monotonic() - last_advisory_scan >= 5:
        _work_once.last_advisory_scan = time.monotonic()
        try:
            from dtvp.knowledge.advisory_schedule import reconcile as reconcile_advisories

            reconcile_advisories(factory, Journal(artifacts.root / "knowledge"), settings)
        except Exception:
            logger.exception("Automatic advisory scheduling awaits reconciliation")
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
    with RuntimeLease(artifacts.root / "knowledge"):
        while True:
            if not work_once(factory, artifacts, settings):
                time.sleep(1)
