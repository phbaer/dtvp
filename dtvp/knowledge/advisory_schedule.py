"""Opt-in bounded refresh policies and durable shared provider request pacing."""

import logging
import time
from datetime import UTC, timedelta
from email.utils import parsedate_to_datetime
from types import SimpleNamespace
from typing import Literal

from fastapi import HTTPException
from pydantic import Field, model_validator
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from dtvp.auth import aware
from dtvp.jobs import actor_for
from dtvp.knowledge.advisory_jobs import KIND, enqueue_advisory_refresh
from dtvp.knowledge.advisory_sources import (
    PUBLISHERS,
    AdvisoryRefreshInput,
    baseline_identifiers,
    enabled,
)
from dtvp.knowledge.evidence import evidence_ref
from dtvp.knowledge.journal import SECTIONS, Conflict, Name, Ref, Sha, Update
from dtvp.knowledge.ownership import product_heads
from dtvp.models import AdvisoryProviderThrottle, Job, Project, now
from dtvp.non_us_advisories import supports_identifier
from dtvp.schemas import RequestModel
from dtvp.storage import canonical, digest

logger = logging.getLogger(__name__)

MAX_SELECTED_BYTES = 64 * 1024 * 1024
MAX_SELECTED_RECORDS = 100_000
MIN_INTERVAL = {"nvd": 6.0, "circl": 1.0, "euvd": 1.0, "jvn": 1.0}
MAX_WAIT_SECONDS = 30.0


class ProviderSchedule(RequestModel):
    provider: Literal["nvd", "circl", "euvd", "jvn"]
    versions: list[Name] = Field(min_length=1, max_length=20)
    interval_seconds: int = Field(default=86400, ge=3600, le=30 * 86400, strict=True)
    batch_size: int = Field(default=20, ge=1, le=20, strict=True)

    @model_validator(mode="after")
    def unique_versions(self):
        if len(set(self.versions)) != len(self.versions):
            raise ValueError("Scheduled versions must be distinct")
        self.versions = sorted(self.versions)
        return self


class AdvisoryScheduleInput(RequestModel):
    request_id: Name
    expected_policy: Sha | None
    providers: list[ProviderSchedule] = Field(default_factory=list, max_length=4)

    @model_validator(mode="after")
    def unique_providers(self):
        if len({item.provider for item in self.providers}) != len(self.providers):
            raise ValueError("Configure each advisory provider only once")
        self.providers = sorted(self.providers, key=lambda item: item.provider)
        return self


def policy_ref(project_id):
    return Ref(kind="policy", project_id=project_id, name="advisory-schedule")


def policy(journal, project_id):
    state = journal.resolve(policy_ref(project_id))
    return state, (
        journal.load(journal.records(state, "history")["configuration"])
        if state
        else {"providers": []}
    )


def configure(journal, settings, *, project_id, actor, data):
    for provider in data.providers:
        enabled(settings, provider.provider)
    payload = data.model_dump(mode="json")
    fingerprint = digest(
        canonical(
            ["dtvp.advisory-schedule/1", project_id, actor.user.id, actor.credential.id, payload]
        )
    )
    request_id = digest(canonical([project_id, actor.user.id, data.request_id]))
    with journal.writer():
        receipt = journal.receipt(request_id, fingerprint)
    if receipt:
        return receipt
    previous = journal.resolve(policy_ref(project_id))
    if previous != data.expected_policy:
        raise Conflict("Advisory schedule changed; reload before configuring")
    sections = {key: {} for key in SECTIONS}
    sections["history"]["configuration"] = {
        "format": "dtvp.advisory-schedule/1",
        "providers": payload["providers"],
        "actor_id": actor.user.id,
        "credential_id": actor.credential.id,
    }
    state = journal.snapshot(
        project_id=project_id,
        version="@advisory-schedule",
        actor_id=actor.user.id,
        reason="Configure known-identifier advisory refresh scheduling",
        parents=[previous] if previous else [],
        sections=sections,
    )
    return journal.publish(
        request_id=request_id,
        fingerprint=fingerprint,
        updates=[Update(ref=policy_ref(project_id), expected=previous, target=state)],
    )


def provider_jobs(project_id, provider):
    return select(Job).where(
        Job.project_id == project_id,
        Job.kind == KIND,
        Job.payload["intake"]["provider"].as_string() == provider,
    )


def next_revision(journal, evidence, provider):
    records = journal.records(evidence, "vulnerabilities") if evidence else {}
    revisions = []
    for key, sha in records.items():
        if key.startswith("evidence-document:"):
            value = journal.load(sha)
            document = value.get("document", {})
            if (
                value.get("source") == "connector:" + provider
                and document.get("document_id") == "dtvp-provider-catalog:" + provider
                and document.get("publisher") == PUBLISHERS[provider]
            ):
                revisions.append(value["source_revision"])
    return max(revisions, default=-1) + 1


def selected_identifiers(journal, project_id, heads):
    # Bound the complete selected logical states before the shared normalizer loads
    # them. Unknown sections are retained in the accounting, never skipped.
    total, records, seen = 0, 0, set()
    for state in heads.values():
        manifest = journal.state(state)
        for section in manifest.sections.values():
            if section not in seen:
                total += journal.objects.path(section).stat().st_size
                seen.add(section)
            if total > MAX_SELECTED_BYTES:
                raise ValueError("Scheduled advisory selection exceeds 64 MiB")
            pointers = journal.load(section)["records"]
            records += len(pointers)
            if records > MAX_SELECTED_RECORDS:
                raise ValueError("Scheduled advisory selection exceeds 100,000 records")
            for sha in pointers.values():
                if sha not in seen:
                    total += journal.objects.path(sha).stat().st_size
                    seen.add(sha)
                if total > MAX_SELECTED_BYTES:
                    raise ValueError("Scheduled advisory selection exceeds 64 MiB")
    return baseline_identifiers(journal, project_id, heads, require_current=False)


def reconcile(factory, journal, settings):
    """Scan at most 100 explicitly configured products; enqueue at most one/provider."""
    refs = journal.references()
    products = sorted(
        {
            ref.project_id
            for key in refs
            if (ref := Ref.model_validate_json(key)).kind == "policy"
            and ref.name == "advisory-schedule"
        }
    )
    cursor = getattr(reconcile, "cursor", "")
    selected = (
        [value for value in products if value > cursor]
        + [value for value in products if value <= cursor]
    )[:100]
    count = 0
    for project_id in selected:
        try:
            state = refs[policy_ref(project_id).key]
            config = journal.load(journal.records(state, "history")["configuration"])
            heads = product_heads(refs, project_id)
            if not heads or len(heads) > 200:
                continue
        except ValueError, OSError:
            logger.warning(
                "Advisory scheduling skipped inconsistent bounded policy input for project %s",
                project_id,
            )
            continue
        for schedule in config["providers"]:
            try:
                provider = schedule["provider"]
                if provider not in settings.providers_enabled or not all(
                    version in heads for version in schedule["versions"]
                ):
                    continue
                with factory.begin() as db:
                    project = db.scalar(
                        select(Project).where(Project.id == project_id).with_for_update()
                    )
                    if not project:
                        continue
                    try:
                        actor = actor_for(
                            db,
                            SimpleNamespace(
                                actor_id=config["actor_id"],
                                payload={"credential_id": config["credential_id"]},
                            ),
                        )
                        actor.require(db, project, "manage")
                        actor.require(db, project, "evidence")
                    except ValueError, HTTPException:
                        continue
                    query = provider_jobs(project_id, provider)
                    if db.scalar(
                        query.where(Job.status.in_(["queued", "running", "import_pending"])).limit(
                            1
                        )
                    ):
                        continue
                    previous = db.scalar(
                        query.order_by(Job.created_at.desc(), Job.id.desc()).limit(1)
                    )
                    tick = now()
                    if (
                        previous
                        and aware(previous.created_at)
                        + timedelta(seconds=schedule["interval_seconds"])
                        > tick
                    ):
                        continue
                    identifiers = sorted(
                        value
                        for value in selected_identifiers(
                            journal,
                            project_id,
                            {version: heads[version] for version in schedule["versions"]},
                        )
                        if supports_identifier(provider, value)
                    )
                    if not identifiers:
                        continue
                    last_id = (
                        previous.payload.get("schedule", {}).get("last_identifier", "")
                        if previous
                        else ""
                    )
                    ordered = [value for value in identifiers if value > last_id] + [
                        value for value in identifiers if value <= last_id
                    ]
                    batch = ordered[: schedule["batch_size"]]
                    evidence = refs.get(evidence_ref(project_id).key)
                    data = AdvisoryRefreshInput(
                        request_id="scheduled:"
                        + digest(
                            canonical(
                                [
                                    state,
                                    provider,
                                    previous.id if previous else None,
                                    heads,
                                    evidence,
                                    batch,
                                ]
                            )
                        ),
                        provider=provider,
                        identifiers=batch,
                        expected_versions=heads,
                        expected_evidence=evidence,
                        revision=next_revision(journal, evidence, provider),
                    )
                    if journal.resolve(policy_ref(project_id)) != state:
                        continue
                    try:
                        job = enqueue_advisory_refresh(
                            db, journal, settings, project_id=project_id, actor=actor, data=data
                        )
                    except Conflict:
                        continue
                    job.payload = {
                        **job.payload,
                        "schedule": {
                            "policy": state,
                            "versions": schedule["versions"],
                            "last_identifier": batch[-1],
                            "interval_seconds": schedule["interval_seconds"],
                            "known_identifiers": len(identifiers),
                        },
                    }
                    count += 1
            except ValueError, HTTPException, OSError:
                logger.warning(
                    "Advisory scheduling skipped bounded or stale provider input for project %s",
                    project_id,
                )
    if selected:
        reconcile.cursor = selected[-1]
    return count


def _marker(db, provider):
    marker = db.scalar(
        select(AdvisoryProviderThrottle)
        .where(AdvisoryProviderThrottle.provider == provider)
        .with_for_update()
    )
    if marker is None:
        try:
            with db.begin_nested():
                db.add(AdvisoryProviderThrottle(provider=provider))
                db.flush()
        except IntegrityError:
            pass
        marker = db.scalar(
            select(AdvisoryProviderThrottle)
            .where(AdvisoryProviderThrottle.provider == provider)
            .with_for_update()
        )
    if marker is None:
        raise ValueError("Provider pacing row is unavailable")
    return marker


def record_provider_retry_after(factory, provider, value, *, clock=None):
    """Retain upstream 429 cooldown without retrying or retaining provider headers."""
    if provider not in MIN_INTERVAL:
        raise ValueError("Unsupported advisory provider")
    tick = (clock or now)()
    try:
        if isinstance(value, str) and value.isascii() and value.isdecimal() and len(value) <= 10:
            until = tick + timedelta(seconds=int(value))
        elif isinstance(value, str) and len(value) <= 200:
            until = parsedate_to_datetime(value)
            until = until.replace(tzinfo=UTC) if until.tzinfo is None else until.astimezone(UTC)
        else:
            raise ValueError("Invalid Retry-After")
    except ValueError, TypeError, OverflowError:
        until = tick + timedelta(seconds=60)
    with factory.begin() as db:
        marker = _marker(db, provider)
        previous = marker.cooldown_until
        if previous:
            until = max(until, aware(previous))
        marker.cooldown_until = max(tick, until)


def wait_for_provider(factory, provider, *, sleep=None, clock=None, check=None):
    """Pace manual/scheduled native GETs across workers using an existing SQL row.

    The operational pacing row has no project or actor ownership. No quota reservation
    survives a delayed process: contenders recheck the dispatch timestamp after
    each wait. Cancellation/authority is rechecked by the caller before its GET.
    """
    if provider not in MIN_INTERVAL:
        raise ValueError("Unsupported advisory provider")
    sleep, clock = sleep or time.sleep, clock or now
    started = clock()
    waited = 0.0
    while True:
        with factory.begin() as db:
            if check is not None:
                check(db)
            interval = MIN_INTERVAL[provider]
            marker = _marker(db, provider)
            tick = clock()
            previous = marker.last_dispatch_at
            delay = (
                max(
                    0.0,
                    (aware(previous) + timedelta(seconds=interval) - tick).total_seconds(),
                )
                if previous
                else 0.0
            )
            cooldown = marker.cooldown_until
            if cooldown:
                delay = max(delay, (aware(cooldown) - tick).total_seconds())
            if delay <= 0:
                marker.last_dispatch_at = tick
                return
        remaining = MAX_WAIT_SECONDS - max(waited, (clock() - started).total_seconds())
        if delay > remaining or remaining <= 0:
            raise ValueError("Provider pacing wait exceeded 30 seconds; retry explicitly")
        sleep(delay)
        waited += delay


def record_retry_after(factory, identity, value, *, clock=None):
    with factory() as db:
        job = db.get(Job, identity)
        if not job or job.kind != KIND:
            raise ValueError("Native advisory job unavailable")
        provider = job.payload["intake"]["provider"]
    return record_provider_retry_after(factory, provider, value, clock=clock)


def wait_for_provider_slot(factory, identity, *, sleep=None, clock=None):
    with factory() as db:
        job = db.get(Job, identity)
        if not job or job.kind != KIND:
            raise ValueError("Native advisory job unavailable")
        provider = job.payload["intake"]["provider"]

    def check(db):
        current = db.get(Job, identity)
        if not current or current.kind != KIND or current.status != "running":
            raise ValueError("Advisory collection cancelled or no longer running")

    return wait_for_provider(factory, provider, sleep=sleep, clock=clock, check=check)
