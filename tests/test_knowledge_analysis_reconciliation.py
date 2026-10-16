"""Explicit authenticated GET recovery cannot create another remote submission."""

import copy

import httpx
import pytest
import respx

from dtvp.knowledge.analysis_jobs import job_view
from dtvp.knowledge.analysis_reconciliation import ReconcileInput, reconcile_analysis
from dtvp.knowledge.journal import Conflict
from dtvp.models import Credential, Job, Project
from dtvp.storage import canonical
from tests.test_knowledge_agentyzer_results import report
from tests.test_knowledge_analysis_jobs import BASE, enqueue, job, run
from tests.test_knowledge_analysis_jobs import env as native_env

env = native_env
TOKEN = "private-authenticated-service-" + "x" * 32


def unknown(env):
    env.settings.agentyzer_token = TOKEN
    env.settings.agentyzer_reconciliation_enabled = True
    identity = enqueue(env)
    with env.factory.begin() as db:
        selected = db.get(Job, identity)
        selected.status = "submission_unknown"
        selected.payload = {**selected.payload, "submission_started": True}
    return identity


def proof(env, identity, remote="remote-1"):
    selected = job(env, identity)
    return {
        "format": "agentyzer.dtvp-binding/1",
        "job_id": remote,
        "status": "completed",
        "binding": copy.deepcopy(selected.payload["correlation"]),
        "request": copy.deepcopy(selected.payload["request"]),
        "report": report(env.derived)["report"],
    }


def reconcile(env, identity, data=None):
    return reconcile_analysis(
        env.factory,
        env.journal,
        env.settings,
        project_id="product",
        job_id=identity,
        actor_id="author",
        credential_id="credential",
        data=data or ReconcileInput(request_id="reconcile-1", remote_id="remote-1"),
    )


@respx.mock
def test_authenticated_capture_reuses_exact_report_and_repeat_never_posts_or_refetches(env):
    identity = unknown(env)
    value = proof(env, identity)
    route = respx.get(BASE + "/jobs/remote-1/dtvp-binding").mock(
        return_value=httpx.Response(200, json=value)
    )
    original = env.journal.head()
    returned = reconcile(env, identity)
    assert returned.status == "queued" and route.call_count == 1
    assert route.calls[0].request.headers["Authorization"] == "Bearer " + TOKEN
    assert env.journal.head() == original
    public = env.journal.load(returned.payload["report_sha256"])
    assert public["report"] == value["report"]
    assert "transport_observation" in public
    assert (
        returned.payload["correlation"]["nonce"]
        not in str(job_view(returned)) + canonical(public).decode()
    )
    assert reconcile(env, identity).id == identity and route.call_count == 1
    run(env, identity)  # Checkpointed report goes directly to existing importer.
    assert job(env, identity).status == "succeeded" and route.call_count == 1
    with pytest.raises(Conflict, match="different"):
        reconcile(env, identity, ReconcileInput(request_id="other", remote_id="remote-2"))


@pytest.mark.parametrize(
    "bad",
    [
        "job",
        "binding",
        "repository",
        "commit",
        "missing_commit",
        "scope",
        "version",
        "request_digest",
        "nonce_echo",
        "private_echo",
        "running",
    ],
)
@respx.mock
def test_wrong_or_unqualified_remote_proof_retains_unknown_without_artifacts(env, bad):
    identity = unknown(env)
    value = proof(env, identity)
    if bad == "job":
        value["job_id"] = "wrong"
    elif bad == "binding":
        value["binding"]["issued_receipt_sha256"] = "f" * 64
    elif bad == "repository":
        value["request"]["component_name"] = "other"
    elif bad == "commit":
        value["report"]["source_input"]["resolved_commit"] = "f" * 40
    elif bad == "missing_commit":
        value["report"]["source_input"].pop("resolved_commit")
    elif bad == "scope":
        value["request"]["assessment_scope"] = "component"
    elif bad == "version":
        value["request"]["project_versions"] = ["other"]
    elif bad == "request_digest":
        value["binding"]["request_sha256"] = "f" * 64
    elif bad == "nonce_echo":
        value["report"]["summary"] = value["binding"]["nonce"]
    elif bad == "private_echo":
        value["report"]["extra"] = {"dtvp_binding": {"nonce": "different"}}
    else:
        value["status"] = "running"
    respx.get(BASE + "/jobs/remote-1/dtvp-binding").mock(
        return_value=httpx.Response(200, json=value)
    )
    files = set(env.journal.objects.root.rglob("*"))
    with pytest.raises(ValueError):
        reconcile(env, identity)
    selected = job(env, identity)
    assert selected.status == "submission_unknown" and not selected.payload.get("remote_id")
    assert not selected.lease_token and set(env.journal.objects.root.rglob("*")) == files


@pytest.mark.parametrize(
    "change", ["cancel", "credential", "repository", "token", "material", "lease", "disabled"]
)
@respx.mock
def test_current_authority_binding_source_and_lease_rechecked_after_get(env, change):
    identity = unknown(env)
    value = proof(env, identity)

    def response(request):
        with env.factory.begin() as db:
            selected = db.get(Job, identity)
            if change == "cancel":
                selected.status = "cancelled"
            elif change == "credential":
                db.get(Credential, "credential").revoked = True
            elif change == "repository":
                db.get(Project, "product").metadata_json = {}
            elif change == "lease":
                selected.lease_token = "new-lease"
        if change == "disabled":
            env.settings.agentyzer_reconciliation_enabled = False
        if change == "token":
            env.settings.agentyzer_token = "changed-service-token-" + "y" * 32
        if change == "material":
            from tests.test_knowledge_agentyzer import imported, qualified

            changed = copy.deepcopy(env.bom)
            changed["components"][0]["version"] = "9"
            imported(
                env.journal,
                changed,
                expected=env.state,
                build_number=2,
                context=qualified(),
            )
        return httpx.Response(200, json=value)

    respx.get(BASE + "/jobs/remote-1/dtvp-binding").mock(side_effect=response)
    with pytest.raises((Conflict, PermissionError, ValueError)):
        reconcile(env, identity)
    assert not job(env, identity).payload.get("remote_id")


@respx.mock
def test_get_uncertainty_can_retry_safely_and_legacy_unknown_has_no_binding(env):
    identity = unknown(env)
    route = respx.get(BASE + "/jobs/remote-1/dtvp-binding").mock(
        side_effect=httpx.ConnectError("unavailable")
    )
    with pytest.raises(httpx.HTTPError):
        reconcile(env, identity)
    assert not job(env, identity).lease_token
    route.mock(return_value=httpx.Response(200, json=proof(env, identity)))
    assert reconcile(env, identity).status == "queued" and route.call_count == 2
    other = identity
    with env.factory.begin() as db:
        selected = db.get(Job, other)
        selected.status = "submission_unknown"
        selected.payload = {
            key: value
            for key, value in selected.payload.items()
            if key not in {"correlation", "remote_id", "report_sha256", "reconciliation"}
        }
    with pytest.raises(Conflict, match="Legacy"):
        reconcile(env, other, ReconcileInput(request_id="legacy", remote_id="remote-1"))


@respx.mock
def test_failed_request_id_remains_bound_after_another_observation_attempt(env):
    identity = unknown(env)
    first = respx.get(BASE + "/jobs/remote-1/dtvp-binding").mock(
        side_effect=httpx.ConnectError("unavailable")
    )
    second = respx.get(BASE + "/jobs/remote-2/dtvp-binding").mock(
        side_effect=httpx.ConnectError("unavailable")
    )
    for request_id, remote_id in (("first", "remote-1"), ("second", "remote-2")):
        with pytest.raises(httpx.HTTPError):
            reconcile(env, identity, ReconcileInput(request_id=request_id, remote_id=remote_id))
    with pytest.raises(Conflict, match="different input"):
        reconcile(env, identity, ReconcileInput(request_id="first", remote_id="remote-2"))
    assert first.call_count == second.call_count == 1


@pytest.mark.parametrize("echo", ["nonce", "private_field"])
@respx.mock
def test_ordinary_worker_polling_rejects_private_echo_before_retention(env, echo):
    env.settings.agentyzer_token = TOKEN
    env.settings.agentyzer_reconciliation_enabled = True
    identity = enqueue(env)
    selected = job(env, identity)
    envelope = report(env.derived)
    envelope["job"]["job_id"] = "remote-1"
    if echo == "nonce":
        envelope["report"]["summary"] = selected.payload["correlation"]["nonce"]
    else:
        envelope["job"]["request"]["dtvp_binding"] = {"unexpected": "private"}
    respx.post(BASE + "/assess").mock(return_value=httpx.Response(200, json={"job_id": "remote-1"}))
    respx.get(BASE + "/jobs/remote-1").mock(return_value=httpx.Response(200, json=envelope["job"]))
    respx.get(BASE + "/jobs/remote-1/result").mock(
        return_value=httpx.Response(200, json=envelope["report"])
    )
    before = set((env.journal.root / "objects").rglob("*"))
    with pytest.raises(ValueError, match="Private"):
        run(env, identity)
    assert set((env.journal.root / "objects").rglob("*")) == before
    assert not job(env, identity).payload.get("report_sha256")


@respx.mock
def test_private_protocol_is_explicit_opt_in_and_never_upgrades_existing_jobs(env):
    from tests.test_knowledge_analysis_jobs import complete_routes

    env.settings.agentyzer_token = TOKEN  # A strong token alone is not protocol admission.
    identity = enqueue(env)
    assert "correlation" not in job(env, identity).payload
    env.settings.agentyzer_reconciliation_enabled = True
    assert enqueue(env) == identity and "correlation" not in job(env, identity).payload
    posted, _, _ = complete_routes(env)
    run(env, identity)
    import json

    assert json.loads(posted.calls[0].request.content) == job(env, identity).payload["request"]


@respx.mock
def test_enabled_private_protocol_sends_exact_correlation(env):
    from tests.test_knowledge_analysis_jobs import complete_routes

    env.settings.agentyzer_token = TOKEN
    env.settings.agentyzer_reconciliation_enabled = True
    identity = enqueue(env)
    selected = job(env, identity)
    posted, _, _ = complete_routes(env)
    run(env, identity)
    import json

    assert json.loads(posted.calls[0].request.content) == {
        **selected.payload["request"],
        "dtvp_binding": selected.payload["correlation"],
    }


@respx.mock
def test_disabled_protocol_retains_original_binding_but_blocks_reconciliation(env):
    identity = unknown(env)
    original = job(env, identity).payload["correlation"]
    env.settings.agentyzer_reconciliation_enabled = False
    with pytest.raises(ValueError, match="configured ASCII"):
        reconcile(env, identity)
    assert job(env, identity).payload["correlation"] == original
    assert not respx.calls
