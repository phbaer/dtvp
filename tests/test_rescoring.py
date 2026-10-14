import copy

import pytest
import respx

from dtvp.models import now
from dtvp.rescoring import calculate, validate_policy
from tests.conftest import login

BASE = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
VECTOR = BASE + "/MAV:P/MAC:H/MPR:H/MUI:R/MC:N/MI:N/MA:N"


def target(client):
    row = next(
        f
        for f in client.get("/api/v2/findings").json()["items"]
        if f["identifier"] == "CVE-2099-20001"
    )
    return client.get(f"/api/v2/findings/{row['id']}").json()


def submit(client, finding, rescoring):
    preview = client.post(
        f"/api/v2/findings/{finding['id']}/rescoring/preview",
        json={
            "expected_version": finding["state_version"],
            "state": "not_affected",
            "rescoring": rescoring,
        },
    )
    if preview.status_code != 200:
        return preview
    return client.post(
        f"/api/v2/findings/{finding['id']}/decisions",
        json={
            "expected_version": finding["state_version"],
            "state": "not_affected",
            "rationale": "Scope examined; protection verified.",
            "rescoring": {**rescoring, "preview_digest": preview.json()["preview_digest"]},
        },
    )


def test_manual_rescoring_review_snapshot_and_revalidation(analyst, release_id):
    finding = target(analyst)
    body = {
        "kind": "manual",
        "base_vector": BASE,
        "vector": VECTOR,
        "rationale": "Verified deployment context.",
    }
    preview = analyst.post(
        f"/api/v2/findings/{finding['id']}/rescoring/preview",
        json={
            "expected_version": finding["state_version"],
            "state": "not_affected",
            "rescoring": body,
        },
    )
    assert preview.status_code == 200, preview.text
    assert preview.json()["proposal"]["score"] == 0
    response = submit(analyst, finding, body)
    assert response.status_code == 201, response.text
    pending = target(analyst)
    assert pending["effective_score"] == pending["original_score"] == 9.8
    assert pending["proposed_rescoring"]["score"] == 0 and pending["adopted_rescoring"] is None
    login(analyst, "reviewer")
    assert (
        analyst.post(
            f"/api/v2/findings/{finding['id']}/approvals",
            json={
                "expected_version": pending["state_version"],
                "decision_id": response.json()["id"],
            },
        ).status_code
        == 200
    )
    approved = target(analyst)
    assert approved["original_score"] == 9.8 and approved["effective_score"] == 0
    assert approved["adopted_rescoring"]["vector"] == preview.json()["proposal"]["vector"]
    assert analyst.get("/api/v2/statistics").json()["effective_severity"]["none"] == 1
    snapshot = analyst.post("/api/v2/snapshots", json={"release_id": release_id}).json()
    bundle = analyst.get(f"/api/v2/snapshots/{snapshot['id']}/bundle").json()
    frozen = next(f for f in bundle["findings"] if f["id"] == finding["id"])
    assert frozen["effective_score"] == 0 and frozen["original_score"] == 9.8
    assert (
        next(v for v in bundle["vscorer"]["cves"] if v["cve_id"] == finding["identifier"])[
            "cvss_vector"
        ]
        == BASE
    )
    login(analyst)
    assert (
        analyst.post(
            f"/api/v2/findings/{finding['id']}/evidence",
            json={
                "source": "pipeline",
                "external_id": "change",
                "assertion": {"kind": "scope", "description": "New deployment"},
            },
        ).status_code
        == 201
    )
    stale = target(analyst)
    assert stale["lifecycle"] == "needs_revalidation" and stale["effective_score"] == 9.8
    assert stale["adopted_rescoring"] is None
    assert analyst.get(f"/api/v2/snapshots/{snapshot['id']}/bundle").json() == bundle


def test_rules_require_preview_and_policy_changes_revalidate(analyst):
    finding = target(analyst)
    project = analyst.get("/api/v2/projects").json()[0]["id"]
    policy = analyst.get(f"/api/v2/projects/{project}/rescore-policy").json()
    validate_policy(policy["config"])
    body = {
        "kind": "rule",
        "base_vector": BASE,
        "policy_digest": policy["digest"],
        "rationale": "Applicability reviewed; use the version-specific rule.",
    }
    preview = analyst.post(
        f"/api/v2/findings/{finding['id']}/rescoring/preview",
        json={
            "expected_version": finding["state_version"],
            "state": "not_affected",
            "rescoring": body,
        },
    )
    assert preview.status_code == 200 and preview.json()["proposal"]["score"] == 0
    assert submit(analyst, finding, body).status_code == 201
    login(analyst, "administrator")
    config = copy.deepcopy(policy["config"])
    config["transitions"][0]["actions"]["3.1"]["MAC"] = "L"
    assert (
        analyst.put(
            f"/api/v2/projects/{project}/rescore-policy",
            json={"expected_version": 0, "config": config},
        ).status_code
        == 200
    )
    assert target(analyst)["lifecycle"] == "needs_revalidation"
    assert (
        analyst.put(
            f"/api/v2/projects/{project}/rescore-policy",
            json={"expected_version": 0, "config": config},
        ).status_code
        == 409
    )
    login(analyst)
    assert submit(analyst, target(analyst), body).status_code == 409
    altered = copy.deepcopy(config)
    altered["transitions"][0]["actions"]["3.1"]["AV"] = "P"
    login(analyst, "administrator")
    assert (
        analyst.put(
            f"/api/v2/projects/{project}/rescore-policy",
            json={"expected_version": 1, "config": altered},
        ).status_code
        == 422
    )


def test_source_proposals_bind_snapshot_revision_and_validate_vectors(analyst, release_id):
    finding = target(analyst)
    snapshot = analyst.post("/api/v2/snapshots", json={"release_id": release_id}).json()
    entry = next(
        v
        for v in analyst.get(f"/api/v2/snapshots/{snapshot['id']}/exports/vscorer/worklist").json()[
            "cves"
        ]
        if v["cve_id"] == finding["identifier"]
    )
    evidence = {
        "source": "vscorer",
        "external_id": "score-1",
        "snapshot_id": snapshot["id"],
        "assertion": {
            "kind": "contextual-assessment",
            "assessment_id": "result-1",
            "base_vector": BASE,
            "component_refs": entry["component_refs"],
            "environmental_vector": VECTOR,
            "environmental_score": 0,
            "rationale": "Model controls cover the reviewed paths.",
        },
    }
    response = analyst.post(f"/api/v2/findings/{finding['id']}/evidence", json=evidence)
    assert response.status_code == 201
    candidate = analyst.get(f"/api/v2/findings/{finding['id']}/rescoring/proposals").json()[
        "items"
    ][0]
    assert candidate["eligible"] and candidate["proposal"]["score"] == 0
    current = target(analyst)
    request = {
        "kind": "evidence",
        "evidence_id": response.json()["id"],
        "rationale": "VScorer output reviewed.",
    }
    assert submit(analyst, current, request).status_code == 201
    assert (
        analyst.post(
            f"/api/v2/findings/{finding['id']}/evidence",
            json={
                "source": "pipeline",
                "external_id": "changed",
                "assertion": {"kind": "scope", "changed": now().isoformat()},
            },
        ).status_code
        == 201
    )
    assert not analyst.get(f"/api/v2/findings/{finding['id']}/rescoring/proposals").json()["items"][
        0
    ]["eligible"]
    assert submit(analyst, target(analyst), request).status_code == 422
    # Delayed results from the old snapshot stay evidence, never current proposals.
    evidence["external_id"] = "late-score"
    assert (
        analyst.post(f"/api/v2/findings/{finding['id']}/evidence", json=evidence).status_code == 201
    )
    assert not analyst.get(f"/api/v2/findings/{finding['id']}/rescoring/proposals").json()["items"][
        0
    ]["eligible"]


@pytest.mark.parametrize(
    "vector",
    [
        BASE.replace("AV:N", "AV:P"),
        VECTOR.replace("CVSS:3.1", "CVSS:3.0"),
        BASE + "/AV:P",
        BASE + "/MC:BAD",
    ],
)
def test_base_metrics_version_duplicates_and_values_cannot_be_changed(vector):
    with pytest.raises(ValueError):
        calculate(BASE, vector)


def test_reserved_details_cannot_bypass_rescoring_validation(analyst):
    finding = target(analyst)
    assert (
        analyst.post(
            f"/api/v2/findings/{finding['id']}/decisions",
            json={
                "expected_version": finding["state_version"],
                "state": "affected",
                "rationale": "Forged score",
                "details": {"rescoring": {"score": 0}},
            },
        ).status_code
        == 422
    )


@pytest.mark.parametrize(
    "base,contextual",
    [
        ("AV:N/AC:L/Au:N/C:C/I:C/A:C", "AV:N/AC:L/Au:N/C:C/I:C/A:C/TD:N"),
        (BASE.replace("3.1", "3.0"), VECTOR.replace("3.1", "3.0")),
        (
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/MVC:N/MVI:N/MVA:N",
        ),
    ],
)
def test_calculator_supports_all_v1_specification_versions(base, contextual):
    assert calculate(base, contextual)["score"] == 0


def test_submit_requires_the_exact_preview_and_rejects_changed_rationale(analyst):
    finding = target(analyst)
    body = {
        "kind": "manual",
        "base_vector": BASE,
        "vector": VECTOR,
        "rationale": "Context verified.",
    }
    raw = {
        "expected_version": finding["state_version"],
        "state": "not_affected",
        "rationale": "Applicability reviewed.",
        "rescoring": body,
    }
    assert analyst.post(f"/api/v2/findings/{finding['id']}/decisions", json=raw).status_code == 409
    preview = analyst.post(
        f"/api/v2/findings/{finding['id']}/rescoring/preview", json=raw | {"rationale": None}
    )
    # Preview has its own strict request schema; unrelated fields are rejected.
    assert preview.status_code == 422
    preview = analyst.post(
        f"/api/v2/findings/{finding['id']}/rescoring/preview",
        json={key: raw[key] for key in ["expected_version", "state", "rescoring"]},
    ).json()
    raw["rescoring"] = body | {
        "preview_digest": preview["preview_digest"],
        "rationale": "Changed scoring basis.",
    }
    assert analyst.post(f"/api/v2/findings/{finding['id']}/decisions", json=raw).status_code == 409


def test_effective_sorting_uses_only_current_approved_scores(analyst):
    finding = target(analyst)
    params = {"sort": "original_score", "limit": 1}
    first = analyst.get("/api/v2/findings", params=params).json()
    assert first["items"][0]["identifier"] == finding["identifier"]
    second = analyst.get(
        "/api/v2/findings", params=params | {"cursor": first["next_cursor"]}
    ).json()
    assert second["items"][0]["identifier"] != finding["identifier"]
    body = {
        "kind": "manual",
        "base_vector": BASE,
        "vector": VECTOR,
        "rationale": "Verified context.",
    }
    decision = submit(analyst, finding, body).json()
    assert (
        analyst.get("/api/v2/findings?sort=effective_score").json()["items"][0]["identifier"]
        == finding["identifier"]
    )
    login(analyst, "reviewer")
    pending = target(analyst)
    assert (
        analyst.post(
            f"/api/v2/findings/{finding['id']}/approvals",
            json={"expected_version": pending["state_version"], "decision_id": decision["id"]},
        ).status_code
        == 200
    )
    sorted_rows = analyst.get("/api/v2/findings?sort=effective_score").json()["items"]
    assert (
        sorted_rows[-1]["identifier"] == finding["identifier"]
        and sorted_rows[-1]["effective_score"] == 0
    )


@respx.mock
def test_native_agentyzer_score_is_correlated_and_generic_evidence_cannot_impersonate_it(
    analyst, release_id
):
    import httpx
    import respx

    from tests.test_analysis import external, report, run_worker
    from tests.test_analysis import submit as analyse

    finding = external(analyst, release_id)
    respx.post("http://agentyzer.test/assess").mock(
        return_value=httpx.Response(200, json={"job_id": "score-run"})
    )
    respx.get("http://agentyzer.test/jobs/score-run").mock(
        return_value=httpx.Response(200, json={"status": "completed"})
    )
    respx.get("http://agentyzer.test/jobs/score-run/result").mock(
        return_value=httpx.Response(
            200,
            json=report(
                rescoring_eligible=True,
                adjusted_cvss={
                    "original_vector": BASE,
                    "adjusted_vector": VECTOR,
                    "adjusted_score": 0,
                },
            ),
        )
    )
    assert analyse(analyst, finding).status_code == 202
    assert run_worker(analyst)
    proposals = analyst.get(f"/api/v2/findings/{finding['id']}/rescoring/proposals").json()
    assert proposals["items"][0]["eligible"] and proposals["items"][0]["proposal"]["score"] == 0
    current = target(analyst)
    real = current["evidence"][0]
    fake = {
        "source": "agentyzer",
        "external_id": "unverified",
        "assertion": {
            "kind": "code-analysis",
            "job_id": real["job_id"],
            "report_sha256": real["report_sha256"],
            "target_verified": True,
            "rescoring_eligible": True,
            "source": "spoofed",
            "published_evidence_revision": 99,
        },
    }
    response = analyst.post(f"/api/v2/findings/{finding['id']}/evidence", json=fake)
    assert response.status_code == 201
    detail = target(analyst)
    latest = detail["evidence"][-1]
    assert (
        latest["source"] == "agentyzer"
        and latest["published_evidence_revision"] == detail["evidence_revision"]
    )
    assert not analyst.get(f"/api/v2/findings/{finding['id']}/rescoring/proposals").json()["items"][
        0
    ]["eligible"]
