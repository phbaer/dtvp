"""Native result intake is evidence, not assessment or score publication."""

from dtvp.rescoring import calculate
from dtvp.storage import canonical, digest
from tests.test_knowledge_api import app as knowledge_app
from tests.test_rescoring import BASE, VECTOR
from tests.test_workflow_api import setup, url, workspace

app = knowledge_app


def test_vscorer_roundtrip_is_comparable_without_approval(analyst, bom):
    project_id, _ = setup(analyst, bom)
    before = workspace(analyst, project_id)
    row = before["items"][0]
    assert "scoring_proposals" not in row  # Preserve pre-proposal pinned bundle bytes.
    receipt = analyst.post(
        url(project_id, f"/states/{before['state']}/vscorer-input"),
        json={
            "context_id": row["context_id"],
            "component_ref": row["context"]["component_ref"],
            "base_selections": {row["vulnerability_id"]: BASE},
        },
    ).json()["dtvp_source"]
    binding = {
        "receipt": receipt,
        "receipt_sha256": digest(canonical(receipt)),
        "verification": "artifact_scope_and_base_consistency",
        "remote_authenticity": "not_verified",
    }
    fragment = {**receipt, **{key: value for key, value in binding.items() if key != "receipt"}}
    payload = {
        "request_id": "native-result",
        "expected": before["state"],
        "source_binding": binding,
        "finding": {
            "id": "vscorer-finding",
            "assessment_id": "vscorer-assessment",
            "cve_id": row["vulnerability_id"],
            "source_facts": {
                "dtvp_source": fragment,
                "base_vector": BASE,
                "base_score": 9.8,
                "components": [{"bom_ref": row["context"]["component_ref"]}],
            },
            "preview": {
                "environmental_vector": VECTOR,
                "environmental_score": calculate(BASE, VECTOR)["score"],
                "environmental_approval_allowed": True,
                "approval_blockers": [],
            },
        },
    }
    path = url(project_id, "/versions/7.1.1/proposals/vscorer")
    imported = analyst.post(path, json=payload)
    assert imported.status_code == 201, imported.text
    assert analyst.post(path, json=payload).json() == imported.json()
    after = workspace(analyst, project_id)
    updated = next(item for item in after["items"] if item["id"] == row["id"])
    assert updated["published_score"] is None
    assert updated["coverage"]["status"] == "unassessed"
    proposal = updated["scoring_proposals"][0]
    assert proposal["eligible"] is True
    assert proposal["requires_coordinator_publication"] is True
    assert proposal["proposal"]["base_score"] == 9.8
    assert proposal["proposal"]["score"] == calculate(BASE, VECTOR)["score"]
    assert proposal["score_input"]["base_vector"] == BASE
    selected = workspace(analyst, project_id, provider="vscorer")
    assert [item["id"] for item in selected["items"]] == [row["id"]]
    assert selected["statistics"]["context_findings"] == 1
