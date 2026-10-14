from datetime import timedelta

from dtvp.models import now
from tests.conftest import login


def test_decision_approval_revalidation_and_snapshot(analyst, release_id, bom):
    client = analyst
    finding = client.get("/api/v2/findings").json()["items"][0]
    response = client.post(
        f"/api/v2/findings/{finding['id']}/decisions",
        json={
            "expected_version": finding["state_version"],
            "state": "affected",
            "rationale": "Patch planned; exposure confirmed.",
        },
    )
    assert response.status_code == 201, response.text
    decision_id = response.json()["id"]
    assert (
        client.post(
            f"/api/v2/findings/{finding['id']}/approvals",
            json={"expected_version": 2, "decision_id": decision_id},
        ).status_code
        == 404
    )
    login(client, "reviewer")
    response = client.post(
        f"/api/v2/findings/{finding['id']}/approvals",
        json={"expected_version": 2, "decision_id": decision_id},
    )
    assert response.status_code == 200, response.text
    assert client.get(f"/api/v2/findings/{finding['id']}").json()["lifecycle"] == "approved"
    snapshot = client.post("/api/v2/snapshots", json={"release_id": release_id}).json()
    bundle = client.get(f"/api/v2/snapshots/{snapshot['id']}/bundle").content
    login(client)
    for vulnerability in bom["vulnerabilities"]:
        vulnerability["description"] += " New scope evidence."
    assert (
        client.post(
            f"/api/v2/releases/{release_id}/ingestions",
            json={
                "source": "pipeline:demo",
                "event_id": "changed",
                "occurred_at": now().isoformat(),
                "sbom": bom,
            },
        ).status_code
        == 201
    )
    updated = client.get(f"/api/v2/findings/{finding['id']}").json()
    assert updated["lifecycle"] == "needs_revalidation"
    assert updated["approval"]
    assert client.get(f"/api/v2/snapshots/{snapshot['id']}/bundle").content == bundle
    stale = client.post(
        f"/api/v2/findings/{finding['id']}/decisions",
        json={"expected_version": 1, "state": "not_affected", "rationale": "Stale submission"},
    )
    assert stale.status_code == 409


def test_curated_metadata_reimport_and_out_of_order(analyst, release_id, bom):
    client = analyst
    component = client.get(f"/api/v2/releases/{release_id}/components").json()["items"][0]
    assert (
        client.put(
            f"/api/v2/components/{component['id']}/metadata",
            json={"expected_version": 0, "metadata": {"owner": "Platform", "eol": "2030-01-01"}},
        ).status_code
        == 200
    )
    for event, occurred in [("new", now()), ("old", now() - timedelta(days=3))]:
        assert (
            client.post(
                f"/api/v2/releases/{release_id}/ingestions",
                json={
                    "source": "pipeline:demo",
                    "event_id": event,
                    "occurred_at": occurred.isoformat(),
                    "sbom": bom,
                    "context": {"commit": "synthetic", "branch": "main"},
                },
            ).status_code
            == 201
        )
    components = client.get(f"/api/v2/releases/{release_id}/components").json()["items"]
    assert (
        next(c for c in components if c["id"] == component["id"])["metadata"]["owner"] == "Platform"
    )
    assert all(f["evidence_revision"] <= 2 for f in client.get("/api/v2/findings").json()["items"])


def test_partial_scan_does_not_remove_findings(analyst, release_id, bom):
    bom["vulnerabilities"] = []
    assert (
        analyst.post(
            f"/api/v2/releases/{release_id}/ingestions",
            json={
                "source": "pipeline:demo",
                "event_id": "partial",
                "completeness": "partial",
                "occurred_at": now().isoformat(),
                "sbom": bom,
                "context": {"commit": "synthetic", "branch": "main"},
            },
        ).status_code
        == 201
    )
    assert len(analyst.get("/api/v2/findings").json()["items"]) == 2


def test_idempotent_upload_and_invalid_graph(analyst, release_id, bom):
    import json

    raw = json.dumps(bom).encode()
    first = analyst.post(
        f"/api/v2/releases/{release_id}/uploads", files={"file": ("demo.json", raw)}
    )
    second = analyst.post(
        f"/api/v2/releases/{release_id}/uploads", files={"file": ("demo.json", raw)}
    )
    assert first.status_code == second.status_code == 201, second.text
    assert first.json()["id"] == second.json()["id"]
    bom["dependencies"][0]["dependsOn"].append("missing")
    invalid = analyst.post(
        f"/api/v2/releases/{release_id}/ingestions",
        json={
            "source": "pipeline:demo",
            "event_id": "broken",
            "occurred_at": now().isoformat(),
            "sbom": bom,
        },
    )
    assert invalid.status_code == 422


def test_vscorer_export_and_return_scope(analyst, release_id):
    client = analyst
    snapshot = client.post("/api/v2/snapshots", json={"release_id": release_id}).json()
    export = client.get(f"/api/v2/snapshots/{snapshot['id']}/exports/vscorer").json()
    assert set(export["cves"]) == {"cves"}
    refs = {c["bom-ref"] for c in export["sbom"]["components"]}
    assert len(export["cves"]["cves"]) == 2
    for entry in export["cves"]["cves"]:
        assert set(entry["component_refs"]) <= refs
        assert set(entry) == {
            "cve_id",
            "component_refs",
            "cvss_vector",
            "base_score",
            "description",
            "cwe_ids",
            "cpe",
            "references",
        }
    entry = export["cves"]["cves"][0]
    mapping = next(f for f in export["finding_mapping"] if f["identifier"] == entry["cve_id"])
    body = {
        "source": "vscorer",
        "external_id": "assessment-1",
        "snapshot_id": snapshot["id"],
        "assertion": {
            "kind": "contextual-assessment",
            "assessment_id": "assessment-1",
            "base_vector": entry["cvss_vector"],
            "component_refs": entry["component_refs"],
            "environmental_score": 4.0,
        },
    }
    response = client.post(f"/api/v2/findings/{mapping['finding_id']}/evidence", json=body)
    assert response.status_code == 201, response.text
    repeated = client.post(f"/api/v2/findings/{mapping['finding_id']}/evidence", json=body)
    assert repeated.status_code == 201, repeated.text
    assert repeated.json()["id"] == response.json()["id"]
    assert client.get(f"/api/v2/findings/{mapping['finding_id']}").json()["lifecycle"] == "open"
    body["external_id"] = "wrong-input"
    body["assertion"]["base_vector"] = "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
    assert (
        client.post(f"/api/v2/findings/{mapping['finding_id']}/evidence", json=body).status_code
        == 422
    )
