"""Advisory facts enrich baseline identifiers without becoming matching decisions."""

import copy

import pytest

from dtvp.knowledge.advisory_documents import FORMAT
from dtvp.knowledge.evidence import (
    EvidenceInput,
    WithdrawalInput,
    current_evidence,
    import_evidence,
    withdraw_evidence,
)
from dtvp.knowledge.journal import Journal
from dtvp.knowledge.ownership import product_heads
from dtvp.knowledge.service import import_inventory
from dtvp.knowledge.vex import parse_evidence, reconcile_evidence
from dtvp.knowledge.workspace import load_sections, load_workspace
from dtvp.storage import canonical, digest


@pytest.fixture
def journal(tmp_path):
    return Journal(tmp_path / "journal")


def feed(identifier="CVE-2099-20001", score=0):
    return {
        "format": FORMAT,
        "id": "provider-daily",
        "publisher": "Attributed provider",
        "advisories": [
            {
                "advisory": {
                    "id": identifier,
                    "description": "Independent provider description",
                    "ratings": [
                        {"score": score, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
                    ],
                    "references": [{"url": "https://provider.invalid/advisory"}],
                    "aliases": [{"id": "GHSA-not-matched"}],
                    "analysis": {"state": "not_affected"},
                },
                "raw": {
                    "provider_payload": {"affected": ["invented range"], "package": "not-matched"}
                },
            }
        ],
    }


def heads(journal):
    return product_heads(journal.references(), "product")


def add(journal, document=None, *, request_id="feed-1", revision=1, source="provider"):
    return import_evidence(
        journal,
        project_id="product",
        actor_id="uploader",
        data=EvidenceInput(
            request_id=request_id,
            expected_evidence=current_evidence(journal, "product")[0],
            expected_versions=heads(journal),
            source=source,
            revision=revision,
            document=document or feed(),
        ),
    )


def inventory(journal, bom, *, version="1", build=1):
    receipt = import_inventory(
        journal,
        project_id="product",
        version=version,
        actor_id="pipeline",
        request_id=f"inventory-{version}-{build}",
        expected=heads(journal).get(version),
        source="pipeline",
        build_number=build,
        occurred_at=f"2026-10-{build:02d}T00:00:00Z",
        sbom=bom,
    )
    return receipt[1].updates[0].target


def facts(journal, version="1"):
    sections = load_sections(journal, heads(journal)[version])
    return [
        item
        for key, item in sections["vulnerabilities"].items()
        if key.startswith("external-evidence:")
    ]


def test_known_id_enrichment_keeps_original_base_zero_and_provider_facts_separate(journal, bom):
    initial = inventory(journal, bom)
    original = load_sections(journal, initial)
    add(journal)
    sections = load_sections(journal, heads(journal)["1"])
    claim = facts(journal)[0]
    assert claim["kind"] == "external-advisory"
    assert claim["identifier"] == "CVE-2099-20001" and claim["ref"] == "http"
    assert claim["advisory"]["ratings"][0]["score"] == 0
    assert claim["advisory"]["aliases"] == [{"id": "GHSA-not-matched"}]
    assert claim["advisory"]["normalized_status"] is None
    assert "analysis" not in claim["advisory"]
    assert claim["statement"]["raw"]["provider_entry"] == feed()["advisories"][0]
    assert claim["publisher"] == "Attributed provider" and claim["trust"] == "unverified"
    baseline = {
        key: value
        for key, value in sections["vulnerabilities"].items()
        if not key.startswith(("external-evidence:", "evidence-document:"))
    }
    assert baseline == original["vulnerabilities"]
    for section in ("inventory", "assessments", "reviews", "scoring"):
        assert sections[section] == original[section]
    row = load_workspace(journal, heads(journal)["1"])["items"][0]
    assert row["published_score"] is None
    assert {rating["score"] for rating in row["source_ratings"]} == {0, 9.8}
    assert len(row["sourcefacts"]) == 2
    assert not row["evidence"]
    assert journal.objects.read(digest(canonical(feed()))) == canonical(feed())


def test_feed_selected_before_inventory_unknown_alias_and_removed_baseline_do_not_create_findings(
    journal, bom
):
    add(journal)
    assert heads(journal) == {}
    inventory(journal, bom)
    assert len(facts(journal)) == 1
    add(journal, feed("GHSA-not-matched"), request_id="alias-feed", source="another-provider")
    assert len(facts(journal)) == 1
    changed = copy.deepcopy(bom)
    changed["vulnerabilities"] = []
    inventory(journal, changed, build=2)
    assert facts(journal) == []
    add(journal, feed(score=3), request_id="new-feed", revision=2)
    assert facts(journal) == []
    sections = load_sections(journal, heads(journal)["1"])
    assert reconcile_evidence(sections) == sections
    for record in sections["vulnerabilities"].values():
        if record.get("document", {}).get("format") == FORMAT and record.get("active"):
            assert record["application"]["matched"] == 0
            assert record["application"]["statements"][0]["unresolved"] == [
                "identifier_not_claimed_by_baseline"
            ]
    assert load_workspace(journal, heads(journal)["1"])["items"] == []


def test_multiple_publishers_contradictions_supersession_and_withdrawal_apply_atomically(
    journal, bom
):
    inventory(journal, bom)
    inventory(journal, bom, version="2")
    receipt = add(journal)
    assert len(receipt[1].updates) == 3
    add(journal, feed(score=10), source="independent-attribution", request_id="second")
    assert {item["advisory"]["ratings"][0]["score"] for item in facts(journal)} == {0, 10}
    revised = feed(score=2)
    add(journal, revised, request_id="revision", revision=2)
    for version in heads(journal):
        assert {item["advisory"]["ratings"][0]["score"] for item in facts(journal, version)} == {
            2,
            10,
        }
    receipt = withdraw_evidence(
        journal,
        project_id="product",
        actor_id="uploader",
        data=WithdrawalInput(
            request_id="withdraw",
            expected_evidence=current_evidence(journal, "product")[0],
            expected_versions=heads(journal),
            artifact_sha=digest(canonical(revised)),
            reason="Withdraw incorrect provider facts",
        ),
    )
    assert len(receipt[1].updates) == 3
    for version in heads(journal):
        assert [item["advisory"]["ratings"][0]["score"] for item in facts(journal, version)] == [10]


@pytest.mark.parametrize(
    "change", ["id", "publisher", "advisory_id", "alias", "rating", "references", "raw", "deep"]
)
def test_malformed_advisory_documents_fail_closed(change):
    document = feed()
    if change in {"id", "publisher"}:
        document[change] = "bad\nidentity"
    elif change == "advisory_id":
        document["advisories"][0]["advisory"]["id"] = "x" * 201
    elif change == "alias":
        document["advisories"][0]["advisory"]["aliases"] = [{"id": ""}]
    elif change == "rating":
        document["advisories"][0]["advisory"]["ratings"] = [{"score": True}]
    elif change == "references":
        document["advisories"][0]["advisory"]["references"] = ["not-an-object"]
    elif change == "raw":
        document["advisories"][0]["raw"] = []
    else:
        nested = document["advisories"][0]["raw"]
        for _ in range(70):
            nested["child"] = {}
            nested = nested["child"]
    with pytest.raises(ValueError):
        parse_evidence(canonical(document))


def test_feed_api_permissions_and_material_revalidation_preserve_human_pins(analyst, app):
    from conftest import login

    demo_response = analyst.post("/api/v3/playground/knowledge/seed", json={})
    assert demo_response.status_code == 200
    demo = demo_response.json()
    project = demo["project_id"]
    base = f"/api/v3/projects/{project}"
    workspace_url = f"{base}/versions/{demo['version']}/workspace"
    initial = analyst.get(workspace_url).json()
    approved = next(item for item in initial["items"] if item["coverage"]["status"] == "approved")
    document = feed(approved["vulnerability_id"])
    selected = analyst.get(base + "/evidence").json()
    body = {
        "request_id": "feed-http",
        "expected_evidence": selected["evidence_state"],
        "expected_versions": selected["versions"],
        "source": "provider",
        "revision": 1,
        "document": document,
    }
    login(analyst, "coordinator")
    assert analyst.get(base + "/evidence").status_code == 200
    assert analyst.post(base + "/evidence/imports", json=body).status_code == 404
    login(analyst, "analyst")
    result = analyst.post(base + "/evidence/imports", json=body)
    assert result.status_code == 201, result.text
    updated = analyst.get(workspace_url).json()
    row = next(item for item in updated["items"] if item["id"] == approved["id"])
    assert row["coverage"]["status"] == "reassessment_needed"
    assert row["coverage"]["assessment"] == approved["coverage"]["assessment"]
    assert row["coverage"]["review"] == approved["coverage"]["review"]
    assert row["published_score"] is None
    selected = analyst.get(base + "/evidence").json()
    result = analyst.post(
        base + "/evidence/withdrawals",
        json={
            "request_id": "withdraw-feed-http",
            "expected_evidence": selected["evidence_state"],
            "expected_versions": selected["versions"],
            "artifact_sha": digest(canonical(document)),
            "reason": "Incorrect provider advisory",
        },
    )
    assert result.status_code == 201, result.text
    restored = next(
        item for item in analyst.get(workspace_url).json()["items"] if item["id"] == approved["id"]
    )
    assert restored["coverage"]["status"] == "approved"
    assert restored["coverage"]["assessment"] == approved["coverage"]["assessment"]


def test_vex_only_identifier_cannot_seed_advisory_enrichment(journal, bom):
    from tests.test_knowledge_vex import openvex

    inventory(journal, bom)
    document = openvex(status="affected", product=bom["components"][0]["purl"])
    document["statements"][0]["vulnerability"]["name"] = "CVE-2099-NEW"
    add(journal, document, request_id="vex", source="vex-provider")
    add(journal, feed("CVE-2099-NEW"), source="advisory-provider")
    claims = facts(journal)
    assert len(claims) == 1
    assert claims[0]["kind"] == "external-status"
    assert claims[0]["identifier"] == "CVE-2099-NEW"


def test_nonfinite_raw_provider_values_are_rejected():
    raw = canonical(feed()).replace(b'"invented range"', b"NaN")
    with pytest.raises(ValueError, match="unambiguous"):
        parse_evidence(raw)
