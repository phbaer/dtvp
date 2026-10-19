"""Compact contribution rows expose exact scoped facts, not inferred approvals."""

import copy

from dtvp.knowledge.contributions import (
    analysis_entries,
    contributions,
    mark_references,
    source_entries,
)
from dtvp.knowledge.cpe import DiscoveryInput, import_discovery_policy
from dtvp.knowledge.vex import parse_evidence
from dtvp.knowledge.workspace import load_workspace
from dtvp.storage import canonical
from tests.test_knowledge_workspace import snapshot
from tests.test_knowledge_workspace import workspace as source_workspace

workspace = source_workspace


def cdx_claim(purl=None):
    component = {"bom-ref": "shared", "name": "shared", **({"purl": purl} if purl else {})}
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "serialNumber": "urn:uuid:contributions",
        "metadata": {"supplier": {"name": "Supplier VEX"}},
        "components": [component],
        "vulnerabilities": [
            {
                "id": "CVE-1",
                "affects": [{"ref": "shared"}],
                "analysis": {
                    "state": "not_affected",
                    "justification": "code_not_reachable",
                    "detail": "Producer-declared unreachable code",
                },
            }
        ],
    }


def selected(workspace):
    journal, state = snapshot(workspace)
    row = next(
        item
        for item in load_workspace(journal, state)["items"]
        if item["vulnerability_id"] == "CVE-1"
    )
    return journal, state, row


def test_source_facts_keep_attribution_and_compact_contribution_content(workspace):
    journal, state, row = selected(workspace)
    before = journal.head()
    result = contributions(journal, state, row)
    sources = result["vulnerability_sources"]
    assert {item["provider"] for item in sources} == {"DT", "supplier"}
    nvd = next(item for item in sources if item["provider"] == "DT")
    assert nvd["ratings"][0]["source"]["name"] == "NVD"
    assert "9.8" in nvd["summary"] and nvd["claims"]["description"] == "Upstream description"
    assert "Upstream description" not in nvd["summary"]
    assert nvd["claims"]["contributes"] == ["description", "ratings"]
    assert nvd["provenance"]["observation_id"] == "one"
    assert nvd["status"] == "current" and nvd["current"]
    assert nvd["adoption"]["status"] == "not_recorded" and not nvd["adoption"]["published_score"]
    assert result["scope"]["state"] == state and journal.head() == before
    assert result["cpe"]["accepted"] == []
    assert result["cpe"]["diagnostics"]


def test_retrieved_no_match_and_inactive_scope_diagnostics_never_leak_other_packages(workspace):
    _, sections = workspace
    _, _, row = selected(workspace)
    component = sections["inventory"]["component:shared"]
    sections = copy.deepcopy(sections)
    sections["vulnerabilities"].update(
        {
            "evidence-document:lookup": {
                "artifact_sha": "lookup",
                "active": True,
                "source": "connector:nvd",
                "document": {
                    "publisher": "NVD",
                    "raw": {
                        "refresh": {
                            "capture_sha256": "capture",
                            "lookups": [
                                {
                                    "identifier": "CVE-1",
                                    "status": "not_found",
                                    "response_sha256": "response",
                                },
                                {
                                    "identifier": "OTHER-CVE",
                                    "status": "found",
                                    "response_sha256": "other",
                                },
                            ],
                        }
                    },
                    "statements": [],
                },
            },
            "evidence-document:empty": {
                "artifact_sha": "empty",
                "active": True,
                "source": "connector:osv",
                "document": {
                    "publisher": "OSV",
                    "matching_coverage": {
                        "purl": component["purl"],
                        "status": "no_matches_reported",
                    },
                    "statements": [],
                },
            },
            "evidence-document:unrelated": {
                "artifact_sha": "unrelated",
                "active": True,
                "document": {
                    "publisher": "Unrelated",
                    "matching_coverage": {
                        "purl": "pkg:generic/other@1",
                        "status": "no_matches_reported",
                    },
                    "statements": [
                        {
                            "vulnerability_id": "CVE-1",
                            "source_refs": [
                                {
                                    "ref": "other",
                                    "component": {"purl": "pkg:generic/other@1"},
                                    "unresolved_reasons": [],
                                }
                            ],
                            "status": "affected",
                        }
                    ],
                },
            },
            "evidence-document:old-vex": {
                "artifact_sha": "old",
                "active": False,
                "document": parse_evidence(canonical(cdx_claim(component["purl"]))),
            },
        }
    )
    result = source_entries(sections, row, component)
    assert not any(item["provider"] == "Unrelated" for item in result)
    lookup = next(item for item in result if item["kind"] == "advisory_lookup")
    assert lookup["status"] == "not_found" and lookup["provenance"]["response_sha256"] == "response"
    assert any(item["status"] == "no_matches_reported" for item in result)
    vex = next(item for item in result if item["provider"] == "Supplier VEX")
    assert vex["status"] == "inactive" and not vex["current"]
    assert all(not item["adoption"]["published_score"] for item in result)


def test_analyses_withheld_stale_and_equal_scores_do_not_establish_use():
    proposal = {
        "id": "vscorer-result",
        "provider": "vscorer",
        "source_label": "Threat model",
        "current": True,
        "eligible": True,
        "target": {"context_id": "ctx", "vulnerability_id": "CVE-1"},
        "proposal": {"score": 0.0, "base_score": 9.8, "vector": "same", "base_vector": "base"},
        "report_sha256": "report",
        "receipt_sha256": "receipt",
        "ineligibility_reasons": [],
    }
    row = {
        "context_id": "ctx",
        "vulnerability_id": "CVE-1",
        "published_score": {"score": 0, "vector": "same"},
        "scoring_proposals": [
            proposal,
            {
                **proposal,
                "id": "old",
                "current": False,
                "eligible": False,
                "ineligibility_reasons": ["source_evidence_changed"],
            },
            {
                **proposal,
                "id": "foreign",
                "target": {"context_id": "other", "vulnerability_id": "CVE-1"},
            },
        ],
        "code_analysis": [
            {
                "id": "agent",
                "provider": "agentyzer",
                "current": True,
                "application_eligible": False,
                "rescoring_eligible": False,
                "summary": "Checkout proof missing",
                "verdict": "inconclusive",
                "source_proof": {"consistency_only": True},
                "report_sha256": "agent-report",
                "ineligibility_reasons": ["source_commit_unknown"],
            }
        ],
        "coverage": {
            "assessment": {
                "revision": "revision",
                "payload": {"evidence": [{"report_sha256": "report"}]},
            }
        },
    }
    results = analysis_entries(row)
    assert len(results) == 3 and not any(item["id"] == "foreign" for item in results)
    assert {item["status"] for item in results} == {"eligible", "stale", "withheld"}
    assert all(item["adoption"]["status"] == "not_recorded" for item in results)
    mark_references(results, row)
    cited = next(item for item in results if item["id"] == "vscorer-result")
    assert cited["adoption"]["status"] == "referenced"
    assert cited["adoption"]["assessment_revisions"] == ["revision"]
    assert not cited["adoption"]["published_score"]
    assert next(item for item in results if item["id"] == "agent")["diagnostics"] == [
        "source_commit_unknown"
    ]
    row["scoring_proposals"].append({**proposal, "id": "agent", "provider": "agentyzer"})
    combined = analysis_entries(row)
    assert len(combined) == 3
    assert sum(item["id"] == "agent" for item in combined) == 1


def test_cpe_declared_configured_and_ranked_remain_separate_from_acceptance(workspace):
    journal, sections = workspace
    cpe = "cpe:2.3:a:acme:shared:1:*:*:*:*:*:*:*"
    sections["inventory"]["component:shared"]["cpe"] = cpe
    journal, state, row = selected(workspace)
    import_discovery_policy(
        journal,
        project_id="product",
        actor_id="manager",
        data=DiscoveryInput(
            request_id="configure",
            expected=None,
            catalog=[],
            rules={
                "pkg:generic/acme/shared": {
                    "cpe": cpe,
                    "status": "internal",
                    "source": "Reviewed mapping",
                    "reason": "Declared package mapping",
                }
            },
        ),
    )
    result = contributions(journal, state, row)["cpe"]
    assert result["declared"][0]["summary"] == cpe
    assert result["curated"][0]["status"] == "curated_mapping"
    assert result["candidates"][0]["summary"] == cpe
    assert (
        result["candidates"][0]["provenance"]["policy_relation"]
        == "current_project_policy_not_inventory_pin"
    )
    assert result["accepted"] == []


def test_selected_snapshot_preserves_prior_source_content(workspace):
    journal, state, row = selected(workspace)
    workspace[1]["vulnerabilities"]["one"]["advisory"]["description"] = "A later source description"
    _, newer = snapshot(workspace)
    updated = next(
        item for item in load_workspace(journal, newer)["items"] if item["id"] == row["id"]
    )
    original = contributions(journal, state, row)
    current = contributions(journal, newer, updated)
    assert original["vulnerability_sources"][0]["claims"]["description"] == "Upstream description"
    assert (
        current["vulnerability_sources"][0]["claims"]["description"] == "A later source description"
    )
    assert original["scope"]["state"] != current["scope"]["state"]


def test_actual_cdx_import_and_withdrawal_retain_scoped_history(workspace):
    from dtvp.knowledge.evidence import (
        EvidenceInput,
        WithdrawalInput,
        current_evidence,
        import_evidence,
        withdraw_evidence,
    )
    from dtvp.knowledge.journal import Ref, Update
    from dtvp.storage import digest

    journal, state, row = selected(workspace)
    ref = Ref(project_id="product", name="1")
    journal.publish(
        request_id="seed",
        fingerprint=digest(b"seed"),
        updates=[Update(ref=ref, expected=None, target=state)],
    )
    document = cdx_claim("pkg:generic/acme/shared@1")
    import_evidence(
        journal,
        project_id="product",
        actor_id="importer",
        data=EvidenceInput(
            request_id="import-vex",
            expected_evidence=None,
            expected_versions={"1": state},
            source="Supplier VEX",
            revision=1,
            document=document,
        ),
    )
    active = journal.resolve(ref)
    current_row = next(
        item for item in load_workspace(journal, active)["items"] if item["id"] == row["id"]
    )
    assert any(
        item["kind"] == "vex"
        for item in contributions(journal, active, current_row)["vulnerability_sources"]
    )
    evidence_state, records = current_evidence(journal, "product")
    artifact = next(iter(records.values()))["artifact_sha"]
    withdraw_evidence(
        journal,
        project_id="product",
        actor_id="manager",
        data=WithdrawalInput(
            request_id="withdraw-vex",
            expected_evidence=evidence_state,
            expected_versions={"1": active},
            artifact_sha=artifact,
            reason="Retain original history but stop applying claim",
        ),
    )
    withdrawn = journal.resolve(ref)
    withdrawn_row = next(
        item for item in load_workspace(journal, withdrawn)["items"] if item["id"] == row["id"]
    )
    report = contributions(journal, withdrawn, withdrawn_row)
    inactive = next(
        item for item in report["vulnerability_sources"] if item["kind"] == "document_statement"
    )
    assert (
        inactive["status"] == "inactive" and inactive["provenance"]["artifact_sha256"] == artifact
    )
    assert not inactive["adoption"]["published_score"]
    assert any(
        item["kind"] == "vex"
        for item in contributions(journal, active, current_row)["vulnerability_sources"]
    )


def test_real_cdx_bare_refs_and_equivalent_openvex_purls_keep_scope_boundaries(workspace):
    journal, sections = workspace
    _, _, row = selected(workspace)
    component = sections["inventory"]["component:shared"]
    bare = parse_evidence(canonical(cdx_claim()))
    sections = copy.deepcopy(sections)
    sections["vulnerabilities"]["evidence-document:bare"] = {
        "artifact_sha": "different-document",
        "active": False,
        "document": bare,
    }
    assert not any(
        item["kind"] == "document_statement" for item in source_entries(sections, row, component)
    )
    sections["inventory"]["baseline"]["artifact_sha"] = "different-document"
    assert any(
        item["kind"] == "document_statement" for item in source_entries(sections, row, component)
    )
    from tests.test_knowledge_vex import openvex

    component["purl"] = "pkg:generic/acme/shared@1?os=linux&arch=amd64"
    document = openvex(product="pkg:generic/acme/shared@1?arch=amd64&os=linux")
    document["statements"][0]["vulnerability"]["name"] = "CVE-1"
    sections["vulnerabilities"]["evidence-document:openvex"] = {
        "artifact_sha": "different-openvex",
        "active": False,
        "document": parse_evidence(canonical(document)),
    }
    result = source_entries(sections, row, component)
    assert any(item["provenance"].get("artifact_sha256") == "different-openvex" for item in result)
