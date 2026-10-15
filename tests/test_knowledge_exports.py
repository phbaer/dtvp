"""Immutable native exports preserve contextual evidence without approval claims."""

import copy
import json

import pytest

from dtvp.knowledge.exports import build_bundle, build_vscorer_worklist, export_bytes
from dtvp.knowledge.journal import CorruptJournal, Ref, Update
from dtvp.knowledge.ownership import resolve_ownership
from dtvp.knowledge.workspace import load_sections
from dtvp.rescoring import base_fact
from dtvp.storage import canonical, digest
from tests.test_knowledge_workspace import snapshot, source
from tests.test_knowledge_workspace import workspace as source_workspace
from tests.test_rescoring import BASE, VECTOR

workspace = source_workspace


def test_deterministic_complete_bundle_preserves_inventory_claims_and_contexts(workspace):
    journal, sections = workspace
    component = sections["inventory"]["component:shared"]
    component.update(
        licenses=[{"license": {"id": "MIT"}}],
        hashes=[{"alg": "SHA-256", "content": "a" * 64}],
        cpe="cpe:2.3:a:example:shared:1:*:*:*:*:*:*:*",
    )
    sections["inventory"]["extra-source-metadata"] = {"unmapped": "Preserve original metadata"}
    journal, state = snapshot(workspace)
    raw, manifest = export_bytes(journal, state)
    assert export_bytes(journal, state) == (raw, manifest)
    bundle = json.loads(raw)
    assert bundle == build_bundle(journal, state)
    assert bundle["format"] == "dtvp.knowledge-bundle/1"
    assert manifest["format"] == "dtvp.knowledge-export/1"
    assert manifest["state"] == state
    assert manifest["bundle_sha256"] == digest(raw)
    assert manifest["bundle_bytes"] == len(raw)
    assert manifest["section_hashes"] == journal.state(state).sections
    assert manifest["integrity"] == "content_digest_only_not_authenticity_or_approval"
    assert bundle["inventory"]["dependencies"] == sections["inventory"]["dependencies"]
    assert bundle["inventory"]["relationships"] == sections["inventory"].get(
        "relationships", {"items": []}
    )
    assert component in bundle["inventory"]["components"]
    assert bundle["inventory"]["other_records"]["extra-source-metadata"] == {
        "unmapped": "Preserve original metadata"
    }
    shared = [
        finding for finding in bundle["findings"] if finding["component"]["bom-ref"] == "shared"
    ]
    assert len(shared) == 2
    assert len({finding["context_id"] for finding in shared}) == 2
    assert all(len(finding["sourcefacts"]) == 2 for finding in shared)
    assert all(not finding["coverage"]["approved"] for finding in bundle["findings"])
    assert all(finding["published_score"] is None for finding in bundle["findings"])


def test_bundle_remains_pinned_when_current_branch_policy_changes(workspace):
    journal, old = snapshot(workspace)
    journal.publish(
        request_id="initial",
        fingerprint=digest(b"initial"),
        updates=[Update(ref=Ref(project_id="product", name="1"), expected=None, target=old)],
    )
    previous = export_bytes(journal, old)
    changed = load_sections(journal, old)
    resolve_ownership(
        changed,
        version="1",
        config={
            "rules": [{"selector": "*", "team_id": "New team"}],
            "context_roots": {"1": ["app-a", "app-b"]},
        },
    )
    current = journal.snapshot(
        project_id="product",
        version="1",
        actor_id="manager",
        reason="Reassign",
        parents=[old],
        sections=changed,
    )
    journal.publish(
        request_id="reassign",
        fingerprint=digest(b"reassign"),
        updates=[Update(ref=Ref(project_id="product", name="1"), expected=old, target=current)],
    )
    assert export_bytes(journal, old) == previous
    assert export_bytes(journal, current)[0] != previous[0]
    assert {row["context"]["team_id"] for row in build_bundle(journal, old)["findings"]} == {
        "A",
        "B",
    }


def test_unknown_ownership_uncontextualized_claims_and_absent_assessments_are_explicit(workspace):
    journal, sections = workspace
    sections["vulnerabilities"]["unlinked"] = source(
        "missing", "CVE-unlinked", 10, "No graph context"
    )
    sections["assessments"]["assessment:old"] = {
        "revision": "f" * 64,
        "payload": {
            "targets": [{"version": "1", "context_id": "a" * 64, "vulnerability_id": "CVE-removed"}]
        },
    }
    for context in sections["ownership"].values():
        if context.get("id"):
            context.update(
                team_id=None, candidate_teams=[], team_scope={}, status="topology_unknown"
            )
    journal, state = snapshot(workspace)
    bundle = build_bundle(journal, state)
    assert bundle["uncontextualized_source_findings"][0]["identifier"] == "CVE-unlinked"
    assert len(bundle["source_observations"]) == 4
    assert bundle["retained_assessments"] == sections["assessments"]
    assert bundle["retained_absent_assessments"][0]["record_id"] == "assessment:old"
    assert not any(finding["vulnerability_id"] == "CVE-removed" for finding in bundle["findings"])
    assert all(finding["context"]["status"] == "topology_unknown" for finding in bundle["findings"])
    assert all(not finding["coverage"]["approved"] for finding in bundle["findings"])


def test_export_has_every_finding_beyond_presentation_page_limit(workspace):
    sections = workspace[1]
    for index in range(205):
        sections["vulnerabilities"][f"large-{index}"] = source(
            "shared", f"CVE-large-{index:04}", 5, "Large inventory"
        )
    journal, state = snapshot(workspace)
    bundle = build_bundle(journal, state)
    assert len(bundle["findings"]) == 413
    assert bundle["statistics"]["totals"]["context_findings"] == 413
    assert len(build_vscorer_worklist(journal, state)["items"]) == 413


def test_original_artifact_manifest_verifies_exact_bytes_and_corruption(workspace):
    journal, sections = workspace
    original = b'{  "producer-original": true }\n'
    sha = journal.objects.put(original)
    sections["inventory"]["baseline"].update(
        artifact_sha=sha, representation="original_bytes", normalizer="dtvp.composition/1"
    )
    journal, state = snapshot(workspace)
    _, manifest = export_bytes(journal, state)
    assert manifest["source_artifacts"] == [{"sha256": sha, "representation": "original_bytes"}]
    assert manifest["normalizers"]["product"] == "dtvp.composition/1"
    journal.objects.path(sha).write_bytes(b"corrupted")
    with pytest.raises(ValueError):
        export_bytes(journal, state)


def test_corrupt_section_fails_closed_before_export(workspace):
    journal, state = snapshot(workspace)
    record = next(iter(journal.records(state, "vulnerabilities").values()))
    journal.objects.path(record).write_bytes(b"corrupted")
    with pytest.raises(CorruptJournal):
        build_bundle(journal, state)


def test_native_vscorer_worklist_retains_context_and_competing_base_assertions(workspace):
    journal, sections = workspace
    alternate = BASE.replace("AV:N", "AV:P")
    sections["vulnerabilities"]["one"]["advisory"]["ratings"] = [
        {"score": 9.8, "vector": BASE, "method": "CVSSv31"},
        {"score": 0.0, "vector": VECTOR, "method": "CVSSv31"},
    ]
    sections["vulnerabilities"]["two"]["advisory"]["ratings"] = [
        {"vector": alternate, "score": base_fact(alternate)["score"]}
    ]
    journal, state = snapshot(workspace)
    result = build_vscorer_worklist(journal, state)
    assert result["format"] == "dtvp.knowledge-vscorer-worklist/1"
    assert result["state"] == state
    assert "cves" not in result
    shared = [item for item in result["items"] if item["component_ref"] == "shared"]
    assert len(shared) == 2
    assert len({item["finding_id"] for item in shared}) == 2
    for item in shared:
        assert item["base_selection"] == "required"
        assert {assertion["base"]["vector"] for assertion in item["source_base_assertions"]} == {
            BASE,
            alternate,
        }
        assert len(item["source_ratings"]) == 3
        assert item["published_contextual_score"] is None
        assert item["environmental_proposals"] == []
        assert all(assertion["vscorer_supported"] for assertion in item["source_base_assertions"])
    assert any("adapter" in text for text in result["limitations"])


def test_assembly_source_states_and_missing_parts_remain_pinned(workspace):
    journal, sections = workspace
    raw = canonical({"exact": "part"})
    sha = journal.objects.put(raw)
    source_sections = copy.deepcopy(sections)
    source_sections["inventory"]["baseline"].update(
        artifact_sha=sha, representation="canonical_json", normalizer="dtvp.composition/1"
    )
    source_state = journal.snapshot(
        project_id="product",
        version="1",
        actor_id="pipeline",
        reason="Part import",
        sections=source_sections,
        artifacts=[sha],
    )
    sections["inventory"]["assembly"] = {
        "parts": [
            {
                "part_id": "runtime",
                "state": source_state,
                "availability": "selected",
                "required": True,
                "baseline": source_sections["inventory"]["baseline"],
            },
            {"part_id": "firmware", "state": None, "availability": "missing", "required": True},
        ]
    }
    sections["inventory"]["baseline"] = {"kind": "assembly", "readiness": "incomplete"}
    journal, state = snapshot(workspace)
    raw, manifest = export_bytes(journal, state)
    assert manifest["source_states"] == [{"part_id": "runtime", "state": source_state}]
    assert manifest["source_artifacts"][0]["sha256"] == sha
    assert manifest["source_artifacts"][0]["parts"][0]["state"] == source_state
    assert manifest["normalizers"]["parts"] == {"runtime": "dtvp.composition/1", "firmware": None}
    bundle = json.loads(raw)
    assert bundle["inventory"]["assembly"]["parts"][1]["availability"] == "missing"
    assert bundle["inventory"]["baseline"]["readiness"] == "incomplete"
