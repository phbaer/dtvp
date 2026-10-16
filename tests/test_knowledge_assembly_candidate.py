"""Structural assembly previews share validation without persisting candidate objects."""

import pytest

from dtvp.api_assembly_editor import preview_candidate
from dtvp.knowledge.assembly import AssemblyInput, build_assembly_candidate, publish_assembly
from dtvp.knowledge.journal import Conflict, Journal
from dtvp.knowledge.service import import_inventory
from dtvp.knowledge.workspace import load_sections


@pytest.fixture
def journal(tmp_path):
    return Journal(tmp_path / "journal")


def part(journal, bom, part_id="application", *, expected=None, build=1, version="1"):
    return (
        import_inventory(
            journal,
            project_id="product",
            version=version,
            actor_id="pipeline",
            request_id=f"part-{part_id}-{build}",
            expected=expected,
            source="CI:" + part_id,
            build_number=build,
            occurred_at="2026-10-16T10:00:00Z",
            sbom=bom,
            part_id=part_id,
        )[1]
        .updates[0]
        .target
    )


def data(state, **changes):
    return AssemblyInput(
        **(
            {
                "request_id": "assembly-1",
                "expected": None,
                "parts": [{"part_id": "application", "state": state, "required": True}],
            }
            | changes
        )
    )


def publish(journal, value):
    return publish_assembly(
        journal, project_id="product", version="1", actor_id="editor", data=value
    )


def test_candidate_and_preview_are_read_only_and_share_published_structural_content(journal, bom):
    source = part(journal, bom)
    value = data(source)
    before = journal.references(), journal.head(), set(journal.objects.root.glob("*/*"))
    candidate = build_assembly_candidate(journal, project_id="product", version="1", data=value)
    preview = preview_candidate(journal, "product", "1", value)
    assert (journal.references(), journal.head(), set(journal.objects.root.glob("*/*"))) == before
    assert preview["readiness"] == "unverified"
    assert preview["counts"]["component_occurrences"] == len(bom["components"]) + 1
    assert preview["counts"]["source_findings"] == len(bom["vulnerabilities"])
    assert candidate["sections"]["ownership"] == {}
    receipt = publish(journal, value)
    current = load_sections(journal, receipt[1].updates[0].target)
    assert current["inventory"] == candidate["sections"]["inventory"]
    assert current["vulnerabilities"] == candidate["sections"]["vulnerabilities"]
    assert current["assessments"] == current["reviews"] == current["scoring"] == {}


def test_historical_part_pin_does_not_repin_when_source_head_advances(journal, bom):
    old = part(journal, bom)
    value = data(old)
    preview = preview_candidate(journal, "product", "1", value)
    newer = part(journal, bom, expected=old, build=2)
    assert newer != old
    assert preview_candidate(journal, "product", "1", value) == preview
    receipt = publish(journal, value)
    manifest = load_sections(journal, receipt[1].updates[0].target)["inventory"]["assembly"]
    assert manifest["parts"][0]["state"] == old


def test_omitted_withdrawn_and_requirement_changes_require_exact_reasons(journal, bom):
    source = part(journal, bom)
    state = publish(journal, data(source))[1].updates[0].target
    missing = data(None, expected=state, request_id="missing")
    with pytest.raises(Conflict, match="withdrawn_parts"):
        build_assembly_candidate(journal, project_id="product", version="1", data=missing)
    value = missing.model_copy(
        update={"withdrawn_parts": ["application"], "withdrawal_reason": "Source input unavailable"}
    )
    assert preview_candidate(journal, "product", "1", value)["readiness"] == "incomplete"
    relaxed = data(
        source,
        expected=state,
        parts=[{"part_id": "application", "state": source, "required": False}],
    )
    with pytest.raises(Conflict, match="policy change"):
        build_assembly_candidate(journal, project_id="product", version="1", data=relaxed)
