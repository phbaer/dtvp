"""Cross-part topology is explicit, pinned and never occurrence identity deduplication."""

import copy

import pytest

from dtvp.api_assembly_editor import preview_candidate
from dtvp.knowledge.assembly import (
    AssemblyInput,
    assembly_request_identity,
    build_assembly_candidate,
    namespaced_ref,
    publish_assembly,
)
from dtvp.knowledge.journal import Conflict
from dtvp.knowledge.workspace import load_sections
from dtvp.storage import canonical, digest
from tests.test_knowledge_assembly_candidate import journal as source_journal
from tests.test_knowledge_assembly_candidate import part

journal = source_journal


def payload(a, b, **changes):
    return {
        "request_id": "linked-assembly",
        "expected": None,
        "parts": [
            {"part_id": "application", "state": a, "required": True},
            {"part_id": "container", "state": b, "required": True},
        ],
        "cross_part_relationships": [
            {
                "relationship_id": "application-container",
                "kind": "DEPENDS_ON",
                "from": {"part_id": "application", "state": a, "ref": "gateway"},
                "to": {"part_id": "container", "state": b, "ref": "gateway"},
                "rationale": "Integration manifest explicitly links these exact delivery parts",
            }
        ],
        **changes,
    }


def build(journal, value):
    return build_assembly_candidate(
        journal, project_id="product", version="1", data=AssemblyInput.model_validate(value)
    )


def publish(journal, value):
    return publish_assembly(
        journal,
        project_id="product",
        version="1",
        actor_id="editor",
        data=AssemblyInput.model_validate(value),
    )


def sources(journal, bom):
    return part(journal, bom), part(journal, bom, "container")


def test_explicit_dependency_keeps_roots_occurrences_originals_and_adds_context(journal, bom):
    a, b = sources(journal, bom)
    value = payload(a, b)
    before = journal.head(), set(journal.objects.root.rglob("*"))
    preview = preview_candidate(journal, "product", "1", AssemblyInput.model_validate(value))
    assert before == (journal.head(), set(journal.objects.root.rglob("*")))
    assert preview["relationship_diagnostics"]["identity_merges"] == 0
    assert preview["relationship_diagnostics"]["preserved_part_roots"] == 2
    receipt = publish(journal, value)
    state = receipt[1].updates[0].target
    sections = load_sections(journal, state)
    inventory = sections["inventory"]
    assert inventory["assembly"]["cross_part_relationships"] == value["cross_part_relationships"]
    roots = [item for key, item in inventory.items() if key.startswith("part-root:")]
    assert {item["bom-ref"] for item in roots} == {
        namespaced_ref("application", "gateway"),
        namespaced_ref("container", "gateway"),
    }
    explicit = [
        item
        for item in inventory["relationships"]["items"]
        if item.get("origin") == "dtvp.assembly-explicit/1"
    ]
    assert (
        len(explicit) == 1
        and explicit[0]["from_origin"] == value["cross_part_relationships"][0]["from"]
    )
    edges = inventory["dependencies"]["edges"]
    assert any(
        item["ref"] == namespaced_ref("application", "gateway")
        and namespaced_ref("container", "gateway") in item["dependsOn"]
        for item in edges
    )
    contexts = [
        item
        for key, item in sections["ownership"].items()
        if key.startswith("context:")
        and item["component_ref"] == namespaced_ref("container", "http")
    ]
    assert {item["root_ref"] for item in contexts} == {
        namespaced_ref("application", "gateway"),
        namespaced_ref("container", "gateway"),
    }
    assert all(not sections[key] for key in ("assessments", "reviews", "scoring"))
    assert a in journal.state(state).parents and b in journal.state(state).parents
    for source in (a, b):
        for artifact in journal.state(source).artifacts:
            assert artifact in journal.state(state).artifacts


def test_contains_is_typed_relationship_without_dependency_or_ownership_inference(journal, bom):
    a, b = sources(journal, bom)
    base = build(journal, payload(a, b, cross_part_relationships=[]))
    value = payload(a, b)
    value["cross_part_relationships"][0]["kind"] = "CONTAINS"
    linked = build(journal, value)
    assert (
        linked["sections"]["inventory"]["dependencies"]
        == base["sections"]["inventory"]["dependencies"]
    )
    assert linked["relationship_diagnostics"]["containment_relations"] == 1
    assert linked["relationship_diagnostics"]["dependency_relations"] == 0


@pytest.mark.parametrize(
    "change",
    [
        "missing_part",
        "missing_ref",
        "stale_pin",
        "same_part",
        "duplicate_id",
        "duplicate_edge",
        "blank_reason",
        "unknown_kind",
    ],
)
def test_unresolvable_or_ambiguous_declarations_fail_before_writes(journal, bom, change):
    a, b = sources(journal, bom)
    value = payload(a, b)
    item = value["cross_part_relationships"][0]
    if change == "missing_part":
        item["to"]["part_id"] = "not-selected"
    elif change == "missing_ref":
        item["to"]["ref"] = "pkg:generic/no-name-or-purl-fallback"
    elif change == "stale_pin":
        item["to"]["state"] = a
    elif change == "same_part":
        item["to"] = copy.deepcopy(item["from"])
    elif change in {"duplicate_id", "duplicate_edge"}:
        other = copy.deepcopy(item)
        if change == "duplicate_edge":
            other["relationship_id"] = "other-id"
        value["cross_part_relationships"].append(other)
    elif change == "blank_reason":
        item["rationale"] = " \t "
    else:
        item["kind"] = "IDENTICAL_TO"
    before = journal.head(), set(journal.objects.root.rglob("*"))
    with pytest.raises(ValueError):
        build(journal, value)
    assert before == (journal.head(), set(journal.objects.root.rglob("*")))


def test_historical_selected_pin_stays_exact_and_changed_selection_needs_new_endpoint_pin(
    journal, bom
):
    a, b = sources(journal, bom)
    value = payload(a, b)
    previous = build(journal, value)
    newer = part(journal, bom, "container", expected=b, build=2)
    assert build(journal, value) == previous
    value["parts"][1]["state"] = newer
    with pytest.raises(ValueError, match="exact selected"):
        build(journal, value)


def test_old_clients_cannot_implicitly_remove_cross_part_topology_and_receipt_replay_survives_advance(
    journal, bom
):
    a, b = sources(journal, bom)
    value = payload(a, b)
    first = publish(journal, value)
    state = first[1].updates[0].target
    old_client = payload(a, b, request_id="old-client", expected=state)
    old_client.pop("cross_part_relationships")
    with pytest.raises(Conflict, match="explicit reason"):
        build(journal, old_client)
    old_client["relationship_change_reason"] = (
        "Integration relation removed after explicit source review"
    )
    second = publish(journal, old_client)
    assert second[1].updates[0].target != state
    assert publish(journal, value) == first
    assert not load_sections(journal, second[1].updates[0].target)["inventory"]["assembly"][
        "cross_part_relationships"
    ]


def test_omitted_new_fields_preserve_existing_request_identity(journal, bom):
    a, b = sources(journal, bom)
    value = payload(a, b, cross_part_relationships=[])
    data = AssemblyInput.model_validate(value)
    old_payload = data.model_dump(
        mode="json", exclude={"cross_part_relationships", "relationship_change_reason"}
    )
    expected = digest(
        canonical(
            {
                "operation": "assembly.select/1",
                "project_id": "product",
                "version": "1",
                "actor_id": "editor",
                **old_payload,
            }
        )
    )
    assert assembly_request_identity("product", "1", "editor", data)[1] == expected
    preview = preview_candidate(journal, "product", "1", data)
    assert "cross_part_relationships" not in preview["input"]
    assert "relationship_diagnostics" not in preview
    assert (
        "cross_part_relationships" not in build(journal, value)["sections"]["inventory"]["assembly"]
    )
