"""Implicit heads preserve exact receipts and ordinary import constraints."""

import copy
import json

import pytest

from dtvp.api_knowledge import InventoryMetadata
from dtvp.knowledge.journal import Conflict, Journal, Ref
from dtvp.knowledge.service import import_inventory, part_ref
from dtvp.storage import canonical, digest


def metadata(**changes):
    return {
        "request_id": "build-1",
        "source": "pipeline/main",
        "build_number": 1,
        "occurred_at": "2026-10-15T01:00:00+00:00",
        "completeness": "complete",
        **changes,
    }


def fields(**changes):
    return {
        "project_id": "product",
        "version": "1",
        "actor_id": "pipeline",
        **{key: value for key, value in metadata().items() if key != "completeness"},
        **changes,
    }


def test_metadata_defaults_to_current_and_retains_explicit_null_and_sha():
    assert InventoryMetadata(**metadata()).expected == "current"
    assert InventoryMetadata(**metadata(expected="current")).expected == "current"
    assert InventoryMetadata(**metadata(expected=None)).expected is None
    assert InventoryMetadata(**metadata(expected="a" * 64)).expected == "a" * 64


@pytest.mark.parametrize("part_id", [None, "application"])
@pytest.mark.parametrize("original_bytes", [False, True])
def test_auto_import_replaces_baseline_and_replays_original_receipt(
    tmp_path, bom, part_id, original_bytes
):
    journal = Journal(tmp_path / "journal")
    ref = part_ref("product", "1", part_id) if part_id else Ref(project_id="product", name="1")

    def payload(document):
        return (
            {"raw": json.dumps(document, indent=2).encode()}
            if original_bytes
            else {"sbom": document}
        )

    first_fields = fields(part_id=part_id, **payload(bom))
    first_receipt = import_inventory(journal, **first_fields)
    first = first_receipt[1].updates[0].target
    assert journal.resolve(ref) == first
    assert first_receipt[1].updates[0].expected is None
    modified = copy.deepcopy(bom)
    removed = modified["components"].pop()["bom-ref"]
    modified["dependencies"] = [edge for edge in modified["dependencies"] if edge["ref"] != removed]
    for edge in modified["dependencies"]:
        edge["dependsOn"] = [child for child in edge.get("dependsOn", []) if child != removed]
    second_receipt = import_inventory(
        journal,
        **fields(part_id=part_id, request_id="build-2", build_number=2, **payload(modified)),
    )
    second = second_receipt[1].updates[0].target
    assert second_receipt[1].updates[0].expected == first
    assert journal.resolve(ref) == second
    assert "component:ref:" + removed not in journal.records(second, "inventory")
    assert import_inventory(journal, **first_fields) == first_receipt
    assert journal.resolve(ref) == second
    changed_payload = {"raw": first_fields["raw"] + b"\n"} if original_bytes else payload(modified)
    with pytest.raises(Conflict, match="request|Request"):
        import_inventory(journal, **(first_fields | changed_payload))


def test_auto_import_retains_explicit_cas_build_source_and_scope_constraints(tmp_path, bom):
    journal = Journal(tmp_path / "journal")
    base = fields(sbom=bom)
    first = import_inventory(journal, **base)[1].updates[0].target
    second = (
        import_inventory(journal, **(base | {"request_id": "build-2", "build_number": 2}))[1]
        .updates[0]
        .target
    )
    for expected in (None, first):
        with pytest.raises(Conflict, match="Branch changed"):
            import_inventory(
                journal,
                **(base | {"request_id": "explicit", "build_number": 3, "expected": expected}),
            )
    for changes, message in [
        ({"build_number": 1}, "not newer"),
        ({"build_number": 2}, "not newer"),
        ({"build_number": 3, "source": "other"}, "authority"),
        ({"build_number": 3, "context": {"target": "other"}}, "scope"),
    ]:
        with pytest.raises(Conflict, match=message):
            import_inventory(journal, **(base | {"request_id": "rejected"} | changes))
    assert journal.resolve(Ref(project_id="product", name="1")) == second
    accepted = import_inventory(
        journal,
        **(base | {"request_id": "build-3", "build_number": 3, "expected": second}),
    )
    assert accepted[1].updates[0].expected == second


@pytest.mark.parametrize("original_bytes", [False, True])
def test_explicit_head_fingerprints_remain_compatible(tmp_path, bom, original_bytes):
    journal = Journal(tmp_path / "journal")
    raw = json.dumps(bom, indent=2).encode()
    base = fields(**({"raw": raw} if original_bytes else {"sbom": bom}))
    previous = None
    for number in (1, 2):
        supplied = base | {"expected": previous, "build_number": number, "request_id": str(number)}
        receipt = import_inventory(journal, **supplied)
        operation = {
            key: value for key, value in supplied.items() if key not in ("request_id", "raw")
        }
        operation.update(operation="inventory.import/1", predecessor=None)
        if original_bytes:
            operation["input_artifact_sha"] = digest(raw)
        assert receipt[1].fingerprint == digest(canonical(operation))
        previous = receipt[1].updates[0].target


def test_auto_head_publication_rejects_a_concurrent_import(tmp_path, bom, monkeypatch):
    journal = Journal(tmp_path / "journal")
    base = fields(sbom=bom)
    import_inventory(journal, **base)
    publish = journal.publish
    competitor = None

    def publish_after_competitor(**kwargs):
        nonlocal competitor
        monkeypatch.setattr(journal, "publish", publish)
        competitor = (
            import_inventory(journal, **(base | {"request_id": "competitor", "build_number": 3}))[1]
            .updates[0]
            .target
        )
        return publish(**kwargs)

    monkeypatch.setattr(journal, "publish", publish_after_competitor)
    with pytest.raises(Conflict):
        import_inventory(journal, **(base | {"request_id": "racing", "build_number": 2}))
    assert journal.resolve(Ref(project_id="product", name="1")) == competitor
