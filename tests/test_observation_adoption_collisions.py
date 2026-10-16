"""Explicit adoption cannot overwrite authority nodes or poison identity history."""

from copy import deepcopy

import pytest

from dtvp.knowledge import observations
from dtvp.knowledge.journal import Journal
from dtvp.knowledge.service import import_inventory
from dtvp.knowledge.workspace import load_sections
from dtvp.storage import canonical, digest
from tests.test_knowledge_observations import COLLECTION, authority, bom, ingest, inputs, selected


def import_build(journal, document, *, expected=None, build=1):
    return (
        import_inventory(
            journal,
            project_id="product",
            version="1",
            actor_id="CI",
            request_id=f"collision-authority-{build}",
            expected=expected,
            source="build",
            build_number=build,
            occurred_at="2026-10-16T00:00:00Z",
            sbom=document,
            context=COLLECTION,
        )[1]
        .updates[0]
        .target
    )


def test_adoption_rejects_preexisting_authority_reference_without_overwriting_it(tmp_path):
    journal = Journal(tmp_path / "journal")
    original = authority(journal)
    first = ingest(journal, inputs(original))[1].updates[0].target
    identity = load_sections(journal, first)["inventory"]["identity"]["entries"]["scan-extra"][
        "lineage_id"
    ]
    collision = "observation:" + digest(canonical([None, "scanner", identity]))
    document = bom()
    document["components"].append(
        {
            "type": "library",
            "bom-ref": collision,
            "name": "authority occurrence",
            "version": "1",
            "purl": "pkg:generic/authority-occurrence@1",
        }
    )
    document["dependencies"][0]["dependsOn"].append(collision)
    document["dependencies"].append({"ref": collision, "dependsOn": []})
    current = import_build(journal, document, expected=original, build=2)
    layer = (
        ingest(journal, inputs(current, request_id="new-scan", expected=first, build_number=2))[1]
        .updates[0]
        .target
    )
    before = journal.head()
    selection = selected(
        journal,
        current,
        layer,
        sources=[
            {
                "source": "scanner",
                "state": layer,
                "accepted_components": ["scan-extra"],
                "reason": "Explicit adoption",
            }
        ],
    )
    with pytest.raises(ValueError, match="existing occurrence"):
        observations.build_selection(journal, project_id="product", version="1", data=selection)
    assert journal.head() == before
    assert any(
        item.get("name") == "authority occurrence"
        for item in load_sections(journal, current)["inventory"].values()
    )


@pytest.mark.parametrize("retired", [False, True])
def test_adoption_rejects_duplicate_live_or_retired_lineage_identity(tmp_path, retired):
    journal = Journal(tmp_path / "journal")
    document = bom()
    document["metadata"]["component"].pop("purl")
    for component in document["components"]:
        component.pop("purl")
    original = import_build(journal, document)
    current = original
    if retired:
        reduced = deepcopy(document)
        reduced["components"] = []
        reduced["dependencies"] = [{"ref": "app", "dependsOn": []}]
        reduced["vulnerabilities"] = []
        current = import_build(journal, reduced, expected=original, build=2)
    layer = ingest(journal, inputs(current, source="build", sbom=document))[1].updates[0].target
    ledger = load_sections(journal, current)["inventory"]["identity"]
    identity = load_sections(journal, layer)["inventory"]["identity"]["entries"]["lib"][
        "lineage_id"
    ]
    if retired:
        assert identity in ledger["tombstones"]
    else:
        assert identity == ledger["entries"]["lib"]["lineage_id"]
    before = journal.head()
    selection = selected(
        journal,
        current,
        layer,
        sources=[
            {
                "source": "build",
                "state": layer,
                "accepted_components": ["lib"],
                "reason": "Explicit occurrence proposal",
            }
        ],
    )
    with pytest.raises(ValueError, match="retained lineage identity"):
        observations.build_selection(journal, project_id="product", version="1", data=selection)
    assert journal.head() == before
