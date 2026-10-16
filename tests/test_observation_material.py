"""Supplemental source facts are visible and invalidate only affected scope."""

from copy import deepcopy

from dtvp.knowledge.assessments import target_fingerprint
from dtvp.knowledge.component_inventory import component_rows
from dtvp.knowledge.journal import Journal
from tests.test_knowledge_assessments import current, seed


def test_observation_facts_are_scoped_material_with_nonmaterial_capture_provenance(tmp_path):
    journal = Journal(tmp_path / "journal")
    seed(journal)
    sections = current(journal)
    context = next(
        value
        for key, value in sections["ownership"].items()
        if key.startswith("context:") and value["component_ref"] == "lib"
    )

    def fingerprint(value):
        return target_fingerprint(value, "7.1.1", context["id"], "CVE-2026-0001")

    original = fingerprint(sections)
    assertion = {
        "source": "binary-scan",
        "part_id": None,
        "state": "a" * 64,
        "ref": "source-ref",
        "component": {
            "bom-ref": "source-ref",
            "name": "lib",
            "description": "Untrusted network parser",
        },
    }
    sections["inventory"]["observation_assertions"] = {
        "format": "dtvp.observation-assertions/1",
        "components": {"lib": [assertion]},
    }
    observed = fingerprint(sections)
    assert observed != original
    assert next(row for row in component_rows(sections) if row["component_ref"] == "lib")[
        "supplemental_component_evidence"
    ] == [assertion]
    newer = deepcopy(sections)
    changed = newer["inventory"]["observation_assertions"]["components"]["lib"][0]
    changed.update(state="b" * 64, ref="renamed-local")
    changed["component"]["bom-ref"] = "renamed-local"
    assert fingerprint(newer) == observed
    changed["component"]["description"] = "Parser has an exploitable configuration"
    assert fingerprint(newer) != observed
    unrelated = deepcopy(sections)
    unrelated["inventory"]["observation_assertions"]["components"]["disconnected"] = [assertion]
    assert fingerprint(unrelated) == observed


def test_adopted_observation_root_remains_importable_and_preserves_target_parent(tmp_path):
    from dtvp.knowledge import observations
    from dtvp.knowledge.service import import_inventory
    from dtvp.knowledge.workspace import load_sections
    from tests.test_knowledge_observations import (
        COLLECTION,
        authority,
        bom,
        ingest,
        inputs,
        publish,
        selected,
    )

    journal = Journal(tmp_path / "journal")
    head = authority(journal)
    document = bom("scan-")
    document["metadata"]["component"]["purl"] = "pkg:generic/scanner-root@2"
    layer = ingest(journal, inputs(head, sbom=document))[1].updates[0].target
    selection = selected(
        journal,
        head,
        layer,
        sources=[
            {
                "source": "scanner",
                "state": layer,
                "accepted_components": ["scan-app"],
                "reason": "Explicit root as additional occurrence",
            }
        ],
    )
    candidate = observations.build_selection(
        journal, project_id="product", version="1", data=selection
    )
    assert candidate["parents"][0] == head
    published = publish(journal, selection)[0][1].updates[0].target
    ledger = load_sections(journal, published)["inventory"]["identity"]
    adopted = next(
        value for key, value in ledger["entries"].items() if key.startswith("observation:")
    )
    assert adopted["role"] == "component" and adopted["source"]["role"] == "root"
    updated = (
        import_inventory(
            journal,
            project_id="product",
            version="1",
            actor_id="CI",
            request_id="authority-next",
            expected=published,
            source="build",
            build_number=2,
            occurred_at="2026-10-16T00:00:00Z",
            sbom=bom(),
            context=COLLECTION,
        )[1]
        .updates[0]
        .target
    )
    assert (
        adopted["lineage_id"]
        in load_sections(journal, updated)["inventory"]["identity"]["tombstones"]
    )


def test_observation_candidate_respects_total_retained_identity_bounds(tmp_path, monkeypatch):
    import pytest

    from dtvp.knowledge import component_lineages, observations
    from tests.test_knowledge_observations import authority, ingest, inputs, selected

    journal = Journal(tmp_path / "journal")
    head = authority(journal)
    layer = ingest(journal, inputs(head))[1].updates[0].target
    selection = selected(
        journal,
        head,
        layer,
        sources=[
            {
                "source": "scanner",
                "state": layer,
                "accepted_components": ["scan-extra"],
                "reason": "Explicit additional occurrence",
            }
        ],
    )
    before = journal.head()
    monkeypatch.setattr(component_lineages, "MAX_IDENTITIES", 2)
    with pytest.raises(ValueError, match="identity ledger"):
        observations.build_selection(journal, project_id="product", version="1", data=selection)
    monkeypatch.setattr(component_lineages, "MAX_IDENTITIES", 100000)
    monkeypatch.setattr(component_lineages, "MAX_LEDGER_BYTES", 10)
    with pytest.raises(ValueError, match="identity ledger"):
        observations.build_selection(journal, project_id="product", version="1", data=selection)
    assert journal.head() == before


def test_empty_observation_selection_cannot_bypass_rotated_authority(tmp_path):
    import pytest

    from dtvp.knowledge import observations
    from dtvp.knowledge.pipeline_config import PipelineConfigInput, configure
    from tests.test_knowledge_observations import authority

    journal = Journal(tmp_path / "journal")
    head = authority(journal)
    policy = (
        configure(
            journal,
            project_id="product",
            actor_id="manager",
            data=PipelineConfigInput(
                request_id="replace-authority",
                expected_policy=None,
                expected_versions={"1": head},
                reason="Retire source",
                parts=[
                    {"part_id": None, "authority_source": "replacement", "observation_sources": []}
                ],
            ),
        )[1]
        .updates[0]
        .target
    )
    with pytest.raises(ValueError, match="role"):
        observations.build_selection(
            journal,
            project_id="product",
            version="1",
            data=observations.ObservationSelection(
                request_id="empty", expected=head, expected_configuration=policy, sources=[]
            ),
        )


def test_withdrawn_inventory_cannot_receive_observations_or_selection(tmp_path):
    import pytest

    from dtvp.knowledge import observations
    from dtvp.knowledge.journal import Conflict
    from dtvp.knowledge.withdrawal import WithdrawalInput, withdraw_inventory
    from tests.test_knowledge_observations import authority, ingest, inputs

    journal = Journal(tmp_path / "journal")
    head = authority(journal)
    withdrawn = (
        withdraw_inventory(
            journal,
            project_id="product",
            version="1",
            actor_id="manager",
            data=WithdrawalInput(
                request_id="withdraw", expected=head, reason="Invalid authority inventory"
            ),
        )[1]
        .updates[0]
        .target
    )
    before = journal.head()
    with pytest.raises(Conflict, match="Withdrawn"):
        ingest(journal, inputs(withdrawn))
    with pytest.raises(Conflict, match="Withdrawn"):
        observations.build_selection(
            journal,
            project_id="product",
            version="1",
            data=observations.ObservationSelection(
                request_id="empty", expected=withdrawn, expected_configuration=None, sources=[]
            ),
        )
    assert journal.head() == before


def test_legacy_authority_bootstraps_complete_ledger_before_observation_adoption(tmp_path):
    from dtvp.knowledge.journal import Ref, Update
    from dtvp.knowledge.service import import_inventory
    from dtvp.knowledge.workspace import load_sections
    from tests.test_knowledge_observations import (
        COLLECTION,
        authority,
        bom,
        ingest,
        inputs,
        publish,
        selected,
    )

    journal = Journal(tmp_path / "journal")
    head = authority(journal)
    sections = load_sections(journal, head)
    del sections["inventory"]["identity"]
    legacy = journal.snapshot(
        project_id="product",
        version="1",
        actor_id="migration",
        reason="Pre-ledger baseline",
        sections=sections,
        parents=[head],
        artifacts=journal.state(head).artifacts,
    )
    journal.publish(
        request_id="legacy",
        fingerprint=legacy,
        updates=[Update(ref=Ref(project_id="product", name="1"), expected=head, target=legacy)],
    )
    layer = ingest(journal, inputs(legacy))[1].updates[0].target
    selection = selected(
        journal,
        legacy,
        layer,
        sources=[
            {
                "source": "scanner",
                "state": layer,
                "accepted_components": ["scan-extra"],
                "reason": "Explicit additional occurrence",
            }
        ],
    )
    published = publish(journal, selection)[0][1].updates[0].target
    ledger = load_sections(journal, published)["inventory"]["identity"]
    assert ledger["format"] == "dtvp.component-lineages/1" and len(ledger["entries"]) == 3
    updated = (
        import_inventory(
            journal,
            project_id="product",
            version="1",
            actor_id="CI",
            request_id="legacy-next",
            expected=published,
            source="build",
            build_number=2,
            occurred_at="2026-10-16T00:00:00Z",
            sbom=bom(),
            context=COLLECTION,
        )[1]
        .updates[0]
        .target
    )
    assert len(load_sections(journal, updated)["inventory"]["identity"]["tombstones"]) == 1
