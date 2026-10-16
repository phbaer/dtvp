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
