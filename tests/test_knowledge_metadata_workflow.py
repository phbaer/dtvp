"""Authored evidence changes invalidate approval; recording bookkeeping does not."""

import copy

from dtvp.knowledge.metadata import get_metadata, save_metadata
from tests.test_knowledge_assessments import (
    assessment,
    coverage,
    current,
    head,
    review,
    save,
    seed,
)
from tests.test_knowledge_assessments import journal as source_journal
from tests.test_knowledge_metadata import data

journal = source_journal


def test_curated_context_changes_require_revalidation_and_rationale_only_edit_does_not(journal):
    seed(journal)
    authored = data(journal)
    save_metadata(journal, project_id="project", version="7.1.1", actor_id="manager", data=authored)
    save(journal, assessment(journal))
    review(journal)
    assert coverage(journal)["approved"]
    before = get_metadata(journal, current(journal), "7.1.1", "lib")
    unchanged = authored.model_copy(
        update={
            "request_id": "recording-edit",
            "expected": head(journal),
            "expected_revision": before["revision"],
            "rationale": "Corrected recording rationale only.",
        }
    )
    save_metadata(
        journal, project_id="project", version="7.1.1", actor_id="manager", data=unchanged
    )
    assert coverage(journal)["approved"]
    annotations = copy.deepcopy(unchanged.annotations)
    annotations.cybersecurity.exposure = "external"
    changed = unchanged.model_copy(
        update={
            "request_id": "changed-exposure",
            "expected": head(journal),
            "expected_revision": get_metadata(journal, current(journal), "7.1.1", "lib")[
                "revision"
            ],
            "annotations": annotations,
        }
    )
    save_metadata(journal, project_id="project", version="7.1.1", actor_id="manager", data=changed)
    assert coverage(journal)["status"] == "reassessment_needed"
    assert not coverage(journal)["approved"]
