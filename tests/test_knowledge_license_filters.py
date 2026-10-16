"""Selection must distinguish approved conclusions from pending drafts."""

import pytest
from pydantic import ValidationError

from dtvp.knowledge.license_filters import LicenseFilters
from dtvp.knowledge.licenses import license_worklist
from tests.test_knowledge_workspace import snapshot
from tests.test_knowledge_workspace import workspace as source_workspace

workspace = source_workspace


def row():
    return {
        "component_ref": "lib",
        "component": {"name": "Straße", "purl": "pkg:generic/lib@1"},
        "evidence": {"status": "unknown", "facts": []},
        "license_review": {
            "status": "approved",
            "approved": True,
            "pending": True,
            "assessment": {"payload": {"disposition": "allowed"}},
            "approved_assessment": {"payload": {"disposition": "restricted"}},
        },
    }


def test_approved_filter_never_uses_pending_disposition_or_stale_approval():
    value = row()
    assert LicenseFilters(approved_disposition="restricted", review_status="pending").matches(value)
    assert not LicenseFilters(approved_disposition="allowed").matches(value)
    value["license_review"]["approved"] = False
    assert LicenseFilters(approved_disposition="missing").matches(value)
    assert not LicenseFilters(approved_disposition="restricted").matches(value)


def test_search_is_casefolded_and_combines_with_source_and_review_filters():
    assert LicenseFilters(q="STRASSE", evidence_status="unknown", review_status="approved").matches(
        row()
    )
    assert LicenseFilters(q="pkg:generic/lib").matches(row())
    assert not LicenseFilters(q="absent").matches(row())
    assert not LicenseFilters(q="component_ref").matches(row())
    assert not LicenseFilters(evidence_status="reported").matches(row())
    assert not LicenseFilters(review_status="draft").matches(row())


@pytest.mark.parametrize(
    "values",
    [
        {"q": "x" * 501},
        {"evidence_status": "clear"},
        {"review_status": "accepted"},
        {"approved_disposition": "permitted"},
    ],
)
def test_invalid_filters_fail_closed(values):
    with pytest.raises(ValidationError):
        LicenseFilters(**values)


def test_selection_precedes_counts_and_pages_without_changing_default_dto(workspace):
    journal, sections = workspace
    sections["inventory"]["component:shared"]["licenses"] = [{"license": {"id": "MIT"}}]
    journal, state = snapshot(workspace)
    baseline = license_worklist(journal, state)
    assert license_worklist(journal, state, filters=LicenseFilters()) == baseline
    selected = license_worklist(
        journal, state, filters=LicenseFilters(evidence_status="reported"), limit=1
    )
    assert selected["total"] == selected["statistics"]["components"] == 1
    assert selected["items"][0]["component_ref"] == "shared"
    empty = license_worklist(journal, state, filters=LicenseFilters(approved_disposition="allowed"))
    assert empty["total"] == empty["statistics"]["components"] == 0
