"""Current authored context filters never resurrect stale or inferred facts."""

import copy

import pytest

from dtvp.knowledge.filters import KnowledgeFilters


def annotated(status="current", applicable=True):
    return {
        "curated_metadata": {
            "status": status,
            "applicable": applicable,
            "payload": {
                "annotations": {
                    "cybersecurity": {"criticality": "critical", "exposure": "external"},
                    "support": {
                        "status": "supported",
                        "end_of_life": "2000-01-01",
                        "support_until": "2000-01-01",
                    },
                }
            },
        },
        "sourcefacts": [{"criticality": "low", "exposure": "not_exposed"}],
    }


def test_authored_context_and_support_are_separate_from_source_or_date_inference():
    row = annotated()
    before = copy.deepcopy(row)
    assert KnowledgeFilters(
        criticality="critical",
        exposure="external",
        support_status="supported",
        metadata_status="current",
    ).matches(row)
    assert not KnowledgeFilters(support_status="unsupported").matches(row)
    assert not KnowledgeFilters(criticality="low").matches(row)
    assert row == before


@pytest.mark.parametrize("status", ["stale", "absent", "out_of_scope", "unrecognized"])
def test_historical_annotations_stay_visible_but_supply_no_current_context(status):
    row = annotated(status)
    assert KnowledgeFilters(
        criticality="unknown",
        exposure="unknown",
        support_status="unknown",
        metadata_status=status if status != "unrecognized" else "unknown",
    ).matches(row)
    assert not KnowledgeFilters(criticality="critical").matches(row)
    assert not KnowledgeFilters(exposure="external").matches(row)


def test_missing_and_nonapplicable_values_are_unknown_without_becoming_low_risk():
    assert KnowledgeFilters(metadata_status="missing", criticality="unknown").matches({})
    assert not KnowledgeFilters(exposure="not_exposed").matches({})
    assert KnowledgeFilters(exposure="unknown").matches(annotated(applicable=False))
    assert KnowledgeFilters(criticality="unknown").matches(
        {"curated_metadata": {"status": "current", "applicable": True, "payload": {}}}
    )
