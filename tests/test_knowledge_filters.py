"""V3 filter semantics preserve source/current distinctions and unknown coverage."""

import copy

import pytest
from pydantic import ValidationError

from dtvp.knowledge.filters import KnowledgeFilters, filter_rows

VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def row(**changes):
    result = {
        "id": "one",
        "component": {
            "name": "Shared TLS",
            "version": "2.0",
            "group": "vendor",
            "purl": "pkg:generic/tls@2.0",
        },
        "context": {
            "root_ref": "app",
            "component_ref": "tls",
            "dependency_graph": "reported",
            "incoming_refs": ["app"],
        },
        "dependency_relation": "direct",
        "source_ratings": [
            {
                "source": {"name": "Supplier", "url": "https://supplier.invalid/advisories"},
                "observed_source": "pipeline:ci",
                "method": "CVSSv31",
                "vector": VECTOR,
                "score": 9.8,
            }
        ],
        "sourcefacts": [
            {"source": "Dependency Track", "advisory": {"source": {"name": "Original publisher"}}}
        ],
        "coverage": {"status": "unassessed", "recorded": False, "approved": False},
        "published_score": None,
    }
    result.update(changes)
    return result


def matches(item, **filters):
    return bool(filter_rows([item], KnowledgeFilters(**filters)))


def test_source_critical_and_published_zero_are_independent_filters():
    item = row(published_score={"current": True, "score": 0})
    assert matches(
        item, source_severity="critical", contextual_severity="none", scoring_status="published"
    )
    assert not matches(item, contextual_severity="critical")
    assert matches(item, source_conflict="no")  # A contextual change is not a source conflict.
    item["source_ratings"].append({"score": 0, "severity": "none"})
    assert matches(item, source_severity="critical")


def test_outdated_published_zero_never_matches_current_contextual_none():
    stale = row(published_score={"current": False, "score": 0})
    assert matches(stale, scoring_status="outdated", contextual_severity="unknown")
    assert not matches(stale, contextual_severity="none")
    assert not matches(stale, scoring_status="published")
    assert matches(row(), scoring_status="not_published", contextual_severity="unknown")
    assert matches(
        row(published_score={"score": 4}), scoring_status="unknown", contextual_severity="unknown"
    )


@pytest.mark.parametrize("value", [None, True, -1, 11, float("nan"), float("inf")])
def test_invalid_or_absent_source_scores_remain_unknown(value):
    assert matches(row(source_ratings=[{"score": value}]), source_severity="unknown")
    assert not matches(row(source_ratings=[{"score": value}]), source_severity="none")


def test_declared_source_severity_fallback_and_numeric_precedence():
    assert matches(
        row(source_ratings=[{"severity": "HIGH"}, {"severity": "low"}]), source_severity="high"
    )
    assert matches(
        row(source_ratings=[{"severity": "critical"}, {"score": 0}]), source_severity="none"
    )


def test_approved_pin_keeps_applicability_while_new_draft_is_pending():
    item = row(
        coverage={
            "status": "approved",
            "recorded": True,
            "approved": True,
            "pending_revision": True,
            "assessment": {"revision": "new", "payload": {"state": "affected"}},
            "approved_assessment": {"revision": "old", "payload": {"state": "not_affected"}},
        }
    )
    assert matches(item, applicability="not_affected", team_review="approved")
    assert matches(item, team_review="pending")
    assert not matches(item, applicability="affected")
    del item["coverage"]["approved_assessment"]
    assert matches(item, applicability="unknown")


def test_stale_and_absent_assessments_do_not_supply_current_applicability():
    for status in ("reassessment_needed", "historically_absent"):
        item = row(
            coverage={
                "status": status,
                "recorded": True,
                "assessment": {"payload": {"state": "not_affected"}},
            }
        )
        assert matches(item, applicability="unknown", team_review="recorded")
        assert not matches(item, applicability="not_affected")
        assert not matches(item, team_review="current")
    assert matches(row(), applicability="unassessed", team_review="missing")


def test_team_submission_is_pending_but_never_approved():
    item = row(
        coverage={
            "status": "submitted",
            "recorded": True,
            "approved": False,
            "assessment": {"payload": {"state": "affected"}},
        }
    )
    assert matches(item, team_review="pending", applicability="affected")
    assert matches(item, team_review="submitted")
    assert not matches(item, team_review="approved")
    assert matches(row(coverage={"status": "draft", "recorded": True}), team_review="draft")
    assert not matches(row(coverage={"status": "draft", "recorded": True}), team_review="pending")


def test_changes_requested_must_bind_current_evidence_fingerprint():
    coverage = {
        "status": "reassessment_needed",
        "recorded": True,
        "fingerprint": "current",
        "review": {"status": "changes_requested", "target": {"fingerprint": "current"}},
    }
    assert matches(row(coverage=coverage), team_review="changes_requested")
    coverage["review"]["target"]["fingerprint"] = "old"
    assert not matches(row(coverage=coverage), team_review="changes_requested")
    assert matches(row(coverage=coverage), team_review="needs_revalidation")


def test_provider_attribution_matches_exact_names_without_implying_independence():
    item = row()
    for provider in (
        "supplier",
        "PIPELINE:CI",
        "dependency track",
        "Original publisher",
        "https://supplier.invalid/advisories",
    ):
        assert matches(item, provider=provider)
    assert not matches(item, provider="supply")
    assert not matches(row(sourcefacts=[], source_ratings=[]), provider="Supplier")


def test_cvss_versions_come_from_reported_methods_or_explicit_vector_prefixes():
    assert matches(row(), cvss_version="3.1")
    assert not matches(row(), cvss_version="4.0")
    assert matches(row(source_ratings=[{"method": "CVSSv4", "score": 8}]), cvss_version="4.0")
    assert matches(
        row(source_ratings=[{"method": "CVSSv2", "vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P"}]),
        cvss_version="2.0",
    )
    assert matches(row(source_ratings=[{"score": 8}]), cvss_version="unknown")
    assert matches(row(source_ratings=[]), cvss_version="unknown")


def test_dependency_uses_full_graph_read_model_and_never_guesses_from_incoming_refs():
    assert matches(row(), dependency="known_direct")
    assert matches(row(dependency_relation="transitive"), dependency="transitive")
    assert matches(row(dependency_relation="root"), dependency="root")
    missing = row()
    del missing["dependency_relation"]
    assert matches(missing, dependency="unknown")
    item = row(dependency_relation="transitive")
    item["context"]["dependency_graph"] = "not_reported"
    assert matches(item, dependency="unknown")
    assert not matches(item, dependency="transitive")


def test_source_discrepancies_compare_same_cvss_versions_and_metric_order_is_irrelevant():
    item = row()
    item["source_ratings"].append({"method": "CVSSv31", "vector": VECTOR, "score": 7.5})
    assert matches(item, source_conflict="yes")
    item["source_ratings"][1]["score"] = 9.8
    item["source_ratings"][1]["vector"] = "/".join(["CVSS:3.1", *reversed(VECTOR.split("/")[1:])])
    assert matches(item, source_conflict="no")
    item["source_ratings"][1]["vector"] = VECTOR.replace("AV:N", "AV:L")
    assert matches(item, source_conflict="yes")
    assert matches(row(source_ratings=[]), source_conflict="unknown")
    assert matches(row(source_ratings=[{"method": "CVSSv31"}]), source_conflict="unknown")


def test_other_cvss_versions_alone_do_not_establish_source_conflict():
    item = row()
    item["source_ratings"].append({"method": "CVSSv4", "vector": "CVSS:4.0/AV:N", "score": 7.5})
    assert matches(item, source_conflict="no", cvss_version="4.0")
    assert matches(
        row(source_ratings=[{"method": "CVSSv4", "vector": VECTOR}]), source_conflict="yes"
    )


def test_component_search_is_case_insensitive_and_filters_preserve_order_and_inputs():
    first, second = row(id="first"), row(id="second", component={"name": "Other package"})
    originals = copy.deepcopy([first, second])
    assert filter_rows([first, second], {"component": "VENDOR"}) == [first]
    assert matches(first, component="generic/tls@2.0")
    assert matches(first, component="shared tls")
    assert filter_rows([first, second], {}) == [first, second]
    assert [first, second] == originals


@pytest.mark.parametrize(
    "filters",
    [
        {"source_severity": "urgent"},
        {"scoring_status": "ready"},
        {"dependency": "inferred"},
        {"cvss_version": "5"},
        {"provider": "x" * 201},
        {"clinical_risk": "low"},
    ],
)
def test_unknown_values_and_fields_are_rejected(filters):
    with pytest.raises(ValidationError):
        KnowledgeFilters.model_validate(filters)


def test_malformed_method_and_missing_approved_revision_stay_unknown():
    item = row(source_ratings=[{"method": {}, "score": 8}])
    assert matches(item, cvss_version="unknown", source_conflict="unknown")
    item["coverage"] = {
        "status": "approved",
        "approved": True,
        "assessment": {"payload": {"state": "not_affected"}},
    }
    assert matches(item, applicability="unknown")


def test_provider_filter_includes_received_proposals_without_claiming_eligibility():
    item = row(
        scoring_proposals=[
            {"provider": "vscorer", "source_label": "Threat model", "eligible": False}
        ]
    )
    assert matches(item, provider="VScorer")
    assert matches(item, provider="Threat model")
    assert not matches(item, provider="Threat")
