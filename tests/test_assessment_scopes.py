"""Assessment scopes (ADR 0010 step 5): helpers and aggregates. The lifecycle
per scope is tested with the shared cases in test_assessment_comparison.py."""

import pytest

from dtvp.assessment_scopes import (
    AMBIGUOUS,
    BASE,
    assessment_scopes,
    combine_lifecycles,
    is_untouched,
    resolved_marker,
    version_scope,
)
from dtvp.grouped_vuln_services import refresh_new_finding_flags
from dtvp.logic import calculate_statistics

NA = "--- [Team: TeamB] [State: NOT_AFFECTED] [Assessed By: bob] [Justification: CODE_NOT_PRESENT] ---\nNot shipped."
EX = "--- [Team: TeamB] [State: EXPLOITABLE] [Assessed By: bob] [Justification: NOT_SET] ---\nShips it."
LEGACY = "[Version Override: legacy] [Override Reason: old build]\n\n"


def _finding(project, state="NOT_SET", details="", component="c1", **extra):
    return {
        "project_uuid": project, "component_uuid": component, "vulnerability_uuid": "v1",
        "analysis_state": state, "analysis_details": details, **extra,
    }


def _group(*findings):
    versions: dict[str, list] = {}
    for finding in findings:
        versions.setdefault(finding["project_uuid"], []).append(finding)
    return {
        "id": "CVE-1",
        "severity": "HIGH",
        "affected_versions": [
            {"project_uuid": uuid, "project_version": uuid, "components": components}
            for uuid, components in versions.items()
        ],
    }


def test_untouched_ignores_only_the_override_and_pending_tags():
    assert is_untouched(_finding("p1"))
    assert is_untouched(_finding("p1", details=LEGACY + "[Status: Pending Review]"))
    assert not is_untouched(_finding("p1", details="Looked at it."))
    assert not is_untouched(_finding("p1", "IN_TRIAGE"))


def test_resolved_marker_per_scope():
    view = assessment_scopes(_group(
        _finding("p1", "NOT_AFFECTED", NA),
        _finding("p2", "EXPLOITABLE", LEGACY + EX),
    ))
    base, legacy = view.scopes

    assert resolved_marker(base) is None
    assert resolved_marker(legacy) == {"label": "legacy", "reason": "old build"}


def test_a_scope_whose_findings_disagree_on_the_reason_has_no_marker():
    view = assessment_scopes(_group(
        _finding("p2", "EXPLOITABLE", LEGACY + EX),
        _finding("p3", "EXPLOITABLE", "[Version Override: legacy] [Override Reason: fork]\n\n" + EX),
    ))
    [_base, legacy] = view.scopes

    assert legacy.reason is None and legacy.reason_mismatch
    with pytest.raises(ValueError):
        resolved_marker(legacy)


def test_labels_compare_without_case():
    view = assessment_scopes(_group(
        _finding("p2", "EXPLOITABLE", LEGACY + EX),
        _finding("p3", "EXPLOITABLE", LEGACY.replace("legacy", "Legacy") + EX),
    ))

    assert [scope.name for scope in view.scopes] == [BASE, "legacy"]
    assert view.version_scopes == {"p2": "legacy", "p3": "legacy"}


def test_version_scope_counts_records_that_are_not_active():
    """Carry-over replaced every tagged finding of an overridden version: the
    records carried from keep the version in its scope."""
    group = _group(_finding("p1", "NOT_AFFECTED", NA), _finding("p2", component="c-new"))
    gone = _finding("p2", "EXPLOITABLE", LEGACY + EX, component="c-old")

    assert version_scope(group, "p2") == BASE
    assert version_scope(group, "p2", extra_records=[gone]) == "legacy"
    other = _finding("p2", "EXPLOITABLE", "[Version Override: fork]\n\n" + EX, component="c-x")
    assert version_scope(group, "p2", extra_records=[gone, other]) == AMBIGUOUS


def test_the_primary_scope_is_base_when_it_has_findings():
    with_base = assessment_scopes(_group(
        _finding("p1", "NOT_AFFECTED", NA),
        _finding("p2", "EXPLOITABLE", LEGACY + EX),
        _finding("p3", "EXPLOITABLE", LEGACY + EX),
    ))
    without = assessment_scopes(_group(_finding("p2", "EXPLOITABLE", LEGACY + EX)))

    assert with_base.primary.name == BASE
    assert without.primary.name == "legacy"


@pytest.mark.parametrize("lifecycles, ambiguous, expected", [
    (["ASSESSED", "INCONSISTENT"], False, "INCONSISTENT"),
    (["ASSESSED"], True, "INCONSISTENT"),
    (["ASSESSED", "INCOMPLETE"], False, "INCOMPLETE"),
    (["OPEN", "ASSESSED"], False, "INCOMPLETE"),
    (["ASSESSED", "NEEDS_APPROVAL"], False, "NEEDS_APPROVAL"),
    (["OPEN", "OPEN"], False, "OPEN"),
    (["ASSESSED", "ASSESSED_LEGACY"], False, "ASSESSED_LEGACY"),
    (["ASSESSED", "ASSESSED"], False, "ASSESSED"),
])
def test_scope_lifecycles_combine_in_order(lifecycles, ambiguous, expected):
    assert combine_lifecycles(lifecycles, ambiguous=ambiguous) == expected


def test_statistics_count_an_approved_override_once_and_not_as_inconsistent():
    overridden = _group(_finding("p1", "NOT_AFFECTED", NA), _finding("p2", "EXPLOITABLE", LEGACY + EX))
    conflicting = _group(_finding("p1", "NOT_AFFECTED", NA), _finding("p2", "EXPLOITABLE", EX))
    conflicting["id"] = "CVE-2"

    stats = calculate_statistics([overridden, conflicting])

    assert stats["state_counts"] == {"NOT_AFFECTED": 1, "INCONSISTENT": 1}
    assert stats["groups_with_overrides"] == 1


def test_a_finding_with_only_the_marker_can_be_new():
    """A new finding inherited into an overridden version may carry nothing
    but the tags; it is still new (``is_untouched``)."""
    group = _group(
        _finding("p1", "NOT_AFFECTED", "--- [Team: TeamB] [State: NOT_AFFECTED] [Date: 1000] ---\nx",
                 attributed_on="1970-01-01T00:00:00.500Z"),
        _finding("p2", details="[Version Override: legacy]", attributed_on="1970-01-01T00:00:02Z"),
    )

    assert refresh_new_finding_flags(group) == 1
