"""The cutoff of the project review, per date basis (ADR 0015)."""

from datetime import date, datetime, timezone

import pytest
from pydantic import ValidationError

from dtvp import main
from dtvp.first_seen import (
    annotate_first_seen,
    cutoff_end_ms,
    normalize_cutoff,
    resolve_cutoff,
)
from dtvp.general_api_routes import BulkWorkflowFilters, _filter_bulk_workflow_groups
from dtvp.grouped_vuln_services import summarize_grouped_vulnerabilities
from dtvp.logic import group_vulnerabilities
from dtvp.task_group_query_services import build_task_group_query_index, query_task_groups

JAN = "2026-01-10T08:00:00Z"
JUN = "2026-06-01T08:00:00Z"
DEC_2025 = 1764547200000  # 2025-12-01, as Dependency-Track serves dates: epoch ms
FEB = "2026-02-01T00:00:00Z"
APR = "2026-04-01T00:00:00Z"
MAY = "2026-05-01T00:00:00Z"
OLD = "2024-03-05T00:00:00Z"

def _ms(text):
    return int(datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp() * 1000)

def _component(name, purl, attributed_on, version="1.0", published=None):
    return {
        "component_name": name,
        "component_purl": purl,
        "component_version": version,
        "component_uuid": f"{name}-{attributed_on}",
        "attributed_on": attributed_on,
        "published": published,
        "analysis_state": "NOT_SET",
        "analysis_details": "",
    }

def _group(group_id, versions):
    return {
        "id": group_id,
        "title": group_id,
        "tags": [],
        "aliases": [],
        "affected_versions": [
            {"project_version": label, "components": components}
            for label, components in versions.items()
        ],
    }

def _groups():
    return [
        # Published before the cutoff and known since 7.1.0; 7.1.1 was
        # deleted and uploaded again: its finding has a new attribution.
        _group("CVE-KNOWN", {
            "7.1.0": [_component("lib", "pkg:npm/lib@1.0", JAN, published=DEC_2025)],
            "7.1.1": [_component("lib", "pkg:npm/lib@1.1", JUN, "1.1", published=DEC_2025)],
        }),
        # Published and found after the cutoff.
        _group("CVE-NEW", {
            "7.1.1": [_component("fresh", "pkg:npm/fresh@2.0", JUN, published=MAY)],
        }),
        # Published long ago, but a component new to the project in 7.1.1.
        _group("CVE-OLD-ADVISORY", {
            "7.1.1": [_component("legacy", "pkg:npm/legacy@0.9", JUN, published=OLD)],
        }),
        # The CVE was published after the cutoff, its GitHub alias before:
        # the earliest publication counts.
        _group("CVE-ALIASED", {
            "7.1.1": [
                _component("parser", "pkg:npm/parser@3.0", JUN, published=APR),
                _component("parser-ghsa", "pkg:npm/parser@3.0", JUN, published=FEB),
            ],
        }),
        # Found early, but the source gives no publication date.
        _group("CVE-UNPUBLISHED", {
            "7.1.0": [_component("internal", "pkg:generic/internal@1", JAN)],
        }),
        # No date at all.
        _group("CVE-UNDATED", {
            "7.1.1": [_component("mystery", "", None)],
        }),
    ]

def _query(index, **filters):
    options = dict(
        q="", lifecycle=[], analysis=[], tag="", vuln_id="", component="",
        assignee="", dependency=[], versions=[], cvss_mismatch=False,
        tmrescore=[], tmrescore_proposal_ids=[], sort_by="id", sort_order="asc",
        offset=0, limit=50,
    )
    options.update(filters)
    return query_task_groups(index, **options)

@pytest.fixture
def index():
    return build_task_group_query_index(summarize_grouped_vulnerabilities(_groups(), {}))

def _ids(response):
    return sorted(item["id"] for item in response["items"])

# -- dates --------------------------------------------------------------------

def test_each_basis_has_its_dates():
    group = _groups()[0]
    dates = annotate_first_seen(group)["cutoff_dates"]
    [old], [recreated] = (v["components"] for v in group["affected_versions"])
    assert old["first_seen_ms"] == recreated["first_seen_ms"] == _ms(JAN)
    assert old["published_ms"] == recreated["published_ms"] == DEC_2025
    assert dates["published"]["by_version"] == {"7.1.0": [DEC_2025, DEC_2025], "7.1.1": [DEC_2025, DEC_2025]}
    # The re-created version keeps the date of the earlier one.
    assert dates["attributed"]["by_version"]["7.1.1"] == [_ms(JAN), _ms(JAN)]
    assert set(dates) == {"published", "attributed"}

def test_a_finding_without_a_date_is_unknown_per_basis():
    unpublished = annotate_first_seen(_groups()[4])["cutoff_dates"]
    assert unpublished["published"] == {"by_version": {}, "unknown": ["7.1.0"]}
    assert unpublished["attributed"]["by_version"] == {"7.1.0": [_ms(JAN), _ms(JAN)]}
    undated = annotate_first_seen(_groups()[5])["cutoff_dates"]
    assert all(entry["unknown"] == ["7.1.1"] for entry in undated.values())

def test_the_published_date_of_a_finding_comes_from_dependency_track():
    # The finding carries the vulnerability's published date, merged in from
    # the full vulnerability record, and the group takes the earliest.
    findings = [
        {
            "component": {"uuid": "c1", "name": "parser", "version": "3.0"},
            "vulnerability": {
                "uuid": "v1", "vulnId": "CVE-2026-1", "source": "NVD", "severity": "HIGH",
                "aliases": [{"cveId": "CVE-2026-1", "ghsaId": "GHSA-aaaa-bbbb-cccc"}],
                "published": _ms(APR),
            },
            "attribution": {"attributedOn": _ms(JUN)},
        },
        {
            "component": {"uuid": "c2", "name": "parser", "version": "3.0"},
            "vulnerability": {
                "uuid": "v2", "vulnId": "GHSA-aaaa-bbbb-cccc", "source": "GITHUB", "severity": "HIGH",
                "aliases": [{"cveId": "CVE-2026-1", "ghsaId": "GHSA-aaaa-bbbb-cccc"}],
                "published": FEB,
            },
            "attribution": {"attributedOn": _ms(JUN)},
        },
    ]
    groups = group_vulnerabilities(
        [{"version": {"uuid": "p1", "name": "App", "version": "1.0"}, "vulnerabilities": findings}],
    )
    assert len(groups) == 1
    [summary] = summarize_grouped_vulnerabilities(groups, {})
    published = summary["list_metadata"]["cutoff_dates"]["published"]
    assert published["by_version"] == {"1.0": [_ms(FEB), _ms(FEB)]}

# -- the filter ---------------------------------------------------------------

def test_cutoff_text_is_a_date_or_a_number_of_days():
    assert normalize_cutoff(" 2026-03-01 ") == "2026-03-01"
    assert normalize_cutoff("30D") == "30d"
    assert normalize_cutoff("") == ""
    for bad in ("2026-02-30", "yesterday", "-3d", "2026/03/01"):
        with pytest.raises(ValueError):
            normalize_cutoff(bad)
    assert cutoff_end_ms("2026-03-01") == cutoff_end_ms("3d", today=date(2026, 3, 4))
    assert resolve_cutoff("", "before", 14, "younger") == ("14d", "after", "attributed")
    assert resolve_cutoff("", "before", 14, "older", "published") == ("14d", "before", "published")
    assert resolve_cutoff("2026-03-01", "after", 14, "older") == ("2026-03-01", "after", "published")
    assert resolve_cutoff("2026-03-01", "before", None, None, "attributed")[2] == "attributed"
    for basis in ("discovered", "attributed_version"):
        with pytest.raises(ValueError):
            resolve_cutoff("2026-03-01", "before", None, None, basis)

def test_published_is_the_default_basis(index):
    response = _query(index, cutoff="2026-03-01")
    assert response["cutoff_basis"] == "published"
    assert _ids(response) == ["CVE-ALIASED", "CVE-KNOWN", "CVE-OLD-ADVISORY", "CVE-UNDATED", "CVE-UNPUBLISHED"]
    # Listed only because the source gives no date.
    assert response["counts"]["filtered"]["cutoff_unknown"] == 2
    assert response["counts"]["facets"]["cutoff"] == 5

def test_attributed_counts_what_the_project_knew(index):
    response = _query(index, cutoff="2026-03-01", cutoff_basis="attributed")
    assert response["cutoff_basis"] == "attributed"
    assert _ids(response) == ["CVE-KNOWN", "CVE-UNDATED", "CVE-UNPUBLISHED"]
    assert response["counts"]["filtered"]["cutoff_unknown"] == 1
    # The re-created 7.1.1 keeps the date of 7.1.0.
    assert _ids(_query(index, cutoff="2026-03-01", cutoff_basis="attributed", versions=["7.1.1"])) == [
        "CVE-KNOWN", "CVE-UNDATED",
    ]

def test_cutoff_after_lists_what_came_later(index):
    # The aliased one was published (as the GitHub advisory) before.
    response = _query(index, cutoff="2026-03-01", cutoff_mode="after")
    assert _ids(response) == ["CVE-NEW", "CVE-UNDATED", "CVE-UNPUBLISHED"]
    response = _query(index, cutoff="2026-03-01", cutoff_mode="after", cutoff_basis="attributed")
    assert _ids(response) == ["CVE-ALIASED", "CVE-NEW", "CVE-OLD-ADVISORY", "CVE-UNDATED"]

def test_the_cutoff_day_is_included(index):
    assert "CVE-NEW" in _ids(_query(index, cutoff="2026-05-01"))
    assert "CVE-NEW" not in _ids(_query(index, cutoff="2026-04-30"))

def test_cutoff_facet_counts_ignore_the_cutoff_itself(index):
    response = _query(index, cutoff="2026-03-01", q="cve-new")
    assert response["filtered"] == 0
    assert response["counts"]["facets"]["cutoff"] == 0
    assert _query(index, q="cve-new")["filtered"] == 1

def test_retired_attribution_age_parameters_are_an_attributed_cutoff(index):
    response = _query(index, attributed_before_days=1, attribution_mode="older")
    assert response["cutoff_basis"] == "attributed"
    assert len(response["items"]) == 6

def test_bulk_changes_current_list_uses_the_cutoff_and_its_basis(index):
    groups = _filter_bulk_workflow_groups(index, BulkWorkflowFilters(cutoff="2026-03-01"))
    assert sorted(group["id"] for group in groups) == [
        "CVE-ALIASED", "CVE-KNOWN", "CVE-OLD-ADVISORY", "CVE-UNDATED", "CVE-UNPUBLISHED",
    ]
    groups = _filter_bulk_workflow_groups(
        index, BulkWorkflowFilters(cutoff="2026-03-01", cutoff_basis="attributed"),
    )
    assert sorted(group["id"] for group in groups) == ["CVE-KNOWN", "CVE-UNDATED", "CVE-UNPUBLISHED"]
    with pytest.raises(ValidationError):
        BulkWorkflowFilters(cutoff="soon")
    with pytest.raises(ValidationError):
        BulkWorkflowFilters(cutoff="2026-03-01", cutoff_basis="discovered")

# -- the API -------------------------------------------------------------------

def test_the_group_route_takes_the_cutoff_and_its_basis(client):
    main.app.dependency_overrides[main.get_current_user] = lambda: "testuser"
    task_id = "task-cutoff"
    main.tasks[task_id] = {
        "id": task_id,
        "_owner": "testuser",
        "status": "completed",
        "result_mode": "summary",
        "result": summarize_grouped_vulnerabilities(_groups(), {}),
    }
    try:
        published = client.get(
            f"/api/tasks/{task_id}/groups", params={"cutoff": "2026-03-01", "versions": "7.1.1"},
        ).json()
        data = client.get(
            f"/api/tasks/{task_id}/groups",
            params={"cutoff": "2026-03-01", "versions": "7.1.1", "cutoff_basis": "attributed"},
        ).json()
        legacy = client.get(
            f"/api/tasks/{task_id}/groups",
            params={"attributed_before_days": 1, "attribution_mode": "older"},
        ).json()
        bad = client.get(f"/api/tasks/{task_id}/groups", params={"cutoff": "soon"})
        bad_mode = client.get(f"/api/tasks/{task_id}/groups", params={"cutoff": "3d", "cutoff_mode": "later"})
        bad_basis = client.get(
            f"/api/tasks/{task_id}/groups", params={"cutoff": "3d", "cutoff_basis": "attributed_version"},
        )
    finally:
        main.tasks.pop(task_id, None)
    assert published["cutoff_basis"] == "published"
    assert sorted(item["id"] for item in published["items"]) == [
        "CVE-ALIASED", "CVE-KNOWN", "CVE-OLD-ADVISORY", "CVE-UNDATED",
    ]
    assert published["counts"]["filtered"]["cutoff_unknown"] == 1
    assert data["cutoff_basis"] == "attributed"
    assert sorted(item["id"] for item in data["items"]) == ["CVE-KNOWN", "CVE-UNDATED"]
    assert data["counts"]["filtered"]["cutoff_unknown"] == 1
    assert legacy["cutoff_basis"] == "attributed"
    # Each finding carries its dates for the detail view.
    [known] = [item for item in data["items"] if item["id"] == "CVE-KNOWN"]
    first_seen = {v["project_version"]: v["components"][0]["first_seen_ms"] for v in known["affected_versions"]}
    assert first_seen["7.1.0"] == first_seen["7.1.1"]
    assert known["affected_versions"][0]["components"][0]["published_ms"] == DEC_2025
    assert bad.status_code == 400
    assert bad_mode.status_code == 422
    assert bad_basis.status_code == 422
