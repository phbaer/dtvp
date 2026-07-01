from dtvp.grouped_vuln_services import summarize_grouped_vulnerabilities
from dtvp.task_group_query_services import (
    build_task_group_query_index,
    decode_task_group_cursor,
    query_task_groups,
)


def test_summary_list_metadata_includes_row_rollups():
    summaries = summarize_grouped_vulnerabilities(
        [
            {
                "id": "CVE-2026-ROLLUP",
                "title": "Rollup vulnerability",
                "description": "Summary metadata test",
                "severity": "HIGH",
                "cvss_score": 8.1,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
                "rescored_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N",
                "tags": [],
                "assignees": [],
                "aliases": [],
                "affected_versions": [
                    {
                        "project_name": "Example",
                        "project_version": "1.0.0",
                        "project_uuid": "project-1",
                        "components": [
                            {
                                "project_name": "Example",
                                "project_version": "1.0.0",
                                "project_uuid": "project-1",
                                "component_name": "library-a",
                                "component_version": "2.0.0",
                                "component_uuid": "component-1",
                                "vulnerability_uuid": "vuln-1",
                                "finding_uuid": "finding-1",
                                "attributed_on": 1760000000000,
                                "analysis_state": "NOT_SET",
                                "analysis_details": "full text omitted from summary",
                                "analysis_comments": [{"comment": "large comment"}],
                                "dependency_chains": ["library-a -> app"],
                                "is_suppressed": False,
                                "is_direct_dependency": False,
                            }
                        ],
                    },
                    {
                        "project_name": "Example",
                        "project_version": "1.1.0",
                        "project_uuid": "project-2",
                        "components": [
                            {
                                "project_name": "Example",
                                "project_version": "1.1.0",
                                "project_uuid": "project-2",
                                "component_name": "library-b",
                                "component_version": "3.0.0",
                                "component_uuid": "component-2",
                                "vulnerability_uuid": "vuln-2",
                                "finding_uuid": "finding-2",
                                "attributed_on": 1761000000000,
                                "analysis_state": "NOT_SET",
                                "is_suppressed": False,
                            }
                        ],
                    },
                ],
            }
        ],
        {},
    )

    summary = summaries[0]
    metadata = summary["list_metadata"]

    assert metadata["component_names"] == ["library-a", "library-b"]
    assert metadata["versions"] == ["1.0.0", "1.1.0"]
    assert metadata["attributed_on_ms_values"] == [1760000000000, 1761000000000]
    assert metadata["oldest_attributed_on_ms"] == 1760000000000
    assert metadata["instance_count"] == 2
    assert metadata["dependency_relationship"] == "TRANSITIVE"
    assert metadata["cvss_version_mismatch"] is True

    component = summary["affected_versions"][0]["components"][0]
    assert "analysis_details" not in component
    assert "analysis_comments" not in component
    assert "dependency_chains" not in component


def test_task_group_query_index_reuses_precomputed_fields():
    groups = [
        {
            "id": "CVE-2026-INDEXED",
            "title": "Indexed alpha finding",
            "cvss_score": 5.0,
            "tags": ["TeamA"],
            "aliases": [],
            "assignees": [],
            "list_metadata": {
                "lifecycle": "OPEN",
                "is_open": True,
                "is_pending": False,
                "technical_state": "NOT_SET",
                "component_names": ["library-a"],
                "versions": ["1.0.0"],
                "dependency_relationship": "DIRECT",
                "cvss_version_mismatch": False,
            },
            "affected_versions": [],
        }
    ]

    index = build_task_group_query_index(groups)
    groups[0]["title"] = "Changed after indexing"

    response = query_task_groups(
        index,
        q="indexed alpha",
        lifecycle=[],
        analysis=[],
        tag="",
        vuln_id="",
        component="",
        assignee="",
        dependency=[],
        versions=[],
        cvss_mismatch=False,
        attributed_before_days=None,
        attribution_mode="older",
        tmrescore=[],
        tmrescore_proposal_ids=[],
        sort_by="id",
        sort_order="asc",
        offset=0,
        limit=10,
    )

    assert response["filtered"] == 1
    assert response["counts"]["all"]["total"] == 1
    assert response["counts"]["all"]["team_tags"]["TeamA"] == {
        "open": 1,
        "assessed": 0,
    }
    assert response["counts"]["all"]["ids"]["CVE-2026-INDEXED"] == 1
    assert response["counts"]["all"]["tmrescore"] == {
        "WITH_PROPOSAL": 0,
        "WITHOUT_PROPOSAL": 1,
    }
    assert response["items"][0]["title"] == "Changed after indexing"

    changed_response = query_task_groups(
        index,
        q="changed",
        lifecycle=[],
        analysis=[],
        tag="",
        vuln_id="",
        component="",
        assignee="",
        dependency=[],
        versions=[],
        cvss_mismatch=False,
        attributed_before_days=None,
        attribution_mode="older",
        tmrescore=[],
        tmrescore_proposal_ids=[],
        sort_by="id",
        sort_order="asc",
        offset=0,
        limit=10,
    )
    assert changed_response["filtered"] == 0


def test_task_group_query_counts_needs_approval_once_per_group():
    groups = [
        {
            "id": "CVE-2026-PENDING-1",
            "title": "Pending one",
            "tags": [],
            "aliases": [],
            "assignees": [],
            "list_metadata": {
                "lifecycle": "NEEDS_APPROVAL",
                "is_open": False,
                "is_pending": True,
                "technical_state": "NOT_AFFECTED",
                "component_names": ["library-a"],
                "versions": ["1.0.0"],
                "dependency_relationship": "DIRECT",
                "cvss_version_mismatch": False,
            },
            "affected_versions": [],
        },
        {
            "id": "CVE-2026-PENDING-2",
            "title": "Pending two",
            "tags": [],
            "aliases": [],
            "assignees": [],
            "list_metadata": {
                "lifecycle": "NEEDS_APPROVAL",
                "is_open": False,
                "is_pending": True,
                "technical_state": "FALSE_POSITIVE",
                "component_names": ["library-b"],
                "versions": ["1.0.0"],
                "dependency_relationship": "TRANSITIVE",
                "cvss_version_mismatch": False,
            },
            "affected_versions": [],
        },
        {
            "id": "CVE-2026-OPEN",
            "title": "Open",
            "tags": [],
            "aliases": [],
            "assignees": [],
            "list_metadata": {
                "lifecycle": "OPEN",
                "is_open": True,
                "is_pending": False,
                "technical_state": "NOT_SET",
                "component_names": ["library-c"],
                "versions": ["1.0.0"],
                "dependency_relationship": "UNKNOWN",
                "cvss_version_mismatch": False,
            },
            "affected_versions": [],
        },
    ]

    response = query_task_groups(
        build_task_group_query_index(groups),
        q="",
        lifecycle=["NEEDS_APPROVAL"],
        analysis=[],
        tag="",
        vuln_id="",
        component="",
        assignee="",
        dependency=[],
        versions=[],
        cvss_mismatch=False,
        attributed_before_days=None,
        attribution_mode="older",
        tmrescore=[],
        tmrescore_proposal_ids=[],
        sort_by="id",
        sort_order="asc",
        offset=0,
        limit=10,
    )

    assert response["counts"]["all"]["lifecycle"]["NEEDS_APPROVAL"] == 2
    assert response["filtered"] == 2
    assert response["counts"]["filtered"]["lifecycle"]["NEEDS_APPROVAL"] == 2
    assert [item["id"] for item in response["items"]] == [
        "CVE-2026-PENDING-1",
        "CVE-2026-PENDING-2",
    ]


def test_task_group_query_cache_reuses_filtered_rows_across_windows():
    groups = [
        {
            "id": "CVE-2026-A",
            "title": "Cached query finding",
            "tags": [],
            "aliases": [],
            "assignees": [],
            "list_metadata": {
                "lifecycle": "OPEN",
                "is_open": True,
                "is_pending": False,
                "technical_state": "NOT_SET",
                "component_names": ["library-a"],
                "versions": ["1.0.0"],
                "dependency_relationship": "DIRECT",
                "cvss_version_mismatch": False,
            },
            "affected_versions": [],
        },
        {
            "id": "CVE-2026-B",
            "title": "Cached query finding",
            "tags": [],
            "aliases": [],
            "assignees": [],
            "list_metadata": {
                "lifecycle": "OPEN",
                "is_open": True,
                "is_pending": False,
                "technical_state": "NOT_SET",
                "component_names": ["library-b"],
                "versions": ["1.0.0"],
                "dependency_relationship": "DIRECT",
                "cvss_version_mismatch": False,
            },
            "affected_versions": [],
        },
    ]

    index = build_task_group_query_index(groups)
    first_window = query_task_groups(
        index,
        q="cached query",
        lifecycle=[],
        analysis=[],
        tag="",
        vuln_id="",
        component="",
        assignee="",
        dependency=[],
        versions=[],
        cvss_mismatch=False,
        attributed_before_days=None,
        attribution_mode="older",
        tmrescore=[],
        tmrescore_proposal_ids=[],
        sort_by="id",
        sort_order="asc",
        offset=0,
        limit=1,
    )

    assert first_window["filtered"] == 2
    assert len(index["query_cache"]) == 1

    for row in index["rows"]:
        row["fields"]["searchable_text"] = ""

    second_window = query_task_groups(
        index,
        q="cached query",
        lifecycle=[],
        analysis=[],
        tag="",
        vuln_id="",
        component="",
        assignee="",
        dependency=[],
        versions=[],
        cvss_mismatch=False,
        attributed_before_days=None,
        attribution_mode="older",
        tmrescore=[],
        tmrescore_proposal_ids=[],
        sort_by="id",
        sort_order="asc",
        offset=1,
        limit=1,
    )

    assert [item["id"] for item in second_window["items"]] == ["CVE-2026-B"]
    assert second_window["filtered"] == 2


def test_task_group_query_supports_opaque_cursor_windows():
    groups = [
        {
            "id": f"CVE-2026-CURSOR-{index}",
            "title": "Cursor query finding",
            "tags": [],
            "aliases": [],
            "assignees": [],
            "list_metadata": {
                "lifecycle": "OPEN",
                "is_open": True,
                "is_pending": False,
                "technical_state": "NOT_SET",
                "component_names": [f"library-{index}"],
                "versions": ["1.0.0"],
                "dependency_relationship": "DIRECT",
                "cvss_version_mismatch": False,
            },
            "affected_versions": [],
        }
        for index in range(3)
    ]
    index = build_task_group_query_index(groups)

    first_window = query_task_groups(
        index,
        q="cursor query",
        lifecycle=[],
        analysis=[],
        tag="",
        vuln_id="",
        component="",
        assignee="",
        dependency=[],
        versions=[],
        cvss_mismatch=False,
        attributed_before_days=None,
        attribution_mode="older",
        tmrescore=[],
        tmrescore_proposal_ids=[],
        sort_by="id",
        sort_order="asc",
        offset=0,
        limit=2,
    )

    assert first_window["offset"] == 0
    assert first_window["has_more"] is True
    assert decode_task_group_cursor(first_window["next_cursor"]) == 2

    second_window = query_task_groups(
        index,
        q="cursor query",
        lifecycle=[],
        analysis=[],
        tag="",
        vuln_id="",
        component="",
        assignee="",
        dependency=[],
        versions=[],
        cvss_mismatch=False,
        attributed_before_days=None,
        attribution_mode="older",
        tmrescore=[],
        tmrescore_proposal_ids=[],
        sort_by="id",
        sort_order="asc",
        offset=0,
        limit=2,
        cursor=first_window["next_cursor"],
    )

    assert second_window["offset"] == 2
    assert second_window["next_cursor"] is None
    assert second_window["has_more"] is False
    assert [item["id"] for item in second_window["items"]] == ["CVE-2026-CURSOR-2"]


def test_task_group_query_rejects_invalid_cursor():
    index = build_task_group_query_index([])

    try:
        query_task_groups(
            index,
            q="",
            lifecycle=[],
            analysis=[],
            tag="",
            vuln_id="",
            component="",
            assignee="",
            dependency=[],
            versions=[],
            cvss_mismatch=False,
            attributed_before_days=None,
            attribution_mode="older",
            tmrescore=[],
            tmrescore_proposal_ids=[],
            sort_by="id",
            sort_order="asc",
            offset=0,
            limit=1,
            cursor="not-a-cursor",
        )
    except ValueError as exc:
        assert str(exc) == "Invalid task group cursor"
    else:
        raise AssertionError("Invalid cursors should be rejected")
