import threading
import time
from array import array
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

from dtvp import general_api_routes
from dtvp import task_group_query_services as query_services
from dtvp.general_api_routes import _query_task_group_window, _task_for_user


def _group(index: int) -> dict:
    return {
        "id": f"CVE-2026-{index:04d}",
        "title": f"Concurrent finding {index}",
        "aliases": [],
        "tags": [],
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


def _query(index: dict, **overrides) -> dict:
    options = {
        "q": "finding",
        "lifecycle": [],
        "inconsistency_reason": [],
        "analysis": [],
        "tag": "",
        "team": "",
        "vuln_id": "",
        "component": "",
        "assignee": "",
        "dependency": [],
        "versions": [],
        "cvss_mismatch": False,
        "attributed_before_days": None,
        "attribution_mode": "older",
        "tmrescore": [],
        "tmrescore_proposal_ids": [],
        "automatic_assessment": [],
        "automatic_assessment_ids": [],
        "sort_by": "id",
        "sort_order": "asc",
        "offset": 0,
        "limit": 25,
    }
    options.update(overrides)
    return query_services.query_task_groups(index, **options)


def test_identical_concurrent_queries_share_one_computation(monkeypatch):
    groups = [_group(index) for index in range(100)]
    query_index = query_services.build_task_group_query_index(groups)
    original_matcher = query_services._matches_task_group_fields
    call_count = 0
    count_lock = threading.Lock()

    def counting_matcher(*args, **kwargs):
        nonlocal call_count
        with count_lock:
            call_count += 1
            first_call = call_count == 1
        if first_call:
            time.sleep(0.05)
        return original_matcher(*args, **kwargs)

    monkeypatch.setattr(
        query_services,
        "_matches_task_group_fields",
        counting_matcher,
    )

    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(_query, query_index)
        second = executor.submit(_query, query_index)
        first_result = first.result()
        second_result = second.result()

    assert call_count == len(groups)
    assert first_result == second_result


def test_unfiltered_queries_reuse_the_same_sort_order(monkeypatch):
    groups = [_group(index) for index in range(100)]
    query_index = query_services.build_task_group_query_index(groups)
    original_sort_key = query_services._task_group_sort_key
    call_count = 0
    count_lock = threading.Lock()

    def counting_sort_key(row, sort_by):
        nonlocal call_count
        with count_lock:
            call_count += 1
            first_call = call_count == 1
        if first_call:
            time.sleep(0.05)
        return original_sort_key(row, sort_by)

    monkeypatch.setattr(
        query_services,
        "_task_group_sort_key",
        counting_sort_key,
    )

    with ThreadPoolExecutor(max_workers=2) as executor:
        first_request = executor.submit(
            _query,
            query_index,
            q="",
            tmrescore_proposal_ids=["CVE-2026-0001"],
        )
        second_request = executor.submit(
            _query,
            query_index,
            q="",
            tmrescore_proposal_ids=["CVE-2026-0002"],
        )
        first = first_request.result()
        second = second_request.result()

    assert call_count == len(groups)
    assert [item["id"] for item in first["items"]] == [
        item["id"] for item in second["items"]
    ]


def test_countless_page_reuses_full_query_cache_entry():
    query_index = query_services.build_task_group_query_index(
        [_group(index) for index in range(3)]
    )

    first = _query(query_index, offset=0, limit=1)
    second = _query(
        query_index,
        offset=1,
        limit=1,
        include_counts=False,
    )

    assert "counts" in first
    assert "counts" not in second
    assert len(query_index["query_cache"]) == 1


def test_full_query_upgrades_countless_cached_filter():
    query_index = query_services.build_task_group_query_index(
        [_group(index) for index in range(3)]
    )

    countless = _query(query_index, include_counts=False)
    counted = _query(query_index, include_counts=True)

    assert "counts" not in countless
    assert counted["counts"]["filtered"]["total"] == 3
    assert len(query_index["query_cache"]) == 1


def test_group_window_reuses_dynamic_context_until_metadata_changes(monkeypatch):
    class ResultStore:
        revision = 1

        def get_assessment_metadata_revision(self):
            return self.revision

        def list_assessment_metadata(self, *, project_name=None):
            return {
                "records": [],
                "stored_analysis_results": 0,
                "usable_assessment_results": 0,
            }

    store = ResultStore()
    task = {
        "status": "completed",
        "result_mode": "summary",
        "result": [_group(1)],
    }
    deps = SimpleNamespace(
        code_analysis_result_store=store,
        logger=SimpleNamespace(warning=lambda *_args, **_kwargs: None),
        load_team_mapping=lambda: {},
        load_team_groups=lambda: {},
    )
    facet_builds = 0
    original = general_api_routes._automatic_assessment_filter_facets

    def count_facet_builds(*args, **kwargs):
        nonlocal facet_builds
        facet_builds += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(
        general_api_routes,
        "_automatic_assessment_filter_facets",
        count_facet_builds,
    )
    options = {
        "q": "",
        "lifecycle": [],
        "inconsistency_reason": [],
        "analysis": [],
        "tag": "",
        "team": "",
        "vuln_id": "",
        "component": "",
        "assignee": "",
        "dependency": [],
        "versions": [],
        "cvss_mismatch": False,
        "attributed_before_days": None,
        "attribution_mode": "older",
        "tmrescore": [],
        "tmrescore_proposal_ids": [],
        "automatic_assessment": [],
        "automatic_assessment_ids": [],
        "sort_by": "id",
        "sort_order": "asc",
        "offset": 0,
        "limit": 25,
        "cursor": "",
    }

    _query_task_group_window(deps, task, options)
    _query_task_group_window(deps, task, {**options, "q": "finding"})
    store.revision += 1
    _query_task_group_window(deps, task, options)

    assert facet_builds == 2


def test_query_cache_uses_packed_indices_and_entry_budget(monkeypatch):
    monkeypatch.setenv("DTVP_GROUP_QUERY_CACHE_ENTRIES", "2")
    monkeypatch.setenv("DTVP_GROUP_QUERY_CACHE_BYTES", "1000000")
    query_index = query_services.build_task_group_query_index(
        [_group(index) for index in range(10)]
    )

    _query(query_index, q="library-0")
    _query(query_index, q="library-1")
    _query(query_index, q="library-0")
    _query(query_index, q="library-2")

    assert len(query_index["query_cache"]) == 2
    assert {key[0] for key in query_index["query_cache"]} == {
        "library-0",
        "library-2",
    }
    assert all(
        isinstance(entry["indices"], array)
        for entry in query_index["query_cache"].values()
    )


def test_query_cache_evicts_old_entries_over_byte_budget(monkeypatch):
    monkeypatch.setenv("DTVP_GROUP_QUERY_CACHE_ENTRIES", "32")
    monkeypatch.setenv("DTVP_GROUP_QUERY_CACHE_BYTES", "1")
    query_index = query_services.build_task_group_query_index(
        [_group(index) for index in range(10)]
    )

    _query(query_index, q="library-1")
    _query(query_index, q="library-2")

    assert len(query_index["query_cache"]) == 1


def test_automatic_assessment_outcome_and_rescore_facets_filter_and_count():
    groups = [_group(index) for index in range(1, 5)]
    query_index = query_services.build_task_group_query_index(groups)
    facets = {
        "cve-2026-0001": {"outcome": "AFFECTED", "rescore": "LOW"},
        "cve-2026-0002": {"outcome": "PROBABLY_AFFECTED", "rescore": "HIGH"},
        "cve-2026-0003": {"outcome": "NOT_AFFECTED", "rescore": "NO_RESCORE"},
    }

    response = _query(
        query_index,
        q="",
        automatic_assessment_ids=list(facets),
        automatic_assessment_outcome=["AFFECTED", "PROBABLY_AFFECTED"],
        automatic_assessment_rescore=["LOW"],
        automatic_assessment_facets=facets,
    )

    assert [item["id"] for item in response["items"]] == ["CVE-2026-0001"]
    assert response["counts"]["all"]["automatic_assessment_outcome"] == {
        "AFFECTED": 1,
        "PROBABLY_AFFECTED": 1,
        "NOT_AFFECTED": 1,
        "INCONCLUSIVE": 0,
    }
    assert response["counts"]["all"]["automatic_assessment_rescore"] == {
        "CRITICAL": 0,
        "HIGH": 1,
        "MEDIUM": 0,
        "LOW": 1,
        "INFO": 0,
        "NO_RESCORE": 1,
        "UNSCORED": 0,
    }


def test_team_alias_counts_are_grouped_without_duplicate_vulnerabilities():
    canonical_and_alias = _group(1)
    canonical_and_alias["tags"] = ["Platform Security", "Platform"]
    alias_only_assessed = _group(2)
    alias_only_assessed["tags"] = ["Platform"]
    alias_only_assessed["list_metadata"]["is_open"] = False
    other_team = _group(3)
    other_team["tags"] = ["Runtime"]
    query_index = query_services.build_task_group_query_index(
        [canonical_and_alias, alias_only_assessed, other_team]
    )

    response = _query(
        query_index,
        q="",
        team_aliases={
            "platform security": "Platform Security",
            "platform": "Platform Security",
            "runtime": "Runtime",
        },
    )

    assert response["counts"]["all"]["team_tags"] == {
        "Platform Security": {"open": 1, "assessed": 0},
        "Platform": {"open": 1, "assessed": 1},
        "Runtime": {"open": 1, "assessed": 0},
    }
    assert response["counts"]["all"]["canonical_team_tags"] == {
        "Platform Security": {"open": 1, "assessed": 1},
        "Runtime": {"open": 1, "assessed": 0},
    }


def test_team_group_counts_include_subteams_without_duplicate_vulnerabilities():
    parent_and_subteam = _group(1)
    parent_and_subteam["tags"] = ["Core-MUC", "Third Party Legacy"]
    subteam_assessed = _group(2)
    subteam_assessed["tags"] = ["3rd Party"]
    subteam_assessed["list_metadata"]["is_open"] = False
    runtime = _group(3)
    runtime["tags"] = ["Runtime"]
    query_index = query_services.build_task_group_query_index(
        [parent_and_subteam, subteam_assessed, runtime]
    )

    response = _query(
        query_index,
        q="",
        team_aliases={
            "core-muc": "Core-MUC",
            "3rd party": "3rd Party",
            "third party legacy": "3rd Party",
            "runtime": "Runtime",
        },
        team_groups={
            "Core-MUC": ["Core-MUC", "3rd Party"],
            "Product Engineering": ["Core-MUC", "3rd Party", "Runtime"],
        },
        team_group_structure={
            "Core-MUC": {
                "teams": ["Core-MUC", "3rd Party"],
                "groups": [],
            },
            "Product Engineering": {
                "teams": ["Runtime"],
                "groups": ["Core-MUC"],
            },
        },
    )

    assert response["counts"]["all"]["team_groups"] == {
        "Core-MUC": {"open": 1, "assessed": 1},
        "Product Engineering": {"open": 2, "assessed": 1},
    }
    assert response["counts"]["all"]["team_group_structure"] == {
        "Core-MUC": {
            "teams": ["Core-MUC", "3rd Party"],
            "groups": [],
        },
        "Product Engineering": {
            "teams": ["Runtime"],
            "groups": ["Core-MUC"],
        },
    }
    assert response["counts"]["all"]["canonical_team_tags"] == {
        "Core-MUC": {"open": 1, "assessed": 0},
        "3rd Party": {"open": 1, "assessed": 1},
        "Runtime": {"open": 1, "assessed": 0},
    }


def test_group_window_query_enforces_task_ownership_and_returns_local_items():
    groups = [_group(1)]
    groups[0]["tags"] = ["Core-MUC"]
    task = {
        "_owner": "alice",
        "status": "completed",
        "result_mode": "summary",
        "result": groups,
    }
    deps = SimpleNamespace(
        tasks={"task-1": task},
        code_analysis_result_store=None,
        logger=SimpleNamespace(warning=lambda *_args, **_kwargs: None),
        load_team_mapping=lambda: {
            "core-component": "Core-MUC",
            "vendor-component": "3rd Party",
        },
        load_team_groups=lambda: {
            "Core-MUC": {
                "teams": ["Core-MUC", "3rd Party"],
                "groups": [],
            },
        },
    )

    assert _task_for_user(deps, "task-1", "alice") is task
    assert _task_for_user(deps, "task-1", "bob") is None

    response = _query_task_group_window(
        deps,
        task,
        {
            "q": "",
            "lifecycle": [],
            "inconsistency_reason": [],
            "analysis": [],
            "tag": "",
            "team": "",
            "vuln_id": "",
            "component": "",
            "assignee": "",
            "dependency": [],
            "versions": [],
            "cvss_mismatch": False,
            "attributed_before_days": None,
            "attribution_mode": "older",
            "tmrescore": [],
            "tmrescore_proposal_ids": [],
            "automatic_assessment": [],
            "automatic_assessment_ids": [],
            "sort_by": "id",
            "sort_order": "asc",
            "offset": 0,
            "limit": 25,
            "cursor": "",
        },
    )

    assert response["items"][0] is not groups[0]
    assert response["counts"]["filtered"]["team_groups"]["Core-MUC"] == {
        "open": 1,
        "assessed": 0,
    }
    assert response["counts"]["filtered"]["team_group_structure"] == {
        "Core-MUC": {
            "teams": ["Core-MUC", "3rd Party"],
            "groups": [],
        },
    }
    response["items"][0]["title"] = "request-local change"
    assert groups[0]["title"] == "Concurrent finding 1"
