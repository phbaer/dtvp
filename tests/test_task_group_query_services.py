import threading
import time
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

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


def test_group_window_query_enforces_task_ownership_and_returns_local_items():
    groups = [_group(1)]
    task = {
        "_owner": "alice",
        "status": "completed",
        "result_mode": "summary",
        "result": groups,
    }
    deps = SimpleNamespace(
        tasks={"task-1": task},
        code_analysis_result_store=None,
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
    response["items"][0]["title"] = "request-local change"
    assert groups[0]["title"] == "Concurrent finding 1"
