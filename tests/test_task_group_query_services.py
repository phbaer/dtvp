import threading
import time
from array import array
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

from dtvp import general_api_routes
from dtvp import task_group_query_services as query_services
from dtvp.general_api_routes import _query_task_group_window, _task_for_user
from dtvp.ssvc_enrichment_services import SOURCES, SsvcEnrichmentService


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


def test_visible_lifecycle_categories_partition_results_and_include_legacy():
    states = ["OPEN", "INCOMPLETE", "INCONSISTENT", "NEEDS_APPROVAL", "ASSESSED", "ASSESSED_LEGACY"]
    groups = []
    for number, state in enumerate(states):
        group = _group(number)
        group["list_metadata"].update({
            "lifecycle": state,
            "is_pending": state in {"INCOMPLETE", "INCONSISTENT", "NEEDS_APPROVAL"},
            "is_approval_ready": state == "NEEDS_APPROVAL",
        })
        groups.append(group)
    index = query_services.build_task_group_query_index(groups)
    categories = ["OPEN", "INCOMPLETE", "INCONSISTENT", "READY_FOR_APPROVAL", "ASSESSED"]
    all_counts = _query(index)["counts"]["all"]["lifecycle"]
    assert sum(all_counts[category] for category in categories) == len(groups)
    seen = []
    for category in categories:
        result = _query(index, lifecycle=[category])
        assert result["filtered"] == all_counts[category]
        seen.extend(item["id"] for item in result["items"])
    assert len(seen) == len(set(seen)) == len(groups)
    assert all_counts["ASSESSED"] == 2


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


def test_evidence_filters_counts_bulk_and_cache_invalidation(tmp_path, monkeypatch):
    now = [1_800_000_000.0]
    service = SsvcEnrichmentService(str(tmp_path / "sources.sqlite3"), clock=lambda: now[0])
    monkeypatch.setattr(query_services, "get_ssvc_enrichment_service", lambda: service)
    groups = [_group(i) for i in range(4)]
    groups[0].update(id="GHSA-alias", aliases=["CVE-2026-1000", "CVE-2026-1000"])
    index = query_services.build_task_group_query_index(groups)
    assert _query(index, evidence=["KEV"])["filtered"] == 0
    service._cache("kev", {"checked": now[0], "data": {"CVE-2026-1000": {"value": "A"}}})
    service._cache(groups[1]["id"], {"checked": now[0], "data": {"value": "N"}})
    service._cache(groups[2]["id"], {"checked": now[0], "data": None})
    result = _query(index, evidence=["kev", "CISA_SSVC"], limit=1)
    assert result["filtered"] == 2
    assert result["items"][0]["id"] == groups[1]["id"]
    assert result["items"][0]["evidence_sources"] == ["CISA_SSVC"]
    assert result["counts"]["all"]["evidence"] == {
        "KEV": 1, "CISA_SSVC": 1, "NOT_CHECKED": 2, "NO_DATA": 1,
        "STALE": 0, "UNAVAILABLE": 0, "NO_CVE": 0,
    }
    assert result["counts"]["filtered"]["evidence"]["NO_DATA"] == 0
    assert _query(index, evidence=["KEV"], ssvc=["UNASSESSED"])["filtered"] == 1
    assert _query(index, evidence=["KEV"], ssvc=["IMMEDIATE"])["filtered"] == 0
    assert _query(index, evidence=["KEV", "CISA_SSVC"], offset=1)["items"][0]["id"] == groups[0]["id"]
    assert "evidence_sources" not in groups[0]
    bulk = general_api_routes._filter_bulk_workflow_groups(
        index, general_api_routes.BulkWorkflowFilters(evidence=["KEV", "CISA_SSVC"])
    )
    assert {item["id"] for item in bulk} == {groups[0]["id"], groups[1]["id"]}
    now[0] += SOURCES["kev"]["ttl_seconds"]
    assert _query(index, evidence=["NO_DATA"])["filtered"] == 0
    assert _query(index, evidence=["KEV"])["items"][0]["evidence_sources"] == ["KEV", "NOT_CHECKED", "STALE"]
    service._cache(groups[3]["id"], {"checked": now[0], "data": {"value": "P"}})
    assert _query(index, evidence=["CISA_SSVC"])["filtered"] == 2


def test_original_severity_and_ssvc_facets_filter_before_pagination_and_cache():
    groups = [
        {**_group(1), "cvss_score": 9.8, "severity": "LOW", "rescored_cvss": 1, "ssvc_summary": {"status": "IMMEDIATE"}},
        {**_group(2), "original_severity": "HIGH", "ssvc_summary": {"status": "SCHEDULED"}},
        {**_group(3), "cvss_score": 0},
    ]
    index = query_services.build_task_group_query_index(groups)
    first = _query(index, original_severity=["critical", "HIGH"], ssvc=["IMMEDIATE"], limit=1)
    assert [group["id"] for group in first["items"]] == [groups[0]["id"]]
    assert first["filtered"] == 1
    assert first["counts"]["all"]["original_severity"]["INFO"] == 1
    assert first["counts"]["filtered"]["ssvc"]["IMMEDIATE"] == 1
    assert first["counts"]["filtered"]["original_severity"]["CRITICAL"] == 1
    second = _query(index, original_severity=["INFO"], ssvc=["UNASSESSED"])
    assert [group["id"] for group in second["items"]] == [groups[2]["id"]]
    assert _query(index, original_severity=["LOW"])["filtered"] == 0
    assert _query(index)["total"] == 3


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


def test_full_query_upgrades_countless_cached_filter(monkeypatch):
    query_index = query_services.build_task_group_query_index(
        [_group(index) for index in range(3)]
    )
    original_matcher = query_services._matches_task_group_fields
    call_count = 0

    def counting_matcher(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        return original_matcher(*args, **kwargs)

    monkeypatch.setattr(
        query_services,
        "_matches_task_group_fields",
        counting_matcher,
    )

    countless = _query(query_index, include_counts=False)
    counted = _query(query_index, include_counts=True)

    assert "counts" not in countless
    assert counted["counts"]["filtered"]["total"] == 3
    assert call_count == 3
    assert len(query_index["query_cache"]) == 1


def test_exact_team_filter_only_evaluates_indexed_candidates(monkeypatch):
    groups = [_group(index) for index in range(100)]
    for index, group in enumerate(groups):
        group["tags"] = ["Platform"] if index % 10 == 0 else ["Runtime"]
    query_index = query_services.build_task_group_query_index(groups)
    original_matcher = query_services._matches_task_group_fields
    call_count = 0

    def counting_matcher(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        return original_matcher(*args, **kwargs)

    monkeypatch.setattr(
        query_services,
        "_matches_task_group_fields",
        counting_matcher,
    )

    result = _query(query_index, q="", team="platform")

    assert result["filtered"] == 10
    assert all(item["tags"] == ["Platform"] for item in result["items"])
    assert call_count == 10


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


def test_incomplete_is_global_with_any_team_coverage_and_counts_are_stable():
    groups = [_group(i) for i in range(3)]
    for group, assessed in zip(groups, [["Team A"], ["Team B"], ["Team A", "Team B"]]):
        group["tags"] = ["Team A", "Team B", "Alias A"]
        group["list_metadata"].update(lifecycle="INCOMPLETE", assessed_teams=assessed)
    index = query_services.build_task_group_query_index(groups)
    for scope in [{"team": "Team A"}, {"tag": "Alias"}, {"tag": "Team A"}, {"q": "Team A"}]:
        def query(coverage):
            return _query(index, lifecycle=["INCOMPLETE"], team_assessment=coverage,
                          team_aliases={"alias a": "Team A"}, **scope)
        initial = query("ANY")
        assert initial["filtered"] == 3
        assert initial["counts"]["all"]["lifecycle"]["INCOMPLETE"] == 3
        assert initial["counts"]["filtered"]["lifecycle"]["INCOMPLETE"] == 3
        assert query("MISSING")["filtered"] == (1 if "team" in scope else 3)
        assert query("DOCUMENTED")["filtered"] == (2 if "team" in scope else 3)
        assert query("ANY") == initial
    bulk = general_api_routes._filter_bulk_workflow_groups(
        index, general_api_routes.BulkWorkflowFilters(team="Team A", lifecycle=["INCOMPLETE"])
    )
    assert [item["id"] for item in bulk] == [group["id"] for group in groups]


def test_plain_team_search_does_not_change_incomplete_lifecycle():
    groups = [_group(i) for i in range(3)]
    for group in groups:
        group["tags"] = ["Security", "Platform"]
        group["list_metadata"].update(lifecycle="INCOMPLETE", assessed_teams=["Security"])
    groups[1]["list_metadata"]["assessed_teams"] = ["Platform"]
    groups[2]["tags"] = ["Other"]
    groups[2]["title"] = "Security issue"
    index = query_services.build_task_group_query_index(groups)
    result = _query(index, q="Security", lifecycle=["INCOMPLETE"])
    assert result["filtered"] == 3
    assert result["counts"]["filtered"]["lifecycle"]["INCOMPLETE"] == 3
    assert _query(index, q="Security", lifecycle=["INCOMPLETE"], team_assessment="MISSING")["filtered"] == 3


def test_team_documentation_is_independent_of_lifecycle_and_pagination():
    groups = [_group(i) for i in range(6)]
    for group, lifecycle in zip(groups, ["INCOMPLETE", "NEEDS_APPROVAL", "INCONSISTENT", "OPEN", "ASSESSED", "ASSESSED_LEGACY"]):
        group["tags"] = ["Security", "Platform", "Sec"]
        group["list_metadata"].update(
            lifecycle=lifecycle, assessed_teams=["Security"], is_pending=True,
        )
    groups[3]["list_metadata"]["assessed_teams"] = []
    groups[4]["list_metadata"]["assessed_teams"] = ["Security", "Platform"]
    groups[5]["tags"] = ["Unassigned"]
    groups[5]["list_metadata"]["assessed_teams"] = []
    index = query_services.build_task_group_query_index(groups)
    aliases = {"sec": "Security"}
    def query(**kwargs):
        return _query(index, team_aliases=aliases, **kwargs)

    result = query(team="Security", team_assessment="DOCUMENTED", limit=2)
    assert result["filtered"] == 4
    assert result["counts"]["filtered"]["team_assessment"] == {"MISSING": 0, "DOCUMENTED": 4}
    assert result["counts"]["all"]["team_assessment"] == {"MISSING": 1, "DOCUMENTED": 4}
    assert [item["id"] for item in result["items"]] == [groups[0]["id"], groups[1]["id"]]
    next_page = query(team="Security", team_assessment="DOCUMENTED", cursor=result["next_cursor"], limit=2)
    assert [item["id"] for item in next_page["items"]] == [groups[2]["id"], groups[4]["id"]]
    assert query(team="Security", team_assessment="DOCUMENTED", lifecycle=["INCOMPLETE"])["filtered"] == 1
    assert query(q="Security", team_assessment="DOCUMENTED")["filtered"] == 5
    assert query(tag="Sec", team_assessment="DOCUMENTED")["filtered"] == 5
    assert query(team="Security", team_assessment="MISSING")["filtered"] == 1
    assert query(team="Platform", team_assessment="MISSING")["filtered"] == 4
    assert query(teams=["Security", "Platform"], team_assessment="DOCUMENTED")["filtered"] == 1
    assert query(team_assessment="DOCUMENTED")["filtered"] == 6
    assert query(team="Unassigned", team_assessment="DOCUMENTED")["filtered"] == 0
    assert query(team="Unassigned", team_assessment="ANY")["filtered"] == 1
    assert query(team="Security", team_assessment="ANY")["filtered"] == 5
    assert query(team="Security", lifecycle=["INCOMPLETE"])["filtered"] == 1
    bulk = general_api_routes._filter_bulk_workflow_groups(
        index, general_api_routes.BulkWorkflowFilters(teams=["Security"], team_assessment="DOCUMENTED"),
        team_aliases=aliases,
    )
    assert [item["id"] for item in bulk] == [groups[i]["id"] for i in [0, 1, 2, 4]]


def test_multiple_teams_use_only_responsible_teams_and_bulk_matches():
    groups = [_group(i) for i in range(4)]
    for group, tags, assessed in zip(groups,
        [["Sec"], ["Platform"], ["Security", "Platform"], ["Other"]],
        [["Security"], [], ["Security"], []],
    ):
        group["tags"] = tags
        group["list_metadata"].update(lifecycle="INCOMPLETE", assessed_teams=assessed)
    index = query_services.build_task_group_query_index(groups)
    options = dict(teams=["SECURITY", "Platform"], team_aliases={"sec": "Security"})
    recorded = _query(index, **options, team_assessment="DOCUMENTED")
    assert [item["id"] for item in recorded["items"]] == [groups[0]["id"]]
    missing = _query(index, **options, team_assessment="MISSING")
    assert [item["id"] for item in missing["items"]] == [groups[1]["id"], groups[2]["id"]]
    assert recorded["counts"]["facets"]["team_assessment"] == {"MISSING": 2, "DOCUMENTED": 1}
    bulk = general_api_routes._filter_bulk_workflow_groups(index,
        general_api_routes.BulkWorkflowFilters(teams=options["teams"], team_assessment="DOCUMENTED"),
        team_aliases=options["team_aliases"],
    )
    assert [item["id"] for item in bulk] == [groups[0]["id"]]
    assert _query(index, **options, team_assessment="DOCUMENTED") == recorded


def test_facet_counts_exclude_own_filter_and_preserve_other_filters():
    groups = [_group(i) for i in range(3)]
    for group, team, lifecycle, assessed in zip(groups,
        ["Security", "Security", "Platform"],
        ["OPEN", "INCOMPLETE", "INCOMPLETE"],
        [[], ["Security"], []],
    ):
        group["tags"] = [team]
        group["list_metadata"].update(lifecycle=lifecycle, assessed_teams=assessed)
    index = query_services.build_task_group_query_index(groups)
    result = _query(index, teams=["Security"], lifecycle=["INCOMPLETE"], team_assessment="MISSING")
    assert result["filtered"] == 0
    facets = result["counts"]["facets"]
    assert facets["lifecycle"]["OPEN"] == 1
    assert facets["lifecycle"]["INCOMPLETE"] == 0
    assert facets["team_assessment"] == {"MISSING": 0, "DOCUMENTED": 1}
    assert facets["dependency_relationship"]["direct"] == 0
