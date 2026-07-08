from types import SimpleNamespace

import dtvp.auto_analysis_services as auto_analysis_services
from dtvp.auto_analysis_services import (
    AutoAnalysisSweepDeps,
    apply_auto_analysis_sweep_plan,
    build_auto_analysis_context_fingerprint,
    build_existing_open_vulnerability_sweep_plan,
    build_auto_analysis_queue_plan,
    get_component_auto_analysis_guidance,
    is_open_for_auto_analysis,
    queue_existing_open_vulnerabilities_for_analysis,
    queue_open_vulnerabilities_for_analysis,
    select_auto_analysis_targets,
)
from dtvp.logic import BOMAnalysisCache, group_vulnerabilities
from dtvp.vulnerability_support_services import merge_vulnerability_details


class FakeAnalysisQueue:
    def __init__(self):
        self.items = {}
        self.submissions = []
        self.cancelled = []
        self._next_id = 1

    def submit_once(self, **kwargs):
        key = (
            kwargs["vuln_id"].strip().lower(),
            kwargs["component_name"].strip().lower(),
        )
        duplicate_statuses = kwargs.get(
            "duplicate_statuses",
            ("queued", "running", "completed", "failed"),
        )
        if key in self.items and self.items[key].status in duplicate_statuses:
            return self.items[key], False

        item = SimpleNamespace(
            queue_id=f"queue-{self._next_id}",
            status="queued",
            position=0,
            **kwargs,
        )
        self._next_id += 1
        self.items[key] = item
        self.submissions.append(kwargs)
        return item, True

    def list_all(self):
        return list(self.items.values())

    def cancel(self, queue_id):
        for item in self.items.values():
            if item.queue_id != queue_id or item.status != "queued":
                continue
            item.status = "cancelled"
            self.cancelled.append(queue_id)
            return True
        return False

    def remove_finished(self, queue_id):
        for key, item in list(self.items.items()):
            if item.queue_id != queue_id or item.status in ("queued", "running"):
                continue
            del self.items[key]
            return True
        return False


class FakeCacheManager:
    def __init__(self, cached_projects=None, snapshots=None, live_projects=None):
        self.cached_projects = cached_projects or []
        self.snapshots = snapshots or {}
        self.live_projects = live_projects or []

    async def get_projects(self, _client, name=""):
        assert name == ""
        return self.live_projects

    def get_cached_project_versions(self):
        return self.cached_projects

    def get_cached_project_snapshot(self, project_uuid):
        return self.snapshots.get(project_uuid)


class FakeLogger:
    def __init__(self):
        self.exceptions = []

    def exception(self, *args):
        self.exceptions.append(args)


class FakeResultStore:
    def __init__(self, fingerprints=None):
        self.fingerprints = set(fingerprints or [])
        self.calls = []

    def find_latest(self, **kwargs):
        self.calls.append(kwargs)
        if kwargs.get("context_fingerprint") in self.fingerprints:
            return {"analysis_run_id": "run-1"}
        return None


def queue_grouped_with_fake_queue(queue):
    def queue_grouped(
        grouped,
        team_mapping,
        handled_vulnerability_ids=None,
        auto_analysis_guidance=None,
    ):
        return queue_open_vulnerabilities_for_analysis(
            analysis_queue=queue,
            grouped_vulns=grouped,
            team_mapping=team_mapping,
            enabled=True,
            handled_vulnerability_ids=handled_vulnerability_ids,
            auto_analysis_guidance=auto_analysis_guidance,
        )

    return queue_grouped


def make_group(component_name="lib-a", state="NOT_SET", details="", **overrides):
    group = {
        "id": "CVE-2026-0001",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "tags": [],
        "affected_versions": [
            {
                "project_name": "ExampleApp",
                "project_version": "1.0.0",
                "components": [
                    {
                        "project_name": "ExampleApp",
                        "component_name": component_name,
                        "component_version": "1.0.0",
                        "analysis_state": state,
                        "analysis_details": details,
                        "dependency_chains": [],
                    }
                ],
            }
        ],
    }
    group.update(overrides)
    return group


def test_select_auto_analysis_targets_prefers_direct_team_mapped_component():
    group = make_group(component_name="team-lib")

    targets = select_auto_analysis_targets(group, {"team-lib": "TeamA"})

    assert len(targets) == 1
    assert targets[0].component_name == "team-lib"
    assert targets[0].team == "TeamA"


def test_auto_analysis_guidance_includes_tmrescore_proposal_context():
    group = make_group(component_name="team-lib")

    plan = build_auto_analysis_queue_plan(
        grouped_vulns=[group],
        team_mapping={"team-lib": "TeamA"},
        enabled=True,
        tmrescore_project_cache={
            "ExampleApp": {
                "proposals": {
                    "CVE-2026-0001": {
                        "analysis": {
                            "detail": "LLM found compensating controls.",
                            "state": "NOT_AFFECTED",
                            "justification": "CODE_NOT_REACHABLE",
                            "response": [{"detail": "No reachable call path"}],
                        },
                        "original_score": 9.8,
                        "rescored_score": 4.2,
                        "original_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        "rescored_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
                        "cwe_descriptions": {"CWE-79": "XSS"},
                        "affected_refs": ["component-1"],
                    }
                }
            }
        },
    )

    assert len(plan.candidates) == 1
    guidance = plan.candidates[0].user_guidance
    assert "TMRescore/vscorer guidance" in guidance
    assert "LLM found compensating controls" in guidance
    assert "Suggested justification: CODE_NOT_REACHABLE" in guidance
    assert "Score guidance: 9.8 -> 4.2" in guidance
    assert "CWE-79" in guidance


def test_component_auto_analysis_guidance_matches_component_selectors():
    group = make_group(component_name="keycloak-extension")
    config = {
        "default": "Always confirm runtime reachability.",
        "components": {
            "Keycloak-Extension": {
                "guidance": [
                    "This service extends Keycloak.",
                    "Check whether the platform package is affected too.",
                ],
            }
        },
    }
    target = auto_analysis_services.AutoAnalysisTarget(
        "keycloak-extension",
        "TeamA",
    )

    guidance = get_component_auto_analysis_guidance(
        config,
        group,
        target,
    )

    assert "Always confirm runtime reachability" in guidance
    assert "This service extends Keycloak" in guidance
    assert "platform package" in guidance


def test_component_auto_analysis_guidance_uses_group_qualified_selector():
    group = make_group(component_name="core")
    group["affected_versions"][0]["components"][0]["component_group"] = "@angular"
    config = {
        "components": {
            "core": "Plain core guidance should not match a grouped component.",
            "@angular:core": "Angular core guidance.",
        },
    }
    target = auto_analysis_services.AutoAnalysisTarget("core", "Frontend")

    guidance = get_component_auto_analysis_guidance(
        config,
        group,
        target,
    )

    assert guidance == "Angular core guidance."


def test_component_auto_analysis_guidance_ignores_legacy_project_entries():
    group = make_group(component_name="team-lib")
    target = auto_analysis_services.AutoAnalysisTarget("team-lib", "TeamA")

    guidance = get_component_auto_analysis_guidance(
        {
            "projects": {
                "ExampleApp": "Legacy project guidance.",
            }
        },
        group,
        target,
    )

    assert guidance == ""


def test_auto_analysis_guidance_includes_static_component_guidance_and_fingerprints_it():
    group = make_group(component_name="team-lib")
    target = auto_analysis_services.AutoAnalysisTarget("team-lib", "TeamA")

    base_fingerprint = build_auto_analysis_context_fingerprint(
        group,
        target,
        "ExampleApp",
    )
    plan = build_auto_analysis_queue_plan(
        grouped_vulns=[group],
        team_mapping={"team-lib": "TeamA"},
        enabled=True,
        auto_analysis_guidance={
            "components": {
                "team-lib": "This component is a Keycloak extension. Also consider upstream Keycloak exposure.",
            }
        },
    )

    assert len(plan.candidates) == 1
    candidate = plan.candidates[0]
    assert "Component-specific auto-assessment guidance" in candidate.user_guidance
    assert "Keycloak extension" in candidate.user_guidance
    assert "upstream Keycloak" in candidate.user_guidance
    assert candidate.context_fingerprint != base_fingerprint
    assert candidate.context_summary["component_guidance_configured"] is True
    assert candidate.context_summary["component_guidance_fingerprint"]


def test_auto_analysis_guidance_matches_team_mapped_path_target_not_vulnerable_dependency():
    group = make_group(component_name="vulnerable-lib")
    group["affected_versions"][0]["components"][0]["dependency_chains"] = [
        "vulnerable-lib -> owned-service -> app-root"
    ]

    plan = build_auto_analysis_queue_plan(
        grouped_vulns=[group],
        team_mapping={"owned-service": "TeamA"},
        enabled=True,
        auto_analysis_guidance={
            "components": {
                "vulnerable-lib": "Guidance for the vulnerable dependency only.",
                "owned-service": "Guidance for the owned service target.",
            }
        },
    )

    assert len(plan.candidates) == 1
    candidate = plan.candidates[0]
    assert candidate.component_name == "owned-service"
    assert "Guidance for the owned service target" in candidate.user_guidance
    assert "Guidance for the vulnerable dependency only" not in candidate.user_guidance


def test_auto_analysis_guidance_marks_selected_team_mapping_selector():
    group = make_group(component_name="keycloak-core")
    group["affected_versions"][0]["components"][0]["dependency_chains"] = [
        "keycloak-core -> gehc-vp6-keycloak -> app-root"
    ]

    plan = build_auto_analysis_queue_plan(
        grouped_vulns=[group],
        team_mapping={"gehc-vp6-keycloak": "K-Core"},
        enabled=True,
        auto_analysis_guidance={
            "components": {
                "gehc-vp6-keycloak": {
                    "guidance": [
                        "This project extends Keycloak.",
                        "If the extension is not affected, still consider whether upstream Keycloak itself is vulnerable.",
                    ]
                }
            }
        },
    )

    assert len(plan.candidates) == 1
    candidate = plan.candidates[0]
    assert candidate.component_name == "gehc-vp6-keycloak"
    assert candidate.context_summary["target_team_mapping_selector"] == (
        "gehc-vp6-keycloak"
    )
    assert "owned by K-Core" in candidate.user_guidance
    assert "scan target gehc-vp6-keycloak" in candidate.user_guidance
    assert "Selector: gehc-vp6-keycloak." in candidate.user_guidance
    assert "not as evidence" in candidate.user_guidance
    assert "Do not infer dependency presence" in candidate.user_guidance
    assert "This project extends Keycloak." in candidate.user_guidance
    assert "upstream Keycloak itself is vulnerable" in candidate.user_guidance


def test_select_auto_analysis_targets_uses_group_qualified_direct_mapping():
    group = make_group(component_name="core")
    group["affected_versions"][0]["components"][0]["component_group"] = "@angular"

    targets = select_auto_analysis_targets(group, {"@angular:core": "Frontend"})

    assert len(targets) == 1
    assert targets[0].component_name == "core"
    assert targets[0].component_group == "@angular"
    assert targets[0].group_known is True
    assert targets[0].team == "Frontend"


def test_select_auto_analysis_targets_uses_purl_direct_mapping():
    group = make_group(component_name="core")
    group["affected_versions"][0]["components"][0][
        "component_purl"
    ] = "pkg:maven/org.example/core@1.2.3"

    targets = select_auto_analysis_targets(
        group,
        {"purl::pkg:maven/org.example/core": "Platform"},
    )

    assert len(targets) == 1
    assert targets[0].component_name == "core"
    assert targets[0].component_purl == "pkg:maven/org.example/core@1.2.3"
    assert targets[0].team == "Platform"


def test_select_auto_analysis_targets_respects_case_sensitive_mapping():
    lower_group = make_group(component_name="team-lib")
    exact_group = make_group(component_name="Team-Lib")

    assert select_auto_analysis_targets(lower_group, {"cs::Team-Lib": "TeamA"}) == []

    targets = select_auto_analysis_targets(exact_group, {"cs::Team-Lib": "TeamA"})
    assert len(targets) == 1
    assert targets[0].component_name == "Team-Lib"
    assert targets[0].team == "TeamA"


def test_select_auto_analysis_targets_respects_explicit_no_group_mapping():
    no_group = make_group(component_name="core")
    no_group["affected_versions"][0]["components"][0]["component_group"] = None
    grouped = make_group(component_name="core")
    grouped["affected_versions"][0]["components"][0]["component_group"] = "@angular"

    targets = select_auto_analysis_targets(no_group, {"nogroup::core": "Native"})
    assert len(targets) == 1
    assert targets[0].component_name == "core"
    assert targets[0].team == "Native"

    assert select_auto_analysis_targets(grouped, {"nogroup::core": "Native"}) == []


def test_select_auto_analysis_targets_uses_first_mapped_dependency_parent():
    group = make_group(component_name="vulnerable-lib")
    group["affected_versions"][0]["components"][0]["dependency_chains"] = [
        "vulnerable-lib -> service-a -> app-root"
    ]

    targets = select_auto_analysis_targets(group, {"service-a": "TeamA"})

    assert len(targets) == 1
    assert targets[0].component_name == "service-a"
    assert targets[0].team == "TeamA"


def test_select_auto_analysis_targets_does_not_apply_nogroup_to_path_only_parent():
    group = make_group(component_name="vulnerable-lib")
    group["affected_versions"][0]["components"][0]["dependency_chains"] = [
        "vulnerable-lib -> service-a -> app-root"
    ]

    targets = select_auto_analysis_targets(group, {"nogroup::service-a": "TeamA"})

    assert targets == []


def test_select_auto_analysis_targets_allows_cs_and_nogroup_as_groups():
    cs_group = make_group(component_name="core")
    cs_group["affected_versions"][0]["components"][0]["component_group"] = "cs"
    nogroup_group = make_group(component_name="core")
    nogroup_group["affected_versions"][0]["components"][0]["component_group"] = "nogroup"

    assert select_auto_analysis_targets(cs_group, {"cs:core": "CaseGroup"})[0].team == "CaseGroup"
    assert (
        select_auto_analysis_targets(nogroup_group, {"nogroup:core": "NamedGroup"})[0].team
        == "NamedGroup"
    )


def test_open_unassessed_group_is_queued_once():
    group = make_group(component_name="team-lib")
    queue = FakeAnalysisQueue()

    queued = queue_open_vulnerabilities_for_analysis(
        analysis_queue=queue,
        grouped_vulns=[group],
        team_mapping={"team-lib": "TeamA"},
        enabled=True,
    )
    duplicate = queue_open_vulnerabilities_for_analysis(
        analysis_queue=queue,
        grouped_vulns=[group],
        team_mapping={"team-lib": "TeamA"},
        enabled=True,
    )

    assert queued == 1
    assert duplicate == 0
    assert queue.submissions[0]["source"] == "automatic"
    assert queue.submissions[0]["submitted_by"] == "dtvp-auto-analysis"
    assert queue.submissions[0]["component_name"] == "team-lib"
    assert queue.submissions[0]["project_name"] == "ExampleApp"
    assert queue.submissions[0]["context_fingerprint"]
    assert queue.submissions[0]["context_summary"]["project_versions"] == ["1.0.0"]
    assert queue.submissions[0]["affected_product_versions"] == ["1.0.0"]


def test_modified_auto_analysis_guidance_replaces_queued_automatic_item():
    group = make_group(component_name="team-lib")
    queue = FakeAnalysisQueue()

    first = queue_open_vulnerabilities_for_analysis(
        analysis_queue=queue,
        grouped_vulns=[group],
        team_mapping={"team-lib": "TeamA"},
        enabled=True,
        auto_analysis_guidance={
            "components": {"team-lib": "Prefer extension-only reachability."}
        },
    )
    first_item = next(iter(queue.items.values()))
    second = queue_open_vulnerabilities_for_analysis(
        analysis_queue=queue,
        grouped_vulns=[group],
        team_mapping={"team-lib": "TeamA"},
        enabled=True,
        auto_analysis_guidance={
            "components": {"team-lib": "Also consider upstream Keycloak exposure."}
        },
    )

    assert first == 1
    assert second == 1
    assert queue.cancelled == [first_item.queue_id]
    assert len(queue.submissions) == 2
    assert "upstream Keycloak" in queue.submissions[1]["user_guidance"]
    assert (
        queue.submissions[1]["context_fingerprint"]
        != queue.submissions[0]["context_fingerprint"]
    )


def test_modified_auto_analysis_guidance_replaces_finished_automatic_item():
    group = make_group(component_name="team-lib")
    queue = FakeAnalysisQueue()

    queue_open_vulnerabilities_for_analysis(
        analysis_queue=queue,
        grouped_vulns=[group],
        team_mapping={"team-lib": "TeamA"},
        enabled=True,
        auto_analysis_guidance={
            "components": {"team-lib": "Prefer extension-only reachability."}
        },
    )
    first_item = next(iter(queue.items.values()))
    first_item.status = "completed"

    queued = queue_open_vulnerabilities_for_analysis(
        analysis_queue=queue,
        grouped_vulns=[group],
        team_mapping={"team-lib": "TeamA"},
        enabled=True,
        auto_analysis_guidance={
            "components": {"team-lib": "Also consider upstream Keycloak exposure."}
        },
    )

    assert queued == 1
    assert len(queue.submissions) == 2
    assert "upstream Keycloak" in queue.submissions[1]["user_guidance"]
    assert next(iter(queue.items.values())).queue_id != first_item.queue_id


def test_auto_analysis_skips_fresh_persisted_result_with_matching_context():
    group = make_group(component_name="team-lib")
    target = auto_analysis_services.AutoAnalysisTarget(
        "team-lib",
        "TeamA",
        team_mapping_selector="team-lib",
    )
    fingerprint = build_auto_analysis_context_fingerprint(
        group,
        target,
        "ExampleApp",
    )
    store = FakeResultStore({fingerprint})
    queue = FakeAnalysisQueue()

    queued = queue_open_vulnerabilities_for_analysis(
        analysis_queue=queue,
        grouped_vulns=[group],
        team_mapping={"team-lib": "TeamA"},
        enabled=True,
        result_store=store,
    )

    assert queued == 0
    assert queue.submissions == []
    assert store.calls[0]["context_fingerprint"] == fingerprint


def test_auto_analysis_requeues_when_persisted_result_context_is_stale():
    group = make_group(component_name="team-lib")
    stale_store = FakeResultStore({"stale-fingerprint"})
    queue = FakeAnalysisQueue()

    queued = queue_open_vulnerabilities_for_analysis(
        analysis_queue=queue,
        grouped_vulns=[group],
        team_mapping={"team-lib": "TeamA"},
        enabled=True,
        result_store=stale_store,
    )

    assert queued == 1
    assert queue.submissions[0]["context_fingerprint"] != "stale-fingerprint"


def test_partial_assessment_with_not_set_team_block_is_not_auto_queued():
    details = (
        "--- [Team: TeamA] [State: NOT_AFFECTED] [Assessed By: analyst] ---\n"
        "Team A reviewed.\n\n"
        "--- [Team: TeamB] [State: NOT_SET] [Assessed By: analyst] ---\n"
        "Team B still needs review.\n\n"
        "[Status: Pending Review]"
    )
    group = make_group(component_name="team-lib", state="IN_TRIAGE", details=details)
    queue = FakeAnalysisQueue()

    queued = queue_open_vulnerabilities_for_analysis(
        analysis_queue=queue,
        grouped_vulns=[group],
        team_mapping={"team-lib": "TeamA"},
        enabled=True,
    )

    assert is_open_for_auto_analysis(group, {"team-lib": "TeamA"}) is False
    assert queued == 0
    assert queue.submissions == []


def test_non_not_set_state_without_details_is_not_auto_queued():
    group = make_group(component_name="team-lib", state="IN_TRIAGE", details="")
    queue = FakeAnalysisQueue()

    queued = queue_open_vulnerabilities_for_analysis(
        analysis_queue=queue,
        grouped_vulns=[group],
        team_mapping={"team-lib": "TeamA"},
        enabled=True,
    )

    assert is_open_for_auto_analysis(group, {"team-lib": "TeamA"}) is False
    assert queued == 0
    assert queue.submissions == []


def test_legacy_assessed_group_is_not_requeued():
    group = make_group(
        component_name="legacy-lib",
        state="NOT_AFFECTED",
        details="Plaintext legacy assessment already exists.",
    )

    assert is_open_for_auto_analysis(group, {"legacy-lib": "TeamA"}) is False


def test_legacy_assessed_details_are_not_requeued_when_raw_state_is_missing():
    group = make_group(
        component_name="legacy-lib",
        state="NOT_SET",
        details="Plaintext legacy assessment already exists.",
    )
    queue = FakeAnalysisQueue()

    queued = queue_open_vulnerabilities_for_analysis(
        analysis_queue=queue,
        grouped_vulns=[group],
        team_mapping={"legacy-lib": "TeamA"},
        enabled=True,
    )

    assert is_open_for_auto_analysis(group, {"legacy-lib": "TeamA"}) is False
    assert queued == 0
    assert queue.submissions == []


def test_reviewed_group_with_missing_instance_is_not_requeued():
    details = (
        "--- [Team: TeamA] [State: NOT_AFFECTED] "
        "[Assessed By: analyst] [Reviewed By: reviewer] ---\n"
        "Reviewed and accepted."
    )
    group = make_group(component_name="team-lib", state="NOT_AFFECTED", details=details)
    group["affected_versions"].append(
        {
            "project_version": "2.0.0",
            "components": [
                {
                    "component_name": "team-lib",
                    "component_version": "1.0.0",
                    "analysis_state": "NOT_SET",
                    "analysis_details": "",
                    "dependency_chains": [],
                }
            ],
        }
    )
    queue = FakeAnalysisQueue()

    queued = queue_open_vulnerabilities_for_analysis(
        analysis_queue=queue,
        grouped_vulns=[group],
        team_mapping={"team-lib": "TeamA"},
        enabled=True,
    )

    assert is_open_for_auto_analysis(group, {"team-lib": "TeamA"}) is False
    assert queued == 0
    assert queue.submissions == []


def test_reviewed_details_are_not_requeued_when_raw_state_is_missing():
    details = (
        "--- [Team: TeamA] [State: NOT_AFFECTED] "
        "[Assessed By: analyst] [Reviewed By: reviewer] ---\n"
        "Reviewed and accepted."
    )
    group = make_group(component_name="team-lib", state="NOT_SET", details=details)
    queue = FakeAnalysisQueue()

    queued = queue_open_vulnerabilities_for_analysis(
        analysis_queue=queue,
        grouped_vulns=[group],
        team_mapping={"team-lib": "TeamA"},
        enabled=True,
    )

    assert is_open_for_auto_analysis(group, {"team-lib": "TeamA"}) is False
    assert queued == 0
    assert queue.submissions == []


def test_assessed_group_without_explicit_open_team_block_is_not_requeued():
    details = (
        "--- [Team: General] [State: NOT_AFFECTED] "
        "[Assessed By: reviewer] [Reviewed By: reviewer] ---\n"
        "Global assessment already reviewed."
    )
    group = make_group(component_name="team-lib", state="NOT_AFFECTED", details=details)

    assert is_open_for_auto_analysis(group, {"team-lib": "TeamA"}) is False


def test_general_not_set_block_is_not_requeued_without_open_team_block():
    details = (
        "--- [Team: General] [State: NOT_SET] "
        "[Assessed By: analyst] ---\n"
        "General placeholder should not trigger automatic analysis."
    )
    group = make_group(component_name="team-lib", state="NOT_SET", details=details)
    queue = FakeAnalysisQueue()

    queued = queue_open_vulnerabilities_for_analysis(
        analysis_queue=queue,
        grouped_vulns=[group],
        team_mapping={"team-lib": "TeamA"},
        enabled=True,
    )

    assert is_open_for_auto_analysis(group, {"team-lib": "TeamA"}) is False
    assert queued == 0
    assert queue.submissions == []


def test_closed_group_cancels_stale_automatic_queue_item():
    details = (
        "--- [Team: TeamA] [State: NOT_AFFECTED] "
        "[Assessed By: analyst] [Reviewed By: reviewer] ---\n"
        "Reviewed and accepted."
    )
    group = make_group(component_name="team-lib", state="NOT_AFFECTED", details=details)
    queue = FakeAnalysisQueue()
    item, _ = queue.submit_once(
        vuln_id=group["id"],
        component_name="team-lib",
        submitted_by="dtvp-auto-analysis",
        source="automatic",
    )

    queued = queue_open_vulnerabilities_for_analysis(
        analysis_queue=queue,
        grouped_vulns=[group],
        team_mapping={"team-lib": "TeamA"},
        enabled=True,
    )

    assert queued == 0
    assert item.status == "cancelled"
    assert queue.cancelled == [item.queue_id]


def test_closed_group_does_not_cancel_manual_queue_item():
    details = (
        "--- [Team: TeamA] [State: NOT_AFFECTED] "
        "[Assessed By: analyst] [Reviewed By: reviewer] ---\n"
        "Reviewed and accepted."
    )
    group = make_group(component_name="team-lib", state="NOT_AFFECTED", details=details)
    queue = FakeAnalysisQueue()
    item, _ = queue.submit_once(
        vuln_id=group["id"],
        component_name="team-lib",
        submitted_by="analyst",
        source="manual",
    )

    queued = queue_open_vulnerabilities_for_analysis(
        analysis_queue=queue,
        grouped_vulns=[group],
        team_mapping={"team-lib": "TeamA"},
        enabled=True,
    )

    assert queued == 0
    assert item.status == "queued"
    assert queue.cancelled == []


def test_handled_group_cancels_stale_automatic_item_by_vulnerability_id():
    details = (
        "--- [Team: TeamA] [State: NOT_AFFECTED] "
        "[Assessed By: analyst] [Reviewed By: reviewer] ---\n"
        "Reviewed and accepted."
    )
    group = make_group(
        component_name="current-target",
        state="NOT_AFFECTED",
        details=details,
    )
    queue = FakeAnalysisQueue()
    item, _ = queue.submit_once(
        vuln_id=group["id"],
        component_name="previous-target",
        submitted_by="dtvp-auto-analysis",
        source="automatic",
    )

    queued = queue_open_vulnerabilities_for_analysis(
        analysis_queue=queue,
        grouped_vulns=[group],
        team_mapping={"current-target": "TeamA"},
        enabled=True,
    )

    assert queued == 0
    assert item.status == "cancelled"
    assert queue.cancelled == [item.queue_id]


def test_unmapped_open_group_is_not_auto_queued():
    group = make_group(component_name="unmapped-lib")
    queue = FakeAnalysisQueue()

    queued = queue_open_vulnerabilities_for_analysis(
        analysis_queue=queue,
        grouped_vulns=[group],
        team_mapping={},
        enabled=True,
    )

    assert queued == 0
    assert queue.submissions == []


def test_open_group_without_owned_target_cancels_stale_automatic_item():
    group = make_group(component_name="unmapped-lib")
    queue = FakeAnalysisQueue()
    item, _ = queue.submit_once(
        vuln_id=group["id"],
        component_name="previous-target",
        submitted_by="dtvp-auto-analysis",
        source="automatic",
    )

    queued = queue_open_vulnerabilities_for_analysis(
        analysis_queue=queue,
        grouped_vulns=[group],
        team_mapping={},
        enabled=True,
    )

    assert queued == 0
    assert item.status == "cancelled"
    assert queue.cancelled == [item.queue_id]


async def test_existing_open_vulnerability_sweep_queues_cached_project_versions():
    projects = [
        {"name": "ExistingApp", "uuid": "project-1", "version": "1.0.0"},
        {"name": "ExistingApp", "uuid": "project-2", "version": "2.0.0"},
    ]
    snapshots = {
        "project-1": (
            [
                {
                    "vulnerability": {
                        "vulnId": "CVE-2026-0001",
                        "severity": "HIGH",
                    },
                    "component": {
                        "name": "team-lib",
                        "version": "1.0.0",
                        "uuid": "component-1",
                    },
                    "analysis": {"state": "NOT_SET"},
                }
            ],
            [],
            {},
        ),
        "project-2": ([], [], {}),
    }
    queue = FakeAnalysisQueue()
    collected_versions = []

    async def collect_version_snapshots(versions, _client, cve, _team_mapping):
        assert cve is None
        collected_versions.extend(version["uuid"] for version in versions)
        return [], {}, {}

    def group_vulnerabilities(combined_data, **_kwargs):
        assert combined_data[0]["version"]["uuid"] == "project-1"
        assert (
            combined_data[0]["vulnerabilities"][0]["component"]["name"]
            == "team-lib"
        )
        return [make_group(component_name="team-lib")]

    deps = AutoAnalysisSweepDeps(
        cache_manager=FakeCacheManager(cached_projects=projects, snapshots=snapshots),
        logger=FakeLogger(),
        sort_projects_by_version=lambda versions: sorted(
            versions,
            key=lambda version: version["version"],
        ),
        load_team_mapping=lambda: {"team-lib": "TeamA"},
        collect_version_snapshots=collect_version_snapshots,
        bom_analysis_cache_cls=lambda bom, mapping: object(),
        merge_vulnerability_details=lambda _findings, _full_vulns: {},
        group_vulnerabilities=group_vulnerabilities,
        queue_grouped_vulnerabilities_for_analysis=queue_grouped_with_fake_queue(queue),
    )

    queued = await queue_existing_open_vulnerabilities_for_analysis(deps, object())

    assert queued == 1
    assert collected_versions == []
    assert queue.submissions[0]["component_name"] == "team-lib"


async def test_existing_open_vulnerability_sweep_plan_defers_queue_mutation():
    projects = [{"name": "ExistingApp", "uuid": "project-1", "version": "1.0.0"}]
    snapshots = {
        "project-1": (
            [
                {
                    "vulnerability": {
                        "vulnId": "CVE-2026-PLAN",
                        "severity": "HIGH",
                    },
                    "component": {
                        "name": "team-lib",
                        "version": "1.0.0",
                        "uuid": "component-1",
                    },
                    "analysis": {"state": "NOT_SET"},
                }
            ],
            [],
            {},
        ),
    }
    queue = FakeAnalysisQueue()

    async def collect_version_snapshots(_versions, _client, _cve, _team_mapping):
        return [], {}, {}

    def group_vulnerabilities(combined_data, **_kwargs):
        assert combined_data[0]["version"]["uuid"] == "project-1"
        return [make_group(component_name="team-lib", id="CVE-2026-PLAN")]

    deps = AutoAnalysisSweepDeps(
        cache_manager=FakeCacheManager(cached_projects=projects, snapshots=snapshots),
        logger=FakeLogger(),
        sort_projects_by_version=lambda versions: versions,
        load_team_mapping=lambda: {"team-lib": "TeamA"},
        collect_version_snapshots=collect_version_snapshots,
        bom_analysis_cache_cls=lambda bom, mapping: object(),
        merge_vulnerability_details=lambda _findings, _full_vulns: {},
        group_vulnerabilities=group_vulnerabilities,
        queue_grouped_vulnerabilities_for_analysis=lambda *_args: 0,
    )

    plan = await build_existing_open_vulnerability_sweep_plan(deps, object())

    assert queue.submissions == []
    assert len(plan.queue_plans) == 1
    assert len(plan.queue_plans[0].candidates) == 1

    queued = apply_auto_analysis_sweep_plan(analysis_queue=queue, plan=plan)

    assert queued == 1
    assert queue.submissions[0]["vuln_id"] == "CVE-2026-PLAN"
    assert queue.submissions[0]["component_name"] == "team-lib"


async def test_existing_open_vulnerability_sweep_yields_around_cached_work(monkeypatch):
    sleep_calls = []

    async def fake_sleep(seconds):
        sleep_calls.append(seconds)

    monkeypatch.setattr(auto_analysis_services.asyncio, "sleep", fake_sleep)

    deps = AutoAnalysisSweepDeps(
        cache_manager=FakeCacheManager(),
        logger=FakeLogger(),
        sort_projects_by_version=lambda versions: versions,
        load_team_mapping=lambda: {},
        collect_version_snapshots=lambda *_args: None,
        bom_analysis_cache_cls=lambda bom, mapping: object(),
        merge_vulnerability_details=lambda _findings, _full_vulns: {},
        group_vulnerabilities=lambda *_args, **_kwargs: [],
        queue_grouped_vulnerabilities_for_analysis=lambda *_args: 0,
    )

    queued = await queue_existing_open_vulnerabilities_for_analysis(deps, object())

    assert queued == 0
    assert sleep_calls[:2] == [0, 0]


async def test_existing_open_vulnerability_sweep_groups_cached_dt_findings():
    queue = FakeAnalysisQueue()
    snapshots = {
        "project-1": (
            [
                {
                    "vulnerability": {
                        "uuid": "vuln-1",
                        "vulnId": "CVE-2026-0002",
                        "severity": "HIGH",
                        "cvssV3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    },
                    "component": {
                        "uuid": "component-1",
                        "name": "cached-lib",
                        "version": "1.0.0",
                    },
                    "analysis": {
                        "analysisState": "NOT_SET",
                        "analysisDetails": "",
                        "isSuppressed": False,
                    },
                }
            ],
            [],
            {},
        ),
    }

    async def collect_version_snapshots(_versions, _client, _cve, _team_mapping):
        raise AssertionError("cached findings should be grouped before live collection")

    deps = AutoAnalysisSweepDeps(
        cache_manager=FakeCacheManager(
            cached_projects=[
                {"name": "CachedApp", "uuid": "project-1", "version": "1.0.0"}
            ],
            snapshots=snapshots,
        ),
        logger=FakeLogger(),
        sort_projects_by_version=lambda versions: versions,
        load_team_mapping=lambda: {"cached-lib": "TeamA"},
        collect_version_snapshots=collect_version_snapshots,
        bom_analysis_cache_cls=BOMAnalysisCache,
        merge_vulnerability_details=merge_vulnerability_details,
        group_vulnerabilities=group_vulnerabilities,
        queue_grouped_vulnerabilities_for_analysis=queue_grouped_with_fake_queue(queue),
    )

    queued = await queue_existing_open_vulnerabilities_for_analysis(deps, object())

    assert queued == 1
    assert queue.submissions[0]["vuln_id"] == "CVE-2026-0002"
    assert queue.submissions[0]["component_name"] == "cached-lib"


async def test_existing_open_vulnerability_sweep_skips_unmapped_cached_dt_findings():
    queue = FakeAnalysisQueue()
    snapshots = {
        "project-1": (
            [
                {
                    "vulnerability": {
                        "uuid": "vuln-1",
                        "vulnId": "CVE-2026-0007",
                        "severity": "HIGH",
                    },
                    "component": {
                        "uuid": "component-1",
                        "name": "openssl",
                        "version": "3.0.0",
                    },
                    "analysis": {
                        "analysisState": "NOT_SET",
                        "analysisDetails": "",
                        "isSuppressed": False,
                    },
                }
            ],
            [],
            {},
        ),
    }

    async def collect_version_snapshots(_versions, _client, _cve, _team_mapping):
        raise AssertionError("cached findings should be grouped before live collection")

    deps = AutoAnalysisSweepDeps(
        cache_manager=FakeCacheManager(
            cached_projects=[
                {"name": "CachedApp", "uuid": "project-1", "version": "1.0.0"}
            ],
            snapshots=snapshots,
        ),
        logger=FakeLogger(),
        sort_projects_by_version=lambda versions: versions,
        load_team_mapping=lambda: {},
        collect_version_snapshots=collect_version_snapshots,
        bom_analysis_cache_cls=BOMAnalysisCache,
        merge_vulnerability_details=merge_vulnerability_details,
        group_vulnerabilities=group_vulnerabilities,
        queue_grouped_vulnerabilities_for_analysis=queue_grouped_with_fake_queue(queue),
    )

    queued = await queue_existing_open_vulnerabilities_for_analysis(deps, object())

    assert queued == 0
    assert queue.submissions == []


async def test_existing_open_vulnerability_sweep_skips_vuln_assessed_elsewhere():
    queue = FakeAnalysisQueue()
    projects = [
        {"name": "HandledApp", "uuid": "handled-project", "version": "1.0.0"},
        {"name": "OpenApp", "uuid": "open-project", "version": "1.0.0"},
    ]
    snapshots = {
        "handled-project": (
            [
                {
                    "vulnerability": {
                        "uuid": "vuln-handled",
                        "vulnId": "CVE-2026-0003",
                        "severity": "HIGH",
                    },
                    "component": {
                        "uuid": "component-handled",
                        "name": "shared-lib",
                        "version": "1.0.0",
                    },
                    "analysis": {
                        "analysisState": "NOT_AFFECTED",
                        "analysisDetails": (
                            "--- [Team: General] [State: NOT_AFFECTED] "
                            "[Assessed By: reviewer] ---\nAlready reviewed."
                        ),
                        "isSuppressed": False,
                    },
                }
            ],
            [],
            {},
        ),
        "open-project": (
            [
                {
                    "vulnerability": {
                        "uuid": "vuln-open",
                        "vulnId": "CVE-2026-0003",
                        "severity": "HIGH",
                    },
                    "component": {
                        "uuid": "component-open",
                        "name": "shared-lib",
                        "version": "1.0.0",
                    },
                    "analysis": {
                        "analysisState": "NOT_SET",
                        "analysisDetails": "",
                        "isSuppressed": False,
                    },
                }
            ],
            [],
            {},
        ),
    }

    async def collect_version_snapshots(_versions, _client, _cve, _team_mapping):
        raise AssertionError("cached findings should be grouped before live collection")

    deps = AutoAnalysisSweepDeps(
        cache_manager=FakeCacheManager(cached_projects=projects, snapshots=snapshots),
        logger=FakeLogger(),
        sort_projects_by_version=lambda versions: versions,
        load_team_mapping=lambda: {},
        collect_version_snapshots=collect_version_snapshots,
        bom_analysis_cache_cls=BOMAnalysisCache,
        merge_vulnerability_details=merge_vulnerability_details,
        group_vulnerabilities=group_vulnerabilities,
        queue_grouped_vulnerabilities_for_analysis=queue_grouped_with_fake_queue(queue),
    )

    queued = await queue_existing_open_vulnerabilities_for_analysis(deps, object())

    assert queued == 0
    assert queue.submissions == []
