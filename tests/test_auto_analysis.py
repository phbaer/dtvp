from types import SimpleNamespace

from dtvp.auto_analysis_services import (
    AutoAnalysisSweepDeps,
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


def queue_grouped_with_fake_queue(queue):
    def queue_grouped(grouped, team_mapping, handled_vulnerability_ids=None):
        return queue_open_vulnerabilities_for_analysis(
            analysis_queue=queue,
            grouped_vulns=grouped,
            team_mapping=team_mapping,
            enabled=True,
            handled_vulnerability_ids=handled_vulnerability_ids,
        )

    return queue_grouped


def make_group(component_name="lib-a", state="NOT_SET", details="", **overrides):
    group = {
        "id": "CVE-2026-0001",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "tags": [],
        "affected_versions": [
            {
                "project_version": "1.0.0",
                "components": [
                    {
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


def test_select_auto_analysis_targets_uses_first_mapped_dependency_parent():
    group = make_group(component_name="vulnerable-lib")
    group["affected_versions"][0]["components"][0]["dependency_chains"] = [
        "vulnerable-lib -> service-a -> app-root"
    ]

    targets = select_auto_analysis_targets(group, {"service-a": "TeamA"})

    assert len(targets) == 1
    assert targets[0].component_name == "service-a"
    assert targets[0].team == "TeamA"


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


def test_unmapped_open_group_falls_back_to_affected_component():
    group = make_group(component_name="unmapped-lib")
    queue = FakeAnalysisQueue()

    queued = queue_open_vulnerabilities_for_analysis(
        analysis_queue=queue,
        grouped_vulns=[group],
        team_mapping={},
        enabled=True,
    )

    assert queued == 1
    assert queue.submissions[0]["component_name"] == "unmapped-lib"


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
        load_team_mapping=lambda: {},
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
