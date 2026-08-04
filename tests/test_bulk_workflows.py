import json
from pathlib import Path

import pytest

from dtvp.bulk_workflows.base import (
    BulkWorkflowContext,
    BulkWorkflowPlugin,
    BulkWorkflowRegistry,
    build_preview_token,
)
from dtvp.bulk_workflows.incomplete_sync import (
    build_incomplete_sync_payloads,
    build_incomplete_sync_preview,
)
from dtvp.bulk_workflows.automatic_assessments import (
    build_automatic_assessment_document,
    build_automatic_assessment_payloads,
    build_automatic_assessment_preview,
)
from dtvp.bulk_workflows.rescore_rule_sync import create_rescore_rule_sync_workflow
from dtvp.code_analysis_assessment_services import assessment_status_for_group
from dtvp.assessment_snapshot_services import build_assessment_group_index
from dtvp.general_api_routes import (
    BulkWorkflowFilters,
    _filter_bulk_workflow_groups,
    _filter_bulk_workflow_task_groups,
    _record_code_analysis_applications,
    _refresh_grouped_vuln_task_snapshots,
)
from dtvp.grouped_vuln_services import summarize_grouped_vulnerabilities
from dtvp.task_group_query_services import (
    build_task_group_query_index,
    get_or_build_task_group_query_index,
)


def _group(group_id: str, lifecycle: str, state: str = "NOT_SET"):
    return {
        "id": group_id,
        "title": group_id,
        "aliases": [],
        "list_metadata": {
            "lifecycle": lifecycle,
            "is_open": lifecycle == "OPEN",
            "is_pending": False,
            "technical_state": state,
        },
        "affected_versions": [],
    }


def test_task_snapshot_refresh_is_copy_on_write():
    full_group = {
        "id": "CVE-COPY-ON-WRITE",
        "aliases": [],
        "affected_versions": [
            {
                "project_name": "Project",
                "project_version": "1.0.0",
                "components": [
                    {
                        "project_uuid": "project-1",
                        "component_uuid": "component-1",
                        "vulnerability_uuid": "vulnerability-1",
                        "finding_uuid": "finding-1",
                        "component_name": "library-a",
                        "analysis_state": "NOT_SET",
                        "analysis_details": "",
                    }
                ],
            }
        ],
    }
    summary = summarize_grouped_vulnerabilities([full_group], {})
    old_index = build_task_group_query_index(summary)
    task = {
        "_owner": "reviewer",
        "status": "completed",
        "result_mode": "summary",
        "result": summary,
        "_full_result": [full_group],
        "_full_result_by_id": {full_group["id"]: full_group},
        "_group_query_index": old_index,
    }

    refreshed = _refresh_grouped_vuln_task_snapshots(
        {"task-1": task},
        [
            (
                {
                    "project_uuid": "project-1",
                    "component_uuid": "component-1",
                    "vulnerability_uuid": "vulnerability-1",
                    "finding_uuid": "finding-1",
                },
                {
                    "state": "NOT_AFFECTED",
                    "details": "Reviewed",
                    "suppressed": False,
                },
            )
        ],
        {},
    )

    assert refreshed == 1
    assert full_group["affected_versions"][0]["components"][0][
        "analysis_state"
    ] == "NOT_SET"
    assert old_index["rows"][0]["fields"]["lifecycle"] == "OPEN"
    assert task["_full_result"][0] is not full_group
    assert "_group_query_index" not in task
    assert (
        get_or_build_task_group_query_index(task)["rows"][0]["fields"]["lifecycle"]
        == "ASSESSED_LEGACY"
    )


def test_task_snapshot_refresh_does_not_scan_unrelated_indexed_groups():
    class UnscannableVersions(list):
        def __iter__(self):
            raise AssertionError("unrelated group was scanned")

    target = {
        "id": "CVE-TARGET",
        "aliases": [],
        "affected_versions": [{
            "components": [{
                "project_uuid": "project-1",
                "component_uuid": "component-1",
                "vulnerability_uuid": "vulnerability-1",
                "finding_uuid": "finding-1",
                "analysis_state": "NOT_SET",
                "analysis_details": "",
            }],
        }],
    }
    unrelated = {
        "id": "CVE-UNRELATED",
        "aliases": [],
        "affected_versions": [{
            "components": [{
                "project_uuid": "project-2",
                "component_uuid": "component-2",
                "vulnerability_uuid": "vulnerability-2",
                "finding_uuid": "finding-2",
                "analysis_state": "NOT_SET",
                "analysis_details": "",
            }],
        }],
    }
    full_result = [target, unrelated]
    assessment_index = build_assessment_group_index(full_result)
    summary = summarize_grouped_vulnerabilities(full_result, {})
    unrelated["affected_versions"] = UnscannableVersions(
        unrelated["affected_versions"]
    )
    task = {
        "status": "completed",
        "result_mode": "summary",
        "result": summary,
        "_full_result": full_result,
        "_full_result_by_id": {
            target["id"]: target,
            unrelated["id"]: unrelated,
        },
        "_assessment_full_group_index": assessment_index,
        "_group_query_index": build_task_group_query_index(summary),
    }

    refreshed = _refresh_grouped_vuln_task_snapshots(
        {"task-1": task},
        [(
            {
                "project_uuid": "project-1",
                "component_uuid": "component-1",
                "vulnerability_uuid": "vulnerability-1",
                "finding_uuid": "finding-1",
            },
            {
                "state": "NOT_AFFECTED",
                "details": "Reviewed",
                "suppressed": False,
            },
        )],
        {},
    )

    assert refreshed == 1
    assert task["_full_result"][1] is unrelated
    assert task["_full_result"][0] is not target
    assert "_group_query_index" not in task


def test_bulk_workflow_registry_and_preview_token_are_deterministic():
    plugin = BulkWorkflowPlugin(
        id="example",
        label="Example",
        description="Example workflow",
        preview_builder=lambda context: {
            "items": [{"group_id": group["id"]} for group in context.groups],
            "summary": {"groups": len(context.groups)},
        },
    )
    registry = BulkWorkflowRegistry([plugin])
    context = BulkWorkflowContext(
        task_id="task-1",
        groups=[_group("CVE-2", "OPEN"), _group("CVE-1", "OPEN")],
        user="reviewer",
    )
    preview = plugin.preview(context)
    first = build_preview_token(
        plugin,
        task_id=context.task_id,
        filter_payload={"analysis": ["NOT_SET"]},
        preview=preview,
    )
    reordered = {**preview, "items": list(reversed(preview["items"]))}
    assert registry.get("example") is plugin
    assert first == build_preview_token(
        plugin,
        task_id=context.task_id,
        filter_payload={"analysis": ["NOT_SET"]},
        preview=reordered,
    )
    assert first != build_preview_token(
        plugin,
        task_id=context.task_id,
        filter_payload={"analysis": ["EXPLOITABLE"]},
        preview=preview,
    )
    changed = {
        **preview,
        "items": [{**preview["items"][0], "target_state": "EXPLOITABLE"}, *preview["items"][1:]],
    }
    assert first != build_preview_token(
        plugin,
        task_id=context.task_id,
        filter_payload={"analysis": ["NOT_SET"]},
        preview=changed,
    )


def test_bulk_workflow_filters_intersect_before_workflow_criteria():
    groups = [
        _group("CVE-INCOMPLETE", "INCOMPLETE", "NOT_SET"),
        _group("CVE-ASSESSED", "ASSESSED", "NOT_AFFECTED"),
    ]

    assert [
        group["id"]
        for group in _filter_bulk_workflow_groups(
            groups,
            BulkWorkflowFilters(
                lifecycle=["INCOMPLETE"],
                analysis=["NOT_SET"],
            ),
        )
    ] == ["CVE-INCOMPLETE"]
    assert _filter_bulk_workflow_groups(
        groups,
        BulkWorkflowFilters(
            lifecycle=["ASSESSED"],
            analysis=["EXPLOITABLE"],
        ),
    ) == []


def test_bulk_workflow_task_filter_reuses_the_visible_summary_index():
    selected_summary = _group("CVE-SELECTED", "ASSESSED", "NOT_AFFECTED")
    other_summary = _group("CVE-OTHER", "OPEN", "NOT_SET")
    selected_full = {
        "id": "CVE-SELECTED",
        "title": "Full selected details",
        "affected_versions": [{"components": []}],
    }
    other_full = {
        "id": "CVE-OTHER",
        "title": "Full other details",
        "affected_versions": [{"components": []}],
    }
    task = {
        "_owner": "reviewer",
        "status": "completed",
        "result_mode": "summary",
        "result": [selected_summary, other_summary],
        "_full_result": [selected_full, other_full],
        "_full_result_by_id": {
            "CVE-SELECTED": selected_full,
            "CVE-OTHER": other_full,
        },
    }
    deps = type(
        "Deps",
        (),
        {
            "tasks": {"task-1": task},
            "prune_grouped_vuln_tasks": staticmethod(lambda: []),
        },
    )()

    filtered = _filter_bulk_workflow_task_groups(
        deps,
        "task-1",
        BulkWorkflowFilters(
            id="CVE-SELECTED",
            lifecycle=["ASSESSED"],
            analysis=["NOT_AFFECTED"],
        ),
        "reviewer",
    )

    assert len(filtered) == 1
    assert filtered[0]["id"] == selected_full["id"]
    assert filtered[0]["title"] == selected_full["title"]
    assert filtered[0]["list_metadata"] == selected_summary["list_metadata"]
    assert "list_metadata" not in selected_full
    assert task.get("_group_query_index") is not None


def test_incomplete_bulk_preview_keeps_lifecycle_when_hydrating_full_groups():
    summary = _group("CVE-INCOMPLETE", "INCOMPLETE", "NOT_AFFECTED")
    full = {
        "id": "CVE-INCOMPLETE",
        "title": "Incomplete full group",
        "affected_versions": [
            {
                "components": [
                    {
                        "finding_uuid": "finding-1",
                        "project_uuid": "project-1",
                        "component_uuid": "component-1",
                        "vulnerability_uuid": "vulnerability-1",
                        "analysis_state": "NOT_AFFECTED",
                        "analysis_details": (
                            "--- [Team: API] [State: NOT_AFFECTED] "
                            "[Assessed By: alice] ---\nNo reachable path."
                        ),
                    },
                    {
                        "finding_uuid": "finding-2",
                        "project_uuid": "project-2",
                        "component_uuid": "component-2",
                        "vulnerability_uuid": "vulnerability-2",
                        "analysis_state": "NOT_SET",
                        "analysis_details": "",
                    },
                ]
            }
        ],
    }
    task = {
        "_owner": "reviewer",
        "status": "completed",
        "result_mode": "summary",
        "result": [summary],
        "_full_result": [full],
        "_full_result_by_id": {full["id"]: full},
    }
    deps = type(
        "Deps",
        (),
        {
            "tasks": {"task-1": task},
            "prune_grouped_vuln_tasks": staticmethod(lambda: []),
        },
    )()

    filtered = _filter_bulk_workflow_task_groups(
        deps,
        "task-1",
        BulkWorkflowFilters(lifecycle=["INCOMPLETE"]),
        "reviewer",
    )
    preview = build_incomplete_sync_preview(filtered)

    assert preview["summary"] == {"groups": 1, "findings": 2}
    assert preview["items"][0]["group_id"] == "CVE-INCOMPLETE"
    assert filtered[0]["list_metadata"]["lifecycle"] == "INCOMPLETE"


def test_visible_filtered_cvss_rule_candidate_is_included_in_preview():
    summary = _group("CVE-RULE-SYNC", "ASSESSED", "NOT_AFFECTED")
    full = {
        "id": "CVE-RULE-SYNC",
        "title": "CVSS rule candidate",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "affected_versions": [
            {
                "components": [
                    {
                        "finding_uuid": "finding-1",
                        "project_uuid": "project-1",
                        "component_uuid": "component-1",
                        "vulnerability_uuid": "vulnerability-1",
                        "analysis_state": "NOT_AFFECTED",
                        "analysis_details": "",
                    }
                ]
            }
        ],
    }
    task = {
        "_owner": "reviewer",
        "status": "completed",
        "result_mode": "summary",
        "result": [summary],
        "_full_result": [full],
        "_full_result_by_id": {full["id"]: full},
    }
    deps = type(
        "Deps",
        (),
        {
            "tasks": {"task-1": task},
            "prune_grouped_vuln_tasks": staticmethod(lambda: []),
        },
    )()
    groups = _filter_bulk_workflow_task_groups(
        deps,
        "task-1",
        BulkWorkflowFilters(
            id="CVE-RULE-SYNC",
            lifecycle=["ASSESSED"],
            analysis=["NOT_AFFECTED"],
        ),
        "reviewer",
    )
    rules = json.loads(Path("data/rescore_rules.json").read_text())
    plugin = create_rescore_rule_sync_workflow(lambda: rules)
    preview = plugin.preview(
        BulkWorkflowContext(task_id="task-1", groups=groups, user="reviewer")
    )

    assert plugin.selectable_ids(preview) == ["CVE-RULE-SYNC"]
    assert plugin.metadata()["label"] == "Repair Rescoring Definitions"
    assert plugin.metadata()["version"] == 2
    assert preview["items"][0]["syncable_finding_count"] == 1
    finding = preview["items"][0]["findings"][0]
    assert finding["issue_type"] == "missing_rescore"
    assert finding["current_vector"] is None
    assert finding["proposed_score"] == 0.0


def test_incomplete_sync_builds_backend_preview_and_payloads():
    group = _group("CVE-INCOMPLETE", "INCOMPLETE", "NOT_AFFECTED")
    group["affected_versions"] = [
        {
            "components": [
                {
                    "finding_uuid": "finding-1",
                    "project_uuid": "project-1",
                    "component_uuid": "component-1",
                    "vulnerability_uuid": "vulnerability-1",
                    "analysis_state": "NOT_AFFECTED",
                    "analysis_details": (
                        "--- [Team: API] [State: NOT_AFFECTED] "
                        "[Assessed By: alice] [Justification: CODE_NOT_REACHABLE] "
                        "[Evidence Reviewed: yes] ---\nNo reachable path."
                    ),
                },
                {
                    "finding_uuid": "finding-2",
                    "project_uuid": "project-2",
                    "component_uuid": "component-2",
                    "vulnerability_uuid": "vulnerability-2",
                    "analysis_state": "NOT_SET",
                    "analysis_details": "",
                },
            ]
        }
    ]

    preview = build_incomplete_sync_preview([group])
    assert preview["summary"] == {"groups": 1, "findings": 2}
    assert preview["items"][0]["target_state"] == "NOT_AFFECTED"
    assert "[Evidence Reviewed: yes]" in preview["items"][0]["target_details"]
    assert "[Team: API] [State: NOT_AFFECTED]" in preview["items"][0]["target_details"]
    assert "[Team: General]" not in preview["items"][0]["target_details"]
    assert "Team assessments:" not in preview["items"][0]["target_details"]

    payloads, skipped = build_incomplete_sync_payloads(
        [group], ["CVE-INCOMPLETE"]
    )
    assert len(payloads) == 2
    assert skipped == {"not_incomplete": 0, "missing_identity": 0}
    assert {payload["state"] for _instance, payload in payloads} == {"NOT_AFFECTED"}


def test_incomplete_sync_removes_legacy_general_team_summary_without_duplication():
    group = _group("CVE-INCOMPLETE-LEGACY", "INCOMPLETE", "IN_TRIAGE")
    group["affected_versions"] = [
        {
            "components": [
                {
                    "finding_uuid": "finding-legacy-1",
                    "project_uuid": "project-1",
                    "component_uuid": "component-1",
                    "vulnerability_uuid": "vulnerability-1",
                    "analysis_state": "IN_TRIAGE",
                    "analysis_details": (
                        "--- [Team: General] [State: NOT_SET] "
                        "[Assessed By: reviewer] ---\n"
                        "Global policy note.\n\n"
                        "Team assessments:\n[API] IN_TRIAGE\n\n"
                        "--- [Team: API] [State: IN_TRIAGE] "
                        "[Assessed By: analyst] ---\n"
                        "Reachability is under review."
                    ),
                },
                {
                    "finding_uuid": "finding-legacy-2",
                    "project_uuid": "project-2",
                    "component_uuid": "component-2",
                    "vulnerability_uuid": "vulnerability-2",
                    "analysis_state": "NOT_SET",
                    "analysis_details": "",
                },
            ]
        }
    ]

    details = build_incomplete_sync_preview([group])["items"][0]["target_details"]

    assert details.count("[Team: General]") == 1
    assert details.lower().count("[team: api]") == 1
    assert "Global policy note." in details
    assert "Reachability is under review." in details
    assert "Team assessments:" not in details


class _AutomaticResultStore:
    def __init__(self, records, applications=None):
        self.records = records
        self.applications = applications or []

    def list(self, **_kwargs):
        return self.records

    def list_applications(self, **_kwargs):
        return self.applications


def _automatic_record(
    run_id,
    component,
    verdict,
    *,
    exposure="reachable",
    ticket_text=None,
    source="automatic",
    target_team="API",
    adjusted_cvss=None,
):
    assessment = {
        "verdict": verdict,
        "affected": verdict == "Affected",
        "confidence": "High",
        "exposure": exposure,
        "summary": f"{component} was assessed as {verdict}.",
        "reasoning": "Source and dependency evidence were checked.",
    }
    if ticket_text:
        assessment["ticket_text"] = ticket_text
    if adjusted_cvss:
        assessment["adjusted_cvss"] = adjusted_cvss
    return {
        "analysis_run_id": run_id,
        "project_name": "ExampleApp",
        "vuln_id": "CVE-2026-AUTO",
        "component_name": component,
        "source": source,
        "status": "completed",
        "context_summary": {"target_team": target_team} if target_team else {},
        "result": {
            "assessment": assessment,
            "versions_checked": ["1.0.0"],
        },
    }


def _automatic_group():
    group = _group("CVE-2026-AUTO", "OPEN")
    group["severity"] = "HIGH"
    group["affected_versions"] = [
        {
            "components": [
                {
                    "finding_uuid": "finding-api",
                    "project_uuid": "project-1",
                    "project_name": "ExampleApp",
                    "component_uuid": "component-api",
                    "component_name": "owned-api",
                    "vulnerability_uuid": "vulnerability-1",
                    "analysis_state": "NOT_SET",
                    "analysis_details": "",
                },
                {
                    "finding_uuid": "finding-worker",
                    "project_uuid": "project-1",
                    "project_name": "ExampleApp",
                    "component_uuid": "component-worker",
                    "component_name": "owned-worker",
                    "vulnerability_uuid": "vulnerability-1",
                    "analysis_state": "NOT_SET",
                    "analysis_details": "",
                },
            ]
        }
    ]
    return group


def test_automatic_assessment_workflow_aggregates_verdicts_and_builds_payloads():
    api_record = _automatic_record(
        "run-api", "owned-api", "Not Affected", exposure="none"
    )
    api_record["result"]["assessment"].update(
        {
            "dependency_presence": {
                "sbom_attributed": True,
                "repo_found": False,
            },
            "researcher_view": {"conclusion": "No reachable vulnerable path."},
            "remediation_view": {"recommendations": ["Keep monitoring releases."]},
            "audit_view": {"conclusion": "Evidence is sufficient."},
            "details": "Important source finding. " + ("Repeated context. " * 100),
        }
    )
    store = _AutomaticResultStore(
        [
            api_record,
            _automatic_record(
                "run-worker",
                "owned-worker",
                "Probably Affected",
                ticket_text="Title: remediate the worker\n\nUpdate owned-worker.",
            ),
        ]
    )
    context = BulkWorkflowContext(
        task_id="task-1",
        groups=[_automatic_group()],
        user="reviewer",
        result_store=store,
    )

    preview = build_automatic_assessment_preview(context)
    assert preview["summary"]["probably_affected_groups"] == 1
    assert preview["items"][0]["verdict_bucket"] == "PROBABLY_AFFECTED"
    assert preview["items"][0]["ticket_text"].startswith("Title: remediate")

    payloads, skipped = build_automatic_assessment_payloads(
        context, ["CVE-2026-AUTO"]
    )
    assert [payload[1]["state"] for payload in payloads] == [
        "IN_TRIAGE",
        "IN_TRIAGE",
    ]
    assert {payload[1]["justification"] for payload in payloads} == {"NOT_SET"}
    assert payloads[1][0]["analysis_run_ids"] == ["run-api", "run-worker"]
    assert "[Analysis Runs: run-api, run-worker]" in payloads[1][1]["details"]
    assert "[Automatic Assessment: run-api]" in payloads[1][1]["details"]
    assert "[Automatic Assessment: run-worker]" in payloads[1][1]["details"]
    assert (
        "Dependency evidence:\nPresent via SBOM attribution; not rediscovered "
        "in repository manifests or lock files."
        in payloads[1][1]["details"]
    )
    assert "Research conclusion:\nNo reachable vulnerable path." in payloads[1][1]["details"]
    assert "Remediation:\n  - Keep monitoring releases." in payloads[1][1]["details"]
    assert '"sbom_attributed"' not in payloads[1][1]["details"]
    assert "Component Assessments:" not in payloads[1][1]["details"]
    assert payloads[1][1]["details"].count("Repeated context.") == 100
    assert skipped == {
        "already_applied": 0,
        "missing_identity": 0,
        "replaced_existing": 0,
    }

    document = build_automatic_assessment_document(context, ["CVE-2026-AUTO"])
    assert "# Automatic Assessment Ticket Drafts" in document
    assert "Title: remediate the worker" in document
    assert "run-api, run-worker" in document


def test_automatic_assessment_workflow_applies_selected_rescore_to_vulnerability():
    group = _automatic_group()
    group.update(
        {
            "cvss_score": 8.1,
            "cvss_vector": (
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            ),
            "rescored_cvss": None,
            "rescored_vector": None,
        }
    )
    affected = _automatic_record(
        "run-affected",
        "owned-api",
        "Affected",
    )
    affected["result"]["assessment"]["adjusted_cvss"] = {
        "original_score": 8.1,
        "adjusted_score": 3.7,
        "original_vector": group["cvss_vector"],
        "adjusted_vector": (
            f"{group['cvss_vector']}/CR:L/IR:L/AR:L"
        ),
        "summary": "Runtime controls reduce the environmental impact.",
    }
    probable = _automatic_record(
        "run-probable",
        "owned-worker",
        "Probably Affected",
    )
    probable["result"]["assessment"]["adjusted_cvss"] = {
        "original_score": 8.1,
        "adjusted_score": 2.1,
        "original_vector": group["cvss_vector"],
        "adjusted_vector": (
            f"{group['cvss_vector']}/CR:L/IR:L/AR:L/MAV:L"
        ),
    }
    context = BulkWorkflowContext(
        task_id="task-1",
        groups=[group],
        user="reviewer",
        result_store=_AutomaticResultStore([affected, probable]),
    )

    preview = build_automatic_assessment_preview(context)
    item = preview["items"][0]

    assert item["rescore"] == {
        "source": "analyzer",
        "source_run_id": "run-affected",
        "current_score": 8.1,
        "current_vector": group["cvss_vector"],
        "original_score": 8.1,
        "original_vector": group["cvss_vector"],
        "proposed_score": 3.7,
        "proposed_vector": f"{group['cvss_vector']}/CR:L/IR:L/AR:L",
        "proposed_severity": "LOW",
    }
    assert preview["summary"]["rescored_groups"] == 1
    assert preview["summary"]["low_rescored_affected_groups"] == 1

    payloads, _skipped = build_automatic_assessment_payloads(
        context,
        [group["id"]],
    )
    details = payloads[0][1]["details"]
    assert details.startswith(
        "[Rescored: 3.7] "
        f"[Rescored Vector: {group['cvss_vector']}/CR:L/IR:L/AR:L]"
    )
    assert details.count("[Rescored:") == 1
    assert details.count("[Rescored Vector:") == 1
    assert all(payload["details"] == details for _instance, payload in payloads)

    summary = summarize_grouped_vulnerabilities([group], {})
    task = {
        "status": "completed",
        "result_mode": "summary",
        "result": summary,
        "_full_result": [group],
        "_full_result_by_id": {group["id"]: group},
        "_group_query_index": build_task_group_query_index(summary),
    }
    assert _refresh_grouped_vuln_task_snapshots(
        {"task-1": task},
        payloads,
        {},
    ) == 1
    refreshed = task["_full_result"][0]
    assert refreshed["rescored_cvss"] == 3.7
    assert (
        refreshed["rescored_vector"]
        == f"{group['cvss_vector']}/CR:L/IR:L/AR:L"
    )
    assert all(
        component["analysis_details"].startswith("[Rescored: 3.7]")
        for version in refreshed["affected_versions"]
        for component in version["components"]
    )


def _owned_team_mapping():
    return {"owned-api": ["TEAM-API"], "owned-worker": ["TEAM-WORKER"]}


def test_automatic_assessment_workflow_writes_one_block_per_owning_team():
    group = _automatic_group()
    group.update(
        {
            "cvss_score": 9.8,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        }
    )
    context = BulkWorkflowContext(
        task_id="task-1",
        groups=[group],
        user="reviewer",
        team_mapping=_owned_team_mapping(),
        result_store=_AutomaticResultStore(
            [
                _automatic_record(
                    "run-api",
                    "owned-api",
                    "Not Affected",
                    exposure="none",
                    adjusted_cvss={
                        "original_score": 9.8,
                        "adjusted_score": 0.0,
                        "adjusted_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                    },
                ),
                _automatic_record(
                    "run-worker",
                    "owned-worker",
                    "Affected",
                    adjusted_cvss={
                        "original_score": 9.8,
                        "adjusted_score": 7.5,
                        "adjusted_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                    },
                ),
            ]
        ),
    )

    preview_item = build_automatic_assessment_preview(context)["items"][0]
    assert preview_item["teams"] == ["TEAM-API", "TEAM-WORKER"]
    assert preview_item["unowned_components"] == []

    payloads, _skipped = build_automatic_assessment_payloads(context, [group["id"]])
    details = payloads[0][1]["details"]

    # Global block: worst state plus the worst assessment's CVSS, no evidence text.
    assert payloads[0][1]["state"] == "EXPLOITABLE"
    assert details.startswith(
        "[Rescored: 7.5] "
        "[Rescored Vector: CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N]"
    )
    assert (
        "--- [Team: General] [State: EXPLOITABLE] "
        "[Assessed By: Automated Code Analysis] [Justification: NOT_SET] "
        "[Evidence Reviewed: yes] [Analysis Runs: run-api, run-worker] ---"
    ) in details
    assert "Assessed Teams: TEAM-API, TEAM-WORKER" in details

    global_block = details.split("--- [Team: TEAM-API]")[0]
    assert "[Automatic Assessment: run-api]" not in global_block
    assert "[Automatic Assessment: run-worker]" not in global_block

    # Team blocks: each team keeps its own verdict and its own evidence.
    assert (
        "--- [Team: TEAM-API] [State: NOT_AFFECTED] "
        "[Assessed By: Automated Code Analysis] [Justification: CODE_NOT_PRESENT] "
        "[Evidence Reviewed: yes] [Analysis Runs: run-api] ---"
    ) in details
    assert (
        "--- [Team: TEAM-WORKER] [State: EXPLOITABLE] "
        "[Assessed By: Automated Code Analysis] [Justification: NOT_SET] "
        "[Evidence Reviewed: yes] [Analysis Runs: run-worker] ---"
    ) in details

    api_block, worker_block = details.split("--- [Team: TEAM-WORKER]")
    assert "[Automatic Assessment: run-api]" in api_block
    assert "owned-api was assessed as Not Affected." in api_block
    assert "[Automatic Assessment: run-worker]" not in api_block
    assert "[Automatic Assessment: run-worker]" in worker_block
    assert "owned-worker was assessed as Affected." in worker_block
    assert "[Automatic Assessment: run-api]" not in worker_block


def test_automatic_assessment_workflow_combines_one_team_worst_wins():
    group = _automatic_group()
    context = BulkWorkflowContext(
        task_id="task-1",
        groups=[group],
        user="reviewer",
        team_mapping={"owned-api": ["TEAM-API"], "owned-worker": ["team-api"]},
        result_store=_AutomaticResultStore(
            [
                _automatic_record("run-api", "owned-api", "Not Affected", exposure="none"),
                _automatic_record("run-worker", "owned-worker", "Probably Affected"),
            ]
        ),
    )

    payloads, _skipped = build_automatic_assessment_payloads(context, [group["id"]])
    details = payloads[0][1]["details"]

    assert details.count("--- [Team: ") == 2
    assert (
        "--- [Team: TEAM-API] [State: IN_TRIAGE] "
        "[Assessed By: Automated Code Analysis] [Justification: NOT_SET] "
        "[Evidence Reviewed: yes] [Analysis Runs: run-api, run-worker] ---"
    ) in details
    assert "[Automatic Assessment: run-api]" in details
    assert "[Automatic Assessment: run-worker]" in details


def test_automatic_assessment_rescore_follows_the_worst_verdict():
    group = _automatic_group()
    group.update(
        {
            "cvss_score": 9.8,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        }
    )
    context = BulkWorkflowContext(
        task_id="task-1",
        groups=[group],
        user="reviewer",
        team_mapping=_owned_team_mapping(),
        result_store=_AutomaticResultStore(
            [
                _automatic_record(
                    "run-api",
                    "owned-api",
                    "Not Affected",
                    exposure="none",
                    adjusted_cvss={
                        "original_score": 9.8,
                        "adjusted_score": 9.0,
                        "adjusted_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L",
                    },
                ),
                _automatic_record(
                    "run-worker",
                    "owned-worker",
                    "Affected",
                    adjusted_cvss={
                        "original_score": 9.8,
                        "adjusted_score": 5.0,
                        "adjusted_vector": "CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:H/I:N/A:N",
                    },
                ),
            ]
        ),
    )

    item = build_automatic_assessment_preview(context)["items"][0]
    assert item["rescore"]["source_run_id"] == "run-worker"
    assert item["rescore"]["proposed_score"] == 5.0
    assert (
        item["rescore"]["proposed_vector"]
        == "CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:H/I:N/A:N"
    )

    payloads, _skipped = build_automatic_assessment_payloads(context, [group["id"]])
    assert payloads[0][1]["details"].startswith(
        "[Rescored: 5.0] "
        "[Rescored Vector: CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:H/I:N/A:N]"
    )


def _rescore_rules():
    return json.loads(Path("data/rescore_rules.json").read_text())


def test_automatic_assessment_applies_configured_rescore_rules_to_the_global_state():
    group = _automatic_group()
    group.update(
        {
            "cvss_score": 9.8,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        }
    )
    context = BulkWorkflowContext(
        task_id="task-1",
        groups=[group],
        user="reviewer",
        team_mapping=_owned_team_mapping(),
        rescore_rules=_rescore_rules(),
        result_store=_AutomaticResultStore(
            [
                _automatic_record("run-api", "owned-api", "Not Affected", exposure="none"),
                _automatic_record(
                    "run-worker",
                    "owned-worker",
                    "Not Affected",
                    exposure="none",
                    adjusted_cvss={
                        "original_score": 9.8,
                        "adjusted_score": 4.2,
                        "adjusted_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:U",
                    },
                ),
            ]
        ),
    )

    item = build_automatic_assessment_preview(context)["items"][0]
    assert item["target_state"] == "NOT_AFFECTED"
    assert item["rescore"]["source"] == "rescore_rules"
    assert item["rescore"]["proposed_score"] == 0.0
    # The analyzer's own metrics survive; the configured rule decides the rest.
    assert "E:U" in item["rescore"]["proposed_vector"]
    for metric in ("CR:L", "IR:L", "AR:L", "MAC:H", "MAV:P", "MPR:H", "MUI:R", "MC:N", "MI:N", "MA:N"):
        assert metric in item["rescore"]["proposed_vector"]

    payloads, _skipped = build_automatic_assessment_payloads(context, [group["id"]])
    details = payloads[0][1]["details"]
    assert details.startswith(
        f"[Rescored: 0.0] [Rescored Vector: {item['rescore']['proposed_vector']}]"
    )

    # The applied result must satisfy Repair Rescoring Definitions right away.
    applied = json.loads(json.dumps(group))
    for version in applied["affected_versions"]:
        for component in version["components"]:
            component["analysis_state"] = payloads[0][1]["state"]
            component["analysis_details"] = details
    repair = create_rescore_rule_sync_workflow(_rescore_rules).preview(
        BulkWorkflowContext(task_id="task-1", groups=[applied], user="reviewer")
    )
    assert repair["items"] == []


def test_automatic_assessment_rescores_a_not_affected_state_without_analyzer_cvss():
    group = _automatic_group()
    group.update(
        {
            "cvss_score": 9.8,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        }
    )
    context = BulkWorkflowContext(
        task_id="task-1",
        groups=[group],
        user="reviewer",
        team_mapping=_owned_team_mapping(),
        rescore_rules=_rescore_rules(),
        result_store=_AutomaticResultStore(
            [
                _automatic_record("run-api", "owned-api", "Not Affected", exposure="none"),
                _automatic_record("run-worker", "owned-worker", "Not Affected"),
            ]
        ),
    )

    payloads, _skipped = build_automatic_assessment_payloads(context, [group["id"]])
    details = payloads[0][1]["details"]
    assert "[Rescored: 0.0]" in details
    assert "[Rescored Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/" in details


def test_automatic_assessment_keeps_the_analyzer_rescore_for_unruled_states():
    group = _automatic_group()
    group.update(
        {
            "cvss_score": 9.8,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        }
    )
    context = BulkWorkflowContext(
        task_id="task-1",
        groups=[group],
        user="reviewer",
        team_mapping=_owned_team_mapping(),
        rescore_rules=_rescore_rules(),
        result_store=_AutomaticResultStore(
            [
                _automatic_record(
                    "run-worker",
                    "owned-worker",
                    "Affected",
                    adjusted_cvss={
                        "original_score": 9.8,
                        "adjusted_score": 7.5,
                        "adjusted_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                    },
                ),
            ]
        ),
    )

    item = build_automatic_assessment_preview(context)["items"][0]
    assert item["target_state"] == "EXPLOITABLE"
    assert item["rescore"]["source"] == "analyzer"
    assert item["rescore"]["proposed_score"] == 7.5


def test_automatic_assessment_keeps_unowned_evidence_in_the_global_block():
    group = _automatic_group()
    context = BulkWorkflowContext(
        task_id="task-1",
        groups=[group],
        user="reviewer",
        result_store=_AutomaticResultStore(
            [
                _automatic_record(
                    "run-api",
                    "owned-api",
                    "Affected",
                    target_team=None,
                ),
            ]
        ),
    )

    item = build_automatic_assessment_preview(context)["items"][0]
    assert item["teams"] == []
    assert item["unowned_components"] == ["owned-api"]

    payloads, _skipped = build_automatic_assessment_payloads(context, [group["id"]])
    details = payloads[0][1]["details"]
    assert details.count("--- [Team: ") == 1
    assert "--- [Team: General] [State: EXPLOITABLE]" in details
    assert "Assessed Teams:" not in details
    assert "[Automatic Assessment: run-api]" in details


def test_automatic_assessment_workflow_preserves_semantic_analysis_and_rationales():
    records = []
    for index in range(1, 6):
        record = _automatic_record(
            f"run-complete-{index}",
            f"owned-component-{index}",
            "Not Affected",
            exposure="none",
        )
        assessment = record["result"]["assessment"]
        assessment.update(
            {
                "summary": (
                    f"Generated summary {index} "
                    + ("summary context " * 50)
                    + f"SUMMARY_END_{index}"
                ),
                "reasoning": (
                    f"Generated rationale {index} "
                    + ("rationale context " * 50)
                    + f"RATIONALE_END_{index}"
                ),
                "details": (
                    "VULNERABILITY ASSESSMENT REPORT\n"
                    + ("detailed evidence " * 50)
                    + f"DETAILS_END_{index}"
                ),
                "dependency_presence": {
                    "presence_basis": "direct",
                    "declared_in": [
                        f"manifest-{fact_index}.xml"
                        for fact_index in range(1, 11)
                    ],
                },
                "version_analysis": {
                    "note": (
                        "Complete version rationale "
                        + ("version context " * 50)
                        + f"VERSION_NOTE_END_{index}"
                    ),
                    "affected_product_versions": [
                        f"release-{release_index}"
                        for release_index in range(1, 11)
                    ],
                    "checked_versions": [
                        {"ref": f"raw-ref-{ref_index}", "notes": "not found"}
                        for ref_index in range(1, 11)
                    ],
                },
                "remediation_view": {
                    "recommendations": [
                        f"Recommendation {recommendation_index}"
                        + (
                            " REMEDIATION_END"
                            if recommendation_index == 10
                            else ""
                        )
                        for recommendation_index in range(1, 11)
                    ]
                },
                "adjusted_cvss": {
                    "original_score": 8.1,
                    "adjusted_score": 0.0,
                    "adjusted_vector": "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N",
                    "summary": "Complete CVSS rationale CVSS_SUMMARY_END",
                    "reasons": [
                        f"CVSS reason {reason_index}"
                        + (" CVSS_REASON_END" if reason_index == 10 else "")
                        for reason_index in range(1, 11)
                    ],
                },
            }
        )
        if index == 1:
            record["result"]["component_results"] = [
                {
                    "component": f"nested-component-{component_index}",
                    "assessment": {
                        "summary": f"Nested summary {component_index}",
                        "reasoning": (
                            f"Nested rationale {component_index}"
                            + (" COMPONENT_RATIONALE_END" if component_index == 10 else "")
                        ),
                    },
                }
                for component_index in range(1, 11)
            ]
        records.append(record)

    context = BulkWorkflowContext(
        task_id="task-1",
        groups=[_automatic_group()],
        user="reviewer",
        result_store=_AutomaticResultStore(records),
    )

    payloads, _skipped = build_automatic_assessment_payloads(
        context,
        ["CVE-2026-AUTO"],
    )
    details = payloads[0][1]["details"]

    assert details.count("[Automatic Assessment: run-complete-") == 5
    assert "SUMMARY_END_1" in details
    assert "SUMMARY_END_5" in details
    assert "RATIONALE_END_1" in details
    assert "RATIONALE_END_5" in details
    assert "DETAILS_END_1" not in details
    assert "DETAILS_END_5" not in details
    assert "Declared in: manifest-10.xml" in details
    assert "VERSION_NOTE_END_1" in details
    assert "VERSION_NOTE_END_5" in details
    assert "Affected product versions: release-1, release-2" in details
    assert "REMEDIATION_END" in details
    assert "CVSS_SUMMARY_END" in details
    assert "CVSS_REASON_END" in details
    assert "COMPONENT_RATIONALE_END" in details
    assert "raw-ref-10" not in details
    assert "omitted for readability" not in details
    assert "Additional analyzer detail omitted" not in details


def test_automatic_assessment_workflow_uses_composite_identity_without_finding_uuid():
    group = _automatic_group()
    for instance in group["affected_versions"][0]["components"]:
        instance.pop("finding_uuid")
    context = BulkWorkflowContext(
        task_id="task-1",
        groups=[group],
        user="reviewer",
        result_store=_AutomaticResultStore(
            [_automatic_record("run-auto", "owned-api", "Not Affected")]
        ),
    )

    preview = build_automatic_assessment_preview(context)
    payloads, skipped = build_automatic_assessment_payloads(context, [group["id"]])

    assert preview["summary"]["findings"] == 2
    assert preview["summary"]["missing_identity_findings"] == 0
    assert len(payloads) == 2
    assert all(instance["finding_uuid"].startswith("finding:project-1:") for instance, _payload in payloads)
    assert skipped["missing_identity"] == 0


def test_automatic_assessment_workflow_hydrates_only_selected_full_results():
    adjusted_cvss = {
        "original_score": 8.1,
        "original_vector": "CVSS:3.1/AV:N/AC:L/C:H",
        "adjusted_score": 3.2,
        "adjusted_vector": "CVSS:3.1/AV:N/AC:L/C:H/CR:L",
    }
    metadata_record = {
        "analysis_run_id": "run-auto",
        "vuln_id": "cve-2026-auto",
        "project_names": ["exampleapp"],
        "component_names": ["owned-api", "owned-worker"],
        "source_kind": "auto",
        "has_assessment": True,
        "assessment": {
            "affected": True,
            "verdict": "Affected",
            "adjusted_cvss": adjusted_cvss,
        },
    }
    full_record = _automatic_record("run-auto", "owned-api", "Affected")
    full_record["result"]["assessment"]["details"] = "Full selected evidence"
    full_record["result"]["assessment"]["adjusted_cvss"] = adjusted_cvss

    class MetadataStore:
        get_many_calls: list[list[str]] = []

        def list_assessment_metadata(self, **_kwargs):
            return {
                "records": [metadata_record],
                "stored_analysis_results": 1,
                "usable_assessment_results": 1,
            }

        def get_many(self, run_ids):
            self.get_many_calls.append(run_ids)
            return [full_record]

        def list_applications(self, **_kwargs):
            return []

    store = MetadataStore()
    context = BulkWorkflowContext(
        task_id="task-1",
        groups=[_automatic_group()],
        user="reviewer",
        result_store=store,
    )

    preview = build_automatic_assessment_preview(context)
    assert preview["items"][0]["verdict_bucket"] == "AFFECTED"
    assert preview["items"][0]["rescore"] == {
        "source": "analyzer",
        "source_run_id": "run-auto",
        "current_score": None,
        "current_vector": "",
        "original_score": 8.1,
        "original_vector": "CVSS:3.1/AV:N/AC:L/C:H",
        "proposed_score": 3.2,
        "proposed_vector": "CVSS:3.1/AV:N/AC:L/C:H/CR:L",
        "proposed_severity": "LOW",
    }
    assert store.get_many_calls == []

    payloads, _skipped = build_automatic_assessment_payloads(
        context,
        ["CVE-2026-AUTO"],
    )
    assert store.get_many_calls == [["run-auto"]]
    assert "Full selected evidence" in payloads[0][1]["details"]


def test_automatic_assessment_workflow_excludes_fully_applied_findings():
    group = _automatic_group()
    store = _AutomaticResultStore(
        [
            _automatic_record("run-api", "owned-api", "Not Affected"),
            _automatic_record("run-worker", "owned-worker", "Affected"),
        ],
        applications=[
            {"analysis_run_id": run_id, "finding_uuid": finding_uuid, "status": "applied"}
            for run_id in ("run-api", "run-worker")
            for finding_uuid in ("finding-api", "finding-worker")
        ],
    )
    context = BulkWorkflowContext(
        task_id="task-1", groups=[group], user="reviewer", result_store=store
    )

    assert build_automatic_assessment_preview(context)["items"] == []
    assert build_automatic_assessment_payloads(context, [group["id"]])[0] == []


def test_automatic_assessment_workflow_includes_reviewer_started_and_follow_up_results():
    group = _automatic_group()
    store = _AutomaticResultStore(
        [
            _automatic_record(
                "run-manual",
                "owned-api",
                "Not Affected",
                source="manual",
            ),
            _automatic_record(
                "run-follow-up",
                "owned-worker",
                "Probably Affected",
                source="follow-up",
            ),
            _automatic_record(
                "run-benchmark",
                "benchmark-target",
                "Affected",
                source="benchmark",
            ),
        ]
    )
    context = BulkWorkflowContext(
        task_id="task-1",
        groups=[group],
        user="reviewer",
        result_store=store,
    )

    preview = build_automatic_assessment_preview(context)
    payloads, _skipped = build_automatic_assessment_payloads(context, [group["id"]])

    assert preview["items"][0]["run_ids"] == ["run-follow-up", "run-manual"]
    assert preview["items"][0]["verdict_bucket"] == "PROBABLY_AFFECTED"
    assert {payload[1]["state"] for payload in payloads} == {"IN_TRIAGE"}
    assert "Run Source: manual" in payloads[0][1]["details"]
    assert "Run Source: follow-up" in payloads[0][1]["details"]
    assert "run-benchmark" not in payloads[0][1]["details"]


def test_code_assessment_status_distinguishes_source_and_component_coverage():
    group = _automatic_group()
    automatic = [
        _automatic_record("run-auto-api", "owned-api", "Not Affected"),
        _automatic_record("run-auto-worker", "owned-worker", "Not Affected"),
    ]
    manual = [
        _automatic_record(
            "run-manual-api", "owned-api", "Not Affected", source="manual"
        ),
        _automatic_record(
            "run-manual-worker", "owned-worker", "Not Affected", source="manual"
        ),
    ]

    assert assessment_status_for_group(group, automatic) == "auto"
    assert assessment_status_for_group(group, manual) == "manual"
    assert assessment_status_for_group(group, [automatic[0], manual[1]]) == "mixed"
    assert assessment_status_for_group(group, [manual[0]]) == "partial"
    unclassified = _automatic_record(
        "run-unclassified", "owned-api", "Not Affected", source=""
    )
    unclassified["context_summary"]["components"] = [
        {"project_name": "ExampleApp", "component_name": "owned-api"},
        {"project_name": "ExampleApp", "component_name": "owned-worker"},
    ]
    assert assessment_status_for_group(group, [unclassified]) == "manual"


def test_automatic_assessment_workflow_accepts_source_less_legacy_summary_results():
    record = {
        "analysis_run_id": "run-unclassified",
        "compact_context": {
            "target": {
                "project_name": "ExampleApp",
                "vuln_id": "CVE-2026-AUTO",
                "component_name": "owning-service",
            },
            "request_context": {
                "context_summary": {
                    "project_name": "ExampleApp",
                    "target_component": "owning-service",
                    "components": [
                        {
                            "project_name": "ExampleApp",
                            "component_name": "owned-api",
                        }
                    ],
                }
            },
        },
        "summary": {
            "affected": True,
            "verdict": "Probably Affected",
            "confidence": "Medium",
            "exposure": "possibly reachable",
            "summary": "A legacy analyzer result without a source tag.",
            "reasoning": "The vulnerable path could not be ruled out.",
            "versions_checked": ["1.2.3"],
        },
    }
    context = BulkWorkflowContext(
        task_id="task-1",
        groups=[_automatic_group()],
        user="reviewer",
        result_store=_AutomaticResultStore([record]),
    )

    preview = build_automatic_assessment_preview(context)
    payloads, _skipped = build_automatic_assessment_payloads(
        context,
        ["CVE-2026-AUTO"],
    )

    assert preview["items"][0]["run_ids"] == ["run-unclassified"]
    assert preview["items"][0]["verdict_bucket"] == "PROBABLY_AFFECTED"
    assert preview["summary"]["stored_analysis_results"] == 1
    assert preview["summary"]["usable_assessment_results"] == 1
    assert preview["summary"]["matched_analysis_results"] == 1
    assert {payload[1]["state"] for payload in payloads} == {"IN_TRIAGE"}
    assert "Run Source: legacy" in payloads[0][1]["details"]
    assert "Versions Checked:" in payloads[0][1]["details"]
    assert "Versions Checked:\n  - 1.2.3" in payloads[0][1]["details"]


def test_automatic_assessment_workflow_recognizes_legacy_run_markers_and_project_scope():
    group = _automatic_group()
    for instance in group["affected_versions"][0]["components"]:
        instance["analysis_details"] = "[Analysis Run: run-applied]\nApplied assessment"
    applied_context = BulkWorkflowContext(
        task_id="task-1",
        groups=[group],
        user="reviewer",
        result_store=_AutomaticResultStore(
            [_automatic_record("run-applied", "owning-service", "Not Affected")]
        ),
    )
    other_project_record = _automatic_record(
        "run-other-project", "owning-service", "Affected"
    )
    other_project_record["project_name"] = "OtherApp"
    other_project_context = BulkWorkflowContext(
        task_id="task-1",
        groups=[_automatic_group()],
        user="reviewer",
        result_store=_AutomaticResultStore([other_project_record]),
    )

    assert build_automatic_assessment_preview(applied_context)["items"] == []
    assert build_automatic_assessment_preview(other_project_context)["items"] == []


def test_automatic_assessment_workflow_matches_indirect_scan_targets_and_replaces_existing():
    group = _automatic_group()
    group["affected_versions"][0]["components"][0]["analysis_state"] = "IN_TRIAGE"
    group["affected_versions"][0]["components"][0]["analysis_details"] = "Manual triage note"
    record = _automatic_record("run-owner", "owning-service", "Affected")
    record["context_summary"] = {
        "project_name": "ExampleApp",
        "target_component": "owning-service",
        "target_team": "API",
        "components": [
            {"project_name": "ExampleApp", "component_name": "owned-api"},
            {"project_name": "ExampleApp", "component_name": "owned-worker"},
        ],
    }
    context = BulkWorkflowContext(
        task_id="task-1",
        groups=[group],
        user="reviewer",
        result_store=_AutomaticResultStore([record]),
    )

    preview = build_automatic_assessment_preview(context)

    assert preview["items"][0]["group_id"] == "CVE-2026-AUTO"
    assert preview["items"][0]["eligible_finding_count"] == 2
    assert preview["items"][0]["preexisting_finding_count"] == 1
    payloads, skipped = build_automatic_assessment_payloads(context, [group["id"]])
    assert {payload[1]["state"] for payload in payloads} == {"EXPLOITABLE"}
    assert skipped["replaced_existing"] == 1


@pytest.mark.parametrize(
    ("verdict", "expected_state", "expected_justification"),
    [
        ("Affected", "EXPLOITABLE", "NOT_SET"),
        ("Probably Affected", "IN_TRIAGE", "NOT_SET"),
        ("Uncertain", "IN_TRIAGE", "NOT_SET"),
        ("Not Affected", "NOT_AFFECTED", "CODE_NOT_REACHABLE"),
    ],
)
def test_automatic_assessment_workflow_maps_overall_verdicts(
    verdict,
    expected_state,
    expected_justification,
):
    record = _automatic_record("run-overall", "owning-service", verdict)
    assessment = record["result"]["assessment"]
    assessment.update(
        {
            "analysis": "ANALYZER_STATE",
            "justification": "ANALYZER_JUSTIFICATION",
            "response": "UPDATE",
            "details": "Detailed analyzer evidence.",
            "advisory_sources": ["NVD", "vendor advisory"],
            "dependency_presence": {"sbom_attributed": True, "repo_found": False},
            "version_analysis": {"detected_version": "1.2.3"},
        }
    )
    context = BulkWorkflowContext(
        task_id="task-1",
        groups=[_automatic_group()],
        user="reviewer",
        result_store=_AutomaticResultStore([record]),
    )

    payloads, skipped = build_automatic_assessment_payloads(
        context,
        ["CVE-2026-AUTO"],
    )

    assert len(payloads) == 2
    assert {payload[1]["state"] for payload in payloads} == {expected_state}
    assert {payload[1]["justification"] for payload in payloads} == {
        expected_justification
    }
    details = payloads[0][1]["details"]
    assert f"Overall Assessment State: {expected_state}" in details
    assert "Analyzer state: ANALYZER_STATE" in details
    assert "Analyzer justification: ANALYZER_JUSTIFICATION" in details
    assert "Suggested response: UPDATE" in details
    assert "Additional analysis:\nDetailed analyzer evidence." in details
    assert (
        "Dependency evidence:\nPresent via SBOM attribution; not rediscovered "
        "in repository manifests or lock files."
        in details
    )
    assert "Version evidence:\nDetected version: 1.2.3" in details
    assert '"sbom_attributed"' not in details
    assert skipped == {
        "already_applied": 0,
        "missing_identity": 0,
        "replaced_existing": 0,
    }


def test_application_provenance_records_success_queue_and_failure():
    class Store:
        def __init__(self):
            self.calls = []

        def record_application(self, **application):
            self.calls.append(application)

    class Logger:
        def exception(self, *_args):
            raise AssertionError("provenance recording should not fail")

    store = Store()
    deps = type(
        "Deps",
        (),
        {"code_analysis_result_store": store, "logger": Logger()},
    )()
    payloads = [
        (
            {
                "finding_uuid": f"finding-{index}",
                "analysis_run_ids": [f"run-{index}"],
                "bulk_workflow_group_id": "CVE-2026-AUTO",
            },
            {"state": "NOT_AFFECTED", "details": str(index)},
        )
        for index in range(1, 4)
    ]
    _record_code_analysis_applications(
        deps,
        payloads=payloads,
        finalized=[
            {"uuid": "finding-1", "status": "success"},
            {"uuid": "finding-2", "status": "error", "queued": True},
            {"uuid": "finding-3", "status": "error", "queued": False},
        ],
        user="reviewer",
        workflow_id="automatic-assessments",
    )

    assert [call["status"] for call in store.calls] == ["applied", "queued", "failed"]
    assert all(call["payload_fingerprint"] for call in store.calls)
