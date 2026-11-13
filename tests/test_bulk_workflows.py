import json
from pathlib import Path

import pytest
from dtvp.ssvc_services import SsvcInput, new_record, read_record, write_record

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
from dtvp.bulk_workflows.assessment_repair import (
    _apply_payloads,
    build_assessment_repair_payloads,
    build_assessment_repair_preview,
    create_assessment_repair_workflow,
)
from dtvp.rescore_rule_services import build_rescore_rule_sync_preview
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


_HUMAN_REVIEW_PREFIX = (
    "HUMAN REVIEW REQUIRED: Read and manually verify this assessment; "
    "a human must approve it before use.\n\n"
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
    plugin = create_assessment_repair_workflow(lambda: rules)
    preview = plugin.preview(
        BulkWorkflowContext(task_id="task-1", groups=groups, user="reviewer")
    )

    assert plugin.selectable_ids(preview) == ["CVE-RULE-SYNC"]
    assert plugin.metadata()["label"] == "Repair Assessments"
    assert [repair["id"] for repair in preview["items"][0]["repairs"]] == ["rescoring"]
    assert preview["items"][0]["finding_count"] == 1
    finding = preview["items"][0]["rescore_findings"][0]
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


@pytest.mark.parametrize("workflow", ["incomplete", "automatic"])
def test_bulk_assessments_preserve_ssvc_per_finding(workflow):
    group = _automatic_group()
    group["list_metadata"] = {"lifecycle": "INCOMPLETE"}
    instances = [instance for version in group["affected_versions"] for instance in version["components"]]
    record = new_record(SsvcInput(model="ssvc:DT_DP", version="1.0.0", answers={}, rationale="Local context"), "reviewer")
    instances[0]["analysis_details"] = write_record(instances[0].get("analysis_details") or "", record)
    if workflow == "incomplete":
        payloads, _ = build_incomplete_sync_payloads([group], [group["id"]])
    else:
        context = BulkWorkflowContext(task_id="task", groups=[group], user="reviewer", result_store=_AutomaticResultStore([_automatic_record("run-api", "owned-api", "Not Affected", exposure="none")]))
        payloads, _ = build_automatic_assessment_payloads(context, [group["id"]])
    assert len(payloads) == len(instances)
    for instance, payload in payloads:
        assert read_record(payload["details"]) == read_record(instance.get("analysis_details") or "")


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
        _HUMAN_REVIEW_PREFIX
        + "[Rescored: 3.7] "
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
        component["analysis_details"].startswith(_HUMAN_REVIEW_PREFIX + "[Rescored: 3.7]")
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
        _HUMAN_REVIEW_PREFIX
        + "[Rescored: 7.5] "
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
        _HUMAN_REVIEW_PREFIX
        + "[Rescored: 5.0] "
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
        _HUMAN_REVIEW_PREFIX
        + f"[Rescored: 0.0] [Rescored Vector: {item['rescore']['proposed_vector']}]"
    )

    # The applied result must satisfy the rescoring repair right away.
    applied = json.loads(json.dumps(group))
    for version in applied["affected_versions"]:
        for component in version["components"]:
            component["analysis_state"] = payloads[0][1]["state"]
            component["analysis_details"] = details
    repair = build_rescore_rule_sync_preview([applied], _rescore_rules())
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


def test_automatic_assessment_workflow_compacts_results_with_executive_summaries():
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
                "executive_summary": {
                    "vulnerability": f"Executive vulnerability {index}",
                    "assessment": f"Executive assessment {index}",
                    "why": [
                        f"Decision reason {index}",
                        (
                            "Complete decisive path evidence "
                            + ("path context " * 50)
                            + f"WHY_END_{index}"
                        ),
                    ],
                },
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
                    "locked_version": f"1.0.{index}",
                    "declared_in": [
                        f"manifest-{fact_index}.xml"
                        for fact_index in range(1, 11)
                    ],
                },
                "version_analysis": {
                    "current_workspace_affected": False,
                    "covered_product_versions": [
                        f"release-{release_index}"
                        for release_index in range(1, 11)
                    ],
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
                    "status": "action_needed",
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
                "audit_view": {
                    "status": "review",
                    "checks": [
                        f"Concern: Review concern {index}",
                        "Concern: Secondary concern",
                    ],
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
    assert "Executive summary:" in details
    assert "Vulnerability: Executive vulnerability 1" in details
    assert "Assessment: Executive assessment 5" in details
    assert "Decision rationale:" in details
    assert "Decision reason 1" in details
    assert "WHY_END_5" in details
    assert "Direct dependency" in details
    assert "Resolved version 1.0.1" in details
    assert "Current dependency version affected: no" in details
    assert (
        "Product versions covered: release-1, release-2, release-3, release-4, "
        "release-5, release-6, release-7, release-8, release-9, release-10"
    ) in details
    assert "Product versions covered:\n" not in details
    assert "release-10" in details
    assert "Review concern 1" not in details
    assert "Recommendation 1" not in details
    assert "Secondary concern" not in details
    assert "SUMMARY_END_1" not in details
    assert "SUMMARY_END_5" not in details
    assert "RATIONALE_END_1" not in details
    assert "RATIONALE_END_5" not in details
    assert "DETAILS_END_1" not in details
    assert "DETAILS_END_5" not in details
    assert "Declared in: manifest-10.xml" not in details
    assert "VERSION_NOTE_END_1" not in details
    assert "VERSION_NOTE_END_5" not in details
    assert "Caller-supplied affected project releases" not in details
    assert "REMEDIATION_END" not in details
    assert "CVSS_SUMMARY_END" not in details
    assert "CVSS_REASON_END" not in details
    assert "COMPONENT_RATIONALE_END" not in details
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


def _takeover_group(*, details: str, tags: list[str] | None = None, group_id: str = "CVE-TAKEOVER"):
    return {
        "id": group_id,
        "title": group_id,
        "tags": tags if tags is not None else ["TeamB"],
        "affected_versions": [{
            "project_name": "Project",
            "project_version": "1.0",
            "components": [{
                "project_uuid": "project-1",
                "component_uuid": "component-1",
                "component_name": "library-a",
                "vulnerability_uuid": "vulnerability-1",
                "finding_uuid": "finding-1",
                "tags": tags if tags is not None else ["TeamB"],
                "analysis_state": "EXPLOITABLE",
                "analysis_details": details,
                "justification": "NOT_SET",
            }],
        }],
    }


def test_historical_blocks_do_not_count_as_current_team_coverage():
    details = (
        "--- [Team: TeamA] [State: EXPLOITABLE] [Assessed By: alice] "
        "[Historical: yes] ---\nFormer owner\n\n"
        "--- [Team: TeamB] [State: RESOLVED] [Assessed By: bob] "
        "[Copied From: TeamA] ---\nCurrent owner"
    )
    group = _takeover_group(details=details)
    group["affected_versions"][0]["components"][0]["analysis_state"] = "RESOLVED"
    metadata = summarize_grouped_vulnerabilities([group], {})[0]["list_metadata"]
    assert metadata["assessed_teams"] == ["TeamB"]
    assert metadata["technical_state"] == "RESOLVED"
    assert metadata["lifecycle"] == "ASSESSED"


def test_historical_marker_survives_ordinary_backend_assessment_edit():
    from dtvp.logic import process_assessment_details

    existing = (
        "--- [Team: TeamA] [State: EXPLOITABLE] [Assessed By: alice] "
        "[Historical: yes] ---\nFormer rationale\n\n"
        "--- [Team: TeamB] [State: RESOLVED] [Assessed By: bob] "
        "[Copied From: TeamA] ---\nCurrent rationale"
    )
    updated, state = process_assessment_details(
        "Updated rationale", "bob", "ANALYST", team="TeamB",
        state="RESOLVED", existing_details=existing,
    )
    assert "[Historical: yes]" in updated
    assert "[Copied From: TeamA]" in updated
    assert state == "RESOLVED"



def _repair_group(details_by_finding: list[tuple[str, str]], *, tags: list[str], lifecycle: str | None = None):
    group = {
        "id": "CVE-REPAIR",
        "title": "CVE-REPAIR",
        "tags": tags,
        "affected_versions": [{
            "project_name": "Project",
            "project_version": f"{index}.0",
            "components": [{
                "project_uuid": f"project-{index}",
                "component_uuid": f"component-{index}",
                "component_name": "library-a",
                "vulnerability_uuid": "vulnerability-1",
                "finding_uuid": f"finding-{index}",
                "tags": tags,
                "analysis_state": state,
                "analysis_details": details,
                "justification": "NOT_SET",
            }],
        } for index, (state, details) in enumerate(details_by_finding, start=1)],
    }
    metadata = summarize_grouped_vulnerabilities([group], {})[0]["list_metadata"]
    group["list_metadata"] = {**metadata, **({"lifecycle": lifecycle} if lifecycle else {})}
    return group


def _repair(group, *, team_mapping=None, rules=None):
    context = BulkWorkflowContext(
        task_id="task-1", groups=[group], user="reviewer", team_mapping=team_mapping or {},
    )
    load_rules = lambda: rules if rules is not None else {}
    preview = build_assessment_repair_preview(context, load_rules)
    payloads, skipped = build_assessment_repair_payloads(context, [group["id"]], load_rules)
    return preview, payloads, skipped


_FORMER = "--- [Team: TeamA] [State: NOT_AFFECTED] [Assessed By: alice] [Justification: CODE_NOT_REACHABLE] ---\nNot reachable."
_CURRENT = "--- [Team: TeamB] [State: NOT_AFFECTED] [Assessed By: bob] [Justification: CODE_NOT_PRESENT] ---\nNot shipped."


def _labels(preview):
    return [repair["id"] for repair in preview["items"][0]["repairs"]]


def _former_label(preview):
    return next(
        repair["label"]
        for repair in preview["items"][0]["repairs"]
        if repair["id"] == "former_teams"
    )


def test_repair_moves_superseded_former_team_into_global_notes_without_deciding():
    both = ("NOT_AFFECTED", f"{_FORMER}\n\n{_CURRENT}")
    group = _repair_group([both, both], tags=["TeamB"])
    assert group["list_metadata"]["lifecycle"] == "ASSESSED"

    preview, payloads, _ = _repair(group)

    assert _labels(preview) == ["former_teams"]
    assert preview["items"][0]["former_teams"] == ["TeamA"]
    assert preview["items"][0]["finding_count"] == 2
    assert _former_label(preview) == "Move former team assessment to global notes: TeamA"
    details = payloads[0][1]["details"]
    assert "[Team: TeamA]" not in details
    assert "[Team: General] [State: NOT_SET]" in details
    assert "Former team assessment (TeamA; NOT_AFFECTED; justification CODE_NOT_REACHABLE; assessed by alice):\nNot reachable." in details
    assert "[Team: TeamB] [State: NOT_AFFECTED]" in details and "Not shipped." in details
    assert payloads[0][1]["state"] == "NOT_AFFECTED"

    applied = _repair_group([("NOT_AFFECTED", details)] * 2, tags=["TeamB"])
    assert applied["list_metadata"]["lifecycle"] == "ASSESSED"
    assert applied["list_metadata"]["assessed_teams"] == ["TeamB"]
    assert _repair(applied)[0]["items"] == []


def test_repair_promotes_approved_former_team_to_global_and_refers_open_teams():
    group = _repair_group([("NOT_AFFECTED", _FORMER)], tags=["TeamB", "TeamC"])

    preview, payloads, _ = _repair(group)

    assert _labels(preview) == ["former_teams"]
    assert _former_label(preview) == (
        "Make former team assessment the global decision: TeamA; "
        "TeamB, TeamC refer to global"
    )
    details = payloads[0][1]["details"]
    assert "[Team: TeamA]" not in details
    assert "[Team: General] [State: NOT_AFFECTED] [Assessed By: reviewer]" in details
    assert "[Justification: CODE_NOT_REACHABLE]" in details
    assert "Not reachable." in details
    for team in ("TeamB", "TeamC"):
        assert f"--- [Team: {team}] [State: NOT_AFFECTED] [Assessed By: reviewer]" in details
    assert details.count("See global assessment.") == 2
    assert "[Status: Pending Review]" not in details

    applied = _repair_group([("NOT_AFFECTED", details)], tags=["TeamB", "TeamC"])
    assert applied["list_metadata"]["lifecycle"] == "ASSESSED"
    assert applied["list_metadata"]["assessed_teams"] == ["TeamB", "TeamC"]
    assert _repair(applied)[0]["items"] == []


def test_repair_keeps_pending_former_team_decision_open_for_current_teams():
    group = _repair_group(
        [("NOT_AFFECTED", f"{_FORMER}\n\n[Status: Pending Review]")], tags=["TeamB"],
    )

    preview, payloads, _ = _repair(group)

    assert _former_label(preview).endswith("TeamB still to assess")
    details = payloads[0][1]["details"]
    assert "[Team: General] [State: NOT_AFFECTED]" in details
    assert "See global assessment." not in details
    assert details.endswith("[Status: Pending Review]")
    applied = _repair_group([("NOT_AFFECTED", details)], tags=["TeamB"])
    assert applied["list_metadata"]["lifecycle"] == "INCOMPLETE"


def test_repair_deduplicates_former_teams_and_never_overrides_an_existing_global():
    other = _FORMER.replace("TeamA", "TeamX").replace("alice", "xavier")
    general = "--- [Team: General] [State: EXPLOITABLE] [Assessed By: rev] [Justification: NOT_SET] ---\nGlobal view."
    group = _repair_group([("EXPLOITABLE", f"{general}\n\n{_FORMER}\n\n{other}")], tags=["TeamB"])

    _, payloads, _ = _repair(group)

    details = payloads[0][1]["details"]
    assert "[Team: General] [State: EXPLOITABLE] [Assessed By: rev]" in details
    assert "Global view." in details
    assert details.count("Former team assessment (") == 1
    assert "(TeamA, TeamX; NOT_AFFECTED; justification CODE_NOT_REACHABLE; assessed by alice, xavier)" in details
    assert "--- [Team: TeamB] [State: EXPLOITABLE] [Assessed By: reviewer]" in details
    assert payloads[0][1]["state"] == "EXPLOITABLE"


def test_repair_leaves_current_historical_and_unowned_groups_alone():
    historical = _FORMER.replace("] ---", "] [Historical: yes] ---")
    assert _repair(_repair_group([("NOT_AFFECTED", _CURRENT)], tags=["TeamB"]))[0]["items"] == []
    assert _repair(
        _repair_group([("NOT_AFFECTED", f"{historical}\n\n{_CURRENT}")], tags=["TeamB"])
    )[0]["items"] == []
    # Without known owners a block cannot be called a former team's.
    assert _repair(_repair_group([("NOT_AFFECTED", _FORMER)], tags=[]))[0]["items"] == []
    # An alias of a current team is the current team.
    assert _repair(
        _repair_group([("NOT_AFFECTED", _FORMER)], tags=["TeamB"]),
        team_mapping={"component": ["TeamB", "TeamA"]},
    )[0]["items"] == []


def test_repair_synchronizes_and_moves_former_team_in_one_write_per_finding():
    both = ("NOT_AFFECTED", f"{_FORMER}\n\n{_CURRENT}")
    group = _repair_group([both, both, ("NOT_SET", "")], tags=["TeamB"])
    assert group["list_metadata"]["lifecycle"] == "INCOMPLETE"

    preview, payloads, skipped = _repair(group)

    assert _labels(preview) == ["sync_findings", "former_teams"]
    assert preview["items"][0]["repairs"][0]["label"] == "Synchronize assessment to 1 finding"
    assert preview["items"][0]["finding_count"] == 3
    assert preview["summary"]["repairable_groups"] == 1
    assert len(payloads) == 3
    assert len({payload["details"] for _, payload in payloads}) == 1
    assert {payload["state"] for _, payload in payloads} == {"NOT_AFFECTED"}
    assert "[Team: TeamA]" not in payloads[0][1]["details"]
    assert skipped == {}


def test_repair_chains_rescoring_on_the_synchronized_result():
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    group = _repair_group([("NOT_AFFECTED", _CURRENT), ("NOT_SET", "")], tags=["TeamB"])
    group["cvss_vector"] = vector

    preview, payloads, _ = _repair(group, rules=_rescore_rules())

    assert _labels(preview) == ["sync_findings", "rescoring"]
    assert preview["items"][0]["finding_count"] == 2
    assert len(payloads) == 2
    for instance, payload in payloads:
        assert instance in [
            component
            for version in group["affected_versions"]
            for component in version["components"]
        ]
        assert "[Team: TeamB] [State: NOT_AFFECTED]" in payload["details"]
        assert "[Rescored: 0.0]" in payload["details"]


def test_repair_reports_invalid_rescore_rules_without_blocking_other_repairs():
    both = ("NOT_AFFECTED", f"{_FORMER}\n\n{_CURRENT}")
    group = _repair_group([both, both], tags=["TeamB"])

    preview, payloads, _ = _repair(group, rules={"version": "broken"})

    assert _labels(preview) == ["former_teams"]
    assert len(payloads) == 2
    assert preview["notes"] and preview["notes"][0].startswith("Rescoring repair skipped:")


def test_repair_does_not_merge_conflicts_between_current_teams():
    group = _repair_group(
        [("NOT_AFFECTED", _FORMER), ("EXPLOITABLE", _CURRENT.replace("NOT_AFFECTED", "EXPLOITABLE"))],
        tags=["TeamB"],
    )
    assert group["list_metadata"]["lifecycle"] == "INCONSISTENT"
    assert _repair(group)[0]["items"] == []


def _conflict_repair(findings, tags=("TeamB", "TeamC")):
    group = _repair_group(findings, tags=list(tags))
    assert group["list_metadata"]["lifecycle"] == "INCONSISTENT"
    preview, payloads, _ = _repair(group)
    assert _labels(preview) == ["combine_conflict"]
    assert len({payload["details"] for _, payload in payloads}) == 1
    details = payloads[0][1]["details"]
    applied = _repair_group([(payloads[0][1]["state"], details)] * len(findings), tags=list(tags))
    return preview["items"][0], payloads, details, applied


def test_repair_combines_agreeing_conflict_into_approved_global_and_refers_teams():
    other = _FORMER.replace("TeamA", "TeamX").replace("Not reachable.", "Feature disabled.")
    general = "--- [Team: General] [State: NOT_AFFECTED] [Assessed By: rev] [Justification: NOT_SET] ---\nApproved earlier."
    item, payloads, details, applied = _conflict_repair(
        [("NOT_AFFECTED", _FORMER), ("NOT_AFFECTED", other), ("NOT_AFFECTED", general), ("NOT_SET", "")]
    )

    assert item["repairs"][0]["label"] == (
        "Combine conflicting assessments into one global decision (NOT_AFFECTED): "
        "former teams TeamA, TeamX and existing global assessment; TeamB, TeamC refer to global"
    )
    assert item["finding_count"] == 4 and len(payloads) == 4
    assert details.count("[Team: General]") == 1
    assert "[Team: General] [State: NOT_AFFECTED] [Assessed By: reviewer]" in details
    assert "Approved earlier." in details
    assert "Former team assessment (TeamA; " in details and "Not reachable." in details
    assert "Former team assessment (TeamX; " in details and "Feature disabled." in details
    assert "[Team: TeamA]" not in details and "[Team: TeamX]" not in details
    assert details.count("See global assessment.") == 2
    assert "[Status: Pending Review]" not in details
    assert applied["list_metadata"]["lifecycle"] == "ASSESSED"
    assert applied["list_metadata"]["assessed_teams"] == ["TeamB", "TeamC"]
    assert _repair(applied)[0]["items"] == []


def test_repair_combines_disagreeing_conflict_as_pending_worst_state():
    exploitable = (
        "--- [Team: TeamX] [State: EXPLOITABLE] [Assessed By: xavier] "
        "[Justification: NOT_SET] [Rescored: 8.1] "
        "[Rescored Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H] ---\nReachable in v2."
    )
    item, payloads, details, applied = _conflict_repair(
        [("NOT_AFFECTED", _FORMER), ("EXPLOITABLE", exploitable)]
    )

    assert item["repairs"][0]["label"].endswith(
        "sources disagree, pending review, TeamB, TeamC still to assess"
    )
    assert {payload["state"] for _, payload in payloads} == {"EXPLOITABLE"}
    assert "[Team: General] [State: EXPLOITABLE]" in details and "[Rescored: 8.1]" in details
    assert "[Rescored Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H]" in details
    assert "Not reachable." in details and "Reachable in v2." in details
    assert "See global assessment." not in details
    assert details.endswith("[Status: Pending Review]")
    assert applied["list_metadata"]["lifecycle"] == "INCOMPLETE"
    assert applied["list_metadata"]["is_pending"] is True


def test_repair_keeps_previously_pending_conflict_pending():
    _, _, details, _ = _conflict_repair(
        [("NOT_AFFECTED", f"{_FORMER}\n\n[Status: Pending Review]"),
         ("NOT_AFFECTED", _FORMER.replace("Not reachable.", "Other wording."))]
    )
    assert "See global assessment." not in details
    assert details.endswith("[Status: Pending Review]")


def test_repair_deduplicates_rationale_moved_to_the_global_assessment():
    shared = "Parser is   only used at build time."
    general = f"--- [Team: General] [State: NOT_AFFECTED] [Assessed By: rev] [Justification: NOT_SET] ---\nGlobal view.\n\n{shared}"
    same_as_global = f"--- [Team: TeamA] [State: NOT_AFFECTED] [Assessed By: alice] [Justification: NOT_SET] ---\nparser is only used at build time."
    other = "--- [Team: TeamX] [State: NOT_AFFECTED] [Assessed By: xavier] [Justification: NOT_SET] ---\nNot deployed."
    different_state = "--- [Team: TeamY] [State: EXPLOITABLE] [Assessed By: yara] [Justification: NOT_SET] ---\nNot  deployed."
    bare = "--- [Team: TeamZ] [State: NOT_AFFECTED] [Assessed By: zoe] [Justification: NOT_SET] ---"
    details = "\n\n".join([general, same_as_global, other, different_state, bare])
    group = _repair_group([("NOT_AFFECTED", details)] * 2, tags=["TeamB"])

    _, payloads, _ = _repair(group)
    result = payloads[0][1]["details"]

    # A rationale the global assessment already holds is not repeated.
    assert result.casefold().count("only used at build time") == 1
    assert "Former team assessment (TeamA; NOT_AFFECTED; assessed by alice): rationale already part of this assessment." in result
    # One text shared by different decisions is written once, with both decisions.
    assert result.count("Not deployed.") + result.count("Not  deployed.") == 1
    assert (
        "Former team assessment (TeamX; NOT_AFFECTED; assessed by xavier | "
        "TeamY; EXPLOITABLE; assessed by yara):\nNot deployed."
    ) in result
    assert "Former team assessment (TeamZ; NOT_AFFECTED; assessed by zoe)." in result
    for team in ("TeamA", "TeamX", "TeamY", "TeamZ"):
        assert f"[Team: {team}]" not in result

    # Moving the same assessments again adds nothing.
    again = _repair_group(
        [("NOT_AFFECTED", "\n\n".join([result, same_as_global, other]))] * 2, tags=["TeamB"],
    )
    repeated = _repair(again)[1][0][1]["details"]
    assert repeated.count("Former team assessment (") == result.count("Former team assessment (")
    assert repeated.count("Not deployed.") == 1


_GLOBAL = "--- [Team: General] [State: NOT_AFFECTED] [Assessed By: rev] [Justification: CODE_NOT_PRESENT] ---\nApproved globally."


def test_repair_refers_unassessed_teams_to_an_approved_global_assessment():
    group = _repair_group([("NOT_AFFECTED", _GLOBAL)] * 2, tags=["TeamB", "TeamC"])
    assert group["list_metadata"]["lifecycle"] == "ASSESSED"
    assert group["list_metadata"]["assessed_teams"] == []

    preview, payloads, _ = _repair(group)

    assert _labels(preview) == ["refer_teams"]
    assert preview["items"][0]["repairs"][0]["label"] == (
        "Refer TeamB, TeamC to the approved global assessment"
    )
    assert preview["summary"]["refer_teams_groups"] == 1
    details = payloads[0][1]["details"]
    assert "[Team: General] [State: NOT_AFFECTED] [Assessed By: rev]" in details
    assert "Approved globally." in details and "Former team assessment" not in details
    for team in ("TeamB", "TeamC"):
        assert (
            f"--- [Team: {team}] [State: NOT_AFFECTED] [Assessed By: reviewer]" in details
        )
    assert details.count("[Justification: CODE_NOT_PRESENT]") == 3
    assert details.count("See global assessment.") == 2

    applied = _repair_group([("NOT_AFFECTED", details)] * 2, tags=["TeamB", "TeamC"])
    assert applied["list_metadata"]["lifecycle"] == "ASSESSED"
    assert applied["list_metadata"]["assessed_teams"] == ["TeamB", "TeamC"]
    assert _repair(applied)[0]["items"] == []


def test_repair_refers_only_teams_without_their_own_assessment():
    group = _repair_group([("NOT_AFFECTED", f"{_GLOBAL}\n\n{_CURRENT}")] * 2, tags=["TeamB", "TeamC"])

    preview, payloads, _ = _repair(group)

    assert preview["items"][0]["repairs"][0]["label"] == "Refer TeamC to the approved global assessment"
    details = payloads[0][1]["details"]
    assert "[Team: TeamB] [State: NOT_AFFECTED] [Assessed By: bob]" in details and "Not shipped." in details
    assert details.count("See global assessment.") == 1


def test_repair_does_not_refer_teams_to_a_pending_or_missing_global_assessment():
    pending = _repair_group(
        [("NOT_AFFECTED", f"{_GLOBAL}\n\n[Status: Pending Review]")] * 2, tags=["TeamB"],
    )
    assert _repair(pending)[0]["items"] == []
    unset = _GLOBAL.replace("[State: NOT_AFFECTED]", "[State: NOT_SET]")
    assert _repair(_repair_group([("NOT_SET", unset)] * 2, tags=["TeamB"]))[0]["items"] == []
    # Unknown ownership: there is no team to refer.
    assert _repair(_repair_group([("NOT_AFFECTED", _GLOBAL)] * 2, tags=[]))[0]["items"] == []


def test_repair_flags_decisions_and_partial_repairs_for_review_first():
    both = ("NOT_AFFECTED", f"{_FORMER}\n\n{_CURRENT}")
    mechanical, _, _ = _repair(_repair_group([both, both], tags=["TeamB"]))
    assert mechanical["items"][0]["requires_review"] is False
    assert mechanical["topics"] == [{"id": "former_teams", "label": "Former teams", "groups": 1}]
    assert mechanical["summary"]["review_first_groups"] == 0

    promoted, _, _ = _repair(_repair_group([("NOT_AFFECTED", _FORMER)], tags=["TeamB"]))
    assert promoted["items"][0]["requires_review"] is True
    assert promoted["summary"]["review_first_groups"] == 1

    referred, _, _ = _repair(_repair_group([("NOT_AFFECTED", _GLOBAL)] * 2, tags=["TeamB"]))
    assert referred["items"][0]["requires_review"] is False

    conflict = _repair_group(
        [("NOT_AFFECTED", _FORMER), ("NOT_AFFECTED", _FORMER.replace("Not reachable.", "Other."))],
        tags=["TeamB"],
    )
    combined, _, _ = _repair(conflict)
    assert [topic["id"] for topic in combined["topics"]] == ["combine_conflict"]
    assert combined["items"][0]["requires_review"] is True


def test_repair_marks_cross_version_rescoring_for_review_first():
    stored = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/CR:L/MC:N/MI:N/MA:N"
    details = _GLOBAL.replace("] ---", f"] [Rescored: 0.0] [Rescored Vector: {stored}] ---")
    group = _repair_group([("NOT_AFFECTED", details)] * 2, tags=[])
    group["cvss_vector"] = "AV:N/AC:L/Au:N/C:P/I:P/A:P"

    preview, payloads, _ = _repair(group, rules=_rescore_rules())

    item = preview["items"][0]
    assert _labels(preview) == ["rescoring"]
    assert item["repairs"][0]["label"] == (
        "Repair rescoring on 2 findings; replaces a stored vector of another CVSS version on 2"
    )
    assert item["requires_review"] is True and item["repairable"] is True
    assert item["review"] == []
    assert all("CVSS:3.1" not in payload["details"] for _, payload in payloads)
    assert all("[Rescored: 0.0]" in payload["details"] for _, payload in payloads)


_RESCORED_TEAMS = (
    "--- [Team: TeamA] [State: NOT_AFFECTED] [Assessed By: alice] [Justification: CODE_NOT_PRESENT] ---\n\n"
    "Not shipped.\n\n"
    "--- [Team: TeamB] [State: NOT_AFFECTED] [Assessed By: bob] [Justification: CODE_NOT_PRESENT] ---\n\n"
    "Version not used"
)


def _apply_repair(group, payloads):
    updated = _apply_payloads([group], payloads, {})[0]
    updated["list_metadata"] = summarize_grouped_vulnerabilities([updated], {})[0]["list_metadata"]
    return updated


def test_repair_settles_when_the_rescoring_precedes_the_team_assessments():
    rules = json.loads(Path("data/rescore_rules.json").read_text())
    group = _repair_group(
        [("NOT_AFFECTED", f"[Rescored: 0.0]\n\n{_RESCORED_TEAMS}")] * 2,
        tags=["TeamA", "TeamB", "TeamC"],
        lifecycle="INCOMPLETE",
    )
    group["cvss_vector"] = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L"
    for version in group["affected_versions"]:
        version["components"][0]["cvss_vector"] = group["cvss_vector"]

    preview, payloads, _ = _repair(group, rules=rules)

    # Nothing is missing on a finding: only the rescoring needs repair.
    assert _labels(preview) == ["rescoring"]
    details = payloads[0][1]["details"]
    assert details.startswith("[Rescored: 0.0] [Rescored Vector: CVSS:3.1/")
    assert "[Team: TeamA]" in details and "[Team: TeamB]" in details

    repaired = _apply_repair(group, payloads)
    repaired["list_metadata"]["lifecycle"] = "INCOMPLETE"
    again, payloads, _ = _repair(repaired, rules=rules)
    assert again["items"] == [] and payloads == []


def test_repair_synchronization_keeps_and_copies_a_manual_rescoring():
    rescoring = "[Rescored: 6.5] [Rescored Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/MAV:L]"
    teams = _RESCORED_TEAMS.replace("NOT_AFFECTED", "EXPLOITABLE").replace("CODE_NOT_PRESENT", "NOT_SET")
    group = _repair_group(
        [("EXPLOITABLE", f"{rescoring}\n\n{teams}"), ("NOT_SET", "")],
        tags=["TeamA", "TeamB"],
        lifecycle="INCOMPLETE",
    )

    preview, payloads, _ = _repair(group)

    assert _labels(preview) == ["sync_findings"]
    assert preview["items"][0]["repairs"][0]["label"] == "Synchronize assessment to 1 finding"
    assert [instance["finding_uuid"] for instance, _ in payloads] == ["finding-2"]
    assert payloads[0][1]["details"].startswith(f"{rescoring}\n\n--- [Team: TeamA]")
    assert payloads[0][1]["state"] == "EXPLOITABLE"
