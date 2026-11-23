"""Repair Assessments carries the assessment of a gone finding whose component
DTVP never knew to the finding of the same vulnerability reported now in the
same version (CVE-2024-28863 on ViewPoint 7.2.0, 2026-11-23): only when that
is unambiguous and the gone records agree; never onto a finding saved since
the preview; a second run changes nothing."""

from types import SimpleNamespace

from dtvp.bulk_workflows.assessment_repair import (
    build_assessment_repair_preview,
    create_assessment_repair_workflow,
)
from dtvp.bulk_workflows.base import CHANGED_SINCE_PREVIEW, BulkWorkflowContext
from dtvp.finding_lifecycle_services import ORIGIN_CARRIED_OVER_BY_SAME_ISSUE
from dtvp.general_api_routes import _persist_local_assessment_payloads
from dtvp.grouped_vuln_services import summarize_grouped_vulnerabilities
from dtvp.same_issue import unknown_component_records

TEXT = (
    "--- [Team: General] [State: NOT_AFFECTED] [Assessed By: rita] [Justification: CODE_NOT_REACHABLE] ---\n"
    "tar functionality is not used in the product.\n\n"
    "--- [Team: D-Web] [State: NOT_AFFECTED] [Assessed By: dan] [Date: 1774017174954] [Justification: CODE_NOT_REACHABLE] ---\n"
    "Not used."
)


def _instance(component, name="tar", version="2.2.2", state="NOT_SET", details=""):
    return {
        "project_uuid": "p-720", "project_name": "ViewPoint_Product", "project_version": "7.2.0",
        "component_uuid": component, "component_name": name, "component_version": version,
        "vulnerability_uuid": "v-tar", "finding_uuid": f"f-{component}", "tags": ["D-Web"],
        "analysis_state": state, "analysis_details": details, "justification": "NOT_SET",
    }


def _group(*instances):
    group = {
        "id": "CVE-2024-28863", "title": "CVE-2024-28863", "tags": ["D-Web"],
        "affected_versions": [{
            "project_name": "ViewPoint_Product", "project_version": "7.2.0",
            "project_uuid": "p-720", "components": list(instances),
        }],
    }
    group["list_metadata"] = summarize_grouped_vulnerabilities([group], {})[0]["list_metadata"]
    return group


def _rows(gone_states=("NOT_AFFECTED",), reported=("c-new",), texts=None):
    rows = {}
    for index, state in enumerate(gone_states):
        text = (texts or [TEXT] * len(gone_states))[index]
        rows[(f"c-old{index}", "v-tar")] = {
            "component_uuid": f"c-old{index}", "vulnerability_uuid": "v-tar",
            "vuln_id": "CVE-2024-28863", "status": "gone", "predates_tracking": 1,
            "_record": {"analysisState": state, "analysisDetails": text, "isSuppressed": False,
                        "sync_status": "inactive", "updated_at": f"2026-08-1{index}T15:27:11"},
        }
    for component in reported:
        rows[(component, "v-tar")] = {
            "component_uuid": component, "vulnerability_uuid": "v-tar",
            "vuln_id": "CVE-2024-28863", "status": "reported", "component_name": "tar",
            "component_version": "2.2.2", "component_purl": "pkg:npm/tar@2.2.2",
            "component_identity": "pkg:npm/tar",
        }
    return rows


def _context(group, rows, stored=None):
    return BulkWorkflowContext(
        task_id="t", groups=[group], user="rita",
        unknown_component_records=lambda project: unknown_component_records(
            rows, lambda row: row.get("_record")
        ),
        stored_assessments=stored,
    )


def _run(group, rows, stored=None):
    context = _context(group, rows, stored)
    rules = lambda: {}
    preview = build_assessment_repair_preview(context, rules)
    # Through the plugin, as the apply route builds them (with the guard
    # against saves made since the preview).
    payloads, skipped = create_assessment_repair_workflow(rules).build_payloads(
        context, [group["id"]]
    )
    return preview, payloads, skipped


def test_an_unambiguous_record_is_carried_pending_review_with_the_carry_origin():
    preview, payloads, skipped = _run(_group(_instance("c-new")), _rows())

    [item] = preview["items"]
    [repair] = [r for r in item["repairs"] if r["id"] == "unknown_component"]
    assert repair["label"] == (
        "Carry the assessment of a gone finding whose component is unknown "
        "(NOT_AFFECTED, D-Web, 2026-08-10) to tar 2.2.2 in 7.2.0, pending review"
    )
    # Never preselected.
    assert item["requires_review"] is True
    [(instance, payload)] = payloads
    assert instance["component_uuid"] == "c-new"
    assert payload["state"] == "NOT_AFFECTED"
    assert payload["details"].startswith(TEXT)
    assert payload["details"].rstrip().endswith("[Status: Pending Review]")
    assert payload["origin"] == ORIGIN_CARRIED_OVER_BY_SAME_ISSUE
    assert skipped == {}


def test_records_that_differ_on_several_candidates_are_ambiguous_and_not_carried():
    group = _group(_instance("c-new"), _instance("c-other", version="6.2.0"))
    rows = _rows(
        gone_states=("NOT_AFFECTED", "NOT_AFFECTED"), reported=("c-new", "c-other"),
        texts=[TEXT, TEXT.replace("Not used.", "Not loaded.")],
    )
    preview, payloads, _ = _run(group, rows)

    assert payloads == []
    [item] = preview["items"]
    assert item["review"] == [
        "A gone finding whose component is unknown has an assessment; in 7.2.0 the "
        "vulnerability is reported on tar 2.2.2, tar 2.2.2: ambiguous, choose in the "
        "gone findings panel"
    ]


def test_records_that_agree_go_to_every_candidate():
    """CVE-2024-7260 on a2e34de3: two records with the same text, the
    vulnerability now on keycloak-model-storage and keycloak-model-legacy.
    Which record was on which component does not matter: both get it."""
    group = _group(
        _instance("c-new", name="keycloak-model-storage", version="26.0.5"),
        _instance("c-other", name="keycloak-model-legacy", version="26.0.5"),
    )
    rows = _rows(gone_states=("NOT_AFFECTED", "NOT_AFFECTED"), reported=("c-new", "c-other"),
                 texts=[TEXT, TEXT + "  \n"])
    preview, payloads, _ = _run(group, rows)

    assert sorted(instance["component_uuid"] for instance, _payload in payloads) == ["c-new", "c-other"]
    assert all(payload["details"].startswith(TEXT) for _i, payload in payloads)
    [item] = preview["items"]
    labels = [r["label"] for r in item["repairs"] if r["id"] == "unknown_component"]
    assert labels == [
        "Carry the assessment of a gone finding whose component is unknown (NOT_AFFECTED, "
        f"D-Web, 2026-08-11) to {name} 26.0.5 in 7.2.0, pending review; 2 earlier records "
        "agree, applied to all 2 candidates"
        for name in ("keycloak-model-storage", "keycloak-model-legacy")
    ]
    # An assessed candidate keeps its own; the others still get it.
    assessed = _group(
        _instance("c-new", state="EXPLOITABLE", details="--- [Team: D-Web] [State: EXPLOITABLE] ---"),
        _instance("c-other", name="keycloak-model-legacy", version="26.0.5"),
    )
    preview, _, _ = _run(assessed, rows)
    labels = [r["label"] for item in preview["items"] for r in item["repairs"] if r["id"] == "unknown_component"]
    assert len(labels) == 1 and "to keycloak-model-legacy 26.0.5" in labels[0]


def test_gone_records_that_disagree_are_conflicting_and_not_carried():
    preview, payloads, _ = _run(
        _group(_instance("c-new")), _rows(gone_states=("NOT_AFFECTED", "EXPLOITABLE"))
    )
    assert payloads == []
    [item] = preview["items"]
    assert item["review"] == [
        "Gone findings whose component is unknown disagree in 7.2.0 "
        "(EXPLOITABLE, NOT_AFFECTED): conflicting, not carried"
    ]


def test_a_finding_saved_since_the_preview_is_not_overwritten():
    saved = lambda instances: [
        {"recorded": True, "state": "EXPLOITABLE", "details": "Someone saved.", "suppressed": False,
         "revision": 1}
        for _ in instances
    ]
    _, payloads, skipped = _run(_group(_instance("c-new")), _rows(), stored=saved)
    assert payloads == []
    assert skipped == {CHANGED_SINCE_PREVIEW: 1}


def test_a_second_run_changes_nothing():
    _, [(_instance_, payload)], _ = _run(_group(_instance("c-new")), _rows())
    rows = _rows()
    rows[("c-new", "v-tar")]["_record"] = {
        "analysisState": payload["state"], "analysisDetails": payload["details"],
        "isSuppressed": False, "sync_status": "pending",
    }
    again = _group(_instance("c-new", state=payload["state"], details=payload["details"]))
    preview, payloads, _ = _run(again, rows)
    assert payloads == []
    assert not any(
        repair["id"] == "unknown_component"
        for item in preview["items"] for repair in item["repairs"]
    )


async def test_each_origin_is_written_with_its_own_origin():
    calls = []

    async def persist(payloads, *, replace, origin, author, **_):
        calls.append((origin, [payload["component_uuid"] for payload in payloads]))
        return [{"payload": payload} for payload in payloads]

    deps = SimpleNamespace(cache_manager=SimpleNamespace(persist_assessment_updates=persist))
    payloads = [
        ({}, {"project_uuid": "p", "component_uuid": "a", "vulnerability_uuid": "v",
              "state": "NOT_AFFECTED", "details": "x", "origin": ORIGIN_CARRIED_OVER_BY_SAME_ISSUE}),
        ({}, {"project_uuid": "p", "component_uuid": "b", "vulnerability_uuid": "v",
              "state": "NOT_AFFECTED", "details": "x"}),
    ]
    persisted, written, changed = await _persist_local_assessment_payloads(deps, payloads, author="rita")
    assert sorted(calls) == [("bulk-workflow", ["b"]), (ORIGIN_CARRIED_OVER_BY_SAME_ISSUE, ["a"])]
    assert len(persisted) == 2 and len(written) == 2 and changed == 0
    assert all("origin" not in payload for _instance, payload in written)
