"""Findings of one vulnerability that disagree, and making them agree.

The texts are those of a real vulnerability (anonymised): twelve findings in
six versions of a product, saved together six times, of which three never
agreed with the rest. The three had come later (a new project version, a
replaced component), after a reviewer had recorded the SSVC decision, and
every save kept each finding's own SSVC record, which for them was none.
"""

import logging
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from dtvp import dt_cache, main
from dtvp.assessment_services import AssessmentServiceDeps, build_assessment_payloads
from dtvp.assessment_use_cases import (
    AssessmentConflictError,
    AssessmentPermissionError,
    AssessmentRequest,
    AssessmentValidationError,
    clean_up_assessment,
    save_assessment,
)
from dtvp.grouped_vuln_services import comparable_assessment_text, summarize_grouped_vulnerabilities
from dtvp.logic import calculate_aggregated_state, process_assessment_details
from dtvp.ssvc_services import SsvcInput, new_record, read_record, write_record

LEAD = (
    "[Rescored: 0.0] [Rescored Vector: CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H"
    "/SC:N/SI:N/SA:N/CR:L/IR:L/AR:L/MUI:P/MVC:N/MVI:N/MVA:N]"
)
GENERAL = (
    "--- [Team: General] [State: NOT_AFFECTED] [Assessed By: analyst-1] "
    "[Date: 1795535973530] [Justification: CODE_NOT_REACHABLE] ---"
)
TEAMS = (
    "--- [Team: Third Party] [State: NOT_AFFECTED] [Assessed By: analyst-2] "
    "[Date: 1795530000886] [Justification: CODE_NOT_REACHABLE] ---\n"
    "The decoder is only reached for compressed request bodies.\n\n"
    "--- [Team: Platform] [State: NOT_SET] [Assessed By: analyst-3] "
    "[Date: 1795530009887] [Justification: CODE_NOT_REACHABLE] ---\n\n"
    "--- [Team: Identity] [State: NOT_AFFECTED] [Assessed By: analyst-4] "
    "[Date: 1795530016568] [Justification: CODE_NOT_REACHABLE] [Assigned: analyst-4] ---\n"
    "Request decompression is disabled; no reachable attack path was found."
)
PENDING = "[Status: Pending Review]"
# The teams that own the component; all of them are current.
TEAM_NAMES = ["Third Party", "Platform", "Identity"]
# Only the exploitation is answered, as in the original: priority Incomplete.
RECORD = new_record(
    SsvcInput(model="ssvc:DT_DP", version="1.0.0", answers={"ssvc:E:1.1.0": "A"}),
    "reviewer-1",
)
WITHOUT_SSVC = f"{LEAD}\n\n{GENERAL}\n\n{TEAMS}\n\n{PENDING}"
WITH_SSVC = write_record(WITHOUT_SSVC, RECORD)

FINDINGS = [
    {"project_uuid": f"p-{version}", "component_uuid": component,
     "vulnerability_uuid": "v-1", "finding_uuid": f"f-{version}-{component}",
     "project_version": version}
    for version, component in [("7.1.0", "brotli"), ("7.1.2", "brotli"), ("7.1.1", "brotli")]
]
EARLY, ALSO_EARLY, LATER = FINDINGS


def _key(instance):
    return {name: instance[name] for name in ("project_uuid", "component_uuid", "vulnerability_uuid")}


def _stored(instance):
    return dt_cache.cache_manager.get_assessment_overlay(*_key(instance).values())


def _details(instance):
    return _stored(instance)["analysisDetails"]


def _same(left, right):
    """The store normalises blank lines; the words are what counts."""
    return " ".join(left.split()) == " ".join(right.split())


async def _seed(*texts, states=None, suppressed=None, origin="import"):
    await dt_cache.cache_manager.persist_assessment_updates(
        [
            {**_key(instance), "state": (states or {}).get(index, calculate_aggregated_state(text)),
             "details": text, "suppressed": (suppressed or {}).get(index, False)}
            for index, (instance, text) in enumerate(zip(FINDINGS, texts))
        ],
        origin=origin,
    )


def _reasons(*texts):
    group = {
        "id": "CVE-CASE", "title": "CVE-CASE", "tags": ["Identity"],
        "affected_versions": [
            {"project_name": "Product", "project_version": instance["project_version"],
             "components": [{**instance, "component_name": "brotli", "tags": ["Identity"],
                             "analysis_state": calculate_aggregated_state(text),
                             "analysis_details": text}]}
            for instance, text in zip(FINDINGS, texts)
        ],
    }
    return summarize_grouped_vulnerabilities([group], {})[0]["list_metadata"]["inconsistency_reasons"]


@pytest.fixture
def deps():
    logger = logging.getLogger("test")
    service_deps = AssessmentServiceDeps(
        cache_manager=dt_cache.cache_manager,
        logger=logger,
        calculate_aggregated_state=calculate_aggregated_state,
        process_assessment_details=process_assessment_details,
    )
    return SimpleNamespace(
        cache_manager=dt_cache.cache_manager,
        logger=logger,
        code_analysis_result_store=None,
        get_user_role=lambda _user: "ANALYST",
        build_assessment_payloads=lambda req, user, role: (
            build_assessment_payloads(service_deps, req, user, role)
        ),
    )


# -- why the findings did not agree -----------------------------------------


def test_the_original_texts_differ_only_in_the_ssvc_record_which_is_optional():
    # The SSVC record is optional: a finding without it does not differ.
    assert _reasons(WITH_SSVC, WITH_SSVC, WITHOUT_SSVC) == []
    assert comparable_assessment_text(write_record(WITH_SSVC, None)) == (
        comparable_assessment_text(WITHOUT_SSVC)
    )


@pytest.mark.parametrize("role,team", [("ANALYST", "Third Party"), ("REVIEWER", None)])
async def test_a_save_gives_a_later_finding_the_ssvc_record_the_others_agree_on(deps, role, team):
    await _seed(WITH_SSVC, WITH_SSVC, WITHOUT_SSVC)
    deps.get_user_role = lambda _user: role

    await save_assessment(
        deps,
        AssessmentRequest(
            instances=FINDINGS, state="NOT_AFFECTED", justification="CODE_NOT_REACHABLE",
            details="The decoder is only reached for compressed request bodies.", team=team,
        ),
        user="analyst-2", client=None,
    )

    assert [read_record(_details(instance)) for instance in FINDINGS] == [RECORD] * 3
    assert _reasons(*(_details(instance) for instance in FINDINGS)) == []


async def test_a_save_keeps_each_finding_s_record_when_the_records_differ(deps):
    other = new_record(SsvcInput(model="ssvc:DT_DP", version="1.0.0", answers={}, rationale="Other"), "reviewer-2")
    await _seed(WITH_SSVC, write_record(WITHOUT_SSVC, other), WITHOUT_SSVC)

    await save_assessment(
        deps,
        AssessmentRequest(instances=FINDINGS, state="NOT_AFFECTED", details="Checked.", team="Third Party"),
        user="analyst-2", client=None,
    )

    assert [read_record(_details(instance)) for instance in FINDINGS] == [RECORD, other, None]


async def test_a_record_never_adds_a_general_block(deps):
    team_only = TEAMS
    await _seed(WITH_SSVC, WITH_SSVC, team_only)

    await save_assessment(
        deps,
        AssessmentRequest(instances=FINDINGS, state="NOT_AFFECTED", details="Checked.", team="Third Party"),
        user="analyst-2", client=None,
    )

    assert "[Team: General]" not in _details(LATER)
    assert read_record(_details(LATER)) is None


# -- cleanup ----------------------------------------------------------------


async def test_a_dry_run_shows_each_finding_before_and_after_and_writes_nothing(deps):
    await _seed(WITH_SSVC, WITH_SSVC, WITHOUT_SSVC)

    preview = await clean_up_assessment(
        deps, FINDINGS, action="apply", team=None, source=_key(EARLY),
        user="rita", role="REVIEWER", dry_run=True,
    )

    assert [(entry["finding_uuid"], entry["changed"]) for entry in preview] == [
        (ALSO_EARLY["finding_uuid"], False),
        (LATER["finding_uuid"], True),
    ]
    later = preview[1]
    assert later["before"]["details"] == WITHOUT_SSVC
    assert read_record(later["after"]["details"]) == RECORD
    assert later["revision"] == 1
    assert _details(LATER) == WITHOUT_SSVC
    assert len(dt_cache.cache_manager.get_assessment_history(*_key(LATER).values())) == 1


async def test_keeping_one_version_makes_the_group_consistent_and_is_recorded(deps):
    await _seed(WITH_SSVC, WITH_SSVC, WITHOUT_SSVC)

    results = await clean_up_assessment(
        deps, FINDINGS, action="apply", team=None, source=_key(EARLY),
        user="rita", role="REVIEWER", revisions={"|".join(_key(LATER).values()): 1},
    )

    assert [result["uuid"] for result in results] == [LATER["finding_uuid"]]
    assert _same(_details(LATER), WITH_SSVC)
    assert _stored(LATER)["dtvpSyncStatus"] == "pending"
    history = dt_cache.cache_manager.get_assessment_history(*_key(LATER).values())
    assert (history[0]["origin"], history[0]["author"]) == ("assessment-cleanup", "rita")
    assert _reasons(*(_details(instance) for instance in FINDINGS)) == []


async def test_a_finding_keeps_its_own_records_and_version_override(deps):
    record = (
        "--- [Team: Former] [State: EXPLOITABLE] [Assessed By: alice] "
        "[Justification: NOT_SET] [Historical: yes] ---\nReachable then."
    )
    override = "[Version Override: legacy line] [Override Reason: Built differently]"
    await _seed(WITH_SSVC, WITH_SSVC, f"{override}\n\n{record}\n\n{TEAMS}")

    await clean_up_assessment(
        deps, [LATER], action="apply", team=None, source=_key(EARLY), user="rita", role="REVIEWER",
    )

    details = _details(LATER)
    assert "Reachable then." in details and "[Historical: yes]" in details
    assert "[Version Override: legacy line]" in details
    assert read_record(details) == RECORD
    assert _reasons(WITH_SSVC, WITH_SSVC, details) == []


async def test_the_state_and_suppression_come_with_the_whole_assessment(deps):
    await _seed(WITH_SSVC, WITH_SSVC, "Legacy text, still in triage.",
                states={2: "IN_TRIAGE"}, suppressed={0: True})

    await clean_up_assessment(
        deps, [LATER], action="apply", team=None, source=_key(EARLY), user="rita", role="REVIEWER",
    )

    assert (_stored(LATER)["analysisState"], _stored(LATER)["isSuppressed"]) == ("NOT_AFFECTED", True)


async def test_an_analyst_takes_over_one_team_s_block_which_goes_to_review(deps):
    approved = WITHOUT_SSVC.replace(f"\n\n{PENDING}", "")
    stray = approved.replace(
        "The decoder is only reached for compressed request bodies.", "Not checked yet."
    )
    await _seed(approved, approved, stray)

    await clean_up_assessment(
        deps, FINDINGS, action="apply", team="Third Party", source=_key(EARLY), user="ana",
    )

    details = _details(LATER)
    assert "The decoder is only reached for compressed request bodies." in details
    assert "Not checked yet." not in details
    assert details.endswith(PENDING)
    assert _details(EARLY) == approved  # it already agreed


async def test_a_stray_version_is_cleared_from_selected_findings(deps):
    await _seed(WITH_SSVC, WITH_SSVC, "Old note from before the team assessments.")

    await clean_up_assessment(deps, [LATER], action="clear", team=None, source=None, user="rita", role="REVIEWER")

    assert (_stored(LATER)["analysisState"], _details(LATER)) == ("NOT_SET", "")
    assert _same(_details(EARLY), WITH_SSVC)


async def test_the_block_of_a_team_that_no_longer_exists_is_removed(deps):
    stale = (
        "--- [Team: Retired Team] [State: IN_TRIAGE] [Assessed By: bob] "
        "[Justification: NOT_SET] ---\nWas looking into it."
    )
    approved = WITHOUT_SSVC.replace(f"\n\n{PENDING}", "")
    await _seed(approved, approved, f"{approved}\n\n{stale}")
    # A block that one finding has and the others lack is a gap, not a
    # contradiction; the stale block is removed all the same.
    assert _reasons(approved, approved, f"{approved}\n\n{stale}") == []

    await clean_up_assessment(
        deps, FINDINGS, action="clear", team="Retired Team", source=None, user="ana",
    )

    assert "Retired Team" not in _details(LATER)
    # What remains goes to review; the review marker is not a difference.
    assert _details(LATER).endswith(PENDING)
    assert _reasons(*(_details(instance) for instance in FINDINGS)) == []
    assert _stored(EARLY)["dtvpRevision"] == 1  # nothing to remove there


async def test_only_reviewers_clean_up_the_global_or_the_whole_assessment(deps):
    await _seed(WITH_SSVC, WITH_SSVC, WITHOUT_SSVC)
    for team in (None, "General", "general"):
        with pytest.raises(AssessmentPermissionError):
            await clean_up_assessment(
                deps, FINDINGS, action="apply", team=team, source=_key(EARLY), user="ana",
            )
    assert _details(LATER) == WITHOUT_SSVC


async def test_invalid_requests_are_validation_errors(deps):
    await _seed(WITH_SSVC, WITH_SSVC, WITHOUT_SSVC)
    cases = [
        dict(action="merge", team=None, source=_key(EARLY)),
        dict(action="apply", team=None, source=None),
        dict(action="apply", team="Nobody", source=_key(EARLY)),
        dict(action="apply", team=None, source={**_key(EARLY), "project_uuid": "p-unknown"}),
    ]
    for case in cases:
        with pytest.raises(AssessmentValidationError):
            await clean_up_assessment(deps, FINDINGS, user="rita", role="REVIEWER", **case)
    with pytest.raises(AssessmentValidationError, match="already agree"):
        await clean_up_assessment(
            deps, [ALSO_EARLY], action="apply", team=None, source=_key(EARLY), user="rita", role="REVIEWER",
        )


async def test_a_change_after_the_preview_is_a_conflict(deps):
    await _seed(WITH_SSVC, WITH_SSVC, WITHOUT_SSVC)
    previewed = {"|".join(_key(instance).values()): 1 for instance in FINDINGS}
    await dt_cache.cache_manager.persist_assessment_updates(
        [{**_key(EARLY), "state": "EXPLOITABLE", "details": "Changed meanwhile", "suppressed": False}],
        origin="individual-assessment",
    )

    with pytest.raises(AssessmentConflictError):
        await clean_up_assessment(
            deps, FINDINGS, action="apply", team=None, source=_key(EARLY),
            user="rita", role="REVIEWER", revisions=previewed,
        )
    assert _details(LATER) == WITHOUT_SSVC


# -- route ------------------------------------------------------------------


async def test_the_route_previews_applies_and_refuses(client):
    main.app.dependency_overrides[main.get_current_user] = lambda: "rita"
    await _seed(WITH_SSVC, WITH_SSVC, WITHOUT_SSVC)
    body = {"instances": FINDINGS, "action": "apply", "source": _key(EARLY)}

    with patch("dtvp.main.get_user_role", return_value="ANALYST"):
        assert client.post("/api/assessment/cleanup", json=body).status_code == 403
    with patch("dtvp.main.get_user_role", return_value="REVIEWER"):
        assert client.post("/api/assessment/cleanup", json={**body, "action": "merge"}).status_code == 422
        preview = client.post("/api/assessment/cleanup", json={**body, "dry_run": True})
        assert preview.status_code == 200
        assert [entry["changed"] for entry in preview.json()] == [False, True]
        assert _details(LATER) == WITHOUT_SSVC
        revisions = {
            f"{entry['project_uuid']}|{entry['component_uuid']}|{entry['vulnerability_uuid']}": entry["revision"]
            for entry in preview.json()
        }
        assert {entry["source_revision"] for entry in preview.json()} == {1}
        revisions["|".join(_key(EARLY).values())] = 1
        applied = client.post("/api/assessment/cleanup", json={**body, "revisions": revisions})
        assert applied.status_code == 200
        assert [result["uuid"] for result in applied.json()] == [LATER["finding_uuid"]]
        again = client.post("/api/assessment/cleanup", json={**body, "revisions": revisions})
        assert again.status_code == 409
    assert read_record(_details(LATER)) == RECORD


# -- Repair Assessments: carry the SSVC record -----------------------------

from dtvp.bulk_workflows.assessment_repair import (  # noqa: E402
    build_assessment_repair_payloads,
    build_assessment_repair_preview,
)
from dtvp.bulk_workflows.base import BulkWorkflowContext  # noqa: E402


def _repair_group(*texts):
    group = {
        "id": "CVE-CASE", "title": "CVE-CASE", "tags": TEAM_NAMES,
        "affected_versions": [
            {"project_name": "Product", "project_version": instance["project_version"],
             "project_uuid": instance["project_uuid"],
             "components": [{**instance, "component_name": "brotli", "tags": TEAM_NAMES,
                             "analysis_state": calculate_aggregated_state(text),
                             "analysis_details": text}]}
            for instance, text in zip(FINDINGS, texts)
        ],
    }
    group["list_metadata"] = summarize_grouped_vulnerabilities([group], {})[0]["list_metadata"]
    return group


def _repair(group):
    context = BulkWorkflowContext(task_id="task", groups=[group], user="rita")
    preview = build_assessment_repair_preview(context, lambda: {})
    payloads, _skipped = build_assessment_repair_payloads(context, [group["id"]], lambda: {})
    return preview, payloads


def test_repair_carries_the_agreed_ssvc_record_to_the_later_findings():
    group = _repair_group(WITH_SSVC, WITH_SSVC, WITHOUT_SSVC)
    # Not a conflict: the carry is a tidy-up.
    assert group["list_metadata"]["inconsistency_reasons"] == []

    preview, payloads = _repair(group)

    (item,) = preview["items"]
    # Platform's block holds no decision: the team stage, which now sees the
    # group as consistent, may add its own note; the carry comes first.
    assert [repair["id"] for repair in item["repairs"]][0] == "ssvc_record"
    assert item["repairs"][0]["label"] == (
        "Carry the SSVC record the other findings agree on to 1 finding without one"
    )
    assert {"id": "ssvc_record", "label": "SSVC record", "groups": 1} in preview["topics"]
    assert item["finding_count"] == 1
    ((instance, payload),) = payloads
    assert instance["finding_uuid"] == LATER["finding_uuid"]
    assert read_record(payload["details"]) == RECORD
    # Nothing else changes: the text without the record is the old text.
    assert " ".join(write_record(payload["details"], None).split()) == " ".join(
        write_record(WITHOUT_SSVC, None).split()
    )
    assert payload["state"] == "NOT_AFFECTED"
    assert _reasons(WITH_SSVC, WITH_SSVC, payload["details"]) == []


def test_repair_does_not_carry_records_that_differ():
    other = new_record(SsvcInput(model="ssvc:DT_DP", version="1.0.0", answers={}, rationale="Other"), "reviewer-2")
    group = _repair_group(WITH_SSVC, write_record(WITHOUT_SSVC, other), WITHOUT_SSVC)

    preview, payloads = _repair(group)

    assert all(
        repair["id"] != "ssvc_record" for item in preview["items"] for repair in item["repairs"]
    )
    assert all(read_record(payload["details"]) is None or payload["details"] != WITHOUT_SSVC
               for _instance, payload in payloads)
    assert not any(instance["finding_uuid"] == LATER["finding_uuid"] for instance, _ in payloads)


def test_repair_never_adds_a_general_block_for_the_record():
    group = _repair_group(WITH_SSVC, WITH_SSVC, TEAMS)

    preview, payloads = _repair(group)

    # The carry does not touch the finding without a General block; if
    # Synchronize gives it the Global assessment, the record comes with it.
    assert all(
        repair["id"] != "ssvc_record" for item in preview["items"] for repair in item["repairs"]
    )
    for _instance, payload in payloads:
        if read_record(payload["details"]) is not None:
            assert "[Team: General]" in payload["details"]


def _repair_group_of(texts, states=None):
    """A group of len(texts) findings in as many versions."""
    instances = [
        {"project_uuid": f"p-{index}", "component_uuid": "core", "vulnerability_uuid": "v-1",
         "finding_uuid": f"f-{index}", "project_version": f"6.15.{index}"}
        for index in range(len(texts))
    ]
    group = {
        "id": "CVE-CASE", "title": "CVE-CASE", "tags": TEAM_NAMES,
        "affected_versions": [
            {"project_name": "Product", "project_version": instance["project_version"],
             "project_uuid": instance["project_uuid"],
             "components": [{**instance, "component_name": "core", "tags": TEAM_NAMES,
                             "analysis_state": (states or {}).get(index) or (
                                 calculate_aggregated_state(text) if text else "NOT_SET"),
                             "analysis_details": text}]}
            for index, (instance, text) in enumerate(zip(instances, texts))
        ],
    }
    group["list_metadata"] = summarize_grouped_vulnerabilities([group], {})[0]["list_metadata"]
    return group


def _after(group, payloads):
    written = {instance["finding_uuid"]: payload for instance, payload in payloads}
    return [
        (written[c["finding_uuid"]]["details"] if c["finding_uuid"] in written else c["analysis_details"])
        for version in group["affected_versions"] for c in version["components"]
    ]


def _metadata(group, texts):
    copy = _repair_group_of(texts)
    return copy["list_metadata"]


def test_one_repair_run_carries_the_record_and_then_synchronizes_the_unassessed_finding():
    # GHSA-JFC7 as it was before the run (anonymised): an SSVC record on all
    # but one assessed finding, and one finding of a later version without
    # any assessment. Inconsistent only because of the record.
    approved = WITHOUT_SSVC.replace(f"\n\n{PENDING}", "")
    group = _repair_group_of([write_record(approved, RECORD)] * 4 + [approved, ""])
    # Incomplete (one finding unassessed); the missing record is no conflict.
    assert group["list_metadata"]["inconsistency_reasons"] == []

    preview, payloads = _repair(group)

    (item,) = preview["items"]
    ids = [repair["id"] for repair in item["repairs"]]
    assert ids[:2] == ["ssvc_record", "sync_findings"]
    after = _after(group, payloads)
    assert [read_record(text) for text in after] == [RECORD] * 6
    metadata = _metadata(group, after)
    assert metadata["inconsistency_reasons"] == []
    assert metadata["lifecycle"] != "INCOMPLETE"


def test_repair_carries_the_agreed_response_to_findings_without_one():
    # GHSA-692R and CVE-2023-49803 (anonymised): the findings of a later
    # version lack the response the others carry; nothing else differs.
    blocks = WITHOUT_SSVC.replace(f"\n\n{PENDING}", "").split("\n\n", 1)[1]
    with_response = f"{LEAD} [Response: UPDATE]\n\n{blocks}"
    without = f"{LEAD}\n\n{blocks}"
    group = _repair_group_of([with_response, with_response, without])
    # The response is optional: no conflict; the carry is a tidy-up.
    assert group["list_metadata"]["inconsistency_reasons"] == []

    preview, payloads = _repair(group)

    (item,) = preview["items"]
    assert [repair["id"] for repair in item["repairs"]][0] == "response"
    assert item["repairs"][0]["label"] == (
        "Carry the response the other findings agree on (UPDATE) to 1 finding without one"
    )
    after = _after(group, payloads)
    assert _metadata(group, after)["inconsistency_reasons"] == []
    differing = _repair_group_of([with_response, "[Response: ROLLBACK]\n\n" + blocks, without])
    assert all(
        repair["id"] != "response"
        for entry in _repair(differing)[0]["items"] for repair in entry["repairs"]
    )


async def test_a_save_gives_a_later_finding_the_response_the_others_agree_on(deps):
    blocks = WITHOUT_SSVC.split("\n\n", 1)[1]
    await _seed(f"{LEAD} [Response: UPDATE]\n\n{blocks}", f"{LEAD} [Response: UPDATE]\n\n{blocks}", f"{LEAD}\n\n{blocks}")

    await save_assessment(
        deps,
        AssessmentRequest(instances=FINDINGS, state="NOT_AFFECTED", details="Checked.", team="Third Party"),
        user="analyst-2", client=None,
    )

    assert all("[Response: UPDATE]" in _details(instance) for instance in FINDINGS)


async def test_global_cleanup_preview_removes_pending_only_without_changing_teams(deps):
    from dtvp.assessment_model import parse_assessment, version_override, with_version_override
    from dtvp.assessment_review import changes_requests, with_changes_requests

    requests = [{'team': 'Identity', 'rationale': 'More evidence', 'reviewer': 'rita', 'requested_at_ms': 1794822866568}]
    scope = {'label': '7.x exception', 'reason': 'Different configuration'}
    text = with_changes_requests(with_version_override(f'{TEAMS}\n\n{PENDING}', scope), requests)
    await _seed(text, origin="assessment-changes-requested")
    assert changes_requests(_details(EARLY)) == requests
    before = parse_assessment('NOT_AFFECTED', _details(EARLY), False)
    preview = await clean_up_assessment(deps, [EARLY], action='clear', team='General', source=None,
                                       user='rita', role='REVIEWER', dry_run=True)
    assert preview[0]['changed'] is True
    after = preview[0]['after']
    assert PENDING not in after['details']
    assert parse_assessment(after['state'], after['details'], False)['teams'] == before['teams']
    assert version_override(after['details']) == scope
    assert changes_requests(after['details']) == requests
    assert PENDING in _details(EARLY)  # preview writes nothing
    await clean_up_assessment(deps, [EARLY], action='clear', team='General', source=None,
                              user='rita', role='REVIEWER')
    assert PENDING not in _details(EARLY)


async def test_global_cleanup_removes_ssvc_and_general_while_retaining_team_metadata(deps):
    from dtvp.assessment_model import parse_assessment

    historical = (
        '--- [Team: Retired] [State: EXPLOITABLE] [Assessed By: earlier-author] '
        '[Reviewed By: earlier-reviewer] [Date: 1700000000000] [Historical: yes] '
        '[Rescored: 9.8] [Rescored Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H] ---\n'
        'Historical evidence.'
    )
    await _seed(f'{WITH_SSVC}\n\n{historical}')
    before = parse_assessment('NOT_AFFECTED', _details(EARLY), False)
    expected_teams = [team for team in before['teams'] if team['team'] != 'General']
    await clean_up_assessment(deps, [EARLY], action='clear', team='General', source=None,
                              user='rita', role='REVIEWER')
    after = parse_assessment(_stored(EARLY)['analysisState'], _details(EARLY), False)
    assert after['teams'] == expected_teams
    assert after['pending_review'] is False
    assert after['rescored_score'] is None and after['rescored_vector'] is None
    assert after['free_text'] == '' and after['response'] is None
    assert read_record(_details(EARLY)) is None
