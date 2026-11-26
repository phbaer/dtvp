"""The assessment use cases work without the web layer."""

import logging
from types import SimpleNamespace

import pytest

from dtvp import dt_cache
from dtvp.assessment_review import (
    REQUEST_CHANGES_ORIGIN,
    WITHDRAW_CHANGES_ORIGIN,
    changes_requests,
)
from dtvp.assessment_services import (
    AssessmentServiceDeps,
    build_assessment_payloads,
    collect_assessment_conflicts,
    fetch_current_assessment_analyses,
)
from dtvp.assessment_use_cases import (
    AssessmentConflictError,
    AssessmentPermissionError,
    AssessmentRequest,
    AssessmentValidationError,
    request_assessment_changes,
    save_assessment,
    seen_assessments,
)
from dtvp.logic import calculate_aggregated_state, process_assessment_details

INSTANCE = {
    "project_uuid": "p1",
    "component_uuid": "c1",
    "vulnerability_uuid": "v1",
    "finding_uuid": "f1",
}
SSVC = {"model": "ssvc:DT_DP", "version": "1.0.0", "answers": {}, "rationale": "r"}


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
        fetch_current_assessment_analyses=lambda req, client: (
            fetch_current_assessment_analyses(service_deps, req, client)
        ),
        collect_assessment_conflicts=lambda req, analyses: (
            collect_assessment_conflicts(service_deps, req, analyses)
        ),
        build_assessment_payloads=lambda req, user, role: (
            build_assessment_payloads(service_deps, req, user, role)
        ),
    )


def _request(**overrides):
    values = {
        "instances": [dict(INSTANCE)],
        "state": "IN_TRIAGE",
        "details": "Looking into it",
        "team": "Team A",
    }
    values.update(overrides)
    return AssessmentRequest(**values)


async def test_save_persists_locally_and_reports_the_revision(deps):
    seen = []

    async def after_persist(payloads):
        seen.extend(payloads)

    results = await save_assessment(
        deps, _request(), user="alice", client=None, after_persist=after_persist
    )

    assert [r["status"] for r in results] == ["success"]
    assert results[0]["uuid"] == "f1"
    assert results[0]["revision"] == 1
    assert results[0]["sync_status"] == "pending"
    stored = dt_cache.cache_manager.get_assessment_overlay("p1", "c1", "v1")
    assert "Looking into it" in stored["analysisDetails"]
    assert "[Status: Pending Review]" in stored["analysisDetails"]
    assert [payload["details"] for _instance, payload in seen] == [
        stored["analysisDetails"]
    ]


async def test_an_assessment_sent_as_fields_is_rendered_and_stored_as_those_fields(deps):
    fields = {
        "free_text": "Agreed with the supplier.",
        "pending_review": True,
        "teams": [
            {"team": "Team A", "state": "NOT_AFFECTED", "assessed_by": "alice",
             "justification": "CODE_NOT_REACHABLE", "ticket": "EXP-7",
             "assessed_at_ms": 1794561289026, "details": "Not reachable."},
        ],
    }
    results = await save_assessment(
        deps,
        # Whatever text a client still sends is ignored once fields are given.
        _request(state="NOT_AFFECTED", details="--- [Team: General] ---", fields=fields),
        user="alice", client=None,
    )

    assert [r["status"] for r in results] == ["success"]
    stored = dt_cache.cache_manager.get_assessment_overlay("p1", "c1", "v1")
    assert stored["analysisState"] == "NOT_AFFECTED"
    assert stored["analysisDetails"] == (
        "Agreed with the supplier.\n\n"
        "--- [Team: Team A] [State: NOT_AFFECTED] [Assessed By: alice] "
        "[Date: 1794561289026] [Justification: CODE_NOT_REACHABLE] [Ticket: EXP-7] ---\n"
        "Not reachable.\n\n[Status: Pending Review]"
    )
    record = dt_cache.cache_manager.get_assessment_fields("p1", "c1", "v1")
    assert (record["free_text"], record["pending_review"]) == (
        "Agreed with the supplier.", True
    )
    [team] = record["teams"]
    assert (team["team"], team["ticket"], team["justification"], team["details"]) == (
        "Team A", "EXP-7", "CODE_NOT_REACHABLE", "Not reachable."
    )


async def test_free_text_is_kept_unless_the_save_sends_one(deps):
    team = {"team": "Team A", "state": "IN_TRIAGE", "details": "First."}
    await save_assessment(
        deps,
        _request(fields={"free_text": "Agreed with the supplier.", "teams": [team]}),
        user="alice", client=None,
    )

    # A save from the form: fields without free text.
    await save_assessment(
        deps,
        _request(fields={"teams": [{**team, "details": "Second."}]}),
        user="alice", client=None,
    )
    record = dt_cache.cache_manager.get_assessment_fields("p1", "c1", "v1")
    assert record["free_text"] == "Agreed with the supplier."
    assert record["teams"][0]["details"] == "Second."

    # An explicit empty string removes it.
    await save_assessment(
        deps, _request(fields={"free_text": "", "teams": [team]}),
        user="alice", client=None,
    )
    assert dt_cache.cache_manager.get_assessment_fields("p1", "c1", "v1")["free_text"] == ""


async def test_the_payload_the_web_form_sends_is_accepted(deps):
    """The shape `assessmentTextToFields` produces in the frontend (see
    frontend/src/lib/__tests__/assessmentSubmission.spec.ts)."""
    payload = {
        "instances": [dict(INSTANCE)],
        "state": "EXPLOITABLE",
        "fields": {
            "free_text": None,
            "pending_review": True,
            "rescored_score": 9.8,
            "rescored_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "teams": [{
                "team": "Team A", "state": "EXPLOITABLE", "justification": None,
                "assessed_by": "reviewer", "reviewed_by": None,
                "assessed_at_ms": 1794561289026, "rescored_score": None,
                "rescored_vector": None, "ssvc": None, "ssvc_details": None,
                "assigned": ["alice"], "ticket": "SEC-1234",
                "evidence_reviewed": "yes", "version_coverage": "yes",
                "historical": False, "copied_from": None,
                "details": "Current team details",
            }],
        },
        "suppressed": False,
        "team": "Team A",
        "original_analysis": {},
        "force": False,
        "analysis_run_ids": [],
    }
    results = await save_assessment(
        deps, AssessmentRequest(**payload), user="alice", client=None
    )
    assert [r["status"] for r in results] == ["success"]
    record = dt_cache.cache_manager.get_assessment_fields("p1", "c1", "v1")
    assert (record["state"], record["rescored_score"], record["pending_review"]) == (
        "EXPLOITABLE", 9.8, True
    )
    [team] = record["teams"]
    assert (team["ticket"], team["assigned"], team["evidence_reviewed"]) == (
        "SEC-1234", ["alice"], "yes"
    )


EXISTING_WITH_TAGS = (
    "--- [Team: General] [State: NOT_AFFECTED] [Assessed By: alice] [Reviewed By: rita] "
    "[Date: 1794561289026] [Justification: CODE_NOT_REACHABLE] [Evidence Reviewed: yes] "
    "[Version Coverage: yes] [Ticket: EXP-1001] ---\nNot reachable.\n\n"
    "--- [Team: Team B] [State: NOT_AFFECTED] [Assessed By: bob] [Date: 1794561289027] "
    "[Justification: CODE_NOT_REACHABLE] [Ticket: EXP-7] ---\nTeam B agrees."
)


async def test_a_team_save_keeps_every_tag_of_the_other_teams(deps):
    """A save that names one team (the MCP tools, API clients) rebuilt every
    block with a subset of the tags and dropped date, justification, ticket,
    and the review confirmations from all of them."""
    await dt_cache.cache_manager.persist_assessment_updates(
        [{**INSTANCE, "state": "NOT_AFFECTED", "details": EXISTING_WITH_TAGS,
          "suppressed": False}]
    )

    await save_assessment(
        deps,
        # As the MCP tools call it: the stored text is the base of the merge.
        _request(state="NOT_AFFECTED", details="Team A checked it.",
                 justification="CODE_NOT_PRESENT",
                 instances=[{**INSTANCE, "analysis_details": EXISTING_WITH_TAGS}]),
        user="alice", client=None,
    )

    record = dt_cache.cache_manager.get_assessment_fields("p1", "c1", "v1")
    teams = {team["team"]: team for team in record["teams"]}
    general, team_b, team_a = teams["General"], teams["Team B"], teams["Team A"]
    assert (general["assessed_at_ms"], general["justification"], general["ticket"],
            general["evidence_reviewed"], general["version_coverage"],
            general["reviewed_by"]) == (
        1794561289026, "CODE_NOT_REACHABLE", "EXP-1001", "yes", "yes", "rita"
    )
    assert (team_b["assessed_at_ms"], team_b["ticket"], team_b["details"]) == (
        1794561289027, "EXP-7", "Team B agrees."
    )
    # The saved team is dated and carries the justification that was sent.
    assert team_a["assessed_by"] == "alice" and team_a["assessed_at_ms"] > 1794561289027
    assert team_a["justification"] == "CODE_NOT_PRESENT"


async def test_every_writer_stores_the_same_layout(deps):
    spaced = EXISTING_WITH_TAGS.replace("---\nNot reachable", "---\n\nNot reachable")
    payload = {**INSTANCE, "state": "NOT_AFFECTED", "details": spaced, "suppressed": False}

    await dt_cache.cache_manager.persist_assessment_updates([payload])

    stored = dt_cache.cache_manager.get_assessment_overlay("p1", "c1", "v1")
    assert stored["analysisDetails"] == EXISTING_WITH_TAGS
    # The caller is told what was stored.
    assert payload["details"] == EXISTING_WITH_TAGS


async def test_fields_that_cannot_be_rendered_are_refused(deps):
    duplicate = {"teams": [{"team": "Team A"}, {"team": "team a"}]}
    with pytest.raises(AssessmentValidationError, match="More than one assessment"):
        await save_assessment(
            deps, _request(fields=duplicate), user="alice", client=None
        )
    assert dt_cache.cache_manager.get_assessment_overlay("p1", "c1", "v1") is None


async def test_explicit_role_overrides_the_configured_role(deps):
    deps.get_user_role = lambda _user: "REVIEWER"

    await save_assessment(
        deps, _request(), user="alice", client=None, role="ANALYST"
    )

    stored = dt_cache.cache_manager.get_assessment_overlay("p1", "c1", "v1")
    assert "[Status: Pending Review]" in stored["analysisDetails"]


@pytest.mark.parametrize("how", ["fields", "replace"])
async def test_an_analysts_save_always_waits_for_review(deps, how):
    """Only a reviewer approves: an analyst's client cannot leave the marker
    out, neither in fields nor in a whole text."""
    text = (
        "--- [Team: Team A] [State: NOT_AFFECTED] [Assessed By: alice] "
        "[Justification: CODE_NOT_PRESENT] ---\nNot shipped."
    )
    if how == "fields":
        request = _request(team="Team A", state="NOT_AFFECTED", fields={
            "pending_review": False,
            "teams": [{"team": "Team A", "state": "NOT_AFFECTED", "assessed_by": "alice",
                       "justification": "CODE_NOT_PRESENT", "details": "Not shipped."}],
        })
    else:
        request = _request(team="Team A", state="NOT_AFFECTED", details=text,
                           comparison_mode="REPLACE")

    await save_assessment(deps, request, user="alice", client=None, role="ANALYST")

    stored = dt_cache.cache_manager.get_assessment_overlay("p1", "c1", "v1")
    assert "[Status: Pending Review]" in stored["analysisDetails"]
    assert parse_assessment(
        stored["analysisState"], stored["analysisDetails"], False
    )["pending_review"] is True


async def test_a_reviewers_save_can_approve(deps):
    request = _request(team=None, state="NOT_AFFECTED", fields={
        "pending_review": False,
        "teams": [{"team": "General", "state": "NOT_AFFECTED", "assessed_by": "rita",
                   "justification": "CODE_NOT_PRESENT", "details": "Not shipped."}],
    })

    await save_assessment(deps, request, user="rita", client=None, role="REVIEWER")

    stored = dt_cache.cache_manager.get_assessment_overlay("p1", "c1", "v1")
    assert "[Status: Pending Review]" not in stored["analysisDetails"]


async def test_ssvc_requires_a_reviewer(deps):
    with pytest.raises(AssessmentPermissionError):
        await save_assessment(
            deps, _request(team="General", ssvc=SSVC), user="alice", client=None
        )
    assert dt_cache.cache_manager.get_assessment_overlay("p1", "c1", "v1") is None


async def test_invalid_ssvc_is_a_validation_error(deps):
    with pytest.raises(AssessmentValidationError):
        await save_assessment(
            deps,
            _request(team="General", ssvc={**SSVC, "version": "unknown"}),
            user="rita",
            client=None,
            role="REVIEWER",
        )


async def test_unknown_analysis_run_is_a_validation_error(deps):
    with pytest.raises(AssessmentValidationError):
        await save_assessment(
            deps, _request(analysis_run_ids=["missing"]), user="alice", client=None
        )
    assert dt_cache.cache_manager.get_assessment_overlay("p1", "c1", "v1") is None


async def test_stale_revision_is_a_conflict(deps):
    await save_assessment(deps, _request(), user="alice", client=None)

    stale = _request(
        details="Second opinion",
        original_analysis={"f1": {"dtvpRevision": 0}},
    )
    with pytest.raises(AssessmentConflictError) as excinfo:
        await save_assessment(deps, stale, user="bob", client=None)

    conflict = excinfo.value.conflicts[0]
    assert conflict["finding_uuid"] == "f1"
    assert "Looking into it" in conflict["current"]["analysisDetails"]
    stored = dt_cache.cache_manager.get_assessment_overlay("p1", "c1", "v1")
    assert "Second opinion" not in stored["analysisDetails"]


def test_the_value_an_edit_was_made_on_is_taken_from_the_request():
    other = {**INSTANCE, "component_uuid": "c2", "finding_uuid": "f2"}
    untracked = {**INSTANCE, "component_uuid": "c3", "finding_uuid": "f3"}
    req = _request(
        instances=[dict(INSTANCE), other, untracked],
        original_analysis={
            "f1": {"analysisState": "IN_TRIAGE", "analysisDetails": "Seen", "isSuppressed": True},
            # Only a revision: says nothing about the text the author saw.
            "f2": {"dtvpRevision": 0},
        },
    )

    assert seen_assessments(req) == {
        ("p1", "c1", "v1"): {"state": "IN_TRIAGE", "details": "Seen", "suppressed": True}
    }
    assert seen_assessments(_request()) == {}


# --- The analysis response ---------------------------------------------------

_GENERAL = {"team": "General", "state": "EXPLOITABLE", "assessed_by": "rita",
            "details": "Reachable."}
_TEAM_A = {"team": "Team A", "state": "EXPLOITABLE", "assessed_by": "alice",
           "details": "Confirmed."}


def _response(instance=INSTANCE):
    record = dt_cache.cache_manager.get_assessment_fields(
        instance["project_uuid"], instance["component_uuid"],
        instance["vulnerability_uuid"],
    )
    return record["response"]


async def _save(deps, role, **request):
    return await save_assessment(
        deps, _request(state="EXPLOITABLE", **request), user="rita", role=role,
        client=None,
    )


async def test_a_reviewer_sets_changes_and_removes_the_response(deps):
    await _save(deps, "REVIEWER", team=None,
                fields={"response": "UPDATE", "teams": [_GENERAL]})
    stored = dt_cache.cache_manager.get_assessment_overlay("p1", "c1", "v1")
    assert stored["analysisDetails"].startswith("[Response: UPDATE]\n\n--- [Team: General]")
    assert _response() == "UPDATE"

    await _save(deps, "REVIEWER", team=None,
                fields={"response": "will_not_fix", "teams": [_GENERAL]})
    assert _response() == "WILL_NOT_FIX"

    # Optional also for an exploitable finding: null removes it.
    await _save(deps, "REVIEWER", team=None,
                fields={"response": None, "teams": [_GENERAL]})
    assert _response() is None
    stored = dt_cache.cache_manager.get_assessment_overlay("p1", "c1", "v1")
    assert "Response" not in stored["analysisDetails"]

    await _save(deps, "REVIEWER", team=None,
                fields={"response": "ROLLBACK", "teams": [_GENERAL]})
    await _save(deps, "REVIEWER", team=None,
                fields={"response": "NOT_SET", "teams": [_GENERAL]})
    assert _response() is None


async def test_a_save_that_is_not_a_reviewers_keeps_each_findings_response(deps):
    other = {**INSTANCE, "component_uuid": "c2", "finding_uuid": "f2"}
    await _save(deps, "REVIEWER", team=None,
                fields={"response": "UPDATE", "teams": [_GENERAL]})
    await _save(deps, "REVIEWER", team=None, instances=[dict(other)],
                fields={"response": "ROLLBACK", "teams": [_GENERAL]})

    # An analyst's team save over both findings, whatever its fields claim.
    for claimed in ({"response": "CAN_NOT_FIX"}, {"response": None}, {}):
        await _save(deps, "ANALYST", team="Team A",
                    instances=[dict(INSTANCE), dict(other)],
                    fields={**claimed, "pending_review": True,
                            "teams": [_GENERAL, _TEAM_A]})
        assert (_response(), _response(other)) == ("UPDATE", "ROLLBACK")
    record = dt_cache.cache_manager.get_assessment_fields("p1", "c1", "v1")
    assert [team["team"] for team in record["teams"]] == ["General", "Team A"]


async def test_fields_without_a_response_keep_it_for_a_reviewer_too(deps):
    """A client that does not know the field must not remove it."""
    await _save(deps, "REVIEWER", team=None,
                fields={"response": "UPDATE", "teams": [_GENERAL]})
    await _save(deps, "REVIEWER", team=None,
                fields={"free_text": "", "teams": [{**_GENERAL, "details": "Edited."}]})
    assert _response() == "UPDATE"
    record = dt_cache.cache_manager.get_assessment_fields("p1", "c1", "v1")
    assert record["teams"][0]["details"] == "Edited."


def test_an_unknown_response_is_refused():
    from pydantic import ValidationError

    for request in (
        {"fields": {"response": "MAYBE_LATER", "teams": [_GENERAL]}},
        {"response": "MAYBE_LATER"},
        {"response": 3},
    ):
        with pytest.raises(ValidationError, match="response"):
            _request(**request)
    assert _request(response="not_set").response == "NOT_SET"
    assert _request(fields={"response": "NOT_SET"}).fields.response is None


async def test_a_save_as_text_changes_the_response_only_as_a_reviewers_global_save(deps):
    await _save(deps, "REVIEWER", team=None, details="Reachable.", response="UPDATE")
    assert _response() == "UPDATE"

    def loaded():
        # A save as text merges into the text the client loaded.
        stored = dt_cache.cache_manager.get_assessment_overlay("p1", "c1", "v1")
        return [{**INSTANCE, "analysis_details": stored["analysisDetails"]}]

    # A team save, by anyone, keeps it and cannot name one.
    await _save(deps, "ANALYST", team="Team A", details="Confirmed.", instances=loaded())
    assert _response() == "UPDATE"
    for role, team in (("ANALYST", None), ("ANALYST", "Team A"), ("REVIEWER", "Team A")):
        with pytest.raises(AssessmentPermissionError, match="response"):
            await _save(deps, role, team=team, details="Confirmed.",
                        response="ROLLBACK", instances=loaded())
    assert _response() == "UPDATE"
    # A reviewer's Global save that names none keeps it as well.
    await _save(deps, "REVIEWER", team=None, details="Reachable.", instances=loaded())
    assert _response() == "UPDATE"

    await _save(deps, "REVIEWER", team=None, details="Reachable.", response="NOT_SET",
                instances=loaded())
    assert _response() is None



async def test_a_text_cannot_forge_or_remove_the_response(deps):
    """As with SSVC: what the client says the assessment was, and what it
    writes into a text, is no authority for the response. Also not when the
    whole text is replaced."""
    await _save(deps, "REVIEWER", team=None,
                fields={"response": "UPDATE", "teams": [_GENERAL]})
    general = (
        "--- [Team: General] [State: EXPLOITABLE] [Assessed By: rita] "
        "[Justification: NOT_SET] ---\nReachable."
    )
    forged = f"[Response: CAN_NOT_FIX]\n\n{general}"

    for role in ("ANALYST", "REVIEWER"):
        for text in (general, forged):
            # Merging into a text the client claims to have loaded ...
            await _save(deps, role, team="Team A", details="Confirmed.",
                        instances=[{**INSTANCE, "analysis_details": text}])
            assert _response() == "UPDATE"
            # ... and replacing the whole text.
            await _save(deps, role, team=None, details=text, comparison_mode="REPLACE")
            assert _response() == "UPDATE"
            stored = dt_cache.cache_manager.get_assessment_overlay("p1", "c1", "v1")
            assert stored["analysisDetails"].count("[Response:") == 1

    # A reviewer replaces the text and names the response beside it.
    await _save(deps, "REVIEWER", team=None, details=general,
                comparison_mode="REPLACE", response="ROLLBACK")
    assert _response() == "ROLLBACK"
    await _save(deps, "REVIEWER", team=None, details=forged,
                comparison_mode="REPLACE", response="NOT_SET")
    assert _response() is None


# -- code evidence a person referenced ---------------------------------------


def _evidence_store(tmp_path):
    from dtvp.code_evidence_services import CodeEvidenceStore

    return CodeEvidenceStore(path_provider=lambda: str(tmp_path / "evidence.sqlite"))


def _add_evidence(store, *, project="TestApp", vulnerability_uuid="v1", finding_uuid="f1"):
    from dtvp.code_evidence_services import normalize_evidence_input

    record, _created = store.add(
        project_name=project,
        vuln_id="CVE-2026-0001",
        vuln_ids=["CVE-2026-0001"],
        scope="vulnerability",
        targets=[
            {
                "component": "library-a",
                "finding_uuid": finding_uuid,
                "vulnerability_uuid": vulnerability_uuid,
            }
        ],
        author_username="alice",
        token_id="tok_1",
        agent_label="bot",
        **normalize_evidence_input(title="Not linked", body_markdown="Body"),
    )
    return record


EVIDENCE_INSTANCE = {**INSTANCE, "project_name": "TestApp"}


@pytest.mark.parametrize(
    "case", ["unknown", "withdrawn", "other_project", "other_vulnerability"]
)
async def test_unusable_code_evidence_is_rejected_before_the_write(
    deps, tmp_path, case
):
    store = _evidence_store(tmp_path)
    deps.code_evidence_store = store
    evidence_id = "ev_missing"
    if case == "withdrawn":
        evidence_id = _add_evidence(store)["evidence_id"]
        store.withdraw(evidence_id, "rita", "wrong")
    elif case == "other_project":
        evidence_id = _add_evidence(store, project="Other")["evidence_id"]
    elif case == "other_vulnerability":
        evidence_id = _add_evidence(
            store, vulnerability_uuid="v9", finding_uuid="f9"
        )["evidence_id"]

    with pytest.raises(AssessmentValidationError, match="evidence"):
        await save_assessment(
            deps,
            _request(instances=[dict(EVIDENCE_INSTANCE)], code_evidence_ids=[evidence_id]),
            user="bob",
            client=None,
        )
    assert dt_cache.cache_manager.get_assessment_overlay("p1", "c1", "v1") is None
    assert store.list_applications([evidence_id]) == []


async def test_code_evidence_applications_are_recorded_after_the_save(deps, tmp_path):
    store = _evidence_store(tmp_path)
    deps.code_evidence_store = store
    # The same DT vulnerability in another project version is the same
    # vulnerability, even with a different finding.
    evidence_id = _add_evidence(store, finding_uuid="f-older-version")["evidence_id"]

    await save_assessment(
        deps,
        _request(instances=[dict(EVIDENCE_INSTANCE)], code_evidence_ids=[evidence_id]),
        user="bob",
        client=None,
    )

    assert dt_cache.cache_manager.get_assessment_overlay("p1", "c1", "v1") is not None
    [application] = store.list_applications([evidence_id])
    assert application["finding_uuid"] == "f1"
    assert application["applied_by"] == "bob"
    assert application["status"] == "queued"
    assert application["workflow_id"] == "individual-assessment"


# --- A save never drops another team's block ------------------------------

from dtvp.assessment_model import parse_assessment, render_assessment  # noqa: E402

_TEAM_B_STORED = {
    "team": "TeamB", "state": "EXPLOITABLE", "assessed_by": "bob",
    "assessed_at_ms": 1794561289027, "justification": "PROTECTED_BY_MITIGATING_CONTROL",
    "ticket": "EXP-1", "details": "TeamB confirmed it.",
}
_TEAM_A_FIELDS = {
    "team": "TeamA", "state": "NOT_AFFECTED", "assessed_by": "alice",
    "assessed_at_ms": 1794561289100, "justification": "CODE_NOT_REACHABLE",
    "details": "TeamA does not reach it.",
}


async def _store(deps, *teams, instance=INSTANCE, free_text=None, pending=True):
    """The starting text, stored through a reviewer's save of all blocks."""
    fields = {"teams": list(teams), "pending_review": pending}
    if free_text is not None:
        fields["free_text"] = free_text
    await save_assessment(
        deps, _request(team=None, state="NOT_SET", fields=fields,
                       instances=[dict(instance)]),
        user="rita", role="REVIEWER", client=None,
    )


def _stored(instance=INSTANCE):
    return dt_cache.cache_manager.get_assessment_overlay(
        instance["project_uuid"], instance["component_uuid"],
        instance["vulnerability_uuid"],
    )


def _teams(instance=INSTANCE):
    stored = _stored(instance)
    record = parse_assessment(
        stored["analysisState"], stored["analysisDetails"], stored["isSuppressed"]
    )
    # One block per team: rendering the fields again must not fail.
    render_assessment(record)
    return {team["team"]: team for team in record["teams"]}


async def test_a_team_save_without_another_teams_block_keeps_it_as_historical(deps):
    await _store(deps, _TEAM_B_STORED)
    revision = _stored()["dtvpRevision"]

    # TeamA's form did not show TeamB's block.
    await save_assessment(
        deps,
        _request(team="TeamA", state="NOT_AFFECTED",
                 fields={"pending_review": True, "teams": [_TEAM_A_FIELDS]}),
        user="alice", client=None,
    )

    teams = _teams()
    team_b = teams["TeamB"]
    assert team_b["historical"] is True
    assert (team_b["state"], team_b["assessed_by"], team_b["assessed_at_ms"],
            team_b["justification"], team_b["ticket"], team_b["details"]) == (
        "EXPLOITABLE", "bob", 1794561289027, "PROTECTED_BY_MITIGATING_CONTROL",
        "EXP-1", "TeamB confirmed it.",
    )
    assert teams["TeamA"]["historical"] is False
    # TeamB no longer counts: the finding has TeamA's state.
    assert _stored()["analysisState"] == "NOT_AFFECTED"
    assert _stored()["dtvpRevision"] == revision + 1


async def test_a_reviewers_whole_text_without_a_block_keeps_it_as_historical(deps):
    await _store(deps, _TEAM_B_STORED, {**_TEAM_A_FIELDS})
    text = (
        "--- [Team: TeamA] [State: NOT_AFFECTED] [Assessed By: alice] "
        "[Justification: CODE_NOT_REACHABLE] ---\nTeamA does not reach it."
    )

    await save_assessment(
        deps, _request(team=None, state="NOT_AFFECTED", details=text,
                       comparison_mode="REPLACE"),
        user="rita", role="REVIEWER", client=None,
    )

    teams = _teams()
    assert teams["TeamB"]["historical"] is True
    assert teams["TeamB"]["ticket"] == "EXP-1"
    assert _stored()["analysisState"] == "NOT_AFFECTED"


async def test_a_team_clearing_its_own_block_leaves_no_historical_block(deps):
    await _store(deps, _TEAM_A_FIELDS, _TEAM_B_STORED)

    await save_assessment(
        deps,
        _request(team="TeamA", state="EXPLOITABLE",
                 fields={"pending_review": True, "teams": [_TEAM_B_STORED]}),
        user="alice", client=None,
    )

    assert set(_teams()) == {"TeamB"}
    assert _teams()["TeamB"]["historical"] is False


async def test_a_team_save_never_removes_the_general_assessment(deps):
    general = {"team": "General", "state": "FALSE_POSITIVE", "assessed_by": "rita",
               "assessed_at_ms": 1794561289000, "details": "Not this package."}
    await _store(deps, general, {**_TEAM_A_FIELDS, "state": "IN_TRIAGE"})

    await save_assessment(
        deps,
        _request(team="TeamA", state="NOT_AFFECTED",
                 fields={"pending_review": True, "teams": [_TEAM_A_FIELDS]}),
        user="alice", client=None,
    )

    teams = _teams()
    assert list(teams) == ["General", "TeamA"]
    assert teams["General"]["historical"] is False
    assert (teams["General"]["state"], teams["General"]["details"],
            teams["General"]["assessed_at_ms"]) == (
        "FALSE_POSITIVE", "Not this package.", 1794561289000
    )
    assert teams["TeamA"]["state"] == "NOT_AFFECTED"
    # The General assessment still decides the finding's state.
    assert _stored()["analysisState"] == "FALSE_POSITIVE"
    assert _stored()["analysisDetails"].endswith("[Status: Pending Review]")


async def test_a_historical_block_a_save_leaves_out_is_kept(deps):
    await _store(deps, _TEAM_A_FIELDS, {**_TEAM_B_STORED, "historical": True})

    await save_assessment(
        deps,
        _request(team="TeamA", state="NOT_AFFECTED",
                 fields={"pending_review": True,
                         "teams": [{**_TEAM_A_FIELDS, "details": "Rechecked."}]}),
        user="alice", client=None,
    )

    teams = _teams()
    assert teams["TeamB"]["historical"] is True
    assert teams["TeamB"]["ticket"] == "EXP-1"
    assert teams["TeamA"]["details"] == "Rechecked."


def _all_blocks(instance=INSTANCE):
    stored = _stored(instance)
    record = parse_assessment(
        stored["analysisState"], stored["analysisDetails"], stored["isSuppressed"]
    )
    render_assessment(record)
    return record["teams"]


@pytest.mark.parametrize("by_fields", [True, False])
async def test_a_teams_save_keeps_its_own_historical_block(deps, by_fields):
    # TeamB's former assessment, kept by the repair; TeamB owns it again.
    await _store(deps, {**_TEAM_B_STORED, "historical": True})

    if by_fields:
        request = _request(
            team="TeamB", state="NOT_AFFECTED",
            fields={"pending_review": True, "teams": [{
                "team": "TeamB", "state": "NOT_AFFECTED", "assessed_by": "bert",
                "justification": "CODE_NOT_REACHABLE", "details": "Rechecked.",
            }]},
        )
    else:
        request = _request(team="TeamB", state="NOT_AFFECTED", details="Rechecked.",
                           justification="CODE_NOT_REACHABLE")
    await save_assessment(deps, request, user="bert", client=None)

    team_b = sorted(
        (team for team in _all_blocks() if team["team"] == "TeamB"),
        key=lambda team: not team["historical"],
    )
    assert [(team["historical"], team["state"], team["assessed_by"]) for team in team_b] == [
        (True, "EXPLOITABLE", "bob"), (False, "NOT_AFFECTED", "bert"),
    ]
    record = team_b[0]
    assert (record["assessed_at_ms"], record["justification"], record["ticket"],
            record["details"]) == (
        1794561289027, "PROTECTED_BY_MITIGATING_CONTROL", "EXP-1", "TeamB confirmed it.",
    )
    assert team_b[1]["details"] == "Rechecked."
    assert _stored()["analysisState"] == "NOT_AFFECTED"


async def test_an_open_block_a_save_leaves_out_stays_open(deps):
    # Another team's block without a decision but with assignees tracks
    # work: a save whose view lacked it keeps it as it was, still open.
    await _store(deps, _TEAM_A_FIELDS, {"team": "TeamB", "state": "NOT_SET",
                                         "assigned": ["bob"]})
    assert "TeamB" in _teams()

    await save_assessment(
        deps,
        _request(team="TeamA", state="NOT_AFFECTED",
                 fields={"pending_review": True, "teams": [_TEAM_A_FIELDS]}),
        user="alice", client=None,
    )

    teams = _teams()
    assert set(teams) == {"TeamA", "TeamB"}
    assert teams["TeamB"]["historical"] is False
    assert teams["TeamB"]["assigned"] == ["bob"]


async def test_an_empty_block_a_save_leaves_out_is_not_brought_back(deps):
    await _store(deps, _TEAM_A_FIELDS, {"team": "TeamB", "state": "NOT_SET"})

    await save_assessment(
        deps,
        _request(team="TeamA", state="NOT_AFFECTED",
                 fields={"pending_review": True, "teams": [_TEAM_A_FIELDS]}),
        user="alice", client=None,
    )

    assert set(_teams()) == {"TeamA"}


async def test_only_the_finding_that_had_the_block_gets_it_back(deps):
    other = {**INSTANCE, "component_uuid": "c2", "finding_uuid": "f2"}
    await _store(deps, _TEAM_B_STORED)
    await _store(deps, {**_TEAM_A_FIELDS, "state": "IN_TRIAGE"}, instance=other)

    await save_assessment(
        deps,
        _request(team="TeamA", state="NOT_AFFECTED",
                 instances=[dict(INSTANCE), dict(other)],
                 fields={"pending_review": True, "teams": [_TEAM_A_FIELDS]}),
        user="alice", client=None,
    )

    assert _teams()["TeamB"]["historical"] is True
    assert set(_teams(other)) == {"TeamA"}


async def test_a_merge_save_from_a_stale_view_keeps_the_block_it_did_not_see(deps):
    """A save as text merges into the text the client loaded; a block that
    text lacked is still not lost."""
    await _store(deps, _TEAM_B_STORED)

    await save_assessment(
        deps,
        _request(team="TeamA", state="NOT_AFFECTED", details="TeamA checked.",
                 instances=[{**INSTANCE, "analysis_details": ""}]),
        user="alice", client=None,
    )

    teams = _teams()
    assert teams["TeamB"]["historical"] is True
    assert teams["TeamA"]["details"] == "TeamA checked."


# --- A save that changes only metadata keeps who assessed and when --------

_TEAM_A_STORED = {**_TEAM_A_FIELDS, "ticket": "EXP-1", "assessed_by": "alice",
                  "assessed_at_ms": 1794561289100}


async def _save_team_a(deps, team_a, *others, pending=True, role=None, user="carol"):
    await save_assessment(
        deps,
        _request(team="TeamA", state=team_a["state"],
                 fields={"pending_review": pending, "teams": [team_a, *others]}),
        user=user, role=role, client=None,
    )


async def test_a_ticket_change_keeps_assessor_and_date(deps):
    await _store(deps, _TEAM_A_STORED)

    await _save_team_a(deps, {**_TEAM_A_STORED, "ticket": "EXP-1, EXP-2",
                              "assessed_by": "carol", "assessed_at_ms": 1794561299999})

    team_a = _teams()["TeamA"]
    assert (team_a["ticket"], team_a["assessed_by"], team_a["assessed_at_ms"]) == (
        "EXP-1, EXP-2", "alice", 1794561289100
    )
    assert _stored()["analysisDetails"].endswith("[Status: Pending Review]")


async def test_a_changed_text_takes_the_new_assessor_and_date(deps):
    await _store(deps, _TEAM_A_STORED)

    await _save_team_a(deps, {**_TEAM_A_STORED, "ticket": "EXP-2", "details": "Rechecked.",
                              "assessed_by": "carol", "assessed_at_ms": 1794561299999})

    team_a = _teams()["TeamA"]
    assert (team_a["assessed_by"], team_a["assessed_at_ms"]) == ("carol", 1794561299999)


async def test_an_approval_takes_the_assessor_and_date_it_sends(deps):
    await _store(deps, _TEAM_A_STORED)

    await _save_team_a(deps, {**_TEAM_A_STORED, "ticket": "EXP-2",
                              "assessed_by": "rita", "assessed_at_ms": 1794561299999},
                       pending=False, role="REVIEWER", user="rita")

    team_a = _teams()["TeamA"]
    assert (team_a["assessed_by"], team_a["assessed_at_ms"]) == ("rita", 1794561299999)


async def test_another_teams_unchanged_block_keeps_its_attribution(deps):
    await _store(deps, _TEAM_A_STORED, _TEAM_B_STORED)

    await _save_team_a(deps, {**_TEAM_A_STORED, "details": "Rechecked."},
                       {**_TEAM_B_STORED, "assessed_by": "carol",
                        "assessed_at_ms": 1794561299999})

    team_b = _teams()["TeamB"]
    assert (team_b["assessed_by"], team_b["assessed_at_ms"]) == ("bob", 1794561289027)


async def test_a_merge_save_that_only_assigns_keeps_assessor_and_date(deps):
    await _store(deps, _TEAM_A_STORED)
    stored = _stored()["analysisDetails"]

    await save_assessment(
        deps,
        _request(team="TeamA", state="NOT_AFFECTED", details="TeamA does not reach it.",
                 assigned=["dave"],
                 instances=[{**INSTANCE, "analysis_details": stored}]),
        user="carol", client=None,
    )

    team_a = _teams()["TeamA"]
    assert team_a["assigned"] == ["dave"]
    assert (team_a["assessed_by"], team_a["assessed_at_ms"]) == ("alice", 1794561289100)


# --- Only an explicit approval removes pending review ----------------------

from dtvp.assessment_use_cases import delete_assessment  # noqa: E402

_PENDING = "[Status: Pending Review]"


async def _reviewer_save(deps, **request):
    await save_assessment(
        deps, _request(**request), user="rita", role="REVIEWER", client=None
    )


@pytest.mark.parametrize("how", ["fields", "replace", "merge"])
async def test_a_reviewers_plain_save_keeps_pending_review(deps, how):
    """Editing a pending assessment is not approving it, whatever the
    reviewer's client sends."""
    await _store(deps, _TEAM_A_STORED)
    assert _PENDING in _stored()["analysisDetails"]

    edited = {**_TEAM_A_STORED, "details": "Reworded by the reviewer."}
    if how == "fields":
        await _reviewer_save(deps, team="TeamA", state="NOT_AFFECTED",
                             fields={"pending_review": False, "teams": [edited]})
    elif how == "replace":
        await _reviewer_save(
            deps, team="TeamA", state="NOT_AFFECTED", comparison_mode="REPLACE",
            details=render_assessment({"teams": [edited], "pending_review": False}),
        )
    else:
        await _reviewer_save(deps, team="TeamA", state="NOT_AFFECTED",
                             details="Reworded by the reviewer.",
                             justification="CODE_NOT_REACHABLE")

    assert _teams()["TeamA"]["details"] == "Reworded by the reviewer."
    assert _stored()["analysisDetails"].endswith(_PENDING)


@pytest.mark.parametrize("client_says_pending", [False, True])
async def test_an_explicit_approval_removes_pending_review(deps, client_says_pending):
    await _store(deps, _TEAM_A_STORED)

    await _reviewer_save(
        deps, team="TeamA", state="NOT_AFFECTED", approve=True,
        fields={"pending_review": client_says_pending, "teams": [_TEAM_A_STORED]},
    )

    stored = _stored()
    assert _PENDING not in stored["analysisDetails"]
    assert parse_assessment(
        stored["analysisState"], stored["analysisDetails"], False
    )["pending_review"] is False
    assert stored["analysisState"] == "NOT_AFFECTED"


async def test_only_a_reviewer_can_approve(deps):
    await _store(deps, _TEAM_A_STORED)
    revision = _stored()["dtvpRevision"]

    with pytest.raises(AssessmentPermissionError):
        await save_assessment(
            deps,
            _request(team="TeamA", state="NOT_AFFECTED", approve=True,
                     fields={"pending_review": False, "teams": [_TEAM_A_STORED]}),
            user="alice", role="ANALYST", client=None,
        )

    assert _stored()["dtvpRevision"] == revision
    assert _PENDING in _stored()["analysisDetails"]


async def test_a_reviewers_own_assessment_of_something_not_pending_is_not_pending(deps):
    """There is no pending status to keep: the reviewer's decision stands."""
    await _store(deps, _TEAM_A_STORED, pending=False)
    assert _PENDING not in _stored()["analysisDetails"]

    await _reviewer_save(deps, team="TeamA", state="NOT_AFFECTED",
                         fields={"pending_review": False,
                                 "teams": [{**_TEAM_A_STORED, "details": "Checked."}]})

    assert _PENDING not in _stored()["analysisDetails"]


@pytest.mark.parametrize("was_pending", [True, False])
async def test_a_reviewers_deletion_of_a_team_assessment_keeps_pending_review(
    deps, was_pending
):
    await _store(deps, _TEAM_A_STORED, _TEAM_B_STORED, pending=was_pending)

    await delete_assessment(
        deps, [dict(INSTANCE)], team="TeamB", user="rita", role="REVIEWER"
    )

    assert list(_teams()) == ["TeamA"]
    assert (_PENDING in _stored()["analysisDetails"]) is was_pending


# --- A forced save is still guarded against a concurrent write --------------


class _RacingCache:
    """The cache manager, with another author's save landing between the use
    case's read and its persist."""

    def __init__(self, real, racing_payload):
        self._real = real
        self._racing_payload = racing_payload

    def __getattr__(self, name):
        return getattr(self._real, name)

    async def persist_assessment_updates(self, payloads, **options):
        if self._racing_payload is not None:
            racing, self._racing_payload = self._racing_payload, None
            await self._real.persist_assessment_updates(
                [racing], replace=True, author="bob", origin="user"
            )
        return await self._real.persist_assessment_updates(payloads, **options)


_RACING = {
    "project_uuid": "p1", "component_uuid": "c1", "vulnerability_uuid": "v1",
    "state": "EXPLOITABLE", "suppressed": False,
    "details": "--- [Team: TeamB] [State: EXPLOITABLE] [Assessed By: bob] "
               "[Justification: NOT_SET] ---\nSaved meanwhile.",
}


@pytest.mark.parametrize("request_options", [
    {"force": True, "original_analysis": {}},
    {"force": True, "original_analysis": {"f1": {"dtvpRevision": 0}}},
    {"force": False},
], ids=["forced", "forced-with-a-stale-view", "no-view-given"])
async def test_a_save_without_a_view_fails_when_another_save_lands_first(
    deps, request_options
):
    await _store(deps, _TEAM_A_STORED)
    deps.cache_manager = _RacingCache(dt_cache.cache_manager, dict(_RACING))

    with pytest.raises(AssessmentConflictError) as excinfo:
        await _reviewer_save(
            deps, team="TeamA", state="NOT_AFFECTED",
            fields={"pending_review": True,
                    "teams": [{**_TEAM_A_STORED, "details": "Overwrites."}]},
            **request_options,
        )

    assert excinfo.value.conflicts[0]["finding_uuid"] == "f1"
    # The save that landed first is what is stored.
    assert "Saved meanwhile." in _stored()["analysisDetails"]
    assert "Overwrites." not in _stored()["analysisDetails"]


async def test_a_forced_save_without_a_race_overwrites_a_stale_view(deps):
    await _store(deps, _TEAM_A_STORED)
    deps.cache_manager = _RacingCache(dt_cache.cache_manager, None)

    await _reviewer_save(
        deps, team="TeamA", state="NOT_AFFECTED", force=True,
        original_analysis={"f1": {"dtvpRevision": 0}},
        fields={"pending_review": True,
                "teams": [{**_TEAM_A_STORED, "details": "Overwrites."}]},
    )

    assert _teams()["TeamA"]["details"] == "Overwrites."


# --- Approval only when Ready for approval (ADR 0014) ------------------------

_TEAMS_INSTANCE = {**INSTANCE, "tags": ["TeamA", "TeamB"]}
_GENERAL_PENDING = {"team": "General", "state": "NOT_AFFECTED", "assessed_by": "alice",
                    "justification": "CODE_NOT_PRESENT", "details": "Not shipped."}


async def test_approval_of_an_incomplete_vulnerability_is_refused(deps):
    # TeamB has no assessment and no General decision covers it: Incomplete.
    await _store(deps, _TEAM_A_STORED, instance=_TEAMS_INSTANCE)
    revision = _stored()["dtvpRevision"]

    with pytest.raises(AssessmentValidationError, match="ready for approval"):
        await _reviewer_save(
            deps, instances=[dict(_TEAMS_INSTANCE)], team=None, state="NOT_AFFECTED", approve=True,
            fields={"pending_review": False, "teams": [_GENERAL_PENDING, _TEAM_A_STORED]},
        )

    assert _stored()["dtvpRevision"] == revision
    assert _PENDING in _stored()["analysisDetails"]


async def test_a_pending_general_decision_that_covers_a_team_can_be_approved(deps):
    # Saved first (pending), the General decision covers TeamB: Ready for approval.
    await _store(deps, _GENERAL_PENDING, _TEAM_A_STORED, instance=_TEAMS_INSTANCE)

    await _reviewer_save(
        deps, instances=[dict(_TEAMS_INSTANCE)], team=None, state="NOT_AFFECTED", approve=True,
        fields={"pending_review": False, "teams": [_GENERAL_PENDING, _TEAM_A_STORED]},
    )

    assert _PENDING not in _stored()["analysisDetails"]


async def _request_changes(deps, instances, team="TeamA", rationale="Check the patch.",
                           revisions=None, **options):
    return await request_assessment_changes(
        deps, instances, team=team, rationale=rationale, user="rita",
        revisions=revisions if revisions is not None else {
            instance["finding_uuid"]: (_stored(instance) or {}).get("dtvpRevision", 0)
            for instance in instances
        },
        **options,
    )


async def test_changes_request_preserves_verdict_and_blocks_forced_approval(deps):
    await _store(deps, _GENERAL_PENDING, _TEAM_A_STORED, instance=_TEAMS_INSTANCE)
    original = _stored()
    with pytest.raises(AssessmentPermissionError, match="Only reviewers"):
        await _request_changes(deps, [_TEAMS_INSTANCE])
    deps.get_user_role = lambda _user: "REVIEWER"
    with pytest.raises(AssessmentValidationError, match="submitted team"):
        await _request_changes(deps, [_TEAMS_INSTANCE], team="TeamB")
    with pytest.raises(AssessmentConflictError):
        await _request_changes(deps, [_TEAMS_INSTANCE], revisions={"f1": 0})
    await _request_changes(deps, [_TEAMS_INSTANCE])

    assert _stored()["analysisState"] == original["analysisState"] == "NOT_AFFECTED"
    assert _teams()["TeamA"]["assessed_by"] == "alice"
    [feedback] = changes_requests(_stored()["analysisDetails"])
    assert (feedback["team"], feedback["rationale"], feedback["reviewer"]) == (
        "TeamA", "Check the patch.", "rita",
    )
    with pytest.raises(AssessmentValidationError, match="resubmit"):
        await _reviewer_save(deps, approve=True, force=True)

    await delete_assessment(deps, [_TEAMS_INSTANCE], team=None, user="rita")
    assert changes_requests(_stored()["analysisDetails"]) == [feedback]
    with pytest.raises(AssessmentValidationError, match="resubmit"):
        await _reviewer_save(deps, approve=True, force=True)
    await _request_changes(deps, [INSTANCE], rationale=None, withdraw=True)
    assert changes_requests(_stored()["analysisDetails"]) == []

    history = dt_cache.cache_manager.assessment_outbox.list_revisions(("p1", "c1", "v1"))
    assert history[0]["origin"] == WITHDRAW_CHANGES_ORIGIN
    assert any(
        event["origin"] == REQUEST_CHANGES_ORIGIN
        and changes_requests(event["analysisDetails"]) == [feedback]
        for event in history
    )


async def test_explicit_resubmit_checks_scope_and_displayed_revisions(deps):
    await _store(deps, _TEAM_A_STORED, _TEAM_B_STORED, instance=_TEAMS_INSTANCE)
    deps.get_user_role = lambda _user: "REVIEWER"
    await _request_changes(deps, [_TEAMS_INSTANCE])
    stale_revision = _stored()["dtvpRevision"]
    await _request_changes(deps, [_TEAMS_INSTANCE], team="TeamB")

    request = {
        "instances": [dict(_TEAMS_INSTANCE)],
        "team": "TeamA",
        "state": "NOT_AFFECTED",
        "fields": {"pending_review": False, "teams": [
            {**_TEAM_A_STORED, "details": "Patch confirmed."},
            {**_TEAM_B_STORED, "details": "Stale and unrelated change."},
        ]},
        "force": True,
        "resubmit_changes": True,
    }
    with pytest.raises(AssessmentValidationError, match="full vulnerability"):
        await save_assessment(deps, _request(**request), user="alice", role="ANALYST", client=None)
    request.update(review_task_id="task", review_group_id="group")
    with pytest.raises(AssessmentConflictError):
        await save_assessment(
            deps, _request(**request, original_analysis={"f1": {"dtvpRevision": stale_revision}}),
            user="alice", role="ANALYST", client=None, approval_instances=[_TEAMS_INSTANCE],
        )
    await save_assessment(
        deps, _request(**request, original_analysis={"f1": {"dtvpRevision": _stored()["dtvpRevision"]}}),
        user="alice", role="ANALYST", client=None, approval_instances=[_TEAMS_INSTANCE],
    )
    assert [feedback["team"] for feedback in changes_requests(_stored()["analysisDetails"])] == ["TeamB"]
    assert _teams()["TeamA"]["details"] == "Patch confirmed."
    assert _teams()["TeamB"]["details"] == _TEAM_B_STORED["details"]
    assert _PENDING in _stored()["analysisDetails"]


async def test_approval_guards_canonical_finding_omitted_from_payload(deps):
    sibling = {**_TEAMS_INSTANCE, "component_uuid": "c2", "finding_uuid": "f2"}
    group = [_TEAMS_INSTANCE, sibling]
    for instance in group:
        await _store(deps, _GENERAL_PENDING, _TEAM_A_STORED, instance=instance)
    deps.get_user_role = lambda _user: "REVIEWER"
    await _request_changes(deps, [sibling])

    with pytest.raises(AssessmentValidationError, match="resubmit"):
        await save_assessment(
            deps, _request(instances=[_TEAMS_INSTANCE], approve=True, force=True, team=None),
            user="rita", client=None, approval_instances=group,
        )
    assert _PENDING in _stored()["analysisDetails"]


async def test_approval_revision_guard_covers_an_unwritten_sibling(deps):
    sibling = {**_TEAMS_INSTANCE, "component_uuid": "c2", "finding_uuid": "f2"}
    group = [_TEAMS_INSTANCE, sibling]
    for instance in group:
        await _store(deps, _GENERAL_PENDING, _TEAM_A_STORED, instance=instance)
    deps.cache_manager = _RacingCache(dt_cache.cache_manager, {**_RACING, "component_uuid": "c2"})
    req = _request(instances=[_TEAMS_INSTANCE], approve=True, force=True, team=None)

    with pytest.raises(AssessmentConflictError) as conflict:
        await save_assessment(deps, req, user="rita", role="REVIEWER", client=None,
                              approval_instances=group)

    assert conflict.value.conflicts[0]["finding_uuid"] == "f2"
    assert _PENDING in _stored()["analysisDetails"]
