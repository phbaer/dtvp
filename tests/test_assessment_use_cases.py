"""The assessment use cases work without the web layer."""

import logging
from types import SimpleNamespace

import pytest

from dtvp import dt_cache
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
