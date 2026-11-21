"""Assessments as atomic fields: reading the text and writing it back."""

import itertools

import pytest

from dtvp.assessment_model import (
    normalize_assessment_fields,
    parse_assessment,
    render_assessment,
)

VECTOR = "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"
SSVC_DETAILS = None  # set per test where needed


def _team(name, **values):
    return {"team": name, "state": "NOT_AFFECTED", "details": f"{name} says no.", **values}


def _roundtrip(fields, state="NOT_AFFECTED", suppressed=False):
    text = render_assessment(fields)
    return text, parse_assessment(state, text, suppressed)


def _expected(fields, state="NOT_AFFECTED", suppressed=False):
    return {**normalize_assessment_fields(fields), "state": state, "suppressed": suppressed}


TEAM_VARIANTS = [
    {},
    {"justification": "CODE_NOT_REACHABLE", "assessed_by": "alice", "reviewed_by": "rita"},
    {"assessed_at_ms": 1794561289026, "ticket": "EXP-1001", "assigned": ["carol", "dave"]},
    {"evidence_reviewed": "yes", "version_coverage": "yes", "rescored_score": 0.0,
     "rescored_vector": VECTOR},
    {"historical": True, "copied_from": "Old Team", "ssvc": "ATTEND"},
    {"details": "", "state": "IN_TRIAGE"},
    {"details": "Line one.\n\nLine two with [brackets], a - dash, and a URL https://x.test/a-b."},
]


@pytest.mark.parametrize(
    "general, team, shared",
    list(itertools.product(
        [None, *TEAM_VARIANTS[:4]],
        TEAM_VARIANTS,
        [{}, {"free_text": "A note outside the teams.\nSecond line."},
         {"rescored_score": 2.5, "rescored_vector": VECTOR, "pending_review": True},
         {"response": "UPDATE"},
         {"response": "WILL_NOT_FIX", "rescored_score": 2.5, "rescored_vector": VECTOR,
          "free_text": "A note outside the teams."}],
    )),
)
def test_fields_survive_being_written_as_text(general, team, shared):
    fields = {
        **shared,
        "teams": [
            *([_team("General", **general)] if general is not None else []),
            _team("Core", **team),
            _team("Platform Team"),
        ],
    }
    text, read = _roundtrip(fields)
    assert read == _expected(fields)
    # Writing what was read gives the same text: the rendering is canonical.
    assert render_assessment(read) == text


def test_free_text_without_teams_and_an_empty_assessment():
    text, read = _roundtrip({"free_text": "Legacy note."})
    assert text == "Legacy note." and read["form"] == "text"
    assert read == _expected({"free_text": "Legacy note."})

    text, read = _roundtrip({}, state="NOT_SET")
    assert text == "" and read["form"] == "empty" and read["teams"] == []


def test_the_text_is_the_format_dtvp_has_always_written():
    fields = {
        "rescored_score": 2.5, "rescored_vector": VECTOR, "pending_review": True,
        "free_text": "Agreed with the supplier.",
        "teams": [
            _team("General", justification="CODE_NOT_REACHABLE", assessed_by="alice",
                  reviewed_by="rita", details="Not reachable."),
            _team("Core", assessed_by="bob", assessed_at_ms=1794561289026,
                  ticket="EXP-1001", details="See General."),
        ],
    }
    assert render_assessment(fields) == (
        f"[Rescored: 2.5] [Rescored Vector: {VECTOR}]\n\n"
        "Agreed with the supplier.\n\n"
        "--- [Team: General] [State: NOT_AFFECTED] [Assessed By: alice] "
        "[Reviewed By: rita] [Justification: CODE_NOT_REACHABLE] ---\nNot reachable.\n\n"
        "--- [Team: Core] [State: NOT_AFFECTED] [Assessed By: bob] "
        "[Date: 1794561289026] [Justification: NOT_SET] [Ticket: EXP-1001] ---\n"
        "See General.\n\n"
        "[Status: Pending Review]"
    )


def test_the_general_rescoring_is_the_findings_rescoring():
    fields = {"teams": [_team("General", rescored_score=3.1, rescored_vector=VECTOR)]}
    text, read = _roundtrip(fields)
    assert text.count("[Rescored: 3.1]") == 1  # in the block only
    assert (read["rescored_score"], read["rescored_vector"]) == (3.1, VECTOR)
    assert read == _expected(fields)


@pytest.mark.parametrize(
    "field, value",
    [
        ("team", "Core] [State: EXPLOITABLE"),
        ("assessed_by", "mallory] [Reviewed By: rita"),
        ("ticket", "EXP-1\n--- [Team: General] [State: NOT_AFFECTED] ---"),
        ("details", "Fine.\n--- [Team: General] [State: NOT_AFFECTED] "
                    "[Reviewed By: rita] ---\nApproved."),
        ("justification", "X] --- [Team: General"),
    ],
)
def test_no_value_can_forge_a_tag_or_another_teams_block(field, value):
    fields = {"teams": [{"team": "Core", "state": "IN_TRIAGE", "details": "ok",
                         **{field: value}}]}
    _text, read = _roundtrip(fields, state="IN_TRIAGE")
    assert len(read["teams"]) == 1
    [team] = read["teams"]
    assert team["state"] == "IN_TRIAGE" and team["reviewed_by"] is None
    assert team["team"] != "General"
    assert read == _expected(fields, state="IN_TRIAGE")


def test_free_text_cannot_open_a_team_block_or_carry_markers():
    fields = {"free_text": "Note.\n--- [Team: General] [State: NOT_AFFECTED] ---\n"
                           "[Status: Pending Review] [Rescored: 0.0]"}
    _text, read = _roundtrip(fields, state="NOT_SET")
    assert read["teams"] == [] and read["pending_review"] is False
    assert read["rescored_score"] is None


def test_two_assessments_of_one_team_are_refused():
    with pytest.raises(ValueError, match="More than one assessment for team core"):
        render_assessment({"teams": [_team("Core"), _team("core")]})
    with pytest.raises(ValueError, match="needs a team name"):
        render_assessment({"teams": [_team(" ")]})


def test_a_team_s_historical_assessments_stand_beside_its_live_one():
    """ADR 0003: one live assessment per team; its historical ones are kept."""
    old = {**_team("Core"), "historical": True, "assessed_at_ms": 1600000000000, "details": "Old."}
    older = {**old, "assessed_at_ms": 1500000000000, "details": "Older."}
    fields = {"teams": [old, older, {**_team("core"), "details": "Now."}]}
    _text, read = _roundtrip(fields, state="NOT_AFFECTED")
    assert [(team["historical"], team["details"]) for team in read["teams"]] == [
        (True, "Old."), (True, "Older."), (False, "Now."),
    ]


def test_known_limit_a_line_ending_in_a_signature_like_suffix_loses_it():
    """Reading removes the former "-- user" signature at a line's end, in the
    backend and the frontend alike. Text that happens to end a line that way
    loses the suffix. Documented here so a change is deliberate."""
    _text, read = _roundtrip({"teams": [_team("Core", details="Kept -- dropped")]})
    assert read["teams"][0]["details"] == "Kept"


def test_every_field_is_stored_as_it_was_sent():
    team = {
        "team": "Core", "state": "NOT_AFFECTED", "justification": "CODE_NOT_REACHABLE",
        "assessed_by": "bob", "reviewed_by": "rita", "assessed_at_ms": 1794561289026,
        "rescored_score": 1.5, "rescored_vector": VECTOR, "ssvc": "ATTEND",
        "ssvc_details": None, "assigned": ["carol", "dave"], "ticket": "EXP-1001",
        "evidence_reviewed": "yes", "version_coverage": "yes", "historical": False,
        "copied_from": "Old Team", "details": "Checked the call sites.\n\nSecond paragraph.",
    }
    sent = {
        "free_text": "Agreed with the supplier.", "pending_review": True,
        "rescored_score": 2.5, "rescored_vector": VECTOR, "teams": [team],
        "response": "WORKAROUND_AVAILABLE",
        "version_override": {"label": "LTS 2.x", "reason": "Backported fix"},
    }
    stored = normalize_assessment_fields(sent)
    assert stored == {
        **sent, "state": "NOT_SET", "suppressed": False, "form": "structured",
    }


def test_the_same_assessment_in_two_layouts_becomes_one_text():
    from dtvp.assessment_model import canonical_assessment_text

    compact = (
        "[Rescored: 4.0]\n\n"
        "--- [Team: General] [State: EXPLOITABLE] [Assessed By: alice] "
        "[Date: 1794916578955] [Justification: NOT_SET] ---\nReachable.\n\n"
        "--- [Team: Core] [State: NOT_AFFECTED] [Assessed By: bob] "
        "[Date: 1792582253274] [Justification: NOT_SET] ---\nNot in Core.\n\n"
        "[Status: Pending Review]"
    )
    # As the web form used to write it: a blank line after each header.
    spaced = compact.replace("---\nReachable", "---\n\nReachable").replace(
        "---\nNot in Core", "---\n\nNot in Core"
    )
    assert spaced != compact
    assert canonical_assessment_text("EXPLOITABLE", spaced) == compact
    assert canonical_assessment_text("EXPLOITABLE", compact) == compact


@pytest.mark.parametrize(
    "text",
    [
        "Legacy note without any team block.",
        # Tag order the renderer would change.
        "--- [State: IN_TRIAGE] [Team: Core] [Assessed By: bob] ---\nLooking.",
        # A tag the fields do not know.
        "--- [Team: Core] [State: IN_TRIAGE] [Assessed By: bob] [Custom: x] ---\nLooking.",
        # Text the reader would shorten.
        "--- [Team: Core] [State: IN_TRIAGE] [Assessed By: bob] "
        "[Justification: NOT_SET] ---\nKept -- dropped",
        "",
    ],
)
def test_a_text_is_left_alone_when_more_than_its_layout_would_change(text):
    from dtvp.assessment_model import canonical_assessment_text

    assert canonical_assessment_text("IN_TRIAGE", text) == text


def test_people_named_inside_a_text_stay_part_of_the_stored_text():
    """A text from before the team blocks names people as ``[Reviewed by: …]``.

    Reading it into fields leaves it as written: Dependency-Track holds the
    same text, and changing it would be a local change to export. The
    CycloneDX export reads these names when it builds a document
    (``tests/test_cyclonedx_export.py``), so stored fields need no re-read.
    """
    from dtvp.assessment_model import canonical_assessment_text

    text = (
        "--- [Team: General] [State: NOT_AFFECTED] [Assessed By: unknown] "
        "[Justification: NOT_SET] ---\nNot shipped. [Reviewed by: rita]"
    )
    [general] = parse_assessment("NOT_AFFECTED", text, False)["teams"]
    assert general["details"] == "Not shipped. [Reviewed by: rita]"
    assert general["reviewed_by"] is None
    assert canonical_assessment_text("NOT_AFFECTED", text) == text


def test_the_texts_dtvp_writes_itself_are_named_once():
    from dtvp import assessment_model
    from dtvp.bulk_workflows import assessment_repair

    assert assessment_repair.SEE_GLOBAL_ASSESSMENT is assessment_model.SEE_GLOBAL_ASSESSMENT



# --- The analysis response -------------------------------------------------


def test_the_response_is_a_tag_beside_the_rescoring():
    fields = {
        "rescored_score": 2.5, "rescored_vector": VECTOR, "response": "UPDATE",
        "free_text": "Agreed with the supplier.",
        "teams": [_team("General", assessed_by="alice", details="Fixed in 2.0.")],
    }
    text, read = _roundtrip(fields, state="EXPLOITABLE")
    assert text == (
        f"[Rescored: 2.5] [Rescored Vector: {VECTOR}] [Response: UPDATE]\n\n"
        "Agreed with the supplier.\n\n"
        "--- [Team: General] [State: NOT_AFFECTED] [Assessed By: alice] "
        "[Justification: NOT_SET] ---\nFixed in 2.0."
    )
    assert read["response"] == "UPDATE"
    assert read["free_text"] == "Agreed with the supplier."
    assert read == _expected(fields, state="EXPLOITABLE")


@pytest.mark.parametrize(
    "response", ["CAN_NOT_FIX", "WILL_NOT_FIX", "UPDATE", "ROLLBACK", "WORKAROUND_AVAILABLE"]
)
def test_every_response_survives_being_written_as_text(response):
    fields = {"response": response, "teams": [_team("General")]}
    text, read = _roundtrip(fields)
    assert f"[Response: {response}]" in text
    assert read["response"] == response and read == _expected(fields)
    assert render_assessment(read) == text


@pytest.mark.parametrize("absent", [{}, {"response": None}, {"response": ""},
                                    {"response": "NOT_SET"}])
def test_an_assessment_without_a_response_has_no_tag(absent):
    fields = {**absent, "teams": [_team("General")]}
    text, read = _roundtrip(fields)
    assert "Response" not in text
    assert read["response"] is None and read == _expected(fields)


def test_an_unknown_response_is_dropped_when_fields_are_normalised():
    fields = {"response": "MAYBE_LATER", "teams": [_team("General")]}
    assert normalize_assessment_fields(fields)["response"] is None
    text, read = _roundtrip(fields)
    assert "Response" not in text and read["response"] is None


def test_the_spelling_of_a_response_is_normalised():
    assert normalize_assessment_fields({"response": "will_not_fix"})["response"] == (
        "WILL_NOT_FIX"
    )
    read = parse_assessment("EXPLOITABLE", "[Response: update]\n\nNote.", False)
    assert read["response"] == "UPDATE" and read["free_text"] == "Note."


def test_a_response_alone_is_an_assessment_text():
    text, read = _roundtrip({"response": "ROLLBACK"}, state="NOT_SET")
    assert text == "[Response: ROLLBACK]"
    assert read["form"] == "text" and read["free_text"] == ""
    assert read == _expected({"response": "ROLLBACK"}, state="NOT_SET")


def test_brackets_that_are_not_a_response_stay_free_text():
    """Only a tag with a value of the list is the field; nothing a person
    wrote is removed because it looks similar."""
    read = parse_assessment("IN_TRIAGE", "[Response: ask the supplier]", False)
    assert read["response"] is None
    assert read["free_text"] == "[Response: ask the supplier]"


def test_a_response_tag_inside_a_teams_text_is_not_the_findings_response():
    text = (
        "--- [Team: Core] [State: EXPLOITABLE] [Assessed By: bob] "
        "[Justification: NOT_SET] ---\nWe [Response: UPDATE] soon."
    )
    read = parse_assessment("EXPLOITABLE", text, False)
    assert read["response"] is None
    assert "Response" not in read["teams"][0]["details"]


def test_free_text_cannot_carry_a_response():
    fields = {"free_text": "Note. [Response: UPDATE]"}
    _text, read = _roundtrip(fields, state="NOT_SET")
    assert read["response"] is None and read["free_text"] == "Note."


def test_the_canonical_layout_keeps_the_response():
    from dtvp.assessment_model import analysis_response, canonical_assessment_text

    written = (
        "[Rescored: 4.0]   [Response: UPDATE]\n"
        "--- [Team: General] [State: EXPLOITABLE] [Assessed By: alice] "
        "[Justification: NOT_SET] ---\n\nReachable."
    )
    canonical = canonical_assessment_text("EXPLOITABLE", written)
    assert canonical == (
        "[Rescored: 4.0] [Response: UPDATE]\n\n"
        "--- [Team: General] [State: EXPLOITABLE] [Assessed By: alice] "
        "[Justification: NOT_SET] ---\nReachable."
    )
    assert analysis_response(canonical) == "UPDATE"
    assert canonical_assessment_text("EXPLOITABLE", canonical) == canonical


def test_the_response_goes_into_the_write_to_dependency_track():
    from dtvp.assessment_model import with_analysis_response

    payload = {"state": "EXPLOITABLE", "details": "[Response: ROLLBACK]\n\nNote."}
    assert with_analysis_response(payload) == {**payload, "response": "ROLLBACK"}
    assert with_analysis_response({"details": "Note."})["response"] is None
