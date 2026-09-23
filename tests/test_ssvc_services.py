from copy import deepcopy
from itertools import product
from types import SimpleNamespace
import json
from urllib.parse import quote

import pytest

from dtvp.assessment_services import build_assessment_payloads
from dtvp.general_api_routes import AssessmentRequest
from dtvp.logic import calculate_aggregated_state, process_assessment_details
from dtvp.ssvc_services import (
    SsvcInput, evaluate, get_models, new_record, preserve_record, read_record,
    summarize_group, validate_model, write_record, DETAILS,
)


def selection(**changes):
    return SsvcInput.model_validate({
        "model": "ssvc:DT_DP", "version": "1.0.0", "rationale": "Deployment context",
        "answers": {"ssvc:E:1.1.0": "A", "ssvc:EXP:1.0.1": "O", "ssvc:A:2.0.0": "Y", "ssvc:HI:2.0.2": "VH"},
        **changes,
    })


def test_all_72_official_deployer_decisions():
    # Independent flattened fixture in E / EXP / A / HI order from upstream 1.0.0.
    expected = "DDSSDSSSDSSSSSSSDSSSSSSODSSSSSSSDSSSSSSOSSSOSSOOSSOOSOOOSSOOOOOOSOOIOOII"
    keys = ["ssvc:E:1.1.0", "ssvc:EXP:1.0.1", "ssvc:A:2.0.0", "ssvc:HI:2.0.2"]
    actual = "".join(evaluate(selection(answers=dict(zip(keys, values)))) for values in product(
        ["N", "P", "A"], ["S", "C", "O"], ["N", "Y"], ["L", "M", "H", "VH"],
    ))
    assert len(actual) == 72
    assert actual == expected


def test_partial_and_invalid_answers():
    assert evaluate(selection(answers={})) is None
    assert evaluate(selection(answers={"ssvc:E:1.1.0": "A"})) is None
    for changes in ({"version": "99"}, {"model": "other"}, {"answers": {"bad": "N"}}, {"answers": {"ssvc:E:1.1.0": "bad"}}):
        with pytest.raises(ValueError):
            evaluate(selection(**changes))


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "bad_value"])
def test_invalid_resource_tables_rejected(mutation):
    model = deepcopy(get_models()[0])
    if mutation == "missing":
        model["mapping"].pop()
    elif mutation == "duplicate":
        model["mapping"].append(model["mapping"][0])
    else:
        model["mapping"][0][model["outcome"]] = "invalid"
    with pytest.raises(ValueError):
        validate_model(model)


def test_metadata_roundtrip_clear_and_preservation():
    details = "--- [Team: General] [State: NOT_SET] [Assessed By: alice] ---\n\nRationale\n\n--- [Team: Team A] [State: IN_TRIAGE] ---\n\nTeam details"
    record = new_record(selection(rationale="Brackets ] [ — café\n---"), "alice")
    saved = write_record(details, record)
    assert "[SSVC: IMMEDIATE]" in saved
    assert "%7B" not in saved
    assert json.loads(DETAILS.search(saved)[1]) == record
    assert read_record(saved) == record
    assert write_record(saved, None) == details
    assert read_record(preserve_record("New assessment", saved)) == record
    assert read_record(preserve_record(saved, "No previous SSVC")) is None
    historical = {**record, "version": "99"}
    assert "99" in preserve_record("", write_record("", historical))


def test_legacy_records_migrate_only_when_written_and_keep_historical_data():
    record = new_record(selection(), "alice")
    encoded = quote(json.dumps(record), safe="").replace("-", "%2D")
    legacy = f"--- [Team: General] [State: NOT_SET] [SSVC: {encoded}] ---\n\nNotes"
    assert read_record(legacy) == record
    migrated = preserve_record(legacy, legacy)
    assert "[SSVC: IMMEDIATE]" in migrated
    assert read_record(migrated) == record
    assert preserve_record(migrated, migrated) == migrated
    unsupported = legacy.replace("1.0.0", "99")
    assert encoded.replace("1.0.0", "99") in preserve_record("New notes", unsupported)


def test_plain_json_survives_delimiters_unicode_and_team_edits():
    rationale = 'Café ] [ 50% \\ path\n--- [Team: Injected] [State: EXPLOITABLE] ---\n[Status: Pending Review]\n[/SSVC Details]\nAssessed --alice'
    record = new_record(selection(rationale=rationale), "alice")
    saved = write_record("--- [Team: General] [State: NOT_AFFECTED] ---\n\nOriginal notes", record)
    assert "[Team: Injected]" not in saved
    assert "[Status: Pending Review]" not in saved
    assert read_record(saved) == record
    assert calculate_aggregated_state(saved) == "NOT_AFFECTED"
    edited, state = process_assessment_details("Team notes", "bob", "REVIEWER", team="Security", state="IN_TRIAGE", existing_details=saved)
    assert read_record(edited) == record
    assert state == "NOT_AFFECTED"
    cleared = write_record(edited, None)
    assert "SSVC" not in cleared
    assert "Team notes" in cleared
    assert "Original notes" in cleared


@pytest.mark.parametrize("mutation", ["mismatch", "missing_json", "missing_tag", "duplicate_json", "bad_json", "wrong_team"])
def test_atomic_outcome_requires_matching_general_json(mutation):
    saved = write_record("", new_record(selection(), "alice"))
    if mutation == "mismatch":
        saved = saved.replace("[SSVC: IMMEDIATE]", "[SSVC: DEFER]")
    elif mutation == "missing_json":
        saved = DETAILS.sub("", saved)
    elif mutation == "missing_tag":
        saved = saved.replace("[SSVC: IMMEDIATE]", "")
    elif mutation == "duplicate_json":
        saved += DETAILS.search(saved)[0]
    elif mutation == "bad_json":
        saved = DETAILS.sub("\n\n[SSVC Details]\nbad\n[/SSVC Details]", saved)
    else:
        block = DETAILS.search(saved)[0]
        saved = DETAILS.sub("", saved) + "\n\n--- [Team: Security] [State: NOT_SET] ---" + block
    with pytest.raises(ValueError):
        read_record(saved)
    assert summarize_group(group(saved))["status"] == "INVALID"


def test_incomplete_outcome_is_explicit_and_invalid_new_records_are_preserved():
    saved = write_record("", new_record(selection(answers={}), "alice"))
    assert "[SSVC: INCOMPLETE]" in saved
    assert read_record(saved)["outcome"] is None
    invalid = saved.replace('"version": "1.0.0"', '"version": "99"')
    preserved = preserve_record("New notes", invalid)
    assert '"version": "99"' in preserved
    assert summarize_group(group(preserved))["status"] == "INVALID"


def group(*texts):
    return {"affected_versions": [{"components": [{"analysis_details": text} for text in texts]}]}


def test_group_summary_does_not_hide_mixed_or_missing_assessments():
    record = new_record(selection(), "alice")
    saved = write_record("", record)
    assert summarize_group(group(saved, saved))["status"] == "IMMEDIATE"
    assert summarize_group(group("", ""))["status"] == "UNASSESSED"
    assert summarize_group(group(saved, ""))["status"] == "INCOMPLETE"
    assert summarize_group(group(write_record("", new_record(selection(answers={}), "alice"))))["status"] == "INCOMPLETE"
    different = write_record("", new_record(selection(rationale="Other context"), "bob"))
    assert summarize_group(group(saved, different))["status"] == "MIXED"
    forged = write_record("", {**record, "outcome": "D"})
    assert summarize_group(group(forged))["status"] == "INVALID"
    assert summarize_group(group(write_record("", {**record, "version": "99"})))["status"] == "INVALID"


def test_assessment_writes_explicitly_change_or_preserve_each_findings_ssvc():
    deps = SimpleNamespace(calculate_aggregated_state=calculate_aggregated_state, process_assessment_details=process_assessment_details)
    saved = write_record("", new_record(selection(), "alice"))
    instances = [{"finding_uuid": "f1", "project_uuid": "p", "component_uuid": "c", "vulnerability_uuid": "v", "analysis_details": saved}]
    req = AssessmentRequest(instances=instances, state="IN_TRIAGE", details="Team update", team="Team A")
    result = build_assessment_payloads(deps, req, "analyst", "ANALYST")[0][1]
    assert read_record(result["details"]) == read_record(saved)
    for role, team in [("ANALYST", None), ("REVIEWER", "Team A")]:
        with pytest.raises(ValueError):
            build_assessment_payloads(deps, req.model_copy(update={"ssvc": selection(), "team": team}), "user", role)
    cleared = req.model_copy(update={"ssvc": None, "team": None})
    assert read_record(build_assessment_payloads(deps, cleared, "reviewer", "REVIEWER")[0][1]["details"]) is None
    changed = cleared.model_copy(update={"ssvc": selection()})
    record = read_record(build_assessment_payloads(deps, changed, "reviewer", "REVIEWER")[0][1]["details"])
    assert record["assessor"] == "reviewer"
    assert record["outcome"] == "I"
