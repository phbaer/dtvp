"""SSVC is exact, model-pinned evidence inside ordinary contextual team reviews."""

import pytest

from dtvp.knowledge.filters import KnowledgeFilters
from dtvp.knowledge.ssvc import SsvcInput, action, evaluate, models, workspace_summary
from dtvp.knowledge.workspace import load_workspace
from tests.test_knowledge_assessments import (
    assessment,
    coverage,
    current,
    head,
    review,
    save,
    seed,
    target,
)
from tests.test_knowledge_assessments import journal as source_journal

journal = source_journal


def selection(*, last=False):
    model = models()[0]
    row = model["mapping"][-1 if last else 0]
    return SsvcInput(
        model=model["id"],
        version=model["version"],
        model_sha256=model["sha256"],
        answers={key: value for key, value in row.items() if key != model["outcome"]},
        rationale="Explicit cybersecurity prioritization for this consuming context.",
        evidence=[
            {
                "reference": "pipeline:build-1",
                "description": "Operator-supplied evidence; no external verification claimed.",
            }
        ],
    )


def test_exact_model_answers_and_pins_no_guessed_or_client_outcomes():
    first, last = evaluate(selection()), evaluate(selection(last=True))
    assert first["outcome_label"] == "Defer" and last["outcome_label"] == "Immediate"
    assert first["complete"] and first["selection"]["evidence"]
    for changes in (
        {"model_sha256": "0" * 64},
        {"model": "unknown"},
        {"version": "2"},
        {"answers": {"bad": "X"}},
    ):
        with pytest.raises(ValueError):
            evaluate(selection().model_copy(update=changes))
    incomplete = selection().model_copy(update={"answers": {}})
    assert evaluate(incomplete)["outcome"] is None
    with pytest.raises(ValueError, match="every decision point"):
        evaluate(incomplete, submit=True)
    with pytest.raises(ValueError):
        SsvcInput.model_validate({**selection().model_dump(), "outcome": "Immediate"})


def test_submission_review_pending_ssvc_change_and_retained_approval(journal, capsys):
    seed(journal)
    save(journal, assessment(journal, ssvc=selection()))
    summary = workspace_summary(coverage(journal))
    assert summary["status"] == "submitted" and summary["approved"] is None
    review(journal)
    approved = workspace_summary(coverage(journal))
    assert approved["status"] == "approved" and action(approved) == "DEFER"
    revision = current(journal)["assessments"]["assessment:decision"]["revision"]
    save(
        journal,
        assessment(
            journal, request_id="changed", expected_revision=revision, ssvc=selection(last=True)
        ),
        submit=False,
    )
    pending = workspace_summary(coverage(journal))
    assert pending["status"] == "pending" and pending["pending"]
    assert pending["current"]["outcome_label"] == "Immediate"
    assert pending["approved"]["outcome_label"] == "Defer"
    assert "ssvc" in coverage(journal)["pending_changes"]
    assert action(pending) == "DEFER"
    row = load_workspace(journal, head(journal))["items"][0]
    assert KnowledgeFilters(ssvc_status="pending", ssvc_action="DEFER").matches(row)
    assert not KnowledgeFilters(ssvc_action="IMMEDIATE").matches(row)
    from dtvp.knowledge.client import display_workspace

    display_workspace(load_workspace(journal, head(journal)))
    assert "ssvc=pending current=Immediate approved=Defer" in capsys.readouterr().out


def test_four_versions_scope_remains_explicit_and_ssvc_material_stales(journal):
    versions = ["6.15.6", "7.1.1", "7.1.2", "7.2.0"]
    for version in versions:
        seed(journal, version=version)
    selected = [target(journal, version) for version in versions[:3]]
    save(
        journal,
        assessment(
            journal,
            targets=selected,
            conditions="Same explicit deployment conditions.",
            ssvc=selection(),
        ),
    )
    review(journal, selected)
    assert all(
        workspace_summary(coverage(journal, item))["status"] == "approved" for item in selected
    )
    assert (
        workspace_summary(coverage(journal, target(journal, versions[-1])))["status"] == "missing"
    )
    old = head(journal)
    seed(
        journal,
        parent=old,
        modify=lambda section: section["vulnerabilities"]["claim"]["advisory"].update(
            description="Material upstream change"
        ),
    )
    summary = workspace_summary(coverage(journal))
    assert summary["status"] == "stale" and summary["approved"] is None
    assert action(summary) == ""


def test_optional_ssvc_omitted_preserves_old_operation_fingerprint_and_payload(
    journal, monkeypatch
):
    import dtvp.knowledge.assessments as service

    seed(journal)
    original = service.prepare
    seen = []

    def capture(*args, **kwargs):
        seen.append(args[-1])
        return original(*args, **kwargs)

    monkeypatch.setattr(service, "prepare", capture)
    data = assessment(journal)
    save(journal, data)
    assert "ssvc" not in seen[0]
    assert "ssvc" not in current(journal)["assessments"]["assessment:decision"]["payload"]
    assert save(journal, data)


def test_incomplete_submission_and_team_authorization_do_not_publish(journal):
    seed(journal)
    before = head(journal)
    with pytest.raises(ValueError, match="every decision point"):
        save(journal, assessment(journal, ssvc=selection().model_copy(update={"answers": {}})))
    assert head(journal) == before

    def deny(team, capability):
        raise PermissionError("No team permission")

    with pytest.raises(PermissionError):
        save(journal, assessment(journal, ssvc=selection()), authorize=deny)
    assert head(journal) == before


@pytest.mark.parametrize(
    ("base", "version", "score"),
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "3.1", 9.8),
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", "4.0", 10.0),
    ],
)
def test_only_validated_original_base_vectors_are_offered(journal, base, version, score):

    def rating(section):
        section["vulnerabilities"]["claim"]["advisory"]["ratings"] = [
            {"vector": base, "score": score},
            {"vector": base + "/CR:H", "score": score},
            {"vector": base, "score": 1.0},
            {"vector": "garbage", "score": 10},
        ]

    seed(journal, modify=rating)
    row = load_workspace(journal, head(journal))["items"][0]
    assert len(row["source_ratings"]) == 4
    assert row["original_base_vectors"] == [{"vector": base, "version": version, "score": score}]
