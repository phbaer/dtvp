"""Rules use approved applicability, immutable policy provenance and atomic CAS."""

import copy

import pytest

from dtvp.knowledge.journal import Conflict, Journal
from dtvp.knowledge.rule_scoring import (
    PolicyInput,
    RuleInput,
    RulePublication,
    configure_policy,
    current_policy,
    prepare_rule_score,
    publish_rule_score,
)
from dtvp.knowledge.scoring import score_key
from tests.test_knowledge_assessments import assessment, current, head, review, save, seed, target

BASE = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


@pytest.fixture
def journal(tmp_path):
    return Journal(tmp_path / "journal")


def setup(journal, *, state="not_affected", approve=True):
    def add_rating(sections):
        sections["vulnerabilities"]["claim"]["advisory"]["ratings"] = [
            {"vector": BASE, "score": 9.8}
        ]

    seed(journal, modify=add_rating)
    save(
        journal,
        assessment(
            journal,
            state=state,
            justification="code_not_reachable" if state == "not_affected" else None,
        ),
    )
    if approve:
        review(journal)
    return RuleInput(
        request_id="rule-score",
        expected_policy=None,
        expected_versions={"7.1.1": head(journal)},
        targets=[target(journal)],
        base_vector=BASE,
        vector=BASE,
        rationale="Approved deployment conditions",
    )


def test_rule_publication_archives_policy_and_exact_replay_survives_policy_changes(journal):
    data = setup(journal)
    preview, _, _ = prepare_rule_score(journal, project_id="project", data=data)
    assert preview["eligible"]
    assert preview["proposal"]["base_vector"] == BASE
    assert preview["proposal"]["score"] == 0
    publication = RulePublication(**data.model_dump(), preview=preview["preview"])
    receipt = publish_rule_score(
        journal, project_id="project", actor_id="coordinator", data=publication
    )
    record = current(journal)["scoring"][
        score_key(data.targets[0].context_id, data.targets[0].vulnerability_id)
    ]
    assert record["provenance"] == preview["provenance"]
    configured = current_policy(journal, "project")
    change = PolicyInput(request_id="configure", expected_policy=None, config=configured["config"])
    configure_policy(journal, project_id="project", actor_id="manager", data=change)
    assert (
        publish_rule_score(journal, project_id="project", actor_id="coordinator", data=publication)
        == receipt
    )
    assert record["provenance"]["policy_state"] is None
    assert configure_policy(journal, project_id="project", actor_id="manager", data=change)
    with pytest.raises(Conflict):
        configure_policy(
            journal,
            project_id="project",
            actor_id="manager",
            data=PolicyInput(**{**change.model_dump(), "request_id": "stale"}),
        )


def test_unapproved_target_and_false_positive_for_affected_are_rejected(journal):
    data = setup(journal, state="affected", approve=False)
    with pytest.raises(Conflict, match="approved"):
        prepare_rule_score(journal, project_id="project", data=data)
    review(journal)
    data = data.model_copy(
        update={"expected_versions": {"7.1.1": head(journal)}, "rule_basis": "false_positive"}
    )
    with pytest.raises(ValueError, match="not-affected"):
        prepare_rule_score(journal, project_id="project", data=data)


def test_policy_change_between_preview_and_publication_is_rejected(journal):
    data = setup(journal)
    preview, _, _ = prepare_rule_score(journal, project_id="project", data=data)
    configured = current_policy(journal, "project")
    configure_policy(
        journal,
        project_id="project",
        actor_id="manager",
        data=PolicyInput(request_id="configure", expected_policy=None, config=configured["config"]),
    )
    with pytest.raises(Conflict, match="policy changed"):
        publish_rule_score(
            journal,
            project_id="project",
            actor_id="coordinator",
            data=RulePublication(**data.model_dump(), preview=preview["preview"]),
        )


def test_policy_check_is_atomic_with_branch_publication(journal, monkeypatch):
    data = setup(journal)
    preview, _, _ = prepare_rule_score(journal, project_id="project", data=data)
    original = journal.publish
    before = head(journal)

    def race(**kwargs):
        if kwargs.get("checks"):
            monkeypatch.setattr(journal, "publish", original)
            configure_policy(
                journal,
                project_id="project",
                actor_id="manager",
                data=PolicyInput(
                    request_id="race",
                    expected_policy=None,
                    config=current_policy(journal, "project")["config"],
                ),
            )
        return original(**kwargs)

    monkeypatch.setattr(journal, "publish", race)
    with pytest.raises(Conflict, match="policy changed"):
        publish_rule_score(
            journal,
            project_id="project",
            actor_id="coordinator",
            data=RulePublication(**data.model_dump(), preview=preview["preview"]),
        )
    assert head(journal) == before


@pytest.mark.parametrize(
    "mutate",
    [
        lambda c: c.update(metric_rules=[]),
        lambda c: c["metric_rules"]["3.1"].update(base_metrics=[{}]),
        lambda c: c["transitions"][0].update(trigger=123),
    ],
)
def test_malformed_rule_configuration_is_rejected_without_publication(journal, mutate):
    config = copy.deepcopy(current_policy(journal, "project")["config"])
    mutate(config)
    with pytest.raises(ValueError):
        configure_policy(
            journal,
            project_id="project",
            actor_id="manager",
            data=PolicyInput(request_id="invalid", expected_policy=None, config=config),
        )
    assert journal.head() is None


@pytest.mark.parametrize(
    "base",
    [
        BASE.replace("3.1", "3.0"),
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    ],
)
def test_native_rules_support_cvss_versions_without_changing_base(journal, base):
    from dtvp.rescoring import base_fact

    def rating(sections):
        sections["vulnerabilities"]["claim"]["advisory"]["ratings"] = [base_fact(base)]

    seed(journal, modify=rating)
    save(journal, assessment(journal))
    review(journal)
    data = RuleInput(
        request_id="version-score",
        expected_policy=None,
        expected_versions={"7.1.1": head(journal)},
        targets=[target(journal)],
        base_vector=base,
        vector=base,
        rationale="Reviewed deployment",
    )
    preview, _, _ = prepare_rule_score(journal, project_id="project", data=data)
    assert preview["proposal"]["base_vector"] == base
    assert preview["proposal"]["score"] == 0


def test_false_positive_choice_is_explicit_and_bound_to_receipt(journal):
    data = setup(journal).model_copy(update={"rule_basis": "false_positive"})
    preview, _, _ = prepare_rule_score(journal, project_id="project", data=data)
    assert preview["provenance"]["trigger"] == "FALSE_POSITIVE"
    publication = RulePublication(**data.model_dump(), preview=preview["preview"])
    publish_rule_score(journal, project_id="project", actor_id="coordinator", data=publication)
    with pytest.raises(Conflict):
        publish_rule_score(
            journal,
            project_id="project",
            actor_id="coordinator",
            data=publication.model_copy(update={"rule_basis": "applicability"}),
        )


def test_conflicting_approved_applicability_cannot_share_rule_publication(journal):
    first = setup(journal)

    def rating(sections):
        sections["vulnerabilities"]["claim"]["advisory"]["ratings"] = [
            {"vector": BASE, "score": 9.8}
        ]

    seed(journal, "7.1.2", modify=rating)
    selected = target(journal, "7.1.2")
    save(
        journal,
        assessment(
            journal,
            targets=[selected],
            request_id="second-assessment",
            expected_revision=current(journal)["assessments"]["assessment:decision"]["revision"],
            state="affected",
            justification=None,
        ),
    )
    review(journal, [selected], request_id="second-review")
    data = first.model_copy(
        update={
            "expected_versions": {"7.1.1": head(journal), "7.1.2": head(journal, "7.1.2")},
            "targets": [*first.targets, selected],
        }
    )
    with pytest.raises(ValueError, match="compatible"):
        prepare_rule_score(journal, project_id="project", data=data)
