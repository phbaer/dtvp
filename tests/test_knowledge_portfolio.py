"""Corporate workload units, shared decisions and current scoring stay distinct."""

from uuid import uuid4

import pytest

from dtvp.knowledge.filters import KnowledgeFilters
from dtvp.knowledge.issued_exports import issue_export
from dtvp.knowledge.journal import Journal, Ref, Update
from dtvp.knowledge.portfolio import load_portfolio
from dtvp.knowledge.scoring import review_gate, score_key
from dtvp.knowledge.workspace import load_sections
from dtvp.storage import digest
from tests.test_knowledge_assessments import (
    assessment,
    current,
    head,
    review,
    save,
    seed,
    target,
)  # noqa: F401


@pytest.fixture
def journal(tmp_path):
    return Journal(tmp_path / "journal")


def update(journal, version, mutate):
    parent = head(journal, version)
    sections = load_sections(journal, parent)
    mutate(sections)
    state = journal.snapshot(
        project_id="project",
        version=version,
        actor_id="fixture",
        reason="Update",
        sections=sections,
        parents=[parent],
        artifacts=journal.state(parent).artifacts,
    )
    journal.publish(
        request_id=str(uuid4()),
        fingerprint=digest(state.encode()),
        updates=[
            Update(ref=Ref(project_id="project", name=version), expected=parent, target=state)
        ],
    )
    return state


def test_shared_multiversion_decision_counts_once_but_each_target_remains_work(journal):  # noqa: F811
    seed(journal)
    seed(journal, "7.1.2")
    selected = [target(journal), target(journal, "7.1.2")]
    save(journal, assessment(journal, selected))
    result = load_portfolio(journal, "project")
    stats = result["statistics"]
    assert stats["context_findings"] == 2 and stats["unique_vulnerabilities"] == 1
    assert stats["unique_latest_logical_assessments"] == 1
    assert stats["unique_latest_assessment_revisions"] == 1
    assert stats["submitted_targets"] == 2 and stats["reviewed_covered_targets"] == 0
    assert stats["required_context_review_workload"]["remaining_targets"] == 2
    review(journal, selected)
    approved = load_portfolio(journal, "project")["statistics"]
    assert approved["unique_approved_logical_assessments"] == 1
    assert approved["unique_approved_assessment_revisions"] == 1
    assert approved["reviewed_covered_targets"] == 2
    assert approved["required_context_review_workload"]["remaining_targets"] == 0


def test_pending_shared_extension_keeps_old_approved_pin_and_new_target_unreviewed(journal):  # noqa: F811
    seed(journal)
    seed(journal, "7.1.2")
    first, second = target(journal), target(journal, "7.1.2")
    save(journal, assessment(journal, [first]))
    review(journal, [first])
    revision = current(journal)["assessments"]["assessment:decision"]["revision"]
    save(
        journal,
        assessment(
            journal,
            [first, second],
            request_id="extend",
            expected_revision=revision,
            rationale="Changed pending reasoning",
        ),
        submit=False,
    )
    stats = load_portfolio(journal, "project")["statistics"]
    assert (
        stats["unique_latest_logical_assessments"]
        == stats["unique_approved_logical_assessments"]
        == 1
    )
    assert stats["by_status"] == {"approved": 1, "draft": 1}
    assert stats["pending_revision_targets"] == stats["reviewed_covered_targets"] == 1
    assert stats["required_context_review_workload"]["remaining_targets"] == 1


def test_full_filtered_counts_and_same_workspace_filter_semantics(journal):  # noqa: F811
    seed(journal)
    seed(journal, "7.1.2", team="B")
    result = load_portfolio(
        journal,
        "project",
        team_id="B",
        q="CVE-2026",
        lifecycle="unassessed",
        filters=KnowledgeFilters(source_severity="unknown", provider="supplier"),
    )
    assert result["statistics"]["context_findings"] == 1
    assert result["by_version"]["7.1.1"]["context_findings"] == 0
    assert result["by_version"]["7.1.2"]["context_findings"] == 1
    assert result["by_team"].keys() == {"B"}
    assert (
        load_portfolio(journal, "project", q="does not exist")["statistics"]["context_findings"]
        == 0
    )
    assert result["state_evidence"]["7.1.1"]["scope"] == "state_unfiltered"


def test_source_and_current_published_severity_never_mix_with_outdated_scores(journal):  # noqa: F811
    seed(journal)
    seed(journal, "7.1.2")
    selected = [target(journal), target(journal, "7.1.2")]
    save(journal, assessment(journal, selected))
    review(journal, selected)

    def score(sections, selected, current):
        gate = review_gate(journal, sections, selected.version, selected.vulnerability_id)
        sections["scoring"][score_key(selected.context_id, selected.vulnerability_id)] = {
            "target": selected.model_dump(),
            "proposal": {"score": 0, "base_score": 9.8},
            "rationale": "coordinator score",
            "actor_id": "coordinator",
            "coverage_digest": gate["digest"] if current else "f" * 64,
        }

    update(journal, "7.1.1", lambda sections: score(sections, selected[0], True))
    update(journal, "7.1.2", lambda sections: score(sections, selected[1], False))
    stats = load_portfolio(journal, "project")["statistics"]
    assert stats["source_severity"] == {"unknown": 2}
    assert stats["current_published_severity"] == {"none": 1, "unknown": 1}
    assert stats["scoring_status"] == {"outdated": 1, "published": 1}
    filtered = load_portfolio(
        journal, "project", filters=KnowledgeFilters(contextual_severity="none")
    )
    assert filtered["statistics"]["context_findings"] == 1


def test_heads_are_one_snapshot_export_bookkeeping_does_not_change_digest(journal, monkeypatch):  # noqa: F811
    seed(journal)
    before = load_portfolio(journal, "project")
    issue_export(
        journal,
        project_id="project",
        actor_id="issuer",
        state=head(journal),
        kind="knowledge-bundle",
    )
    assert load_portfolio(journal, "project")["heads_digest"] == before["heads_digest"]
    seed(journal, "7.1.2")
    assert load_portfolio(journal, "project")["heads_digest"] != before["heads_digest"]
    native = type(journal).references
    captured = []

    def snapshot(self):
        captured.append(True)
        return native(self)

    monkeypatch.setattr(type(journal), "references", snapshot)
    result = load_portfolio(journal, "project", versions=["7.1.1"])
    assert len(captured) == 1
    assert result["heads"] == {"7.1.1": head(journal)}
    with pytest.raises(ValueError, match="Unknown requested"):
        load_portfolio(journal, "project", versions=["missing"])


def test_unknown_coverage_withdrawn_baseline_and_uncontextualized_findings_are_visible(journal):  # noqa: F811
    seed(journal)

    def unknown(sections):
        sections["inventory"]["baseline"]["withdrawn"] = True
        sections["ownership"] = {}

    update(journal, "7.1.1", unknown)
    result = load_portfolio(journal, "project", q="no match")
    assert result["statistics"]["context_findings"] == 0
    evidence = result["state_evidence"]["7.1.1"]
    assert evidence["baseline_status"] == "withdrawn"
    assert evidence["collection_coverage"] == {
        "package_coverage": "unknown",
        "dependency_coverage": "unknown",
        "license_coverage": "unknown",
    }
    assert evidence["uncontextualized_source_findings"] == 1
    assert evidence["coverage_verification"] == "not_verified"


def test_unresolved_contexts_are_required_but_not_assessable_work(journal):  # noqa: F811
    seed(journal)

    def unresolved(sections):
        for key, context in sections["ownership"].items():
            if key.startswith("context:"):
                context.update(status="conflict", team_id=None, candidate_teams=["A", "B"])

    update(journal, "7.1.1", unresolved)
    result = load_portfolio(journal, "project")
    work = result["statistics"]["required_context_review_workload"]
    assert work == {
        "required_targets": 1,
        "approved_targets": 0,
        "remaining_targets": 1,
        "unresolved_targets": 1,
        "not_assessable_targets": 1,
    }
    assert (
        result["by_team"]["A"]["context_findings"]
        == result["by_team"]["B"]["context_findings"]
        == 1
    )
    assert result["statistics"]["context_findings"] == 1 and result["team_counts_overlap"]


def test_empty_product_and_explicit_empty_selection_do_not_claim_cleanliness(journal):  # noqa: F811
    result = load_portfolio(journal, "project")
    assert result["heads"] == {} and result["statistics"]["context_findings"] == 0
    assert result["limitations"]
    seed(journal)
    assert load_portfolio(journal, "project", versions=[])["heads"] == {}


def test_separate_consuming_roots_count_context_work_not_unique_vulnerabilities(tmp_path):
    from tests.test_knowledge_workspace import workspace

    local, sections = workspace.__wrapped__(tmp_path)
    state = local.snapshot(
        project_id="product",
        version="1",
        actor_id="fixture",
        reason="Two consuming trees",
        sections=sections,
    )
    local.publish(
        request_id="rooted",
        fingerprint=digest(state.encode()),
        updates=[Update(ref=Ref(project_id="product", name="1"), expected=None, target=state)],
    )
    stats = load_portfolio(local, "product")["statistics"]
    assert stats["context_findings"] == 3 and stats["unique_vulnerabilities"] == 2
    assert stats["required_context_review_workload"]["required_targets"] == 3
    assert stats["source_severity"] == {"critical": 2, "medium": 1}


def test_tags_source_and_configuration_refs_are_not_additional_versions(journal):
    state = seed(journal)
    refs = [
        Ref(project_id="project", kind=kind, name=name)
        for kind, name in (
            ("tag", "released"),
            ("source", "constituent"),
            ("policy", "teams"),
        )
    ]
    journal.publish(
        request_id="other-refs",
        fingerprint=digest(b"other-refs"),
        updates=[Update(ref=ref, expected=None, target=state) for ref in refs],
    )
    result = load_portfolio(journal, "project")
    assert result["heads"] == {"7.1.1": state}
    with pytest.raises(ValueError, match="Unknown requested"):
        load_portfolio(journal, "project", versions=["released"])
    before = journal.head()
    assert load_portfolio(journal, "project") == result
    assert journal.head() == before


def test_missing_material_target_is_not_assessable_even_if_ownership_claim_resolved(journal):
    seed(journal)
    update(journal, "7.1.1", lambda sections: sections["inventory"].pop("component:lib"))
    work = load_portfolio(journal, "project")["statistics"]["required_context_review_workload"]
    assert work["required_targets"] == 1 and work["not_assessable_targets"] == 1
    assert work["unresolved_targets"] == 0
