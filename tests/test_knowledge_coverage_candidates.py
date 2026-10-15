"""Parallel-version scope discovery never grants human coverage or identity."""

import pytest

from dtvp.knowledge import coverage_candidates as service
from dtvp.knowledge.assessments import load_sections
from dtvp.knowledge.comparison import reachable_states
from dtvp.knowledge.journal import Journal, Ref, Update
from dtvp.knowledge.ownership import resolve_ownership
from dtvp.knowledge.service import create_tag
from dtvp.storage import digest
from tests.test_knowledge_assessments import (
    assessment,
    current,
    head,
    review,
    save,
    seed,
    target,
)
from tests.test_knowledge_assessments import journal as source_journal
from tests.test_knowledge_synchronization import publish

journal = source_journal
VERSIONS = ("6.15.6", "7.1.1", "7.1.2", "7.2.0")


def parallel(journal):
    for version in VERSIONS:
        seed(journal, version=version)


def candidates(journal, *, source=None, version="7.1.1", **kwargs):
    selected = target(journal, version)
    return service.coverage_candidates(
        journal,
        "project",
        source or head(journal, version),
        selected.context_id,
        selected.vulnerability_id,
        **kwargs,
    )


def update(journal, version, modify, team="A"):
    sections = current(journal, version)
    modify(sections)
    resolve_ownership(
        sections,
        version=version,
        config={"rules": [{"selector": "*", "team_id": team}], "context_roots": {}},
    )
    return publish(journal, sections, version=version)


def test_four_parallel_versions_include_unassessed_source_and_exact_unreviewed_selectors(journal):
    parallel(journal)
    before = journal.head()
    result = candidates(journal)
    assert journal.head() == before
    assert result["format"] == "dtvp.coverage-candidates/1"
    assert result["source"]["coverage"]["status"] == "unassessed"
    assert result["heads"] == {version: head(journal, version) for version in VERSIONS}
    assert result["statistics"] == {
        "versions": 4,
        "rows": 4,
        "assessment_candidates": 4,
        "by_classification": {"matching_material": 4},
        "by_availability": {"present": 4},
        "by_coverage": {"unassessed": 4},
    }
    for row in result["items"]:
        assert row["state"] == result["heads"][row["version"]]
        assert row["selector"] == target(journal, row["version"]).model_dump()
        assert row["comparison"]["identity_equal"] and row["comparison"]["material_equal"]
        assert row["assessment_candidate"] and row["conditions_required"]
        assert row["comparison"]["equivalence"] == "source_local_material_match"
        assert not row["coverage"]["approved"]
        assert row["team_id"] == "A"


def test_source_approval_never_extends_to_other_versions_and_team_changes_remain_separate(journal):
    parallel(journal)
    save(journal, assessment(journal))
    review(journal)
    update(journal, "7.1.2", lambda sections: None, team="B")
    result = candidates(journal)
    rows = {row["version"]: row for row in result["items"]}
    assert rows["7.1.1"]["coverage"]["approved"]
    assert rows["7.1.2"]["coverage"]["status"] == "unassessed"
    assert rows["7.1.2"]["team_id"] == "B"
    assert rows["7.1.2"]["classification"] == "matching_material"
    assert result["statistics"]["by_coverage"] == {"unassessed": 3, "approved": 1}


def test_same_package_family_new_version_is_material_changed_not_dropped_or_approved(journal):
    parallel(journal)

    def changed(sections):
        component = sections["inventory"]["component:lib"]
        component["version"] = "2"
        component["purl"] = "pkg:generic/lib@2"

    update(journal, "7.1.2", changed)
    row = next(row for row in candidates(journal)["items"] if row["version"] == "7.1.2")
    assert row["classification"] == "material_changed"
    assert row["assessment_candidate"] and not row["coverage"]["approved"]
    assert not row["comparison"]["identity_equal"] and not row["comparison"]["material_equal"]
    assert row["comparison"]["lineage_compatible"]
    assert row["comparison"]["equivalence"] == "not_established"


@pytest.mark.parametrize("retain_claim", [True, False])
def test_recycled_component_ref_for_unrelated_package_is_an_identity_conflict(
    journal, retain_claim
):
    parallel(journal)

    def changed(sections):
        sections["inventory"]["component:lib"].update(name="another", purl="pkg:generic/another@1")
        if not retain_claim:
            sections["vulnerabilities"].clear()

    update(journal, "7.1.2", changed)
    row = next(row for row in candidates(journal)["items"] if row["version"] == "7.1.2")
    assert row["classification"] == "identity_conflict"
    assert not row["assessment_candidate"]
    assert "reused_source_component_ref_has_incompatible_identity" in row["reasons"]


def test_missing_refs_are_absent_even_when_identical_names_and_purls_exist(journal):
    parallel(journal)

    def renamed(sections):
        component = sections["inventory"].pop("component:lib")
        component["bom-ref"] = "new-ref"
        sections["inventory"]["component:new-ref"] = component
        sections["inventory"]["dependencies"]["edges"] = [
            {"ref": "app", "dependsOn": ["new-ref"]},
            {"ref": "new-ref", "dependsOn": []},
        ]
        sections["vulnerabilities"]["claim"]["ref"] = "new-ref"

    update(journal, "7.1.2", renamed)
    rows = [row for row in candidates(journal)["items"] if row["version"] == "7.1.2"]
    assert len(rows) == 1
    assert rows[0]["availability"] == "component_absent"
    assert rows[0]["classification"] == "absent" and not rows[0]["assessment_candidate"]
    assert rows[0]["component"] is None


def test_other_consuming_roots_are_distinct_candidates_and_missing_original_context_stays_explicit(
    journal,
):
    parallel(journal)

    def second_root(sections):
        sections["inventory"]["component:other-app"] = {
            "bom-ref": "other-app",
            "name": "other-app",
            "version": "1",
        }
        sections["inventory"]["dependencies"]["edges"].append(
            {"ref": "other-app", "dependsOn": ["lib"]}
        )

    update(journal, "7.1.2", second_root)
    rows = [row for row in candidates(journal)["items"] if row["version"] == "7.1.2"]
    assert len(rows) == 2 and len({row["context_id"] for row in rows}) == 2
    other = next(row for row in rows if row["root_ref"] == "other-app")
    assert other["classification"] == "different_context"
    assert other["assessment_candidate"] and other["conditions_required"]
    assert not other["comparison"]["same_context_references"]
    assert not other["comparison"]["material_equal"]

    def remove_original_usage(sections):
        sections["inventory"]["dependencies"]["edges"][0]["dependsOn"] = []

    update(journal, "7.1.2", remove_original_usage)
    rows = [row for row in candidates(journal)["items"] if row["version"] == "7.1.2"]
    assert len(rows) == 2
    absent = next(row for row in rows if row["root_ref"] == "app")
    assert absent["classification"] == "unresolved" and absent["availability"] == "context_missing"
    assert not absent["assessment_candidate"]


def test_absent_vulnerability_retains_prior_assessment_without_current_coverage(journal):
    parallel(journal)
    selected = target(journal, "7.1.2")
    save(journal, assessment(journal, [selected], request_id="target"))
    review(journal, [selected], request_id="review-target")
    update(journal, "7.1.2", lambda sections: sections["vulnerabilities"].clear())
    row = next(row for row in candidates(journal)["items"] if row["version"] == "7.1.2")
    assert row["availability"] == "finding_absent" and row["classification"] == "absent"
    assert row["coverage"]["status"] == "historically_absent"
    assert row["coverage"]["recorded"] and not row["coverage"]["approved"]
    assert not row["assessment_candidate"]


def test_unresolved_ownership_or_unknown_topology_never_becomes_a_ready_target(journal):
    parallel(journal)

    def uncertain(sections):
        sections["inventory"]["baseline"]["dependency_graph"] = "not_reported"

    update(journal, "7.1.2", uncertain)
    row = next(row for row in candidates(journal)["items"] if row["version"] == "7.1.2")
    assert row["classification"] == "unresolved"
    assert row["context"]["status"] == "topology_unknown"
    assert not row["assessment_candidate"]


def test_weak_local_identity_name_change_is_blocked_but_package_version_change_is_reviewable(
    journal,
):
    parallel(journal)
    for version in VERSIONS:
        update(
            journal, version, lambda sections: sections["inventory"]["component:lib"].pop("purl")
        )
    update(
        journal,
        "7.1.2",
        lambda sections: sections["inventory"]["component:lib"].update(name="different"),
    )
    update(
        journal,
        "7.2.0",
        lambda sections: sections["inventory"]["component:lib"].update(version="2"),
    )
    rows = {row["version"]: row for row in candidates(journal)["items"]}
    assert rows["7.1.2"]["classification"] == "identity_conflict"
    assert not rows["7.1.2"]["assessment_candidate"]
    assert rows["7.2.0"]["classification"] == "material_changed"
    assert rows["7.2.0"]["assessment_candidate"]


def test_digest_and_full_statistics_are_stable_across_bounded_pages(journal):
    parallel(journal)
    first = candidates(journal, limit=1)
    second = candidates(journal, offset=1, limit=2)
    assert first["total"] == second["total"] == 4
    assert first["statistics"] == second["statistics"]
    assert first["heads"] == second["heads"]
    assert first["preview_digest"] == second["preview_digest"]
    assert first["next_offset"] == 1 and second["next_offset"] == 3
    assert first["items"][0]["id"] not in {row["id"] for row in second["items"]}


def test_reference_snapshot_is_read_once_and_later_publication_changes_new_preview_only(
    journal, monkeypatch
):
    parallel(journal)
    source, selected = head(journal), target(journal)
    original = Journal.references
    calls = []

    def references(self):
        refs = original(self)
        calls.append(refs)
        return refs

    monkeypatch.setattr(Journal, "references", references)
    first = service.coverage_candidates(
        journal, "project", source, selected.context_id, selected.vulnerability_id
    )
    assert len(calls) == 1
    update(
        journal,
        "7.2.0",
        lambda sections: sections["history"].update(note={"text": "Later nightly"}),
    )
    second = candidates(journal)
    assert first["heads"]["7.2.0"] != second["heads"]["7.2.0"]
    assert first["preview_digest"] != second["preview_digest"]
    assert first["statistics"] == second["statistics"]


def test_sections_loaded_once_per_head_without_synthesizing_all_other_findings(
    journal, monkeypatch
):
    parallel(journal)
    original = service.load_sections
    calls = []

    def load(journal, state):
        calls.append(state)
        return original(journal, state)

    monkeypatch.setattr(service, "load_sections", load)
    candidates(journal)
    assert len(calls) == len(set(calls)) == 4


def test_historical_tagged_source_is_accepted_but_tags_are_never_candidates_or_moved(journal):
    parallel(journal)
    old = head(journal)
    create_tag(
        journal,
        project_id="project",
        actor_id="release",
        name="released",
        state=old,
        request_id="tag",
    )
    update(
        journal,
        "7.1.1",
        lambda sections: sections["vulnerabilities"]["claim"]["advisory"].update(
            description="New source claim"
        ),
    )
    result = candidates(journal, source=old)
    assert result["source"]["state"] == old
    assert result["heads"]["7.1.1"] != old
    assert result["statistics"]["versions"] == 4
    assert journal.resolve(Ref(kind="tag", project_id="project", name="released")) == old
    assert (
        next(row for row in result["items"] if row["version"] == "7.1.1")["classification"]
        == "material_changed"
    )


def test_unpublished_or_foreign_source_states_are_rejected(journal):
    parallel(journal)
    initial = head(journal)
    foreign = journal.snapshot(
        project_id="another",
        version="7.1.1",
        actor_id="test",
        reason="Unpublished",
        sections=load_sections(journal, initial),
    )
    selected = target(journal)
    with pytest.raises(ValueError, match="one product line"):
        service.coverage_candidates(
            journal, "project", foreign, selected.context_id, selected.vulnerability_id
        )
    unpublished = journal.snapshot(
        project_id="project",
        version="7.1.1",
        actor_id="test",
        reason="Unpublished",
        sections=load_sections(journal, initial),
        parents=[initial],
    )
    with pytest.raises(ValueError, match="committed product state"):
        candidates(journal, source=unpublished)


def test_missing_source_finding_and_bad_page_bounds_are_rejected(journal):
    parallel(journal)
    selected = target(journal)
    with pytest.raises(ValueError, match="absent"):
        service.coverage_candidates(
            journal, "project", head(journal), selected.context_id, "CVE-unknown"
        )
    with pytest.raises(ValueError, match="bounds"):
        candidates(journal, limit=0)
    with pytest.raises(ValueError, match="bounds"):
        candidates(journal, offset=-1)


def test_reachable_states_accepts_explicit_empty_reference_snapshot(journal):
    seed(journal)
    assert reachable_states(journal, "project", references={}) == {}


def test_publication_during_read_cannot_mix_current_branch_heads(journal, monkeypatch):
    parallel(journal)
    source, selected = head(journal), target(journal)
    before = head(journal, "7.2.0")
    new_state = journal.snapshot(
        project_id="project",
        version="7.2.0",
        actor_id="pipeline",
        reason="Concurrent nightly",
        sections=current(journal, "7.2.0"),
        parents=[before],
    )
    original = Journal.references
    reads = []

    def references(self):
        refs = original(self)
        reads.append(refs)
        if len(reads) == 1:
            self.publish(
                request_id="concurrent-nightly",
                fingerprint=digest(new_state.encode()),
                updates=[
                    Update(
                        ref=Ref(project_id="project", name="7.2.0"),
                        expected=before,
                        target=new_state,
                    )
                ],
            )
        return refs

    monkeypatch.setattr(Journal, "references", references)
    result = service.coverage_candidates(
        journal, "project", source, selected.context_id, selected.vulnerability_id
    )
    assert len(reads) == 1
    assert result["heads"]["7.2.0"] == before
    row = next(row for row in result["items"] if row["version"] == "7.2.0")
    assert row["state"] == before
    assert head(journal, "7.2.0") == new_state


def test_branching_after_source_approval_does_not_approve_the_new_patch(journal):
    parallel(journal)
    save(journal, assessment(journal))
    review(journal)
    approved = head(journal)
    new_state = journal.snapshot(
        project_id="project",
        version="7.1.3",
        actor_id="pipeline",
        reason="Patch branch",
        sections=load_sections(journal, approved),
        parents=[approved],
    )
    journal.publish(
        request_id="new-patch",
        fingerprint=digest(new_state.encode()),
        updates=[
            Update(ref=Ref(project_id="project", name="7.1.3"), expected=None, target=new_state)
        ],
    )
    row = next(row for row in candidates(journal)["items"] if row["version"] == "7.1.3")
    assert row["classification"] == "matching_material"
    assert row["assessment_candidate"] and not row["coverage"]["approved"]
    assert row["coverage"]["status"] == "unassessed"


def test_compact_rows_keep_pending_and_approved_revision_pins_independent(journal):
    parallel(journal)
    save(journal, assessment(journal))
    review(journal)
    approved = current(journal)["assessments"]["assessment:decision"]["revision"]
    save(
        journal,
        assessment(
            journal,
            request_id="pending-change",
            expected_revision=approved,
            rationale="Pending changed explanation",
            evidence=[{"source": "large source artifact", "artifact_sha256": "f" * 64}],
        ),
        submit=False,
    )
    result = candidates(journal)
    row = next(row for row in result["items"] if row["version"] == "7.1.1")
    coverage = row["coverage"]
    assert row["coverage_detail"] == "summary"
    assert coverage["status"] == "approved" and coverage["pending_revision"]
    assert coverage["assessment"]["revision"] != coverage["approved_assessment"]["revision"]
    assert coverage["approved_assessment"]["revision"] == approved
    assert coverage["review"]["assessment_revision"] == approved
    assert "assessment" not in coverage["review"]
    for key in ("assessment", "approved_assessment"):
        assert "targets" not in coverage[key]["payload"]
        assert "evidence" not in coverage[key]["payload"]
    assert result["source"]["coverage"]["assessment"]["payload"]["evidence"]
    assert result["source"]["coverage"]["assessment"]["payload"]["targets"]


def test_current_source_does_not_scan_all_historical_revisions(journal, monkeypatch):
    parallel(journal)

    def historical_scan(*args, **kwargs):
        pytest.fail("A current branch pin already establishes committed reachability")

    monkeypatch.setattr(service, "reachable_states", historical_scan)
    assert candidates(journal)["total"] == 4
