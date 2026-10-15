"""Explicit coverage survives bookkeeping, but never changed evidence or scope."""

import copy

import pytest
from pydantic import ValidationError

from dtvp.knowledge.assessments import (
    AssessmentInput,
    ReviewInput,
    Target,
    coverage_status,
    create_review,
    load_sections,
    save_assessment,
    target_fingerprint,
)
from dtvp.knowledge.journal import SECTIONS, Conflict, Journal, Ref, Update
from dtvp.knowledge.ownership import resolve_ownership
from dtvp.storage import digest


@pytest.fixture
def journal(tmp_path):
    return Journal(tmp_path / "journal")


def seed(journal, version="7.1.1", *, parent=None, team="A", modify=None):
    sections = load_sections(journal, parent) if parent else {name: {} for name in SECTIONS}
    if not parent:
        sections["inventory"] = {
            "baseline": {
                "dependency_graph": "reported",
                "source": "pipeline",
                "build_number": 1,
                "collection": {"pipeline_run": "1", "target": "linux"},
            },
            "root": {"bom-ref": "app", "name": "app", "version": "1"},
            "component:lib": {
                "bom-ref": "lib",
                "name": "lib",
                "version": "1",
                "purl": "pkg:generic/lib@1",
                "dtvp_origin": {"state": "old", "ref": "lib"},
            },
            "dependencies": {
                "edges": [{"ref": "app", "dependsOn": ["lib"]}, {"ref": "lib", "dependsOn": []}]
            },
            "relationships": {"items": []},
        }
        sections["vulnerabilities"] = {
            "claim": {
                "identifier": "CVE-2026-0001",
                "ref": "lib",
                "source": "supplier",
                "advisory": {"description": "A defect"},
            }
        }
    if modify:
        modify(sections)
    resolve_ownership(
        sections,
        version=version,
        config={"rules": [{"selector": "*", "team_id": team}], "context_roots": {}},
    )
    state = journal.snapshot(
        project_id="project",
        version=version,
        actor_id="pipeline",
        reason="Fixture",
        sections=sections,
        parents=[parent] if parent else [],
    )
    journal.publish(
        request_id="seed-" + state,
        fingerprint=digest(state.encode()),
        updates=[
            Update(ref=Ref(project_id="project", name=version), expected=parent, target=state)
        ],
    )
    return state


def target(journal, version="7.1.1"):
    sections = current(journal, version)
    context = next(
        value
        for key, value in sections["ownership"].items()
        if key.startswith("context:") and value["component_ref"] == "lib"
    )
    return Target(version=version, context_id=context["id"], vulnerability_id="CVE-2026-0001")


def current(journal, version="7.1.1"):
    return load_sections(journal, head(journal, version))


def head(journal, version="7.1.1"):
    return journal.resolve(Ref(project_id="project", name=version))


def allow(team, capability):
    assert team in {"A", "B"}
    assert capability in {"assess", "approve"}


def assessment(journal, targets=None, **changes):
    selected = targets or [target(journal)]
    return AssessmentInput(
        **(
            {
                "request_id": "assessment",
                "expected_versions": {t.version: head(journal, t.version) for t in selected},
                "expected_revision": None,
                "targets": selected,
                "state": "not_affected",
                "justification": "code_not_reachable",
                "rationale": "The affected function cannot be reached in this configuration.",
            }
            | changes
        )
    )


def save(journal, data, *, submit=True, actor="analyst", assessment_id="decision", authorize=allow):
    return save_assessment(
        journal,
        project_id="project",
        actor_id=actor,
        assessment_id=assessment_id,
        data=data,
        submit=submit,
        authorize=authorize,
    )


def review(journal, selected=None, **changes):
    selected = selected or [target(journal)]
    revision = current(journal, selected[0].version)["assessments"]["assessment:decision"][
        "revision"
    ]
    data = ReviewInput(
        **(
            {
                "request_id": "review",
                "expected_versions": {t.version: head(journal, t.version) for t in selected},
                "assessment_id": "decision",
                "assessment_revision": revision,
                "targets": selected,
                "action": "approve",
                "rationale": "Independently checked reachability and the stated control.",
            }
            | changes
        )
    )
    return create_review(
        journal, project_id="project", actor_id="reviewer", data=data, authorize=allow
    )


def coverage(journal, selected=None):
    selected = selected or target(journal)
    return coverage_status(journal, current(journal, selected.version), **selected.model_dump())


def test_draft_submission_and_independent_review(journal):
    seed(journal)
    initial = target(journal)
    assert coverage(journal)["status"] == "unassessed"
    draft = assessment(journal, justification=None)
    save(journal, draft, submit=False)
    assert coverage(journal)["status"] == "draft"
    revision = current(journal)["assessments"]["assessment:decision"]["revision"]
    with pytest.raises(ValueError, match="justification"):
        save(
            journal,
            assessment(
                journal, request_id="invalid-submit", expected_revision=revision, justification=None
            ),
        )
    save(journal, assessment(journal, request_id="submit", expected_revision=revision))
    assert coverage(journal)["status"] == "submitted"
    submitted = current(journal)["assessments"]["assessment:decision"]
    own = ReviewInput(
        request_id="self",
        expected_versions={"7.1.1": head(journal)},
        assessment_id="decision",
        assessment_revision=submitted["revision"],
        targets=[initial],
        action="approve",
        rationale="Self review",
    )
    with pytest.raises(PermissionError, match="independent"):
        create_review(journal, project_id="project", actor_id="analyst", data=own, authorize=allow)
    review(journal)
    approved = coverage(journal)
    assert approved["status"] == "approved" and approved["approved"]
    assert approved["review"]["assessment_revision"] == submitted["revision"]
    assert approved["review"]["assessment"]["justification"] == "code_not_reachable"


def test_unchanged_reimport_and_team_reassignment_preserve_approval(journal):
    seed(journal)
    save(journal, assessment(journal))
    review(journal)
    revision = coverage(journal)["assessment_revision"]

    def bookkeeping(sections):
        sections["inventory"]["baseline"].update(
            build_number=2, occurred_at="tomorrow", artifact_sha="changed"
        )
        sections["inventory"]["baseline"]["collection"]["pipeline_run"] = "nightly-2"
        sections["inventory"]["component:lib"]["dtvp_origin"]["state"] = "new"

    seed(journal, parent=head(journal), team="B", modify=bookkeeping)
    status = coverage(journal)
    assert status["status"] == "approved"
    assert status["team_id"] == "B" and status["historical_team_id"] == "A"
    assert status["assessment_revision"] == revision


@pytest.mark.parametrize(
    "change",
    [
        lambda s: s["inventory"]["component:lib"].update(version="2"),
        lambda s: s["inventory"]["root"].update(configuration="new-exposure"),
        lambda s: s["vulnerabilities"]["claim"]["advisory"].update(
            description="A different impact"
        ),
        lambda s: s["inventory"]["baseline"]["collection"].update(target="windows"),
        lambda s: s["inventory"]["baseline"]["collection"].update(
            source_revision="different-source-commit"
        ),
        lambda s: s["inventory"]["component:lib"].update(
            properties=[{"name": "control", "value": "disabled"}]
        ),
    ],
)
def test_material_change_requires_reassessment(journal, change):
    seed(journal)
    save(journal, assessment(journal))
    review(journal)
    seed(journal, parent=head(journal), modify=change)
    assert coverage(journal)["status"] == "reassessment_needed"
    assert not coverage(journal)["approved"]


def test_absence_retains_assessment_and_reappearance_checks_material_state(journal):
    seed(journal)
    selected = target(journal)
    save(journal, assessment(journal))
    review(journal)
    before = current(journal)

    def remove(sections):
        sections["inventory"].pop("component:lib")
        sections["inventory"]["dependencies"]["edges"] = [{"ref": "app", "dependsOn": []}]
        sections["vulnerabilities"] = {}

    seed(journal, parent=head(journal), modify=remove)
    assert coverage(journal, selected)["status"] == "historically_absent"
    assert current(journal)["assessments"] == before["assessments"]
    seed(
        journal,
        parent=head(journal),
        modify=lambda s: s.update(
            inventory=before["inventory"], vulnerabilities=before["vulnerabilities"]
        ),
    )
    assert coverage(journal)["status"] == "approved"


def test_multi_version_submission_is_atomic_and_scope_extension_keeps_approved_revision(journal):
    seed(journal)
    seed(journal, "7.1.2")
    first, second = target(journal), target(journal, "7.1.2")
    save(journal, assessment(journal, [first]))
    review(journal, [first])
    approved_revision = coverage(journal)["assessment_revision"]
    extension = assessment(
        journal, [first, second], request_id="extension", expected_revision=approved_revision
    )
    save(journal, extension)
    assert coverage(journal)["status"] == "approved"
    assert coverage(journal)["assessment_revision"] == approved_revision
    assert coverage(journal, second)["status"] == "submitted"
    review(journal, [second], request_id="review-extension")
    assert coverage(journal, second)["status"] == "approved"
    assert (
        coverage(journal)["assessment_revision"] != coverage(journal, second)["assessment_revision"]
    )


def test_stale_head_blocks_all_versions_and_retry_does_not_publish_twice(journal):
    seed(journal)
    seed(journal, "7.1.2")
    selected = [target(journal), target(journal, "7.1.2")]
    data = assessment(journal, selected)
    stale = copy.deepcopy(data)
    seed(journal, "7.1.2", parent=head(journal, "7.1.2"))
    before = journal.head()
    with pytest.raises(Conflict, match="version changed"):
        save(journal, stale)
    assert journal.head() == before
    assert current(journal)["assessments"] == {}
    data = assessment(journal, selected, request_id="current")
    receipt = save(journal, data)
    before = journal.head()
    assert save(journal, data) == receipt
    assert journal.head() == before
    with pytest.raises(Conflict, match="different input"):
        save(journal, data.model_copy(update={"rationale": "Different"}))


def test_unowned_or_unknown_topology_and_permission_do_not_publish(journal):
    seed(journal)
    data = assessment(journal)
    before = journal.head()

    def deny(team, capability):
        raise PermissionError("No assessment role")

    with pytest.raises(PermissionError):
        save(journal, data, authorize=deny)
    assert journal.head() == before
    seed(
        journal,
        parent=head(journal),
        modify=lambda s: s["inventory"]["baseline"].update(dependency_graph="not_reported"),
    )
    with pytest.raises(Conflict, match="topology"):
        save(journal, assessment(journal))


def test_review_requires_current_revision_and_current_claims(journal):
    seed(journal)
    save(journal, assessment(journal))
    revision = current(journal)["assessments"]["assessment:decision"]["revision"]
    seed(
        journal,
        parent=head(journal),
        modify=lambda s: s["vulnerabilities"]["claim"]["advisory"].update(
            description="new evidence"
        ),
    )
    before = journal.head()
    with pytest.raises(Conflict, match="evidence changed"):
        review(journal)
    assert journal.head() == before
    save(journal, assessment(journal, expected_revision=revision, request_id="fresh"))
    with pytest.raises(Conflict, match="exact current"):
        review(journal, assessment_revision=revision)
    review(journal, action="request_changes", request_id="changes")
    assert coverage(journal)["status"] == "reassessment_needed"


def test_expected_versions_and_targets_are_exact(journal):
    seed(journal)
    with pytest.raises(ValidationError, match="exactly match"):
        assessment(journal, expected_versions={})
    with pytest.raises(ValidationError, match="distinct"):
        assessment(journal, [target(journal), target(journal)])
    sections = current(journal)
    selected = target(journal)
    sections["vulnerabilities"] = {}
    assert target_fingerprint(sections, **selected.model_dump()) is None


def test_new_scope_must_reference_the_published_shared_assessment(journal):
    seed(journal)
    seed(journal, "7.1.2")
    save(journal, assessment(journal))
    second = target(journal, "7.1.2")
    before = journal.head()
    with pytest.raises(Conflict, match="already exists"):
        save(journal, assessment(journal, [second], request_id="unrelated-create"))
    assert journal.head() == before
    old_revision = current(journal)["assessments"]["assessment:decision"]["revision"]
    save(
        journal,
        assessment(
            journal, [second], request_id="extend-new-branch", expected_revision=old_revision
        ),
    )
    assert coverage(journal, second)["status"] == "submitted"


def test_approved_coverage_exposes_separate_latest_editable_draft(journal):
    seed(journal)
    save(journal, assessment(journal))
    review(journal)
    approved = coverage(journal)
    revision = approved["assessment_revision"]
    save(
        journal,
        assessment(journal, request_id="revise-draft", expected_revision=revision),
        submit=False,
    )
    status = coverage(journal)
    assert status["status"] == "approved"
    assert status["assessment"]["stage"] == "draft"
    assert status["assessment"]["revision"] != revision
    assert status["approved_assessment"]["revision"] == revision
    assert status["review"]["assessment_revision"] == revision


def test_unassigned_ownership_blocks_draft_and_review(journal):
    seed(journal)
    data = assessment(journal)
    parent = head(journal)
    sections = load_sections(journal, parent)
    resolve_ownership(sections, version="7.1.1", config={"rules": [], "context_roots": {}})
    state = journal.snapshot(
        project_id="project",
        version="7.1.1",
        actor_id="manager",
        reason="Remove owners",
        sections=sections,
        parents=[parent],
    )
    journal.publish(
        request_id="unassign",
        fingerprint=digest(b"unassign"),
        updates=[
            Update(ref=Ref(project_id="project", name="7.1.1"), expected=parent, target=state)
        ],
    )
    with pytest.raises(Conflict, match="resolved ownership"):
        save(journal, data.model_copy(update={"expected_versions": {"7.1.1": state}}), submit=False)


def test_shared_scope_rejects_different_vulnerabilities_and_package_lineage(journal):
    seed(journal)
    seed(
        journal,
        "7.1.2",
        modify=lambda s: s["inventory"]["component:lib"].update(purl="pkg:generic/other-lib@1"),
    )
    first, second = target(journal), target(journal, "7.1.2")
    with pytest.raises(ValidationError, match="one vulnerability"):
        assessment(
            journal, [first, second.model_copy(update={"vulnerability_id": "CVE-2026-9999"})]
        )
    with pytest.raises(ValueError, match="compatible component lineage"):
        save(journal, assessment(journal, [first, second]))
    assert current(journal)["assessments"] == {}
    assert current(journal, "7.1.2")["assessments"] == {}


def test_package_versions_can_be_shared_only_with_explicit_target_review(journal):
    seed(journal)
    seed(
        journal,
        "7.1.2",
        modify=lambda s: s["inventory"]["component:lib"].update(
            version="2", purl="pkg:generic/lib@2"
        ),
    )
    selected = [target(journal), target(journal, "7.1.2")]
    save(journal, assessment(journal, selected))
    review(journal, selected[:1])
    assert coverage(journal, selected[0])["status"] == "approved"
    assert coverage(journal, selected[1])["status"] == "submitted"
    review(journal, selected[1:], request_id="other-version-review")
    assert coverage(journal, selected[1])["status"] == "approved"


def test_weak_lineage_needs_conditions_and_identical_local_refs(journal):
    def weak(sections):
        sections["inventory"]["component:lib"].pop("purl")

    seed(journal, modify=weak)
    seed(journal, "7.1.2", modify=weak)
    selected = [target(journal), target(journal, "7.1.2")]
    with pytest.raises(ValueError, match="supporting conditions"):
        save(journal, assessment(journal, selected))
    save(
        journal,
        assessment(
            journal,
            selected,
            request_id="conditions",
            conditions="Both selected configurations use the same source-local component and identical build configuration.",
        ),
    )
    assert coverage(journal, selected[1])["status"] == "submitted"


def test_concurrent_same_id_creation_in_other_version_cannot_split_assessment(journal, monkeypatch):
    seed(journal)
    seed(journal, "7.1.2")
    first = assessment(journal, [target(journal)], request_id="first-creator")
    second = assessment(journal, [target(journal, "7.1.2")], request_id="second-creator")
    original_publish = journal.publish
    raced = False

    def racing_publish(**kwargs):
        nonlocal raced
        if not raced:
            raced = True
            # The first author has already inspected the registry heads, but a
            # different version commits the same logical ID before its CAS.
            monkeypatch.setattr(journal, "publish", original_publish)
            save(journal, second)
        return original_publish(**kwargs)

    monkeypatch.setattr(journal, "publish", racing_publish)
    with pytest.raises(Conflict, match="Product versions changed"):
        save(journal, first)
    assert raced
    assert current(journal)["assessments"] == {}
    assert (
        current(journal, "7.1.2")["assessments"]["assessment:decision"]["payload"]["targets"][0][
            "version"
        ]
        == "7.1.2"
    )


def test_payload_revision_is_explicit_verified_artifact_in_each_mutated_state(journal):
    seed(journal)
    seed(journal, "7.1.2")
    selected = [target(journal), target(journal, "7.1.2")]
    save(journal, assessment(journal, selected))
    revision = current(journal)["assessments"]["assessment:decision"]["revision"]
    for chosen in selected:
        assert revision in journal.verify_state(head(journal, chosen.version)).artifacts
    review(journal, selected)
    for chosen in selected:
        assert revision in journal.verify_state(head(journal, chosen.version)).artifacts
