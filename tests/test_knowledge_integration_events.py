"""Git-object consistency never authenticates integration or transfers human approvals."""

import base64
import copy
import hashlib
from uuid import uuid4

import pytest

from dtvp.knowledge import git_ancestry
from dtvp.knowledge import integration_events as module
from dtvp.knowledge.assessments import (
    AssessmentInput,
    ReviewInput,
    Target,
    create_review,
    save_assessment,
)
from dtvp.knowledge.journal import Conflict, Journal, Ref
from dtvp.knowledge.ownership import OwnershipInput, update_policy
from dtvp.knowledge.service import import_inventory
from dtvp.knowledge.workspace import load_sections, load_workspace
from dtvp.storage import digest


def commit(message, *parents):
    raw = (
        "tree "
        + "f" * 40
        + "\n"
        + "".join("parent " + parent + "\n" for parent in parents)
        + "author Synthetic <fixture@example.invalid> 1 +0000\ncommitter Synthetic <fixture@example.invalid> 1 +0000\n\n"
        + message
        + "\n"
    ).encode()
    sha = hashlib.sha1(b"commit " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
    return sha, raw


def proof():
    source, raw_source = commit("source")
    middle, raw_middle = commit("intermediate", source)
    target, raw_target = commit("target", middle)
    objects = {source: raw_source, middle: raw_middle, target: raw_target}
    return (
        source,
        target,
        {sha: base64.b64encode(raw).decode() for sha, raw in objects.items()},
        objects,
    )


def imported(journal, bom, version, sha, *, expected=None, build=1, subject=None, run=None):
    return (
        import_inventory(
            journal,
            project_id="project",
            version=version,
            actor_id="pipeline",
            request_id=str(uuid4()),
            expected=expected,
            source="pipeline",
            build_number=build,
            occurred_at="2026-10-16T01:00:00Z",
            sbom=bom,
            context={
                "analysis_source": {"repository_name": "gateway", "source_commit": sha},
                "subject_kind": "build",
                "subject_digest": subject or "sha256:" + "e" * 64,
                "pipeline_run": run or "target-build",
            },
        )[1]
        .updates[0]
        .target
    )


@pytest.fixture
def env(tmp_path, bom):
    journal = Journal(tmp_path / "journal")
    source_commit, target_commit, encoded, raw = proof()
    source = imported(journal, bom, "7.1.1", source_commit, run="source-build")
    target = imported(journal, bom, "7.1.2", target_commit)
    update_policy(
        journal,
        project_id="project",
        actor_id="operator",
        data=OwnershipInput(
            request_id="policy",
            expected_policy=None,
            expected_versions={"7.1.1": source, "7.1.2": target},
            rules=[{"selector": "*", "team_id": "A"}],
        ),
    )
    return journal, bom, encoded, raw


def data(env, **changes):
    journal, _, encoded, _ = env
    source_commit, target_commit, _, _ = proof()
    return module.IntegrationInput.model_validate(
        {
            "request_id": "integration",
            "source": journal.resolve(Ref(project_id="project", name="7.1.1")),
            "target": journal.resolve(Ref(project_id="project", name="7.1.2")),
            "expected_target": journal.resolve(Ref(project_id="project", name="7.1.2")),
            "repository": "gateway",
            "source_commit": source_commit,
            "target_commit": target_commit,
            "target_subject_digest": "sha256:" + "e" * 64,
            "pipeline_run": "target-build",
            "integration_kind": "merge",
            "occurred_at": "2026-10-16T01:00:00Z",
            "rationale": "Pipeline declares this exact cascading integration",
            "git_commit_objects": encoded,
            **changes,
        }
    )


def record(env, selected=None):
    return module.record_integration(
        env[0], project_id="project", actor_id="pipeline", data=selected or data(env)
    )


def test_actual_commit_objects_prove_only_hash_and_parent_path_and_keep_exact_bytes(env):
    journal, _, _, raw = env
    selected = data(env)
    previous = load_sections(journal, selected.target)
    source_before = journal.resolve(Ref(project_id="project", name="7.1.1"))
    receipt = record(env, selected)
    state = receipt[1].updates[0].target
    event_id = module.event_identity("project", "pipeline", selected)[0]
    event = module.integration_event(journal, "project", state, event_id)
    assert event["git_ancestry"]["status"] == "verified_commit_object_ancestry"
    assert event["git_ancestry"]["path"][0] == selected.source_commit
    assert event["git_ancestry"]["path"][-1] == selected.target_commit
    assert not event["software_integration_verified"]
    assert event["provenance_verification"] == "producer_declared_not_authenticated"
    current = load_sections(journal, state)
    for section in previous.keys() - {"history"}:
        assert current[section] == previous[section]
    assert journal.state(state).parents == [selected.target]
    assert journal.resolve(Ref(project_id="project", name="7.1.1")) == source_before
    for sha, value in raw.items():
        assert event["git_ancestry"]["objects"][sha] == digest(value)
        assert digest(value) in journal.state(state).artifacts
        assert journal.objects.read(digest(value)) == value


def test_declaration_without_proof_does_not_become_verified_ancestry(env):
    selected = data(env, git_commit_objects={}, integration_kind="cherry_pick")
    receipt = record(env, selected)
    state = receipt[1].updates[0].target
    event_id = module.event_identity("project", "pipeline", selected)[0]
    event = module.integration_event(env[0], "project", state, event_id)
    assert event["git_ancestry"]["status"] == "not_provided"
    assert event["declaration"]["integration_kind"] == "cherry_pick"
    assert event["software_integration_verified"] is False


@pytest.mark.parametrize(
    "broken", ["wrong_hash", "partial", "unrelated", "invalid_base64", "too_many"]
)
def test_supplied_invalid_or_incomplete_proof_never_records_integration(env, broken):
    journal, _, encoded, _ = env
    supplied = copy.deepcopy(encoded)
    source, target, _, _ = proof()
    if broken == "wrong_hash":
        supplied[source] = base64.b64encode(b"wrong bytes").decode()
    elif broken == "partial":
        supplied.pop(source)
    elif broken == "unrelated":
        other, raw_other = commit("unrelated target")
        supplied = {source: supplied[source], other: base64.b64encode(raw_other).decode()}
        target = other
    elif broken == "invalid_base64":
        supplied[source] = "!notbase64"
    else:

        class WideDict(dict):
            def __len__(self):
                return 1001

            def items(self):
                raise AssertionError("Oversized proof must not be traversed")

        with pytest.raises(ValueError):
            git_ancestry.verify_objects(WideDict(), source, target)
        return
    before = journal.head(), journal.references(), set(journal.objects.root.rglob("*"))
    with pytest.raises(ValueError):
        if broken == "unrelated":
            git_ancestry.verify_objects(supplied, source, target)
        else:
            record(env, data(env, git_commit_objects=supplied))
    assert before == (journal.head(), journal.references(), set(journal.objects.root.rglob("*")))


def test_decoded_budget_admitted_before_base64_allocation(monkeypatch):
    source, target, encoded, _ = proof()
    monkeypatch.setattr(git_ancestry, "MAX_TOTAL_BYTES", 1)

    def forbidden(*args, **kwargs):
        raise AssertionError("Budget must be checked before decoding")

    monkeypatch.setattr(git_ancestry.base64, "b64decode", forbidden)
    with pytest.raises(ValueError, match="budget"):
        git_ancestry.verify_objects(encoded, source, target)


@pytest.mark.parametrize(
    "field,value",
    [
        ("repository", "different"),
        ("source_commit", "0" * 40),
        ("target_commit", "0" * 40),
        ("target_subject_digest", "sha256:" + "0" * 64),
        ("pipeline_run", "different-build"),
    ],
)
def test_exact_producer_pins_must_match_both_accepted_inventory_states(env, field, value):
    before = env[0].head()
    with pytest.raises(Conflict):
        record(env, data(env, **{field: value}))
    assert env[0].head() == before


def test_historical_source_allowed_and_target_advance_requires_new_observation(env):
    journal, bom, _, _ = env
    selected = data(env)
    imported(journal, bom, "7.1.1", "a" * 40, expected=selected.source, build=2, run="later-source")
    first = record(env, selected)
    state = first[1].updates[0].target
    event_id = module.event_identity("project", "pipeline", selected)[0]
    preview = module.integration_synchronization_preview(
        journal,
        project_id="project",
        event_id=event_id,
        data=module.IntegrationPreviewInput(target=state),
    )
    assert preview["proposals"]["source"] == selected.source
    assert preview["basis_selection"] == "none_no_inferred_common_basis"
    assert preview["proposals"]["basis"] is None and not preview["apply_supported"]
    advanced = imported(
        journal,
        bom,
        "7.1.2",
        selected.target_commit,
        expected=state,
        build=2,
        subject="sha256:" + "f" * 64,
    )
    with pytest.raises(Conflict, match="artifact"):
        module.integration_synchronization_preview(
            journal,
            project_id="project",
            event_id=event_id,
            data=module.IntegrationPreviewInput(target=advanced),
        )


def test_replay_receipt_before_old_target_checks_and_reverification(env, monkeypatch):
    journal, bom, _, _ = env
    selected = data(env)
    first = record(env, selected)
    state = first[1].updates[0].target
    advanced = imported(journal, bom, "7.1.2", selected.target_commit, expected=state, build=2)

    def forbidden(*args, **kwargs):
        raise AssertionError("Exact receipt replay must not verify proof again")

    monkeypatch.setattr(module, "verify_objects", forbidden)
    assert record(env, selected) == first
    assert journal.resolve(Ref(project_id="project", name="7.1.2")) == advanced
    with pytest.raises(Conflict):
        record(env, selected.model_copy(update={"rationale": "different replay"}))


def test_approved_source_stays_proposal_only_and_target_decisions_unchanged(env):
    journal = env[0]
    source = data(env).source
    row = load_workspace(journal, source)["items"][0]
    target = Target(
        version="7.1.1", context_id=row["context_id"], vulnerability_id=row["vulnerability_id"]
    )
    save_assessment(
        journal,
        project_id="project",
        actor_id="analyst",
        assessment_id="source-assessment",
        data=AssessmentInput(
            request_id="assessment",
            expected_versions={"7.1.1": source},
            expected_revision=None,
            targets=[target],
            state="affected",
            rationale="Source team assessment",
        ),
        submit=True,
        authorize=lambda *args: True,
    )
    source = journal.resolve(Ref(project_id="project", name="7.1.1"))
    revision = load_sections(journal, source)["assessments"]["assessment:source-assessment"][
        "revision"
    ]
    create_review(
        journal,
        project_id="project",
        actor_id="reviewer",
        data=ReviewInput(
            request_id="approve",
            expected_versions={"7.1.1": source},
            assessment_id="source-assessment",
            assessment_revision=revision,
            targets=[target],
            action="approve",
            rationale="Independent source review",
        ),
        authorize=lambda *args: True,
    )
    selected = data(env)
    receipt = record(env, selected)
    state = receipt[1].updates[0].target
    event_id = module.event_identity("project", "pipeline", selected)[0]
    preview = module.integration_synchronization_preview(
        journal,
        project_id="project",
        event_id=event_id,
        data=module.IntegrationPreviewInput(target=state),
    )
    assert preview["proposals"]["total"] == 1
    sections = load_sections(journal, state)
    assert all(not sections[key] for key in ("assessments", "reviews", "scoring"))
    assert preview["proposals"]["items"][0]["requires_new_target_review"]


def test_wide_parent_headers_preserve_exact_path_and_reject_duplicate_parent():
    source, raw_source = commit("source")
    parents = [f"{number:040x}" for number in range(2000)]
    target, raw_target = commit("wide merge", *parents, source)
    encoded = {
        source: base64.b64encode(raw_source).decode(),
        target: base64.b64encode(raw_target).decode(),
    }
    verified, _ = git_ancestry.verify_objects(encoded, source, target)
    assert verified["path"] == [source, target]
    duplicate, raw_duplicate = commit("duplicate parent", *parents, source, source)
    with pytest.raises(ValueError, match="repeated"):
        git_ancestry.verify_objects(
            {source: encoded[source], duplicate: base64.b64encode(raw_duplicate).decode()},
            source,
            duplicate,
        )


@pytest.mark.parametrize("mutation", ["tree", "author", "parent", "continuation"])
def test_matching_hash_does_not_admit_invalid_commit_headers(mutation):
    source, raw = commit("source")
    if mutation == "tree":
        raw = raw.replace(b"tree " + b"f" * 40, b"tree wrong")
    elif mutation == "author":
        raw = raw.replace(b"author Synthetic <fixture@example.invalid> 1 +0000\n", b"")
    elif mutation == "parent":
        raw = raw.replace(b"author ", b"parent invalid\nauthor ")
    else:
        raw = raw.replace(b"committer ", b" invalid continuation\ncommitter ")
    identity = hashlib.sha1(b"commit " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
    with pytest.raises(ValueError):
        git_ancestry.verify_objects({identity: base64.b64encode(raw).decode()}, identity, identity)


def test_target_cas_race_and_existing_tags_preserve_original_heads(env, monkeypatch):
    from dtvp.knowledge.journal import Update
    from dtvp.knowledge.service import create_tag

    journal = env[0]
    selected = data(env)
    create_tag(
        journal,
        project_id="project",
        actor_id="operator",
        name="released",
        state=selected.target,
        request_id="tag",
    )
    original = journal.publish
    advanced = None

    def raced(**kwargs):
        nonlocal advanced
        advanced = journal.snapshot(
            project_id="project",
            version="7.1.2",
            actor_id="other",
            reason="Concurrent target edit",
            sections=load_sections(journal, selected.target),
            parents=[selected.target],
            artifacts=journal.state(selected.target).artifacts,
        )
        original(
            request_id="target-race",
            fingerprint=digest(b"target-race"),
            updates=[
                Update(
                    ref=Ref(project_id="project", name="7.1.2"),
                    expected=selected.target,
                    target=advanced,
                )
            ],
        )
        return original(**kwargs)

    monkeypatch.setattr(journal, "publish", raced)
    with pytest.raises(Conflict):
        record(env, selected)
    assert journal.resolve(Ref(project_id="project", name="7.1.2")) == advanced
    assert (
        journal.resolve(Ref(kind="tag", project_id="project", name="released")) == selected.target
    )
    assert not module.integration_events(journal, "project", advanced)["items"]


@pytest.mark.parametrize("unsupported", ["assembly", "withdrawn"])
def test_unaccepted_or_assembled_state_cannot_claim_whole_product_integration(env, unsupported):
    from dtvp.knowledge.journal import Update

    journal = env[0]
    selected = data(env)
    sections = load_sections(journal, selected.target)
    if unsupported == "assembly":
        sections["inventory"]["assembly"] = {"parts": []}
    else:
        sections["inventory"]["baseline"]["withdrawn"] = True
    state = journal.snapshot(
        project_id="project",
        version="7.1.2",
        actor_id="pipeline",
        reason="Assembly fixture",
        sections=sections,
        parents=[selected.target],
        artifacts=journal.state(selected.target).artifacts,
    )
    journal.publish(
        request_id="assembly-target",
        fingerprint=digest(b"assembly-target"),
        updates=[
            Update(
                ref=Ref(project_id="project", name="7.1.2"), expected=selected.target, target=state
            )
        ],
    )
    with pytest.raises(ValueError):
        record(env, data(env))
