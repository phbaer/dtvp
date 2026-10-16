"""Explicit reference correspondence stays pinned, attributed and non-authoritative."""

from uuid import uuid4

import pytest

from dtvp.knowledge.journal import Conflict, Journal, Ref, Update
from dtvp.knowledge.reconciliation import (
    Pair,
    ReconciliationInput,
    RetractionInput,
    confirm_reconciliation,
    correspondence_key,
    list_reconciliations,
    preview_reconciliation,
    retract_reconciliation,
)
from dtvp.knowledge.workspace import load_sections
from dtvp.storage import digest
from tests.test_knowledge_assessments import seed


@pytest.fixture
def journal(tmp_path):
    return Journal(tmp_path / "journal")


def update(journal, parent, mutate, version="7.1.1"):
    sections = load_sections(journal, parent)
    mutate(sections)
    ref = Ref(project_id="project", name=version)
    state = journal.snapshot(
        project_id="project",
        version=version,
        actor_id="pipeline",
        reason="Fixture",
        sections=sections,
        parents=[parent],
        artifacts=journal.state(parent).artifacts,
    )
    journal.publish(
        request_id=str(uuid4()),
        fingerprint=digest(state.encode()),
        updates=[Update(ref=ref, expected=journal.resolve(ref), target=state)],
    )
    return state


def renamed(sections):
    lib = sections["inventory"].pop("component:lib")
    lib["bom-ref"] = "new-lib"
    sections["inventory"]["component:new-lib"] = lib
    for edge in sections["inventory"]["dependencies"]["edges"]:
        if edge["ref"] == "lib":
            edge["ref"] = "new-lib"
        edge["dependsOn"] = ["new-lib" if ref == "lib" else ref for ref in edge["dependsOn"]]
    for claim in sections["vulnerabilities"].values():
        claim["ref"] = "new-lib"
    from dtvp.knowledge.ownership import resolve_ownership

    resolve_ownership(
        sections,
        version="7.1.1",
        config={"rules": [{"selector": "*", "team_id": "A"}], "context_roots": {}},
    )


def allow(capability):
    assert capability == "write"


def pair(kind="component", source_id="lib", target_id="new-lib"):
    return Pair(kind=kind, source_id=source_id, target_id=target_id)


def confirm(journal, source, target, pairs=None, **changes):
    selected = pairs or [pair()]
    preview = preview_reconciliation(journal, "project", source, target, selected)
    data = ReconciliationInput(
        **(
            dict(
                request_id=str(uuid4()),
                expected=target,
                expected_revision=None,
                source=source,
                preview_digest=preview["preview_digest"],
                pairs=selected,
                rationale="Producer changed source-local references; explicitly reviewed correspondence",
                evidence=[{"ticket": "mapping-123"}],
            )
            | changes
        )
    )
    return confirm_reconciliation(
        journal, "project", "7.1.1", "curator", "mapping", data, allow
    ), data


def record(journal, state):
    return load_sections(journal, state)["history"][correspondence_key("mapping")]


def test_ref_rename_preview_and_confirmation_never_rewrite_inventory_or_approvals(journal):
    source = seed(journal)
    target = update(journal, source, renamed)
    preview = preview_reconciliation(journal, "project", source, target, [pair()])
    assert preview["eligible"] and preview["items"][0]["classification"] == "candidate"
    before = load_sections(journal, target)
    _, data = confirm(journal, source, target)
    state = journal.resolve(Ref(project_id="project", name="7.1.1"))
    after = load_sections(journal, state)
    assert {k: v for k, v in before.items() if k != "history"} == {
        k: v for k, v in after.items() if k != "history"
    }
    mapping = record(journal, state)
    assert mapping["payload"]["source"] == source and mapping["payload"]["target"] == target
    assert journal.load(mapping["revision"]) == mapping["payload"]
    assert set(journal.state(state).parents) == {source, target}
    assert mapping["revision"] in journal.state(state).artifacts
    assert after["assessments"] == after["reviews"] == after["scoring"] == {}
    assert list_reconciliations(journal, state)["total"] == 1


def test_exact_package_family_and_same_version_hash_conflicts_block_confirmation(journal):
    def qualified(sections):
        sections["inventory"]["component:lib"]["hashes"] = [{"alg": "SHA-256", "content": "a" * 64}]

    source = update(journal, seed(journal), qualified)

    def conflict(sections):
        renamed(sections)
        sections["inventory"]["component:new-lib"]["hashes"][0]["content"] = "b" * 64

    target = update(journal, source, conflict)
    result = preview_reconciliation(journal, "project", source, target, [pair()])
    assert not result["eligible"]
    assert "same_version_hash_conflict" in result["items"][0]["reasons"]
    with pytest.raises(Conflict, match="Conflicting"):
        confirm(journal, source, target)

    def family(sections):
        sections["inventory"]["component:new-lib"]["purl"] = "pkg:generic/other@1"

    changed = update(journal, target, family)
    assert preview_reconciliation(journal, "project", source, changed, [pair()])["items"][0][
        "reasons"
    ] == ["package_family_conflict"]


def test_version_change_is_lineage_correspondence_not_artifact_equivalence(journal):
    source = seed(journal)

    def version(sections):
        renamed(sections)
        sections["inventory"]["component:new-lib"].update(version="2", purl="pkg:generic/lib@2")

    target = update(journal, source, version)
    preview = preview_reconciliation(journal, "project", source, target, [pair()])
    assert preview["eligible"] and preview["items"][0]["classification"] == "material_change"
    assert "package_version_changed" in preview["items"][0]["reasons"]
    confirm(journal, source, target)


def test_context_pair_is_separate_and_does_not_imply_component_or_usage_equivalence(journal):
    source = seed(journal)
    target = update(journal, source, renamed)
    old = next(
        value["id"]
        for key, value in load_sections(journal, source)["ownership"].items()
        if key.startswith("context:") and value["component_ref"] == "lib"
    )
    new = next(
        value["id"]
        for key, value in load_sections(journal, target)["ownership"].items()
        if key.startswith("context:") and value["component_ref"] == "new-lib"
    )
    result = preview_reconciliation(
        journal, "project", source, target, [pair(), pair("context", old, new)]
    )
    assert len(result["items"]) == 2 and result["eligible"]
    context = next(row for row in result["items"] if row["kind"] == "context")
    assert "consuming_context_changed_requires_new_target_review" in context["reasons"]
    assert context["source_facts"]["root"]["bom-ref"] == "app"


def test_ambiguous_missing_and_uncommitted_scopes_fail_safely(journal):
    source = seed(journal)
    target = update(journal, source, renamed)
    with pytest.raises(ValueError, match="one-to-one"):
        preview_reconciliation(journal, "project", source, target, [pair(), pair(target_id="app")])
    absent = preview_reconciliation(journal, "project", source, target, [pair(target_id="absent")])
    assert not absent["eligible"] and absent["items"][0]["classification"] == "unresolved"
    candidate = journal.snapshot(
        project_id="project",
        version="7.1.1",
        actor_id="pipeline",
        reason="Not committed",
        sections=load_sections(journal, source),
    )
    with pytest.raises(ValueError, match="committed product history"):
        preview_reconciliation(journal, "project", candidate, target, [pair()])
    with pytest.raises(Conflict, match="target version changed"):
        preview_reconciliation(journal, "project", source, source, [pair()])
    with pytest.raises(ValueError, match="1 to 100"):
        preview_reconciliation(journal, "project", source, target, [])


def test_replay_cas_preview_pin_supersession_and_explicit_retraction(journal):
    source = seed(journal)
    target = update(journal, source, renamed)
    receipt, data = confirm(journal, source, target)
    assert (
        confirm_reconciliation(journal, "project", "7.1.1", "curator", "mapping", data, allow)
        == receipt
    )
    first = journal.resolve(Ref(project_id="project", name="7.1.1"))
    revision = record(journal, first)["revision"]
    with pytest.raises(Conflict, match="different input"):
        confirm_reconciliation(
            journal,
            "project",
            "7.1.1",
            "curator",
            "mapping",
            data.model_copy(update={"rationale": "different"}),
            allow,
        )
    with pytest.raises(Conflict, match="revision changed"):
        confirm(journal, source, first)
    _, superseded = confirm(journal, source, first, expected_revision=revision)
    current = journal.resolve(Ref(project_id="project", name="7.1.1"))
    assert record(journal, current)["payload"]["previous"] == revision
    retract = RetractionInput(
        request_id="retract",
        expected=current,
        expected_revision=record(journal, current)["revision"],
        reason="Producer supplied contradictory correspondence evidence",
    )
    receipt = retract_reconciliation(
        journal, "project", "7.1.1", "curator", "mapping", retract, allow
    )
    assert (
        retract_reconciliation(journal, "project", "7.1.1", "curator", "mapping", retract, allow)
        == receipt
    )
    final = journal.resolve(Ref(project_id="project", name="7.1.1"))
    assert record(journal, final)["payload"]["stage"] == "retracted"
    assert record(journal, first)["payload"]["stage"] == "active"
    assert journal.load(revision)["stage"] == "active"


def test_source_snapshot_remains_valid_after_source_branch_advances_cross_version(journal):
    source = seed(journal, version="7.1.2")
    target = update(journal, source, renamed)
    preview = preview_reconciliation(journal, "project", source, target, [pair()])
    seed(journal, version="7.1.2", parent=source)
    assert preview_reconciliation(journal, "project", source, target, [pair()]) == preview
    confirm(journal, source, target)


def test_authorization_and_atomic_target_cas(journal, monkeypatch):
    source = seed(journal)
    target = update(journal, source, renamed)
    preview = preview_reconciliation(journal, "project", source, target, [pair()])
    data = ReconciliationInput(
        request_id="confirm",
        expected=target,
        expected_revision=None,
        source=source,
        preview_digest=preview["preview_digest"],
        pairs=[pair()],
        rationale="Reviewed source evidence",
    )

    def deny(capability):
        raise PermissionError(capability)

    before = journal.head()
    with pytest.raises(PermissionError, match="write"):
        confirm_reconciliation(journal, "project", "7.1.1", "curator", "mapping", data, deny)
    assert journal.head() == before
    native = Journal.publish
    raced = []

    def race(self, **kwargs):
        if not raced:
            raced.append(True)
            update(
                journal,
                target,
                lambda sections: sections["inventory"]["component:new-lib"].update(version="3"),
            )
        return native(self, **kwargs)

    monkeypatch.setattr(Journal, "publish", race)
    with pytest.raises(Conflict, match="Branch changed"):
        confirm_reconciliation(journal, "project", "7.1.1", "curator", "mapping", data, allow)
    assert (
        list_reconciliations(journal, journal.resolve(Ref(project_id="project", name="7.1.1")))[
            "total"
        ]
        == 0
    )


def test_preview_pin_context_usage_changes_and_historical_artifacts_are_preserved(journal):
    source = seed(journal, version="7.1.2")
    raw = journal.objects.put(b"Original source SBOM bytes")
    enriched = journal.snapshot(
        project_id="project",
        version="7.1.2",
        actor_id="producer",
        reason="Pinned original",
        sections=load_sections(journal, source),
        parents=[source],
        artifacts=[raw],
    )
    journal.publish(
        request_id="source-original",
        fingerprint=digest(enriched.encode()),
        updates=[
            Update(ref=Ref(project_id="project", name="7.1.2"), expected=source, target=enriched)
        ],
    )
    target = update(journal, seed(journal), renamed)
    preview = preview_reconciliation(journal, "project", enriched, target, [pair()])
    with pytest.raises(Conflict, match="preview changed"):
        confirm(journal, enriched, target, preview_digest="f" * 64)
    confirm(journal, enriched, target)
    current = journal.resolve(Ref(project_id="project", name="7.1.1"))
    assert raw in journal.state(current).artifacts
    assert journal.objects.read(raw) == b"Original source SBOM bytes"
    assert preview["source_version"] == "7.1.2"


def test_context_usage_graph_change_is_disclosed_without_transferring_coverage(journal):
    source = seed(journal)
    source_context = next(
        value["id"]
        for key, value in load_sections(journal, source)["ownership"].items()
        if key.startswith("context:") and value["component_ref"] == "lib"
    )

    def changed_graph(sections):
        sections["inventory"]["component:extra"] = {
            "bom-ref": "extra",
            "name": "extra",
            "version": "1",
        }
        sections["inventory"]["dependencies"]["edges"][0]["dependsOn"].append("extra")

    target = update(journal, source, changed_graph)
    result = preview_reconciliation(
        journal, "project", source, target, [pair("context", source_context, source_context)]
    )
    row = result["items"][0]
    assert (
        row["source_facts"]["usage"]["fingerprint"] != row["target_facts"]["usage"]["fingerprint"]
    )
    assert "consuming_context_changed_requires_new_target_review" in row["reasons"]


@pytest.mark.parametrize(
    "source_version,target_version,target_purl,eligible",
    [
        (None, None, "pkg:generic/lib@2", True),
        ("1", None, "pkg:generic/lib@2", True),
        ("1", "2", "pkg:generic/lib@1", False),
    ],
)
def test_package_url_versions_fill_missing_fields_and_contradictions_block(
    journal, source_version, target_version, target_purl, eligible
):
    def original(sections):
        component = sections["inventory"]["component:lib"]
        component["hashes"] = [{"alg": "SHA-256", "content": "a" * 64}]
        if source_version is None:
            component.pop("version", None)
        else:
            component["version"] = source_version

    source = seed(journal, modify=original)

    def changed(sections):
        renamed(sections)
        component = sections["inventory"]["component:new-lib"]
        component.update(purl=target_purl, hashes=[{"alg": "SHA-256", "content": "b" * 64}])
        if target_version is None:
            component.pop("version", None)
        else:
            component["version"] = target_version

    target = update(journal, source, changed)
    preview = preview_reconciliation(journal, "project", source, target, [pair()])
    assert preview["eligible"] is eligible
    row = preview["items"][0]
    if eligible:
        assert row["classification"] == "material_change"
        assert "artifact_hashes_changed_across_versions" in row["reasons"]
        confirm(journal, source, target)
    else:
        assert row["reasons"] == ["component_version_coordinate_conflict"]
        with pytest.raises(Conflict, match="Conflicting"):
            confirm(journal, source, target)


def test_spdx_and_cyclonedx_hash_algorithm_aliases_cannot_hide_same_version_conflicts(journal):
    def checksummed(sections):
        sections["inventory"]["component:lib"]["hashes"] = [{"alg": "SHA256", "content": "a" * 64}]

    source = seed(journal, modify=checksummed)

    def change(sections):
        renamed(sections)
        sections["inventory"]["component:new-lib"]["hashes"] = [
            {"alg": "SHA-256", "content": "b" * 64}
        ]

    target = update(journal, source, change)
    row = preview_reconciliation(journal, "project", source, target, [pair()])["items"][0]
    assert row["blocked"] and row["hash_conflicts"] == ["SHA-256"]
    assert row["reasons"] == ["same_version_hash_conflict"]


@pytest.mark.parametrize(
    "malformed",
    [
        [{"alg": "SHA-256", "content": 42}],
        None,
        [None],
        [["SHA-256", "abc"]],
        [{"alg": "SHA-256", "content": "not-a-checksum"}],
        [{"alg": 42, "content": "a" * 64}],
    ],
)
def test_malformed_hash_records_are_unresolved_not_server_errors(journal, malformed):
    source = seed(journal)

    def change(sections):
        renamed(sections)
        sections["inventory"]["component:new-lib"]["hashes"] = malformed

    target = update(journal, source, change)
    preview = preview_reconciliation(journal, "project", source, target, [pair()])
    assert not preview["eligible"]
    assert preview["items"][0]["classification"] == "unresolved"
    assert preview["items"][0]["reasons"] == ["invalid_component_hash_evidence"]
    with pytest.raises(Conflict, match="Conflicting"):
        confirm(journal, source, target)


@pytest.mark.parametrize("purl", [42, "not-a-package-url"])
def test_malformed_package_coordinates_are_blocked(journal, purl):
    source = seed(journal)

    def changed(sections):
        renamed(sections)
        sections["inventory"]["component:new-lib"]["purl"] = purl

    target = update(journal, source, changed)
    preview = preview_reconciliation(journal, "project", source, target, [pair()])
    assert not preview["eligible"]
    assert preview["items"][0]["reasons"] == ["invalid_package_url"]
