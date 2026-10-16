"""Stable identity bridges preserve only proved reference-only reviewed scope."""

from copy import deepcopy

import pytest
from test_knowledge_assessments import assessment, current, head, review, save, seed

from dtvp.knowledge.assessment_continuity import approval_bridge
from dtvp.knowledge.assessments import Target, coverage_status, load_sections, target_fingerprint
from dtvp.knowledge.component_lineages import reconcile_lineages
from dtvp.knowledge.journal import Journal, Ref, Update
from dtvp.storage import digest


@pytest.fixture
def journal(tmp_path):
    return Journal(tmp_path / "journal")


def initial(
    journal, *, root_identity=True, legacy=False, component_marker="purl", configuration=None
):
    def modify(sections):
        inventory = sections["inventory"]
        inventory["baseline"]["artifact_sha"] = "a" * 64
        if configuration is not None:
            inventory["pipeline_configuration"] = {
                "state": "c" * 64,
                "configuration": deepcopy(configuration),
            }
        if root_identity:
            inventory["root"]["purl"] = "pkg:generic/app@1"
        if component_marker != "purl":
            inventory["component:lib"].pop("purl")
            if component_marker == "digest":
                inventory["component:lib"].update(
                    type="library", hashes=[{"alg": "SHA-256", "content": "c" * 64}]
                )
        inventory["relationships"] = {
            "items": [{"from": "app", "to": "lib", "kind": "DEPENDS_ON", "origin": "test"}]
        }
        sections["vulnerabilities"]["claim"]["advisory"]["affects"] = [{"ref": "lib"}]
        if not legacy:
            inventory["identity"] = reconcile_lineages(
                {}, inventory, project_id="project", version="7.1.1"
            )

    seed(journal, modify=modify)
    save(journal, assessment(journal))
    review(journal)
    return head(journal)


def rename(journal, *, version="7.1.1", change=None, refs=None, team="A"):
    parent = head(journal)
    previous = current(journal)["inventory"]
    refs = refs or {"app": "app-new", "lib": "lib-new"}

    def modify(sections):
        inventory = sections["inventory"]
        inventory["root"]["bom-ref"] = refs["app"]
        component = inventory.pop("component:lib")
        component["bom-ref"] = refs["lib"]
        component["dtvp_origin"]["ref"] = refs["lib"]
        inventory["component:" + refs["lib"]] = component
        for edge in inventory["dependencies"]["edges"]:
            edge["ref"] = refs[edge["ref"]]
            edge["dependsOn"] = [refs[ref] for ref in edge["dependsOn"]]
        for edge in inventory["relationships"]["items"]:
            edge["from"], edge["to"] = refs[edge["from"]], refs[edge["to"]]
        claim = sections["vulnerabilities"]["claim"]
        claim["ref"] = refs["lib"]
        claim["advisory"]["affects"][0]["ref"] = refs["lib"]
        inventory["baseline"]["artifact_sha"] = "b" * 64
        if change:
            change(sections)
        inventory["identity"] = reconcile_lineages(
            previous,
            inventory,
            project_id="project",
            version=version,
            previous_state=parent,
            previous_version="7.1.1",
        )

    return seed(journal, version=version, parent=parent, modify=modify, team=team)


def selected(journal, *, version="7.1.1", root="app-new"):
    sections = current(journal, version)
    context = next(
        context
        for key, context in sections["ownership"].items()
        if key.startswith("context:")
        and context["component_ref"] == "lib-new"
        and context["root_ref"] == root
    )
    return Target(version=version, context_id=context["id"], vulnerability_id="CVE-2026-0001")


def test_reference_rename_preserves_approval_without_rewriting_review(journal):
    source = initial(journal)
    original = deepcopy(current(journal)["reviews"])
    rename(journal)
    target = selected(journal)
    sections = current(journal)
    result = coverage_status(journal, sections, **target.model_dump())
    assert result["approved"]
    assert result["continuity"]["source_state"] == source
    assert result["review"]["target"]["context_id"] != target.context_id
    assert result["fingerprint"] != result["review"]["target"]["fingerprint"]
    assert sections["reviews"] == original
    assert load_sections(journal, source)["reviews"] == original


@pytest.mark.parametrize(
    "change",
    [
        lambda s: s["inventory"]["component:lib-new"].update(version="2", purl="pkg:generic/lib@2"),
        lambda s: s["inventory"]["component:lib-new"].update(
            properties=[{"name": "exposure", "value": "internet"}]
        ),
        lambda s: s["inventory"]["component:lib-new"].update(
            description="Changed descriptive text"
        ),
        lambda s: s["vulnerabilities"]["claim"]["advisory"].update(
            description="Changed advisory evidence"
        ),
        lambda s: s["vulnerabilities"]["claim"]["advisory"].update(severity="critical"),
        lambda s: s["inventory"]["baseline"]["collection"].update(target="windows"),
        lambda s: s["inventory"]["relationships"]["items"][0].update(kind="CONTAINS"),
        lambda s: s["vulnerabilities"]["claim"].update(controls={"ref": "lib-new"}),
    ],
)
def test_material_or_unknown_metadata_change_requires_revalidation(journal, change):
    initial(journal)
    rename(journal, change=change)
    result = coverage_status(journal, current(journal), **selected(journal).model_dump())
    assert not result["approved"]


def test_missing_root_identity_does_not_bridge(journal):
    initial(journal, root_identity=False)
    rename(journal)
    assert approval_bridge(journal, current(journal), **selected(journal).model_dump()) is None


def test_legacy_preledger_review_can_be_proved_by_bootstrap(journal):
    initial(journal, legacy=True)
    rename(journal)
    assert coverage_status(journal, current(journal), **selected(journal).model_dump())["approved"]


def test_new_version_never_inherits_review(journal):
    initial(journal)
    rename(journal)
    sections = current(journal)
    sections["inventory"]["identity"]["scope"]["version"] = "7.1.2"
    state = journal.snapshot(
        project_id="project",
        version="7.1.2",
        actor_id="pipeline",
        reason="New version",
        sections=sections,
        parents=[head(journal)],
    )
    journal.publish(
        request_id="branch-new-version",
        fingerprint=digest(state.encode()),
        updates=[Update(ref=Ref(project_id="project", name="7.1.2"), expected=None, target=state)],
    )
    assert not coverage_status(
        journal, current(journal, "7.1.2"), **selected(journal, version="7.1.2").model_dump()
    )["approved"]


def test_new_context_never_inherits_review(journal):
    initial(journal)

    def change(sections):
        inventory = sections["inventory"]
        inventory["component:other"] = {
            "bom-ref": "other",
            "name": "other",
            "version": "1",
            "purl": "pkg:generic/other@1",
        }
        inventory["dependencies"]["edges"].append({"ref": "other", "dependsOn": ["lib-new"]})

    rename(journal, change=change)
    assert not coverage_status(
        journal, current(journal), **selected(journal, root="other").model_dump()
    )["approved"]


def test_removed_component_retains_historical_assessment(journal):
    initial(journal)
    original = next(iter(current(journal)["reviews"].values()))["target"]

    def remove(sections):
        sections["inventory"].pop("component:lib")
        sections["inventory"]["dependencies"]["edges"] = [{"ref": "app", "dependsOn": []}]
        sections["inventory"]["relationships"]["items"] = []
        sections["vulnerabilities"] = {}
        sections["inventory"].pop("identity")

    seed(journal, parent=head(journal), modify=remove)
    result = coverage_status(
        journal,
        current(journal),
        **{k: original[k] for k in ("version", "context_id", "vulnerability_id")},
    )
    assert result["status"] == "historically_absent"
    assert result["recorded"]


def test_ambiguous_package_occurrences_block_bridge(journal):
    initial(journal)

    def duplicate(sections):
        sections["inventory"]["component:duplicate"] = {
            "bom-ref": "duplicate",
            "name": "lib",
            "version": "1",
            "purl": "pkg:generic/lib@1",
        }
        sections["inventory"]["dependencies"]["edges"][0]["dependsOn"].append("duplicate")

    rename(journal, change=duplicate)
    assert not coverage_status(journal, current(journal), **selected(journal).model_dump())[
        "approved"
    ]


def test_original_fingerprint_contract_unchanged(journal):
    initial(journal)
    sections = current(journal)
    reviewed = next(iter(sections["reviews"].values()))["target"]
    assert (
        target_fingerprint(
            sections, reviewed["version"], reviewed["context_id"], reviewed["vulnerability_id"]
        )
        == reviewed["fingerprint"]
    )


def test_real_part_assembly_reference_rename_keeps_review(journal):
    from dtvp.knowledge.assembly import AssemblyInput, build_assembly_candidate, namespaced_ref
    from dtvp.knowledge.ownership import resolve_ownership
    from dtvp.knowledge.service import import_inventory

    def document(suffix):
        root, lib = "app" + suffix, "lib" + suffix
        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "metadata": {
                "component": {
                    "bom-ref": root,
                    "name": "app",
                    "version": "1",
                    "type": "application",
                    "purl": "pkg:generic/app@1",
                }
            },
            "components": [
                {
                    "bom-ref": lib,
                    "name": "lib",
                    "version": "1",
                    "type": "library",
                    "purl": "pkg:generic/lib@1",
                }
            ],
            "dependencies": [{"ref": root, "dependsOn": [lib]}, {"ref": lib, "dependsOn": []}],
            "vulnerabilities": [
                {"id": "CVE-2026-0001", "description": "A defect", "affects": [{"ref": lib}]}
            ],
        }

    def part(suffix, previous=None):
        return (
            import_inventory(
                journal,
                project_id="project",
                version="7.1.1",
                actor_id="pipeline",
                request_id="part" + suffix,
                expected=previous,
                source="nightly",
                build_number=2 if previous else 1,
                occurred_at="2026-10-15T00:00:00+00:00",
                part_id="engine",
                sbom=document(suffix),
            )[1]
            .updates[0]
            .target
        )

    def assemble(source, parent=None):
        candidate = build_assembly_candidate(
            journal,
            project_id="project",
            version="7.1.1",
            data=AssemblyInput(
                request_id="assembly-" + source,
                expected=parent,
                parts=[{"part_id": "engine", "state": source, "required": True}],
            ),
        )
        sections = candidate["sections"]
        resolve_ownership(
            sections,
            version="7.1.1",
            config={
                "rules": [{"selector": "*", "team_id": "A"}],
                "context_roots": {},
            },
        )
        state = journal.snapshot(
            project_id="project",
            version="7.1.1",
            actor_id="pipeline",
            reason="Assemble",
            sections=sections,
            parents=candidate["parents"],
            artifacts=candidate["artifacts"],
        )
        journal.publish(
            request_id="assembly-" + source,
            fingerprint=digest(state.encode()),
            updates=[
                Update(ref=Ref(project_id="project", name="7.1.1"), expected=parent, target=state)
            ],
        )
        context = next(
            item
            for key, item in sections["ownership"].items()
            if key.startswith("context:")
            and item["component_ref"]
            == namespaced_ref("engine", "lib" + ("-new" if source != first else ""))
        )
        return Target(version="7.1.1", context_id=context["id"], vulnerability_id="CVE-2026-0001")

    first = part("")
    old_target = assemble(first)
    save(journal, assessment(journal, targets=[old_target]))
    review(journal, selected=[old_target])
    reviewed = head(journal)
    second = part("-new", previous=first)
    new_target = assemble(second, parent=reviewed)
    result = coverage_status(journal, current(journal), **new_target.model_dump())
    assert result["approved"]
    assert result["continuity"]["source_state"] == reviewed


def test_team_reassignment_keeps_historical_review_after_reference_rename(journal):
    initial(journal)
    rename(journal, team="B")
    result = coverage_status(journal, current(journal), **selected(journal).model_dump())
    assert result["approved"]
    assert result["team_id"] == "B"
    assert result["historical_team_id"] == "A"


@pytest.mark.parametrize("marker, approved", [("digest", True), ("none", False)])
def test_optional_purl_requires_other_strong_continuity(journal, marker, approved):
    initial(journal, component_marker=marker)
    rename(journal)
    assert (
        coverage_status(journal, current(journal), **selected(journal).model_dump())["approved"]
        is approved
    )


def test_arbitrary_nested_reference_metadata_is_not_normalized(journal):
    initial(journal)

    def add(sections):
        sections["vulnerabilities"]["claim"]["advisory"]["custom_control"] = {"ref": "lib"}

    seed(journal, parent=head(journal), modify=add)
    save(
        journal,
        assessment(
            journal,
            request_id="updated-assessment",
            expected_revision=current(journal)["assessments"]["assessment:decision"]["revision"],
        ),
    )
    review(journal, request_id="updated-review")

    def change(sections):
        sections["vulnerabilities"]["claim"]["advisory"]["custom_control"]["ref"] = "lib-new"

    rename(journal, change=change)
    assert not coverage_status(journal, current(journal), **selected(journal).model_dump())[
        "approved"
    ]


def pipeline_configuration():
    return {
        "models": [
            {
                "model_id": "model",
                "revision": "1",
                "digest_sha256": "c" * 64,
                "entities": [
                    {"entity_id": "engine", "name": "Processing engine", "external": False}
                ],
            }
        ],
        "mappings": [
            {
                "mapping_id": "lib-engine",
                "component_selector": "lib",
                "context_selector": "app",
                "model_id": "model",
                "entity_ids": ["engine"],
                "legacy_names": [],
            }
        ],
    }


@pytest.mark.parametrize(
    "change",
    [
        lambda c: c["models"][0].update(revision="2"),
        lambda c: c["models"][0].update(digest_sha256="d" * 64),
        lambda c: c["models"][0]["entities"][0].update(name="Other role"),
        lambda c: c["mappings"][0].update(legacy_names=["legacy-engine"]),
        lambda c: c.update(mappings=[]),
    ],
)
def test_effective_model_context_changes_invalidate_bridge(journal, change):
    initial(journal, configuration=pipeline_configuration())

    def modify(sections):
        change(sections["inventory"]["pipeline_configuration"]["configuration"])

    rename(journal, change=modify)
    assert not coverage_status(journal, current(journal), **selected(journal).model_dump())[
        "approved"
    ]


def test_unrelated_pipeline_rule_and_pointer_edits_do_not_reopen(journal):
    initial(journal, configuration=pipeline_configuration())

    def modify(sections):
        pipeline = sections["inventory"]["pipeline_configuration"]
        pipeline["state"] = "d" * 64
        pipeline["configuration"]["mappings"].append(
            {
                "mapping_id": "unrelated",
                "component_selector": "other",
                "context_selector": None,
                "model_id": "model",
                "entity_ids": ["engine"],
                "legacy_names": ["Other"],
            }
        )

    rename(journal, change=modify)
    assert coverage_status(journal, current(journal), **selected(journal).model_dump())["approved"]


def test_pipeline_material_is_limited_to_its_consuming_context(journal):
    from dtvp.knowledge.ownership import resolve_ownership

    initial(journal, configuration=pipeline_configuration())
    sections = current(journal)
    sections["inventory"]["component:other"] = {
        "bom-ref": "other",
        "name": "other",
        "version": "1",
        "purl": "pkg:generic/other@1",
    }
    sections["inventory"]["dependencies"]["edges"].append({"ref": "other", "dependsOn": ["lib"]})
    resolve_ownership(
        sections,
        version="7.1.1",
        config={
            "rules": [{"selector": "*", "team_id": "A"}],
            "context_roots": {},
        },
    )
    contexts = [
        value
        for key, value in sections["ownership"].items()
        if key.startswith("context:") and value["component_ref"] == "lib"
    ]
    assert len(contexts) == 2
    before = {
        c["root_ref"]: target_fingerprint(sections, "7.1.1", c["id"], "CVE-2026-0001")
        for c in contexts
    }
    sections["inventory"]["pipeline_configuration"]["configuration"]["models"][0]["revision"] = "2"
    after = {
        c["root_ref"]: target_fingerprint(sections, "7.1.1", c["id"], "CVE-2026-0001")
        for c in contexts
    }
    assert before["app"] != after["app"]
    assert before["other"] == after["other"]


def test_workspace_and_coordinator_gate_use_current_bridged_scope(journal):
    from dtvp.knowledge.scoring import review_gate
    from dtvp.knowledge.workspace import load_workspace

    initial(journal)
    rename(journal)
    workspace = load_workspace(journal, head(journal))
    assert workspace["items"][0]["coverage"]["approved"]
    assert workspace["items"][0]["coverage"]["continuity"]["source_context_id"]
    assert review_gate(journal, current(journal), "7.1.1", "CVE-2026-0001")["ready"]


def test_request_local_resolver_does_not_reload_historical_states(journal, monkeypatch):
    from dtvp.knowledge import assessments
    from dtvp.knowledge.assessment_continuity import ApprovalContinuityResolver

    initial(journal)
    rename(journal)
    resolver = ApprovalContinuityResolver(journal, current(journal), "7.1.1", state=head(journal))
    target = selected(journal)
    assert resolver(target.context_id, target.vulnerability_id)
    monkeypatch.setattr(
        assessments, "load_sections", lambda *args: pytest.fail("Repeated historical load")
    )
    assert resolver(target.context_id, target.vulnerability_id)


def test_unqualified_additional_approval_cannot_hide_ambiguity(journal):
    initial(journal)
    rename(journal)
    sections = current(journal)
    duplicate = deepcopy(next(iter(sections["reviews"].values())))
    duplicate["target"]["context_id"] = "f" * 64
    sections["reviews"]["unqualified-review"] = duplicate
    assert approval_bridge(journal, sections, **selected(journal).model_dump()) is None
