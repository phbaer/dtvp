"""Consumers receive frozen model declarations scoped to their exact context."""

import copy

import pytest

from dtvp.knowledge.exports import (
    build_bundle,
    build_vscorer_worklist,
    contextual_pipeline_metadata,
)
from dtvp.knowledge.issued_exports import find_issued_export, issue_export, resolve_issued_export
from dtvp.knowledge.journal import Ref, Update
from dtvp.knowledge.pipeline_config import PipelineConfigInput, configure
from dtvp.knowledge.vscorer import derive_context_inputs
from dtvp.storage import canonical, digest
from tests.test_knowledge_vscorer import prepare
from tests.test_knowledge_workspace import workspace as source_workspace
from tests.test_rescoring import BASE

workspace = source_workspace


def setup(workspace, mappings=True):
    journal, old, context = prepare(workspace)
    config_input = PipelineConfigInput(
        request_id="metadata",
        expected_policy=None,
        expected_versions={},
        reason="CI declaration",
        models=[
            {
                "model_id": "model",
                "revision": "revision-one",
                "digest_sha256": "a" * 64,
                "entities": [{"entity_id": "explicit-id", "name": "Processing", "external": False}],
            }
        ],
        mappings=[
            {
                "mapping_id": "placement",
                "component_selector": "cs::acme:shared",
                "context_selector": "cs::acme:app-a",
                "model_id": "model",
                "entity_ids": ["explicit-id"],
                "legacy_names": ["Processing name"],
            }
        ]
        if mappings
        else [],
    )
    config = (
        configure(journal, project_id="product", actor_id="owner", data=config_input)[1]
        .updates[0]
        .target
    )
    sections = workspace[1]
    sections["inventory"]["pipeline_configuration"] = {"state": config}
    state = journal.snapshot(
        project_id="product",
        version="1",
        actor_id="CI",
        reason="Pinned metadata",
        sections=sections,
        parents=[old, config],
    )
    journal.publish(
        request_id="product-state",
        fingerprint=state,
        updates=[Update(ref=Ref(project_id="product", name="1"), expected=None, target=state)],
    )
    return journal, state, context, config, config_input


def test_bundle_and_worklist_use_exact_pinned_configuration_after_change(workspace):
    journal, state, context, policy, original = setup(workspace)
    first = canonical(build_bundle(journal, state))
    config_input = original.model_copy(
        update={
            "request_id": "change",
            "expected_policy": policy,
            "expected_versions": {"1": state},
            "mappings": [],
        }
    )
    configure(journal, project_id="product", actor_id="owner", data=config_input)
    assert canonical(build_bundle(journal, state)) == first
    bundle = build_bundle(journal, state)
    assert bundle["pipeline_context"]["configuration_state"] == policy
    assert bundle["pipeline_context"]["configuration"]["models"][0]["revision"] == "revision-one"
    assert build_vscorer_worklist(journal, state)["pipeline_context"] == bundle["pipeline_context"]
    subset = contextual_pipeline_metadata(bundle, context["id"])
    assert subset["models"][0]["entities"][0]["entity_id"] == "explicit-id"
    assert all(row["context_id"] == context["id"] for row in subset["rows"])
    other = next(
        row["context_id"]
        for row in bundle["pipeline_context"]["rows"]
        if row["component_ref"] == "shared" and row["root_ref"] == "app-b"
    )
    other_subset = contextual_pipeline_metadata(bundle, other)
    assert other_subset["models"] == [] and other_subset["unmapped"] == 1


def test_issued_vscorer_files_scope_and_recovery_remain_frozen(workspace, monkeypatch):
    journal, state, context, _, _ = setup(workspace)
    payload = derive_context_inputs(
        journal, state, context["id"], "shared", {"CVE-2099-10001": BASE}
    )
    assert payload["dtvp_source"]["artifacts"]["pipeline_context_sha256"] == digest(
        canonical(payload["pipeline_context"])
    )
    assert payload["pipeline_context"]["rows"][0]["mappings"][0]["legacy_names"] == [
        "Processing name"
    ]
    issued = issue_export(
        journal,
        project_id="product",
        actor_id="issuer",
        state=state,
        kind="vscorer-input",
        payload=payload,
        selector={"context_id": context["id"]},
    )
    assert issued["serializer_id"] == "dtvp.vscorer-input-serializer/3"
    artifact = issued["files"]["pipeline-context.json"]
    assert journal.objects.read(artifact["sha256"]) == canonical(payload["pipeline_context"])
    monkeypatch.setattr(
        "dtvp.knowledge.issued_exports.export_bytes",
        lambda *_: pytest.fail("Frozen inputs must not be serialized again"),
    )
    assert (
        resolve_issued_export(journal, "product", issued["receipt_sha256"])["files"]
        == issued["files"]
    )
    assert (
        find_issued_export(
            journal,
            "product",
            state=state,
            kind="vscorer-input",
            selector={"context_id": context["id"]},
        )["payload"]
        == payload
    )


def test_knowledge_bundle_uses_metadata_serializer_and_missing_mapping_diagnostic(workspace):
    journal, state, context, _, _ = setup(workspace, mappings=False)
    result = issue_export(
        journal, project_id="product", actor_id="issuer", state=state, kind="knowledge-bundle"
    )
    assert result["serializer_id"] == "dtvp.knowledge-bundle-serializer/3"
    assert result["payload"]["pipeline_context"]["unmapped"] > 0
    payload = derive_context_inputs(
        journal, state, context["id"], "shared", {"CVE-2099-10001": BASE}
    )
    assert payload["eligible"] and payload["pipeline_context"]["unmapped"] == 1
    assert payload["pipeline_context"]["models"] == []


def test_pipeline_file_cannot_be_replaced_or_omitted(workspace):
    journal, state, context, _, _ = setup(workspace)
    payload = derive_context_inputs(
        journal, state, context["id"], "shared", {"CVE-2099-10001": BASE}
    )
    wrong = copy.deepcopy(payload)
    wrong["pipeline_context"]["models"] = []
    wrong["dtvp_source"]["artifacts"]["pipeline_context_sha256"] = digest(
        canonical(wrong["pipeline_context"])
    )
    with pytest.raises(ValueError, match="differs from its pinned"):
        issue_export(
            journal,
            project_id="product",
            actor_id="issuer",
            state=state,
            kind="vscorer-input",
            payload=wrong,
        )
    missing = copy.deepcopy(payload)
    missing.pop("pipeline_context")
    with pytest.raises(ValueError, match="metadata is missing"):
        issue_export(
            journal,
            project_id="product",
            actor_id="issuer",
            state=state,
            kind="vscorer-input",
            payload=missing,
        )


def test_effective_mapping_material_ignores_other_contexts_and_rule_identity(workspace):
    from dtvp.knowledge.pipeline_config import context_material, resolve_sections, retained_config

    journal, state, context, policy, _ = setup(workspace)
    config = retained_config(journal, "product", policy)
    sections = workspace[1]
    material = context_material(config, sections, context)
    assert material[0]["entities"][0]["entity_id"] == "explicit-id"
    assert resolve_sections(config, sections)["total"] > 1
    renamed = copy.deepcopy(config)
    renamed["mappings"][0]["mapping_id"] = "renamed-rule"
    assert context_material(renamed, sections, context) == material
    renamed["models"].append(
        {"model_id": "unrelated", "revision": "one", "digest_sha256": "c" * 64, "entities": []}
    )
    assert context_material(renamed, sections, context) == material
    changed = copy.deepcopy(config)
    changed["models"][0]["digest_sha256"] = "b" * 64
    assert context_material(changed, sections, context) != material
    other_context = next(
        value
        for key, value in sections["ownership"].items()
        if key.startswith("context:")
        and value["component_ref"] == "shared"
        and value["root_ref"] == "app-b"
    )
    assert context_material(config, sections, other_context) == []
    assert context_material(changed, sections, other_context) == []
