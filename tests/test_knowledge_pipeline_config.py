"""Pinned user/CI declarations preserve incomplete input and external identity."""

import pytest
from pydantic import ValidationError

from dtvp.knowledge import pipeline_config as module
from dtvp.knowledge.journal import Conflict, Journal
from tests.test_identity_matches import inventory, publish


def data(**changes):
    return module.PipelineConfigInput.model_validate(
        {
            "request_id": "configure",
            "expected_policy": None,
            "expected_versions": {},
            "reason": "CI owner mapping",
            "parts": [
                {
                    "part_id": None,
                    "authority_source": "build",
                    "observation_sources": ["binary-scan"],
                }
            ],
            "models": [
                {
                    "model_id": "model",
                    "revision": "git-revision",
                    "digest_sha256": "a" * 64,
                    "entities": [
                        {"entity_id": "guid-1", "name": "Processing", "external": False},
                        {"entity_id": "guid-2", "name": "External device", "external": True},
                    ],
                }
            ],
            "mappings": [
                {
                    "mapping_id": "library",
                    "component_selector": "cs::org.example:lib",
                    "model_id": "model",
                    "entity_ids": ["guid-1", "guid-2"],
                    "legacy_names": ["Processing (legacy name)"],
                }
            ],
            **changes,
        }
    )


def apply(journal, value):
    return module.configure(journal, project_id="project", actor_id="manager", data=value)


def test_revision_history_exact_retry_and_scope(tmp_path):
    journal = Journal(tmp_path / "journal")
    first = apply(journal, data())
    sha = first[1].updates[0].target
    assert module.current_config(journal, "project")[0] == sha
    later = (
        apply(journal, data(request_id="later", expected_policy=sha, mappings=[]))[1]
        .updates[0]
        .target
    )
    assert later != sha
    assert apply(journal, data()) == first
    assert module.retained_config(journal, "project", sha)["mappings"][0]["legacy_names"] == [
        "Processing (legacy name)"
    ]
    with pytest.raises(ValueError, match="not retained"):
        module.retained_config(journal, "other", sha)
    with pytest.raises(Conflict):
        apply(journal, data(request_id="stale"))
    assert len(journal.references()) == 1


def test_heads_are_frozen_without_mutating_product_state(tmp_path):
    journal = Journal(tmp_path / "journal")
    state = publish(journal, inventory())
    with pytest.raises(Conflict):
        apply(journal, data())
    result = apply(journal, data(expected_versions={"1": state}))
    assert len(result[1].updates) == 1
    assert journal.resolve(module.Ref(project_id="project", name="1")) == state
    assert not journal.records(result[1].updates[0].target, "assessments")


def test_namespace_case_multiple_entities_and_missing_fields(tmp_path):
    journal = Journal(tmp_path / "journal")
    source = inventory()
    source["component:old"].update(group="org.example")
    source["component:unknown"] = {"bom-ref": "unknown", "name": "unknown"}
    state = publish(journal, source)
    policy = apply(journal, data(expected_versions={"1": state}))[1].updates[0].target
    result = module.resolve_context(
        journal, project_id="project", state=state, configuration=policy, limit=1
    )
    assert result["total"] == 2 and result["unmapped"] == 1 and result["next_offset"] == 1
    second = module.resolve_context(
        journal, project_id="project", state=state, configuration=policy, offset=1, limit=1
    )
    assert second["digest"] == result["digest"]
    mapped = next(row for row in result["rows"] + second["rows"] if row["status"] == "mapped")
    assert mapped["mappings"][0]["entity_ids"] == ["guid-1", "guid-2"]
    assert mapped["mappings"][0]["model_sha256"] == "a" * 64
    assert result["unused_mapping_ids"] == []
    unpublished = journal.snapshot(
        project_id="project",
        version="1",
        actor_id="actor",
        reason="Unpublished",
        sections={section: {} for section in module.SECTIONS},
    )
    with pytest.raises(ValueError, match="committed"):
        module.resolve_context(
            journal, project_id="project", state=unpublished, configuration=policy
        )


@pytest.mark.parametrize(
    "change",
    [
        {"parts": [{"authority_source": "same", "observation_sources": ["same"]}]},
        {
            "models": [
                {
                    "model_id": "model",
                    "revision": "one",
                    "digest_sha256": "a" * 64,
                    "entities": [
                        {"entity_id": "same", "name": "one"},
                        {"entity_id": "same", "name": "two"},
                    ],
                }
            ]
        },
        {
            "mappings": [
                {
                    "mapping_id": "unknown",
                    "component_selector": "lib",
                    "model_id": "unknown",
                    "entity_ids": ["guid-1"],
                }
            ]
        },
        {
            "mappings": [
                {
                    "mapping_id": "all",
                    "component_selector": "*",
                    "model_id": "model",
                    "entity_ids": ["guid-1"],
                }
            ]
        },
    ],
)
def test_invalid_declarations_rejected(change):
    with pytest.raises(ValidationError):
        data(**change)


def test_authority_roles_are_explicit_and_provider_independent():
    config = module.PipelineConfiguration.model_validate(
        data().model_dump(include=set(module.PipelineConfiguration.model_fields))
    ).model_dump(mode="json")
    module.validate_source_role(config, None, "build", "authority")
    module.validate_source_role(config, None, "binary-scan", "observation")
    module.validate_source_role(None, None, "anything", "observation")
    for part, source, role in [
        (None, "binary-scan", "authority"),
        (None, "other", "observation"),
        ("missing", "build", "authority"),
    ]:
        with pytest.raises(ValueError):
            module.validate_source_role(config, part, source, role)


def test_context_selectors_are_independent_and_no_name_to_id_guessing(tmp_path):
    journal = Journal(tmp_path / "journal")
    sections = {name: {} for name in module.SECTIONS}
    sections["inventory"] = inventory() | {
        "root": {"bom-ref": "application", "name": "Application"},
    }
    sections["ownership"] = {
        "context:one": {"id": "one", "component_ref": "old", "root_ref": "application"},
        "context:two": {"id": "two", "component_ref": "old", "root_ref": "other"},
    }
    state = journal.snapshot(
        project_id="project",
        version="1",
        actor_id="test",
        reason="Context inventory",
        sections=sections,
    )
    journal.publish(
        request_id="inventory",
        fingerprint=state,
        updates=[
            module.Update(
                ref=module.Ref(project_id="project", name="1"), expected=None, target=state
            )
        ],
    )
    mapping = data().mappings[0].model_dump() | {
        "component_selector": "purl::pkg:maven/org.example/lib@1",
        "context_selector": "cs::Application",
    }
    policy = (
        apply(journal, data(expected_versions={"1": state}, mappings=[mapping]))[1]
        .updates[0]
        .target
    )
    report = module.resolve_context(
        journal, project_id="project", state=state, configuration=policy
    )
    assert report["total"] == 2 and report["unmapped"] == 1
    assert next(row for row in report["rows"] if row["context_id"] == "one")["status"] == "mapped"
    invalid = mapping | {"entity_ids": ["Processing"]}
    with pytest.raises(ValidationError, match="unknown model or entity"):
        data(mappings=[invalid])


def test_new_branch_race_is_rejected_at_atomic_publication(tmp_path, monkeypatch):
    journal = Journal(tmp_path / "journal")
    original_publish = journal.publish

    def racing_publish(**kwargs):
        monkeypatch.setattr(journal, "publish", original_publish)
        publish(journal, inventory())
        return original_publish(**kwargs)

    monkeypatch.setattr(journal, "publish", racing_publish)
    with pytest.raises(Conflict, match="versions changed"):
        apply(journal, data())
    assert module.current_config(journal, "project")[0] is None
