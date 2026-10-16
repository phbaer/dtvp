"""Observation layers never replace authority without explicit pinned selection."""

import pytest

from dtvp.knowledge import observations as module
from dtvp.knowledge.journal import Conflict, Journal, Ref, Update
from dtvp.knowledge.pipeline_config import PipelineConfigInput, configure
from dtvp.knowledge.service import import_inventory
from dtvp.knowledge.workspace import load_sections
from dtvp.storage import canonical, digest

COLLECTION = {"subject_kind": "binary", "target": "runtime", "subject_digest": "sha256:" + "a" * 64}


def bom(prefix="", extra=False):
    components = [
        {
            "type": "library",
            "name": "lib",
            "version": "1",
            "bom-ref": prefix + "lib",
            "purl": "pkg:pypi/lib@1",
        }
    ]
    if extra:
        components.append(
            {
                "type": "library",
                "name": "extra",
                "version": "1",
                "bom-ref": prefix + "extra",
                "purl": "pkg:pypi/extra@1",
            }
        )
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": "app",
                "version": "1",
                "bom-ref": prefix + "app",
                "purl": "pkg:generic/app@1",
            }
        },
        "components": components,
        "dependencies": [
            {
                "ref": prefix + "app",
                "dependsOn": [component["bom-ref"] for component in components],
            },
            *[{"ref": component["bom-ref"], "dependsOn": []} for component in components],
        ],
        "vulnerabilities": [
            {
                "id": "CVE-2099-1234",
                "affects": [{"ref": prefix + "lib"}],
                "description": "Synthetic evidence",
            }
        ],
    }


def authority(journal, *, context=COLLECTION, config=None):
    return (
        import_inventory(
            journal,
            project_id="product",
            version="1",
            actor_id="CI",
            request_id="authority",
            expected=None,
            source="build",
            build_number=1,
            occurred_at="2026-10-16T00:00:00Z",
            sbom=bom(),
            context=context,
            expected_configuration=config,
        )[1]
        .updates[0]
        .target
    )


def inputs(head, **changes):
    return module.ObservationInput.model_validate(
        {
            "request_id": "scan",
            "source": "scanner",
            "expected": None,
            "expected_authority": head,
            "expected_configuration": None,
            "build_number": 1,
            "occurred_at": "2026-10-16T00:00:00Z",
            "context": COLLECTION,
            "sbom": bom("scan-", extra=True),
            **changes,
        }
    )


def ingest(journal, data):
    return module.import_observation(
        journal, project_id="product", version="1", source=data.source, actor_id="CI", data=data
    )


def selected(journal, head, observation, **changes):
    return module.ObservationSelection.model_validate(
        {
            "request_id": "select",
            "expected": head,
            "expected_configuration": None,
            "sources": [{"source": "scanner", "state": observation}],
            **changes,
        }
    )


def publish(journal, data):
    preview = module.build_selection(journal, project_id="product", version="1", data=data)[
        "preview"
    ]
    applied = data.model_copy(update={"preview_digest": preview["preview_digest"]})
    return module.publish_selection(
        journal, project_id="product", version="1", actor_id="analyst", data=applied
    ), applied


def test_intake_is_non_authoritative_and_selection_merges_matches_only(tmp_path):
    journal = Journal(tmp_path / "journal")
    head = authority(journal)
    original = load_sections(journal, head)
    data = inputs(head)
    receipt = ingest(journal, data)
    observation = receipt[1].updates[0].target
    assert journal.resolve(Ref(project_id="product", name="1")) == head
    assert load_sections(journal, head) == original
    assert ingest(journal, data) == receipt
    selection = selected(journal, head, observation)
    before = journal.head()
    candidate = module.build_selection(journal, project_id="product", version="1", data=selection)
    assert journal.head() == before
    assert (
        len([key for key in candidate["sections"]["inventory"] if key.startswith("component:")])
        == 1
    )
    assert len(candidate["sections"]["vulnerabilities"]) == 2
    assertions = candidate["sections"]["inventory"]["observation_assertions"]["components"]
    assert assertions["lib"][0]["component"]["bom-ref"] == "scan-lib"
    assert assertions["lib"][0]["state"] == observation
    assert candidate["sections"]["inventory"]["component:ref:lib"]["bom-ref"] == "lib"
    with pytest.raises(Conflict, match="preview"):
        module.publish_selection(
            journal, project_id="product", version="1", actor_id="analyst", data=selection
        )
    result, applied = publish(journal, selection)
    assert (
        module.publish_selection(
            journal, project_id="product", version="1", actor_id="analyst", data=applied
        )
        == result
    )
    assert journal.resolve(Ref(project_id="product", name="1")) == result[1].updates[0].target


def test_adoption_requires_reason_and_explicit_endpoints_then_omission_restores_authority(tmp_path):
    journal = Journal(tmp_path / "journal")
    head = authority(journal)
    observation = ingest(journal, inputs(head))[1].updates[0].target
    choice = {
        "source": "scanner",
        "state": observation,
        "accepted_components": ["scan-extra"],
        "accepted_relationships": [{"from": "scan-app", "to": "scan-extra", "kind": "DEPENDS_ON"}],
        "reason": "Review confirms omitted library",
    }
    selection = selected(journal, head, observation, sources=[choice])
    result, _ = publish(journal, selection)
    merged = result[1].updates[0].target
    sections = load_sections(journal, merged)
    with pytest.raises(ValueError, match="Removing adopted"):
        module.build_selection(
            journal, project_id="product", version="1", data=selected(journal, merged, observation)
        )
    extra = next(
        value
        for key, value in sections["inventory"].items()
        if key.startswith("component:") and value["name"] == "extra"
    )
    assert extra["bom-ref"].startswith("observation:")
    assert (
        extra["bom-ref"]
        in next(
            edge for edge in sections["inventory"]["dependencies"]["edges"] if edge["ref"] == "app"
        )["dependsOn"]
    )
    # Human history is preserved even when its component is later removed.
    sections["assessments"]["retained-example"] = {"historical": "unchanged"}
    manual = journal.snapshot(
        project_id="product",
        version="1",
        actor_id="test",
        reason="Retained decision",
        sections=sections,
        parents=[merged],
    )
    journal.publish(
        request_id="decision",
        fingerprint=manual,
        updates=[Update(ref=Ref(project_id="product", name="1"), expected=merged, target=manual)],
    )
    with pytest.raises(ValueError, match="removal requires"):
        module.build_selection(
            journal,
            project_id="product",
            version="1",
            data=selected(journal, manual, observation, sources=[]),
        )
    removed, _ = publish(
        journal,
        selected(
            journal,
            manual,
            observation,
            request_id="remove",
            sources=[],
            removal_reason="Drop obsolete scanner layer",
        ),
    )
    final = load_sections(journal, removed[1].updates[0].target)
    assert final["assessments"] == sections["assessments"]
    assert not any(
        value.get("name") == "extra"
        for key, value in final["inventory"].items()
        if key.startswith("component:")
    )
    assert extra["bom-ref"] in {
        value["bom-ref"]
        for key, value in load_sections(journal, merged)["inventory"].items()
        if key.startswith("component:")
    }


def test_subject_declaration_binds_exact_bytes_and_authorized_scope(tmp_path):
    journal = Journal(tmp_path / "journal")
    context = {"subject_kind": "binary", "target": "runtime"}
    head = authority(journal, context=context)
    data = inputs(head, context=context)
    with pytest.raises(ValueError, match="subject_digest_unknown"):
        ingest(journal, data)
    declaration = {
        "product_id": "product",
        "version": "1",
        "subject_id": "runtime",
        "build_id": "1",
        "authority_sbom_sha256": digest(canonical(bom())),
        "observation_sbom_sha256": digest(canonical(data.sbom)),
    }
    good = inputs(head, context=context, subject_declaration=declaration)
    assert ingest(journal, good)
    for key, value in [
        ("product_id", "other"),
        ("version", "2"),
        ("observation_sbom_sha256", "b" * 64),
    ]:
        with pytest.raises(ValueError):
            ingest(
                journal,
                inputs(
                    head,
                    context=context,
                    request_id="bad-" + key,
                    subject_declaration=declaration | {key: value},
                ),
            )


def test_config_roles_current_heads_source_revision_and_bounds_fail_closed(tmp_path, monkeypatch):
    journal = Journal(tmp_path / "journal")
    policy_data = PipelineConfigInput(
        request_id="config",
        expected_policy=None,
        expected_versions={},
        reason="CI source roles",
        parts=[{"authority_source": "build", "observation_sources": ["scanner"]}],
    )
    policy = (
        configure(journal, project_id="product", actor_id="manager", data=policy_data)[1]
        .updates[0]
        .target
    )
    head = authority(journal, config=policy)
    with pytest.raises(Conflict, match="configuration"):
        ingest(journal, inputs(head))
    observation = ingest(journal, inputs(head, expected_configuration=policy))[1].updates[0].target
    with pytest.raises(ValueError, match="not configured"):
        ingest(
            journal,
            inputs(
                head, request_id="wrong-source", source="unlisted", expected_configuration=policy
            ),
        )
    selection = selected(journal, head, observation, expected_configuration=policy)
    candidate = module.build_selection(journal, project_id="product", version="1", data=selection)
    assert candidate["sections"]["inventory"]["pipeline_configuration"]["configuration"]["parts"]
    with pytest.raises(Conflict, match="source changed"):
        ingest(
            journal,
            inputs(head, request_id="stale-source", expected_configuration=policy, build_number=2),
        )
    monkeypatch.setattr(module, "MAX_CANDIDATE_BYTES", 10)
    with pytest.raises(ValueError, match="bounds"):
        module.build_selection(journal, project_id="product", version="1", data=selection)


def test_two_observations_deduplicate_only_unique_scoped_strong_identity(tmp_path):
    journal = Journal(tmp_path / "journal")
    head = authority(journal)
    one = ingest(journal, inputs(head))[1].updates[0].target
    second_bom = bom("other-", extra=True)
    second_bom["components"][1]["description"] = "Alternative scanner claim"
    two = (
        ingest(journal, inputs(head, request_id="other", source="scanner-two", sbom=second_bom))[1]
        .updates[0]
        .target
    )
    choices = [
        {
            "source": source,
            "state": state,
            "accepted_components": [prefix + "extra"],
            "accepted_relationships": [
                {"from": prefix + "app", "to": prefix + "extra", "kind": "DEPENDS_ON"}
            ],
            "reason": "Explicit library adoption",
        }
        for source, state, prefix in [("scanner", one, "scan-"), ("scanner-two", two, "other-")]
    ]
    value = selected(journal, head, one, sources=choices)
    candidate = module.build_selection(journal, project_id="product", version="1", data=value)
    extras = [
        component
        for key, component in candidate["sections"]["inventory"].items()
        if key.startswith("component:") and component["name"] == "extra"
    ]
    assert len(extras) == 1
    assert {origin["source"] for origin in extras[0]["dtvp_observations"]} == {
        "scanner",
        "scanner-two",
    }
    assert "description" in extras[0]["dtvp_observation_conflicts"]
    assertions = candidate["sections"]["inventory"]["observation_assertions"]["components"][
        extras[0]["bom-ref"]
    ]
    assert len(assertions) == 2
    assert assertions[1]["component"]["description"] == "Alternative scanner claim"
    reversed_value = value.model_copy(update={"sources": list(reversed(value.sources))})
    assert (
        module.build_selection(journal, project_id="product", version="1", data=reversed_value)[
            "sections"
        ]
        == candidate["sections"]
    )


@pytest.mark.parametrize("difference", ["location", "hash", "duplicate"])
def test_adopted_identity_conflicts_and_duplicate_occurrences_remain_separate(tmp_path, difference):
    journal = Journal(tmp_path / "journal")
    head = authority(journal)
    first_bom, second_bom = bom("scan-", extra=True), bom("other-", extra=True)
    if difference == "location":
        first_bom["components"][1]["evidence"] = {"occurrences": [{"location": "/first/lib"}]}
        second_bom["components"][1]["evidence"] = {"occurrences": [{"location": "/second/lib"}]}
    elif difference == "hash":
        first_bom["components"][1]["hashes"] = [{"alg": "SHA-256", "content": "a" * 64}]
        second_bom["components"][1]["hashes"] = [{"alg": "SHA-256", "content": "b" * 64}]
    else:
        duplicate = dict(second_bom["components"][1], **{"bom-ref": "other-extra-two"})
        second_bom["components"].append(duplicate)
        second_bom["dependencies"].append({"ref": "other-extra-two", "dependsOn": []})
    one = ingest(journal, inputs(head, sbom=first_bom))[1].updates[0].target
    two = (
        ingest(journal, inputs(head, request_id="other", source="scanner-two", sbom=second_bom))[1]
        .updates[0]
        .target
    )
    choices = [
        {
            "source": "scanner",
            "state": one,
            "accepted_components": ["scan-extra"],
            "reason": "Explicitly retain",
        },
        {
            "source": "scanner-two",
            "state": two,
            "accepted_components": ["other-extra"],
            "reason": "Explicitly retain",
        },
    ]
    candidate = module.build_selection(
        journal,
        project_id="product",
        version="1",
        data=selected(journal, head, one, sources=choices),
    )
    extras = [
        component
        for key, component in candidate["sections"]["inventory"].items()
        if key.startswith("component:") and component["name"] == "extra"
    ]
    assert len(extras) == 2
