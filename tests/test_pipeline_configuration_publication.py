"""Publication pins declared source roles and rejects configuration races."""

import pytest

from dtvp.api_assembly_editor import preview_candidate
from dtvp.knowledge.assembly import publish_assembly
from dtvp.knowledge.journal import Conflict, Journal
from dtvp.knowledge.pipeline_config import PipelineConfigInput, configure, current_config
from dtvp.knowledge.service import import_inventory
from dtvp.knowledge.workspace import load_sections
from tests.test_knowledge_assembly_candidate import data, part


def configure_parts(journal, parts, *, request="config"):
    previous, _ = current_config(journal, "product")
    return (
        configure(
            journal,
            project_id="product",
            actor_id="manager",
            data=PipelineConfigInput(
                request_id=request,
                expected_policy=previous,
                expected_versions={},
                reason="CI ownership",
                parts=parts,
            ),
        )[1]
        .updates[0]
        .target
    )


def test_single_import_pins_exact_configuration_and_role_before_publication(tmp_path, bom):
    journal = Journal(tmp_path / "journal")
    config = configure_parts(
        journal,
        [{"part_id": None, "authority_source": "build", "observation_sources": ["scanner"]}],
    )
    kwargs = dict(
        project_id="product",
        version="1",
        actor_id="pipeline",
        request_id="build",
        expected=None,
        source="build",
        build_number=1,
        occurred_at="2026-10-16T00:00:00Z",
        sbom=bom,
        expected_configuration=config,
    )
    with pytest.raises(Conflict, match="configuration"):
        import_inventory(journal, **(kwargs | {"expected_configuration": "a" * 64}))
    with pytest.raises(ValueError, match="role"):
        import_inventory(journal, **(kwargs | {"source": "scanner"}))
    receipt = import_inventory(journal, **kwargs)
    state = receipt[1].updates[0].target
    pinned = load_sections(journal, state)["inventory"]["pipeline_configuration"]
    assert pinned == {"state": config, "configuration": current_config(journal, "product")[1]}
    assert config in journal.state(state).parents
    assert import_inventory(journal, **kwargs) == receipt


def test_assembly_preview_pins_policy_and_apply_rejects_changed_configuration(tmp_path, bom):
    journal = Journal(tmp_path / "journal")
    first = configure_parts(
        journal,
        [
            {
                "part_id": "application",
                "authority_source": "CI:application",
                "observation_sources": [],
            }
        ],
    )
    source = part(journal, bom)
    selection = data(source)
    preview = preview_candidate(journal, "product", "1", selection)
    assert preview["configuration_state"] == first
    second = configure_parts(
        journal,
        [
            {
                "part_id": "application",
                "authority_source": "CI:application",
                "observation_sources": ["scanner"],
            }
        ],
        request="update",
    )
    assert (
        preview_candidate(journal, "product", "1", selection)["preview_digest"]
        != preview["preview_digest"]
    )
    with pytest.raises(Conflict, match="configuration"):
        publish_assembly(
            journal,
            project_id="product",
            version="1",
            actor_id="pipeline",
            data=selection,
            configuration_guard=first,
        )
    state = (
        publish_assembly(
            journal,
            project_id="product",
            version="1",
            actor_id="pipeline",
            data=selection,
            configuration_guard=second,
        )[1]
        .updates[0]
        .target
    )
    assert load_sections(journal, state)["inventory"]["pipeline_configuration"]["state"] == second
