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


@pytest.mark.parametrize("missing", ["reason", "pin", None])
def test_authority_rotation_requires_explicit_manager_policy_pin_and_reason(tmp_path, bom, missing):
    journal = Journal(tmp_path / "journal")
    base = dict(
        project_id="product",
        version="1",
        actor_id="pipeline",
        expected=None,
        source="build",
        build_number=50,
        occurred_at="2026-10-16T00:00:00Z",
        sbom=bom,
    )
    original = import_inventory(journal, request_id="old-build", **base)[1].updates[0].target
    config = (
        configure(
            journal,
            project_id="product",
            actor_id="manager",
            data=PipelineConfigInput(
                request_id="rotate-config",
                expected_policy=None,
                expected_versions={"1": original},
                reason="Replace retired build provider",
                parts=[
                    {"part_id": None, "authority_source": "new-build", "observation_sources": []}
                ],
            ),
        )[1]
        .updates[0]
        .target
    )
    changes = dict(
        expected=original,
        source="new-build",
        build_number=1,
        expected_configuration=config,
        authority_change_reason="Switch approved CI authority",
    )
    if missing == "reason":
        changes["authority_change_reason"] = ""
    if missing == "pin":
        changes["expected_configuration"] = None
    if missing:
        with pytest.raises(Conflict, match="authority"):
            import_inventory(journal, request_id="new-build", **(base | changes))
    else:
        receipt = import_inventory(journal, request_id="new-build", **(base | changes))
        sections = load_sections(journal, receipt[1].updates[0].target)
        assert sections["inventory"]["baseline"]["authority_change"] == {
            "previous_source": "build",
            "configuration": config,
            "reason": changes["authority_change_reason"],
        }
        assert sections["inventory"]["baseline"]["build_number"] == 1
        assert import_inventory(journal, request_id="new-build", **(base | changes)) == receipt
        assert load_sections(journal, original)["inventory"]["baseline"]["source"] == "build"
