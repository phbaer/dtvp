"""Qualified repository inputs never confuse project releases with package versions."""

import copy
import json
from uuid import uuid4

import pytest
from pydantic import ValidationError

from dtvp.knowledge.agentyzer import AgentyzerSourceReceipt, derive_analysis_input
from dtvp.knowledge.assembly import AssemblyInput, namespaced_ref, publish_assembly
from dtvp.knowledge.assessments import target_fingerprint
from dtvp.knowledge.composition import AnalysisSource, CollectionContext, collection_summary
from dtvp.knowledge.journal import Journal
from dtvp.knowledge.service import import_inventory
from dtvp.knowledge.workspace import load_sections
from dtvp.parsers import parse
from dtvp.storage import canonical, digest

COMMIT = "a" * 40
VERSION = "7.1.1"
VULNERABILITY = "CVE-2099-20001"


@pytest.fixture
def journal(tmp_path):
    return Journal(tmp_path / "journal")


def imported(journal, bom, *, part_id=None, context=None, expected=None, build_number=1):
    result = import_inventory(
        journal,
        project_id="product",
        version=VERSION,
        actor_id="pipeline",
        request_id=str(uuid4()),
        expected=expected,
        source="CI/main",
        build_number=build_number,
        occurred_at="2026-10-15T01:00:00+00:00",
        sbom=bom,
        context=context,
        part_id=part_id,
    )
    return result[1].updates[0].target


def qualified(repository="gateway", commit=COMMIT):
    return CollectionContext(
        analysis_source={"repository_name": repository, "source_commit": commit},
        subject_kind="build",
        subject_digest="sha256:" + "f" * 64,
    ).model_dump(mode="json")


def context_for(journal, state, ref="http"):
    return next(
        value
        for key, value in load_sections(journal, state)["ownership"].items()
        if key.startswith("context:") and value["component_ref"] == ref
    )


def derive(journal, state, ref="http"):
    return derive_analysis_input(
        journal, state, context_for(journal, state, ref)["id"], VULNERABILITY
    )


def test_typed_source_qualification_preserves_existing_default_serialization(bom):
    default = CollectionContext()
    expected = {
        "subject_kind": "unknown",
        "subject_digest": None,
        "target": None,
        "platform": None,
        "configuration": None,
        "source_revision": None,
        "pipeline_run": None,
        "collector": None,
        "collector_version": None,
        "method": "unknown",
        "package_coverage": "unknown",
        "dependency_coverage": "unknown",
        "license_coverage": "unknown",
        "limitations": [],
    }
    assert default.model_dump(mode="json") == expected
    assert json.loads(default.model_dump_json()) == expected
    assert CollectionContext(analysis_source=None).model_dump(mode="json") == expected
    summary = collection_summary(parse(canonical(bom)), default)
    assert summary["collection"] == expected
    assert "analysis_source" not in summary["collection"]
    source = AnalysisSource(repository_name="Gateway", source_commit="B" * 40)
    assert source.model_dump() == {"repository_name": "Gateway", "source_commit": "b" * 40}


@pytest.mark.parametrize("commit", ["HEAD", "main", "a" * 39, "a" * 41, "z" * 40, "sha1:" + COMMIT])
def test_qualified_source_requires_full_git_commit(commit):
    with pytest.raises(ValidationError):
        CollectionContext(analysis_source={"repository_name": "gateway", "source_commit": commit})


def test_repository_name_is_nonempty_and_normalized():
    with pytest.raises(ValidationError):
        AnalysisSource(repository_name=" \t ", source_commit=COMMIT)
    assert (
        AnalysisSource(repository_name=" gateway ", source_commit=COMMIT).repository_name
        == "gateway"
    )


def test_rooted_qualified_source_pins_request_target_and_artifacts(journal, bom):
    state = imported(journal, bom, context=qualified())
    before = journal.head()
    result = derive(journal, state)
    assert journal.head() == before
    assert result["ready_to_submit"]
    assert result["request"] == {
        "component_name": "gateway",
        "vuln_id": VULNERABILITY,
        "project_versions": [VERSION],
        "assessment_scope": "repository",
        "source_commit": COMMIT,
    }
    receipt = AgentyzerSourceReceipt.model_validate(result["receipt"])
    assert receipt.state == state and receipt.source_state == state
    assert receipt.focal_component["version"] == "1.2.0"
    assert receipt.focal_component["purl"] == "pkg:npm/demo-http@1.2.0"
    assert receipt.version == VERSION
    assert receipt.subject_digest == "sha256:" + "f" * 64
    assert receipt.sbom_sha256 == digest(canonical(bom))
    assert receipt.request_sha256 == digest(canonical(result["request"]))
    assert receipt.source_verification == "producer_declared_only"
    assert not receipt.build_binding_verified and not receipt.binary_binding_verified
    assert receipt.repository_authorization == "not_checked"
    assert result["coverage"]["reasons"] == []


def test_unqualified_commit_or_release_never_becomes_a_repository_binding(journal, bom):
    state = imported(
        journal, bom, context={"source_revision": COMMIT, "pipeline_run": "gateway/main"}
    )
    result = derive(journal, state)
    assert not result["ready_to_submit"] and result["request"] is None
    assert result["receipt"]["analysis_source"] is None
    assert "qualified_analysis_source_missing_or_invalid" in result["coverage"]["reasons"]


def test_qualification_changes_material_fingerprint_but_none_default_does_not(journal, bom):
    first = imported(journal, bom)
    context_id = context_for(journal, first)["id"]
    before = target_fingerprint(load_sections(journal, first), VERSION, context_id, VULNERABILITY)
    same = imported(
        journal,
        bom,
        context=CollectionContext(analysis_source=None).model_dump(mode="json"),
        expected=first,
        build_number=2,
    )
    assert (
        target_fingerprint(load_sections(journal, same), VERSION, context_id, VULNERABILITY)
        == before
    )
    changed = imported(
        journal,
        bom,
        context=CollectionContext(
            analysis_source={"repository_name": "gateway", "source_commit": COMMIT}
        ).model_dump(mode="json"),
        expected=same,
        build_number=3,
    )
    assert (
        target_fingerprint(load_sections(journal, changed), VERSION, context_id, VULNERABILITY)
        != before
    )


def assembled(journal, bom):
    backend = imported(journal, bom, part_id="backend", context=qualified("backend"))
    frontend = imported(journal, bom, part_id="frontend", context=qualified("frontend", "b" * 40))
    result = publish_assembly(
        journal,
        project_id="product",
        version=VERSION,
        actor_id="pipeline",
        data=AssemblyInput(
            request_id="select",
            expected=None,
            parts=[
                {"part_id": part, "state": state, "required": True}
                for part, state in (("backend", backend), ("frontend", frontend))
            ],
        ),
    )
    return result[1].updates[0].target, backend, frontend


def test_multipart_inputs_use_exact_consuming_part_not_another_equal_package(journal, bom):
    state, backend, frontend = assembled(journal, bom)
    for part_id, source_state, commit in (
        ("backend", backend, COMMIT),
        ("frontend", frontend, "b" * 40),
    ):
        result = derive(journal, state, namespaced_ref(part_id, "http"))
        assert result["ready_to_submit"]
        assert result["request"]["component_name"] == part_id
        assert result["request"]["source_commit"] == commit
        assert result["receipt"]["part_id"] == part_id
        assert result["receipt"]["source_state"] == source_state
        assert result["receipt"]["focal_component"]["version"] == "1.2.0"
        assert result["request"]["project_versions"] == [VERSION]


def snapshot(journal, state, sections):
    return journal.snapshot(
        project_id="product",
        version=VERSION,
        actor_id="test",
        reason="Input fixture",
        sections=sections,
        parents=[state],
        artifacts=journal.state(state).artifacts,
    )


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ("missing_origin", "consuming_root_or_focal_constituent_origin_missing"),
        ("different_part", "consuming_root_and_focal_constituent_sources_differ"),
        ("different_state", "consuming_root_and_focal_constituent_sources_differ"),
        ("ambiguous_part", "constituent_selection_missing_or_ambiguous"),
        ("manifest", "constituent_manifest_source_mismatch"),
    ],
)
def test_ambiguous_or_conflicting_constituent_provenance_never_selects_a_repository(
    journal, bom, change, reason
):
    state, _, _ = assembled(journal, bom)
    sections = load_sections(journal, state)
    ref = namespaced_ref("backend", "http")
    focal = next(value for value in sections["inventory"].values() if value.get("bom-ref") == ref)
    if change == "missing_origin":
        focal.pop("dtvp_origin")
    elif change == "different_part":
        focal["dtvp_origin"]["part_id"] = "frontend"
    elif change == "different_state":
        focal["dtvp_origin"]["state"] = "f" * 64
    elif change == "ambiguous_part":
        sections["inventory"]["assembly"]["parts"].append(
            copy.deepcopy(sections["inventory"]["assembly"]["parts"][0])
        )
    else:
        sections["inventory"]["assembly"]["parts"][0]["baseline"]["collection"]["analysis_source"][
            "repository_name"
        ] = "other-repo"
    modified = snapshot(journal, state, sections)
    result = derive(journal, modified, ref)
    assert not result["ready_to_submit"] and result["request"] is None
    assert reason in result["coverage"]["reasons"]


def test_unknown_package_version_and_unknown_graph_stay_explicit(journal, bom):
    bom = copy.deepcopy(bom)
    next(component for component in bom["components"] if component["bom-ref"] == "http")[
        "version"
    ] = ""
    bom.pop("dependencies")
    state = imported(journal, bom, context=qualified())
    result = derive(journal, state)
    assert not result["ready_to_submit"]
    assert "focal_component_version_unknown" in result["coverage"]["reasons"]
    assert "consuming_dependency_topology_unknown" in result["coverage"]["reasons"]


def test_absent_target_is_rejected_without_source_inference(journal, bom):
    state = imported(journal, bom, context=qualified())
    with pytest.raises(ValueError, match="absent"):
        derive_analysis_input(journal, state, "f" * 64, VULNERABILITY)
    with pytest.raises(ValueError, match="absent"):
        derive_analysis_input(journal, state, context_for(journal, state)["id"], "CVE-not-reported")


def test_unavailable_original_artifact_never_produces_ready_request(journal, bom):
    state = imported(journal, bom, context=qualified())
    sections = load_sections(journal, state)
    sections["inventory"]["baseline"]["artifact_sha"] = "f" * 64
    modified = snapshot(journal, state, sections)
    result = derive(journal, modified)
    assert not result["ready_to_submit"]
    assert result["request"] is None
    assert result["receipt"]["sbom_sha256"] is None
    assert "source_sbom_artifact_unavailable" in result["coverage"]["reasons"]
