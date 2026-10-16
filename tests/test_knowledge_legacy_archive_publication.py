"""Reviewed v1 archives retain claims and exact bytes without native authority."""

import copy
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from dtvp.knowledge import legacy_archive_migration as module
from dtvp.knowledge.journal import Conflict, Journal, Ref, Update
from dtvp.knowledge.legacy_archive import preview_archive
from dtvp.knowledge.workspace import load_sections, load_workspace
from dtvp.storage import canonical, digest
from tests.test_knowledge_legacy_archive import fixture, rebuild, unpack

FIXTURES = Path(__file__).parent / "fixtures" / "legacy-v1"


def sanitized():
    return (FIXTURES / "reviewed-single-version.zip").read_bytes()


def arguments(raw=None, **changes):
    raw = sanitized() if raw is None else raw
    metadata = dict(
        request_id="reviewed-archive",
        archive_sha256=digest(raw),
        source_entry_id=preview_archive(raw)["items"][0]["source_entry_id"],
        expected=None,
        expected_policy=None,
        expected_evidence=None,
        source="reviewed-v1-export",
        build_number=0,
        occurred_at="2026-10-16T01:00:00Z",
        reason="Reviewed synthetic archive and disclosure audience",
        acknowledge_sanitized_export=True,
        acknowledge_operator_review=True,
        acknowledge_project_reader_disclosure=True,
    )
    metadata.update(changes)
    return dict(
        project_id="product",
        version="1.0.0",
        actor_id="operator",
        raw=raw,
        data=module.LegacyArchiveMigrationInput(**metadata),
    )


def prepare_apply(journal, args):
    preview = module.preview_migration(journal, **args)
    return args | {
        "data": module.LegacyArchiveMigrationApply(
            **args["data"].model_dump(), preview_digest=preview["preview_digest"]
        )
    }


@pytest.fixture
def journal(tmp_path):
    return Journal(tmp_path / "journal")


def test_sanitized_fixture_is_explicit_variant_and_original_credential_fixture_unchanged():
    provenance = json.loads((FIXTURES / "reviewed-single-version-provenance.json").read_text())
    assert provenance["sha256"] == digest(sanitized())
    assert provenance["source_sha256"] == digest(fixture())
    assert b"fixture-secret" in unpack(fixture())["manifest.json"]
    assert b"fixture-secret" not in unpack(sanitized())["manifest.json"]


def test_preview_pure_and_publication_retains_every_byte_without_native_decisions(journal):
    args = arguments()
    before = journal.head(), journal.references(), set(journal.objects.root.rglob("*"))
    preview = module.preview_migration(journal, **args)
    assert preview == module.preview_migration(journal, **args)
    assert before == (journal.head(), journal.references(), set(journal.objects.root.rglob("*")))
    assert preview["archive_sha256"] == digest(args["raw"])
    receipt = module.apply_migration(journal, **prepare_apply(journal, args))
    state = receipt[1].updates[0].target
    sections = load_sections(journal, state)
    assert all(not sections[key] for key in ("assessments", "reviews", "scoring"))
    assert not sections["ownership"].get("rules")
    artifacts = journal.state(state).artifacts
    for raw in [args["raw"], *unpack(args["raw"]).values()]:
        assert digest(raw) in artifacts
        assert journal.objects.read(digest(raw)) == raw
    ratings = [
        rating
        for value in sections["vulnerabilities"].values()
        for rating in value.get("advisory", {}).get("ratings", [])
    ]
    assert any(rating.get("score") == 0 for rating in ratings)
    assert not any(rating.get("score") == 9.8 for rating in ratings)
    assert b"Synthetic Reviewer" in canonical(sections["history"])
    rows = load_workspace(journal, state)["items"]
    assert rows and all(
        not row["coverage"].get("approved") and row.get("published_score") is None for row in rows
    )


@pytest.mark.parametrize(
    "ack",
    [
        "acknowledge_sanitized_export",
        "acknowledge_operator_review",
        "acknowledge_project_reader_disclosure",
    ],
)
@pytest.mark.parametrize("value", [False, 1, "true", None])
def test_all_review_and_project_reader_acknowledgements_are_explicit_strict_true(ack, value):
    with pytest.raises(ValidationError):
        arguments(**{ack: value})


def test_credentials_in_original_export_rejected_despite_operator_acknowledgement(journal):
    with pytest.raises(ValueError):
        module.preview_migration(journal, **arguments(fixture()))
    assert journal.head() is None


def test_more_than_one_version_is_not_a_selected_subset_import(journal):
    files = unpack(sanitized())
    manifest = json.loads(files["manifest.json"])
    second = copy.deepcopy(manifest["project"]["versions"][0])
    second["project"]["uuid"] = "source-project-2"
    second["project"]["version"] = "2.0.0"
    for role, path in list(second["paths"].items()):
        replacement = path.replace("0001-1.0.0", "0002-2.0.0")
        second["paths"][role] = replacement
        files[replacement] = (
            files[path]
            .replace(b"source-project-1", b"source-project-2")
            .replace(b"1.0.0", b"2.0.0")
        )
    manifest["project"]["versions"].append(second)
    files["manifest.json"] = canonical(manifest)
    raw = rebuild(files)
    assert preview_archive(raw)["statistics"]["versions"] == 2
    with pytest.raises(ValueError):
        module.preview_migration(journal, **arguments(raw))


@pytest.mark.parametrize("plain", [False, True])
def test_documentation_mapping_uses_only_source_uuid_and_preserves_unmapped_history(journal, plain):
    files = unpack(sanitized())
    for path in list(files):
        if path.endswith(("/findings.json", "/assessments.json")):
            values = json.loads(files[path])
            for value in values:
                value["component"]["uuid"] = "missing-exact-uuid"
                if plain:
                    value["analysis"]["analysisDetails"] = (
                        "Plain historical source assessment; no metadata"
                    )
            files[path] = canonical(values)
    raw = rebuild(files)
    receipt = module.apply_migration(journal, **prepare_apply(journal, arguments(raw)))
    sections = load_sections(journal, receipt[1].updates[0].target)
    assert all(
        not sections[key] for key in ("assessments", "reviews", "scoring", "vulnerabilities")
    )
    assert b"missing-exact-uuid" in canonical(sections["history"])


def test_replay_receipt_precedes_archive_parsing_and_branch_advance(journal, monkeypatch):
    args = prepare_apply(journal, arguments())
    first = module.apply_migration(journal, **args)
    state = first[1].updates[0].target
    sections = load_sections(journal, state)
    advanced = journal.snapshot(
        project_id="product",
        version="1.0.0",
        actor_id="operator",
        reason="Advance",
        sections=sections,
        parents=[state],
        artifacts=journal.state(state).artifacts,
    )
    journal.publish(
        request_id="advance",
        fingerprint=digest(b"advance"),
        updates=[
            Update(ref=Ref(project_id="product", name="1.0.0"), expected=state, target=advanced)
        ],
    )

    def forbidden(*args, **kwargs):
        raise AssertionError("Replay must not decompress the archive")

    monkeypatch.setattr(module, "preview_archive", forbidden)
    assert module.apply_migration(journal, **args) == first
    assert journal.resolve(Ref(project_id="product", name="1.0.0")) == advanced


@pytest.mark.parametrize(
    "kind,name", [("branch", "1.0.0"), ("policy", "ownership"), ("evidence", "documents")]
)
def test_new_branch_policy_or_evidence_after_preview_invalidates_publication(journal, kind, name):
    from dtvp.knowledge.journal import SECTIONS

    args = prepare_apply(journal, arguments())
    sections = {key: {} for key in SECTIONS}
    if kind == "policy":
        sections["ownership"]["configuration"] = {"rules": [], "context_roots": {}}
    changed = journal.snapshot(
        project_id="product",
        version=name,
        actor_id="operator",
        reason="Concurrent change",
        sections=sections,
    )
    journal.publish(
        request_id="race-" + kind,
        fingerprint=digest(kind.encode()),
        updates=[
            Update(
                ref=Ref(kind=kind, project_id="product", name=name), expected=None, target=changed
            )
        ],
    )
    before = journal.head(), journal.references()
    with pytest.raises(Conflict):
        module.apply_migration(journal, **args)
    assert before == (journal.head(), journal.references())


@pytest.mark.parametrize(
    "field,value", [("apiKey", False), ("password", 0), ("access_token", "not-allowed")]
)
def test_known_credential_fields_reject_false_zero_and_nonempty_values(journal, field, value):
    files = unpack(sanitized())
    manifest = json.loads(files["manifest.json"])
    manifest["source"][field] = value
    files["manifest.json"] = canonical(manifest)
    raw = rebuild(files)
    with pytest.raises(ValueError):
        module.preview_migration(journal, **arguments(raw))
    assert journal.head() is None


def test_long_malformed_url_like_text_is_bounded_and_real_userinfo_still_rejected():
    module.reject_credentials({"text": "a" * 100000 + ":/broken-url"})
    with pytest.raises(ValueError):
        module.reject_credentials(
            {"text": "a" * 100000 + " https://operator:secret@example.invalid"}
        )


@pytest.mark.parametrize("conflict", [False, True])
def test_literal_uuid_reference_mapping_and_conflict_between_exact_bases(journal, conflict):
    files = unpack(sanitized())
    path = next(name for name in files if name.endswith("/bom.json"))
    bom = json.loads(files[path])
    component = bom["components"][0]
    component.pop("uuid")
    component["bom-ref"] = "source-component-1"
    if conflict:
        bom["components"].append(
            {
                "type": "library",
                "bom-ref": "different-ref",
                "uuid": "source-component-1",
                "name": "Other exact binding",
                "version": "1",
            }
        )
    files[path] = canonical(bom)
    manifest = json.loads(files["manifest.json"])
    manifest["project"]["versions"][0]["counts"]["bom_components"] = len(bom["components"])
    files["manifest.json"] = canonical(manifest)
    raw = rebuild(files)
    receipt = module.apply_migration(journal, **prepare_apply(journal, arguments(raw)))
    sections = load_sections(journal, receipt[1].updates[0].target)
    assert bool(sections["vulnerabilities"]) is not conflict
    assert all(not sections[key] for key in ("assessments", "reviews", "scoring"))


MALFORMED_BOM_CASES = (
    "metadata_null",
    "root_null",
    "component_null",
    "component_children_null",
    "root_children_null",
    "root_child_null",
    "root_child_invalid_ref",
    "root_child_duplicate_ref",
)


def malformed_archive(case):
    files = unpack(sanitized())
    path = next(name for name in files if name.endswith("/bom.json"))
    bom = json.loads(files[path])
    if case == "metadata_null":
        bom["metadata"] = None
    elif case == "root_null":
        bom["metadata"]["component"] = None
    elif case == "component_null":
        bom["components"] = [None]
    elif case == "component_children_null":
        bom["components"][0]["components"] = None
    elif case == "root_children_null":
        bom["metadata"]["component"]["components"] = None
    elif case == "root_child_null":
        bom["metadata"]["component"]["components"] = [None]
    else:
        child = {
            "type": "library",
            "name": "Nested root child",
            "version": "1",
            "bom-ref": None
            if case == "root_child_invalid_ref"
            else bom["components"][0]["bom-ref"],
        }
        bom["metadata"]["component"]["components"] = [child]
    files[path] = canonical(bom)
    return rebuild(files)


@pytest.mark.parametrize("case", MALFORMED_BOM_CASES)
def test_malformed_raw_component_tree_never_creates_partial_publication(journal, case):
    raw = malformed_archive(case)
    args = arguments(raw)
    before = journal.head(), journal.references(), set(journal.objects.root.rglob("*"))
    with pytest.raises(ValueError):
        module.preview_migration(journal, **args)
    applied = args | {
        "data": module.LegacyArchiveMigrationApply(
            **args["data"].model_dump(), preview_digest="0" * 64
        )
    }
    with pytest.raises(ValueError):
        module.apply_migration(journal, **applied)
    assert before == (journal.head(), journal.references(), set(journal.objects.root.rglob("*")))


def test_nonempty_valid_root_nested_composition_is_rejected_without_loss(journal):
    files = unpack(sanitized())
    path = next(name for name in files if name.endswith("/bom.json"))
    bom = json.loads(files[path])
    bom["metadata"]["component"]["components"] = [
        {
            "type": "library",
            "name": "Root-only dependency",
            "version": "1",
            "bom-ref": "root-only-child",
            "uuid": "root-only-child-id",
        }
    ]
    files[path] = canonical(bom)
    args = arguments(rebuild(files))
    before = journal.head(), journal.references(), set(journal.objects.root.rglob("*"))
    with pytest.raises(ValueError, match="Unsupported root-nested composition"):
        module.preview_migration(journal, **args)
    applied = args | {
        "data": module.LegacyArchiveMigrationApply(
            **args["data"].model_dump(),
            preview_digest="0" * 64,
        )
    }
    with pytest.raises(ValueError, match="Unsupported root-nested composition"):
        module.apply_migration(journal, **applied)
    assert before == (journal.head(), journal.references(), set(journal.objects.root.rglob("*")))
