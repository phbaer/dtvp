"""Current readers consume genuinely older serialized captures without rebuilding them."""

import json
import zipfile
from pathlib import Path

import pytest

from dtvp.knowledge.issued_exports import (
    find_issued_export,
    index_ref,
    issue_export,
    resolve_issued_export,
)
from dtvp.knowledge.journal import CorruptJournal, Journal
from dtvp.knowledge.workspace import load_sections
from dtvp.storage import canonical, digest

FIXTURES = Path(__file__).parent / "fixtures" / "issued-serializer-compat"
VARIANTS = ("pre-register", "metadata-register")
COMMITS = {
    "pre-register": "b5ff695687f2ff7a0e1fe90a3d2ff4afa6dbc1fc",
    "metadata-register": "3480f645439010bc197ad87dfe43c7c28dd930fe",
}


def restore(tmp_path, variant):
    archive = (FIXTURES / (variant + ".zip")).read_bytes()
    raw_expected = (FIXTURES / (variant + ".expected.json")).read_bytes()
    provenance = json.loads((FIXTURES / (variant + ".provenance.json")).read_bytes())
    assert provenance["synthetic"] and provenance["source_commit"] == COMMITS[variant]
    assert digest(archive) == provenance["archive_sha256"]
    assert digest(raw_expected) == provenance["expected_sha256"]
    root = tmp_path / variant
    root.mkdir()
    with zipfile.ZipFile(FIXTURES / (variant + ".zip")) as source:
        assert set(source.namelist()) == set(provenance["members"])
        for name, metadata in provenance["members"].items():
            assert not Path(name).is_absolute() and ".." not in Path(name).parts
            raw = source.read(name)
            assert digest(raw) == metadata["sha256"] and len(raw) == metadata["bytes"]
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
    return Journal(root), json.loads(raw_expected), provenance


def disable_current_builders(monkeypatch):
    def unavailable(*args, **kwargs):
        raise AssertionError("Historical issuance must not invoke current serialization/enrichment")

    for path in (
        "dtvp.knowledge.issued_exports.export_bytes",
        "dtvp.knowledge.issued_exports.material_fingerprint",
        "dtvp.knowledge.exports.build_bundle",
        "dtvp.knowledge.vscorer.derive_context_inputs",
        "dtvp.knowledge.agentyzer.derive_analysis_input",
        "dtvp.knowledge.metadata.list_metadata",
    ):
        monkeypatch.setattr(path, unavailable)


@pytest.mark.parametrize("variant", VARIANTS)
def test_pinned_old_code_captures_replay_every_consumer_byte_without_current_builders(
    tmp_path, monkeypatch, variant
):
    journal, expected, provenance = restore(tmp_path, variant)
    sections = load_sections(journal, expected["state"])
    assert all(not sections[key] for key in ("assessments", "reviews", "scoring"))
    assert any(key.startswith("metadata:") for key in sections["history"])
    disable_current_builders(monkeypatch)
    before = journal.head(), journal.references(), set(journal.objects.root.rglob("*"))
    for capture in expected["captures"]:
        project = expected["project_id"]
        assert (
            resolve_issued_export(journal, project, capture["receipt_sha256"], kind=capture["kind"])
            == capture
        )
        assert (
            find_issued_export(
                journal,
                project,
                state=expected["state"],
                kind=capture["kind"],
                selector=capture["selector"],
            )
            == capture
        )
        replay = issue_export(
            journal,
            project_id=project,
            actor_id="different-current-authorized-reader",
            state=expected["state"],
            kind=capture["kind"],
            selector=capture["selector"],
        )
        assert replay == capture
        for name, file in capture["files"].items():
            raw = journal.objects.read(file["sha256"])
            assert len(raw) == file["bytes"] and digest(raw) == file["sha256"]
            if name == "payload.json":
                assert raw == canonical(capture["payload"])
        if capture["kind"] == "knowledge-bundle":
            assert ("component_metadata" in capture["payload"]) == (variant == "metadata-register")
            assert capture["serializer_id"] == "dtvp.knowledge-bundle-serializer/" + (
                "1" if variant == "pre-register" else "2"
            )
    assert before == (journal.head(), journal.references(), set(journal.objects.root.rglob("*")))


@pytest.mark.parametrize("variant", VARIANTS)
@pytest.mark.parametrize("damage", ["artifact", "missing", "index"])
def test_old_capture_corruption_never_falls_back_to_current_serializers(
    tmp_path, monkeypatch, variant, damage
):
    journal, expected, _ = restore(tmp_path, variant)
    capture = expected["captures"][0]
    if damage == "index":
        state = journal.resolve(index_ref(expected["project_id"]))
        index = journal.load(journal.records(state, "history")["issued-export-index"])
        sha = next(iter(index["buckets"].values()))
    else:
        sha = capture["files"]["bundle.json"]["sha256"]
    path = journal.objects.path(sha)
    if damage == "missing":
        path.unlink()
    else:
        path.write_bytes(b"Corrupted historical object")
    disable_current_builders(monkeypatch)
    before = journal.head()
    with pytest.raises(CorruptJournal):
        resolve_issued_export(journal, expected["project_id"], capture["receipt_sha256"])
    assert journal.head() == before
