"""Legacy ZIP inspection preserves source claims and fails closed on hostile containers."""

import copy
import io
import json
import stat
import struct
import zipfile
from pathlib import Path

import pytest

from dtvp.knowledge import legacy_archive as module
from dtvp.knowledge.legacy_archive import preview_archive
from dtvp.storage import canonical, digest

FIXTURES = Path(__file__).parent / "fixtures" / "legacy-v1"


def fixture(name="valid-synthetic.zip"):
    return (FIXTURES / name).read_bytes()


def unpack(raw=None):
    with zipfile.ZipFile(io.BytesIO(raw or fixture())) as archive:
        return {info.filename: archive.read(info) for info in archive.infolist()}


def pack(files):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, raw in files.items():
            archive.writestr(name, raw)
    return output.getvalue()


def rebuild(files):
    manifest = json.loads(files["manifest.json"])
    manifest["files"] = {
        name: {"sha256": digest(raw), "size": len(raw)}
        for name, raw in files.items()
        if name != "manifest.json"
    }
    return pack({**files, "manifest.json": canonical(manifest)})


@pytest.mark.parametrize(
    "name,normalization,documentation",
    [
        ("old-writer.zip", "unsupported", "plain"),
        ("valid-synthetic.zip", "supported", "tagged"),
        ("diffable-synthetic.zip", "supported", "tagged"),
    ],
)
def test_actual_frozen_old_writer_fixtures_and_explicit_normalization_limits(
    name, normalization, documentation
):
    raw = fixture(name)
    provenance = json.loads((FIXTURES / "provenance.json").read_text())
    assert provenance["synthetic"] and provenance["fixtures"][name] == digest(raw)
    result = preview_archive(raw)
    assert (
        result["dry_run"]
        and not result["writes"]
        and not result["creates_native_approvals"]
        and not result["history_complete"]
    )
    assert result["statistics"]["versions"] == result["total"] == 1
    row = result["items"][0]
    assert row["normalization"]["status"] == normalization
    assert row["documentation"] == {documentation: 1}
    assert row["source_states"] == {"not_affected": 1}
    assert "assessment_comments_may_have_been_stripped" in row["losses"]
    assert result["representation"] == (
        "diffable_tree_export" if name.startswith("diffable") else "snapshot_export"
    )
    second = preview_archive(raw, offset=1, limit=1)
    assert second["items"] == [] and second["preview_digest"] == result["preview_digest"]
    text = json.dumps(result)
    for secret in (
        "fixture-secret",
        "fixture-user",
        "Synthetic Reviewer",
        "ArchiveApp",
        "source-project-1",
        "Historical source statement",
    ):
        assert secret not in text


@pytest.mark.parametrize(
    "name", ["../escape", "/absolute", "a\\b", "C:drive", "versions/./bad", "versions//bad"]
)
def test_unsafe_paths_refused_without_extraction(name):
    files = unpack()
    files[name] = b"hidden"
    with pytest.raises(ValueError):
        preview_archive(pack(files))


@pytest.mark.parametrize(
    "mode", ["extra", "missing", "checksum", "size", "schema", "paths", "counts", "duplicate_json"]
)
def test_manifest_contract_fails_closed(mode):
    files = unpack()
    manifest = json.loads(files["manifest.json"])
    first = next(iter(manifest["files"]))
    if mode == "extra":
        files["extra.json"] = b"{}"
    elif mode == "missing":
        del files[first]
    elif mode == "checksum":
        files[first] += b" "
    elif mode == "size":
        manifest["files"][first]["size"] = True
    elif mode == "schema":
        manifest["schema_version"] = "dtvp.project-archive/v99"
    elif mode == "paths":
        manifest["project"]["versions"][0]["paths"]["bom"] = "undeclared.json"
    elif mode == "counts":
        manifest["project"]["versions"][0]["counts"]["findings"] = True
    elif mode == "duplicate_json":
        files["manifest.json"] = (
            b'{"schema_version":"dtvp.project-archive/v1","schema_version":"dtvp.project-archive/v1"}'
        )
    if mode not in {"duplicate_json"}:
        files["manifest.json"] = canonical(manifest)
    with pytest.raises(ValueError):
        preview_archive(pack(files))


def test_duplicate_member_alias_symlink_and_alternate_unicode_path_refused():
    for name in ("manifest.json", "MANIFEST.JSON"):
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as archive:
            archive.writestr("manifest.json", b"{}")
            archive.writestr(name, b"{}")
        with pytest.raises(ValueError):
            preview_archive(output.getvalue())
    for metadata in ("symlink", "unicode"):
        output = io.BytesIO()
        info = zipfile.ZipInfo("manifest.json")
        if metadata == "symlink":
            info.create_system = 3
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
        else:
            info.extra = struct.pack("<HH", 0x7075, 0)
        with zipfile.ZipFile(output, "w") as archive:
            archive.writestr(info, b"{}")
        with pytest.raises(ValueError):
            preview_archive(output.getvalue())


@pytest.mark.parametrize("mutation", ["directory_size", "entry_count", "member_size", "encrypted"])
def test_central_directory_admitted_before_zipfile_allocation(monkeypatch, mutation):
    raw = bytearray(fixture())
    eocd = raw.rfind(b"PK\x05\x06")
    central = raw.find(b"PK\x01\x02")
    if mutation == "directory_size":
        struct.pack_into("<L", raw, eocd + 12, module.MAX_DIRECTORY + 1)
    elif mutation == "entry_count":
        struct.pack_into("<HH", raw, eocd + 8, module.MAX_ENTRIES + 1, module.MAX_ENTRIES + 1)
    elif mutation == "member_size":
        struct.pack_into("<L", raw, central + 24, module.MAX_MEMBER + 1)
    else:
        struct.pack_into("<H", raw, central + 8, 1)

    def forbidden(*args, **kwargs):
        pytest.fail("ZipFile allocated before actual central-directory admission")

    monkeypatch.setattr(module.zipfile, "ZipFile", forbidden)
    with pytest.raises(ValueError):
        preview_archive(bytes(raw))


def test_compressed_expanded_and_actual_stream_limits(monkeypatch):
    raw = fixture()
    monkeypatch.setattr(module, "MAX_COMPRESSED", len(raw) - 1)
    with pytest.raises(ValueError):
        preview_archive(raw)
    monkeypatch.setattr(module, "MAX_COMPRESSED", 64 * 1024 * 1024)
    monkeypatch.setattr(module, "MAX_EXPANDED", 1)
    with pytest.raises(ValueError):
        preview_archive(raw)
    monkeypatch.setattr(module, "MAX_EXPANDED", 128 * 1024 * 1024)
    monkeypatch.setattr(
        module.zipfile.ZipFile,
        "open",
        lambda *args, **kwargs: io.BytesIO(b"x" * (module.MAX_MEMBER + 1)),
    )
    with pytest.raises(ValueError):
        preview_archive(raw)


def test_strict_json_duplicate_keys_nonfinite_and_nesting():
    for raw in (b'{"a":1,"a":2}', b'{"x":NaN}', b"[" * 65 + b"0" + b"]" * 65):
        with pytest.raises(ValueError):
            module.strict_json(raw)


def test_duplicate_source_labels_are_reported_without_mapping_or_guesses():
    files = unpack()
    manifest = json.loads(files["manifest.json"])
    other = copy.deepcopy(manifest["project"]["versions"][0])
    for role, path in list(other["paths"].items()):
        new_path = path.replace("0001-", "0002-")
        files[new_path] = files[path]
        other["paths"][role] = new_path
    manifest["project"]["versions"].append(other)
    files["manifest.json"] = canonical(manifest)
    result = preview_archive(rebuild(files), limit=1)
    assert (
        result["statistics"]["duplicate_source_uuids"]
        == result["statistics"]["duplicate_source_version_labels"]
        == 1
    )
    assert result["total"] == 2 and len(result["items"]) == 1 and result["next_offset"] == 1
    assert result["preview_digest"] == preview_archive(rebuild(files), offset=1)["preview_digest"]


def test_long_malformed_documentation_scans_without_synthesizing_metadata():
    assert not module.tagged_documentation("[Team: incomplete " * 100_000)
    assert module.tagged_documentation("[Team: Synthetic][Reviewed by: Historical]")


def test_file_directory_namespace_collisions_are_ambiguous():
    for paths in (("versions", "versions/file.json"), ("versions", "versions/")):
        with pytest.raises(ValueError):
            module.directory(pack({paths[0]: b"", paths[1]: b""}))


def test_unmapped_component_is_reported_without_name_or_purl_fallback():
    files = unpack()
    manifest = json.loads(files["manifest.json"])
    path = manifest["project"]["versions"][0]["paths"]["assessments"]
    records = json.loads(files[path])
    records[0]["component"]["uuid"] = "unmapped-synthetic-uuid"
    files[path] = canonical(records)
    row = preview_archive(rebuild(files))["items"][0]
    assert row["component_reference_coverage"]["assessments"] == {
        "exact_source_uuid_refs": 0,
        "unresolved": 1,
        "ambiguous": 0,
    }
    assert "legacy_component_mapping_unresolved_no_name_or_purl_guess" in row["losses"]


@pytest.mark.parametrize(
    "variant", ["missing_documentation", "unknown_version", "malformed_bom_metadata"]
)
def test_legacy_missing_metadata_is_reported_without_invented_values(variant):
    files = unpack()
    manifest = json.loads(files["manifest.json"])
    entry = manifest["project"]["versions"][0]
    if variant == "missing_documentation":
        path = entry["paths"]["assessments"]
        records = json.loads(files[path])
        records[0]["analysis"]["analysisDetails"] = None
        files[path] = canonical(records)
    elif variant == "unknown_version":
        entry["project"]["version"] = None
        path = entry["paths"]["project"]
        project = json.loads(files[path])
        project["version"] = None
        files[path] = canonical(project)
        files["manifest.json"] = canonical(manifest)
    else:
        path = entry["paths"]["bom"]
        bom = json.loads(files[path])
        bom["metadata"] = []
        files[path] = canonical(bom)
    row = preview_archive(rebuild(files))["items"][0]
    if variant == "missing_documentation":
        assert row["documentation"] == {"missing": 1}
    elif variant == "unknown_version":
        assert "source_version_label_unknown" in row["losses"]
    else:
        assert row["normalization"]["status"] == "unsupported"


@pytest.mark.parametrize("shape", ["list", "dict"])
def test_wide_json_budget_checked_before_child_queue_growth(monkeypatch, shape):
    class GuardedChildren(list):
        def __iter__(self):
            pytest.fail("Child queue grew before complete node-budget admission")

    children = GuardedChildren([0, 1, 2, 3])

    class WideDict(dict):
        def values(self):
            return children

    value = children if shape == "list" else WideDict(a=0, b=1, c=2, d=3)
    monkeypatch.setattr(module, "MAX_JSON_NODES", 3)
    monkeypatch.setattr(module.json, "loads", lambda *args, **kwargs: value)
    with pytest.raises(ValueError):
        module.strict_json(b"[]")


def test_json_child_depth_checked_before_enqueue(monkeypatch):
    class GuardedChildren(list):
        def __iter__(self):
            pytest.fail("Child queue grew before next-depth admission")

    value = GuardedChildren([0])
    monkeypatch.setattr(module, "MAX_JSON_DEPTH", 0)
    monkeypatch.setattr(module.json, "loads", lambda *args, **kwargs: value)
    with pytest.raises(ValueError):
        module.strict_json(b"[]")


@pytest.mark.parametrize("raw", [b"[1e9999]", b'{"value":-1e9999}'])
def test_float_overflow_is_rejected_as_nonfinite_json(raw):
    with pytest.raises(ValueError):
        module.strict_json(raw)
