"""verify and inspect: one negative test per container, format, record,
referential and semantic rule (C, F, S, R, W)."""

import copy
import json
import zipfile

import pytest

from dtvp.backup import container, schemas, upcasters
from dtvp.backup.errors import DumpError
from dtvp.backup.verify import inspect_dump, verify_dump
from tests.dump_helpers import FIXTURE_V1, build_dump, fixture_records, pack_tree


@pytest.fixture
def dump_path(tmp_path):
    return tmp_path / "dump.zip"


def _refused(path, code, **kwargs):
    with pytest.raises(DumpError) as raised:
        result = verify_dump(str(path), **kwargs)
        if result.errors:
            raise DumpError(result.errors[0].code, result.errors[0].message)
    assert raised.value.code == code, raised.value
    return raised.value


def _codes(findings):
    return {finding.code for finding in findings}


def test_the_frozen_fixture_verifies(tmp_path):
    result = verify_dump(str(pack_tree(FIXTURE_V1, tmp_path / "fixture.zip")))
    assert result.ok
    assert _codes(result.warnings) == {"W8"}
    assert result.records["assessment"] == 5
    # Format minor 0: the entities added since are not listed, and none held.
    assert (result.records["saved_view"], result.records["saved_view_default"]) == (0, 0)


def test_inspect_reads_only_the_manifest(tmp_path):
    path = pack_tree(FIXTURE_V1, tmp_path / "fixture.zip")
    summary = inspect_dump(str(path))
    assert summary["dump_id"] == "5d0c3c2e-7c55-4b8e-9d0e-2f6b5a1c9e01"
    assert summary["contains_credentials"] is True
    assert summary["records"]["revision"] == 6
    assert summary["config"]["user_roles"] == "absent"


# -- container ---------------------------------------------------------------


def _rezip(source, target, *, drop=(), add=None, replace=None):
    with zipfile.ZipFile(source) as original, zipfile.ZipFile(target, "w") as copy_:
        for info in original.infolist():
            if info.filename in drop:
                continue
            data = (replace or {}).get(info.filename, original.read(info.filename))
            copy_.writestr(info.filename, data)
        for name, data in (add or {}).items():
            copy_.writestr(name, data)
    return target


def test_c1_unsafe_member_name(tmp_path):
    good = build_dump(tmp_path / "good.zip")
    _refused(_rezip(good, tmp_path / "bad.zip", add={"../evil": b"x"}), "C1")


def test_c2_member_not_in_the_manifest(tmp_path):
    good = build_dump(tmp_path / "good.zip")
    _refused(_rezip(good, tmp_path / "bad.zip", add={"records/extra.jsonl": b"{}\n"}), "C2")


def test_c3_listed_member_missing(tmp_path):
    good = build_dump(tmp_path / "good.zip")
    path = _rezip(good, tmp_path / "bad.zip", drop={"records/revision/revision-0001.jsonl"})
    _refused(path, "C3")
    no_manifest = _rezip(good, tmp_path / "none.zip", drop={"manifest.json"})
    _refused(no_manifest, "C3")


def test_c4_too_many_members(dump_path, monkeypatch):
    build_dump(dump_path)
    monkeypatch.setattr(container, "MAX_MEMBERS", 3)
    _refused(dump_path, "C4")


def test_c5_declared_total_over_the_limit(dump_path, monkeypatch):
    build_dump(dump_path)
    monkeypatch.setenv("DTVP_DUMP_MAX_UNCOMPRESSED_BYTES", "1000")
    _refused(dump_path, "C5")


def _part_change(entity, **values):
    def change(manifest):
        manifest["entities"][entity]["parts"][0].update(values)

    return change


def test_c6_part_digest_differs(dump_path):
    build_dump(dump_path, change_manifest=_part_change("revision", sha256="0" * 64))
    _refused(dump_path, "C6")


def test_c6_config_digest_differs(dump_path):
    def change(manifest):
        manifest["config"]["team_mapping"]["sha256"] = "0" * 64

    build_dump(dump_path, change_manifest=change)
    _refused(dump_path, "C6")


def test_c7_part_size_differs(tmp_path):
    good = json.loads(zipfile.ZipFile(build_dump(tmp_path / "g.zip")).read("manifest.json"))
    part = good["entities"]["revision"]["parts"][0]
    path = build_dump(tmp_path / "bad.zip", change_manifest=_part_change("revision", bytes=part["bytes"] + 1))
    _refused(path, "C7")


def test_c8_part_record_count_differs(tmp_path):
    path = build_dump(tmp_path / "bad.zip", change_manifest=_part_change("revision", records=99))
    _refused(path, "C8")


def test_c9_line_over_the_maximum(dump_path, monkeypatch):
    build_dump(dump_path)
    monkeypatch.setattr(container, "MAX_RECORD_BYTES", 200)
    _refused(dump_path, "C9")


def test_c10_damaged_zip(tmp_path):
    good = build_dump(tmp_path / "good.zip")
    data = bytearray(good.read_bytes())
    data[60:90] = b"\0" * 30
    damaged = tmp_path / "damaged.zip"
    damaged.write_bytes(bytes(data))
    with pytest.raises(DumpError) as raised:
        verify_dump(str(damaged))
    assert raised.value.code in {"C10", "C6"}
    (tmp_path / "junk.zip").write_bytes(b"junk")
    _refused(tmp_path / "junk.zip", "C10")


@pytest.mark.parametrize("line", [b"not json\n", b"[1, 2]\n", b'{"a": NaN}\n'])
def test_c11_line_is_not_a_json_object(dump_path, line):
    build_dump(dump_path, raw_parts={"records/revision/revision-0001.jsonl": line})
    _refused(dump_path, "C11")


# -- format ------------------------------------------------------------------


def _manifest(change):
    def apply(manifest):
        change(manifest)
        return manifest

    return apply


@pytest.mark.parametrize(
    "code, change",
    [
        ("F1", lambda m: m.update(format="dtvp.project-archive")),
        ("F2", lambda m: m.update(format_version=2)),
        ("F3", lambda m: m["required_features"].append("encryption")),
        ("F4", lambda m: m["scope"].update(kind="projects")),
        ("F5", lambda m: m.pop("cut_point")),
        ("F5", lambda m: m.update(created_at="yesterday")),
        ("F7", lambda m: m["entities"]["revision"].update(schema="dtvp.dump.revision/2")),
        ("F8", lambda m: m["entities"]["revision"].update(schema="dtvp.dump.revision/0")),
        ("F9", lambda m: m.update(contains_credentials=False)),
    ],
)
def test_format_rules(dump_path, code, change):
    build_dump(dump_path, change_manifest=_manifest(change))
    _refused(dump_path, code)


def test_f9_tokens_without_the_feature(dump_path):
    def change(manifest):
        manifest["required_features"] = []
        manifest["contains_credentials"] = False

    build_dump(dump_path, change_manifest=change)
    _refused(dump_path, "F9")


def _newer_minor(manifest):
    manifest["format_minor"] = schemas.FORMAT_MINOR + 1
    manifest["future_manifest_field"] = True
    manifest["entities"]["future_entity"] = {"schema": "dtvp.dump.future_entity/1", "records": 0, "parts": []}


def test_f6_newer_minor_is_a_warning_in_verify(dump_path):
    records = copy.deepcopy(fixture_records("known_project"))
    records[0]["future_field"] = "x"
    build_dump(dump_path, records={"known_project": records}, change_manifest=_manifest(_newer_minor))
    result = verify_dump(str(dump_path))
    assert result.ok
    f6 = [str(w) for w in result.warnings if w.code == "F6"]
    assert any("future_entity" in w and "future_manifest_field" in w for w in f6)
    assert any("future_field" in w for w in f6)
    assert result.stripped_fields == ["future_field"]


def test_f6_newer_minor_is_refused_without_allow_unknown(dump_path):
    build_dump(dump_path, change_manifest=_manifest(_newer_minor))
    _refused(dump_path, "F6", allow_unknown=False)
    records = copy.deepcopy(fixture_records("known_project"))
    records[0]["future_field"] = "x"

    def only_minor(manifest):
        manifest["format_minor"] = schemas.FORMAT_MINOR + 1

    build_dump(dump_path, records={"known_project": records}, change_manifest=only_minor)
    _refused(dump_path, "F6", allow_unknown=False)


def test_unknown_field_under_the_same_minor_is_s1(dump_path):
    records = copy.deepcopy(fixture_records("known_project"))
    records[0]["future_field"] = "x"
    build_dump(dump_path, records={"known_project": records})
    _refused(dump_path, "S1")


def test_upcaster_chain_is_applied_before_validation(dump_path, monkeypatch):
    def upcast(record):
        record = dict(record)
        record["project_uuid"] = record.pop("uuid")
        return record

    monkeypatch.setitem(upcasters.UPCASTERS, ("known_project", 0), (1, upcast))
    old = []
    for record in fixture_records("known_project"):
        record = dict(record)
        record["uuid"] = record.pop("project_uuid")
        old.append(record)
    build_dump(
        dump_path,
        records={"known_project": old},
        change_manifest=_manifest(
            lambda m: m["entities"]["known_project"].update(schema="dtvp.dump.known_project/0")
        ),
    )
    assert verify_dump(str(dump_path)).ok
    chain = upcasters.upcast_chain("known_project", 0)
    assert len(chain) == 1
    with pytest.raises(DumpError) as raised:
        upcasters.upcast_chain("revision", 0)
    assert raised.value.code == "F8"


# -- records -----------------------------------------------------------------


def _broken(entity):
    records = fixture_records(entity) or [
        {"project_uuid": "p", "position": 0, "payload": {}}
    ]
    record = copy.deepcopy(records[0])
    for field, value in record.items():
        if isinstance(value, bool):
            record[field] = "yes"
            break
        if isinstance(value, int):
            record[field] = str(value)
            break
    else:
        record.pop(next(iter(schemas.load_schema(entity)["required"])))
    return [record]


@pytest.mark.parametrize("entity", schemas.ENTITY_ORDER)
def test_s1_a_record_fails_its_schema(dump_path, entity):
    records = {entity: _broken(entity)}
    build_dump(dump_path, records=records)
    error = _refused(dump_path, "S1")
    assert entity in error.message


# -- referential ---------------------------------------------------------------


def _with(entity, change):
    records = copy.deepcopy(fixture_records(entity))
    change(records)
    return {entity: records}


def test_r1_duplicate_natural_key(dump_path):
    build_dump(dump_path, records=_with("known_project", lambda r: r.append(dict(r[0]))))
    _refused(dump_path, "R1")


def test_r2_duplicate_update_id(dump_path):
    def change(records):
        records[1]["update_id"] = records[0]["update_id"]

    build_dump(dump_path, records=_with("outbox_entry", change))
    _refused(dump_path, "R2")


def test_r2_duplicate_token_digest(dump_path):
    def change(records):
        records.append({**records[0], "token_id": "tok-2"})

    build_dump(dump_path, records=_with("access_token", change))
    _refused(dump_path, "R2")


def test_r3_history_without_assessment(dump_path):
    def change(records):
        records[0]["key"]["component_uuid"] = "unknown"

    build_dump(dump_path, records=_with("revision", change))
    _refused(dump_path, "R3")


def test_r4_application_without_result(dump_path):
    build_dump(dump_path, records={"code_analysis_result": []})
    _refused(dump_path, "R4")


@pytest.mark.parametrize(
    "records",
    [
        _with("source_snapshot", lambda r: r[0].update(item_count=3)),
        _with("source_snapshot", lambda r: r.pop(0)),
        {"source_project_vulnerability": [
            {"project_uuid": "0f1b2c3d-1111-4a11-8a11-111111111111", "position": 0, "payload": {}}
        ]},
        {"source_finding": []},
    ],
    ids=["count differs", "no snapshot", "items of a raw snapshot", "items missing"],
)
def test_r5_snapshot_items(dump_path, records):
    build_dump(dump_path, records=records)
    _refused(dump_path, "R5")


def test_r6_sequence_below_the_largest_id(dump_path):
    build_dump(
        dump_path,
        change_manifest=_manifest(
            lambda m: m["cut_point"]["sequences"].update(assessment_revisions=3)
        ),
    )
    _refused(dump_path, "R6")


# -- semantic ----------------------------------------------------------------


def _warnings(dump_path, **records):
    build_dump(dump_path, records=records)
    result = verify_dump(str(dump_path))
    assert result.ok, result.errors
    return _codes(result.warnings)


def test_w1_update_id_differs(dump_path):
    outbox = copy.deepcopy(fixture_records("outbox_entry"))
    outbox[0]["update_id"] = "another"
    assert "W1" in _warnings(dump_path, outbox_entry=outbox)


def test_w2_pending_without_outbox(dump_path):
    outbox = copy.deepcopy(fixture_records("outbox_entry"))[1:]
    assert "W2" in _warnings(dump_path, outbox_entry=outbox)


def test_w3_outbox_for_a_synced_assessment(dump_path):
    assessments = copy.deepcopy(fixture_records("assessment"))
    assessments[1]["sync"]["status"] = "synced"
    assert "W3" in _warnings(dump_path, assessment=assessments)


def test_w4_revision_below_history(dump_path):
    assessments = copy.deepcopy(fixture_records("assessment"))
    assessments[1]["revision"] = 1
    assert "W4" in _warnings(dump_path, assessment=assessments)


def test_w5_outbox_without_assessment(dump_path):
    outbox = copy.deepcopy(fixture_records("outbox_entry"))
    outbox.append({**outbox[0], "key": {**outbox[0]["key"], "component_uuid": "zzz"}, "update_id": "u-9"})
    assert "W5" in _warnings(dump_path, outbox_entry=outbox)


def test_w6_assessment_without_history(dump_path):
    revisions = [r for r in fixture_records("revision") if r["revision_id"] != 7]
    assert "W6" in _warnings(dump_path, revision=revisions)


def test_w7_settings_fail_their_rules(dump_path):
    build_dump(dump_path, config={"user_roles": b'{"alice": 1}'})
    result = verify_dump(str(dump_path))
    assert result.ok
    assert any(w.code == "W7" and "user_roles" in w.message for w in result.warnings)


def test_w8_raw_payloads(dump_path):
    audit = copy.deepcopy(fixture_records("token_audit"))
    audit[0].pop("target")
    audit[0]["target_raw"] = "{x"
    codes = [str(w) for w in verify_dump(str(build_dump(dump_path, records={"token_audit": audit}))).warnings]
    assert any("token_audit" in w and "target_raw" in w for w in codes)
    assert any("outbox_entry" in w and "payload_raw" in w for w in codes)
