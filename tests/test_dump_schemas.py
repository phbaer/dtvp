"""The published JSON Schemas of dtvp.dump/1, the frozen fixture, and the
enums the schemas share with the code."""

import copy
import hashlib
import json
import re
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from dtvp import access_token_services, assessment_outbox_services
from dtvp.backup import schemas
from dtvp.bundle_io import jsonl_line
from tests.dump_helpers import FIXTURE_V1, fixture_manifest, fixture_records

REPO = Path(__file__).resolve().parent.parent


def _errors(name, document):
    return schemas.errors(name, document)


def test_every_schema_is_a_valid_draft_2020_12_schema():
    names = schemas.schema_names()
    assert set(names) == {"common", "manifest", *schemas.ENTITY_ORDER}
    for name in names:
        schema = schemas.load_schema(name)
        Draft202012Validator.check_schema(schema)
        assert schema["$id"] == f"urn:dtvp:dump:1:{name}"
        assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"


def _objects(node, path=""):
    if isinstance(node, dict):
        if node.get("type") == "object" and "properties" in node:
            yield path, node
        for key, value in node.items():
            yield from _objects(value, f"{path}/{key}")
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from _objects(value, f"{path}/{index}")


def test_every_object_schema_forbids_unknown_properties():
    for name in schemas.schema_names():
        for path, node in _objects(schemas.load_schema(name)):
            assert node.get("additionalProperties") is False, f"{name}{path}"


def test_the_fixture_manifest_and_records_validate():
    manifest = fixture_manifest()
    assert _errors("manifest", manifest) == []
    # The manifest is written with sorted keys; readers process the entities
    # in the fixed order of schemas.ENTITY_ORDER.
    assert set(manifest["entities"]) == set(schemas.ENTITY_ORDER)
    for entity in schemas.ENTITY_ORDER:
        for record in fixture_records(entity):
            assert _errors(entity, record) == [], (entity, record)


def test_the_fixture_digests_are_real():
    """The fixture is frozen; if this fails, the expected values are printed."""
    manifest = fixture_manifest()
    mismatches = []
    for entity, spec in manifest["entities"].items():
        total = 0
        for part in spec["parts"]:
            data = (FIXTURE_V1 / part["path"]).read_bytes()
            actual = {
                "path": part["path"],
                "sha256": hashlib.sha256(data).hexdigest(),
                "bytes": len(data),
                "records": data.count(b"\n"),
            }
            total += actual["records"]
            if actual != part:
                mismatches.append(actual)
            # Lines are in the canonical encoding.
            for line in data.splitlines(keepends=True):
                assert jsonl_line(json.loads(line)) == line
        if total != spec["records"]:
            mismatches.append({entity: total})
    for name, spec in manifest["config"].items():
        if spec["absent"]:
            assert not (FIXTURE_V1 / "config" / f"{name}.json").exists()
            continue
        data = (FIXTURE_V1 / spec["path"]).read_bytes()
        actual = {
            "absent": False,
            "path": spec["path"],
            "sha256": hashlib.sha256(data).hexdigest(),
            "bytes": len(data),
        }
        if actual != spec:
            mismatches.append(actual)
    assert mismatches == [], f"expected manifest values: {mismatches}"


def test_the_fixture_covers_the_listed_cases():
    assessments = fixture_records("assessment")
    statuses = {record["sync"]["status"] for record in assessments}
    assert statuses == {"synced", "pending", "error", "inactive", "cancelled"}
    assert any(r["sync"]["base"] == r["value"] for r in assessments)
    assert any(
        r["sync"]["base"] not in (None, r["value"]) for r in assessments
    )
    assert any(r["sync"]["remote"] is not None for r in assessments)
    revisions = fixture_records("revision")
    origins = {record["origin"] for record in revisions}
    assert {"import", "before-history", "bulk-workflow"} <= origins
    assert any(origin.startswith("wf-") for origin in origins)
    known = {record["project_uuid"] for record in fixture_records("known_project")}
    listed = {
        record["payload"]["uuid"] for record in fixture_records("source_project")
    }
    assert known - listed
    assert any(r["form"] == "raw" for r in fixture_records("source_snapshot"))
    assert any("payload_raw" in r for r in fixture_records("outbox_entry"))
    assert fixture_manifest()["config"]["user_roles"] == {"absent": True}
    for entity in schemas.ENTITY_ORDER:
        if entity != "source_project_vulnerability":
            assert fixture_records(entity), entity


# -- negative records -------------------------------------------------------


def _assessment():
    return copy.deepcopy(fixture_records("assessment")[1])


def _negatives():
    missing_key = _assessment()
    del missing_key["key"]["component_uuid"]
    string_boolean = _assessment()
    string_boolean["value"]["suppressed"] = "false"
    base_same = _assessment()
    base_same["sync"]["base_same"] = 1
    text_in_record = copy.deepcopy(fixture_records("revision")[0])
    text_in_record["text_in_record"] = 1
    unknown_status = _assessment()
    unknown_status["sync"]["status"] = "diverged"
    unknown_state = _assessment()
    unknown_state["value"]["state"] = "WONT_FIX"
    application = copy.deepcopy(fixture_records("code_analysis_application")[0])
    application["status"] = "rejected"
    both = copy.deepcopy(fixture_records("outbox_entry")[0])
    both["payload_raw"] = "{}"
    neither = copy.deepcopy(fixture_records("outbox_entry")[0])
    del neither["payload"]
    target_both = copy.deepcopy(fixture_records("token_audit")[0])
    target_both["target_raw"] = "x"
    raw_without_form = copy.deepcopy(fixture_records("source_snapshot")[0])
    raw_without_form["raw"] = []
    raw_missing = copy.deepcopy(fixture_records("source_snapshot")[1])
    del raw_missing["raw"]
    result_not_object = copy.deepcopy(fixture_records("code_analysis_result")[0])
    result_not_object["payload"] = [1]
    unknown_scope = copy.deepcopy(fixture_records("access_token")[0])
    unknown_scope["scopes"] = ["read", "admin"]
    empty_origin = copy.deepcopy(fixture_records("revision")[0])
    empty_origin["origin"] = ""
    negative_revision = _assessment()
    negative_revision["revision"] = -1
    return {
        "missing key": ("assessment", missing_key),
        "string boolean": ("assessment", string_boolean),
        "base_same leaks": ("assessment", base_same),
        "text_in_record leaks": ("revision", text_in_record),
        "unknown sync status": ("assessment", unknown_status),
        "unknown state": ("assessment", unknown_state),
        "unknown application status": ("code_analysis_application", application),
        "payload and payload_raw": ("outbox_entry", both),
        "neither payload": ("outbox_entry", neither),
        "target and target_raw": ("token_audit", target_both),
        "raw on a list snapshot": ("source_snapshot", raw_without_form),
        "raw snapshot without raw": ("source_snapshot", raw_missing),
        "code-analysis payload not an object": ("code_analysis_result", result_not_object),
        "unknown token scope": ("access_token", unknown_scope),
        "empty origin": ("revision", empty_origin),
        "negative revision": ("assessment", negative_revision),
    }


@pytest.mark.parametrize("case", list(_negatives()))
def test_negative_records_are_rejected(case):
    entity, record = _negatives()[case]
    assert _errors(entity, record), case


def _manifest_negatives():
    def changed(change):
        manifest = fixture_manifest()
        change(manifest)
        return manifest

    return {
        "unknown scope": changed(lambda m: m["scope"].update(kind="tenant")),
        "projects scope is reserved": changed(lambda m: m["scope"].update(kind="projects")),
        "unknown required feature": changed(
            lambda m: m["required_features"].append("encryption")
        ),
        "wrong format": changed(lambda m: m.update(format="dtvp.archive")),
        "major version 2": changed(lambda m: m.update(format_version=2)),
        "missing entity": changed(lambda m: m["entities"].pop("revision")),
        "unknown excluded": changed(lambda m: m["excluded"].append("history")),
        "high-water mark set": changed(
            lambda m: m["cut_point"].update(event_log_high_water_mark=5)
        ),
        "fingerprint field": changed(lambda m: m.update(session_key_fingerprint="x")),
        "config path elsewhere": changed(
            lambda m: m["config"]["team_mapping"].update(path="../etc/passwd")
        ),
    }


@pytest.mark.parametrize("case", list(_manifest_negatives()))
def test_negative_manifests_are_rejected(case):
    assert _errors("manifest", _manifest_negatives()[case]), case


# -- enums shared with the code (gap 9) --------------------------------------


def _schema_enum(name, *path):
    node = schemas.load_schema(name)
    for part in path:
        node = node[part]
    return set(node["enum"])


def test_sync_status_enum_matches_the_code():
    constants = {
        value
        for name, value in vars(assessment_outbox_services).items()
        if name.startswith("SYNC_") and isinstance(value, str)
    }
    sources = "\n".join(
        path.read_text(encoding="utf-8") for path in (REPO / "dtvp").rglob("*.py")
    ) + "\n".join(
        path.read_text(encoding="utf-8")
        for path in (REPO / "dtvp" / "migrations").rglob("*.sql")
    )
    literals = set(re.findall(r"sync_status\s*=\s*'([a-z_]+)'", sources))
    # Values written by the migrations of an older model and converted by
    # them, so no dump can hold them.
    literals -= {"diverged"}
    assert {"synced", "error", "pending"} <= literals | constants
    enum = _schema_enum("assessment", "properties", "sync", "properties", "status")
    assert constants | literals == enum


def test_origin_is_an_open_string():
    origin = schemas.load_schema("revision")["properties"]["origin"]
    assert "enum" not in origin and "const" not in origin
    assert origin == {"$ref": "urn:dtvp:dump:1:common#/$defs/non_empty_string"}


def test_application_status_enum_matches_the_code():
    source = (REPO / "dtvp" / "code_analysis_result_services.py").read_text()
    match = re.search(r"normalized_status not in (\{[^}]+\})", source)
    allowed = set(eval(match.group(1)))  # noqa: S307 - a literal set from our source
    assert allowed == _schema_enum(
        "code_analysis_application", "properties", "status"
    )


def test_token_scope_enum_matches_the_code():
    scopes = schemas.load_schema("access_token")["properties"]["scopes"]["items"]
    assert set(scopes["enum"]) == set(access_token_services.VALID_SCOPES)


def test_state_enum_matches_the_states_the_code_knows():
    from dtvp.logic import STATE_PRIORITY

    states = set(schemas.load_schema("common")["$defs"]["analysis_state"]["enum"])
    assert set(STATE_PRIORITY) <= states | {"NOT_SET"}
    assert "NOT_SET" in states


def test_strip_unknown_properties():
    record = _assessment()
    record["future_field"] = 1
    record["sync"]["future_nested"] = True
    stripped, removed = schemas.strip_unknown_properties("assessment", record)
    assert stripped == _assessment()
    assert removed == ["future_field", "sync/future_nested"]
    broken = _assessment()
    broken["future_field"] = 1
    broken["revision"] = "1"
    assert schemas.strip_unknown_properties("assessment", broken) is None
