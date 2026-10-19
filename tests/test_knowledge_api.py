import copy
import hashlib
import json
import os

import pytest
from sqlalchemy import delete, text

from dtvp.config import Settings
from dtvp.db import engine_for
from dtvp.knowledge.projection import catch_up, heads, records
from dtvp.main import create_app
from tests.conftest import login


@pytest.fixture(params=["sqlite"] + (["postgres"] if os.getenv("DTVP_TEST_DATABASE_URL") else []))
def app(tmp_path, request):
    url = "sqlite:///:memory:"
    if request.param == "postgres":
        url = os.environ["DTVP_TEST_DATABASE_URL"]
        if not url.rsplit("/", 1)[-1].endswith("_test"):
            pytest.fail("Disposable test database name must end in _test")
        engine = engine_for(url)
        with engine.begin() as connection:
            connection.execute(text("DROP SCHEMA public CASCADE"))
            connection.execute(text("CREATE SCHEMA public"))
        engine.dispose()
    return create_app(
        Settings(
            _env_file=None,
            playground=True,
            database_url=url,
            artifact_dir=tmp_path / "artifacts",
            frontend_dir=tmp_path / "absent",
        )
    )


def product(client):
    return client.get("/api/v1/projects").json()[0]["id"]


def body(bom, **changes):
    return {
        "request_id": "nightly-1",
        "expected": None,
        "source": "pipeline/main",
        "build_number": 1,
        "occurred_at": "2026-10-15T01:00:00+00:00",
        "completeness": "complete",
        "sbom": bom,
        **changes,
    }


def imported(client, project_id, version, data):
    response = client.post(f"/api/v1/projects/{project_id}/versions/{version}/imports", json=data)
    assert response.status_code == 201, response.text
    return response.json()["updates"][0]["target"]


def test_parallel_versions_diff_tags_retries_and_projection_rebuild(analyst, app, bom):
    project_id = product(analyst)
    original = body(bom)
    first = imported(analyst, project_id, "7.1.1", original)
    modified = copy.deepcopy(bom)
    modified["components"] = [c for c in modified["components"] if c["bom-ref"] != "utility"]
    for edge in modified["dependencies"]:
        edge["dependsOn"] = [ref for ref in edge.get("dependsOn", []) if ref != "utility"]
    modified["dependencies"] = [e for e in modified["dependencies"] if e["ref"] != "utility"]
    second = imported(
        analyst,
        project_id,
        "7.1.2",
        body(
            modified,
            request_id="version-2",
            predecessor=first,
        ),
    )
    diff = analyst.get(
        f"/api/v1/projects/{project_id}/compare", params={"before": first, "after": second}
    )
    assert diff.status_code == 200, diff.text
    assert "component:ref:utility" in diff.json()["changes"]["inventory"]["removed"]
    path = f"/api/v1/projects/{project_id}/versions/7.1.1/inventory"
    before = analyst.get(path).json()
    assert before["state"] == first
    tagged = analyst.post(
        f"/api/v1/projects/{project_id}/tags",
        json={
            "name": "release-7.1.1",
            "state": first,
            "request_id": "tag",
        },
    )
    assert tagged.status_code == 201
    next_state = imported(
        analyst,
        project_id,
        "7.1.1",
        body(
            bom,
            request_id="nightly-2",
            expected=first,
            build_number=2,
        ),
    )
    # Retrying an earlier successful request does not reset the branch.
    assert imported(analyst, project_id, "7.1.1", original) == first
    assert analyst.get(path).json()["state"] == next_state
    assert analyst.get(path, params={"expected": first}).status_code == 409
    tag_again = analyst.post(
        f"/api/v1/projects/{project_id}/tags",
        json={
            "name": "release-7.1.1",
            "state": next_state,
            "request_id": "retag",
        },
    )
    assert tag_again.status_code == 409
    with app.state.engine.begin() as connection:
        connection.execute(delete(records))
        connection.execute(delete(heads))
    catch_up(app.state.engine, app.state.knowledge, rebuild=True)
    assert analyst.get(path).json()["state"] == next_state
    assert (
        analyst.get(f"/api/v1/projects/{project_id}/versions/7.1.2/inventory").json()["state"]
        == second
    )
    # Rebuilding native projections never re-enables the retired review API.
    assert analyst.get("/api/v1/findings").status_code == 404


def test_stale_partial_conflicting_and_unauthorized_imports(analyst, bom):
    project_id = product(analyst)
    path = f"/api/v1/projects/{project_id}/versions/7.1.1/imports"
    first = imported(analyst, project_id, "7.1.1", body(bom))
    for changes, status in [
        ({"request_id": "stale", "expected": first, "build_number": 0}, 409),
        ({"request_id": "conflict", "build_number": 2}, 409),
        ({"build_number": 2}, 409),
        ({"request_id": "partial", "expected": first, "completeness": "partial"}, 422),
        ({"request_id": "time", "occurred_at": "2026-10-15T01:00:00"}, 422),
        ({"request_id": "authority", "expected": first, "source": "other", "build_number": 2}, 409),
    ]:
        response = analyst.post(path, json=body(bom, **changes))
        assert response.status_code == status, response.text
    assert (
        analyst.get(
            f"/api/v1/projects/{project_id}/compare",
            params={"before": first, "after": "a" * 64},
        ).status_code
        == 404
    )
    login(analyst, "operations")
    assert analyst.post(path, json=body(bom)).status_code == 404
    assert (
        analyst.get(
            f"/api/v1/projects/{project_id}/compare", params={"before": first, "after": first}
        ).status_code
        == 404
    )


def test_committed_import_with_failed_projection_returns_pending_and_retries(
    analyst, app, bom, monkeypatch
):
    import dtvp.api_knowledge as module

    project_id = product(analyst)
    original = module.catch_up

    def failed(*args):
        raise RuntimeError("Database unavailable after journal commit")

    monkeypatch.setattr(module, "catch_up", failed)
    path = f"/api/v1/projects/{project_id}/versions/7.1.1/imports"
    response = analyst.post(path, json=body(bom))
    assert response.status_code == 202
    assert response.json()["committed"] is True
    assert response.json()["projection"] == "pending"
    first = response.json()["updates"][0]["target"]
    monkeypatch.setattr(module, "catch_up", original)
    retry = analyst.post(path, json=body(bom))
    assert retry.status_code == 201
    assert retry.json()["updates"][0]["target"] == first
    assert len(list(app.state.knowledge.publications())) == 1
    monkeypatch.setattr(module, "catch_up", failed)
    newer = analyst.post(
        path,
        json=body(
            bom,
            request_id="nightly-2",
            expected=first,
            build_number=2,
        ),
    )
    assert newer.status_code == 202
    current = analyst.get(f"/api/v1/projects/{project_id}/versions/7.1.1/inventory").json()
    assert current["state"] == first
    assert current["reference_state"] == newer.json()["updates"][0]["target"]
    assert current["projection_current"] is False


@pytest.mark.parametrize("after_replace", [False, True])
def test_uncertain_publication_is_explicit_and_safe_to_retry(
    analyst, app, bom, monkeypatch, after_replace
):
    journal = app.state.knowledge
    original = journal._replace_head

    def interrupted(sha):
        if after_replace:
            original(sha)
        raise OSError("Interrupted publication")

    project_id = product(analyst)
    path = f"/api/v1/projects/{project_id}/versions/7.1.1/imports"
    monkeypatch.setattr(journal, "_replace_head", interrupted)
    result = analyst.post(path, json=body(bom))
    assert result.status_code == 503
    assert result.json()["committed"] is None
    assert result.json()["status"] == "uncertain"
    monkeypatch.setattr(journal, "_replace_head", original)
    retry = analyst.post(path, json=body(bom))
    assert retry.status_code == 201
    assert len(list(journal.publications())) == 1


def test_file_intake_preserves_bytes_and_declared_scope_without_claiming_coverage(
    analyst, app, bom
):
    project_id = product(analyst)
    metadata = body(bom)
    metadata.pop("sbom")
    metadata["context"] = {
        "subject_kind": "container",
        "target": "runtime-image",
        "platform": "linux/amd64",
        "subject_digest": "sha256:" + "a" * 64,
        "collector": "fixture-scanner",
        "collector_version": "1.0",
        "method": "container_scan",
        "package_coverage": "reported_complete",
        "license_coverage": "partial",
        "limitations": ["Statically linked vendored code has not been identified."],
    }
    raw = (json.dumps(bom, indent=3) + "\n\n").encode()
    path = f"/api/v1/projects/{project_id}/versions/7.1.1/files"

    def upload(content, meta=metadata):
        return analyst.post(
            path,
            data={"metadata": json.dumps(meta)},
            files={"file": ("original.cdx.json", content, "application/json")},
        )

    first = upload(raw)
    assert first.status_code == 201, first.text
    state = first.json()["updates"][0]["target"]
    assert upload(raw).json()["updates"][0]["target"] == state
    assert upload(json.dumps(bom).encode()).status_code == 409
    source_path = f"/api/v1/projects/{project_id}/states/{state}/source"
    original = analyst.get(source_path)
    assert original.content == raw
    assert original.headers["x-content-sha256"] == hashlib.sha256(raw).hexdigest()
    assert original.headers["x-dtvp-representation"] == "original_bytes"
    inventory = analyst.get(f"/api/v1/projects/{project_id}/versions/7.1.1/inventory").json()
    assert inventory["baseline"]["coverage_verification"] == "not_verified"
    assert inventory["baseline"]["collection"]["license_coverage"] == "partial"
    assert (
        inventory["baseline"]["snapshot_completeness"] == "producer_declared_complete_within_scope"
    )
    changed = copy.deepcopy(metadata)
    changed.update(request_id="new-platform", expected=state, build_number=2)
    changed["context"]["platform"] = "linux/arm64"
    assert upload(raw, changed).status_code == 409
    changed["context"]["platform"] = "linux/amd64"
    changed["context"]["subject_digest"] = "sha256:" + "b" * 64
    assert upload(raw, changed).status_code == 201
    assert analyst.get(source_path).content == raw
    login(analyst, "operations")
    assert analyst.get(source_path).status_code == 404


def test_missing_graph_and_missing_coverage_stay_unknown(analyst, bom):
    project_id = product(analyst)
    changed = copy.deepcopy(bom)
    changed.pop("dependencies")
    imported(analyst, project_id, "7.1.1", body(changed))
    baseline = analyst.get(f"/api/v1/projects/{project_id}/versions/7.1.1/inventory").json()[
        "baseline"
    ]
    assert baseline["dependency_graph"] == "not_reported"
    assert baseline["collection"]["package_coverage"] == "unknown"
    assert baseline["collection"]["license_coverage"] == "unknown"


def test_xml_file_round_trip_and_invalid_file_do_not_advance_baseline(analyst, app, bom):
    project_id = product(analyst)
    metadata = body(bom)
    metadata.pop("sbom")
    path = f"/api/v1/projects/{project_id}/versions/7.1.1/files"
    raw = b"""<?xml version="1.0" encoding="UTF-8"?>
<bom xmlns="http://cyclonedx.org/schema/bom/1.6" version="1">
  <components><component type="library" bom-ref="vendored-library">
    <name>Vendored C library</name><version>1.0</version>
  </component></components>
</bom>\n"""
    response = analyst.post(
        path,
        data={"metadata": json.dumps(metadata)},
        files={"file": ("legacy.xml", raw, "application/xml")},
    )
    assert response.status_code == 201, response.text
    state = response.json()["updates"][0]["target"]
    assert analyst.get(f"/api/v1/projects/{project_id}/states/{state}/source").content == raw
    head = app.state.knowledge.head()
    metadata.update(request_id="bad-file", expected=state, build_number=2)
    result = analyst.post(
        path,
        data={"metadata": json.dumps(metadata)},
        files={"file": ("broken.xml", b"<bom><broken", "application/xml")},
    )
    assert result.status_code == 422
    assert app.state.knowledge.head() == head


def test_spdx_containment_does_not_become_dependency_topology(analyst, app):
    project_id = product(analyst)
    bom = {
        "spdxVersion": "SPDX-2.3",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "Legacy product",
        "packages": [
            {"SPDXID": "SPDXRef-A", "name": "LegacyApp", "versionInfo": "1"},
            {"SPDXID": "SPDXRef-B", "name": "VendorLibrary", "versionInfo": "2"},
        ],
        "relationships": [
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relatedSpdxElement": "SPDXRef-A",
                "relationshipType": "DESCRIBES",
            },
            {
                "spdxElementId": "SPDXRef-A",
                "relatedSpdxElement": "SPDXRef-B",
                "relationshipType": "CONTAINS",
            },
        ],
    }
    first = imported(analyst, project_id, "7.1.1", body(bom))
    journal = app.state.knowledge
    inventory = {key: journal.load(sha) for key, sha in journal.records(first, "inventory").items()}
    assert inventory["dependencies"]["edges"] == []
    assert {item["kind"] for item in inventory["relationships"]["items"]} == {
        "DESCRIBES",
        "CONTAINS",
    }
    assert inventory["baseline"]["dependency_graph"] == "not_reported"
    bom["relationships"].append(
        {
            "spdxElementId": "SPDXRef-A",
            "relatedSpdxElement": "SPDXRef-B",
            "relationshipType": "DEPENDS_ON",
        }
    )
    second = imported(
        analyst,
        project_id,
        "7.1.1",
        body(
            bom,
            request_id="dependency",
            expected=first,
            build_number=2,
        ),
    )
    inventory = {
        key: journal.load(sha) for key, sha in journal.records(second, "inventory").items()
    }
    assert inventory["dependencies"]["edges"] == [{"ref": "SPDXRef-A", "dependsOn": ["SPDXRef-B"]}]
    assert inventory["baseline"]["dependency_graph"] == "reported"
