"""Native target inspection supports empty projects without inventing authority."""

import json

from tests.conftest import login
from tests.test_knowledge_api import app as knowledge_app
from tests.test_workflow_api import setup, url, workspace

app = knowledge_app


def metadata(**changes):
    return {
        "request_id": "file-import",
        "expected": None,
        "source": "pipeline:file",
        "build_number": 1,
        "occurred_at": "2026-10-16T10:00:00Z",
        "completeness": "complete",
        **changes,
    }


def test_empty_version_target_bootstraps_exact_original_file_and_receipt_replay(analyst, app, bom):
    project_id, _ = setup(analyst, bom)
    target = analyst.get(url(project_id, "/intake-target"), params={"version": "new-version"})
    assert target.status_code == 200, target.text
    assert target.json()["state"] is None and target.json()["capabilities"] == ["import"]
    assert target.json()["source_authority"] == "unassigned"
    raw = json.dumps(bom, ensure_ascii=False, indent=3).encode() + b"\n"
    fields = metadata()
    path = url(project_id, "/versions/new-version/files")

    def upload():
        return analyst.post(
            path,
            data={"metadata": json.dumps(fields)},
            files={"file": ("original.cdx.json", raw, "application/json")},
        )

    first = upload()
    assert first.status_code == 201, first.text
    assert upload().json() == first.json()
    state = workspace(analyst, project_id, "new-version")["state"]
    current = analyst.get(
        url(project_id, "/intake-target"), params={"version": "new-version"}
    ).json()
    assert current["state"] == state and current["source_authority"] == "file"
    assert current["baseline"]["source"] == "pipeline:file"
    baseline = app.state.knowledge.load(app.state.knowledge.records(state, "inventory")["baseline"])
    assert app.state.knowledge.objects.read(baseline["artifact_sha"]) == raw
    assert baseline["representation"] == "original_bytes"


def test_part_target_and_search_are_scoped_and_do_not_publish_product_head(analyst, app, bom):
    project_id, _ = setup(analyst, bom)
    product = workspace(analyst, project_id)["state"]
    for part_id in ("container", "firmware", "frontend"):
        response = analyst.post(
            url(project_id, f"/versions/7.1.1/parts/{part_id}/files"),
            data={"metadata": json.dumps(metadata(request_id="part-" + part_id))},
            files={"file": ("part.json", json.dumps(bom).encode(), "application/json")},
        )
        assert response.status_code == 201, response.text
    page = analyst.get(
        url(project_id, "/intake-parts"), params={"version": "7.1.1", "q": "f", "limit": 1}
    ).json()
    assert page["total"] == 2 and page["next_offset"] == 1
    assert [row["part_id"] for row in page["items"]] == ["firmware"]
    later = analyst.get(
        url(project_id, "/intake-parts"),
        params={"version": "7.1.1", "q": "f", "limit": 1, "offset": 1},
    ).json()
    assert [row["part_id"] for row in later["items"]] == ["frontend"]
    assert (
        analyst.get(url(project_id, "/intake-parts"), params={"version": "other"}).json()["items"]
        == []
    )
    target = analyst.get(
        url(project_id, "/intake-target"), params={"version": "7.1.1", "part_id": "container"}
    ).json()
    assert target["kind"] == "part" and target["state"] != product
    assert target["baseline"]["source"] == "pipeline:file"
    assert workspace(analyst, project_id)["state"] == product


def test_connector_authority_and_assembly_cannot_be_misrepresented_as_file_targets(
    analyst, app, bom
):
    project_id, _ = setup(analyst, bom)
    journal = app.state.knowledge
    # Use the real importer optional connector provenance contract.
    from dtvp.knowledge.service import import_inventory

    receipt = import_inventory(
        journal,
        project_id=project_id,
        version="connector",
        actor_id="pipeline",
        request_id="connector-fixture",
        expected=None,
        source="dependency-track:bound-source",
        build_number=1,
        occurred_at="2026-10-16T10:00:00Z",
        sbom=bom,
        source_provenance={"format": "dtvp.dependency-track-intake/1"},
    )
    target = analyst.get(url(project_id, "/intake-target"), params={"version": "connector"}).json()
    assert target["source_authority"] == "connector" and target["capabilities"] == []
    assert target["state"] == receipt[1].updates[0].target
    assert "authority_policy" in target["blocked_reasons"][0]
    assert (
        analyst.get(url(project_id, "/intake-target"), params={"version": "@reserved"}).json()[
            "capabilities"
        ]
        == []
    )


def test_read_capability_does_not_grant_import_and_foreign_project_is_hidden(analyst, bom):
    project_id, _ = setup(analyst, bom)
    login(analyst, "coordinator")
    response = analyst.get(url(project_id, "/intake-target"), params={"version": "new-version"})
    assert response.status_code == 200 and response.json()["capabilities"] == []
    login(analyst, "operations")
    assert (
        analyst.get(
            url(project_id, "/intake-target"), params={"version": "new-version"}
        ).status_code
        == 404
    )
    assert (
        analyst.get(url(project_id, "/intake-parts"), params={"version": "7.1.1"}).status_code
        == 404
    )


def test_assembled_product_target_requires_explicit_part_selection(analyst, bom):
    from tests.test_knowledge_assembly import assembly, publish, selection, source_import

    project_id, _ = setup(analyst, bom)
    state = source_import(analyst, project_id, "application", bom, version="assembled")
    publish(analyst, project_id, assembly([selection("application", state)]), version="assembled")
    response = analyst.get(url(project_id, "/intake-target"), params={"version": "assembled"})
    assert response.status_code == 200, response.text
    assert response.json()["source_authority"] == "assembly"
    assert response.json()["capabilities"] == []
    assert "part_selection" in response.json()["blocked_reasons"][0]


def test_existing_scope_template_preserves_boundary_without_stale_provenance(analyst, app, bom):
    from tests.test_knowledge_api import body, imported

    project_id, _ = setup(analyst, bom)
    boundary = {
        "subject_kind": "build",
        "target": "delivery",
        "platform": "linux",
        "configuration": "prod",
    }
    old_context = {
        **boundary,
        "analysis_source": {"repository_name": "claimed-repository", "source_commit": "a" * 40},
        "subject_digest": "sha256:" + "b" * 64,
        "source_revision": "old-commit",
        "pipeline_run": "old-run",
        "collector": "old-collector",
    }
    old_context.update(
        method="build",
        package_coverage="reported_complete",
        dependency_coverage="reported_complete",
        license_coverage="reported_complete",
    )
    state = imported(
        analyst,
        project_id,
        "scoped-files",
        body(bom, source="pipeline:file", request_id="scoped-first", context=old_context),
    )
    result = analyst.get(
        url(project_id, "/intake-target"), params={"version": "scoped-files"}
    ).json()
    assert result["scope_template"] == boundary
    assert result["capabilities"] == ["import"]
    response = analyst.post(
        url(project_id, "/versions/scoped-files/files"),
        data={
            "metadata": json.dumps(
                metadata(
                    request_id="scoped-second",
                    expected=state,
                    build_number=2,
                    context=result["scope_template"],
                )
            )
        },
        files={"file": ("nightly.json", json.dumps(bom).encode(), "application/json")},
    )
    assert response.status_code == 201, response.text
    latest = response.json()["updates"][0]["target"]
    baseline = app.state.knowledge.load(
        app.state.knowledge.records(latest, "inventory")["baseline"]
    )
    collection = baseline["collection"]
    assert {key: collection[key] for key in boundary} == boundary
    assert "analysis_source" not in collection
    assert collection["pipeline_run"] is None and collection["subject_digest"] is None
    assert collection["source_revision"] is None and collection["collector"] is None
    assert (
        collection["package_coverage"]
        == collection["dependency_coverage"]
        == collection["license_coverage"]
        == "unknown"
    )


def test_new_product_default_file_import_handles_xml_bom_and_subsequent_updates(analyst, app):
    project = analyst.post("/api/v1/projects/resolve", json={"project": "New XML product"}).json()[
        "id"
    ]
    path = url(project, "/versions/1.0/files")
    raw = b'\xef\xbb\xbf<?xml version="1.0" encoding="UTF-8"?>\r\n<bom xmlns="http://cyclonedx.org/schema/bom/1.6" version="1"><components><component type="library" bom-ref="lib"><name>Example</name><version>1</version></component></components></bom>'
    for sequence in (1, 2):
        target = analyst.get(url(project, "/intake-target"), params={"version": "1.0"}).json()
        assert target["defaults"]["source"] == "file:upload"
        assert target["defaults"]["build_number"] == sequence
        fields = {
            **target["defaults"],
            "request_id": f"default-{sequence}",
            "expected": target["state"],
        }
        response = analyst.post(
            path,
            data={"metadata": json.dumps(fields)},
            files={"file": ("example.cdx", raw, "application/xml")},
        )
        assert response.status_code == 201, response.text
        replay = analyst.post(
            path,
            data={"metadata": json.dumps(fields)},
            files={"file": ("example.cdx", raw, "application/xml")},
        )
        assert (
            replay.status_code == 201
            and replay.json()["publication"] == response.json()["publication"]
        )
        state = response.json()["updates"][0]["target"]
        journal = app.state.knowledge
        baseline = journal.load(journal.records(state, "inventory")["baseline"])
        assert journal.objects.read(baseline["artifact_sha"]) == raw
        assert baseline["build_number"] == sequence
