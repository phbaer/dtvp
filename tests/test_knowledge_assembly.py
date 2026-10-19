"""Product assembly boundaries: source intake, coherent publication and retained knowledge."""

import copy
import json

import pytest
from sqlalchemy import delete

from dtvp.knowledge.journal import SECTIONS, Ref, Update
from dtvp.knowledge.projection import catch_up, heads, records
from dtvp.storage import canonical, digest
from tests.conftest import login
from tests.test_knowledge_api import app as knowledge_app
from tests.test_knowledge_api import body, imported, product

# Register the same SQLite/PostgreSQL application fixture for these API scenarios.
app = knowledge_app


def path(project_id, version="7.1.1"):
    return f"/api/v1/projects/{project_id}/versions/{version}"


def source_import(client, project_id, part_id, bom, *, version="7.1.1", **changes):
    response = client.post(
        f"{path(project_id, version)}/parts/{part_id}/imports",
        json=body(bom, **{"request_id": f"{version}-{part_id}-1", **changes}),
    )
    assert response.status_code == 201, response.text
    return response.json()["updates"][0]["target"]


def selection(part_id, state, **changes):
    return {"part_id": part_id, "state": state, "required": True, "role": "delivery", **changes}


def assembly(parts, **changes):
    return {
        "request_id": "assembly-1",
        "expected": None,
        "parts": parts,
        "removed_parts": [],
        "coherence": {
            "status": "producer_declared",
            "build_id": "integration-1",
            "rationale": "Selected together by the integration pipeline",
        },
        **changes,
    }


def publish(client, project_id, payload, version="7.1.1"):
    response = client.post(f"{path(project_id, version)}/assembly", json=payload)
    assert response.status_code == 201, response.text
    return response.json()["updates"][0]["target"]


def inventory(client, project_id, version="7.1.1"):
    response = client.get(f"{path(project_id, version)}/inventory")
    assert response.status_code == 200, response.text
    return response.json()


def tag(client, project_id, state, name):
    return client.post(
        f"/api/v1/projects/{project_id}/tags",
        json={"request_id": f"tag-{name}", "name": name, "state": state},
    )


def test_part_intake_is_isolated_and_assembly_preserves_source_occurrences(analyst, app, bom):
    project_id = product(analyst)
    a = source_import(analyst, project_id, "application", bom)
    b = source_import(analyst, project_id, "container", bom)
    assert analyst.get(f"{path(project_id)}/inventory").status_code == 404
    part = analyst.get(f"{path(project_id)}/parts/application")
    assert part.status_code == 200, part.text
    assert part.json()["state"] == a
    state = publish(
        analyst, project_id, assembly([selection("application", a), selection("container", b)])
    )
    current = inventory(analyst, project_id)
    assert current["state"] == state
    assert current["baseline"]["kind"] == "assembly"
    assert current["baseline"]["readiness"] == "producer_declared_ready"
    components = [item["component"] for item in current["items"]]
    refs = [item["bom-ref"] for item in components]
    assert len(set(refs)) == len(refs)
    for original in bom["components"]:
        occurrences = [item for item in components if item.get("purl") == original.get("purl")]
        assert len(occurrences) == 2  # Identical package identity is not identical usage context.
        assert {item["dtvp_origin"]["part_id"] for item in occurrences} == {
            "application",
            "container",
        }
        assert {item["dtvp_origin"]["ref"] for item in occurrences} == {original["bom-ref"]}
        assert {item["dtvp_origin"]["state"] for item in occurrences} == {a, b}
    manifest = analyst.get(f"/api/v1/projects/{project_id}/states/{state}/assembly")
    assert manifest.status_code == 200, manifest.text
    assert manifest.json()["state"] == state
    assert {item["part_id"] for item in manifest.json()["manifest"]["parts"]} == {
        "application",
        "container",
    }
    journal = app.state.knowledge
    graph = journal.load(journal.records(state, "inventory")["dependencies"])["edges"]
    assembled_records = [journal.load(sha) for sha in journal.records(state, "inventory").values()]
    part_for_ref = {
        item["bom-ref"]: item["dtvp_origin"]["part_id"]
        for item in assembled_records
        if "dtvp_origin" in item
    }
    for edge in graph:
        assert edge["ref"] in part_for_ref
        for dependency in edge.get("dependsOn", []):
            assert dependency in part_for_ref
            assert part_for_ref[edge["ref"]] == part_for_ref[dependency]
    assembled_findings = [
        journal.load(sha) for sha in journal.records(state, "vulnerabilities").values()
    ]
    assert len(assembled_findings) == len(bom["vulnerabilities"]) * 2
    for finding in assembled_findings:
        assert finding["ref"] in part_for_ref
        assert finding["match"]["ref"] == finding["ref"]
        assert part_for_ref[finding["ref"]] == finding["dtvp_origin"]["part_id"]
    assert tag(analyst, project_id, state, "release").status_code == 201
    assert (
        analyst.post(
            f"{path(project_id)}/imports", json=body(bom, request_id="overwrite", expected=state)
        ).status_code
        == 409
    )


def test_part_update_requires_selection_and_preserves_other_knowledge(analyst, app, bom):
    project_id = product(analyst)
    a = source_import(analyst, project_id, "application", bom)
    b = source_import(analyst, project_id, "container", bom)
    first = publish(
        analyst, project_id, assembly([selection("application", a), selection("container", b)])
    )
    journal = app.state.knowledge
    sections = {
        section: {key: journal.load(sha) for key, sha in journal.records(first, section).items()}
        for section in SECTIONS
    }
    sections["assessments"]["retained-assessment"] = {"reason": "Human assessment remains retained"}
    assessed = journal.snapshot(
        project_id=project_id,
        version="7.1.1",
        actor_id="test",
        reason="Record assessment",
        sections=sections,
        parents=[first],
    )
    journal.publish(
        request_id="record-assessment",
        fingerprint=digest(b"record-assessment"),
        updates=[
            Update(ref=Ref(project_id=project_id, name="7.1.1"), expected=first, target=assessed)
        ],
    )
    catch_up(app.state.engine, journal)
    changed = copy.deepcopy(bom)
    changed["components"][0]["description"] = "Changed application component evidence"
    a2 = source_import(
        analyst, project_id, "application", changed, request_id="app-2", expected=a, build_number=2
    )
    assert inventory(analyst, project_id)["state"] == assessed
    second = publish(
        analyst,
        project_id,
        assembly(
            [selection("application", a2), selection("container", b)],
            request_id="assembly-2",
            expected=assessed,
        ),
    )
    assert journal.records(second, "assessments") == journal.records(assessed, "assessments")
    current_records = [journal.load(sha) for sha in journal.records(second, "inventory").values()]
    by_origin = {
        (item["dtvp_origin"]["part_id"], item["dtvp_origin"]["ref"]): item
        for item in current_records
        if "dtvp_origin" in item
    }
    for sha in journal.records(first, "inventory").values():
        value = journal.load(sha)
        if "dtvp_origin" in value:
            origin = value["dtvp_origin"]
            assert by_origin[origin["part_id"], origin["ref"]]["bom-ref"] == value["bom-ref"]
    diff = analyst.get(
        f"/api/v1/projects/{project_id}/compare", params={"before": first, "after": second}
    )
    assert diff.status_code == 200, diff.text
    assert diff.json()["changes"]["inventory"]["changed"]
    part_delta = diff.json()["assembly"]
    assert part_delta["added"] == []
    assert part_delta["removed"] == []
    assert [item["part_id"] for item in part_delta["changed"]] == ["application"]
    assert part_delta["changed"][0]["before"]["state"] == a
    assert part_delta["changed"][0]["after"]["state"] == a2
    assert not diff.json()["changes"]["inventory"]["removed"]


@pytest.mark.parametrize(
    "missing,coherence,readiness",
    [
        (
            True,
            {
                "status": "producer_declared",
                "build_id": "integration-1",
                "rationale": "Pipeline selected",
            },
            "incomplete",
        ),
        (False, {"status": "unverified"}, "unverified"),
    ],
)
def test_incomplete_or_unverified_assembly_cannot_be_tagged(
    analyst, bom, missing, coherence, readiness
):
    project_id = product(analyst)
    a = source_import(analyst, project_id, "application", bom)
    parts = [selection("application", a)]
    if missing:
        parts.append(selection("supplier", None))
    state = publish(analyst, project_id, assembly(parts, coherence=coherence))
    assert inventory(analyst, project_id)["baseline"]["readiness"] == readiness
    assert tag(analyst, project_id, state, "candidate").status_code == 409


def test_part_removal_is_explicit_and_keeps_original_and_previous_state(analyst, app, bom):
    project_id = product(analyst)
    a = source_import(analyst, project_id, "application", bom)
    b = source_import(analyst, project_id, "supplier", bom)
    first = publish(
        analyst, project_id, assembly([selection("application", a), selection("supplier", b)])
    )
    original = analyst.get(f"/api/v1/projects/{project_id}/states/{b}/source")
    assert original.status_code == 200
    assert original.content == canonical(bom)
    payload = assembly([selection("application", a)], request_id="remove", expected=first)
    for changes in (
        {},
        {"removed_parts": ["supplier"]},
        {"removed_parts": ["unknown"], "removal_reason": "Removed"},
    ):
        response = analyst.post(f"{path(project_id)}/assembly", json={**payload, **changes})
        assert response.status_code in (409, 422), response.text
        assert inventory(analyst, project_id)["state"] == first
    second = publish(
        analyst,
        project_id,
        {
            **payload,
            "removed_parts": ["supplier"],
            "removal_reason": "Supplier is no longer shipped",
        },
    )
    assert all(
        i["component"]["dtvp_origin"]["part_id"] == "application"
        for i in inventory(analyst, project_id)["items"]
    )
    assert (
        analyst.get(f"/api/v1/projects/{project_id}/states/{b}/source").content == original.content
    )
    assert (
        len(
            analyst.get(f"/api/v1/projects/{project_id}/states/{first}/assembly").json()[
                "manifest"
            ]["parts"]
        )
        == 2
    )
    diff = analyst.get(
        f"/api/v1/projects/{project_id}/compare", params={"before": first, "after": second}
    ).json()
    assert diff["changes"]["inventory"]["removed"]


def test_assembly_cas_retry_and_projection_rebuild(analyst, app, bom):
    project_id = product(analyst)
    a = source_import(analyst, project_id, "application", bom)
    original = assembly([selection("application", a)])
    first = publish(analyst, project_id, original)
    second = publish(
        analyst, project_id, {**original, "request_id": "assembly-2", "expected": first}
    )
    assert publish(analyst, project_id, original) == first
    assert inventory(analyst, project_id)["state"] == second
    for payload in (
        {**original, "request_id": "stale"},
        {**original, "coherence": {"status": "unverified"}},
    ):
        assert analyst.post(f"{path(project_id)}/assembly", json=payload).status_code == 409
    with app.state.engine.begin() as connection:
        connection.execute(delete(records))
        connection.execute(delete(heads))
    catch_up(app.state.engine, app.state.knowledge, rebuild=True)
    assert inventory(analyst, project_id)["state"] == second
    assert analyst.get(f"{path(project_id)}/parts/application").json()["state"] == a
    assert inventory(analyst, project_id)["items"]


def test_assembly_rejects_foreign_version_part_and_nonpart_states(analyst, bom):
    project_id = product(analyst)
    a = source_import(analyst, project_id, "application", bom)
    other_version = source_import(analyst, project_id, "application", bom, version="7.1.2")
    ordinary = imported(analyst, project_id, "ordinary", body(bom, request_id="ordinary"))
    assembled = publish(analyst, project_id, assembly([selection("application", a)]))
    for part_id, state in [
        ("application", other_version),
        ("supplier", a),
        ("application", ordinary),
        ("application", assembled),
    ]:
        payload = assembly(
            [selection(part_id, state)], expected=assembled, request_id=f"invalid-{state}-{part_id}"
        )
        response = analyst.post(f"{path(project_id)}/assembly", json=payload)
        assert response.status_code in (409, 422), response.text
        assert inventory(analyst, project_id)["state"] == assembled
    login(analyst, "operations")
    foreign_product = product(analyst)
    foreign = source_import(analyst, foreign_product, "application", bom)
    assert analyst.get(f"/api/v1/projects/{project_id}/states/{a}/assembly").status_code == 404
    login(analyst)
    response = analyst.post(
        f"{path(project_id)}/assembly",
        json=assembly(
            [selection("application", foreign)], expected=assembled, request_id="foreign"
        ),
    )
    assert response.status_code in (404, 409, 422), response.text
    assert inventory(analyst, project_id)["state"] == assembled


def test_required_part_policy_cannot_be_silently_downgraded(analyst, bom):
    project_id = product(analyst)
    a = source_import(analyst, project_id, "application", bom)
    first = publish(analyst, project_id, assembly([selection("application", a)]))
    payload = assembly(
        [selection("application", a, required=False)],
        request_id="policy-change",
        expected=first,
    )
    response = analyst.post(f"{path(project_id)}/assembly", json=payload)
    assert response.status_code in (409, 422), response.text
    assert inventory(analyst, project_id)["state"] == first
    publish(
        analyst,
        project_id,
        {
            **payload,
            "policy_change_reason": "Application is now an optional product attachment",
        },
    )


def test_part_head_update_does_not_prevent_selecting_an_older_pinned_revision(analyst, bom):
    project_id = product(analyst)
    first = source_import(analyst, project_id, "application", bom)
    second = source_import(
        analyst,
        project_id,
        "application",
        bom,
        request_id="application-2",
        expected=first,
        build_number=2,
    )
    assembled = publish(analyst, project_id, assembly([selection("application", first)]))
    manifest = analyst.get(f"/api/v1/projects/{project_id}/states/{assembled}/assembly").json()[
        "manifest"
    ]
    assert manifest["parts"][0]["state"] == first
    assert analyst.get(f"{path(project_id)}/parts/application").json()["state"] == second


def test_selected_part_withdrawal_requires_explicit_acknowledgement(analyst, bom):
    project_id = product(analyst)
    source = source_import(analyst, project_id, "supplier", bom)
    first = publish(analyst, project_id, assembly([selection("supplier", source, required=False)]))
    payload = assembly(
        [selection("supplier", None, required=False)],
        request_id="withdrawal",
        expected=first,
    )
    for changes in (
        {},
        {"withdrawn_parts": ["supplier"]},
        {"withdrawn_parts": ["unknown"], "withdrawal_reason": "Supplier input is invalid"},
    ):
        response = analyst.post(f"{path(project_id)}/assembly", json={**payload, **changes})
        assert response.status_code in (409, 422), response.text
        assert inventory(analyst, project_id)["state"] == first
    second = publish(
        analyst,
        project_id,
        {
            **payload,
            "withdrawn_parts": ["supplier"],
            "withdrawal_reason": "Supplier withdrew this input pending correction",
        },
    )
    manifest = analyst.get(f"/api/v1/projects/{project_id}/states/{second}/assembly").json()[
        "manifest"
    ]
    assert manifest["parts"][0]["part_id"] == "supplier"
    assert manifest["parts"][0]["state"] is None
    assert analyst.get(
        f"/api/v1/projects/{project_id}/states/{source}/source"
    ).content == canonical(bom)


def test_empty_optional_assembly_cannot_be_release_tagged(analyst):
    project_id = product(analyst)
    state = publish(
        analyst, project_id, assembly([selection("optional-delivery", None, required=False)])
    )
    baseline = inventory(analyst, project_id)["baseline"]
    assert baseline["readiness"] == "incomplete"
    assert tag(analyst, project_id, state, "empty-release").status_code == 409


def test_part_file_intake_retains_exact_bytes_and_does_not_publish_product(analyst, bom):
    project_id = product(analyst)
    metadata = body(bom, request_id="original-file")
    metadata.pop("sbom")
    raw = (json.dumps(bom, indent=3) + "\n\n").encode()
    endpoint = f"{path(project_id)}/parts/application/files"
    response = analyst.post(
        endpoint,
        data={"metadata": json.dumps(metadata)},
        files={"file": ("original.cdx.json", raw, "application/json")},
    )
    assert response.status_code == 201, response.text
    state = response.json()["updates"][0]["target"]
    original = analyst.get(f"/api/v1/projects/{project_id}/states/{state}/source")
    assert original.content == raw
    assert original.headers["x-dtvp-representation"] == "original_bytes"
    assert analyst.get(f"{path(project_id)}/inventory").status_code == 404
    metadata.update(request_id="broken-file", expected=state, build_number=2)
    invalid = analyst.post(
        endpoint,
        data={"metadata": json.dumps(metadata)},
        files={"file": ("broken.json", b"{", "application/json")},
    )
    assert invalid.status_code == 422, invalid.text
    assert analyst.get(f"{path(project_id)}/parts/application").json()["state"] == state
