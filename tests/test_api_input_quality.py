"""Pinned composition report authorization precedes object access."""

from tests.conftest import login
from tests.test_knowledge_api import app as knowledge_app
from tests.test_knowledge_api import body, imported
from tests.test_workflow_api import setup

app = knowledge_app


def path(project, state):
    return f"/api/v3/projects/{project}/states/{state}/input-quality"


def test_report_is_full_scope_pinned_and_read_only(analyst, app, bom):
    project, _ = setup(analyst, bom)
    state = imported(analyst, project, "quality", body(bom, request_id="quality"))
    before = app.state.knowledge.head(), app.state.knowledge.references()
    response = analyst.get(path(project, state), params={"limit": 1})
    assert response.status_code == 200, response.text
    result = response.json()
    assert len(result["items"]) == 1 and result["total"] > 1
    assert result["statistics"]["by_role"]["inventory_component"] == len(bom["components"])
    selected = analyst.get(path(project, state), params={"code": "license_not_reported"}).json()
    assert selected["statistics"] == result["statistics"]
    assert selected["report_digest"] == result["report_digest"]
    assert result["sources"][0]["coverage_verification"] == "not_verified"
    assert (app.state.knowledge.head(), app.state.knowledge.references()) == before
    login(analyst, "viewer")
    assert analyst.get(path(project, state)).status_code == 200
    login(analyst, "operations")
    assert analyst.get(path(project, state)).status_code == 404


def test_retained_part_history_is_available_before_assembly_but_arbitrary_objects_are_not(
    analyst, app, bom
):
    from dtvp.knowledge.service import import_inventory

    project, _ = setup(analyst, bom)
    journal = app.state.knowledge
    first = (
        import_inventory(
            journal,
            project_id=project,
            version="quality",
            actor_id="producer",
            request_id="part-first",
            expected=None,
            source="supplier",
            build_number=1,
            occurred_at="2026-10-16T10:00:00Z",
            sbom=bom,
            part_id="firmware",
        )[1]
        .updates[0]
        .target
    )
    import_inventory(
        journal,
        project_id=project,
        version="quality",
        actor_id="producer",
        request_id="part-next",
        expected=first,
        source="supplier",
        build_number=2,
        occurred_at="2026-10-17T10:00:00Z",
        sbom=bom,
        part_id="firmware",
    )
    response = analyst.get(path(project, first))
    assert response.status_code == 200, response.text
    assert response.json()["sources"][0]["part_id"] == "firmware"
    raw = journal.objects.put(b"not a state")
    before = journal.head()
    assert analyst.get(path(project, raw)).status_code == 404
    assert analyst.get(path(project, "f" * 64)).status_code == 404
    assert journal.head() == before
