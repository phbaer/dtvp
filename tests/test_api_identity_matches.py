"""Identity matching is pinned, authorized and unable to alter product state."""

from copy import deepcopy

from dtvp.knowledge.journal import SECTIONS
from tests.conftest import login
from tests.test_knowledge_api import app as knowledge_app
from tests.test_knowledge_api import body, imported, product

app = knowledge_app


def test_renamed_refs_missing_identity_and_pagination_are_read_only(analyst, app, bom):
    project = product(analyst)
    source = imported(analyst, project, "7.1.1", body(bom))
    changed = deepcopy(bom)
    for component in changed["components"]:
        component["bom-ref"] += "-renamed"
    for edge in changed["dependencies"]:
        if edge["ref"] != changed.get("metadata", {}).get("component", {}).get("bom-ref"):
            edge["ref"] += "-renamed"
        edge["dependsOn"] = [ref + "-renamed" for ref in edge.get("dependsOn", [])]
    for vulnerability in changed.get("vulnerabilities", []):
        for affected in vulnerability.get("affects", []):
            affected["ref"] += "-renamed"
    target = imported(
        analyst,
        project,
        "7.1.1",
        body(changed, request_id="second", expected=source, build_number=2),
    )
    journal = app.state.knowledge
    before = journal.head()
    path = f"/api/v3/projects/{project}/states/{target}/identity-matches"
    response = analyst.get(path, params={"source": source, "limit": 1})
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["summary"]["matched"] > 0
    assert result["items"][0]["target_id"] == result["items"][0]["source_id"] + "-renamed"
    if result["next_offset"] is not None:
        other = analyst.get(
            path, params={"source": source, "offset": result["next_offset"], "limit": 1}
        ).json()
        assert other["report_digest"] == result["report_digest"]
    assert journal.head() == before
    for section in set(SECTIONS) - {"inventory", "vulnerabilities", "ownership", "history"}:
        assert journal.records(source, section) == journal.records(target, section)
    assert analyst.get(path, params={"source": source, "limit": 201}).status_code == 422
    login(analyst, "operations")
    assert analyst.get(path, params={"source": source}).status_code == 404


def test_uncommitted_state_is_not_an_identity_destination(analyst, app, bom):
    project = product(analyst)
    source = imported(analyst, project, "7.1.1", body(bom))
    sections = {name: {} for name in SECTIONS}
    sections["inventory"] = {"baseline": {}}
    staged = app.state.knowledge.snapshot(
        project_id=project,
        version="7.1.1",
        actor_id="fixture",
        reason="Unpublished",
        sections=sections,
    )
    result = analyst.get(
        f"/api/v3/projects/{project}/states/{staged}/identity-matches", params={"source": source}
    )
    assert result.status_code == 422
