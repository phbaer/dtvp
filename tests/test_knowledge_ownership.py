"""Contextual responsibility is versioned knowledge, never an authorization grant."""

import copy

import pytest
from sqlalchemy import delete

from dtvp.knowledge.journal import SECTIONS, Ref, Update
from dtvp.knowledge.projection import catch_up, heads, records
from dtvp.storage import digest
from tests.conftest import login
from tests.test_knowledge_api import app as knowledge_app
from tests.test_knowledge_api import body, imported, product

app = knowledge_app


def endpoint(project_id):
    return f"/api/v3/projects/{project_id}"


def graph(edges, roots=("root",)):
    refs = sorted(set(edges) | {dep for values in edges.values() for dep in values})
    result = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "components": [
            {
                "type": "library",
                "bom-ref": ref,
                "group": "example",
                "name": ref,
                "version": "1.0",
                "purl": f"pkg:generic/example/{ref}@1.0",
            }
            for ref in refs
        ],
        "dependencies": [{"ref": ref, "dependsOn": values} for ref, values in edges.items()],
    }
    if len(roots) == 1:
        root = next(item for item in result["components"] if item["bom-ref"] == roots[0])
        result["metadata"] = {"component": copy.deepcopy(root)}
        result["components"] = [item for item in result["components"] if item is not root]
    return result


def administrator(client):
    project_id = product(client)
    login(client, "administrator")
    teams = {item["name"]: item["id"] for item in client.get("/api/v2/workspaces").json()}
    return project_id, teams


def current_policy(client, project_id):
    response = client.get(f"{endpoint(project_id)}/ownership")
    assert response.status_code == 200, response.text
    return response.json()


def rule(ref, team_id, **changes):
    return {"selector": f"example:{ref}", "team_id": team_id, **changes}


def policy_body(client, project_id, rules, **changes):
    current = current_policy(client, project_id)
    return {
        "request_id": "ownership-1",
        "expected_policy": current["policy_state"],
        "expected_versions": current["versions"],
        "rules": rules,
        "context_roots": {},
        **changes,
    }


def apply_policy(client, project_id, rules, **changes):
    response = client.put(
        f"{endpoint(project_id)}/ownership",
        json=policy_body(client, project_id, rules, **changes),
    )
    assert response.status_code == 201, response.text
    return current_policy(client, project_id)


def contexts(client, project_id, version="7.1.1", **params):
    response = client.get(f"{endpoint(project_id)}/versions/{version}/contexts", params=params)
    assert response.status_code == 200, response.text
    return response.json()


def indexed(result):
    return {(item["root_ref"], item["component_ref"]): item for item in result["items"]}


def test_recursive_delegation_covers_bypass_and_deduplicates_diamonds(analyst):
    project_id, teams = administrator(analyst)
    bom = graph(
        {
            "root": ["A", "X", "left", "right"],
            "A": ["X"],
            "left": ["Y"],
            "right": ["Y"],
            "X": [],
            "Y": [],
        }
    )
    imported(analyst, project_id, "7.1.1", body(bom))
    configured = apply_policy(
        analyst,
        project_id,
        [
            rule("root", teams["Platform"]),
            rule("A", teams["Operations"]),
        ],
    )
    result = contexts(analyst, project_id)
    items = indexed(result)
    assert len(items) == len(result["items"]) == 6
    assert {item["root_ref"] for item in items.values()} == {"root"}
    for ref in ("A", "X"):
        assert items[("root", ref)]["team_id"] == teams["Operations"]
        assert items[("root", ref)]["status"] == "resolved"
    assert items[("root", "Y")]["team_id"] == teams["Platform"]
    assert "A" in items[("root", "X")]["owner_boundaries"]
    assert result["policy_state"] == configured["policy_state"]
    filtered = contexts(analyst, project_id, team_id=teams["Operations"])
    assert {item["component_ref"] for item in filtered["items"]} == {"A", "X"}
    delegated = contexts(analyst, project_id, team_id=teams["Platform"], include_delegated=True)
    assert {item["id"] for item in delegated["items"]} == {item["id"] for item in result["items"]}


def test_shared_dependencies_keep_distinct_roots_and_conflicts_visible(analyst):
    project_id, teams = administrator(analyst)
    imported(
        analyst,
        project_id,
        "7.1.1",
        body(
            graph(
                {
                    "root": ["A", "D"],
                    "A": ["X"],
                    "D": ["X"],
                    "X": [],
                    "other": ["X"],
                }
            )
        ),
    )
    apply_policy(
        analyst,
        project_id,
        [
            rule("root", teams["Platform"]),
            rule("other", teams["Platform"]),
            rule("A", teams["Platform"]),
            rule("D", teams["Operations"]),
        ],
        context_roots={"7.1.1": ["root", "other"]},
    )
    items = indexed(contexts(analyst, project_id))
    conflict = items[("root", "X")]
    assert conflict["status"] == "conflict"
    assert conflict["team_id"] is None
    assert set(conflict["candidate_teams"]) == set(teams.values())
    assert items[("other", "X")]["status"] == "resolved"
    assert conflict["id"] != items[("other", "X")]["id"]
    for team_id in teams.values():
        filtered = contexts(analyst, project_id, team_id=team_id)
        assert conflict["id"] in {item["id"] for item in filtered["items"]}


def test_policy_applies_to_future_imports_and_version_limits(analyst):
    project_id, teams = administrator(analyst)
    bom = graph({"root": ["A"], "A": []})
    first = imported(analyst, project_id, "7.1.1", body(bom))
    imported(analyst, project_id, "7.1.2", body(bom, request_id="parallel"))
    apply_policy(
        analyst,
        project_id,
        [
            rule("root", teams["Platform"]),
            rule("A", teams["Operations"], versions=["7.1.2"]),
        ],
    )
    one = indexed(contexts(analyst, project_id))
    two = indexed(contexts(analyst, project_id, "7.1.2"))
    assert one[("root", "A")]["team_id"] == teams["Platform"]
    assert two[("root", "A")]["team_id"] == teams["Operations"]
    latest = current_policy(analyst, project_id)["versions"]["7.1.1"]
    assert latest != first
    imported(
        analyst,
        project_id,
        "7.1.1",
        body(
            graph({"root": ["A", "new"], "A": [], "new": []}),
            request_id="nightly-2",
            expected=latest,
            build_number=2,
        ),
    )
    after = indexed(contexts(analyst, project_id))
    assert after[("root", "new")]["team_id"] == teams["Platform"]
    assert after[("root", "A")]["id"] == one[("root", "A")]["id"]


def test_policy_cas_is_atomic_idempotent_and_requires_all_active_versions(analyst, app):
    project_id, teams = administrator(analyst)
    bom = graph({"root": ["X"], "X": []})
    for version in ("7.1.1", "7.1.2"):
        imported(analyst, project_id, version, body(bom, request_id=version))
    payload = policy_body(analyst, project_id, [rule("root", teams["Platform"])])
    before = app.state.knowledge.head()
    incomplete = {**payload, "expected_versions": {"7.1.1": payload["expected_versions"]["7.1.1"]}}
    assert analyst.put(f"{endpoint(project_id)}/ownership", json=incomplete).status_code == 409
    assert app.state.knowledge.head() == before
    response = analyst.put(f"{endpoint(project_id)}/ownership", json=payload)
    assert response.status_code == 201, response.text
    committed = app.state.knowledge.head()
    retry = analyst.put(f"{endpoint(project_id)}/ownership", json=payload)
    assert retry.status_code == 201, retry.text
    assert app.state.knowledge.head() == committed
    stale = {**payload, "request_id": "stale"}
    assert analyst.put(f"{endpoint(project_id)}/ownership", json=stale).status_code == 409
    assert app.state.knowledge.head() == committed


def test_ownership_does_not_grant_access_and_mutation_requires_manage(analyst):
    project_id, teams = administrator(analyst)
    imported(analyst, project_id, "7.1.1", body(graph({"root": []})))
    payload = policy_body(analyst, project_id, [rule("root", teams["Operations"])])
    login(analyst, "analyst")
    assert analyst.put(f"{endpoint(project_id)}/ownership", json=payload).status_code == 404
    login(analyst, "administrator")
    invalid = {**payload, "rules": [rule("root", "nonexistent-workspace")]}
    assert analyst.put(f"{endpoint(project_id)}/ownership", json=invalid).status_code == 422
    apply_policy(analyst, project_id, [rule("root", teams["Operations"])])
    login(analyst, "operations")
    assert analyst.get(f"{endpoint(project_id)}/ownership").status_code == 404
    assert analyst.get(f"{endpoint(project_id)}/versions/7.1.1/contexts").status_code == 404


def test_reassignment_and_component_removal_retain_assessments_and_tag(analyst, app):
    project_id, teams = administrator(analyst)
    first = imported(analyst, project_id, "7.1.1", body(graph({"root": ["X"], "X": []})))
    journal = app.state.knowledge
    sections = {
        section: {key: journal.load(sha) for key, sha in journal.records(first, section).items()}
        for section in SECTIONS
    }
    sections["assessments"]["retained"] = {"reason": "Retain the historical team assessment"}
    assessed = journal.snapshot(
        project_id=project_id,
        version="7.1.1",
        actor_id="test",
        reason="Assessment fixture",
        sections=sections,
        parents=[first],
    )
    journal.publish(
        request_id="assessment",
        fingerprint=digest(b"assessment"),
        updates=[
            Update(ref=Ref(project_id=project_id, name="7.1.1"), expected=first, target=assessed)
        ],
    )
    catch_up(app.state.engine, journal)
    apply_policy(analyst, project_id, [rule("root", teams["Platform"])])
    initial = contexts(analyst, project_id)
    tagged = analyst.post(
        f"{endpoint(project_id)}/tags",
        json={
            "request_id": "tag-owned",
            "name": "released",
            "state": initial["state"],
        },
    )
    assert tagged.status_code == 201, tagged.text
    old_sections = journal.verify_state(initial["state"]).sections
    apply_policy(analyst, project_id, [rule("root", teams["Operations"])], request_id="reassign")
    reassigned = contexts(analyst, project_id)
    assert indexed(initial)[("root", "X")]["id"] == indexed(reassigned)[("root", "X")]["id"]
    assert journal.records(reassigned["state"], "assessments") == journal.records(
        assessed, "assessments"
    )
    latest = imported(
        analyst,
        project_id,
        "7.1.1",
        body(
            graph({"root": []}),
            request_id="remove",
            expected=reassigned["state"],
            build_number=2,
        ),
    )
    assert not any(item["component_ref"] == "X" for item in contexts(analyst, project_id)["items"])
    assert journal.records(latest, "assessments") == journal.records(assessed, "assessments")
    assert journal.verify_state(initial["state"]).sections == old_sections
    assert (
        journal.resolve(Ref(project_id=project_id, kind="tag", name="released")) == initial["state"]
    )


def test_context_pagination_stale_guard_and_projection_rebuild(analyst, app):
    project_id, teams = administrator(analyst)
    imported(analyst, project_id, "7.1.1", body(graph({"root": ["A", "B"], "A": [], "B": []})))
    apply_policy(analyst, project_id, [rule("root", teams["Platform"])])
    full = contexts(analyst, project_id)
    items = []
    offset = 0
    while offset is not None:
        page = contexts(analyst, project_id, limit=1, offset=offset, expected=full["state"])
        items.extend(page["items"])
        offset = page["next_offset"]
    assert items == full["items"]
    with app.state.engine.begin() as connection:
        connection.execute(delete(records))
        connection.execute(delete(heads))
    catch_up(app.state.engine, app.state.knowledge, rebuild=True)
    assert contexts(analyst, project_id) == full
    apply_policy(analyst, project_id, [rule("root", teams["Operations"])], request_id="changed")
    assert (
        analyst.get(
            f"{endpoint(project_id)}/versions/7.1.1/contexts", params={"expected": full["state"]}
        ).status_code
        == 409
    )


@pytest.mark.parametrize("missing_graph", [False, True])
def test_missing_topology_and_rootless_cycles_never_claim_recursive_coverage(
    analyst, missing_graph
):
    project_id, teams = administrator(analyst)
    bom = graph({"A": ["B"], "B": ["A"]}, roots=())
    if missing_graph:
        bom.pop("dependencies")
    imported(analyst, project_id, "7.1.1", body(bom))
    apply_policy(analyst, project_id, [rule("A", teams["Platform"])])
    result = contexts(analyst, project_id)
    items = result["items"]
    assert {item["component_ref"] for item in items} == {"A", "B"}
    if missing_graph:
        assert result["summary"]["topology_status"] == "not_reported"
        assert indexed(result)[("B", "B")]["team_id"] is None
    else:
        assert all(item["status"] == "topology_unknown" for item in items)


def test_constituent_intake_has_no_product_context_until_assembly(analyst, bom):
    from tests.test_knowledge_assembly import assembly, publish, selection, source_import

    project_id, teams = administrator(analyst)
    source = source_import(analyst, project_id, "application", bom)
    assert current_policy(analyst, project_id)["versions"] == {}
    apply_policy(analyst, project_id, [{"selector": "*", "team_id": teams["Platform"]}])
    assert analyst.get(f"{endpoint(project_id)}/versions/7.1.1/contexts").status_code == 404
    state = publish(analyst, project_id, assembly([selection("application", source)]))
    current = contexts(analyst, project_id)
    assert current["state"] == state
    assert current["items"]
    assert all(item["team_id"] == teams["Platform"] for item in current["items"])
    assert all(
        item["component_ref"] not in {c["bom-ref"] for c in bom["components"]}
        for item in current["items"]
    )
    assert current_policy(analyst, project_id)["versions"] == {"7.1.1": state}


def test_invalid_context_root_does_not_publish_any_policy_or_branch(analyst, app):
    project_id, teams = administrator(analyst)
    imported(analyst, project_id, "7.1.1", body(graph({"root": []})))
    before = app.state.knowledge.head()
    payload = policy_body(
        analyst,
        project_id,
        [rule("root", teams["Platform"])],
        context_roots={"7.1.1": ["missing-component"]},
    )
    response = analyst.put(f"{endpoint(project_id)}/ownership", json=payload)
    assert response.status_code in {409, 422}, response.text
    assert app.state.knowledge.head() == before


def test_explicit_consuming_roots_replace_aggregate_product_context(analyst):
    project_id, teams = administrator(analyst)
    imported(
        analyst,
        project_id,
        "7.1.1",
        body(
            graph(
                {
                    "root": ["B", "C"],
                    "B": ["X"],
                    "C": ["X"],
                    "X": [],
                }
            )
        ),
    )
    apply_policy(
        analyst,
        project_id,
        [rule("B", teams["Platform"]), rule("C", teams["Operations"])],
        context_roots={"7.1.1": ["B", "C"]},
    )
    items = indexed(contexts(analyst, project_id))
    assert set(items) == {("B", "B"), ("B", "X"), ("C", "C"), ("C", "X")}
    assert items[("B", "X")]["team_id"] == teams["Platform"]
    assert items[("C", "X")]["team_id"] == teams["Operations"]
