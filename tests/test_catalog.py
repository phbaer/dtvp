"""Scoped native product discovery; no release/finding compatibility catalogs."""

from tests.conftest import login
from tests.test_knowledge_api import body, imported


def create(client, name):
    workspace = client.get("/api/v1/me").json()["workspaces"][0]["id"]
    response = client.post("/api/v1/projects", json={"workspace_id": workspace, "name": name})
    assert response.status_code == 201
    return response.json()["id"]


def test_catalog_search_pages_and_access_scope(analyst, bom):
    for number in range(30):
        create(analyst, f"Catalog product {number:04}")
    target = create(analyst, "Catalog product 9999")
    imported(analyst, target, "1.0", body(bom))
    seen, cursor = [], ""
    while True:
        page = analyst.get(
            "/api/v1/catalog/projects",
            params={"q": "Catalog product", "cursor": cursor, "limit": 7},
        ).json()
        seen.extend(row["id"] for row in page["items"])
        cursor = page["next_cursor"]
        if not cursor:
            break
    assert len(seen) == len(set(seen)) == 31
    result = analyst.get("/api/v1/catalog/projects?q=9999").json()["items"]
    assert len(result) == 1 and result[0]["version_count"] == 1
    assert "release_count" not in result[0] and "finding_count" not in result[0]
    login(analyst, "operations")
    assert analyst.get("/api/v1/catalog/projects?q=Catalog").json()["items"] == []
    assert analyst.get(f"/api/v1/projects/{target}").status_code == 404


def test_catalog_cursors_are_bound_to_query(analyst):
    create(analyst, "Another project")
    page = analyst.get("/api/v1/catalog/projects?limit=1").json()
    assert page["next_cursor"]
    assert (
        analyst.get(
            "/api/v1/catalog/projects", params={"q": "different", "cursor": page["next_cursor"]}
        ).status_code
        == 422
    )
    assert analyst.get("/api/v1/catalog/projects?cursor=garbage").status_code == 422
